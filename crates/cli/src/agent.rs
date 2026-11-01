//! The unlock agent: lets programs read chosen secrets without the master
//! password, for a limited time (like `ssh-agent`), but **scoped**.
//!
//! `passforme unlock` opens the vault once, at a terminal, and hands the
//! agent only the items marked `agent` (API keys and the like). The agent
//! never sees the vault key: while it runs, a program of this user can read
//! those items and nothing else — the bank password is simply not there.
//!
//! - The agent is this binary (`passforme __agent SECS`), hardened like every
//!   command (no core dumps, not ptrace-able), detached in its own process
//!   group. It receives the items as JSON on stdin, never as arguments.
//! - It listens on `$XDG_RUNTIME_DIR/passforme/agent.sock`: the directory is
//!   0700, the socket 0600, and every connection's peer uid (`SO_PEERCRED`)
//!   must be this user's.
//! - Protocol: one JSON request per connection, one JSON answer
//!   (`Request`/`Response` below).
//! - It wipes the items and exits when its time is up, on `lock`, or when
//!   its socket disappears (the runtime directory is removed when the
//!   session ends): with no time limit (`unlock --for forever`) an agent
//!   must not outlive its socket, holding keys nobody can lock anymore.
//!
//! Same-user malware can still ask it for the marked items while it runs;
//! the point of the scope is that this is all it can get.

use std::fs::{self, DirBuilder};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use passforme_core::item::Item;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::Result;

/// How often the agent checks that its socket still exists.
const WATCH_SECS: u64 = 30;
/// Longest a request line may be.
const REQUEST_LIMIT: u64 = 4096;
/// Longest timed `unlock --for` accepts; `forever` has no limit.
pub const MAX_SECS: u64 = 7 * 24 * 3600;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub enum Request {
    Get { query: String, field: String },
    Status,
    Lock,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<usize>,
    /// Unix seconds when the agent empties itself; absent without a limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
    /// Titles of the items it holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub titles: Option<Vec<String>>,
    /// Ids (base64) chosen at `unlock ITEM…`; absent when it holds every
    /// marked item, so that a newly marked one joins on refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection: Option<Vec<String>>,
}

/// What `unlock` hands the agent.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Load {
    pub selection: Option<Vec<String>>,
    pub items: Vec<Item>,
}

impl Response {
    fn error(message: impl Into<String>) -> Self {
        Self {
            error: Some(message.into()),
            ..Self::default()
        }
    }
}

pub(crate) fn socket_dir() -> Result<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|d| !d.is_empty())
        .ok_or("XDG_RUNTIME_DIR is not set; the agent needs a private runtime directory")?;
    Ok(PathBuf::from(runtime).join("passforme"))
}

fn socket_path() -> Result<PathBuf> {
    Ok(socket_dir()?.join("agent.sock"))
}

/// Sends one request. `None` when no agent is running.
pub fn request(request: &Request) -> Result<Option<Response>> {
    call(&socket_path()?, request)
}

/// One JSON request to the daemon listening on `path`, one JSON answer.
/// `None` when nothing listens there.
pub(crate) fn call<Q: Serialize, A: serde::de::DeserializeOwned>(
    path: &std::path::Path,
    request: &Q,
) -> Result<Option<A>> {
    let mut stream = match UnixStream::connect(path) {
        Ok(stream) => stream,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(crate::error::Error::Io(path.to_owned(), e)),
    };
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut line = serde_json::to_vec(request).expect("requests serialize");
    line.push(b'\n');
    stream.write_all(&line)?;
    let mut answer = Zeroizing::new(String::new());
    stream.read_to_string(&mut answer)?;
    serde_json::from_str(&answer)
        .map(Some)
        .map_err(|e| format!("unexpected answer from {}: {e}", path.display()).into())
}

/// Replaces any running agent with one holding `load` for `secs`, or
/// until `lock` when `None`.
pub fn start(load: &Load, secs: Option<u64>) -> Result<()> {
    let _ = request(&Request::Lock);
    let mut child = Command::new(std::env::current_exe()?)
        .args(["__agent", &secs.unwrap_or(0).to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        // Its own process group: Ctrl-C in this terminal must not kill it.
        .process_group(0)
        .spawn()?;
    let payload = Zeroizing::new(serde_json::to_vec(load).expect("items serialize"));
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin.write_all(&payload)?;
    drop(stdin);
    let mut ready = String::new();
    BufReader::new(child.stdout.take().expect("stdout is piped")).read_line(&mut ready)?;
    if ready.trim() == "ready" {
        Ok(())
    } else {
        let _ = child.kill();
        Err(format!("the agent did not start: {}", ready.trim()).into())
    }
}

type Held = Arc<Mutex<Option<Vec<Item>>>>;

/// Body of `__agent`: runs detached until its time is up or `lock`. Its
/// stderr goes nowhere, so a startup failure is reported on the line where
/// `start` waits for "ready". `secs` 0 means no time limit.
pub fn serve(secs: u64) -> Result<()> {
    let (listener, path, held, selection) = match listen() {
        Ok(ready) => ready,
        Err(e) => {
            println!("{e}");
            return Err(e);
        }
    };
    let expires = (secs > 0).then(|| crate::now() + secs);
    let inode = fs::metadata(&path)?.ino();
    {
        let held = Arc::clone(&held);
        let path = path.clone();
        std::thread::spawn(move || watch(&held, &path, inode, expires));
    }
    println!("ready");
    io::stdout().flush()?;

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if handle(&stream, &held, expires, selection.as_ref()) {
            shutdown(&held, &path);
        }
    }
    Ok(())
}

/// Ends the agent when its time is up or its socket is gone or replaced.
fn watch(held: &Held, path: &PathBuf, inode: u64, expires: Option<u64>) -> ! {
    loop {
        let now = crate::now();
        if expires.is_some_and(|at| now >= at)
            || fs::metadata(path).map_or(true, |m| m.ino() != inode)
        {
            shutdown(held, path);
        }
        let until_expiry = expires.map_or(WATCH_SECS, |at| at - now);
        std::thread::sleep(Duration::from_secs(until_expiry.min(WATCH_SECS)));
    }
}

type Selection = Option<Vec<String>>;

/// Reads the items from stdin and binds the private socket.
fn listen() -> Result<(UnixListener, PathBuf, Held, Selection)> {
    let mut payload = Zeroizing::new(Vec::new());
    io::stdin().read_to_end(&mut payload)?;
    let Load { selection, items } =
        serde_json::from_slice(&payload).map_err(|e| format!("bad items: {e}"))?;
    drop(payload);
    let (listener, path) = bind_private("agent.sock")?;
    Ok((listener, path, Arc::new(Mutex::new(Some(items))), selection))
}

/// Binds `name` in the private runtime directory (0700, this user's),
/// with the socket itself 0600.
pub(crate) fn bind_private(name: &str) -> Result<(UnixListener, PathBuf)> {
    let dir = socket_dir()?;
    DirBuilder::new().mode(0o700).recursive(true).create(&dir)?;
    let meta = fs::metadata(&dir)?;
    if meta.uid() != rustix::process::getuid().as_raw() || meta.mode() & 0o077 != 0 {
        return Err(format!("{} must be private to this user", dir.display()).into());
    }
    let path = dir.join(name);
    let _ = fs::remove_file(&path); // a socket left by a daemon that died
    let listener =
        UnixListener::bind(&path).map_err(|e| crate::error::Error::Io(path.clone(), e))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok((listener, path))
}

/// Whether the other end of `stream` runs as this user (`SO_PEERCRED`).
pub(crate) fn same_user(stream: &UnixStream) -> bool {
    rustix::net::sockopt::socket_peercred(stream)
        .is_ok_and(|cred| cred.uid == rustix::process::getuid())
}

/// Wipes the items (they zeroize on drop), removes the socket, exits.
fn shutdown(held: &Held, path: &PathBuf) -> ! {
    let mut guard = held
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    drop(guard.take());
    let _ = fs::remove_file(path);
    std::process::exit(0);
}

/// Answers one connection; true when it asked the agent to lock.
fn handle(
    stream: &UnixStream,
    held: &Held,
    expires: Option<u64>,
    selection: Option<&Vec<String>>,
) -> bool {
    if !same_user(stream) {
        return false;
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut line = Zeroizing::new(String::new());
    let mut reader = BufReader::new(stream.take(REQUEST_LIMIT));
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    let (response, lock) = match serde_json::from_str::<Request>(&line) {
        Ok(Request::Lock) => (
            Response {
                ok: true,
                ..Response::default()
            },
            true,
        ),
        Ok(Request::Status) => {
            let titles: Vec<String> = held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .map(|items| items.iter().map(|i| i.title.clone()).collect())
                .unwrap_or_default();
            (
                Response {
                    ok: true,
                    items: Some(titles.len()),
                    expires,
                    titles: Some(titles),
                    selection: selection.cloned(),
                    ..Response::default()
                },
                false,
            )
        }
        Ok(Request::Get { query, field }) => (answer_get(held, &query, &field), false),
        Err(e) => (Response::error(format!("bad request: {e}")), false),
    };
    let mut out = Zeroizing::new(serde_json::to_vec(&response).expect("responses serialize"));
    out.push(b'\n');
    let _ = { stream }.write_all(&out);
    if let Some(value) = response.value {
        drop(Zeroizing::new(value));
    }
    lock
}

fn answer_get(held: &Held, query: &str, field: &str) -> Response {
    let guard = held
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(items) = guard.as_ref() else {
        return Response::error("the agent is locked");
    };
    let titles: Vec<&str> = items.iter().map(|i| i.title.as_str()).collect();
    let item = match crate::pick_index(&titles, query) {
        Ok(index) => &items[index],
        Err(_) => {
            return Response::error(format!(
                "no item matching '{query}' is available to the agent \
                 (mark it with `passforme edit ITEM --agent`, then `passforme unlock`)"
            ));
        }
    };
    match crate::field_value(item, Some(field)) {
        Ok((_, value)) => Response {
            ok: true,
            value: Some(value.to_string()),
            ..Response::default()
        },
        Err(e) => Response::error(e.to_string()),
    }
}
