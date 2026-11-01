//! The session keeper: after the master password opens the vault at a
//! terminal, the next commands stop asking for it until the vault sits
//! unused for a while (15 min by default), the screen locks, or
//! `passforme lock` — like `sudo` remembering a password for a few minutes.
//!
//! Unlike the unlock agent (`agent.rs`), which holds only the items marked
//! for programs, the keeper holds the **master password**, so it opens the
//! whole vault. Hence:
//!
//! - It is a separate process with its own socket, `session.sock`, next to
//!   the agent's (same private directory, 0600, `SO_PEERCRED`). Locking one
//!   never hands its contents to the other.
//! - Only commands run at a terminal ask it. `get --stdout` without a
//!   terminal (a program reading its API key) never does: programs stay limited
//!   to the agent's marked items.
//! - It keeps the password, not a derived key: every command still runs
//!   Argon2 (about 0.6 s), but syncing, which may have to open the server's
//!   copy, works exactly as with a typed password. For this vault the
//!   password and its keys are worth the same to a thief; the phrase is
//!   used nowhere else.
//! - It locks itself when idle for its time (each use starts it again;
//!   wall-clock time, so a suspend longer than that locks it too), when a
//!   screen locker runs (`hyprlock` and the like; `hypridle` usually
//!   locks the screen before a suspend as well), when its socket is
//!   gone, and on `lock`. `passwd` locks it.
//!
//! Same-user malware can ask it for the password while it runs; that is
//! the cost of not typing it, as in every password manager with an unlock
//! timeout, and the idle time bounds the window.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::agent;
use crate::error::Result;

pub const DEFAULT_IDLE_SECS: u64 = 15 * 60;
/// How often the keeper looks for a screen locker and its socket.
const WATCH_SECS: u64 = 2;
const REQUEST_LIMIT: u64 = 1024;
/// Screen lockers whose presence means "the user walked away".
const LOCKERS: &[&str] = &["hyprlock", "swaylock", "gtklock", "waylock", "i3lock"];

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum Request {
    Password,
    Status,
    Lock,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    /// Unix seconds when it locks unless used again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires: Option<u64>,
    /// Its idle time, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    idle: Option<u64>,
}

fn socket_path() -> Result<PathBuf> {
    Ok(agent::socket_dir()?.join("session.sock"))
}

fn call(request: &Request) -> Result<Option<Response>> {
    agent::call(&socket_path()?, request)
}

/// The master password, if a session is open; the session starts its idle
/// time again. Any failure counts as no session: the caller just asks.
pub fn password() -> Option<SecretString> {
    match call(&Request::Password) {
        Ok(Some(Response {
            ok: true,
            password: Some(password),
            ..
        })) => Some(SecretString::from(password)),
        _ => None,
    }
}

/// When an open session locks unless used, and its idle time.
pub fn status() -> Result<Option<(u64, u64)>> {
    Ok(call(&Request::Status)?.and_then(|r| Some((r.expires?, r.idle?))))
}

/// Ends the session; true when one was open.
pub fn lock() -> Result<bool> {
    Ok(call(&Request::Lock)?.is_some())
}

/// Opens a session holding `password` (already checked against the vault),
/// replacing any open one.
pub fn start(password: &SecretString, idle_secs: u64) -> Result<()> {
    let _ = lock();
    let mut child = Command::new(std::env::current_exe()?)
        .args(["__session", &idle_secs.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        // Its own process group: Ctrl-C in this terminal must not kill it.
        .process_group(0)
        .spawn()?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin.write_all(password.expose_secret().as_bytes())?;
    drop(stdin);
    let mut ready = String::new();
    BufReader::new(child.stdout.take().expect("stdout is piped")).read_line(&mut ready)?;
    if ready.trim() == "ready" {
        Ok(())
    } else {
        let _ = child.kill();
        Err(format!("the session did not start: {}", ready.trim()).into())
    }
}

/// What the keeper holds: the password, and when it locks.
struct State {
    password: Option<SecretString>,
    expires: u64,
}

type Shared = Arc<Mutex<State>>;

/// Body of `__session`: runs detached until it locks. A startup failure is
/// reported on the line where `start` waits for "ready".
pub fn serve(idle_secs: u64) -> Result<()> {
    let setup = || -> Result<_> {
        let mut text = Zeroizing::new(String::new());
        io::stdin().take(4096).read_to_string(&mut text)?;
        if text.is_empty() {
            return Err("no password given".into());
        }
        let password = SecretString::from(text.as_str());
        let (listener, path) = agent::bind_private("session.sock")?;
        Ok((listener, path, password))
    };
    let (listener, path, password) = match setup() {
        Ok(ready) => ready,
        Err(e) => {
            println!("{e}");
            return Err(e);
        }
    };
    let state = Arc::new(Mutex::new(State {
        password: Some(password),
        expires: crate::now() + idle_secs,
    }));
    let inode = fs::metadata(&path)?.ino();
    {
        let state = Arc::clone(&state);
        let path = path.clone();
        std::thread::spawn(move || watch(&state, &path, inode));
    }
    println!("ready");
    io::stdout().flush()?;

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if handle(&stream, &state, idle_secs) {
            shutdown(&state, &path);
        }
    }
    Ok(())
}

fn watch(state: &Shared, path: &Path, inode: u64) -> ! {
    loop {
        let expires = state.lock().unwrap_or_else(PoisonError::into_inner).expires;
        if crate::now() >= expires
            || fs::metadata(path).map_or(true, |m| m.ino() != inode)
            || screen_locked()
        {
            shutdown(state, path);
        }
        std::thread::sleep(Duration::from_secs(WATCH_SECS));
    }
}

/// Whether a screen locker of this user is running.
fn screen_locked() -> bool {
    let uid = rustix::process::getuid().as_raw();
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    entries.flatten().any(|entry| {
        let pid_dir = entry.path();
        entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
            && fs::metadata(&pid_dir).is_ok_and(|m| m.uid() == uid)
            && fs::read_to_string(pid_dir.join("comm"))
                .is_ok_and(|comm| LOCKERS.contains(&comm.trim_end()))
    })
}

/// Wipes the password (it zeroizes on drop), removes the socket, exits.
fn shutdown(state: &Shared, path: &Path) -> ! {
    let mut guard = state.lock().unwrap_or_else(PoisonError::into_inner);
    drop(guard.password.take());
    let _ = fs::remove_file(path);
    std::process::exit(0);
}

/// Answers one connection; true when the keeper must lock.
fn handle(stream: &UnixStream, state: &Shared, idle_secs: u64) -> bool {
    if !agent::same_user(stream) {
        return false;
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut line = String::new();
    if BufReader::new(stream.take(REQUEST_LIMIT))
        .read_line(&mut line)
        .is_err()
    {
        return false;
    }
    let now = crate::now();
    let mut guard = state.lock().unwrap_or_else(PoisonError::into_inner);
    // Time is checked here too, not only by the watcher: after a suspend
    // the first request may arrive before the watcher wakes up.
    let expired = now >= guard.expires;
    let (response, lock) = match serde_json::from_str::<Request>(&line) {
        Ok(Request::Lock) => (
            Response {
                ok: true,
                ..Response::default()
            },
            true,
        ),
        Ok(_) if expired => (Response::default(), true),
        Ok(Request::Status) => (
            Response {
                ok: true,
                expires: Some(guard.expires),
                idle: Some(idle_secs),
                ..Response::default()
            },
            false,
        ),
        Ok(Request::Password) => {
            guard.expires = now + idle_secs;
            (
                Response {
                    ok: true,
                    password: guard
                        .password
                        .as_ref()
                        .map(|p| p.expose_secret().to_owned()),
                    ..Response::default()
                },
                false,
            )
        }
        Err(_) => (Response::default(), false),
    };
    drop(guard);
    let mut out = Zeroizing::new(serde_json::to_vec(&response).expect("responses serialize"));
    out.push(b'\n');
    let _ = { stream }.write_all(&out);
    if let Some(password) = response.password {
        drop(Zeroizing::new(password));
    }
    lock
}
