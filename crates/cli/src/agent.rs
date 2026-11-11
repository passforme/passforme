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
//!
//! **Writable** (`unlock --writable`): programs may also create items and
//! change the ones they created (an AI agent keeping the test accounts it
//! makes). The agent still has no vault key. It holds the key of a
//! *journal* (`passforme_core::journal`), appends every such item to it,
//! sealed, and the next command that opens the vault brings the journal
//! in. Items the owner created are never changed through the socket.

use std::fs::{self, DirBuilder};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64ct::{Base64, Encoding};
use getrandom::SysRng;
use passforme_core::item::{Item, Origin};
use passforme_core::journal;
use passforme_core::kdf::AccountId;
use passforme_core::seal::{ItemId, JournalId, JournalKey};
use rand_core::UnwrapErr;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Result;

/// How often the agent checks that its socket still exists.
const WATCH_SECS: u64 = 30;
/// Longest a request line may be: room for the largest agent-made item.
const REQUEST_LIMIT: u64 = 2 * journal::MAX_AGENT_ITEM_LEN as u64;
/// Longest timed `unlock --for` accepts; `forever` has no limit.
pub const MAX_SECS: u64 = 7 * 24 * 3600;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub enum Request {
    Get {
        query: String,
        field: String,
    },
    Status,
    Lock,
    /// What the agent holds, as the rows of `list`.
    List,
    /// A new agent-made item.
    Create {
        item: Item,
    },
    /// An agent-made item, whole, for a client about to change it.
    Fetch {
        query: String,
    },
    /// The agent-made item `id` as the client changed it.
    Replace {
        id: String,
        item: Item,
    },
    /// The next unused recovery code of an agent-made item, marked used.
    Code {
        query: String,
    },
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
    /// Whether programs may create items and change the ones they made.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub writable: bool,
    /// Writes waiting in the journal for a command that opens the vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<u64>,
    /// The agent is being restarted; the same request works in a moment.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub retry: bool,
    /// `Fetch`: the item and its id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<Item>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `List`: one row per item, as `list` prints them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<Vec<String>>>,
    /// `Code`: unused codes left.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<usize>,
}

/// What `unlock` hands the agent.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Load {
    pub selection: Option<Vec<String>>,
    pub items: Vec<Held>,
    /// Present for a writable agent.
    pub journal: Option<JournalLoad>,
}

/// An item and its id (base64) in the vault.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Held {
    pub id: String,
    pub item: Item,
}

/// The journal a writable agent appends to, and its bare key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalLoad {
    pub path: PathBuf,
    pub account_id: String,
    pub journal_id: String,
    /// Base64; wiped on drop.
    pub key: String,
}

impl Drop for JournalLoad {
    fn drop(&mut self) {
        self.key.zeroize();
    }
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
    let mut line = Zeroizing::new(serde_json::to_vec(request).expect("requests serialize"));
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

/// What the agent holds; `None` once emptied.
struct State {
    items: Vec<Held>,
    journal: Option<Journal>,
}

type Shared = Arc<Mutex<Option<State>>>;

/// The journal of a writable agent.
struct Journal {
    path: PathBuf,
    account_id: AccountId,
    id: JournalId,
    key: JournalKey,
    /// Place of the next entry.
    next: u64,
    /// A write failed halfway: the file may end in half a line, so nothing
    /// more is appended to it.
    broken: bool,
}

/// Why a write was refused: a sentence, and whether trying again helps.
struct Refused {
    why: String,
    retry: bool,
}

impl From<&str> for Refused {
    fn from(why: &str) -> Self {
        Self {
            why: why.to_owned(),
            retry: false,
        }
    }
}

impl From<String> for Refused {
    fn from(why: String) -> Self {
        Self { why, retry: false }
    }
}

impl Journal {
    fn open(load: &JournalLoad) -> Result<Self> {
        let fixed = |text: &str| {
            Base64::decode_vec(text)
                .ok()
                .and_then(|v| <[u8; 16]>::try_from(v).ok())
                .ok_or("bad journal")
        };
        let key = Zeroizing::new(Base64::decode_vec(&load.key).map_err(|_| "bad journal")?);
        Ok(Self {
            path: load.path.clone(),
            account_id: AccountId::from_bytes(fixed(&load.account_id)?),
            id: JournalId::from_bytes(fixed(&load.journal_id)?),
            key: JournalKey::from_bytes(&key).ok_or("bad journal")?,
            next: 0,
            broken: false,
        })
    }

    /// Appends `item` under `id`, durably, or changes nothing. The file is
    /// locked for the append, and must still be the one this agent was
    /// started with: a command that imported it has removed or replaced it,
    /// and is about to restart the agent.
    fn append(&mut self, id: &ItemId, item: &Item) -> std::result::Result<(), Refused> {
        use std::os::unix::fs::MetadataExt;
        let stale = || Refused {
            why: "the agent is being refreshed; try again".to_owned(),
            retry: true,
        };
        if self.broken {
            return Err(
                "the agent journal is damaged; run any passforme command in a terminal \
                        to import it"
                    .into(),
            );
        }
        let line = journal::seal_entry(
            &self.key,
            &self.account_id,
            &self.id,
            self.next,
            id,
            item,
            &mut UnwrapErr(SysRng),
        )
        .map_err(|e| e.to_string())?;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| stale())?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
            .map_err(|e| format!("cannot lock the agent journal: {e}"))?;
        let ours = file.metadata().map_err(|_| stale())?;
        if fs::metadata(&self.path).map_or(true, |m| m.ino() != ours.ino()) {
            return Err(stale());
        }
        if ours.len() + line.len() as u64 + 1 > journal::MAX_JOURNAL_LEN {
            return Err(
                "the agent journal is full; run any passforme command in a terminal to import it"
                    .into(),
            );
        }
        if let Err(e) = file
            .write_all(format!("{line}\n").as_bytes())
            .and_then(|()| file.sync_data())
        {
            self.broken = true;
            return Err(format!("cannot write the agent journal: {e}").into());
        }
        self.next += 1;
        Ok(())
    }
}

/// A copy of an item, which is deliberately not `Clone`.
fn copy(item: &Item) -> Item {
    Item::from_plaintext(&item.to_plaintext()).expect("an item's own JSON parses")
}

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
fn watch(held: &Shared, path: &PathBuf, inode: u64, expires: Option<u64>) -> ! {
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
fn listen() -> Result<(UnixListener, PathBuf, Shared, Selection)> {
    let mut payload = Zeroizing::new(Vec::new());
    io::stdin().read_to_end(&mut payload)?;
    let Load {
        selection,
        items,
        journal,
    } = serde_json::from_slice(&payload).map_err(|e| format!("bad items: {e}"))?;
    drop(payload);
    let journal = journal.as_ref().map(Journal::open).transpose()?;
    let (listener, path) = bind_private("agent.sock")?;
    let state = State { items, journal };
    Ok((listener, path, Arc::new(Mutex::new(Some(state))), selection))
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
fn shutdown(held: &Shared, path: &PathBuf) -> ! {
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
    held: &Shared,
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
    let request = serde_json::from_str::<Request>(&line);
    let lock = matches!(request, Ok(Request::Lock));
    let response = match request {
        Ok(Request::Lock) => Response {
            ok: true,
            ..Response::default()
        },
        Ok(request) => {
            let mut guard = held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match guard.as_mut() {
                Some(state) => answer(state, request, expires, selection),
                None => Response::error("the agent is locked"),
            }
        }
        Err(e) => Response::error(format!("bad request: {e}")),
    };
    let mut out = Zeroizing::new(serde_json::to_vec(&response).expect("responses serialize"));
    out.push(b'\n');
    let _ = { stream }.write_all(&out);
    if let Some(value) = response.value {
        drop(Zeroizing::new(value));
    }
    lock
}

fn answer(
    state: &mut State,
    request: Request,
    expires: Option<u64>,
    selection: Option<&Vec<String>>,
) -> Response {
    let ok = || Response {
        ok: true,
        ..Response::default()
    };
    let result = match request {
        Request::Lock => Ok(ok()),
        Request::Status => {
            let titles: Vec<String> = state.items.iter().map(|h| h.item.title.clone()).collect();
            Ok(Response {
                items: Some(titles.len()),
                expires,
                titles: Some(titles),
                selection: selection.cloned(),
                writable: state.journal.is_some(),
                pending: state.journal.as_ref().map(|j| j.next),
                ..ok()
            })
        }
        Request::List => Ok(Response {
            rows: Some(
                state
                    .items
                    .iter()
                    .map(|h| crate::list_row(&h.item).to_vec())
                    .collect(),
            ),
            ..ok()
        }),
        Request::Get { query, field } => get(state, &query, &field),
        Request::Create { item } => create(state, item).map(|()| ok()),
        Request::Fetch { query } => fetch(state, &query),
        Request::Replace { id, item } => replace(state, &id, item).map(|()| ok()),
        Request::Code { query } => code(state, &query),
    };
    result.unwrap_or_else(|refused| Response {
        retry: refused.retry,
        ..Response::error(refused.why)
    })
}

type Answer<T> = std::result::Result<T, Refused>;

/// Which held item `query` means: the owner's first, as everywhere.
fn pick(state: &State, query: &str) -> Answer<usize> {
    let titles: Vec<&str> = state.items.iter().map(|h| h.item.title.as_str()).collect();
    let made: Vec<bool> = state
        .items
        .iter()
        .map(|h| h.item.origin == Origin::Agent)
        .collect();
    crate::pick_tiered(&titles, &made, query).map_err(|e| {
        if e.to_string().starts_with("no item matches") {
            format!(
                "no item matching '{query}' is available to the agent \
                 (mark it with `passforme edit ITEM --agent`, then `passforme unlock`)"
            )
            .into()
        } else {
            e.to_string().into()
        }
    })
}

fn get(state: &State, query: &str, field: &str) -> Answer<Response> {
    let item = &state.items[pick(state, query)?].item;
    let (_, value) = crate::field_value(item, Some(field)).map_err(|e| e.to_string())?;
    Ok(Response {
        ok: true,
        value: Some(value.to_string()),
        ..Response::default()
    })
}

/// The journal, or why nothing can be written.
fn writable(state: &mut State) -> Answer<&mut Journal> {
    state.journal.as_mut().ok_or_else(|| {
        "the agent is read-only; the owner makes it writable with \
         `passforme unlock --writable`"
            .into()
    })
}

/// An agent-made item by query, or why it cannot be changed.
fn pick_made(state: &State, query: &str) -> Answer<usize> {
    let index = pick(state, query)?;
    let item = &state.items[index].item;
    if item.origin == Origin::Agent {
        Ok(index)
    } else {
        Err(format!(
            "'{}' is the owner's: a program can only change the items it made",
            item.title
        )
        .into())
    }
}

fn title_taken(state: &State, title: &str, except: Option<usize>) -> bool {
    state
        .items
        .iter()
        .enumerate()
        .any(|(n, h)| Some(n) != except && h.item.title.eq_ignore_ascii_case(title))
}

fn create(state: &mut State, mut item: Item) -> Answer<()> {
    writable(state)?;
    item.origin = Origin::Agent;
    item.agent = true;
    item.created = crate::now();
    item.modified = item.created;
    journal::check_item(&item).map_err(|why| format!("'{}' was refused: {why}", item.title))?;
    if title_taken(state, &item.title, None) {
        return Err(format!("an item called '{}' already exists", item.title).into());
    }
    let made = state
        .items
        .iter()
        .filter(|h| h.item.origin == Origin::Agent)
        .count();
    if made >= journal::MAX_AGENT_ITEMS {
        return Err(format!(
            "the agent space is full ({} items); the owner removes some with `passforme rm`",
            journal::MAX_AGENT_ITEMS
        )
        .into());
    }
    let (id, text) = loop {
        let id = ItemId::generate(&mut UnwrapErr(SysRng));
        let text = Base64::encode_string(id.as_bytes());
        if state.items.iter().all(|h| h.id != text) {
            break (id, text);
        }
    };
    writable(state)?.append(&id, &item)?;
    state.items.push(Held { id: text, item });
    Ok(())
}

fn fetch(state: &State, query: &str) -> Answer<Response> {
    let held = &state.items[pick_made(state, query)?];
    Ok(Response {
        ok: true,
        id: Some(held.id.clone()),
        item: Some(copy(&held.item)),
        ..Response::default()
    })
}

fn item_id(text: &str) -> Answer<ItemId> {
    Base64::decode_vec(text)
        .ok()
        .and_then(|v| <[u8; 16]>::try_from(v).ok())
        .map(ItemId::from_bytes)
        .ok_or_else(|| "bad item id".into())
}

fn replace(state: &mut State, id: &str, mut item: Item) -> Answer<()> {
    writable(state)?;
    let index = state
        .items
        .iter()
        .position(|h| h.id == id)
        .ok_or("no such item in the agent")?;
    let current = &state.items[index].item;
    if current.origin != Origin::Agent {
        return Err(format!(
            "'{}' is the owner's: a program can only change the items it made",
            current.title
        )
        .into());
    }
    item.origin = Origin::Agent;
    item.agent = true;
    item.created = current.created;
    item.modified = crate::now();
    journal::check_item(&item).map_err(|why| format!("'{}' was refused: {why}", item.title))?;
    if title_taken(state, &item.title, Some(index)) {
        return Err(format!("an item called '{}' already exists", item.title).into());
    }
    writable(state)?.append(&item_id(id)?, &item)?;
    state.items[index].item = item;
    Ok(())
}

/// The next unused code, marked used only once the journal has it.
fn code(state: &mut State, query: &str) -> Answer<Response> {
    writable(state)?;
    let index = pick_made(state, query)?;
    let held = &state.items[index];
    let Some(n) = held.item.codes.iter().position(|c| !c.used) else {
        return Err(if held.item.codes.is_empty() {
            format!("'{}' has no recovery codes", held.item.title)
        } else {
            format!("all codes of '{}' are used", held.item.title)
        }
        .into());
    };
    let mut item = copy(&held.item);
    item.codes[n].used = true;
    item.modified = crate::now();
    let id = item_id(&held.id)?;
    writable(state)?.append(&id, &item)?;
    let value = item.codes[n].code.clone();
    let left = item.codes.iter().filter(|c| !c.used).count();
    state.items[index].item = item;
    Ok(Response {
        ok: true,
        value: Some(value),
        left: Some(left),
        ..Response::default()
    })
}
