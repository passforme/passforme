//! The server's data directory. Nothing in it can decrypt anything.
//!
//! ```text
//! state.json       { revision, account_id, auth_hash }   the account
//! vault.json       the current vault file, exactly as uploaded
//! history/<rev>.json   the last HISTORY versions, for recovery from a bad sync
//! invite.json      { hash, expires }   a pending single-use invite, if any
//! ```
//!
//! Every write goes through a temporary file, `fsync` and `rename`, so a
//! crash leaves the old or the new version, never half of one.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Old vault versions kept in `history/`.
pub const HISTORY: u64 = 30;
pub const INVITE_TTL_SECS: u64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub revision: u64,
    pub account_id: String,
    pub auth_hash: String,
}

impl State {
    pub fn auth_hash(&self) -> Option<[u8; 32]> {
        Base64::decode_vec(&self.auth_hash)
            .ok()
            .and_then(|v| v.try_into().ok())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Invite {
    hash: String,
    expires: u64,
}

pub struct Storage {
    dir: PathBuf,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn invite_hash(token: &str) -> String {
    Base64::encode_string(&Sha256::digest(token.trim().as_bytes()))
}

impl Storage {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn state(&self) -> io::Result<Option<State>> {
        match fs::read(self.dir.join("state.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn vault(&self) -> io::Result<String> {
        fs::read_to_string(self.dir.join("vault.json"))
    }

    /// Stores a new vault and state; the previous vault goes to history.
    pub fn commit(&self, vault: &str, state: &State) -> io::Result<()> {
        let current = self.dir.join("vault.json");
        if let Some(old) = self.state()?.filter(|_| current.exists()) {
            let history = self.dir.join("history");
            fs::create_dir_all(&history)?;
            fs::copy(&current, history.join(format!("{}.json", old.revision)))?;
            if let Some(expired) = old.revision.checked_sub(HISTORY) {
                let _ = fs::remove_file(history.join(format!("{expired}.json")));
            }
        }
        // Vault first: a crash in between leaves a newer vault under the
        // older revision, which the next client upload simply replaces.
        write_atomic(&current, vault.as_bytes())?;
        write_atomic(
            &self.dir.join("state.json"),
            &serde_json::to_vec_pretty(state).expect("state serializes"),
        )
    }

    /// Creates a single-use invite and returns its token.
    pub fn create_invite(&self) -> io::Result<String> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(io::Error::other)?;
        let token = bytes.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write as _;
            write!(s, "{b:02x}").expect("writing to a String");
            s
        });
        let invite = Invite {
            hash: invite_hash(&token),
            expires: now() + INVITE_TTL_SECS,
        };
        write_atomic(
            &self.dir.join("invite.json"),
            &serde_json::to_vec(&invite).expect("invite serializes"),
        )?;
        Ok(token)
    }

    /// Checks and consumes the invite: true only once, before it expires.
    pub fn take_invite(&self, token: &str) -> io::Result<bool> {
        let path = self.dir.join("invite.json");
        let invite: Invite = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let expected: [u8; 32] = Base64::decode_vec(&invite.hash)
            .ok()
            .and_then(|v| v.try_into().ok())
            .unwrap_or([0; 32]);
        let given: [u8; 32] = Sha256::digest(token.trim().as_bytes()).into();
        let valid = passforme_core::api::equal(&expected, &given) && now() < invite.expires;
        if valid {
            fs::remove_file(&path)?;
        }
        Ok(valid)
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().expect("files live in the data directory");
    let tmp = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("passforme-storage-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn invites_are_single_use() {
        let dir = temp_dir("invite");
        let storage = Storage::new(dir.clone());
        assert!(!storage.take_invite("anything").unwrap());
        let token = storage.create_invite().unwrap();
        assert!(!storage.take_invite("wrong").unwrap());
        assert!(storage.take_invite(&token).unwrap());
        assert!(!storage.take_invite(&token).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn history_keeps_the_previous_versions() {
        let dir = temp_dir("history");
        let storage = Storage::new(dir.clone());
        for revision in 1..=HISTORY + 3 {
            let state = State {
                revision,
                account_id: String::new(),
                auth_hash: String::new(),
            };
            storage.commit(&format!("v{revision}"), &state).unwrap();
        }
        assert_eq!(storage.vault().unwrap(), format!("v{}", HISTORY + 3));
        let kept = fs::read_dir(dir.join("history")).unwrap().count();
        assert_eq!(u64::try_from(kept).unwrap(), HISTORY);
        assert!(!dir.join("history/1.json").exists());
        assert_eq!(
            fs::read_to_string(dir.join("history/32.json")).unwrap(),
            "v32"
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
