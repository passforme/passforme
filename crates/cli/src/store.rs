//! Where the vault and the Secret Key live on this device, and how they are
//! written.
//!
//! `$PASSFORME_DIR`, or `$XDG_DATA_HOME/passforme`, or
//! `~/.local/share/passforme`, mode 0700, holding:
//!
//! - `vault.json` (0600): the vault file, ciphertext only; the previous
//!   version is kept as `vault.json.bak` on every write.
//! - `secret-key` (0600): the Secret Key in Emergency Kit text. A separate
//!   file so the vault file can be copied or synced without it.
//! - `sync.json` (0600), once linked to a server: its URL and the highest
//!   revision seen there (a lower one later means a rollback).
//! - `sync-base.json` (0600): the vault as of the last sync, the common
//!   ancestor of the three-way merge. Ciphertext, like `vault.json`.
//! - `agent-journal` (0600), while a writable unlock agent runs: what
//!   programs wrote through it, sealed, until a command that opens the
//!   vault brings it in (`passforme_core::journal`). A journal that could
//!   not be read whole is kept as `agent-journal.rejected`.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use passforme_core::kdf::SecretKey;
use passforme_core::vault::VaultFile;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub struct Store {
    dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncState {
    pub url: String,
    pub revision: u64,
}

impl Store {
    pub fn locate() -> Result<Self> {
        let dir = if let Some(dir) = std::env::var_os("PASSFORME_DIR") {
            PathBuf::from(dir)
        } else if let Some(data) = std::env::var_os("XDG_DATA_HOME").filter(|d| !d.is_empty()) {
            PathBuf::from(data).join("passforme")
        } else {
            let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
            PathBuf::from(home).join(".local/share/passforme")
        };
        Ok(Self { dir })
    }

    pub fn vault_path(&self) -> PathBuf {
        self.dir.join("vault.json")
    }

    fn secret_key_path(&self) -> PathBuf {
        self.dir.join("secret-key")
    }

    pub fn exists(&self) -> bool {
        self.vault_path().exists() || self.secret_key_path().exists()
    }

    pub fn load_vault(&self) -> Result<VaultFile> {
        let path = self.vault_path();
        let bytes = fs::read(&path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Error::from(format!(
                    "no vault at {}; create one with `passforme init`",
                    path.display()
                ))
            } else {
                Error::Io(path.clone(), e)
            }
        })?;
        Ok(VaultFile::from_json(&bytes)?)
    }

    pub fn load_secret_key(&self) -> Result<SecretKey> {
        let path = self.secret_key_path();
        check_private(&path)?;
        let text = Zeroizing::new(fs::read_to_string(&path).map_err(|e| Error::Io(path, e))?);
        Ok(SecretKey::from_kit(&text)?)
    }

    /// Writes a new Secret Key file; never replaces an existing one.
    pub fn create_secret_key(&self, key: &SecretKey) -> Result<()> {
        self.create_dir()?;
        let path = self.secret_key_path();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| Error::Io(path.clone(), e))?;
        let mut text = key.to_kit();
        text.push('\n');
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| Error::Io(path, e))?;
        sync_dir(&self.dir)
    }

    /// Replaces `vault.json` atomically: write a temporary file, flush it to
    /// disk, keep the current version as `.bak`, rename over. A crash
    /// leaves either the old vault or the new one, never half of one.
    pub fn save_vault(&self, file: &VaultFile) -> Result<()> {
        self.create_dir()?;
        let path = self.vault_path();
        let tmp = self.dir.join("vault.json.tmp");
        let io_err = |p: &Path| {
            let p = p.to_path_buf();
            move |e| Error::Io(p, e)
        };
        let mut out = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(io_err(&tmp))?;
        out.write_all(&file.to_json())
            .and_then(|()| out.sync_all())
            .map_err(io_err(&tmp))?;
        if path.exists() {
            let bak = self.dir.join("vault.json.bak");
            fs::copy(&path, &bak).map_err(io_err(&bak))?;
        }
        fs::rename(&tmp, &path).map_err(io_err(&path))?;
        sync_dir(&self.dir)
    }

    pub fn sync_state(&self) -> Result<Option<SyncState>> {
        let path = self.dir.join("sync.json");
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| format!("{}: {e}", path.display()).into()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(path, e)),
        }
    }

    pub fn sync_base(&self) -> Result<VaultFile> {
        let path = self.dir.join("sync-base.json");
        let bytes = fs::read(&path).map_err(|e| Error::Io(path, e))?;
        Ok(VaultFile::from_json(&bytes)?)
    }

    /// Records a completed sync: the base first, then the state that points
    /// at it.
    pub fn save_sync(&self, state: &SyncState, base: &VaultFile) -> Result<()> {
        self.create_dir()?;
        self.write_atomic("sync-base.json", &base.to_json())?;
        let mut json = serde_json::to_vec_pretty(state).expect("state serializes");
        json.push(b'\n');
        self.write_atomic("sync.json", &json)
    }

    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let path = self.dir.join(name);
        let tmp = self.dir.join(format!("{name}.tmp"));
        let mut out = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| Error::Io(tmp.clone(), e))?;
        out.write_all(bytes)
            .and_then(|()| out.sync_all())
            .map_err(|e| Error::Io(tmp.clone(), e))?;
        fs::rename(&tmp, &path).map_err(|e| Error::Io(path, e))?;
        sync_dir(&self.dir)
    }

    pub fn journal_path(&self) -> PathBuf {
        self.dir.join("agent-journal")
    }

    /// The agent journal, locked against the agent's appends for as long
    /// as the file returned is open, and its text. `None` without one.
    pub fn lock_journal(&self) -> Result<Option<(File, String)>> {
        use std::io::Read;
        let path = self.journal_path();
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::Io(path, e)),
        };
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
            .map_err(|e| Error::Io(path.clone(), e.into()))?;
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|e| Error::Io(path, e))?;
        Ok(Some((file, text)))
    }

    /// Starts a new journal with `head` as its first line, replacing any
    /// other: an agent still appending to the old one notices and stops.
    pub fn start_journal(&self, head: &str) -> Result<()> {
        self.create_dir()?;
        self.write_atomic("agent-journal", format!("{head}\n").as_bytes())
    }

    pub fn remove_journal(&self) -> Result<()> {
        let path = self.journal_path();
        match fs::remove_file(&path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(Error::Io(path, e)),
            _ => sync_dir(&self.dir),
        }
    }

    /// Keeps a copy of a journal that could not be read whole, and says
    /// where.
    pub fn keep_rejected_journal(&self) -> Result<PathBuf> {
        let kept = self.dir.join("agent-journal.rejected");
        fs::copy(self.journal_path(), &kept).map_err(|e| Error::Io(kept.clone(), e))?;
        Ok(kept)
    }

    /// Deletes `vault.json.bak`, if any.
    pub fn remove_backup(&self) -> Result<()> {
        let bak = self.dir.join("vault.json.bak");
        match fs::remove_file(&bak) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(Error::Io(bak, e)),
            _ => sync_dir(&self.dir),
        }
    }

    fn create_dir(&self) -> Result<()> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .map_err(|e| Error::Io(self.dir.clone(), e))
    }
}

/// Refuses a Secret Key file others can read, as ssh does with private keys.
fn check_private(path: &Path) -> Result<()> {
    let mode = fs::metadata(path)
        .map_err(|e| Error::Io(path.to_path_buf(), e))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "{} is accessible by other users (mode {:o}); run `chmod 600` on it",
            path.display(),
            mode & 0o777
        )
        .into());
    }
    Ok(())
}

/// Makes a rename or a new file in `dir` durable.
fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| Error::Io(dir.to_path_buf(), e))
}
