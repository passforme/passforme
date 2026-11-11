//! An unlocked vault and what it took to unlock it, for one command.

use passforme_core::kdf::SecretKey;
use passforme_core::vault::UnlockedVault;
use std::io::IsTerminal;

use secrecy::SecretString;

use crate::error::Result;
use crate::prompt;
use crate::store::Store;
use crate::sync;
use crate::{config, keeper};

pub struct Session {
    pub store: Store,
    pub vault: UnlockedVault,
    pub secret_key: SecretKey,
    /// Kept for the length of the command: syncing may need to open the
    /// server's copy, which uses the same password.
    pub password: SecretString,
}

impl Session {
    pub fn open() -> Result<Self> {
        let store = Store::locate()?;
        let file = store.load_vault()?;
        let secret_key = store.load_secret_key()?;
        let vault;
        let password;
        // A session is only used, and only opened, by commands at a
        // terminal: programs stay limited to the agent's marked items.
        let at_terminal = std::io::stdin().is_terminal();
        let kept = at_terminal.then(keeper::password).flatten();
        match kept.map(|p| UnlockedVault::unlock(file.clone(), &p, &secret_key).map(|v| (v, p))) {
            Some(Ok((v, p))) => {
                vault = v;
                password = p;
            }
            kept => {
                if kept.is_some() {
                    // The password changed since the session opened.
                    let _ = keeper::lock();
                }
                password = prompt::secret("Master password: ")?;
                vault = UnlockedVault::unlock(file, &password, &secret_key)?;
                if at_terminal {
                    open_session(&password);
                }
            }
        }
        let mut session = Self {
            store,
            vault,
            secret_key,
            password,
        };
        session.import_journal()?;
        Ok(session)
    }

    /// Brings in what programs wrote through a writable agent since the
    /// last command, and syncs it like any other change.
    fn import_journal(&mut self) -> Result<()> {
        if crate::settle_agent(self, crate::Restart::IfWaiting)?.imported {
            self.sync_or_warn();
        }
        Ok(())
    }

    pub(crate) fn sync_or_warn(&mut self) {
        match self.store.sync_state() {
            Ok(None) => {}
            Ok(Some(_)) => match sync::sync(self) {
                Ok(summary) => summary.print(),
                Err(e) => eprintln!(
                    "Saved on this device, but the sync failed: {e}\nRun `passforme sync` later."
                ),
            },
            Err(e) => eprintln!("Saved on this device, but not synced: {e}"),
        }
    }

    /// Saves a change on this device and, when the vault is linked to a
    /// server, syncs it. A failed sync is a warning: the change is safe here
    /// and goes up with the next `passforme sync`.
    pub fn commit(mut self) -> Result<()> {
        self.store.save_vault(self.vault.file())?;
        self.sync_or_warn();
        // A running agent is rebuilt from the vault; what programs wrote
        // through it meanwhile comes in first, and then goes up too.
        match crate::settle_agent(&mut self, crate::Restart::Refresh) {
            Ok(settled) if settled.imported => self.sync_or_warn(),
            Ok(_) => {}
            Err(e) => eprintln!("Could not refresh the agent ({e}); run `passforme unlock`."),
        }
        Ok(())
    }
}

/// Opens a session for the configured idle time; a failure only costs
/// typing the password again next time.
pub fn open_session(password: &SecretString) {
    let secs = match config::load() {
        Ok(config) => config.session_secs,
        Err(e) => {
            eprintln!("No session: {e}");
            return;
        }
    };
    if let Some(secs) = secs
        && let Err(e) = keeper::start(password, secs)
    {
        eprintln!("No session ({e}); the next command asks for the password again.");
    }
}
