//! Linking a vault to a sync server and keeping the two in step.
//!
//! - `register URL`: puts this device's vault on an empty server (needs the
//!   single-use invite printed by `passforme-server invite`).
//! - `login URL`: sets up a new device from the server, with the Secret Key
//!   from the Emergency Kit and the master password.
//! - `sync`: three-way merge (`passforme_core::sync`) of this device's
//!   changes into the server's copy, then both sides store the result.
//!
//! The server never sees anything it could decrypt: it gets the vault file
//! (ciphertext) and the auth key, which HKDF keeps unrelated to the keys
//! that open the vault.

use base64ct::{Base64, Encoding};
use getrandom::SysRng;
use passforme_core::api::{PutVault, Register, VaultResponse};
use passforme_core::kdf::{self, SecretKey};
use passforme_core::sync::{MergeReport, merge};
use passforme_core::vault::{UnlockedVault, VaultFile};
use rand_core::UnwrapErr;
use secrecy::ExposeSecret;

use crate::error::Result;
use crate::prompt;
use crate::remote::{Fetch, Put, Remote};
use crate::session::Session;
use crate::store::{Store, SyncState};

/// Retries when another device uploads between our download and upload.
const ATTEMPTS: usize = 3;

pub struct Summary {
    url: String,
    revision: u64,
    pulled: usize,
    report: MergeReport,
    password_changed_elsewhere: bool,
}

impl Summary {
    pub fn print(&self) {
        let pushed = self.report.pushed;
        if pushed == 0 && self.pulled == 0 {
            eprintln!("In sync with {} (revision {}).", self.url, self.revision);
        } else {
            eprintln!(
                "Synced with {} (revision {}): {pushed} change(s) sent, {} item(s) updated from the server.",
                self.url, self.revision, self.pulled
            );
        }
        for title in &self.report.conflicts {
            eprintln!(
                "Conflict: '{title}' changed here and elsewhere; the other version is kept, \
                 yours is now '{title} (conflict)'."
            );
        }
        for title in &self.report.kept_after_remote_edit {
            eprintln!("Kept: '{title}' was deleted here but changed elsewhere.");
        }
        if self.password_changed_elsewhere {
            eprintln!("The master password now is the one set on the other device.");
        }
    }
}

fn vault_text(file: &VaultFile) -> String {
    String::from_utf8(file.to_json()).expect("the vault file is UTF-8 JSON")
}

pub fn register(url: &str) -> Result<()> {
    let remote = Remote::new(url)?;
    let store = Store::locate()?;
    if let Some(state) = store.sync_state()? {
        return Err(format!("this vault is already linked to {}", state.url).into());
    }
    let session = Session::open()?;
    let invite = prompt::secret("Invite (from `passforme-server invite`): ")?;
    let file = session.vault.file();
    let revision = remote.register(&Register {
        invite: invite.expose_secret().trim().to_owned(),
        auth_key: Base64::encode_string(session.vault.auth_key().to_server()),
        vault: vault_text(file),
    })?;
    store.save_sync(
        &SyncState {
            url: remote.url().to_owned(),
            revision,
        },
        file,
    )?;
    eprintln!("Vault stored on {} and linked.", remote.url());
    Ok(())
}

pub fn login(url: &str) -> Result<()> {
    let remote = Remote::new(url)?;
    let store = Store::locate()?;
    if store.exists() {
        return Err(format!(
            "this device already has a vault at {}",
            store.vault_path().display()
        )
        .into());
    }
    let (account_id, salt, params) = remote.prelogin()?.parse()?;
    let kit = prompt::secret("Secret Key (SB1-…, from the Emergency Kit): ")?;
    let secret_key = SecretKey::from_kit(kit.expose_secret())?;
    let password = prompt::secret("Master password: ")?;
    let keys = kdf::derive_keys(&password, &secret_key, &salt, &account_id, &params)?;
    let Fetch::Vault(response) = remote.get_vault(&keys.auth_key)? else {
        return Err("wrong master password or Secret Key".into());
    };
    let file = VaultFile::from_json(response.vault.as_bytes())?;
    if file.account_id != account_id {
        return Err("the server answered with another account's vault".into());
    }
    let vault = UnlockedVault::unlock(file, &password, &secret_key)?;
    store.create_secret_key(&secret_key)?;
    store.save_vault(vault.file())?;
    store.save_sync(
        &SyncState {
            url: remote.url().to_owned(),
            revision: response.revision,
        },
        vault.file(),
    )?;
    eprintln!(
        "Logged in: {} item(s) from {}.",
        vault.file().records.len(),
        remote.url()
    );
    Ok(())
}

/// Syncs `session` with its server; on success the session holds the merged
/// vault (and the current master password, if it changed elsewhere).
pub fn sync(session: &mut Session) -> Result<Summary> {
    let state = session
        .store
        .sync_state()?
        .ok_or("this vault is not linked to a server; see `passforme register`")?;
    let remote = Remote::new(&state.url)?;
    let base = session.store.sync_base()?;
    if session.vault.file().salt != base.salt {
        return Err("the master password changed here without the server; run `passforme passwd` again while online".into());
    }
    let mut password_changed_elsewhere = false;

    for _ in 0..ATTEMPTS {
        let (response, changed_elsewhere) = fetch(&remote, session)?;
        password_changed_elsewhere |= changed_elsewhere;
        if response.revision < state.revision {
            return Err(format!(
                "the server returned revision {} but revision {} was seen before: \
                 refusing an older vault (rollback?)",
                response.revision, state.revision
            )
            .into());
        }

        let (merged, pulled, report) = if response.revision == state.revision {
            // Nothing new on the server: it must still hold exactly the base.
            if response.vault != vault_text(&base) {
                return Err(
                    "the server changed the vault without a new revision; refusing it".into(),
                );
            }
            let changed = session.vault.file() != &base;
            let report = MergeReport {
                pushed: usize::from(changed),
                ..MergeReport::default()
            };
            (None, 0, report)
        } else {
            let file = VaultFile::from_json(response.vault.as_bytes())?;
            if file.account_id != session.vault.file().account_id {
                return Err("the server answered with another account's vault".into());
            }
            let mut remote_vault =
                UnlockedVault::unlock(file, &session.password, &session.secret_key)?;
            // What the server changed since the base: new or edited items,
            // plus deleted ones.
            let base_revision = |id| base.records.iter().find(|b| b.id == id).map(|b| b.revision);
            let pulled = remote_vault
                .file()
                .records
                .iter()
                .filter(|r| base_revision(r.id) != Some(r.revision))
                .count()
                + base
                    .records
                    .iter()
                    .filter(|b| remote_vault.revision_of(&b.id).is_none())
                    .count();
            let report = merge(
                &base,
                &session.vault,
                &mut remote_vault,
                &mut UnwrapErr(SysRng),
            )?;
            (Some(remote_vault), pulled, report)
        };

        let revision = if report.is_empty() {
            response.revision
        } else {
            let upload = merged.as_ref().unwrap_or(&session.vault);
            let request = PutVault {
                base_revision: response.revision,
                vault: vault_text(upload.file()),
                new_auth_key: None,
            };
            match remote.put_vault(upload.auth_key(), &request)? {
                Put::Stored(revision) => revision,
                Put::Stale => continue,
            }
        };

        if let Some(merged) = merged {
            session.vault = merged;
        }
        // Vault first: a crash before the sync state is written only makes
        // the next sync see this device's changes again (a harmless repeat
        // or a conflict copy), never lose the server's.
        session.store.save_vault(session.vault.file())?;
        session.store.save_sync(
            &SyncState {
                url: state.url.clone(),
                revision,
            },
            session.vault.file(),
        )?;
        return Ok(Summary {
            url: state.url,
            revision,
            pulled,
            report,
            password_changed_elsewhere,
        });
    }
    Err("the server kept changing during the sync; try again".into())
}

/// Downloads the server's copy. When the server refuses this device's auth
/// key, the master password was changed on another device: asks for the
/// current one, and on success keeps it in the session (the `bool`).
fn fetch(remote: &Remote, session: &mut Session) -> Result<(VaultResponse, bool)> {
    if let Fetch::Vault(response) = remote.get_vault(session.vault.auth_key())? {
        return Ok((response, false));
    }
    eprintln!(
        "The server refused this device's key: the master password was changed on another device."
    );
    let password = prompt::secret("Current master password: ")?;
    let (account_id, salt, params) = remote.prelogin()?.parse()?;
    let keys = kdf::derive_keys(&password, &session.secret_key, &salt, &account_id, &params)?;
    let Fetch::Vault(response) = remote.get_vault(&keys.auth_key)? else {
        return Err("wrong master password".into());
    };
    // An open session holds the old password.
    if crate::keeper::lock()? {
        crate::session::open_session(&password);
    }
    session.password = password;
    Ok((response, true))
}

/// Changes the master password of a linked vault: sync first, rotate, then
/// upload with the old auth key while announcing the new one. Nothing is
/// saved on this device unless the server took it.
pub fn change_password(
    session: &mut Session,
    new_password: &secrecy::SecretString,
    params: &kdf::KdfParams,
) -> Result<()> {
    sync(session)?.print();
    let state = session
        .store
        .sync_state()?
        .expect("synced vaults are linked");
    let remote = Remote::new(&state.url)?;
    // Changed in place: if the server refuses, the command fails and this
    // session, never saved, is dropped with it.
    eprintln!("Re-encrypting the vault under a new key...");
    let old_auth = session.vault.change_password(
        new_password,
        &session.secret_key,
        params,
        &mut UnwrapErr(SysRng),
    )?;
    let request = PutVault {
        base_revision: state.revision,
        vault: vault_text(session.vault.file()),
        new_auth_key: Some(Base64::encode_string(session.vault.auth_key().to_server())),
    };
    let revision = match remote.put_vault(&old_auth, &request)? {
        Put::Stored(revision) => revision,
        Put::Stale => {
            return Err("the server changed during the password change; nothing was changed, run `passforme passwd` again".into());
        }
    };
    session.store.save_vault(session.vault.file())?;
    session.store.save_sync(
        &SyncState {
            url: state.url,
            revision,
        },
        session.vault.file(),
    )?;
    Ok(())
}
