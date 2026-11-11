//! The vault file and the operations on an unlocked vault.
//!
//! The file is JSON with every binary value in base64. It holds only what
//! the server will hold too: public parameters and ciphertext. Titles are
//! inside the sealed items, so even the list of what is stored is secret.
//!
//! ```json
//! {
//!   "format": 1,
//!   "account_id": "…", "salt": "…",
//!   "kdf": { "memory_kib": 262144, "iterations": 3, "parallelism": 1 },
//!   "vault_key": "…",
//!   "items": [ { "id": "…", "revision": 1, "sealed": "…" } ]
//! }
//! ```

use std::collections::HashSet;
use std::fmt;

use base64ct::{Base64, Encoding};
use rand_core::CryptoRng;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::item::Item;
use crate::kdf::{self, AccountId, AuthKey, KdfError, KdfParams, Salt, SecretKey};
use crate::seal::{self, ItemId, JournalId, JournalKey, SealError, Sealed, VaultKey};

pub const FILE_FORMAT: u32 = 1;

#[derive(Debug)]
pub enum VaultError {
    /// The file is not a vault this version understands.
    Format(String),
    Kdf(KdfError),
    /// The vault key did not open: wrong master password or Secret Key (or
    /// a tampered file; the two cannot be told apart).
    WrongCredentials,
    /// An item did not open with a key that opened the vault: tampering.
    Corrupt(ItemId),
    NotFound,
    Seal(SealError),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(why) => write!(f, "not a valid vault file: {why}"),
            Self::Kdf(e) => e.fmt(f),
            Self::WrongCredentials => f.write_str("wrong master password or Secret Key"),
            Self::Corrupt(id) => write!(
                f,
                "item {} failed authentication: the vault file was modified",
                Base64::encode_string(id.as_bytes())
            ),
            Self::NotFound => f.write_str("no such item"),
            Self::Seal(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<KdfError> for VaultError {
    fn from(e: KdfError) -> Self {
        Self::Kdf(e)
    }
}

impl From<SealError> for VaultError {
    fn from(e: SealError) -> Self {
        Self::Seal(e)
    }
}

/// One sealed item as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub id: ItemId,
    pub revision: u64,
    pub sealed: Sealed,
}

/// The vault as stored: safe to write anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultFile {
    pub account_id: AccountId,
    pub salt: Salt,
    pub kdf: KdfParams,
    pub vault_key: Sealed,
    pub records: Vec<Record>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileJson {
    format: u32,
    account_id: String,
    salt: String,
    kdf: KdfJson,
    vault_key: String,
    items: Vec<RecordJson>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfJson {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordJson {
    id: String,
    revision: u64,
    sealed: String,
}

fn decode_fixed<const N: usize>(what: &str, text: &str) -> Result<[u8; N], VaultError> {
    Base64::decode_vec(text)
        .ok()
        .and_then(|v| <[u8; N]>::try_from(v).ok())
        .ok_or_else(|| VaultError::Format(format!("bad {what}")))
}

fn decode_sealed(what: &str, text: &str) -> Result<Sealed, VaultError> {
    Base64::decode_vec(text)
        .ok()
        .and_then(|v| Sealed::from_bytes(v).ok())
        .ok_or_else(|| VaultError::Format(format!("bad {what}")))
}

impl VaultFile {
    pub fn to_json(&self) -> Vec<u8> {
        let file = FileJson {
            format: FILE_FORMAT,
            account_id: Base64::encode_string(self.account_id.as_bytes()),
            salt: Base64::encode_string(self.salt.as_bytes()),
            kdf: KdfJson {
                memory_kib: self.kdf.memory_kib(),
                iterations: self.kdf.iterations(),
                parallelism: self.kdf.parallelism(),
            },
            vault_key: Base64::encode_string(self.vault_key.as_bytes()),
            items: self
                .records
                .iter()
                .map(|r| RecordJson {
                    id: Base64::encode_string(r.id.as_bytes()),
                    revision: r.revision,
                    sealed: Base64::encode_string(r.sealed.as_bytes()),
                })
                .collect(),
        };
        let mut out = serde_json::to_vec_pretty(&file).expect("the file always serializes");
        out.push(b'\n');
        out
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, VaultError> {
        let file: FileJson =
            serde_json::from_slice(bytes).map_err(|e| VaultError::Format(e.to_string()))?;
        if file.format != FILE_FORMAT {
            return Err(VaultError::Format(format!(
                "format {} is not supported (expected {FILE_FORMAT})",
                file.format
            )));
        }
        let mut seen = HashSet::new();
        let records = file
            .items
            .iter()
            .map(|r| {
                let id = ItemId::from_bytes(decode_fixed("item id", &r.id)?);
                if !seen.insert(id) {
                    return Err(VaultError::Format("duplicate item id".into()));
                }
                Ok(Record {
                    id,
                    revision: r.revision,
                    sealed: decode_sealed("item", &r.sealed)?,
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            account_id: AccountId::from_bytes(decode_fixed("account id", &file.account_id)?),
            salt: Salt::from_bytes(decode_fixed("salt", &file.salt)?),
            kdf: KdfParams::new(
                file.kdf.memory_kib,
                file.kdf.iterations,
                file.kdf.parallelism,
            )?,
            vault_key: decode_sealed("vault key", &file.vault_key)?,
            records,
        })
    }
}

/// A vault whose key is in memory. Items are decrypted on demand, one call
/// at a time, and wiped when the caller drops them.
#[derive(Debug)]
pub struct UnlockedVault {
    file: VaultFile,
    vault_key: VaultKey,
    /// Derived with the wrap key; proves the account to the sync server.
    auth_key: AuthKey,
}

impl UnlockedVault {
    pub fn create<R: CryptoRng + ?Sized>(
        password: &SecretString,
        secret_key: &SecretKey,
        params: &KdfParams,
        rng: &mut R,
    ) -> Result<Self, VaultError> {
        let account_id = AccountId::generate(rng);
        let salt = Salt::generate(rng);
        let keys = kdf::derive_keys(password, secret_key, &salt, &account_id, params)?;
        let vault_key = VaultKey::generate(rng);
        let wrapped = seal::wrap_vault_key(&vault_key, &keys.wrap_key, &account_id, rng);
        Ok(Self {
            file: VaultFile {
                account_id,
                salt,
                kdf: *params,
                vault_key: wrapped,
                records: Vec::new(),
            },
            vault_key,
            auth_key: keys.auth_key,
        })
    }

    pub fn unlock(
        file: VaultFile,
        password: &SecretString,
        secret_key: &SecretKey,
    ) -> Result<Self, VaultError> {
        let keys = kdf::derive_keys(
            password,
            secret_key,
            &file.salt,
            &file.account_id,
            &file.kdf,
        )?;
        let vault_key = seal::unwrap_vault_key(&file.vault_key, &keys.wrap_key, &file.account_id)
            .map_err(|e| match e {
            SealError::Rejected => VaultError::WrongCredentials,
            other => VaultError::Seal(other),
        })?;
        Ok(Self {
            file,
            vault_key,
            auth_key: keys.auth_key,
        })
    }

    /// Changes the master password and **rotates the vault key**: fresh
    /// salt, fresh vault key, every item re-sealed under it at the next
    /// revision. Re-wrapping the old vault key would be enough to change the
    /// password, but then any older copy of the file (a backup, `.bak`, the
    /// server) would still open with the old password and yield the key
    /// that also protects everything written afterwards. With rotation, an
    /// old password opens old copies only. The Secret Key and the account
    /// id stay; the Argon2 parameters become `params`.
    ///
    /// Returns the auth key it replaced: the sync server still expects that
    /// one until it has been told the new one.
    pub fn change_password<R: CryptoRng + ?Sized>(
        &mut self,
        new_password: &SecretString,
        secret_key: &SecretKey,
        params: &KdfParams,
        rng: &mut R,
    ) -> Result<AuthKey, VaultError> {
        let items = self.items()?;
        let salt = Salt::generate(rng);
        let keys = kdf::derive_keys(
            new_password,
            secret_key,
            &salt,
            &self.file.account_id,
            params,
        )?;
        let vault_key = VaultKey::generate(rng);
        let mut records = Vec::with_capacity(items.len());
        for ((id, item), old) in items.iter().zip(&self.file.records) {
            let revision = old.revision + 1;
            let sealed = seal::seal_item(
                &vault_key,
                &self.file.account_id,
                id,
                revision,
                &item.to_plaintext(),
                rng,
            )?;
            records.push(Record {
                id: *id,
                revision,
                sealed,
            });
        }
        self.file.vault_key =
            seal::wrap_vault_key(&vault_key, &keys.wrap_key, &self.file.account_id, rng);
        self.file.salt = salt;
        self.file.kdf = *params;
        self.file.records = records;
        self.vault_key = vault_key;
        Ok(std::mem::replace(&mut self.auth_key, keys.auth_key))
    }

    pub fn file(&self) -> &VaultFile {
        &self.file
    }

    /// Every item, in stored order. One that fails to open aborts the whole
    /// listing: a tampered vault is reported, not partially shown.
    pub fn items(&self) -> Result<Vec<(ItemId, Item)>, VaultError> {
        self.file
            .records
            .iter()
            .map(|r| Ok((r.id, self.open(r)?)))
            .collect()
    }

    pub fn get(&self, id: &ItemId) -> Result<Item, VaultError> {
        self.open(self.record(id)?)
    }

    pub fn add<R: CryptoRng + ?Sized>(
        &mut self,
        item: &Item,
        rng: &mut R,
    ) -> Result<ItemId, VaultError> {
        let id = loop {
            let id = ItemId::generate(rng);
            if self.record(&id).is_err() {
                break id;
            }
        };
        let sealed = self.seal(&id, 1, item, rng)?;
        self.file.records.push(Record {
            id,
            revision: 1,
            sealed,
        });
        Ok(id)
    }

    pub fn update<R: CryptoRng + ?Sized>(
        &mut self,
        id: &ItemId,
        item: &Item,
        rng: &mut R,
    ) -> Result<(), VaultError> {
        let revision = self.record(id)?.revision + 1;
        let sealed = self.seal(id, revision, item, rng)?;
        let record = self
            .file
            .records
            .iter_mut()
            .find(|r| r.id == *id)
            .expect("checked above");
        record.revision = revision;
        record.sealed = sealed;
        Ok(())
    }

    pub fn remove(&mut self, id: &ItemId) -> Result<(), VaultError> {
        self.record(id)?;
        self.file.records.retain(|r| r.id != *id);
        Ok(())
    }

    pub fn auth_key(&self) -> &AuthKey {
        &self.auth_key
    }

    /// Wraps the key of a new agent journal under the vault key.
    pub fn wrap_journal_key<R: CryptoRng + ?Sized>(
        &self,
        journal_key: &JournalKey,
        journal_id: &JournalId,
        rng: &mut R,
    ) -> Sealed {
        seal::wrap_journal_key(
            journal_key,
            &self.vault_key,
            &self.file.account_id,
            journal_id,
            rng,
        )
    }

    /// The key of an agent journal written for this vault.
    pub fn unwrap_journal_key(
        &self,
        sealed: &Sealed,
        journal_id: &JournalId,
    ) -> Result<JournalKey, SealError> {
        seal::unwrap_journal_key(sealed, &self.vault_key, &self.file.account_id, journal_id)
    }

    /// The stored revision of an item, if it exists.
    pub fn revision_of(&self, id: &ItemId) -> Option<u64> {
        self.record(id).ok().map(|r| r.revision)
    }

    /// Stores `item` under a given id and revision: used by sync to bring
    /// back an item removed elsewhere or created on another device.
    pub fn insert<R: CryptoRng + ?Sized>(
        &mut self,
        id: ItemId,
        revision: u64,
        item: &Item,
        rng: &mut R,
    ) -> Result<(), VaultError> {
        if self.record(&id).is_ok() {
            return Err(VaultError::Format("duplicate item id".into()));
        }
        let sealed = self.seal(&id, revision, item, rng)?;
        self.file.records.push(Record {
            id,
            revision,
            sealed,
        });
        Ok(())
    }

    fn record(&self, id: &ItemId) -> Result<&Record, VaultError> {
        self.file
            .records
            .iter()
            .find(|r| r.id == *id)
            .ok_or(VaultError::NotFound)
    }

    fn open(&self, record: &Record) -> Result<Item, VaultError> {
        let plain = seal::open_item(
            &record.sealed,
            &self.vault_key,
            &self.file.account_id,
            &record.id,
            record.revision,
        )
        .map_err(|_| VaultError::Corrupt(record.id))?;
        Item::from_plaintext(&plain).map_err(|_| VaultError::Corrupt(record.id))
    }

    fn seal<R: CryptoRng + ?Sized>(
        &self,
        id: &ItemId,
        revision: u64,
        item: &Item,
        rng: &mut R,
    ) -> Result<Sealed, VaultError> {
        Ok(seal::seal_item(
            &self.vault_key,
            &self.file.account_id,
            id,
            revision,
            &item.to_plaintext(),
            rng,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom::SysRng;
    use rand_core::UnwrapErr;

    fn rng() -> UnwrapErr<SysRng> {
        UnwrapErr(SysRng)
    }

    /// The cheapest parameters the file accepts, to keep tests quick.
    fn params() -> KdfParams {
        KdfParams::new(KdfParams::MIN_MEMORY_KIB, KdfParams::MIN_ITERATIONS, 1).unwrap()
    }

    fn login(title: &str, password: &str) -> Item {
        let mut item = Item::default();
        item.title = title.into();
        item.password = password.into();
        item
    }

    fn new_vault() -> (UnlockedVault, SecretString, SecretKey) {
        let password = SecretString::from("master password");
        let secret_key = SecretKey::generate(&mut rng());
        let vault = UnlockedVault::create(&password, &secret_key, &params(), &mut rng()).unwrap();
        (vault, password, secret_key)
    }

    fn reload(vault: &UnlockedVault) -> VaultFile {
        VaultFile::from_json(&vault.file().to_json()).unwrap()
    }

    #[test]
    fn survives_a_round_trip_through_the_file() {
        let (mut vault, password, sk) = new_vault();
        let a = vault.add(&login("A", "pa"), &mut rng()).unwrap();
        let b = vault.add(&login("B", "pb"), &mut rng()).unwrap();
        let file = reload(&vault);
        assert_eq!(&file, vault.file());
        let reopened = UnlockedVault::unlock(file, &password, &sk).unwrap();
        let items = reopened.items().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!((items[0].0, items[0].1.password.as_str()), (a, "pa"));
        assert_eq!((items[1].0, items[1].1.password.as_str()), (b, "pb"));
    }

    #[test]
    fn the_file_holds_no_plaintext() {
        let (mut vault, _, _) = new_vault();
        vault
            .add(&login("Bank of Nowhere", "s3cr3t-value"), &mut rng())
            .unwrap();
        let json = String::from_utf8(vault.file().to_json()).unwrap();
        assert!(!json.contains("Nowhere"));
        assert!(!json.contains("s3cr3t"));
    }

    #[test]
    fn wrong_password_or_secret_key_is_refused() {
        let (vault, password, sk) = new_vault();
        let other_sk = SecretKey::generate(&mut rng());
        for (pw, key) in [
            (SecretString::from("master passworD"), &sk),
            (password, &other_sk),
        ] {
            let error = UnlockedVault::unlock(reload(&vault), &pw, key).unwrap_err();
            assert!(matches!(error, VaultError::WrongCredentials), "{error}");
        }
    }

    #[test]
    fn update_bumps_the_revision_and_remove_deletes() {
        let (mut vault, _, _) = new_vault();
        let id = vault.add(&login("A", "one"), &mut rng()).unwrap();
        vault.update(&id, &login("A", "two"), &mut rng()).unwrap();
        assert_eq!(vault.file().records[0].revision, 2);
        assert_eq!(vault.get(&id).unwrap().password, "two");
        vault.remove(&id).unwrap();
        assert!(matches!(vault.get(&id), Err(VaultError::NotFound)));
        assert!(matches!(vault.remove(&id), Err(VaultError::NotFound)));
    }

    #[test]
    fn swapped_or_rolled_back_items_are_detected() {
        let (mut vault, password, sk) = new_vault();
        let a = vault.add(&login("A", "pa"), &mut rng()).unwrap();
        vault.add(&login("B", "pb"), &mut rng()).unwrap();

        // Swap the ciphertexts of the two items.
        let mut file = reload(&vault);
        let first = file.records[0].sealed.clone();
        file.records[0].sealed = file.records[1].sealed.clone();
        file.records[1].sealed = first;
        let swapped = UnlockedVault::unlock(file, &password, &sk).unwrap();
        assert!(matches!(swapped.items(), Err(VaultError::Corrupt(id)) if id == a));

        // Put back revision 1 of an item under revision 2.
        let old = reload(&vault).records[0].sealed.clone();
        vault.update(&a, &login("A", "new"), &mut rng()).unwrap();
        let mut file = reload(&vault);
        file.records[0].sealed = old;
        let rolled = UnlockedVault::unlock(file, &password, &sk).unwrap();
        assert!(matches!(rolled.get(&a), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn change_password_rotates_everything() {
        let (mut vault, old_password, sk) = new_vault();
        let id = vault.add(&login("A", "pa"), &mut rng()).unwrap();
        let before = reload(&vault);
        let new_password = SecretString::from("a new master password");
        vault
            .change_password(&new_password, &sk, &params(), &mut rng())
            .unwrap();
        let after = reload(&vault);

        assert_eq!(after.account_id, before.account_id);
        assert_ne!(after.salt, before.salt);
        assert_ne!(after.vault_key, before.vault_key);
        assert_eq!(after.records[0].revision, 2);

        let reopened = UnlockedVault::unlock(after.clone(), &new_password, &sk).unwrap();
        assert_eq!(reopened.get(&id).unwrap().password, "pa");
        assert!(matches!(
            UnlockedVault::unlock(after.clone(), &old_password, &sk),
            Err(VaultError::WrongCredentials)
        ));
        // The old file still opens with the old password, but its vault key
        // no longer opens the new items.
        let old = UnlockedVault::unlock(before, &old_password, &sk).unwrap();
        let mut mixed = old.file().clone();
        mixed.records = after.records;
        let mixed = UnlockedVault::unlock(mixed, &old_password, &sk).unwrap();
        assert!(matches!(mixed.get(&id), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn bad_files_are_refused() {
        let (vault, _, _) = new_vault();
        let good = String::from_utf8(vault.file().to_json()).unwrap();
        for (bad, why) in [
            (
                good.replace("\"format\": 1", "\"format\": 2"),
                "not supported",
            ),
            (
                good.replace("\"iterations\": 2", "\"iterations\": 1"),
                "Argon2",
            ),
            (
                good.replace("\"items\": []", "\"items\": [], \"extra\": 0"),
                "unknown field",
            ),
            ("{}".to_owned(), "missing field"),
        ] {
            let error = VaultFile::from_json(bad.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(error.contains(why), "{error}");
        }
    }
}
