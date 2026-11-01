//! The sync server's HTTP API, shared by the server and the clients.
//!
//! One account per server. Everything is JSON; binary values are base64;
//! the vault travels as the exact text of its file (`VaultFile::to_json`).
//!
//! ```text
//! GET  /api/v1/prelogin   → Prelogin            public: what a new device needs to derive keys
//! POST /api/v1/register   ← Register → Revision  once, with a single-use invite
//! GET  /api/v1/vault      → VaultResponse        Authorization: Bearer <auth_key, base64>
//! PUT  /api/v1/vault      ← PutVault → Revision  409 + Revision when base_revision is stale
//! ```
//!
//! The server stores only `auth_hash(auth_key)`. The auth key is 256 bits
//! derived from the master password and the Secret Key, so a fast hash is
//! enough: nothing about it can be guessed, and the hash only saves a
//! database leak from being replayed as a login.

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::kdf::{AccountId, KEY_LEN, KdfParams, Salt};
use crate::vault::{VaultError, VaultFile};

pub const PRELOGIN: &str = "/api/v1/prelogin";
pub const REGISTER: &str = "/api/v1/register";
pub const VAULT: &str = "/api/v1/vault";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prelogin {
    pub account_id: String,
    pub salt: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Prelogin {
    pub fn from_file(file: &VaultFile) -> Self {
        Self {
            account_id: Base64::encode_string(file.account_id.as_bytes()),
            salt: Base64::encode_string(file.salt.as_bytes()),
            memory_kib: file.kdf.memory_kib(),
            iterations: file.kdf.iterations(),
            parallelism: file.kdf.parallelism(),
        }
    }

    /// Validated like a vault file: the parameters must pass `KdfParams::new`.
    pub fn parse(&self) -> Result<(AccountId, Salt, KdfParams), VaultError> {
        let bad = |what: &str| VaultError::Format(format!("bad {what} from the server"));
        let account_id = Base64::decode_vec(&self.account_id)
            .ok()
            .and_then(|v| <[u8; 16]>::try_from(v).ok())
            .ok_or_else(|| bad("account id"))?;
        let salt = Base64::decode_vec(&self.salt)
            .ok()
            .and_then(|v| <[u8; 16]>::try_from(v).ok())
            .ok_or_else(|| bad("salt"))?;
        Ok((
            AccountId::from_bytes(account_id),
            Salt::from_bytes(salt),
            KdfParams::new(self.memory_kib, self.iterations, self.parallelism)?,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Register {
    pub invite: String,
    pub auth_key: String,
    pub vault: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultResponse {
    pub revision: u64,
    pub vault: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutVault {
    /// The server revision this upload was built on.
    pub base_revision: u64,
    pub vault: String,
    /// Set when the master password changed: the key to accept from now on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_auth_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub revision: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub error: String,
}

/// What the server stores instead of the auth key.
pub fn auth_hash(auth_key: &[u8; KEY_LEN]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"strongbox v1 auth-hash")
        .chain_update(auth_key)
        .finalize()
        .into()
}

/// Constant-time equality, for comparing auth hashes.
pub fn equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_hash_is_domain_separated_and_compares() {
        let a = auth_hash(&[1; 32]);
        let plain: [u8; 32] = Sha256::digest([1u8; 32]).into();
        assert_ne!(a, plain);
        assert!(equal(&a, &auth_hash(&[1; 32])));
        assert!(!equal(&a, &auth_hash(&[2; 32])));
    }

    #[test]
    fn prelogin_rejects_weak_parameters() {
        let p = Prelogin {
            account_id: Base64::encode_string(&[0; 16]),
            salt: Base64::encode_string(&[0; 16]),
            memory_kib: 1024,
            iterations: 3,
            parallelism: 1,
        };
        assert!(matches!(p.parse(), Err(VaultError::Kdf(_))));
    }
}
