//! Key derivation: master password + Secret Key → wrap key and auth key.
//!
//! ```text
//! pw_key     = Argon2id(NFKC(password), salt, params)            32 bytes
//! master_key = HKDF-Extract(salt = account_id, pw_key ‖ secret_key)
//! wrap_key   = HKDF-Expand(master_key, "strongbox v1 wrap", 32)
//! auth_key   = HKDF-Expand(master_key, "strongbox v1 auth", 32)
//! ```
//!
//! `wrap_key` unlocks the vault key and never leaves the client; `auth_key`
//! may be shown to the server, and HKDF makes it useless for recovering
//! `wrap_key`.
//!
//! Wiping is best effort: every buffer this module owns is zeroized, the
//! Argon2 memory included, but copies a dependency makes on the stack while
//! computing cannot be reached from here.

use std::fmt;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use hkdf::Hkdf;
use rand_core::CryptoRng;
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const SECRET_KEY_LEN: usize = 16;
pub const ACCOUNT_ID_LEN: usize = 16;

// Domain labels keep the project's first name, "strongbox", on purpose:
// they are part of the derivation, and changing them would lock out every
// existing vault. See "Name" in AGENTS.md.
const INFO_WRAP: &[u8] = b"strongbox v1 wrap";
const INFO_AUTH: &[u8] = b"strongbox v1 auth";

/// Argon2id cost. The fields are private so every value in use has passed
/// [`KdfParams::new`]: the parameters are stored with the account and come
/// back from the server, which must not be able to weaken them (floor) or
/// exhaust the client's memory (ceiling).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl KdfParams {
    /// 256 MiB, 3 passes, 1 lane: about 0.6 s per unlock on the laptop.
    pub const DEFAULT: Self = Self {
        memory_kib: 256 * 1024,
        iterations: 3,
        parallelism: 1,
    };
    pub const MIN_MEMORY_KIB: u32 = 64 * 1024;
    pub const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;
    pub const MIN_ITERATIONS: u32 = 2;
    pub const MAX_ITERATIONS: u32 = 64;
    pub const MAX_PARALLELISM: u32 = 16;

    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, KdfError> {
        let valid = (Self::MIN_MEMORY_KIB..=Self::MAX_MEMORY_KIB).contains(&memory_kib)
            && (Self::MIN_ITERATIONS..=Self::MAX_ITERATIONS).contains(&iterations)
            && (1..=Self::MAX_PARALLELISM).contains(&parallelism);
        if !valid {
            return Err(KdfError::InvalidParams {
                memory_kib,
                iterations,
                parallelism,
            });
        }
        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
        })
    }

    pub fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    pub fn parallelism(&self) -> u32 {
        self.parallelism
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug)]
pub enum KdfError {
    InvalidParams {
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    },
    Argon2(argon2::Error),
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParams {
                memory_kib,
                iterations,
                parallelism,
            } => write!(
                f,
                "unacceptable Argon2 parameters: m={memory_kib} KiB, t={iterations}, p={parallelism}"
            ),
            Self::Argon2(e) => write!(f, "Argon2 failed: {e}"),
        }
    }
}

impl std::error::Error for KdfError {}

public_bytes!(
    /// Argon2 salt.
    Salt,
    SALT_LEN
);
public_bytes!(
    /// Account identifier; also the HKDF salt, binding the keys to the account.
    AccountId,
    ACCOUNT_ID_LEN
);

secret_bytes!(
    /// The 128-bit Secret Key: never sent anywhere, kept on each device and
    /// in the printed Emergency Kit.
    SecretKey,
    SECRET_KEY_LEN
);
secret_bytes!(
    /// Unlocks the vault key. Never leaves the client.
    WrapKey,
    KEY_LEN
);
secret_bytes!(
    /// Proves the user's identity to the server.
    AuthKey,
    KEY_LEN
);

impl SecretKey {
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut key = Self::zeroed();
        rng.fill_bytes(key.expose_mut());
        key
    }

    /// Takes the bytes and wipes the caller's copy.
    pub fn from_bytes(bytes: &mut [u8; SECRET_KEY_LEN]) -> Self {
        let mut key = Self::zeroed();
        key.expose_mut().copy_from_slice(bytes);
        bytes.zeroize();
        key
    }
}

impl AuthKey {
    /// The bytes sent to the server.
    pub fn to_server(&self) -> &[u8; KEY_LEN] {
        self.expose()
    }
}

#[derive(Debug)]
pub struct DerivedKeys {
    pub wrap_key: WrapKey,
    pub auth_key: AuthKey,
}

/// Derives the wrap and auth keys (see the module documentation).
///
/// # Panics
///
/// Never in practice: the only `expect`s guard HKDF output lengths, which
/// are fixed at 32 bytes and always valid for SHA-256.
pub fn derive_keys(
    password: &SecretString,
    secret_key: &SecretKey,
    salt: &Salt,
    account_id: &AccountId,
    params: &KdfParams,
) -> Result<DerivedKeys, KdfError> {
    let normalized = nfkc(password.expose_secret());

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(KdfError::Argon2)?;
    // Our own memory, so it is wiped: the crate's allocator frees its
    // blocks without clearing them, and they determine the output.
    let mut memory = Zeroizing::new(vec![Block::default(); argon_params.block_count()]);
    let mut ikm = Zeroizing::new([0u8; KEY_LEN + SECRET_KEY_LEN]);
    let (pw_key, rest) = ikm.split_at_mut(KEY_LEN);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into_with_memory(
            normalized.as_bytes(),
            salt.as_bytes(),
            pw_key,
            memory.as_mut_slice(),
        )
        .map_err(KdfError::Argon2)?;
    drop(memory);
    rest.copy_from_slice(secret_key.expose());

    let (mut master_key, hkdf) = Hkdf::<Sha256>::extract(Some(account_id.as_bytes()), &*ikm);
    master_key.as_mut_slice().zeroize();

    let mut keys = DerivedKeys {
        wrap_key: WrapKey::zeroed(),
        auth_key: AuthKey::zeroed(),
    };
    hkdf.expand(INFO_WRAP, keys.wrap_key.expose_mut())
        .expect("32 bytes is a valid HKDF-SHA256 length");
    hkdf.expand(INFO_AUTH, keys.auth_key.expose_mut())
        .expect("32 bytes is a valid HKDF-SHA256 length");
    Ok(keys)
}

/// NFKC, so the same password typed on another device or keyboard layout
/// (composed "é" or "e" + combining accent, a ligature) yields the same
/// key. The length is measured first and the string allocated once, so no
/// reallocation leaves a partial copy behind.
fn nfkc(password: &str) -> Zeroizing<String> {
    let len = password.nfkc().map(char::len_utf8).sum();
    let mut out = Zeroizing::new(String::with_capacity(len));
    out.extend(password.nfkc());
    debug_assert_eq!(out.capacity(), len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write as _;
            write!(s, "{b:02x}").unwrap();
            s
        })
    }

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// Small parameters so the test suite stays fast; below the production
    /// floor, which is why they are built directly instead of via `new`.
    const FAST: KdfParams = KdfParams {
        memory_kib: 1024,
        iterations: 2,
        parallelism: 1,
    };

    fn fixture() -> (SecretKey, Salt, AccountId) {
        let mut sk: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f");
        (
            SecretKey::from_bytes(&mut sk),
            Salt::from_bytes(unhex("101112131415161718191a1b1c1d1e1f")),
            AccountId::from_bytes(unhex("202122232425262728292a2b2c2d2e2f")),
        )
    }

    fn derive(password: &str, params: &KdfParams) -> DerivedKeys {
        let (sk, salt, id) = fixture();
        derive_keys(&SecretString::from(password), &sk, &salt, &id, params).unwrap()
    }

    #[test]
    fn argon2id_rfc9106_vector() {
        // RFC 9106, section 5.3 (Argon2id, version 0x13).
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[4; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let argon =
            Argon2::new_with_secret(&[3; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut memory = vec![Block::default(); 32];
        let mut out = [0u8; 32];
        argon
            .hash_password_into_with_memory(&[1; 32], &[2; 16], &mut out, &mut memory[..])
            .unwrap();
        assert_eq!(
            hex(&out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[test]
    fn hkdf_sha256_rfc5869_vector() {
        // RFC 5869, appendix A.1.
        let ikm = [0x0b; 22];
        let salt: [u8; 13] = unhex("000102030405060708090a0b0c");
        let info: [u8; 10] = unhex("f0f1f2f3f4f5f6f7f8f9");
        let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        assert_eq!(
            hex(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let mut okm = [0u8; 42];
        hkdf.expand(&info, &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    // The expected values below come from an independent implementation:
    // Python with argon2-cffi (the Argon2 authors' reference C code),
    // `unicodedata` for NFKC and `hmac` for HKDF written from RFC 5869.

    #[test]
    fn derivation_matches_reference_fast_params() {
        let keys = derive("correct horse battery staple", &FAST);
        assert_eq!(hex(keys.wrap_key.expose()), WRAP_FAST);
        assert_eq!(hex(keys.auth_key.expose()), AUTH_FAST);
    }

    #[test]
    fn derivation_matches_reference_default_params() {
        let keys = derive("correct horse battery staple", &KdfParams::DEFAULT);
        assert_eq!(hex(keys.wrap_key.expose()), WRAP_DEFAULT);
        assert_eq!(hex(keys.auth_key.expose()), AUTH_DEFAULT);
    }

    #[test]
    fn password_is_nfkc_normalized() {
        // Composed é (U+00E9) and ﬁ ligature (U+FB01) versus their NFKC forms.
        let composed = derive("caf\u{e9} \u{fb01}sh", &FAST);
        let decomposed = derive("cafe\u{301} fish", &FAST);
        assert_eq!(composed.wrap_key.expose(), decomposed.wrap_key.expose());
        assert_eq!(hex(composed.wrap_key.expose()), WRAP_UNICODE);
    }

    #[test]
    fn every_input_changes_the_keys() {
        let base = derive("pw", &FAST);
        let (sk, salt, id) = fixture();
        let pw = SecretString::from("pw");
        let mut other_sk_bytes = [0xff; 16];
        let other_sk = SecretKey::from_bytes(&mut other_sk_bytes);
        assert_eq!(other_sk_bytes, [0; 16], "caller's copy is wiped");
        let other_salt = Salt::from_bytes([0xff; 16]);
        let other_id = AccountId::from_bytes([0xff; 16]);
        let variants = [
            derive("pW", &FAST),
            derive_keys(&pw, &other_sk, &salt, &id, &FAST).unwrap(),
            derive_keys(&pw, &sk, &other_salt, &id, &FAST).unwrap(),
            derive_keys(&pw, &sk, &salt, &other_id, &FAST).unwrap(),
            derive_keys(
                &pw,
                &sk,
                &salt,
                &id,
                &KdfParams {
                    iterations: 3,
                    ..FAST
                },
            )
            .unwrap(),
        ];
        for v in &variants {
            assert_ne!(v.wrap_key.expose(), base.wrap_key.expose());
            assert_ne!(v.auth_key.expose(), base.auth_key.expose());
        }
        assert_ne!(base.wrap_key.expose(), base.auth_key.expose());
    }

    #[test]
    fn params_outside_bounds_are_rejected() {
        assert_eq!(
            KdfParams::new(256 * 1024, 3, 1).unwrap(),
            KdfParams::DEFAULT
        );
        for (m, t, p) in [
            (KdfParams::MIN_MEMORY_KIB - 1, 3, 1),
            (KdfParams::MAX_MEMORY_KIB + 1, 3, 1),
            (256 * 1024, 1, 1),
            (256 * 1024, 65, 1),
            (256 * 1024, 3, 0),
            (256 * 1024, 3, 17),
        ] {
            assert!(KdfParams::new(m, t, p).is_err(), "{m} {t} {p}");
        }
    }

    #[test]
    fn debug_output_is_redacted() {
        let keys = derive("pw", &FAST);
        let text = format!("{keys:?} {:?}", fixture().0);
        assert!(!text.contains(&hex(keys.wrap_key.expose())));
        assert_eq!(
            text,
            "DerivedKeys { wrap_key: WrapKey([REDACTED]), auth_key: AuthKey([REDACTED]) } \
             SecretKey([REDACTED])"
        );
    }

    const WRAP_FAST: &str = "98ad6ddae82d95eb94f85971144e87f3cd485e8dfb883aad8e26dbdb4454c0d0";
    const AUTH_FAST: &str = "0333abd27505560b44a9573e390801f2c6a1368d37b176ff839f424af0e3acb0";
    const WRAP_DEFAULT: &str = "1eb5d82324aa93f96cdfbd687eccec96b657aba70d1f78f997aa1208bae22991";
    const AUTH_DEFAULT: &str = "c12fed11fd1703a69983de1182bd88b9f679dbf218fd0d84fd67da80f203bcf7";
    const WRAP_UNICODE: &str = "c07a315c90d56a837c509cb3dfb573b9ce5e9f10d47d613e7db074f702b23bfb";
}
