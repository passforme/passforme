//! Authenticated encryption of the vault key and of vault items.
//!
//! One construction for both, XChaCha20-Poly1305 with a fresh random 192-bit
//! nonce per encryption, and one wire format:
//!
//! ```text
//! version (1 byte, = 1) ‖ nonce (24) ‖ ciphertext ‖ tag (16)
//! ```
//!
//! What each ciphertext means is fixed by its associated data (AAD), which is
//! authenticated but not stored: a domain string, then fixed-length fields.
//!
//! ```text
//! vault key: "strongbox v1 vault-key" ‖ account_id
//! item:      "strongbox v1 item" ‖ account_id ‖ item_id ‖ revision (u64, big-endian)
//! ```
//!
//! So a ciphertext only opens as what it was sealed as: another account's
//! item, another item, another revision of the same item, or the wrapped vault
//! key presented as an item all fail authentication.
//!
//! Item plaintexts are padded (ISO/IEC 7816-4: `0x80`, then zeros) to a
//! power of two, at least 256 bytes, so the ciphertext length does not give
//! away the length of a password or note. The padding is removed only after
//! the tag has been verified, so there is no padding oracle.

use std::fmt;

use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::kdf::{AccountId, KEY_LEN, WrapKey};

pub const FORMAT_V1: u8 = 1;
pub const ITEM_ID_LEN: usize = 16;
/// Largest item plaintext; attachments, if they ever exist, go elsewhere.
pub const MAX_ITEM_LEN: usize = 1 << 20;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 1 + NONCE_LEN;
const MIN_BUCKET: usize = 256;

const DOMAIN_VAULT_KEY: &[u8] = b"strongbox v1 vault-key";
const DOMAIN_ITEM: &[u8] = b"strongbox v1 item";

secret_bytes!(
    /// Encrypts every item. Random, generated once per account, stored only
    /// wrapped by the wrap key, so a new master password re-wraps 32 bytes
    /// instead of re-encrypting the vault.
    VaultKey,
    KEY_LEN
);

impl VaultKey {
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut key = Self::zeroed();
        rng.fill_bytes(key.expose_mut());
        key
    }
}

public_bytes!(
    /// Random identifier of an item, stable across its revisions.
    ItemId,
    ITEM_ID_LEN
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// Not something this code wrote: unknown version, too short or too long.
    Malformed,
    /// Authentication failed: wrong key, or the ciphertext, its nonce or its
    /// context (account, item, revision) is not the one it was sealed with.
    /// Deliberately says nothing more.
    Rejected,
    TooLarge {
        len: usize,
    },
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("not a passforme ciphertext"),
            Self::Rejected => f.write_str("decryption failed: wrong key or tampered data"),
            Self::TooLarge { len } => {
                write!(
                    f,
                    "item of {len} bytes exceeds the {MAX_ITEM_LEN}-byte limit"
                )
            }
        }
    }
}

impl std::error::Error for SealError {}

/// A sealed blob in the wire format above. Holds only ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed(Vec<u8>);

impl Sealed {
    /// Accepts bytes from storage or the network after a structural check;
    /// authenticity is checked when opening.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SealError> {
        let max = HEADER_LEN + padded_len(MAX_ITEM_LEN) + TAG_LEN;
        if bytes.first() != Some(&FORMAT_V1)
            || bytes.len() < HEADER_LEN + TAG_LEN
            || bytes.len() > max
        {
            return Err(SealError::Malformed);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub fn wrap_vault_key<R: CryptoRng + ?Sized>(
    vault_key: &VaultKey,
    wrap_key: &WrapKey,
    account_id: &AccountId,
    rng: &mut R,
) -> Sealed {
    seal(
        wrap_key.expose(),
        random_nonce(rng),
        &vault_key_aad(account_id),
        vault_key.expose(),
        KEY_LEN,
    )
}

pub fn unwrap_vault_key(
    sealed: &Sealed,
    wrap_key: &WrapKey,
    account_id: &AccountId,
) -> Result<VaultKey, SealError> {
    let plain = open(wrap_key.expose(), &vault_key_aad(account_id), sealed)?;
    if plain.len() != KEY_LEN {
        return Err(SealError::Malformed);
    }
    let mut key = VaultKey::zeroed();
    key.expose_mut().copy_from_slice(&plain);
    Ok(key)
}

pub fn seal_item<R: CryptoRng + ?Sized>(
    vault_key: &VaultKey,
    account_id: &AccountId,
    item_id: &ItemId,
    revision: u64,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Sealed, SealError> {
    if plaintext.len() > MAX_ITEM_LEN {
        return Err(SealError::TooLarge {
            len: plaintext.len(),
        });
    }
    Ok(seal(
        vault_key.expose(),
        random_nonce(rng),
        &item_aad(account_id, item_id, revision),
        plaintext,
        padded_len(plaintext.len()),
    ))
}

pub fn open_item(
    sealed: &Sealed,
    vault_key: &VaultKey,
    account_id: &AccountId,
    item_id: &ItemId,
    revision: u64,
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let mut plain = open(
        vault_key.expose(),
        &item_aad(account_id, item_id, revision),
        sealed,
    )?;
    // Authenticated already, so a bad padding means a bug, not an attack.
    let end = plain
        .iter()
        .rposition(|&b| b != 0)
        .filter(|&i| plain[i] == 0x80)
        .ok_or(SealError::Malformed)?;
    plain.truncate(end);
    Ok(plain)
}

fn vault_key_aad(account_id: &AccountId) -> Vec<u8> {
    [DOMAIN_VAULT_KEY, account_id.as_bytes()].concat()
}

fn item_aad(account_id: &AccountId, item_id: &ItemId, revision: u64) -> Vec<u8> {
    [
        DOMAIN_ITEM,
        account_id.as_bytes(),
        item_id.as_bytes(),
        &revision.to_be_bytes(),
    ]
    .concat()
}

/// Smallest power of two, at least `MIN_BUCKET`, that fits the plaintext
/// and the mandatory `0x80` marker.
fn padded_len(len: usize) -> usize {
    (len + 1).next_power_of_two().max(MIN_BUCKET)
}

fn random_nonce<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    nonce
}

/// Seals `plaintext`, padded to `body_len` when that is longer. The output
/// buffer is allocated once at its final size and the plaintext is
/// encrypted in place in it, so no unencrypted copy is left behind.
fn seal(
    key: &[u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    body_len: usize,
) -> Sealed {
    let mut out = Vec::with_capacity(HEADER_LEN + body_len + TAG_LEN);
    out.push(FORMAT_V1);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plaintext);
    if body_len > plaintext.len() {
        out.push(0x80);
        out.resize(HEADER_LEN + body_len, 0);
    }
    let tag = XChaCha20Poly1305::new(key.into())
        .encrypt_inout_detached(&XNonce::from(nonce), aad, (&mut out[HEADER_LEN..]).into())
        .expect("bounded plaintext and AAD are within XChaCha20-Poly1305 limits");
    out.extend_from_slice(&tag);
    debug_assert_eq!(out.len(), out.capacity());
    Sealed(out)
}

/// Verifies and decrypts, returning the (still padded) plaintext in a buffer
/// that is wiped on drop.
fn open(key: &[u8; KEY_LEN], aad: &[u8], sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let bytes = sealed.as_bytes();
    let (header, rest) = bytes.split_at(HEADER_LEN);
    let (body, tag) = rest.split_at(rest.len() - TAG_LEN);
    let nonce = XNonce::try_from(&header[1..]).expect("header holds a 24-byte nonce");
    let tag = Tag::try_from(tag).expect("16-byte tag");
    let mut plain = Zeroizing::new(body.to_vec());
    XChaCha20Poly1305::new(key.into())
        .decrypt_inout_detached(&nonce, aad, plain.as_mut_slice().into(), &tag)
        .map_err(|_| SealError::Rejected)?;
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom::SysRng;
    use rand_core::UnwrapErr;

    fn rng() -> UnwrapErr<SysRng> {
        UnwrapErr(SysRng)
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vault_key(byte: u8) -> VaultKey {
        let mut key = VaultKey::zeroed();
        key.expose_mut().fill(byte);
        key
    }

    fn wrap_key(byte: u8) -> WrapKey {
        let mut key = WrapKey::zeroed();
        key.expose_mut().fill(byte);
        key
    }

    const ACCOUNT: AccountId = AccountId::from_bytes([0xa1; 16]);
    const ITEM: ItemId = ItemId::from_bytes([0x17; 16]);

    #[test]
    fn xchacha20poly1305_draft_vector() {
        // draft-irtf-cfrg-xchacha-03, appendix A.3.1; also reproduced with
        // libsodium through PyNaCl.
        let key: [u8; 32] = std::array::from_fn(|i| 0x80 + u8::try_from(i).unwrap());
        let nonce: [u8; 24] = std::array::from_fn(|i| 0x40 + u8::try_from(i).unwrap());
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let mut buf = b"Ladies and Gentlemen of the class of '99: If I could offer you only one \
                        tip for the future, sunscreen would be it."
            .to_vec();
        let tag = XChaCha20Poly1305::new(&key.into())
            .encrypt_inout_detached(&XNonce::from(nonce), &aad, buf.as_mut_slice().into())
            .unwrap();
        assert_eq!(
            buf,
            unhex(
                "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
                 731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
                 2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
                 21f9664c97637da9768812f615c68b13b52e"
            )
        );
        assert_eq!(tag.to_vec(), unhex("c0875924c1c7987947deafd8780acf49"));
    }

    // The two vectors below were computed independently with libsodium
    // (PyNaCl) by tools/seal_reference.py: same key, nonce, AAD and padding.

    #[test]
    fn item_format_matches_reference() {
        let sealed = seal(
            &[0x42; 32],
            [0x24; 24],
            &item_aad(&ACCOUNT, &ITEM, 7),
            b"hunter2",
            padded_len(7),
        );
        assert_eq!(sealed.as_bytes(), unhex(ITEM_REFERENCE));
        let opened = open_item(&sealed, &vault_key(0x42), &ACCOUNT, &ITEM, 7).unwrap();
        assert_eq!(&opened[..], b"hunter2");
    }

    #[test]
    fn vault_key_format_matches_reference() {
        let sealed = seal(
            &[0x57; 32],
            [0x31; 24],
            &vault_key_aad(&ACCOUNT),
            &[0x42; 32],
            KEY_LEN,
        );
        assert_eq!(sealed.as_bytes(), unhex(VAULT_KEY_REFERENCE));
        let key = unwrap_vault_key(&sealed, &wrap_key(0x57), &ACCOUNT).unwrap();
        assert_eq!(key.expose(), &[0x42; 32]);
    }

    #[test]
    fn items_round_trip_at_bucket_edges() {
        let key = VaultKey::generate(&mut rng());
        for (len, bucket) in [
            (0, 256),
            (1, 256),
            (255, 256),
            (256, 512),
            (511, 512),
            (512, 1024),
            (MAX_ITEM_LEN, 2 * MAX_ITEM_LEN),
        ] {
            let plain: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
            let sealed = seal_item(&key, &ACCOUNT, &ITEM, 1, &plain, &mut rng()).unwrap();
            assert_eq!(
                sealed.as_bytes().len(),
                HEADER_LEN + bucket + TAG_LEN,
                "{len}"
            );
            let again = Sealed::from_bytes(sealed.as_bytes().to_vec()).unwrap();
            assert_eq!(
                &open_item(&again, &key, &ACCOUNT, &ITEM, 1).unwrap()[..],
                &plain[..]
            );
        }
        // Plaintexts ending in 0x80 or zeros survive the padding.
        for plain in [&b"a\x80"[..], b"a\x00\x00", b"\x80\x00"] {
            let sealed = seal_item(&key, &ACCOUNT, &ITEM, 1, plain, &mut rng()).unwrap();
            assert_eq!(
                &open_item(&sealed, &key, &ACCOUNT, &ITEM, 1).unwrap()[..],
                plain
            );
        }
    }

    #[test]
    fn oversized_item_is_refused() {
        let key = VaultKey::generate(&mut rng());
        let plain = vec![0; MAX_ITEM_LEN + 1];
        assert_eq!(
            seal_item(&key, &ACCOUNT, &ITEM, 1, &plain, &mut rng()).unwrap_err(),
            SealError::TooLarge {
                len: MAX_ITEM_LEN + 1
            }
        );
    }

    #[test]
    fn every_flipped_bit_is_rejected() {
        let key = VaultKey::generate(&mut rng());
        let sealed = seal_item(&key, &ACCOUNT, &ITEM, 3, b"secret", &mut rng()).unwrap();
        for i in 0..sealed.as_bytes().len() {
            for bit in 0..8 {
                let mut bytes = sealed.as_bytes().to_vec();
                bytes[i] ^= 1 << bit;
                let result = Sealed::from_bytes(bytes)
                    .and_then(|s| open_item(&s, &key, &ACCOUNT, &ITEM, 3).map(|_| ()));
                let expected = if i == 0 {
                    SealError::Malformed
                } else {
                    SealError::Rejected
                };
                assert_eq!(result.unwrap_err(), expected, "byte {i} bit {bit}");
            }
        }
    }

    #[test]
    fn wrong_context_is_rejected() {
        let key = VaultKey::generate(&mut rng());
        let sealed = seal_item(&key, &ACCOUNT, &ITEM, 3, b"secret", &mut rng()).unwrap();
        let other_account = AccountId::from_bytes([0xa2; 16]);
        let other_item = ItemId::from_bytes([0x18; 16]);
        let other_key = VaultKey::generate(&mut rng());
        for result in [
            open_item(&sealed, &other_key, &ACCOUNT, &ITEM, 3),
            open_item(&sealed, &key, &other_account, &ITEM, 3),
            open_item(&sealed, &key, &ACCOUNT, &other_item, 3),
            open_item(&sealed, &key, &ACCOUNT, &ITEM, 2),
            open_item(&sealed, &key, &ACCOUNT, &ITEM, 4),
        ] {
            assert_eq!(result.unwrap_err(), SealError::Rejected);
        }
    }

    #[test]
    fn wrapped_vault_key_does_not_open_as_an_item() {
        // Same key bytes on both sides: only the AAD tells them apart.
        let sealed = wrap_vault_key(&vault_key(1), &wrap_key(9), &ACCOUNT, &mut rng());
        assert_eq!(
            open_item(&sealed, &vault_key(9), &ACCOUNT, &ITEM, 0).unwrap_err(),
            SealError::Rejected
        );
        assert_eq!(
            unwrap_vault_key(&sealed, &wrap_key(8), &ACCOUNT).unwrap_err(),
            SealError::Rejected
        );
        let other_account = AccountId::from_bytes([0xa2; 16]);
        assert_eq!(
            unwrap_vault_key(&sealed, &wrap_key(9), &other_account).unwrap_err(),
            SealError::Rejected
        );
        assert_eq!(
            unwrap_vault_key(&sealed, &wrap_key(9), &ACCOUNT)
                .unwrap()
                .expose(),
            &[1; 32]
        );
    }

    #[test]
    fn nonces_are_fresh() {
        let key = VaultKey::generate(&mut rng());
        let a = seal_item(&key, &ACCOUNT, &ITEM, 1, b"same", &mut rng()).unwrap();
        let b = seal_item(&key, &ACCOUNT, &ITEM, 1, b"same", &mut rng()).unwrap();
        assert_ne!(a.as_bytes()[1..HEADER_LEN], b.as_bytes()[1..HEADER_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn malformed_blobs_are_refused() {
        let too_long = vec![FORMAT_V1; HEADER_LEN + 2 * MAX_ITEM_LEN + TAG_LEN + 1];
        for bytes in [
            vec![],
            vec![FORMAT_V1; HEADER_LEN + TAG_LEN - 1],
            vec![2; HEADER_LEN + TAG_LEN + 256],
            too_long,
        ] {
            assert_eq!(Sealed::from_bytes(bytes).unwrap_err(), SealError::Malformed);
        }
    }

    const ITEM_REFERENCE: &str = "01242424242424242424242424242424242424242424242424cd2bb9110b567e26a22f3f3a0e880dca32f18eba7c1f749d2161e64d6b10dbcd149188d8349b5b9c7cb5b1bbf9dd288c574d2ffe274881dc123a89d3911fb4f8ee9432240631db00cc966d3e35245afabe9b70c0a6386ea403bf33f097187924d56b377c62d1a6055294105aacce651bb564a2c42ff7499438dc9febe1f0315cba2a75624e6ea1be97dd042eb3ec28086dc7e95c41425e220ba1bf3c5abdcc8a295dd67dcd55084001333b3e5ac085a5bfdb2bf2ad8cd2355749f0c217a628235ee4249c9b9135b7c79700af17bfb2bbc6dca65fb1df3c5a3ef2630602dfc5fce598147556e52b73bfdd79a54e8ebbdc7614d2612de10e3be021ad627e2920e877fda2d89c67dd847c7e474c56525472";
    const VAULT_KEY_REFERENCE: &str = "01313131313131313131313131313131313131313131313131759ea6c1905e877884a77dece62d14bec5f0a22bf5471ed86f542ba3ea563700e1c0b7def0a6483fec8a4ae401c2c0b5";
}
