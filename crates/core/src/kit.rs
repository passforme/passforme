//! The Secret Key as text, for the device file and the printed Emergency Kit.
//!
//! ```text
//! SB1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
//! ```
//!
//! Thirty Crockford base32 digits: 26 for the 128-bit key (the first digit
//! carries only 3 bits, so it is always 0-7), then 4 for a 20-bit checksum,
//! the top of `SHA-256("strongbox v1 kit" ‖ key)`. Crockford's alphabet has
//! no I, L, O or U, and reading accepts I/L as 1 and O as 0, any case, with
//! or without hyphens and spaces, so a key copied by hand from paper comes
//! back right or is refused, never silently wrong (a typo passes the
//! checksum once in about a million).

use std::fmt;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::kdf::{SECRET_KEY_LEN, SecretKey};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PREFIX: &str = "SB1";
const KEY_DIGITS: usize = 26;
const CHECK_DIGITS: usize = 4;
const GROUP: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KitError {
    Prefix,
    Character,
    Length,
    Checksum,
}

impl fmt::Display for KitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Prefix => "a Secret Key starts with SB1-",
            Self::Character => "a Secret Key contains only digits and letters (no U)",
            Self::Length => "a Secret Key has 30 characters after SB1-",
            Self::Checksum => "the Secret Key checksum does not match: check for a typo",
        })
    }
}

impl std::error::Error for KitError {}

fn checksum(key: &[u8; SECRET_KEY_LEN]) -> u32 {
    let digest = Sha256::new()
        .chain_update(b"strongbox v1 kit")
        .chain_update(key)
        .finalize();
    u32::from_be_bytes([0, digest[0], digest[1], digest[2]]) >> 4
}

impl SecretKey {
    /// `SB1-` and six groups of five digits.
    pub fn to_kit(&self) -> Zeroizing<String> {
        let key = self.expose();
        let value = Zeroizing::new(u128::from_be_bytes(*key));
        let check = checksum(key);
        let mut digits = Zeroizing::new([0u8; KEY_DIGITS + CHECK_DIGITS]);
        for i in 0..KEY_DIGITS {
            let shift = 5 * (KEY_DIGITS - 1 - i);
            digits[i] = ALPHABET[usize::try_from((*value >> shift) & 31).expect("5 bits")];
        }
        for i in 0..CHECK_DIGITS {
            let shift = 5 * (CHECK_DIGITS - 1 - i);
            digits[KEY_DIGITS + i] =
                ALPHABET[usize::try_from((check >> shift) & 31).expect("5 bits")];
        }
        let groups = digits.len() / GROUP;
        let mut out = Zeroizing::new(String::with_capacity(PREFIX.len() + groups * (GROUP + 1)));
        out.push_str(PREFIX);
        for group in digits.chunks(GROUP) {
            out.push('-');
            out.extend(group.iter().map(|&b| char::from(b)));
        }
        debug_assert_eq!(out.len(), out.capacity());
        out
    }

    pub fn from_kit(text: &str) -> Result<Self, KitError> {
        let rest = text
            .trim()
            .get(..PREFIX.len())
            .filter(|p| p.eq_ignore_ascii_case(PREFIX))
            .map(|_| &text.trim()[PREFIX.len()..])
            .ok_or(KitError::Prefix)?;
        let mut digits = Zeroizing::new(Vec::with_capacity(KEY_DIGITS + CHECK_DIGITS));
        for c in rest.chars().filter(|c| *c != '-' && !c.is_whitespace()) {
            if digits.len() == KEY_DIGITS + CHECK_DIGITS {
                return Err(KitError::Length);
            }
            digits.push(decode_digit(c).ok_or(KitError::Character)?);
        }
        if digits.len() != KEY_DIGITS + CHECK_DIGITS || digits[0] > 7 {
            return Err(KitError::Length);
        }
        let mut value = Zeroizing::new(0u128);
        for &d in &digits[..KEY_DIGITS] {
            *value = (*value << 5) | u128::from(d);
        }
        let check = digits[KEY_DIGITS..]
            .iter()
            .fold(0u32, |acc, &d| (acc << 5) | u32::from(d));
        let mut bytes = Zeroizing::new(value.to_be_bytes());
        if checksum(&bytes) != check {
            return Err(KitError::Checksum);
        }
        Ok(Self::from_bytes(&mut bytes))
    }
}

fn decode_digit(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        c => c,
    };
    ALPHABET
        .iter()
        .position(|&a| char::from(a) == c)
        .map(|i| u8::try_from(i).expect("alphabet has 32 entries"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom::SysRng;
    use rand_core::UnwrapErr;

    fn key(bytes: [u8; 16]) -> SecretKey {
        let mut bytes = bytes;
        SecretKey::from_bytes(&mut bytes)
    }

    #[test]
    fn known_encodings() {
        // Zero key: 26 zeros, then the checksum of SHA-256("strongbox v1 kit" ‖ 0^16).
        let zero = key([0; 16]).to_kit();
        assert!(
            zero.starts_with("SB1-00000-00000-00000-00000-00000-0"),
            "{}",
            *zero
        );
        // All ones: 2^128 - 1 is "7" followed by 25 "Z".
        let ones = key([0xff; 16]).to_kit();
        assert!(
            ones.starts_with("SB1-7ZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-Z"),
            "{}",
            *ones
        );
        assert_eq!(zero.len(), 3 + 6 * 6);
    }

    #[test]
    fn random_keys_round_trip_in_any_spelling() {
        for _ in 0..200 {
            let original = SecretKey::generate(&mut UnwrapErr(SysRng));
            let text = original.to_kit();
            let body = &text[PREFIX.len()..];
            let messy = format!(
                "sb1{}",
                body.to_lowercase()
                    .replace('-', " ")
                    .replace('0', "o")
                    .replace('1', "l")
            );
            for spelling in [text.as_str(), messy.as_str(), &text.replace('-', "")] {
                assert_eq!(
                    SecretKey::from_kit(spelling).unwrap().expose(),
                    original.expose()
                );
            }
        }
    }

    #[test]
    fn typos_are_caught() {
        let text = key([0x5a; 16]).to_kit();
        let mut rejected = 0;
        let mut tried = 0;
        // Every single-digit substitution in the 30 digits.
        for (pos, c) in text.char_indices().filter(|(i, c)| *i > 3 && *c != '-') {
            for &sub in ALPHABET {
                if char::from(sub) == c {
                    continue;
                }
                let mut typo = text.to_string();
                typo.replace_range(pos..=pos, &char::from(sub).to_string());
                tried += 1;
                if SecretKey::from_kit(&typo).is_err() {
                    rejected += 1;
                }
            }
        }
        assert_eq!(tried, 30 * 31);
        // A 20-bit check lets through about one in a million; allow one.
        assert!(tried - rejected <= 1, "{rejected}/{tried}");
    }

    #[test]
    fn malformed_text_is_refused() {
        let good = key([1; 16]).to_kit();
        assert_eq!(
            SecretKey::from_kit("XX1-00000").unwrap_err(),
            KitError::Prefix
        );
        assert_eq!(SecretKey::from_kit("").unwrap_err(), KitError::Prefix);
        assert_eq!(
            SecretKey::from_kit(&format!("{}U", &good[..good.len() - 1])).unwrap_err(),
            KitError::Character
        );
        assert_eq!(
            SecretKey::from_kit(&good[..good.len() - 1]).unwrap_err(),
            KitError::Length
        );
        assert_eq!(
            SecretKey::from_kit(&format!("{}0", *good)).unwrap_err(),
            KitError::Length
        );
        // First digit above 7 would overflow 128 bits.
        assert_eq!(
            SecretKey::from_kit("SB1-80000-00000-00000-00000-00000-00000").unwrap_err(),
            KitError::Length
        );
    }
}
