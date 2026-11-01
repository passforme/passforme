//! BIP-39 wordlists and the checksum of a recovery phrase.
//!
//! The lists serve two purposes: Brazilian Portuguese passphrases in the
//! generator, and checking a crypto wallet's recovery phrase before it is
//! saved, so a misheard or swapped word is caught while the paper is still
//! at hand. Only the checksum is checked; nothing here derives keys.
//!
//! A phrase of 12, 15, 18, 21 or 24 words encodes 11 bits per word: the
//! entropy, then `words / 3` bits of `SHA-256(entropy)`. A wrong word fails
//! that check with probability `1 - 2^-(words/3)` (15/16 for 12 words).

use std::sync::LazyLock;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The official English list, verbatim; SHA-256 pinned by a test. Source:
/// <https://github.com/bitcoin/bips> (`bip-0039/english.txt`),
/// byte-identical to Trezor's `python-mnemonic`.
const ENGLISH_LIST: &str = include_str!("bip39_english.txt");
/// The official Portuguese (Brazilian) list, verbatim; same sources.
const PORTUGUESE_LIST: &str = include_str!("bip39_portuguese.txt");

pub(crate) static ENGLISH: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| ENGLISH_LIST.lines().collect());
pub(crate) static PORTUGUESE: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| PORTUGUESE_LIST.lines().collect());

/// The list a valid phrase was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wordlist {
    English,
    Portuguese,
}

/// Why a phrase does not check. Positions are 1-based; the words themselves
/// are never named, since the error may be shown or logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedError {
    WordCount(usize),
    /// In neither list (in the list of the first word, when it is in one).
    UnknownWord(usize),
    /// Every word is listed but the checksum fails: a wrong or swapped word.
    Checksum,
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WordCount(n) => write!(f, "{n} words; a BIP-39 phrase has 12, 15, 18, 21 or 24"),
            Self::UnknownWord(at) => write!(f, "word {at} is not in the BIP-39 list"),
            Self::Checksum => f.write_str(
                "the words are all valid but the checksum fails: one is wrong or out of order",
            ),
        }
    }
}

impl std::error::Error for SeedError {}

/// Lowercase, single spaces: the form a phrase is stored in.
pub fn normalize(phrase: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(phrase.len()));
    for word in phrase.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.extend(word.chars().flat_map(char::to_lowercase));
    }
    out
}

/// Checks a recovery phrase (already [`normalize`]d) against both lists.
pub fn check(phrase: &str) -> Result<Wordlist, SeedError> {
    let words: Vec<&str> = phrase.split(' ').filter(|w| !w.is_empty()).collect();
    if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
        return Err(SeedError::WordCount(words.len()));
    }
    let (list, which) = if PORTUGUESE.contains(&words[0]) {
        (&*PORTUGUESE, Wordlist::Portuguese)
    } else {
        (&*ENGLISH, Wordlist::English)
    };
    let mut indices = Zeroizing::new(Vec::with_capacity(words.len()));
    for (n, word) in words.iter().enumerate() {
        let index = list
            .binary_search(word)
            .or_else(|_| list.iter().position(|w| w == word).ok_or(()))
            .map_err(|()| SeedError::UnknownWord(n + 1))?;
        indices.push(index);
    }
    // 11 bits per word, most significant first.
    let total_bits = words.len() * 11;
    let checksum_bits = words.len() / 3;
    let entropy_bytes = (total_bits - checksum_bits) / 8;
    let mut bits = Zeroizing::new(vec![0u8; total_bits.div_ceil(8)]);
    for (n, &index) in indices.iter().enumerate() {
        for b in 0..11 {
            if index >> (10 - b) & 1 == 1 {
                let at = n * 11 + b;
                bits[at / 8] |= 0x80 >> (at % 8);
            }
        }
    }
    let digest = Sha256::digest(&bits[..entropy_bytes]);
    let expected = digest[0] >> (8 - checksum_bits);
    // The checksum bits start right after the entropy, on a byte boundary.
    let got = bits[entropy_bytes] >> (8 - checksum_bits);
    if expected == got {
        Ok(which)
    } else {
        Err(SeedError::Checksum)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fmt::Write;

    use super::*;

    fn sha256_hex(text: &str) -> String {
        Sha256::digest(text.as_bytes())
            .iter()
            .fold(String::new(), |mut s, b| {
                write!(s, "{b:02x}").unwrap();
                s
            })
    }

    #[test]
    fn lists_are_the_pinned_files() {
        assert_eq!(
            sha256_hex(ENGLISH_LIST),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        assert_eq!(
            sha256_hex(PORTUGUESE_LIST),
            "2685e9c194c82ae67e10ba59d9ea5345a23dc093e92276fc5361f6667d79cd3f"
        );
        for list in [&*ENGLISH, &*PORTUGUESE] {
            assert_eq!(list.len(), 2048);
            assert_eq!(list.iter().collect::<HashSet<_>>().len(), 2048);
            assert!(
                list.iter()
                    .all(|w| w.bytes().all(|b| b.is_ascii_lowercase()))
            );
        }
        // No word in both, so the first word tells the language.
        let en: HashSet<_> = ENGLISH.iter().collect();
        assert!(PORTUGUESE.iter().all(|w| !en.contains(w)));
    }

    #[test]
    fn official_test_vectors() {
        // From the BIP-39 reference vectors (Trezor's vectors.json).
        let valid = [
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        ];
        for phrase in valid {
            assert_eq!(check(phrase), Ok(Wordlist::English), "{phrase}");
        }
    }

    #[test]
    fn portuguese_phrase_checks() {
        // Zero entropy: eleven times the first word, then the word whose
        // index carries the checksum (3, as "about" in English).
        let mut words = vec![PORTUGUESE[0]; 11];
        words.push(PORTUGUESE[3]);
        assert_eq!(check(&words.join(" ")), Ok(Wordlist::Portuguese));
        words[11] = PORTUGUESE[4];
        assert_eq!(check(&words.join(" ")), Err(SeedError::Checksum));
    }

    #[test]
    fn mistakes_are_caught_without_naming_the_word() {
        let good = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let swapped = "winner legal thank year wave sausage worth useful legal winner thank yellow";
        assert_eq!(check(swapped), Err(SeedError::Checksum));
        let typo = "legal winner thank year wave sausage worht useful legal winner thank yellow";
        assert_eq!(check(typo), Err(SeedError::UnknownWord(7)));
        assert!(!SeedError::UnknownWord(7).to_string().contains("worht"));
        assert_eq!(check("legal winner"), Err(SeedError::WordCount(2)));
        assert_eq!(check(good), Ok(Wordlist::English));
    }

    #[test]
    fn normalizes_case_and_spaces() {
        assert_eq!(
            &*normalize("  Zoo zoo\tzoo ZOO zoo zoo zoo zoo\nzoo zoo zoo Wrong "),
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        );
    }
}
