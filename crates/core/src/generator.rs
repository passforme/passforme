//! Password and passphrase generator.
//!
//! Every choice is an exactly uniform draw from a cryptographic RNG, so the
//! reported entropy is the real one: `log2` of the number of values the
//! generator can produce, each equally likely.

use std::fmt;
use std::sync::LazyLock;

use rand_core::CryptoRng;
use secrecy::SecretString;
use zeroize::Zeroizing;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
/// All printable ASCII punctuation.
const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
/// Characters easily misread or mistyped when a password is copied by hand.
const AMBIGUOUS: &[u8] = b"Il1|O0o'\"`";

pub const MIN_LENGTH: usize = 4;
pub const MAX_LENGTH: usize = 1024;
pub const MIN_WORDS: usize = 3;
pub const MAX_WORDS: usize = 64;

/// The EFF large wordlist (2016), verbatim: `<dice code>\t<word>` per line.
/// SHA-256 pinned by a test; source: <https://www.eff.org/dice>.
const EFF_LARGE_WORDLIST: &str = include_str!("eff_large_wordlist.txt");

static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    EFF_LARGE_WORDLIST
        .lines()
        .map(|line| line.split_once('\t').expect("wordlist line has a tab").1)
        .collect()
});

/// The BIP-39 Portuguese wordlist (pinned in `bip39`): 2048 words, only
/// `a`-`z` (no accents to type), each fixed by its first four letters.
static WORDS_PT_BR: &LazyLock<Vec<&'static str>> = &crate::bip39::PORTUGUESE;

/// The language of passphrase words: people remember a scene better in
/// their own language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    /// EFF large wordlist, 7776 words, 12.9 bits each.
    #[default]
    English,
    /// BIP-39 Portuguese (Brazilian) wordlist, 2048 words, 11 bits each.
    PortugueseBr,
}

impl Language {
    fn words(self) -> &'static [&'static str] {
        match self {
            Self::English => &WORDS,
            Self::PortugueseBr => WORDS_PT_BR,
        }
    }
}

/// A generated secret and its entropy.
#[derive(Debug)]
pub struct Generated {
    pub secret: SecretString,
    pub entropy_bits: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneratorError {
    NoCharacterClass,
    LengthOutOfRange { length: usize },
    LengthBelowClasses { length: usize, classes: usize },
    WordsOutOfRange { words: usize },
}

impl fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCharacterClass => f.write_str("at least one character class must be enabled"),
            Self::LengthOutOfRange { length } => {
                write!(f, "length {length} is outside {MIN_LENGTH}..={MAX_LENGTH}")
            }
            Self::LengthBelowClasses { length, classes } => write!(
                f,
                "length {length} cannot hold one character from each of {classes} classes"
            ),
            Self::WordsOutOfRange { words } => {
                write!(f, "{words} words is outside {MIN_WORDS}..={MAX_WORDS}")
            }
        }
    }
}

impl std::error::Error for GeneratorError {}

/// Random characters, with at least one from every enabled class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // four independent switches, as the user sees them
pub struct PasswordSpec {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

/// Letters and digits, 29 characters: the style the user liked in
/// Contabo's generator (2026-10-17). 172.6 bits, more than 24 characters
/// with symbols (157.2), and nothing that breaks in a form, a shell or a URL,
/// or stops a double-click from selecting it. Symbols are opt-in, for sites
/// that demand one.
impl Default for PasswordSpec {
    fn default() -> Self {
        Self {
            length: 29,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: false,
            avoid_ambiguous: false,
        }
    }
}

/// Words drawn from the wordlist of `language`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseSpec {
    pub words: usize,
    pub separator: String,
    pub language: Language,
}

impl Default for PassphraseSpec {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".to_owned(),
            language: Language::English,
        }
    }
}

pub fn generate_password<R: CryptoRng + ?Sized>(
    spec: &PasswordSpec,
    rng: &mut R,
) -> Result<Generated, GeneratorError> {
    let classes: Vec<Vec<u8>> = [
        (spec.lowercase, LOWERCASE),
        (spec.uppercase, UPPERCASE),
        (spec.digits, DIGITS),
        (spec.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    .map(|(_, set)| {
        set.iter()
            .copied()
            .filter(|c| !(spec.avoid_ambiguous && AMBIGUOUS.contains(c)))
            .collect()
    })
    .collect();

    if classes.is_empty() {
        return Err(GeneratorError::NoCharacterClass);
    }
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&spec.length) {
        return Err(GeneratorError::LengthOutOfRange {
            length: spec.length,
        });
    }
    if spec.length < classes.len() {
        return Err(GeneratorError::LengthBelowClasses {
            length: spec.length,
            classes: classes.len(),
        });
    }

    let alphabet: Vec<u8> = classes.concat();
    // Rejection sampling: draw uniformly from the whole alphabet and start
    // over if a class is missing. The result is uniform over exactly the
    // strings that satisfy the policy, which is what the entropy counts.
    let mut buf = Zeroizing::new(vec![0u8; spec.length]);
    loop {
        for byte in buf.iter_mut() {
            *byte = alphabet[uniform_index(rng, alphabet.len())];
        }
        if classes
            .iter()
            .all(|class| buf.iter().any(|c| class.contains(c)))
        {
            break;
        }
    }

    let sizes: Vec<usize> = classes.iter().map(Vec::len).collect();
    Ok(Generated {
        secret: exact_secret(&buf),
        entropy_bits: password_entropy_bits(&sizes, spec.length),
    })
}

pub fn generate_passphrase<R: CryptoRng + ?Sized>(
    spec: &PassphraseSpec,
    rng: &mut R,
) -> Result<Generated, GeneratorError> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&spec.words) {
        return Err(GeneratorError::WordsOutOfRange { words: spec.words });
    }
    let words = spec.language.words();
    let picks = Zeroizing::new(
        (0..spec.words)
            .map(|_| uniform_index(rng, words.len()))
            .collect::<Vec<usize>>(),
    );

    let mut buf = Zeroizing::new(Vec::new());
    for (n, &i) in picks.iter().enumerate() {
        if n > 0 {
            buf.extend_from_slice(spec.separator.as_bytes());
        }
        buf.extend_from_slice(words[i].as_bytes());
    }

    #[allow(clippy::cast_precision_loss)] // both values are tiny
    let entropy_bits = spec.words as f64 * (words.len() as f64).log2();
    Ok(Generated {
        secret: exact_secret(&buf),
        entropy_bits,
    })
}

/// A uniform index in `0..n`, by rejection: draws landing in the incomplete
/// last block of `2^32 mod n` values are discarded, so no index is favoured.
fn uniform_index<R: CryptoRng + ?Sized>(rng: &mut R, n: usize) -> usize {
    let n = u64::try_from(n).expect("usize fits in u64");
    assert!(n > 0 && n <= 1 << 32, "range out of bounds");
    let limit = (1u64 << 32) - (1u64 << 32) % n;
    loop {
        let x = u64::from(rng.next_u32());
        if x < limit {
            return usize::try_from(x % n).expect("index below n");
        }
    }
}

/// Copies `bytes` (UTF-8) into a secret without leaving a stray copy behind:
/// the `String` is allocated with the exact size, so turning it into a boxed
/// `str` does not reallocate.
fn exact_secret(bytes: &[u8]) -> SecretString {
    let text = std::str::from_utf8(bytes).expect("generator output is UTF-8");
    let mut owned = String::with_capacity(text.len());
    owned.push_str(text);
    SecretString::from(owned)
}

/// `log2` of the number of strings of `length` over the union of disjoint
/// classes of the given sizes that contain at least one character of each.
///
/// Inclusion-exclusion, normalized by `N^length` to stay within `f64`:
/// `count = N^L * sum over subsets S of (-1)^|S| * (1 - |S chars| / N)^L`.
fn password_entropy_bits(class_sizes: &[usize], length: usize) -> f64 {
    #[allow(clippy::cast_precision_loss)] // sizes and lengths are small
    let total = class_sizes.iter().sum::<usize>() as f64;
    let length_i32 = i32::try_from(length).expect("length is bounded");
    let mut fraction = 0.0;
    for subset in 0u32..(1 << class_sizes.len()) {
        #[allow(clippy::cast_precision_loss)]
        let excluded = class_sizes
            .iter()
            .enumerate()
            .filter(|(i, _)| subset & (1 << i) != 0)
            .map(|(_, size)| *size)
            .sum::<usize>() as f64;
        let term = (1.0 - excluded / total).powi(length_i32);
        fraction += if subset.count_ones() % 2 == 0 {
            term
        } else {
            -term
        };
    }
    #[allow(clippy::cast_precision_loss)]
    let length_f = length as f64;
    length_f * total.log2() + fraction.log2()
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom::SysRng;
    use rand_core::{TryCryptoRng, TryRng, UnwrapErr};
    use secrecy::ExposeSecret;
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;
    use std::convert::Infallible;
    use std::fmt::Write as _;

    fn os_rng() -> UnwrapErr<SysRng> {
        UnwrapErr(SysRng)
    }

    /// Replays fixed values; marked cryptographic only so tests can drive
    /// the generator deterministically.
    struct Scripted(std::vec::IntoIter<u32>);

    impl TryRng for Scripted {
        type Error = Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            Ok(self.0.next().expect("script exhausted"))
        }
        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            unimplemented!()
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Infallible> {
            unimplemented!()
        }
    }
    impl TryCryptoRng for Scripted {}

    #[test]
    fn wordlist_is_the_pinned_eff_file() {
        let digest = Sha256::digest(EFF_LARGE_WORDLIST.as_bytes());
        let hex = digest.iter().fold(String::new(), |mut s, b| {
            write!(s, "{b:02x}").unwrap();
            s
        });
        assert_eq!(
            hex,
            "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
        );
        assert_eq!(WORDS.len(), 7776);
        assert_eq!(WORDS.iter().collect::<HashSet<_>>().len(), 7776);
    }

    #[test]
    fn portuguese_passphrase_uses_listed_words() {
        let spec = PassphraseSpec {
            words: 7,
            language: Language::PortugueseBr,
            ..PassphraseSpec::default()
        };
        let g = generate_passphrase(&spec, &mut os_rng()).unwrap();
        let set: HashSet<&str> = WORDS_PT_BR.iter().copied().collect();
        let parts: Vec<&str> = g.secret.expose_secret().split('-').collect();
        assert_eq!(parts.len(), 7);
        assert!(parts.iter().all(|p| set.contains(p)));
        assert!((g.entropy_bits - 77.0).abs() < 1e-9, "{}", g.entropy_bits);
    }

    #[test]
    fn hyphen_separator_is_unambiguous() {
        // A hyphenated word could collide with two words joined by "-" only
        // if both halves were words too; then the entropy would overcount.
        let set: HashSet<&str> = WORDS.iter().copied().collect();
        for word in WORDS.iter().filter(|w| w.contains('-')) {
            let (a, b) = word.split_once('-').unwrap();
            assert!(!(set.contains(a) && set.contains(b)), "{word}");
        }
    }

    #[test]
    fn uniform_index_rejects_the_incomplete_block() {
        // n = 3: 2^32 mod 3 = 1, so the limit is 2^32 - 1 and u32::MAX is
        // the only value rejected.
        let mut rng = Scripted(vec![u32::MAX, u32::MAX, 7].into_iter());
        assert_eq!(uniform_index(&mut rng, 3), 1);
        let mut rng = Scripted(vec![u32::MAX - 1].into_iter());
        assert_eq!(
            uniform_index(&mut rng, 3),
            usize::try_from((u32::MAX - 1) % 3).unwrap()
        );
    }

    #[test]
    fn entropy_matches_brute_force_count() {
        // Classes of sizes 2 and 3 (5 symbols), length 3: count strings
        // with at least one symbol of each class by enumeration.
        for (sizes, length) in [(vec![2, 3], 3), (vec![1, 2, 2], 4), (vec![4], 5)] {
            let total: usize = sizes.iter().sum();
            let class_of: Vec<usize> = sizes
                .iter()
                .enumerate()
                .flat_map(|(c, &s)| std::iter::repeat_n(c, s))
                .collect();
            let mut count = 0u32;
            for n in 0..total.pow(u32::try_from(length).unwrap()) {
                let mut seen = vec![false; sizes.len()];
                let mut rest = n;
                for _ in 0..length {
                    seen[class_of[rest % total]] = true;
                    rest /= total;
                }
                if seen.iter().all(|&s| s) {
                    count += 1;
                }
            }
            let expected = f64::from(count).log2();
            let got = password_entropy_bits(&sizes, length);
            assert!(
                (got - expected).abs() < 1e-9,
                "{sizes:?} {length}: {got} vs {expected}"
            );
        }
    }

    #[test]
    fn default_password_is_29_letters_and_digits_about_172_bits() {
        let spec = PasswordSpec::default();
        for _ in 0..200 {
            let g = generate_password(&spec, &mut os_rng()).unwrap();
            let p = g.secret.expose_secret().as_bytes();
            assert_eq!(p.len(), 29);
            assert!(p.iter().all(u8::is_ascii_alphanumeric));
            for class in [LOWERCASE, UPPERCASE, DIGITS] {
                assert!(p.iter().any(|c| class.contains(c)));
            }
        }
        let bits = generate_password(&spec, &mut os_rng())
            .unwrap()
            .entropy_bits;
        // 29 * log2(62) = 172.67, minus a little for the class requirement.
        assert!((172.0..172.68).contains(&bits), "{bits}");
    }

    #[test]
    fn symbols_on_request_give_every_class_and_about_157_bits_at_24() {
        let spec = PasswordSpec {
            length: 24,
            symbols: true,
            ..PasswordSpec::default()
        };
        for _ in 0..200 {
            let g = generate_password(&spec, &mut os_rng()).unwrap();
            let p = g.secret.expose_secret().as_bytes();
            for class in [LOWERCASE, UPPERCASE, DIGITS, SYMBOLS] {
                assert!(p.iter().any(|c| class.contains(c)));
            }
        }
        let bits = generate_password(&spec, &mut os_rng())
            .unwrap()
            .entropy_bits;
        // 24 * log2(94) = 157.3, minus a little for the class requirement.
        assert!((156.0..157.3).contains(&bits), "{bits}");
    }

    #[test]
    fn avoid_ambiguous_removes_them() {
        let spec = PasswordSpec {
            length: 200,
            avoid_ambiguous: true,
            ..PasswordSpec::default()
        };
        for _ in 0..50 {
            let g = generate_password(&spec, &mut os_rng()).unwrap();
            assert!(
                !g.secret
                    .expose_secret()
                    .bytes()
                    .any(|c| AMBIGUOUS.contains(&c))
            );
        }
    }

    #[test]
    fn digits_only_pin() {
        let spec = PasswordSpec {
            length: 6,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            avoid_ambiguous: false,
        };
        let g = generate_password(&spec, &mut os_rng()).unwrap();
        assert!(g.secret.expose_secret().bytes().all(|c| c.is_ascii_digit()));
        assert!((g.entropy_bits - 6.0 * 10f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn invalid_password_specs_are_rejected() {
        let none = PasswordSpec {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..PasswordSpec::default()
        };
        assert_eq!(
            generate_password(&none, &mut os_rng()).unwrap_err(),
            GeneratorError::NoCharacterClass
        );
        for length in [0, 3, MAX_LENGTH + 1] {
            let spec = PasswordSpec {
                length,
                ..PasswordSpec::default()
            };
            assert_eq!(
                generate_password(&spec, &mut os_rng()).unwrap_err(),
                GeneratorError::LengthOutOfRange { length }
            );
        }
    }

    #[test]
    fn passphrase_uses_listed_words() {
        let spec = PassphraseSpec::default();
        let g = generate_passphrase(&spec, &mut os_rng()).unwrap();
        let set: HashSet<&str> = WORDS.iter().copied().collect();
        // Rebuild the words greedily, allowing for the four hyphenated ones.
        let parts: Vec<&str> = g.secret.expose_secret().split('-').collect();
        let mut i = 0;
        let mut words = 0;
        while i < parts.len() {
            if i + 1 < parts.len()
                && set.contains(format!("{}-{}", parts[i], parts[i + 1]).as_str())
            {
                i += 2;
            } else {
                assert!(set.contains(parts[i]), "{}", parts[i]);
                i += 1;
            }
            words += 1;
        }
        assert_eq!(words, 6);
        assert!((g.entropy_bits - 77.55).abs() < 0.01, "{}", g.entropy_bits);
    }

    #[test]
    fn passphrase_word_count_is_bounded() {
        for words in [0, 2, MAX_WORDS + 1] {
            let spec = PassphraseSpec {
                words,
                ..PassphraseSpec::default()
            };
            assert_eq!(
                generate_passphrase(&spec, &mut os_rng()).unwrap_err(),
                GeneratorError::WordsOutOfRange { words }
            );
        }
    }

    #[test]
    fn characters_are_roughly_uniform() {
        // 2,000 digit-only passwords of 50 characters: each digit should
        // appear ~10,000 times; 5 standard deviations is ~475.
        let spec = PasswordSpec {
            length: 50,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            avoid_ambiguous: false,
        };
        let mut counts = [0u32; 10];
        for _ in 0..2000 {
            let g = generate_password(&spec, &mut os_rng()).unwrap();
            for c in g.secret.expose_secret().bytes() {
                counts[usize::from(c - b'0')] += 1;
            }
        }
        for count in counts {
            assert!((9525..=10475).contains(&count), "{counts:?}");
        }
    }
}
