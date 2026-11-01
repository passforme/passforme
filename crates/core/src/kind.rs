//! Kinds of item and what each one asks for.
//!
//! Every kind is stored in the same [`Item`](crate::item::Item): the common
//! slots (`username`, `password`, `urls`, `totp`, `notes`) under a label that
//! suits the kind ("PIN", "Key", "Words"), plus named extra fields in a fixed
//! order. A kind is a template for prompting and showing, not a schema: any
//! item can still take any extra field, and nothing is lost if a template
//! changes later. Recovery codes are the one kind with storage of its own
//! (`Item::codes`), since each code is used once.

use serde::{Deserialize, Serialize};

/// What an item is. Stored as kebab-case text; an item from a newer
/// version with a kind this one does not know reads as `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    #[default]
    Login,
    Note,
    RecoveryCodes,
    RecoveryPhrase,
    SecurityQuestions,
    Pin,
    ApiKey,
    CryptoSeed,
    SshKey,
    Card,
    Bank,
    Wifi,
    License,
    Document,
    #[serde(other)]
    Other,
}

/// One thing a kind asks for, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// `Item::username`, shown under this label.
    Username(&'static str),
    /// `Item::password`, the item's main secret, under this label.
    Password(&'static str),
    Urls,
    Totp,
    /// A named extra field.
    Field {
        name: &'static str,
        concealed: bool,
    },
    /// Question and answer pairs, as concealed extra fields.
    Questions,
    /// `Item::codes`.
    Codes,
    Notes,
}

use Slot::{Codes, Field, Notes, Password, Questions, Totp, Urls, Username};

// Macros, not functions: the templates must stay constant expressions to
// be `'static` slices.
macro_rules! visible {
    ($name:literal) => {
        Field {
            name: $name,
            concealed: false,
        }
    };
}

macro_rules! hidden {
    ($name:literal) => {
        Field {
            name: $name,
            concealed: true,
        }
    };
}

impl Kind {
    pub const ALL: [Self; 14] = [
        Self::Login,
        Self::Note,
        Self::RecoveryCodes,
        Self::RecoveryPhrase,
        Self::SecurityQuestions,
        Self::Pin,
        Self::ApiKey,
        Self::CryptoSeed,
        Self::SshKey,
        Self::Card,
        Self::Bank,
        Self::Wifi,
        Self::License,
        Self::Document,
    ];

    /// The name used on the command line and in the vault.
    pub fn name(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Note => "note",
            Self::RecoveryCodes => "recovery-codes",
            Self::RecoveryPhrase => "recovery-phrase",
            Self::SecurityQuestions => "security-questions",
            Self::Pin => "pin",
            Self::ApiKey => "api-key",
            Self::CryptoSeed => "crypto-seed",
            Self::SshKey => "ssh-key",
            Self::Card => "card",
            Self::Bank => "bank",
            Self::Wifi => "wifi",
            Self::License => "license",
            Self::Document => "document",
            Self::Other => "other",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.name().eq_ignore_ascii_case(name))
    }

    /// What the kind is for, one line.
    pub fn about(self) -> &'static str {
        match self {
            Self::Login => "a website or app account: username, password, URLs, TOTP",
            Self::Note => "free text",
            Self::RecoveryCodes => "backup codes of an account, each used once",
            Self::RecoveryPhrase => {
                "an account's recovery phrase (Proton…), BIP-39 checked when it is one"
            }
            Self::SecurityQuestions => "questions and their answers",
            Self::Pin => "a numeric code: phone, card, alarm, lock",
            Self::ApiKey => "an API key or token: its name at the provider, expiry",
            Self::CryptoSeed => "a wallet's recovery phrase (BIP-39 checked) and passphrase",
            Self::SshKey => "an SSH or GPG private key, read from its file",
            Self::Card => "a payment card: number (Luhn checked), expiry, CVV, PIN",
            Self::Bank => "a bank account: branch, account, passwords, Pix key",
            Self::Wifi => "a Wi-Fi network and its password",
            Self::License => "a software license key",
            Self::Document => "an ID document: number, dates, issuer",
            Self::Other => "a kind from a newer version",
        }
    }

    /// What to ask for, in order.
    pub fn slots(self) -> &'static [Slot] {
        match self {
            Self::Login | Self::Other => &[Username("Username"), Password("Password"), Urls, Totp],
            Self::Note => &[Notes],
            Self::RecoveryCodes => &[Username("Account"), Urls, Codes],
            Self::RecoveryPhrase => &[Username("Account"), Urls, Password("Words")],
            Self::SecurityQuestions => &[Username("Account"), Urls, Questions],
            Self::Pin => &[Password("PIN")],
            Self::ApiKey => &[
                Username("Account"),
                visible!("Key name"),
                Password("Key"),
                Urls,
                visible!("Expires"),
            ],
            Self::CryptoSeed => &[
                Password("Words"),
                hidden!("Passphrase"),
                visible!("Wallet"),
                visible!("Network"),
            ],
            Self::SshKey => &[
                Username("User"),
                Password("Private key"),
                visible!("Public key"),
                hidden!("Key passphrase"),
                Urls,
            ],
            Self::Card => &[
                visible!("Cardholder"),
                Password("Number"),
                visible!("Expiry"),
                hidden!("CVV"),
                hidden!("PIN"),
            ],
            Self::Bank => &[
                visible!("Bank"),
                visible!("Branch"),
                visible!("Account"),
                Username("Login"),
                Password("App password"),
                hidden!("Transaction password"),
                visible!("Pix key"),
                Urls,
            ],
            Self::Wifi => &[Username("Network"), Password("Password")],
            Self::License => &[Username("Registered to"), Password("License key"), Urls],
            Self::Document => &[
                visible!("Number"),
                visible!("Issued"),
                visible!("Expires"),
                visible!("Issuer"),
            ],
        }
    }

    /// The label of `username`, or `None` when the kind does not use it.
    pub fn username_label(self) -> Option<&'static str> {
        self.slots().iter().find_map(|s| match s {
            Username(label) => Some(*label),
            _ => None,
        })
    }

    /// The label of `password`, or `None` when the kind does not use it.
    pub fn password_label(self) -> Option<&'static str> {
        self.slots().iter().find_map(|s| match s {
            Password(label) => Some(*label),
            _ => None,
        })
    }
}

/// One recovery code and whether it was used.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, zeroize::Zeroize)]
pub struct Code {
    pub code: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub used: bool,
}

/// The Luhn check digit of a card number (spaces and dashes ignored); also
/// false for anything but 12 to 19 digits.
pub fn luhn_ok(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .map(|c| c.to_digit(10))
        .collect::<Option<_>>()
        .unwrap_or_default();
    if !(12..=19).contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| match (i % 2, d * 2) {
            (0, _) => d,
            (_, doubled) if doubled > 9 => doubled - 9,
            (_, doubled) => doubled,
        })
        .sum();
    sum.is_multiple_of(10)
}

/// A card expiry as `MM/YY` or `MM/YYYY`.
pub fn expiry_ok(text: &str) -> bool {
    let Some((month, year)) = text.trim().split_once('/') else {
        return false;
    };
    let month_ok = month.len() == 2 && month.parse::<u8>().is_ok_and(|m| (1..=12).contains(&m));
    let year_ok = matches!(year.len(), 2 | 4) && year.bytes().all(|b| b.is_ascii_digit());
    month_ok && year_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_match_serde() {
        for kind in Kind::ALL {
            assert_eq!(Kind::from_name(kind.name()), Some(kind));
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{}\"", kind.name()));
        }
        assert_eq!(Kind::from_name("CARD"), Some(Kind::Card));
        assert_eq!(Kind::from_name("nope"), None);
    }

    #[test]
    fn unknown_kind_from_a_newer_version_reads_as_other() {
        let kind: Kind = serde_json::from_str("\"passkey\"").unwrap();
        assert_eq!(kind, Kind::Other);
    }

    #[test]
    fn every_kind_names_each_field_once() {
        for kind in Kind::ALL {
            let mut names: Vec<&str> = kind
                .slots()
                .iter()
                .filter_map(|s| match s {
                    Field { name, .. } => Some(*name),
                    _ => None,
                })
                .collect();
            let count = names.len();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), count, "{kind:?}");
        }
    }

    #[test]
    fn luhn() {
        assert!(luhn_ok("4111 1111 1111 1111"));
        assert!(luhn_ok("5555-5555-5555-4444"));
        assert!(luhn_ok("378282246310005"));
        assert!(!luhn_ok("4111 1111 1111 1112"));
        assert!(!luhn_ok("4111"));
        assert!(!luhn_ok("4111 1111 1111 111x"));
    }

    #[test]
    fn expiry() {
        assert!(expiry_ok("07/29"));
        assert!(expiry_ok("12/2031"));
        assert!(!expiry_ok("13/29"));
        assert!(!expiry_ok("7/29"));
        assert!(!expiry_ok("0729"));
    }
}
