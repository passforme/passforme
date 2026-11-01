//! What a vault item holds, and its plaintext encoding (JSON) before sealing.
//!
//! JSON rather than a compact binary format: the vault must stay readable
//! for decades, and a self-describing format lets later versions add fields
//! (`#[serde(default)]`) without migrating every item.

use std::fmt;
use std::io::Write;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::kind::{Code, Kind};

/// One login, note or anything else worth keeping. Every string is wiped
/// when the item is dropped; the type is deliberately not `Clone`.
#[derive(Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Item {
    pub title: String,
    /// Absent (login) in items written before kinds existed.
    #[serde(default, skip_serializing_if = "is_login")]
    #[zeroize(skip)]
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    /// TOTP secret (base32) or `otpauth://` URI.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub totp: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<Field>,
    /// Recovery codes (kind `recovery-codes`), in the order given.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub codes: Vec<Code>,
    /// Small files kept with the item (a service's recovery file).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
    /// Handed to the unlock agent, where programs can read it without the
    /// master password (API keys and the like); everything else never is.
    #[serde(default, skip_serializing_if = "is_false")]
    pub agent: bool,
    /// Unix seconds.
    pub created: u64,
    pub modified: u64,
}

/// A free-form extra field; `concealed` ones are masked like the password.
#[derive(Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Field {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub concealed: bool,
}

/// A file kept inside an item, sealed with it. Its bytes are standard
/// base64 in the JSON, so the item stays one self-describing document.
#[derive(Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Attachment {
    /// The file's name, without directories.
    pub name: String,
    /// The content, standard base64.
    pub data: String,
}

impl fmt::Debug for Attachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attachment")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("title", &self.title)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Item {
    /// The JSON plaintext, in a buffer allocated once at its exact size (the
    /// length is measured by a first, discarding pass) and wiped on drop.
    pub fn to_plaintext(&self) -> Zeroizing<Vec<u8>> {
        let mut counter = Counter(0);
        serde_json::to_writer(&mut counter, self).expect("an item always serializes");
        let mut out = Zeroizing::new(Vec::with_capacity(counter.0));
        serde_json::to_writer(&mut *out, self).expect("an item always serializes");
        debug_assert_eq!(out.len(), out.capacity());
        out
    }

    /// Parses a plaintext produced by [`Item::to_plaintext`]. Strings without
    /// escapes are copied straight into their final allocation; `serde_json`
    /// only uses (unwiped) scratch space for strings containing escapes.
    pub fn from_plaintext(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's signature
fn is_false(value: &bool) -> bool {
    !*value
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's signature
fn is_login(kind: &Kind) -> bool {
    *kind == Kind::Login
}

struct Counter(usize);

impl Write for Counter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Item {
        Item {
            title: "Example \"quoted\" é".into(),
            username: "eduardo".into(),
            password: "p@ss\\word".into(),
            urls: vec!["https://example.com".into()],
            notes: "line 1\nline 2".into(),
            totp: "JBSWY3DPEHPK3PXP".into(),
            fields: vec![Field {
                name: "PIN".into(),
                value: "1234".into(),
                concealed: true,
            }],
            kind: Kind::Card,
            codes: vec![
                Code {
                    code: "1111-2222".into(),
                    used: true,
                },
                Code {
                    code: "3333 4444".into(),
                    used: false,
                },
            ],
            attachments: vec![Attachment {
                name: "recovery.txt".into(),
                data: "aGVsbG8=".into(),
            }],
            agent: true,
            created: 1,
            modified: 2,
        }
    }

    #[test]
    fn round_trips() {
        let item = sample();
        let plain = item.to_plaintext();
        assert_eq!(Item::from_plaintext(&plain).unwrap(), item);
    }

    #[test]
    fn empty_fields_are_omitted_and_defaulted() {
        let mut item = Item::default();
        item.title = "t".into();
        let plain = item.to_plaintext();
        assert_eq!(&plain[..], br#"{"title":"t","created":0,"modified":0}"#);
        assert_eq!(Item::from_plaintext(&plain).unwrap(), item);
    }

    #[test]
    fn items_from_before_kinds_read_as_logins() {
        let item = Item::from_plaintext(
            br#"{"title":"t","username":"u","password":"p","created":0,"modified":0}"#,
        )
        .unwrap();
        assert_eq!(item.kind, Kind::Login);
        assert!(item.codes.is_empty());
    }

    #[test]
    fn unknown_fields_from_a_newer_version_are_ignored() {
        let item =
            Item::from_plaintext(br#"{"title":"t","created":0,"modified":0,"future":1}"#).unwrap();
        assert_eq!(item.title, "t");
    }

    #[test]
    fn debug_shows_only_the_title() {
        let text = format!("{:?}", sample());
        assert_eq!(text, r#"Item { title: "Example \"quoted\" é", .. }"#);
    }

    #[test]
    fn attachment_debug_hides_the_content() {
        let item = sample();
        let text = format!("{:?}", item.attachments[0]);
        assert_eq!(text, r#"Attachment { name: "recovery.txt", .. }"#);
    }
}
