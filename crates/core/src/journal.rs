//! The agent journal: what a writable unlock agent wrote, waiting for a
//! command that holds the vault key to bring it into the vault.
//!
//! The agent never has the vault key, so it cannot seal an item into the
//! vault. It holds a *journal key* instead, random and wrapped under the
//! vault key in the journal's head, and appends every item it creates or
//! changes, sealed under that key (`seal.rs`). The journal is text, one
//! line each:
//!
//! ```text
//! {"format":1,"account_id":"…","journal_id":"…","key":"…"}
//! <entry 0, base64>
//! <entry 1, base64>
//! ```
//!
//! An entry's plaintext is `{"id":"…","item":{…}}`: the whole item as it
//! is after the write. [`apply`] brings entries into a vault and is where
//! the rules are enforced, whatever the agent process let through: only
//! agent-made items are created or changed, never the owner's.

use std::fmt;

use base64ct::{Base64, Encoding};
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::item::{Item, Origin};
use crate::kdf::AccountId;
use crate::seal::{self, ItemId, JournalId, JournalKey, SealError, Sealed};
use crate::vault::{UnlockedVault, VaultError};

pub const JOURNAL_FORMAT: u32 = 1;
/// Most agent-made items a vault takes.
pub const MAX_AGENT_ITEMS: usize = 200;
/// Largest agent-made item, as plaintext JSON.
pub const MAX_AGENT_ITEM_LEN: usize = 64 * 1024;
/// Largest journal file; writes fail beyond it until it is imported.
pub const MAX_JOURNAL_LEN: u64 = 4 << 20;

#[derive(Debug, PartialEq, Eq)]
pub enum JournalError {
    /// Not a journal this version understands.
    Format(String),
    /// Written for another vault.
    OtherAccount,
    /// Its key did not open with this vault's key.
    WrongKey,
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(why) => write!(f, "not a valid agent journal: {why}"),
            Self::OtherAccount => f.write_str("the agent journal belongs to another vault"),
            Self::WrongKey => f.write_str("the agent journal does not open with this vault's key"),
        }
    }
}

impl std::error::Error for JournalError {}

/// The first line of a journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub account_id: AccountId,
    pub journal_id: JournalId,
    /// The journal key, wrapped under the vault key.
    pub key: Sealed,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadJson {
    format: u32,
    account_id: String,
    journal_id: String,
    key: String,
}

fn decode_fixed<const N: usize>(what: &str, text: &str) -> Result<[u8; N], JournalError> {
    Base64::decode_vec(text)
        .ok()
        .and_then(|v| <[u8; N]>::try_from(v).ok())
        .ok_or_else(|| JournalError::Format(format!("bad {what}")))
}

impl Head {
    /// A head for a new journal of `vault`, and the bare key to hand the
    /// unlock agent.
    pub fn create<R: CryptoRng + ?Sized>(vault: &UnlockedVault, rng: &mut R) -> (Self, JournalKey) {
        let journal_id = JournalId::generate(rng);
        let journal_key = JournalKey::generate(rng);
        let key = vault.wrap_journal_key(&journal_key, &journal_id, rng);
        let head = Self {
            account_id: vault.file().account_id,
            journal_id,
            key,
        };
        (head, journal_key)
    }

    /// The head as its line, without the newline.
    pub fn to_line(&self) -> String {
        serde_json::to_string(&HeadJson {
            format: JOURNAL_FORMAT,
            account_id: Base64::encode_string(self.account_id.as_bytes()),
            journal_id: Base64::encode_string(self.journal_id.as_bytes()),
            key: Base64::encode_string(self.key.as_bytes()),
        })
        .expect("the head always serializes")
    }

    pub fn from_line(line: &str) -> Result<Self, JournalError> {
        let head: HeadJson =
            serde_json::from_str(line).map_err(|e| JournalError::Format(e.to_string()))?;
        if head.format != JOURNAL_FORMAT {
            return Err(JournalError::Format(format!(
                "format {} is not supported (expected {JOURNAL_FORMAT})",
                head.format
            )));
        }
        let key = Base64::decode_vec(&head.key)
            .ok()
            .and_then(|v| Sealed::from_bytes(v).ok())
            .ok_or_else(|| JournalError::Format("bad key".into()))?;
        Ok(Self {
            account_id: AccountId::from_bytes(decode_fixed("account id", &head.account_id)?),
            journal_id: JournalId::from_bytes(decode_fixed("journal id", &head.journal_id)?),
            key,
        })
    }

    /// The journal key, for the vault this journal was written for.
    pub fn unwrap_key(&self, vault: &UnlockedVault) -> Result<JournalKey, JournalError> {
        if self.account_id != vault.file().account_id {
            return Err(JournalError::OtherAccount);
        }
        vault
            .unwrap_journal_key(&self.key, &self.journal_id)
            .map_err(|_| JournalError::WrongKey)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryJson {
    id: String,
    item: Item,
}

/// Why an item cannot be an agent-made one, if it cannot. Checked by the
/// unlock agent before it writes and again by [`apply`].
pub fn check_item(item: &Item) -> Result<(), &'static str> {
    if item.origin != Origin::Agent || !item.agent {
        return Err("it is not marked as made by an agent");
    }
    if item.title.trim().is_empty() {
        return Err("it has no title");
    }
    if !item.attachments.is_empty() {
        return Err("agent-made items take no attachments");
    }
    if item.to_plaintext().len() > MAX_AGENT_ITEM_LEN {
        return Err("it is larger than an agent-made item may be (64 KiB)");
    }
    Ok(())
}

/// One entry as its line (base64, no newline): `item` under `id`, sealed
/// for place `sequence` of the journal.
pub fn seal_entry<R: CryptoRng + ?Sized>(
    key: &JournalKey,
    account_id: &AccountId,
    journal_id: &JournalId,
    sequence: u64,
    id: &ItemId,
    item: &Item,
    rng: &mut R,
) -> Result<String, SealError> {
    let item_json = item.to_plaintext();
    let id_text = Base64::encode_string(id.as_bytes());
    let mut plain = Zeroizing::new(Vec::with_capacity(item_json.len() + id_text.len() + 18));
    plain.extend_from_slice(b"{\"id\":\"");
    plain.extend_from_slice(id_text.as_bytes());
    plain.extend_from_slice(b"\",\"item\":");
    plain.extend_from_slice(&item_json);
    plain.push(b'}');
    let sealed = seal::seal_journal_entry(key, account_id, journal_id, sequence, &plain, rng)?;
    Ok(Base64::encode_string(sealed.as_bytes()))
}

/// Opens the entry at place `sequence`; `None` for anything that is not
/// that entry of this journal (damaged, forged, moved from elsewhere).
pub fn open_entry(
    line: &str,
    key: &JournalKey,
    account_id: &AccountId,
    journal_id: &JournalId,
    sequence: u64,
) -> Option<(ItemId, Item)> {
    let sealed = Sealed::from_bytes(Base64::decode_vec(line.trim()).ok()?).ok()?;
    let plain = seal::open_journal_entry(&sealed, key, account_id, journal_id, sequence).ok()?;
    let entry: EntryJson = serde_json::from_slice(&plain).ok()?;
    let id = <[u8; seal::ITEM_ID_LEN]>::try_from(Base64::decode_vec(&entry.id).ok()?).ok()?;
    Some((ItemId::from_bytes(id), entry.item))
}

/// What [`apply`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// Titles of the items created or changed, each once.
    pub changed: Vec<String>,
    /// Entries refused, each as a sentence for the owner.
    pub skipped: Vec<String>,
}

/// Brings journal entries into `vault`, in order. An entry may create an
/// agent-made item or replace one; anything else is skipped and reported:
/// the agent process is not trusted to have checked.
pub fn apply<R: CryptoRng + ?Sized>(
    vault: &mut UnlockedVault,
    entries: Vec<(ItemId, Item)>,
    rng: &mut R,
) -> Result<Applied, VaultError> {
    let mut applied = Applied::default();
    let mut agent_made = vault
        .items()?
        .iter()
        .filter(|(_, item)| item.origin == Origin::Agent)
        .count();
    for (id, item) in entries {
        if let Err(why) = check_item(&item) {
            applied
                .skipped
                .push(format!("'{}' was not taken: {why}", item.title));
            continue;
        }
        if vault.revision_of(&id).is_some() {
            let current = vault.get(&id)?;
            if current.origin != Origin::Agent {
                applied.skipped.push(format!(
                    "a change to '{}' was not taken: the item is not agent-made",
                    current.title
                ));
                continue;
            }
            if current == item {
                continue;
            }
            vault.update(&id, &item, rng)?;
        } else {
            if agent_made >= MAX_AGENT_ITEMS {
                applied.skipped.push(format!(
                    "'{}' was not taken: the vault already holds {MAX_AGENT_ITEMS} agent-made items",
                    item.title
                ));
                continue;
            }
            vault.insert(id, 1, &item, rng)?;
            agent_made += 1;
        }
        if !applied.changed.contains(&item.title) {
            applied.changed.push(item.title.clone());
        }
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{KdfParams, SecretKey};
    use getrandom::SysRng;
    use rand_core::UnwrapErr;
    use secrecy::SecretString;

    fn rng() -> UnwrapErr<SysRng> {
        UnwrapErr(SysRng)
    }

    fn vault() -> UnlockedVault {
        let params =
            KdfParams::new(KdfParams::MIN_MEMORY_KIB, KdfParams::MIN_ITERATIONS, 1).unwrap();
        UnlockedVault::create(
            &SecretString::from("master password"),
            &SecretKey::generate(&mut rng()),
            &params,
            &mut rng(),
        )
        .unwrap()
    }

    fn agent_item(title: &str, password: &str) -> Item {
        let mut item = Item::default();
        item.title = title.into();
        item.password = password.into();
        item.agent = true;
        item.origin = Origin::Agent;
        item
    }

    fn id(byte: u8) -> ItemId {
        ItemId::from_bytes([byte; 16])
    }

    #[test]
    fn head_round_trips_and_gives_the_key_back() {
        let vault = vault();
        let (head, key) = Head::create(&vault, &mut rng());
        let again = Head::from_line(&head.to_line()).unwrap();
        assert_eq!(again, head);
        assert_eq!(again.unwrap_key(&vault).unwrap().as_bytes(), key.as_bytes());
    }

    #[test]
    fn head_of_another_vault_is_refused() {
        let (head, _) = Head::create(&vault(), &mut rng());
        let other = vault();
        assert_eq!(
            head.unwrap_key(&other).unwrap_err(),
            JournalError::OtherAccount
        );
        // Same account id, another vault key (as after `passwd`).
        let forged = Head {
            account_id: other.file().account_id,
            ..head
        };
        assert_eq!(
            forged.unwrap_key(&other).unwrap_err(),
            JournalError::WrongKey
        );
    }

    #[test]
    fn bad_heads_are_refused() {
        let (head, _) = Head::create(&vault(), &mut rng());
        let line = head.to_line();
        for bad in [
            String::new(),
            "{}".to_owned(),
            line.replace("\"format\":1", "\"format\":2"),
            line.replace("\"key\":\"", "\"key\":\"!"),
            line.replace('}', ",\"extra\":1}"),
        ] {
            assert!(
                matches!(Head::from_line(&bad), Err(JournalError::Format(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn entries_open_only_at_their_place_in_their_journal() {
        let vault = vault();
        let account = vault.file().account_id;
        let (head, key) = Head::create(&vault, &mut rng());
        let item = agent_item("acme admin", "hunter2");
        let line = seal_entry(
            &key,
            &account,
            &head.journal_id,
            3,
            &id(7),
            &item,
            &mut rng(),
        )
        .unwrap();

        let (opened_id, opened) = open_entry(&line, &key, &account, &head.journal_id, 3).unwrap();
        assert_eq!(opened_id, id(7));
        assert_eq!(opened, item);

        let (other_head, other_key) = Head::create(&vault, &mut rng());
        let other_account = AccountId::from_bytes([0xa2; 16]);
        assert!(open_entry(&line, &key, &account, &head.journal_id, 2).is_none());
        assert!(open_entry(&line, &key, &account, &head.journal_id, 4).is_none());
        assert!(open_entry(&line, &key, &account, &other_head.journal_id, 3).is_none());
        assert!(open_entry(&line, &key, &other_account, &head.journal_id, 3).is_none());
        assert!(open_entry(&line, &other_key, &account, &head.journal_id, 3).is_none());
        assert!(open_entry("not base64!", &key, &account, &head.journal_id, 3).is_none());
        assert!(open_entry(&line[..line.len() - 8], &key, &account, &head.journal_id, 3).is_none());
    }

    #[test]
    fn short_entries_share_one_size() {
        let vault = vault();
        let account = vault.file().account_id;
        let (head, key) = Head::create(&vault, &mut rng());
        let seal = |password: &str| {
            seal_entry(
                &key,
                &account,
                &head.journal_id,
                0,
                &id(1),
                &agent_item("a", password),
                &mut rng(),
            )
            .unwrap()
            .len()
        };
        assert_eq!(seal("x"), seal("a much longer password than that"));
    }

    #[test]
    fn apply_creates_then_replaces_agent_made_items() {
        let mut vault = vault();
        let applied = apply(
            &mut vault,
            vec![
                (id(1), agent_item("acme admin", "first")),
                (id(2), agent_item("acme user", "other")),
                (id(1), agent_item("acme admin", "second")),
            ],
            &mut rng(),
        )
        .unwrap();
        assert_eq!(applied.changed, ["acme admin", "acme user"]);
        assert_eq!(applied.skipped, [] as [String; 0]);
        assert_eq!(vault.get(&id(1)).unwrap().password, "second");
        assert_eq!(vault.revision_of(&id(1)), Some(2));
        assert_eq!(vault.revision_of(&id(2)), Some(1));

        // The same entries again change nothing.
        let again = apply(
            &mut vault,
            vec![(id(1), agent_item("acme admin", "second"))],
            &mut rng(),
        )
        .unwrap();
        assert_eq!(again, Applied::default());
        assert_eq!(vault.revision_of(&id(1)), Some(2));
    }

    #[test]
    fn apply_never_touches_the_owners_items() {
        let mut vault = vault();
        let mut owned = Item::default();
        owned.title = "bank".into();
        owned.password = "the real one".into();
        owned.agent = true; // marked for the agent, still the owner's
        let owned_id = vault.add(&owned, &mut rng()).unwrap();

        let applied = apply(
            &mut vault,
            vec![(owned_id, agent_item("bank", "overwritten"))],
            &mut rng(),
        )
        .unwrap();
        assert_eq!(applied.changed, [] as [String; 0]);
        assert_eq!(applied.skipped.len(), 1);
        assert_eq!(vault.get(&owned_id).unwrap().password, "the real one");
        assert_eq!(vault.revision_of(&owned_id), Some(1));
    }

    #[test]
    fn apply_skips_what_breaks_the_rules() {
        let mut vault = vault();
        let mut not_agent_made = agent_item("a", "x");
        not_agent_made.origin = Origin::Owner;
        let mut unmarked = agent_item("b", "x");
        unmarked.agent = false;
        let untitled = agent_item("  ", "x");
        let mut with_file = agent_item("c", "x");
        with_file.attachments.push(crate::item::Attachment {
            name: "f".into(),
            data: "AA==".into(),
        });
        let too_big = agent_item("d", &"x".repeat(MAX_AGENT_ITEM_LEN));

        let applied = apply(
            &mut vault,
            vec![
                (id(1), not_agent_made),
                (id(2), unmarked),
                (id(3), untitled),
                (id(4), with_file),
                (id(5), too_big),
                (id(6), agent_item("fine", "x")),
            ],
            &mut rng(),
        )
        .unwrap();
        assert_eq!(applied.changed, ["fine"]);
        assert_eq!(applied.skipped.len(), 5);
        assert_eq!(vault.file().records.len(), 1);
    }

    #[test]
    fn apply_stops_creating_at_the_limit() {
        let mut vault = vault();
        let entries = (0..=MAX_AGENT_ITEMS)
            .map(|n| {
                let mut bytes = [0u8; 16];
                bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
                (
                    ItemId::from_bytes(bytes),
                    agent_item(&format!("item {n}"), "x"),
                )
            })
            .collect();
        let applied = apply(&mut vault, entries, &mut rng()).unwrap();
        assert_eq!(applied.changed.len(), MAX_AGENT_ITEMS);
        assert_eq!(applied.skipped.len(), 1);
        assert_eq!(vault.file().records.len(), MAX_AGENT_ITEMS);
    }
}
