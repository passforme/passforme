//! Three-way merge of a local vault into the server's copy.
//!
//! `base` is the vault as it was at the last successful sync; comparing item
//! revisions against it tells what each side changed since. The result is
//! built on the **server's** copy (its keys, salt and parameters win, so a
//! master password changed on another device carries over) with the local
//! changes applied on top:
//!
//! | local \ server   | unchanged        | changed                         | deleted              |
//! |------------------|------------------|---------------------------------|----------------------|
//! | added            | added            | —                               | —                    |
//! | changed          | local wins       | server wins, local kept as copy | local brought back   |
//! | deleted          | deleted          | server wins (edit kept)         | deleted              |
//!
//! Nothing typed on either side is ever lost: a conflict keeps the server's
//! version under the original title and the local one as a new item titled
//! `"<title> (conflict)"`.

use std::collections::HashMap;

use rand_core::CryptoRng;

use crate::seal::ItemId;
use crate::vault::{UnlockedVault, VaultError, VaultFile};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Local additions, edits and deletions applied to the server copy.
    pub pushed: usize,
    /// Titles of items edited on both sides; the local edit became a copy.
    pub conflicts: Vec<String>,
    /// Titles of local deletions skipped because the server edited the item.
    pub kept_after_remote_edit: Vec<String>,
}

impl MergeReport {
    pub fn is_empty(&self) -> bool {
        self.pushed == 0 && self.conflicts.is_empty() && self.kept_after_remote_edit.is_empty()
    }
}

/// Applies to `remote` what `local` changed since `base`.
pub fn merge<R: CryptoRng + ?Sized>(
    base: &VaultFile,
    local: &UnlockedVault,
    remote: &mut UnlockedVault,
    rng: &mut R,
) -> Result<MergeReport, VaultError> {
    let base_revisions: HashMap<ItemId, u64> =
        base.records.iter().map(|r| (r.id, r.revision)).collect();
    let mut report = MergeReport::default();

    for (id, item) in local.items()? {
        let local_revision = local.revision_of(&id).expect("listed item exists");
        let base_revision = base_revisions.get(&id).copied();
        if base_revision == Some(local_revision) {
            continue; // unchanged locally
        }
        match (base_revision, remote.revision_of(&id)) {
            // Added here; ids are random, so the server cannot have it.
            (None, None) => remote.insert(id, 1, &item, rng)?,
            (None, Some(_)) => {
                remote.add(&item, rng)?;
            }
            // Edited here, untouched on the server.
            (Some(base), Some(server)) if server == base => remote.update(&id, &item, rng)?,
            // Edited here, deleted on the server: bring it back.
            (Some(base), None) => remote.insert(id, base + 1, &item, rng)?,
            // Edited on both sides.
            (Some(_), Some(_)) => {
                let mut copy = item;
                copy.title = format!("{} (conflict)", copy.title);
                remote.add(&copy, rng)?;
                report.conflicts.push(remote.get(&id)?.title.clone());
            }
        }
        report.pushed += 1;
    }

    for (id, base_revision) in &base_revisions {
        if local.revision_of(id).is_some() {
            continue;
        }
        // Deleted here.
        match remote.revision_of(id) {
            Some(server) if server == *base_revision => {
                remote.remove(id)?;
                report.pushed += 1;
            }
            Some(_) => report
                .kept_after_remote_edit
                .push(remote.get(id)?.title.clone()),
            None => {}
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::Item;
    use crate::kdf::{KdfParams, SecretKey};
    use getrandom::SysRng;
    use rand_core::UnwrapErr;
    use secrecy::SecretString;

    fn rng() -> UnwrapErr<SysRng> {
        UnwrapErr(SysRng)
    }

    fn item(title: &str, password: &str) -> Item {
        let mut item = Item::default();
        item.title = title.into();
        item.password = password.into();
        item
    }

    struct Devices {
        password: SecretString,
        secret_key: SecretKey,
        /// The server's copy, which both devices synced last time.
        base: VaultFile,
    }

    impl Devices {
        fn new(items: &[(&str, &str)]) -> (Self, Vec<ItemId>) {
            let password = SecretString::from("master password");
            let secret_key = SecretKey::generate(&mut rng());
            let params =
                KdfParams::new(KdfParams::MIN_MEMORY_KIB, KdfParams::MIN_ITERATIONS, 1).unwrap();
            let mut vault =
                UnlockedVault::create(&password, &secret_key, &params, &mut rng()).unwrap();
            let ids = items
                .iter()
                .map(|(t, p)| vault.add(&item(t, p), &mut rng()).unwrap())
                .collect();
            let base = vault.file().clone();
            (
                Self {
                    password,
                    secret_key,
                    base,
                },
                ids,
            )
        }

        fn open(&self) -> UnlockedVault {
            UnlockedVault::unlock(self.base.clone(), &self.password, &self.secret_key).unwrap()
        }

        fn titles(vault: &UnlockedVault) -> Vec<(String, String)> {
            let mut all: Vec<_> = vault
                .items()
                .unwrap()
                .iter()
                .map(|(_, i)| (i.title.clone(), i.password.clone()))
                .collect();
            all.sort();
            all
        }
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }

    #[test]
    fn nothing_changed_is_a_no_op() {
        let (d, _) = Devices::new(&[("A", "1")]);
        let (local, mut remote) = (d.open(), d.open());
        let report = merge(&d.base, &local, &mut remote, &mut rng()).unwrap();
        assert!(report.is_empty());
        assert_eq!(remote.file(), &d.base);
    }

    #[test]
    fn independent_changes_on_both_sides_combine() {
        let (d, ids) = Devices::new(&[("A", "1"), ("B", "1"), ("C", "1")]);
        let mut local = d.open();
        let mut remote = d.open();
        local.add(&item("New here", "n"), &mut rng()).unwrap();
        local.update(&ids[0], &item("A", "2"), &mut rng()).unwrap();
        local.remove(&ids[1]).unwrap();
        remote.add(&item("New there", "m"), &mut rng()).unwrap();
        remote.update(&ids[2], &item("C", "2"), &mut rng()).unwrap();

        let report = merge(&d.base, &local, &mut remote, &mut rng()).unwrap();
        assert_eq!(report.pushed, 3);
        assert_eq!(report.conflicts, Vec::<String>::new());
        assert_eq!(
            Devices::titles(&remote),
            pairs(&[
                ("A", "2"),
                ("C", "2"),
                ("New here", "n"),
                ("New there", "m")
            ])
        );
    }

    #[test]
    fn an_item_edited_on_both_sides_keeps_both_versions() {
        let (d, ids) = Devices::new(&[("A", "1")]);
        let mut local = d.open();
        let mut remote = d.open();
        local
            .update(&ids[0], &item("A", "local"), &mut rng())
            .unwrap();
        remote
            .update(&ids[0], &item("A", "server"), &mut rng())
            .unwrap();

        let report = merge(&d.base, &local, &mut remote, &mut rng()).unwrap();
        assert_eq!(report.conflicts, vec!["A".to_owned()]);
        assert_eq!(
            Devices::titles(&remote),
            pairs(&[("A", "server"), ("A (conflict)", "local")])
        );
    }

    #[test]
    fn deletion_versus_edit_never_loses_the_edit() {
        let (d, ids) = Devices::new(&[("A", "1"), ("B", "1")]);
        let mut local = d.open();
        let mut remote = d.open();
        // A: deleted here, edited there. B: edited here, deleted there.
        local.remove(&ids[0]).unwrap();
        remote
            .update(&ids[0], &item("A", "server"), &mut rng())
            .unwrap();
        local
            .update(&ids[1], &item("B", "local"), &mut rng())
            .unwrap();
        remote.remove(&ids[1]).unwrap();

        let report = merge(&d.base, &local, &mut remote, &mut rng()).unwrap();
        assert_eq!(report.kept_after_remote_edit, vec!["A".to_owned()]);
        assert_eq!(
            Devices::titles(&remote),
            pairs(&[("A", "server"), ("B", "local")])
        );
    }

    #[test]
    fn a_password_changed_on_the_server_carries_over() {
        let (d, _) = Devices::new(&[("A", "1")]);
        let mut local = d.open();
        let mut remote = d.open();
        let new_password = SecretString::from("the new master password");
        remote
            .change_password(
                &new_password,
                &d.secret_key,
                &KdfParams::new(KdfParams::MIN_MEMORY_KIB, KdfParams::MIN_ITERATIONS, 1).unwrap(),
                &mut rng(),
            )
            .unwrap();
        local.add(&item("B", "2"), &mut rng()).unwrap();

        merge(&d.base, &local, &mut remote, &mut rng()).unwrap();
        let reopened =
            UnlockedVault::unlock(remote.file().clone(), &new_password, &d.secret_key).unwrap();
        assert_eq!(Devices::titles(&reopened), pairs(&[("A", "1"), ("B", "2")]));
    }
}
