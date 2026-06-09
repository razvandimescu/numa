//! A two-layer domain set: entries seeded from `numa.toml` (reloaded, never
//! persisted) and entries added at runtime (persisted to a JSON file, never
//! written back into the TOML). For features where the UI adds/removes
//! individual domains durably alongside a config-declared bulk list — the
//! rebind allowlist and the blocking allow/block lists. Mirrors
//! `ServiceStore`'s config-vs-user split.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::blocklist::{find_in_set, normalize};
use crate::persist::{load_json_vec, save_json};

#[derive(Debug)]
pub struct PersistedDomainList {
    config: HashSet<String>, // from numa.toml; reloaded each boot, never saved
    user: HashSet<String>,   // runtime-added; persisted to `persist_path`
    persist_path: Option<PathBuf>,
}

impl PersistedDomainList {
    /// The production list: seeds `config_seeds`, then loads persisted
    /// runtime entries from `filename` (resolved under the platform config
    /// dir) — in that order, so config takes precedence on overlap.
    pub fn new(filename: &str, config_seeds: &[String]) -> Self {
        let mut list = PersistedDomainList {
            config: HashSet::new(),
            user: HashSet::new(),
            persist_path: Some(crate::config_dir().join(filename)),
        };
        for domain in config_seeds {
            list.insert_from_config(domain);
        }
        list.load_persisted();
        list
    }

    /// In-memory only: save and load are no-ops. For lists that are pure
    /// config (per-client policies) and for tests.
    pub fn unpersisted() -> Self {
        PersistedDomainList {
            config: HashSet::new(),
            user: HashSet::new(),
            persist_path: None,
        }
    }

    /// Seed a config-declared entry (not written to disk).
    pub fn insert_from_config(&mut self, domain: &str) {
        self.config.insert(normalize(domain));
    }

    /// Add a runtime entry and persist. No-op if config already covers it
    /// exactly or it is already present.
    pub fn insert(&mut self, domain: &str) {
        let d = normalize(domain);
        if !self.config.contains(&d) && self.user.insert(d) {
            self.save();
        }
    }

    /// Remove a runtime entry, persisting on change. Config entries are
    /// file-owned and cannot be removed here; returns false for them.
    pub fn remove(&mut self, domain: &str) -> bool {
        if self.user.remove(&normalize(domain)) {
            self.save();
            true
        } else {
            false
        }
    }

    /// Exact-or-parent suffix match against either layer: `example.com`
    /// matches `nas.example.com` but never `evilexample.com`.
    pub fn matches(&self, qname: &str) -> bool {
        self.find_normalized(&normalize(qname)).is_some()
    }

    /// The matched suffix for an already-normalized domain (config layer
    /// first), or None. Lets callers report *which* entry matched.
    pub fn find_normalized<'a>(&self, domain: &'a str) -> Option<&'a str> {
        find_in_set(domain, &self.config).or_else(|| find_in_set(domain, &self.user))
    }

    /// Whether the exact (normalized) domain came from config — lets the UI
    /// mark which entries are durable vs runtime-removable.
    pub fn is_config(&self, domain: &str) -> bool {
        self.config.contains(&normalize(domain))
    }

    /// All entries (config ∪ user), sorted, for listing.
    pub fn entries(&self) -> Vec<String> {
        let mut v: Vec<String> = self.config.union(&self.user).cloned().collect();
        v.sort();
        v
    }

    /// Entry count. The layers are disjoint: runtime inserts and persisted
    /// loads both skip domains the config layer already holds.
    pub fn len(&self) -> usize {
        self.config.len() + self.user.len()
    }

    pub fn is_empty(&self) -> bool {
        self.config.is_empty() && self.user.is_empty()
    }

    /// Estimated heap usage, mirroring `BlocklistStore::heap_bytes`.
    pub fn heap_bytes(&self) -> usize {
        let per_slot_overhead = std::mem::size_of::<u64>() + std::mem::size_of::<String>() + 1;
        let table = (self.config.capacity() + self.user.capacity()) * per_slot_overhead;
        let strings: usize = self
            .config
            .iter()
            .chain(self.user.iter())
            .map(|d| d.capacity())
            .sum();
        table + strings
    }

    fn load_persisted(&mut self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        for domain in load_json_vec::<String>(path) {
            let d = normalize(&domain);
            if !self.config.contains(&d) {
                self.user.insert(d);
            }
        }
    }

    fn save(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let mut entries: Vec<&String> = self.user.iter().collect();
        entries.sort();
        save_json(path, &entries);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_list() -> PersistedDomainList {
        PersistedDomainList::unpersisted()
    }

    #[test]
    fn save_load_roundtrip_preserves_user_entries() {
        let path =
            std::env::temp_dir().join(format!("numa-domain-list-{}.json", std::process::id()));
        let mut l = test_list();
        l.persist_path = Some(path.clone());
        l.insert("user.example");
        l.insert("config-overlap.example");

        let mut reloaded = test_list();
        reloaded.persist_path = Some(path.clone());
        reloaded.insert_from_config("config-overlap.example");
        reloaded.load_persisted();
        let _ = std::fs::remove_file(&path);

        assert!(reloaded.matches("user.example"));
        assert!(!reloaded.is_config("user.example"));
        // Config wins on overlap: the persisted copy must not shadow it.
        assert!(reloaded.is_config("config-overlap.example"));
        assert_eq!(reloaded.len(), 2);
    }

    #[test]
    fn config_and_user_layers_both_match() {
        let mut l = test_list();
        l.insert_from_config("config.example");
        l.insert("user.example");
        assert!(l.matches("config.example"));
        assert!(l.matches("user.example"));
        assert!(!l.matches("other.example"));
    }

    #[test]
    fn suffix_match_covers_subdomains_not_lookalikes() {
        let mut l = test_list();
        l.insert_from_config("example.com");
        assert!(l.matches("nas.example.com"));
        assert!(l.matches("example.com"));
        assert!(!l.matches("evilexample.com"));
    }

    #[test]
    fn normalizes_case_and_trailing_dot() {
        let mut l = test_list();
        l.insert("NAS.Example.COM.");
        assert!(l.matches("nas.example.com"));
        assert_eq!(l.entries(), vec!["nas.example.com"]);
    }

    #[test]
    fn remove_drops_user_entry_but_not_config() {
        let mut l = test_list();
        l.insert_from_config("keep.example");
        l.insert("drop.example");
        assert!(l.remove("drop.example"));
        assert!(!l.matches("drop.example"));
        // Config entry is file-owned: remove is a no-op and reports false.
        assert!(!l.remove("keep.example"));
        assert!(l.matches("keep.example"));
    }

    #[test]
    fn insert_skips_domain_already_in_config() {
        let mut l = test_list();
        l.insert_from_config("dup.example");
        l.insert("dup.example");
        // No duplicate user copy; still a single listed entry, still config-owned.
        assert_eq!(l.entries(), vec!["dup.example"]);
        assert!(l.is_config("dup.example"));
    }

    #[test]
    fn entries_are_sorted_union() {
        let mut l = test_list();
        l.insert_from_config("b.example");
        l.insert("a.example");
        l.insert("c.example");
        assert_eq!(l.entries(), vec!["a.example", "b.example", "c.example"]);
    }

    #[test]
    fn is_config_distinguishes_layers() {
        let mut l = test_list();
        l.insert_from_config("seed.example");
        l.insert("runtime.example");
        assert!(l.is_config("seed.example"));
        assert!(!l.is_config("runtime.example"));
    }
}
