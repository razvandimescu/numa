//! Last-known-good copy of every remote blocklist.
//!
//! A box that restarts while its upstream is down otherwise blocks nothing at
//! all, and no amount of in-memory care survives a process that is not running
//! yet (issue #336). The cache never expires: age is reported, but it is never
//! a reason to refuse a copy, because the only alternative to an old list is
//! no list.
//!
//! One file per remote source, named for a hash of the URL rather than the URL
//! itself. A readable name has to be sanitised and truncated, and two long URLs
//! that truncate alike would then share a file — which costs the loser exactly
//! the fallback the cache exists to provide. Age is the file's mtime, so there
//! is no second file to keep in step with the body.
//!
//! Local file sources are not cached — the file *is* the user's copy, and
//! duplicating it into the data dir would be surprising.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use log::info;
use ring::digest::{digest, SHA256};

pub struct BlocklistCache {
    dir: PathBuf,
}

pub struct CachedList {
    pub text: String,
    pub fetched_unix: u64,
}

impl BlocklistCache {
    pub fn new(data_dir: &Path) -> Self {
        BlocklistCache {
            dir: data_dir.join("blocklists"),
        }
    }

    /// SHA-256 of the URL, truncated. Not `DefaultHasher`, whose output is not
    /// promised to be stable across Rust releases — a toolchain bump would
    /// rename every file and silently discard every last-known-good copy.
    fn key(url: &str) -> String {
        digest(&SHA256, url.as_bytes()).as_ref()[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn path(&self, url: &str) -> PathBuf {
        self.dir.join(format!("{}.txt", Self::key(url)))
    }

    pub fn store(&self, url: &str, text: &str) {
        if !is_remote(url) {
            return;
        }
        crate::persist::save_text(&self.path(url), text);
    }

    pub fn load(&self, url: &str) -> Option<CachedList> {
        if !is_remote(url) {
            return None;
        }
        let path = self.path(url);
        let text = std::fs::read_to_string(&path).ok()?;
        let fetched_unix = mtime_unix(&path)?;
        info!(
            "serving {url} from cache ({})",
            format_age(now_unix().saturating_sub(fetched_unix))
        );
        Some(CachedList { text, fetched_unix })
    }

    /// Drop everything that is not a copy of a currently configured source.
    /// Editing a list URL would otherwise leave its copy in the data dir
    /// forever, and this sweeps a `.tmp` left by a crashed write too.
    pub fn prune(&self, urls: &[String]) {
        let keep: HashSet<String> = urls
            .iter()
            .filter(|u| is_remote(u))
            .map(|u| format!("{}.txt", Self::key(u)))
            .collect();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !keep.contains(name) && std::fs::remove_file(entry.path()).is_ok() {
                info!("dropped unused blocklist cache file {name}");
            }
        }
    }
}

/// Only remote lists are cached; a local path is already the user's own copy.
fn is_remote(source: &str) -> bool {
    source.starts_with("http://") || source.starts_with("https://")
}

fn mtime_unix(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn format_age(secs: u64) -> String {
    match secs {
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86400 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("numa_blcache_{name}_{nanos}"))
    }

    #[test]
    fn round_trips_a_list() {
        let dir = temp_dir("roundtrip");
        let cache = BlocklistCache::new(&dir);
        let url = "https://example.com/list.txt";
        cache.store(url, "ads.example.com\n");

        let got = cache.load(url).expect("cached copy");
        assert_eq!(got.text, "ads.example.com\n");
        assert!(got.fetched_unix > 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_url_never_stored_is_a_miss() {
        let dir = temp_dir("miss");
        let cache = BlocklistCache::new(&dir);
        assert!(cache.load("https://example.com/absent.txt").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_local_source_is_not_cached() {
        let dir = temp_dir("local");
        let cache = BlocklistCache::new(&dir);
        let url = "file:///etc/hosts";
        cache.store(url, "ads.example.com\n");
        assert!(cache.load(url).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two long URLs sharing a prefix would truncate alike under a readable
    /// name. Each must still keep its own copy, or the loser has no fallback
    /// when its upstream goes down.
    #[test]
    fn urls_that_share_a_long_prefix_keep_separate_copies() {
        let dir = temp_dir("collide");
        let cache = BlocklistCache::new(&dir);
        let long = "https://example.com/".to_string() + &"a".repeat(200);
        let other = long.clone() + "-different";

        cache.store(&long, "one.example\n");
        cache.store(&other, "two.example\n");
        assert_eq!(cache.load(&long).unwrap().text, "one.example\n");
        assert_eq!(cache.load(&other).unwrap().text, "two.example\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Editing a list URL must not leave its copy behind forever.
    #[test]
    fn prune_drops_copies_of_sources_no_longer_configured() {
        let dir = temp_dir("prune");
        let cache = BlocklistCache::new(&dir);
        let (kept, dropped) = ("https://a.example/l.txt", "https://b.example/l.txt");
        cache.store(kept, "one.example\n");
        cache.store(dropped, "two.example\n");

        cache.prune(&[kept.to_string()]);
        assert!(cache.load(kept).is_some(), "still configured");
        assert!(cache.load(dropped).is_none(), "no longer configured");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A local source contributes no key, so pruning must not read it as an
    /// instruction to drop every remote copy.
    #[test]
    fn prune_keeps_remote_copies_alongside_a_local_source() {
        let dir = temp_dir("prune_local");
        let cache = BlocklistCache::new(&dir);
        let url = "https://a.example/l.txt";
        cache.store(url, "one.example\n");

        cache.prune(&[url.to_string(), "file:///etc/hosts".to_string()]);
        assert!(cache.load(url).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_sweeps_a_tmp_file_left_by_a_crashed_write() {
        let dir = temp_dir("prune_tmp");
        let cache = BlocklistCache::new(&dir);
        let url = "https://a.example/l.txt";
        cache.store(url, "one.example\n");
        let orphan = dir.join("blocklists").join("deadbeef.txt.tmp");
        std::fs::write(&orphan, "half written").unwrap();

        cache.prune(&[url.to_string()]);
        assert!(!orphan.exists());
        assert!(cache.load(url).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
