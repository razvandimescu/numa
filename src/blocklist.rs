use std::collections::HashSet;
use std::time::Instant;

use log::{info, warn};

pub struct BlocklistStore {
    domains: HashSet<String>,
    allowlist: HashSet<String>,
    enabled: bool,
    paused_until: Option<Instant>,
    list_sources: Vec<String>,
    last_refresh: Option<Instant>,
}

pub struct BlocklistStats {
    pub enabled: bool,
    pub paused: bool,
    pub domains_loaded: usize,
    pub allowlist_size: usize,
    pub list_sources: Vec<String>,
    pub last_refresh_secs_ago: Option<u64>,
}

impl Default for BlocklistStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlocklistStore {
    pub fn new() -> Self {
        BlocklistStore {
            domains: HashSet::new(),
            allowlist: HashSet::new(),
            enabled: true,
            paused_until: None,
            list_sources: Vec::new(),
            last_refresh: None,
        }
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        if !self.enabled {
            return false;
        }

        if let Some(until) = self.paused_until {
            if Instant::now() < until {
                return false;
            }
        }

        if self.allowlist.contains(domain) {
            return false;
        }

        if self.domains.contains(domain) {
            return true;
        }

        // Walk up: ads.tracker.example.com → tracker.example.com → example.com
        let mut d = domain;
        while let Some(dot) = d.find('.') {
            d = &d[dot + 1..];
            if self.allowlist.contains(d) {
                return false;
            }
            if self.domains.contains(d) {
                return true;
            }
        }

        false
    }

    /// Atomically swap in a new domain set. Build the set outside the lock,
    /// then call this to swap — keeps lock hold time sub-microsecond.
    pub fn swap_domains(&mut self, domains: HashSet<String>, sources: Vec<String>) {
        self.domains = domains;
        self.list_sources = sources;
        self.last_refresh = Some(Instant::now());
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn pause(&mut self, seconds: u64) {
        self.paused_until = Some(Instant::now() + std::time::Duration::from_secs(seconds));
    }

    pub fn is_paused(&self) -> bool {
        self.paused_until
            .map(|until| Instant::now() < until)
            .unwrap_or(false)
    }

    pub fn add_to_allowlist(&mut self, domain: &str) {
        self.allowlist.insert(domain.to_lowercase());
    }

    pub fn remove_from_allowlist(&mut self, domain: &str) -> bool {
        self.allowlist.remove(&domain.to_lowercase())
    }

    pub fn allowlist(&self) -> Vec<String> {
        self.allowlist.iter().cloned().collect()
    }

    pub fn stats(&self) -> BlocklistStats {
        BlocklistStats {
            enabled: self.is_enabled(),
            paused: self.is_paused(),
            domains_loaded: self.domains.len(),
            allowlist_size: self.allowlist.len(),
            list_sources: self.list_sources.clone(),
            last_refresh_secs_ago: self.last_refresh.map(|t| t.elapsed().as_secs()),
        }
    }
}

/// Parse a blocklist text file into a set of domains.
pub fn parse_blocklist(text: &str) -> HashSet<String> {
    let mut domains = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }

        // Handle hosts-file format: "0.0.0.0 domain" or "127.0.0.1 domain" (space or tab)
        let domain = if line.starts_with("0.0.0.0")
            || line.starts_with("127.0.0.1")
            || line.starts_with("::")
        {
            line.split_whitespace()
                .nth(1)
                .unwrap_or("")
                .trim_end_matches('.')
        } else if line.contains(' ') || line.contains('\t') {
            continue;
        } else {
            // Plain domain or adblock filter syntax
            let d = line.trim_start_matches("*.").trim_start_matches("||");
            let d = d.split('$').next().unwrap_or(d); // strip adblock $options
            d.trim_end_matches('^').trim_end_matches('.')
        };

        let domain = domain.to_lowercase();
        if !domain.is_empty()
            && domain.contains('.')
            && domain != "localhost"
            && domain != "localhost.localdomain"
        {
            domains.insert(domain);
        }
    }
    domains
}

pub async fn download_blocklists(lists: &[String]) -> Vec<(String, String)> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    let mut results = Vec::new();

    for url in lists {
        match client.get(url).send().await {
            Ok(resp) => match resp.text().await {
                Ok(text) => {
                    info!("downloaded blocklist: {} ({} bytes)", url, text.len());
                    results.push((url.clone(), text));
                }
                Err(e) => warn!("failed to read blocklist body {}: {}", url, e),
            },
            Err(e) => warn!("failed to download blocklist {}: {}", url, e),
        }
    }

    results
}
