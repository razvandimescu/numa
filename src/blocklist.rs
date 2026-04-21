use std::collections::HashSet;
use std::time::{Duration, Instant};

use log::{info, warn};

pub struct BlocklistStore {
    domains: HashSet<String>,
    allowlist: HashSet<String>,
    enabled: bool,
    paused_until: Option<Instant>,
    list_sources: Vec<String>,
    last_refresh: Option<Instant>,
}

#[derive(serde::Serialize)]
pub struct BlockCheckResult {
    pub blocked: bool,
    pub reason: String,
    pub matched_rule: Option<String>,
}

impl BlockCheckResult {
    fn blocked(rule: &str, reason: &str) -> Self {
        Self {
            blocked: true,
            reason: reason.to_string(),
            matched_rule: Some(rule.to_string()),
        }
    }
    fn allowed(rule: &str, reason: &str) -> Self {
        Self {
            blocked: false,
            reason: reason.to_string(),
            matched_rule: Some(rule.to_string()),
        }
    }
    fn not_blocked() -> Self {
        Self {
            blocked: false,
            reason: "not in blocklist".to_string(),
            matched_rule: None,
        }
    }
    fn disabled() -> Self {
        Self {
            blocked: false,
            reason: "blocking is disabled".to_string(),
            matched_rule: None,
        }
    }
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
        let domain = Self::normalize(domain);
        if Self::find_in_set(&domain, &self.allowlist).is_some() {
            return false;
        }
        Self::find_in_set(&domain, &self.domains).is_some()
    }

    pub fn check(&self, domain: &str) -> BlockCheckResult {
        if !self.enabled {
            return BlockCheckResult::disabled();
        }

        if let Some(until) = self.paused_until {
            if Instant::now() < until {
                return BlockCheckResult::disabled();
            }
        }

        let domain = Self::normalize(domain);

        if let Some(matched) = Self::find_in_set(&domain, &self.allowlist) {
            let reason = if matched == domain {
                "exact match in allowlist"
            } else {
                "parent domain in allowlist"
            };
            return BlockCheckResult::allowed(matched, reason);
        }

        if let Some(matched) = Self::find_in_set(&domain, &self.domains) {
            let reason = if matched == domain {
                "exact match in blocklist"
            } else {
                "parent domain in blocklist"
            };
            return BlockCheckResult::blocked(matched, reason);
        }

        BlockCheckResult::not_blocked()
    }

    fn normalize(domain: &str) -> String {
        domain.to_lowercase().trim_end_matches('.').to_string()
    }

    fn find_in_set<'a>(domain: &'a str, set: &HashSet<String>) -> Option<&'a str> {
        if set.contains(domain) {
            return Some(domain);
        }
        let mut d = domain;
        while let Some(dot) = d.find('.') {
            d = &d[dot + 1..];
            if set.contains(d) {
                return Some(d);
            }
        }
        None
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

    pub fn unpause(&mut self) {
        self.paused_until = None;
    }

    pub fn is_paused(&self) -> bool {
        self.paused_until
            .map(|until| Instant::now() < until)
            .unwrap_or(false)
    }

    pub fn add_to_allowlist(&mut self, domain: &str) {
        self.allowlist.insert(Self::normalize(domain));
    }

    pub fn remove_from_allowlist(&mut self, domain: &str) -> bool {
        self.allowlist.remove(&Self::normalize(domain))
    }

    pub fn allowlist(&self) -> Vec<String> {
        self.allowlist.iter().cloned().collect()
    }

    pub fn heap_bytes(&self) -> usize {
        let per_slot_overhead = std::mem::size_of::<u64>() + std::mem::size_of::<String>() + 1;
        let domains_table = self.domains.capacity() * per_slot_overhead;
        let domains_heap: usize = self.domains.iter().map(|d| d.capacity()).sum();
        let allow_table = self.allowlist.capacity() * per_slot_overhead;
        let allow_heap: usize = self.allowlist.iter().map(|d| d.capacity()).sum();
        domains_table + domains_heap + allow_table + allow_heap
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

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with(domains: &[&str], allowlist: &[&str]) -> BlocklistStore {
        let mut store = BlocklistStore::new();
        store.swap_domains(domains.iter().map(|s| s.to_string()).collect(), vec![]);
        for d in allowlist {
            store.add_to_allowlist(d);
        }
        store
    }

    #[test]
    fn exact_block() {
        let store = store_with(&["ads.example.com"], &[]);
        assert!(store.is_blocked("ads.example.com"));
        assert!(!store.is_blocked("example.com"));
    }

    #[test]
    fn parent_block_covers_subdomain() {
        let store = store_with(&["tracker.com"], &[]);
        assert!(store.is_blocked("tracker.com"));
        assert!(store.is_blocked("www.tracker.com"));
        assert!(store.is_blocked("deep.sub.tracker.com"));
    }

    #[test]
    fn exact_allowlist_unblocks() {
        let store = store_with(&["ads.example.com"], &["ads.example.com"]);
        assert!(!store.is_blocked("ads.example.com"));
    }

    #[test]
    fn parent_allowlist_unblocks_subdomain() {
        let store = store_with(&["example.com", "www.example.com"], &["example.com"]);
        assert!(!store.is_blocked("example.com"));
        assert!(!store.is_blocked("www.example.com"));
        assert!(!store.is_blocked("sub.deep.example.com"));
    }

    #[test]
    fn allowlist_does_not_unblock_sibling() {
        let store = store_with(
            &["www.example.com", "ads.example.com"],
            &["www.example.com"],
        );
        assert!(!store.is_blocked("www.example.com"));
        assert!(store.is_blocked("ads.example.com"));
    }

    #[test]
    fn check_reports_parent_allowlist() {
        let store = store_with(
            &["goatcounter.com", "www.goatcounter.com"],
            &["goatcounter.com"],
        );
        let result = store.check("www.goatcounter.com");
        assert!(!result.blocked);
        assert_eq!(result.matched_rule.as_deref(), Some("goatcounter.com"));
    }

    #[test]
    fn disabled_never_blocks() {
        let mut store = store_with(&["ads.example.com"], &[]);
        store.set_enabled(false);
        assert!(!store.is_blocked("ads.example.com"));
    }

    #[test]
    fn trailing_dot_normalized() {
        let store = store_with(&["ads.example.com"], &["safe.example.com"]);
        assert!(store.is_blocked("ads.example.com."));
        assert!(!store.is_blocked("safe.example.com."));
        let result = store.check("ads.example.com.");
        assert!(result.blocked);
    }

    #[test]
    fn case_insensitive() {
        let store = store_with(&["ads.example.com"], &["safe.example.com"]);
        assert!(store.is_blocked("ADS.Example.COM"));
        assert!(!store.is_blocked("Safe.Example.COM"));
    }

    #[test]
    fn domain_in_neither_list() {
        let store = store_with(&["ads.example.com"], &[]);
        let result = store.check("clean.example.org");
        assert!(!result.blocked);
        assert_eq!(result.reason, "not in blocklist");
        assert!(result.matched_rule.is_none());
    }

    #[test]
    fn heap_bytes_grows_with_domains() {
        let mut store = BlocklistStore::new();
        let empty = store.heap_bytes();
        let domains: HashSet<String> = ["example.com", "example.org", "test.net"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        store.swap_domains(domains, vec![]);
        assert!(store.heap_bytes() > empty);
    }
}

const RETRY_DELAYS_SECS: &[u64] = &[2, 10, 30];

pub async fn download_blocklists(
    lists: &[String],
    resolver: Option<std::sync::Arc<crate::bootstrap_resolver::NumaResolver>>,
) -> Vec<(String, String)> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .gzip(true);
    if let Some(r) = resolver {
        builder = builder.dns_resolver(r);
    }
    let client = builder.build().unwrap_or_default();

    let fetches = lists.iter().map(|url| {
        let client = &client;
        async move {
            let text = fetch_with_retry(client, url).await?;
            info!("downloaded blocklist: {} ({} bytes)", url, text.len());
            Some((url.clone(), text))
        }
    });
    futures::future::join_all(fetches)
        .await
        .into_iter()
        .flatten()
        .collect()
}

async fn fetch_with_retry(client: &reqwest::Client, url: &str) -> Option<String> {
    fetch_with_retry_delays(client, url, RETRY_DELAYS_SECS).await
}

async fn fetch_with_retry_delays(
    client: &reqwest::Client,
    url: &str,
    delays: &[u64],
) -> Option<String> {
    let total = delays.len() + 1;
    for attempt in 1..=total {
        match fetch_once(client, url).await {
            Ok(text) => return Some(text),
            Err(msg) if attempt < total => {
                let delay = delays[attempt - 1];
                warn!(
                    "blocklist {} attempt {}/{} failed: {} — retrying in {}s",
                    url, attempt, total, msg, delay
                );
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
            Err(msg) => {
                warn!(
                    "blocklist {} attempt {}/{} failed: {} — giving up",
                    url, attempt, total, msg
                );
            }
        }
    }
    None
}

async fn fetch_once(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format_error_chain(&e))?;
    resp.text().await.map_err(|e| format_error_chain(&e))
}

fn format_error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut src = e.source();
    while let Some(s) = src {
        parts.push(s.to_string());
        src = s.source();
    }
    parts.join(": ")
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn flaky_http_server(drop_first_n: usize, body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..drop_first_n {
                if let Ok((sock, _)) = listener.accept().await {
                    drop(sock);
                }
            }
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body,
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        addr
    }

    fn zero_delays() -> Vec<u64> {
        vec![0; RETRY_DELAYS_SECS.len()]
    }

    #[tokio::test]
    async fn retry_succeeds_on_final_attempt() {
        let body = "ads.example.com\ntracker.example.net\n";
        let delays = zero_delays();
        let addr = flaky_http_server(delays.len(), body).await;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/");
        let result = fetch_with_retry_delays(&client, &url, &delays).await;
        assert_eq!(result.as_deref(), Some(body));
    }

    #[tokio::test]
    async fn retry_gives_up_when_all_attempts_fail() {
        let delays = zero_delays();
        let addr = flaky_http_server(delays.len() + 2, "unreachable").await;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/");
        let result = fetch_with_retry_delays(&client, &url, &delays).await;
        assert_eq!(result, None);
    }
}
