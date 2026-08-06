use std::collections::HashSet;
use std::time::{Duration, Instant};

use log::{info, warn};

use crate::domain_list::PersistedDomainList;

#[derive(Debug)]
pub struct BlocklistStore {
    domains: HashSet<String>,
    allowlist: PersistedDomainList,
    manual: PersistedDomainList, // UI/API-blocked domains; survives list refresh
    enabled: bool,
    paused_until: Option<Instant>,
    sources: Vec<SourceState>,
    last_refresh: Option<Instant>,
}

#[derive(Debug, PartialEq)]
enum SourceOutcome {
    Pending,
    Ok,
    /// Live fetch failed, but a cached copy is being served. The string is why
    /// the fetch failed, which is still worth showing.
    Stale(String),
    Failed(String),
}

/// Every *configured* source, loaded or not. A source that fails still belongs
/// here: dropping it is what let a dead list look like no list at all (#336).
#[derive(Debug)]
struct SourceState {
    url: String,
    outcome: SourceOutcome,
    /// Wall clock, not `Instant`, because it has to survive a restart to say
    /// anything useful about a cached copy.
    last_ok_unix: Option<u64>,
}

/// What a single source did on the last refresh.
pub enum SourceResult {
    Loaded,
    Cached { error: String, fetched_unix: u64 },
    Failed(String),
}

#[derive(serde::Serialize)]
pub struct SourceStatus {
    pub url: String,
    /// `pending` | `ok` | `stale` | `failed`. One field rather than a pair of
    /// booleans, so a not-yet-fetched source cannot read as a failed one.
    pub status: &'static str,
    pub error: Option<String>,
    pub last_ok_secs_ago: Option<u64>,
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
    pub health: &'static str,
    pub list_sources: Vec<SourceStatus>,
    pub last_refresh_secs_ago: Option<u64>,
}

impl BlocklistStore {
    /// Lists arrive pre-seeded (config entries + persisted runtime entries) —
    /// the orchestrator owns that wiring.
    pub fn new(allowlist: PersistedDomainList, manual: PersistedDomainList) -> Self {
        BlocklistStore {
            domains: HashSet::new(),
            allowlist,
            manual,
            enabled: true,
            paused_until: None,
            sources: Vec::new(),
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
        let domain = normalize(domain);
        if self.allowlist.find_normalized(&domain).is_some() {
            return false;
        }
        self.manual.find_normalized(&domain).is_some()
            || find_in_set(&domain, &self.domains).is_some()
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

        let domain = normalize(domain);

        if let Some(matched) = self.allowlist.find_normalized(&domain) {
            let reason = if matched == domain {
                "exact match in allowlist"
            } else {
                "parent domain in allowlist"
            };
            return BlockCheckResult::allowed(matched, reason);
        }

        if let Some(matched) = self.manual.find_normalized(&domain) {
            return BlockCheckResult::blocked(matched, "manually blocked");
        }

        if let Some(matched) = find_in_set(&domain, &self.domains) {
            let reason = if matched == domain {
                "exact match in blocklist"
            } else {
                "parent domain in blocklist"
            };
            return BlockCheckResult::blocked(matched, reason);
        }

        BlockCheckResult::not_blocked()
    }

    /// Atomically swap in a new domain set. Build the set outside the lock,
    /// then call this to swap — keeps lock hold time sub-microsecond.
    pub fn swap_domains(&mut self, domains: HashSet<String>) {
        self.domains = domains;
        self.last_refresh = Some(Instant::now());
    }

    /// Seed the configured sources before the first fetch, so an empty source
    /// list means "none configured" rather than "none has loaded yet".
    ///
    /// Deduplicated: `record_outcomes` matches by URL, so a repeated entry
    /// would leave a second state stuck `Pending` and health stuck `loading`.
    pub fn set_sources(&mut self, urls: &[String]) {
        self.sources = dedup_sources(urls)
            .iter()
            .map(|url| SourceState {
                url: url.clone(),
                outcome: SourceOutcome::Pending,
                last_ok_unix: None,
            })
            .collect();
    }

    /// Recorded whether or not the domains were swapped in, because a refresh
    /// that keeps the live list still has to say why it kept it.
    pub fn record_outcomes(&mut self, outcomes: &[(String, SourceResult)]) {
        for (url, result) in outcomes {
            let Some(state) = self.sources.iter_mut().find(|s| &s.url == url) else {
                continue;
            };
            match result {
                SourceResult::Loaded => {
                    state.outcome = SourceOutcome::Ok;
                    state.last_ok_unix = Some(crate::blocklist_cache::now_unix());
                }
                SourceResult::Cached {
                    error,
                    fetched_unix,
                } => {
                    state.outcome = SourceOutcome::Stale(error.clone());
                    state.last_ok_unix = Some(*fetched_unix);
                }
                SourceResult::Failed(e) => state.outcome = SourceOutcome::Failed(e.clone()),
            }
        }
    }

    /// Meant to be the one field a monitor reads, so it reports the switch too:
    /// list state is moot when nothing is being blocked on purpose, and a box
    /// with blocking off would otherwise report `loading` forever.
    pub fn health(&self) -> &'static str {
        if !self.enabled {
            return "off";
        }
        if self.sources.is_empty() {
            return "unconfigured";
        }
        if self
            .sources
            .iter()
            .any(|s| s.outcome == SourceOutcome::Pending)
        {
            return "loading";
        }
        if self
            .sources
            .iter()
            .any(|s| matches!(s.outcome, SourceOutcome::Failed(_)))
        {
            // Domains present means something is still being blocked, from the
            // sources that did load or from a list a failed refresh left alone.
            return if self.domains.is_empty() {
                "failed"
            } else {
                "degraded"
            };
        }
        // A cached copy still blocks, so this ranks below a source contributing
        // nothing at all. Age is reported, never a reason to refuse the copy.
        if self
            .sources
            .iter()
            .any(|s| matches!(s.outcome, SourceOutcome::Stale(_)))
        {
            return "stale";
        }
        "ok"
    }

    pub fn domains_loaded(&self) -> usize {
        self.domains.len()
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

    /// Persists across restarts (no-op for domains the config already covers).
    pub fn add_to_allowlist(&mut self, domain: &str) {
        self.allowlist.insert(domain);
    }

    /// False for config-declared entries — those are file-owned.
    pub fn remove_from_allowlist(&mut self, domain: &str) -> bool {
        self.allowlist.remove(domain)
    }

    pub fn allowlist(&self) -> Vec<String> {
        self.allowlist.entries()
    }

    /// Persists across restarts; survives blocklist refresh (separate from
    /// `domains`, which `swap_domains` replaces wholesale).
    pub fn add_to_blocklist(&mut self, domain: &str) {
        self.manual.insert(domain);
    }

    pub fn remove_from_blocklist(&mut self, domain: &str) -> bool {
        self.manual.remove(domain)
    }

    pub fn manual_blocklist(&self) -> Vec<String> {
        self.manual.entries()
    }

    pub fn heap_bytes(&self) -> usize {
        let per_slot_overhead = std::mem::size_of::<u64>() + std::mem::size_of::<String>() + 1;
        let domains_table = self.domains.capacity() * per_slot_overhead;
        let domains_heap: usize = self.domains.iter().map(|d| d.capacity()).sum();
        domains_table + domains_heap + self.allowlist.heap_bytes() + self.manual.heap_bytes()
    }

    pub fn stats(&self) -> BlocklistStats {
        BlocklistStats {
            enabled: self.is_enabled(),
            paused: self.is_paused(),
            domains_loaded: self.domains.len(),
            allowlist_size: self.allowlist.len(),
            health: self.health(),
            list_sources: self
                .sources
                .iter()
                .map(|s| SourceStatus {
                    url: s.url.clone(),
                    status: match s.outcome {
                        SourceOutcome::Pending => "pending",
                        SourceOutcome::Ok => "ok",
                        SourceOutcome::Stale(_) => "stale",
                        SourceOutcome::Failed(_) => "failed",
                    },
                    error: match &s.outcome {
                        SourceOutcome::Failed(e) | SourceOutcome::Stale(e) => Some(e.clone()),
                        _ => None,
                    },
                    last_ok_secs_ago: s
                        .last_ok_unix
                        .map(|t| crate::blocklist_cache::now_unix().saturating_sub(t)),
                })
                .collect(),
            last_refresh_secs_ago: self.last_refresh.map(|t| t.elapsed().as_secs()),
        }
    }
}

/// First occurrence of each URL wins, order preserved. Fetching the same list
/// twice is pure waste, and a repeat also strands a source in `Pending`.
pub fn dedup_sources(lists: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    lists
        .iter()
        .filter(|url| seen.insert((*url).clone()))
        .cloned()
        .collect()
}

/// Parse a blocklist text file into a set of domains.
pub fn parse_blocklist(text: &str) -> HashSet<String> {
    let mut domains = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }

        if line.starts_with("0.0.0.0") || line.starts_with("127.0.0.1") || line.starts_with("::") {
            // BSD hosts(5): an IP followed by N aliases; '#' starts an inline comment.
            let payload = line.split('#').next().unwrap_or(line);
            for alias in payload.split_whitespace().skip(1) {
                insert_if_valid(&mut domains, alias);
            }
            continue;
        }

        if line.contains(' ') || line.contains('\t') {
            continue;
        }

        // Plain domain or adblock filter syntax.
        let d = line.trim_start_matches("*.").trim_start_matches("||");
        let d = d.split('$').next().unwrap_or(d); // strip adblock $options
        insert_if_valid(&mut domains, d.trim_end_matches('^'));
    }
    domains
}

/// Share of entry lines that must parse as domains for a body to be a list at
/// all. Every format Numa parses — hosts lines, bare domains, adblock syntax —
/// yields a domain from essentially every entry line, so anything under half is
/// something else wearing a 200.
const MIN_PARSED_PERCENT: usize = 50;

/// Why this source is not a usable blocklist, or `None` if it is one.
///
/// Judges shape, never size: a twelve-domain personal list parses all of its
/// entry lines and stays valid, while an error page parses almost none. An
/// empty local file is a deliberate "block nothing"; an empty remote body is a
/// broken upstream, never an instruction.
pub(crate) fn source_defect(source: &str, text: &str, domains: &HashSet<String>) -> Option<String> {
    let entries = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('!'))
        .count();
    if entries == 0 {
        return local_path(source)
            .is_none()
            .then(|| "response body has no entries".to_string());
    }
    if domains.len() * 100 < entries * MIN_PARSED_PERCENT {
        return Some(format!(
            "only {} of {entries} entry lines parsed as domains",
            domains.len()
        ));
    }
    None
}

pub(crate) fn normalize(domain: &str) -> String {
    domain.to_lowercase().trim_end_matches('.').to_string()
}

/// Exact-or-parent suffix match: `example.com` matches `nas.example.com` but
/// never `evilexample.com`. `domain` must already be normalized. Shared by the
/// blocklist and rebind allowlist.
pub(crate) fn find_in_set<'a>(domain: &'a str, set: &HashSet<String>) -> Option<&'a str> {
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

fn insert_if_valid(set: &mut HashSet<String>, raw: &str) {
    let d = normalize(raw);
    if !d.is_empty() && d.contains('.') && d != "localhost" && d != "localhost.localdomain" {
        set.insert(d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with(domains: &[&str], allowlist: &[&str]) -> BlocklistStore {
        let mut store = BlocklistStore::new(
            PersistedDomainList::unpersisted(),
            PersistedDomainList::unpersisted(),
        );
        store.swap_domains(domains.iter().map(|s| s.to_string()).collect());
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
    fn config_allowlist_entry_not_runtime_removable() {
        let mut allow = PersistedDomainList::unpersisted();
        allow.insert_from_config("safe.example.com");
        let mut store = BlocklistStore::new(allow, PersistedDomainList::unpersisted());
        store.swap_domains(
            [
                "safe.example.com".to_string(),
                "ads.example.com".to_string(),
            ]
            .into_iter()
            .collect(),
        );
        assert!(!store.remove_from_allowlist("safe.example.com"));
        assert!(!store.is_blocked("safe.example.com"));
        // Runtime entries stay removable.
        store.add_to_allowlist("ads.example.com");
        assert!(!store.is_blocked("ads.example.com"));
        assert!(store.remove_from_allowlist("ads.example.com"));
        assert!(store.is_blocked("ads.example.com"));
    }

    #[test]
    fn manual_block_survives_refresh_and_respects_allowlist() {
        let mut store = store_with(&[], &["safe.example.com"]);
        store.add_to_blocklist("bad.example.com");
        store.add_to_blocklist("safe.example.com");
        assert!(store.is_blocked("bad.example.com"));
        assert!(store.is_blocked("sub.bad.example.com"), "suffix match");
        // Allowlist wins over a manual block, same as over list blocks.
        assert!(!store.is_blocked("safe.example.com"));
        // List refresh replaces `domains` wholesale; manual entries survive.
        store.swap_domains(HashSet::new());
        assert!(store.is_blocked("bad.example.com"));
        assert_eq!(store.check("bad.example.com").reason, "manually blocked");
        assert!(store.remove_from_blocklist("bad.example.com"));
        assert!(!store.is_blocked("bad.example.com"));
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
    fn parses_multi_alias_hosts_line() {
        let domains = parse_blocklist("0.0.0.0 a.com b.com c.com\n");
        assert_eq!(domains.len(), 3);
        assert!(domains.contains("a.com"));
        assert!(domains.contains("b.com"));
        assert!(domains.contains("c.com"));
    }

    #[test]
    fn parses_hosts_inline_comment() {
        let domains = parse_blocklist("0.0.0.0 a.com b.com  # trailing note\n");
        assert_eq!(domains.len(), 2);
        assert!(domains.contains("a.com"));
        assert!(domains.contains("b.com"));
    }

    #[test]
    fn excludes_localhost_aliases_in_hosts_line() {
        let domains = parse_blocklist("127.0.0.1 localhost localhost.localdomain my.local.dev\n");
        assert_eq!(domains.len(), 1);
        assert!(domains.contains("my.local.dev"));
    }

    #[test]
    fn local_path_recognises_file_url() {
        assert_eq!(
            local_path("file:///etc/numa/local.txt"),
            Some(std::path::PathBuf::from("/etc/numa/local.txt"))
        );
    }

    #[test]
    fn local_path_recognises_bare_absolute_unix() {
        #[cfg(unix)]
        assert_eq!(
            local_path("/etc/numa/local.txt"),
            Some(std::path::PathBuf::from("/etc/numa/local.txt"))
        );
    }

    #[test]
    fn local_path_ignores_http_url() {
        assert!(local_path("https://example.com/list.txt").is_none());
        assert!(local_path("http://example.com/list.txt").is_none());
    }

    fn defect(source: &str, text: &str) -> Option<String> {
        source_defect(source, text, &parse_blocklist(text))
    }

    /// A soft-error page small enough to yield one domain-shaped token still
    /// must not replace a working list — the count is not the test, the share
    /// of entry lines that parsed is.
    #[test]
    fn small_error_page_with_one_domain_shaped_line_is_rejected() {
        let body = "<html>\n<head><title>404 Not Found</title></head>\n<body>\n<center><h1>404 Not Found</h1></center>\n<hr><center>nginx/1.18.0</center>\n</body>\n</html>\n";
        assert!(
            !parse_blocklist(body).is_empty(),
            "precondition: parses > 0"
        );
        assert!(defect("https://cdn.example/list.txt", body).is_some());
    }

    /// Size is never the test — a tiny personal list must survive validation
    /// that an error page fails.
    #[test]
    fn tiny_custom_list_is_accepted() {
        assert!(defect("https://cdn.example/list.txt", "# mine\nads.example.com\n").is_none());
    }

    #[test]
    fn real_list_shapes_are_accepted() {
        assert!(defect("https://cdn.example/l.txt", "a.com\nb.com\nc.com\n").is_none());
        assert!(defect(
            "https://cdn.example/l.txt",
            "0.0.0.0 a.com\n0.0.0.0 b.com\n"
        )
        .is_none());
        assert!(defect("https://cdn.example/l.txt", "||a.com^\n||b.com^\n").is_none());
    }

    /// Emptying your own list file is an instruction to block nothing; an empty
    /// remote body is a broken upstream.
    #[test]
    fn empty_local_file_is_valid_but_empty_remote_body_is_not() {
        // temp_dir() rather than a literal: `/etc/...` has no drive prefix, so
        // Path::is_absolute is false for it on Windows.
        let local = std::env::temp_dir().join("numa-local.txt");
        assert!(defect(&local.display().to_string(), "# all clear\n").is_none());
        assert!(defect("https://cdn.example/list.txt", "").is_some());
    }

    #[test]
    fn heap_bytes_grows_with_domains() {
        let mut store = BlocklistStore::new(
            PersistedDomainList::unpersisted(),
            PersistedDomainList::unpersisted(),
        );
        let empty = store.heap_bytes();
        let domains: HashSet<String> = ["example.com", "example.org", "test.net"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        store.swap_domains(domains);
        assert!(store.heap_bytes() > empty);
    }

    fn empty_store() -> BlocklistStore {
        BlocklistStore::new(
            PersistedDomainList::unpersisted(),
            PersistedDomainList::unpersisted(),
        )
    }

    #[test]
    fn health_walks_from_unconfigured_to_failed() {
        let mut store = empty_store();
        assert_eq!(store.health(), "unconfigured");

        let (a, b) = ("https://a.example/l.txt", "https://b.example/l.txt");
        store.set_sources(&[a.to_string(), b.to_string()]);
        assert_eq!(store.health(), "loading", "configured but not yet fetched");
        assert_eq!(
            store.stats().list_sources[0].status,
            "pending",
            "not yet fetched is not the same as failed"
        );

        store.record_outcomes(&[
            (a.to_string(), SourceResult::Loaded),
            (b.to_string(), SourceResult::Loaded),
        ]);
        assert_eq!(
            store.health(),
            "ok",
            "sources that loaded and parsed to nothing are an emptied list"
        );

        store.swap_domains(["ads.example.com".to_string()].into_iter().collect());
        store.record_outcomes(&[(b.to_string(), SourceResult::Failed("HTTP 404".to_string()))]);
        assert_eq!(
            store.health(),
            "degraded",
            "one source down, still blocking"
        );

        store.swap_domains(HashSet::new());
        assert_eq!(store.health(), "failed", "nothing left to block with");
    }

    /// `record_outcomes` matches by URL, so a repeated entry used to strand a
    /// second state in Pending and pin health at "loading" forever.
    #[test]
    fn a_duplicate_source_does_not_pin_health_at_loading() {
        let mut store = empty_store();
        let a = "https://a.example/l.txt";
        store.set_sources(&[a.to_string(), a.to_string()]);
        assert_eq!(store.stats().list_sources.len(), 1, "deduplicated");

        store.record_outcomes(&[(a.to_string(), SourceResult::Loaded)]);
        assert_eq!(store.health(), "ok");
    }

    /// Blocking switched off must not report the same as a box with no lists.
    #[test]
    fn a_disabled_store_keeps_its_sources() {
        let mut store = empty_store();
        store.set_sources(&["https://a.example/l.txt".to_string()]);
        store.set_enabled(false);

        assert_eq!(store.health(), "off");
        let sources = store.stats().list_sources;
        assert_eq!(sources.len(), 1, "still configured, just not running");
        assert_eq!(sources[0].status, "pending");
    }

    /// The #336 shape: a source that failed has to keep its identity, or the
    /// dashboard cannot tell it apart from a source nobody configured.
    #[test]
    fn a_failed_source_keeps_its_url_and_reason() {
        let mut store = empty_store();
        let (a, b) = ("https://a.example/l.txt", "https://b.example/l.txt");
        store.set_sources(&[a.to_string(), b.to_string()]);
        store.record_outcomes(&[
            (a.to_string(), SourceResult::Loaded),
            (b.to_string(), SourceResult::Failed("HTTP 404".to_string())),
        ]);

        let stats = store.stats();
        assert_eq!(stats.list_sources.len(), 2);
        let good = stats.list_sources.iter().find(|s| s.url == a).unwrap();
        assert_eq!(good.status, "ok");
        assert!(good.error.is_none());
        assert!(good.last_ok_secs_ago.is_some());
        let bad = stats.list_sources.iter().find(|s| s.url == b).unwrap();
        assert_eq!(bad.status, "failed");
        assert_eq!(bad.error.as_deref(), Some("HTTP 404"));
        assert!(bad.last_ok_secs_ago.is_none(), "it never loaded");
    }

    /// Serving a cached copy is not a failure — it is still blocking, and the
    /// cache is never refused for being old.
    #[test]
    fn a_cached_copy_reports_stale_and_still_counts_as_blocking() {
        let mut store = empty_store();
        let a = "https://a.example/l.txt";
        store.set_sources(&[a.to_string()]);
        store.swap_domains(["ads.example.com".to_string()].into_iter().collect());
        store.record_outcomes(&[(
            a.to_string(),
            SourceResult::Cached {
                error: "HTTP 404".to_string(),
                fetched_unix: crate::blocklist_cache::now_unix() - 3 * 86400,
            },
        )]);

        assert_eq!(store.health(), "stale");
        let s = &store.stats().list_sources[0];
        assert_eq!(s.status, "stale", "a served cache is still blocking");
        assert_eq!(s.error.as_deref(), Some("HTTP 404"), "why it went stale");
        assert!(s.last_ok_secs_ago.unwrap() >= 3 * 86400, "age survives");
    }

    /// A source contributing nothing is worse news than an old copy.
    #[test]
    fn a_dead_source_outranks_a_stale_one() {
        let mut store = empty_store();
        let (a, b) = ("https://a.example/l.txt", "https://b.example/l.txt");
        store.set_sources(&[a.to_string(), b.to_string()]);
        store.swap_domains(["ads.example.com".to_string()].into_iter().collect());
        store.record_outcomes(&[
            (
                a.to_string(),
                SourceResult::Cached {
                    error: "timeout".to_string(),
                    fetched_unix: crate::blocklist_cache::now_unix(),
                },
            ),
            (b.to_string(), SourceResult::Failed("HTTP 404".to_string())),
        ]);
        assert_eq!(store.health(), "degraded");
    }

    /// A source that recovers must stop reporting the old error.
    #[test]
    fn a_recovered_source_clears_its_error() {
        let mut store = empty_store();
        let a = "https://a.example/l.txt";
        store.set_sources(&[a.to_string()]);
        store.record_outcomes(&[(a.to_string(), SourceResult::Failed("timeout".to_string()))]);
        store.record_outcomes(&[(a.to_string(), SourceResult::Loaded)]);

        let stats = store.stats();
        assert_eq!(stats.list_sources[0].status, "ok");
        assert!(stats.list_sources[0].error.is_none());
        assert_eq!(store.health(), "ok");
    }
}

const RETRY_DELAYS_SECS: &[u64] = &[2, 10, 30];

pub async fn download_blocklists(
    lists: &[String],
    resolver: Option<std::sync::Arc<crate::bootstrap_resolver::NumaResolver>>,
) -> Vec<(String, Result<String, String>)> {
    let mut builder = crate::forward::numa_tls_builder()
        .timeout(Duration::from_secs(30))
        .gzip(true);
    if let Some(r) = resolver {
        builder = builder.dns_resolver(r);
    }
    let client = builder.build().unwrap_or_default();

    let fetches = lists.iter().map(|source| {
        let client = &client;
        async move {
            let text = if let Some(path) = local_path(source) {
                match tokio::fs::read_to_string(&path).await {
                    Ok(t) => {
                        info!("loaded local blocklist: {} ({} bytes)", source, t.len());
                        Ok(t)
                    }
                    Err(e) => {
                        warn!(
                            "blocklist {} unreadable: {} — skipping",
                            source,
                            format_error_chain(&e)
                        );
                        Err("unreadable".to_string())
                    }
                }
            } else {
                match fetch_with_retry(client, source).await {
                    Ok(t) => {
                        info!("downloaded blocklist: {} ({} bytes)", source, t.len());
                        Ok(t)
                    }
                    Err(e) => Err(e),
                }
            };
            (source.clone(), text)
        }
    });
    futures::future::join_all(fetches)
        .await
        .into_iter()
        .collect()
}

fn local_path(source: &str) -> Option<std::path::PathBuf> {
    if let Some(rest) = source.strip_prefix("file://") {
        return Some(std::path::PathBuf::from(rest));
    }
    if std::path::Path::new(source).is_absolute() {
        return Some(std::path::PathBuf::from(source));
    }
    None
}

async fn fetch_with_retry(client: &reqwest::Client, url: &str) -> Result<String, String> {
    fetch_with_retry_delays(client, url, RETRY_DELAYS_SECS).await
}

async fn fetch_with_retry_delays(
    client: &reqwest::Client,
    url: &str,
    delays: &[u64],
) -> Result<String, String> {
    let total = delays.len() + 1;
    let mut last = "fetch failed".to_string();
    for attempt in 1..=total {
        match fetch_once(client, url).await {
            Ok(text) => return Ok(text),
            Err(e) if attempt < total => {
                let delay = delays[attempt - 1];
                warn!(
                    "blocklist {} attempt {}/{} failed: {} — retrying in {}s",
                    url, attempt, total, e.detail, delay
                );
                last = e.short;
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
            Err(e) => {
                warn!(
                    "blocklist {} attempt {}/{} failed: {} — giving up",
                    url, attempt, total, e.detail
                );
                last = e.short;
            }
        }
    }
    Err(last)
}

/// `short` is for the dashboard and must stay a terse token; `detail` is the
/// full chain the logs already carried.
struct FetchError {
    short: String,
    detail: String,
}

impl FetchError {
    fn new(e: reqwest::Error) -> Self {
        let short = if let Some(status) = e.status() {
            format!("HTTP {}", status.as_u16())
        } else if e.is_timeout() {
            "timeout".to_string()
        } else if e.is_connect() {
            "connection failed".to_string()
        } else {
            "fetch failed".to_string()
        };
        FetchError {
            short,
            detail: format_error_chain(&e),
        }
    }
}

async fn fetch_once(client: &reqwest::Client, url: &str) -> Result<String, FetchError> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(FetchError::new)?
        .error_for_status()
        .map_err(FetchError::new)?;
    resp.text().await.map_err(FetchError::new)
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

    async fn flaky_http_server(
        drop_first_n: usize,
        status: &'static str,
        body: &'static str,
    ) -> SocketAddr {
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
                        "HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                        status,
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
        let addr = flaky_http_server(delays.len(), "200 OK", body).await;
        let client = crate::forward::default_client();
        let url = format!("http://{addr}/");
        let result = fetch_with_retry_delays(&client, &url, &delays).await;
        assert_eq!(result.as_deref(), Ok(body));
    }

    fn unique_temp_path(prefix: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}_{nanos}.txt"))
    }

    #[tokio::test]
    async fn download_blocklists_reads_file_url() {
        let path = unique_temp_path("numa_blocklist");
        tokio::fs::write(&path, "0.0.0.0 a.com b.com\n")
            .await
            .unwrap();

        let url = format!("file://{}", path.display());
        let result = download_blocklists(std::slice::from_ref(&url), None).await;
        let _ = tokio::fs::remove_file(&path).await;

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, url);
        let domains = parse_blocklist(result[0].1.as_ref().unwrap());
        assert!(domains.contains("a.com"));
        assert!(domains.contains("b.com"));
    }

    #[tokio::test]
    async fn download_blocklists_reads_bare_absolute_path() {
        let path = unique_temp_path("numa_blocklist_bare");
        tokio::fs::write(&path, "ads.example.com\n").await.unwrap();

        let source = path.display().to_string();
        let result = download_blocklists(std::slice::from_ref(&source), None).await;
        let _ = tokio::fs::remove_file(&path).await;

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, source);
        assert!(result[0].1.as_ref().unwrap().contains("ads.example.com"));
    }

    /// A missing file is reported as a failed source, not dropped: dropping it
    /// is what made a dead list indistinguishable from no list (#336).
    #[tokio::test]
    async fn download_blocklists_reports_missing_local_file() {
        let path = unique_temp_path("numa_blocklist_missing");
        let url = format!(
            "file:///does/not/exist/{}",
            path.file_name().unwrap().to_string_lossy()
        );
        let result = download_blocklists(std::slice::from_ref(&url), None).await;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, url);
        assert_eq!(result[0].1.as_ref().unwrap_err(), "unreadable");
    }

    #[tokio::test]
    async fn retry_gives_up_when_all_attempts_fail() {
        let delays = zero_delays();
        let addr = flaky_http_server(delays.len() + 2, "200 OK", "unreachable").await;
        let client = crate::forward::default_client();
        let url = format!("http://{addr}/");
        let result = fetch_with_retry_delays(&client, &url, &delays).await;
        assert!(result.is_err());
    }

    /// The issue #336 outage: jsDelivr answered 403 with a plain-text error
    /// body, which was accepted as a successful download of zero domains.
    #[tokio::test]
    async fn non_2xx_is_a_failure_not_an_empty_list() {
        let addr = flaky_http_server(
            0,
            "403 Forbidden",
            "Package size exceeded the configured limit of 150 MB.",
        )
        .await;
        let client = crate::forward::default_client();
        let url = format!("http://{addr}/");
        let result = fetch_with_retry_delays(&client, &url, &[0]).await;
        assert_eq!(
            result.unwrap_err(),
            "HTTP 403",
            "403 body must not be taken as a blocklist"
        );
    }

    /// CI canary. Fetches the URL actually compiled into the binary and parses
    /// it with Numa's own parser, so a discontinued format fails here rather
    /// than in the field.
    #[tokio::test]
    #[ignore = "network"]
    async fn shipped_default_blocklist_still_loads() {
        let lists = crate::config::default_blocklists();
        let downloaded = download_blocklists(&lists, None).await;
        assert_eq!(downloaded.len(), lists.len());
        for (source, result) in &downloaded {
            // Every source now comes back whether it loaded or not, so the
            // count above proves nothing on its own — this is the real check.
            let text = result
                .as_ref()
                .unwrap_or_else(|e| panic!("default blocklist {source} failed: {e}"));
            let domains = parse_blocklist(text);
            assert!(
                domains.len() > 100_000,
                "default blocklist {source} parsed only {} domains",
                domains.len()
            );
        }
    }
}
