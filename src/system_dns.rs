use std::net::SocketAddr;

use log::info;

/// A conditional forwarding rule: domains matching `suffix` are forwarded to `upstream`.
#[derive(Debug, Clone)]
pub struct ForwardingRule {
    pub suffix: String,
    dot_suffix: String, // pre-computed ".suffix" for zero-alloc matching
    pub upstream: SocketAddr,
}

/// Discover system DNS forwarding rules from the OS.
/// On macOS, parses `scutil --dns`. Returns rules sorted longest-suffix-first
/// so more specific matches take priority.
pub fn discover_forwarding_rules() -> Vec<ForwardingRule> {
    #[cfg(target_os = "macos")]
    {
        discover_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        info!("system DNS auto-discovery not implemented for this OS");
        Vec::new()
    }
}

#[cfg(target_os = "macos")]
fn discover_macos() -> Vec<ForwardingRule> {
    use log::{debug, warn};

    let output = match std::process::Command::new("scutil").arg("--dns").output() {
        Ok(o) => o,
        Err(e) => {
            warn!("failed to run scutil --dns: {}", e);
            return Vec::new();
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut rules = Vec::new();

    // Parse resolver blocks: look for blocks with both `domain` and `nameserver[0]`
    // that have the `Supplemental` flag (conditional forwarding, not default)
    let mut current_domain: Option<String> = None;
    let mut current_nameserver: Option<String> = None;
    let mut is_supplemental = false;

    for line in text.lines() {
        let line = line.trim();

        if line.starts_with("resolver #") {
            // Emit previous block if valid
            if let (Some(domain), Some(ns), true) = (
                current_domain.take(),
                current_nameserver.take(),
                is_supplemental,
            ) {
                if let Some(rule) = make_rule(&domain, &ns) {
                    rules.push(rule);
                }
            }
            current_domain = None;
            current_nameserver = None;
            is_supplemental = false;
        } else if line.starts_with("domain") && line.contains(':') {
            // "domain   : tailcee7cc.ts.net."
            if let Some(val) = line.split(':').nth(1) {
                let domain = val.trim().trim_end_matches('.').to_lowercase();
                if !domain.is_empty()
                    && domain != "local"
                    && !domain.ends_with("in-addr.arpa")
                    && !domain.ends_with("ip6.arpa")
                {
                    current_domain = Some(domain);
                }
            }
        } else if line.starts_with("nameserver[0]") && line.contains(':') {
            if let Some(val) = line.split(':').nth(1) {
                let ns = val.trim().to_string();
                // Only use IPv4 nameservers for now
                if ns.parse::<std::net::Ipv4Addr>().is_ok() {
                    current_nameserver = Some(ns);
                }
            }
        } else if line.starts_with("flags") && line.contains("Supplemental") {
            is_supplemental = true;
        } else if line.starts_with("DNS configuration (for scoped") {
            // Stop at scoped section — those are interface-specific, not conditional
            if let (Some(domain), Some(ns), true) = (
                current_domain.take(),
                current_nameserver.take(),
                is_supplemental,
            ) {
                if let Some(rule) = make_rule(&domain, &ns) {
                    rules.push(rule);
                }
            }
            break;
        }
    }

    // Emit last block
    if let (Some(domain), Some(ns), true) = (current_domain, current_nameserver, is_supplemental) {
        if let Some(rule) = make_rule(&domain, &ns) {
            rules.push(rule);
        }
    }

    // Sort longest suffix first for most-specific matching
    rules.sort_by(|a, b| b.suffix.len().cmp(&a.suffix.len()));

    for rule in &rules {
        info!(
            "auto-discovered forwarding: *.{} -> {}",
            rule.suffix, rule.upstream
        );
    }

    if rules.is_empty() {
        debug!("no conditional forwarding rules discovered from scutil --dns");
    }

    rules
}

#[cfg(target_os = "macos")]
fn make_rule(domain: &str, nameserver: &str) -> Option<ForwardingRule> {
    let addr: SocketAddr = format!("{}:53", nameserver).parse().ok()?;
    Some(ForwardingRule {
        dot_suffix: format!(".{}", domain),
        suffix: domain.to_string(),
        upstream: addr,
    })
}

/// Find the upstream for a domain by checking forwarding rules.
/// Returns None if no rule matches (use default upstream).
/// Zero-allocation on the hot path — dot_suffix is pre-computed.
pub fn match_forwarding_rule(domain: &str, rules: &[ForwardingRule]) -> Option<SocketAddr> {
    for rule in rules {
        if domain == rule.suffix || domain.ends_with(&rule.dot_suffix) {
            return Some(rule.upstream);
        }
    }
    None
}
