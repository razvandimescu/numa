use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

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

// --- System DNS configuration (install/uninstall) ---

fn numa_data_dir() -> PathBuf {
    dirs_or_home().join(".numa")
}

fn dirs_or_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn backup_path() -> PathBuf {
    numa_data_dir().join("original-dns.json")
}

/// Set the system DNS to 127.0.0.1 so all queries go through Numa.
/// Saves the original DNS settings for later restoration.
pub fn install_system_dns() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        install_macos()
    }
    #[cfg(target_os = "linux")]
    {
        install_linux()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("system DNS configuration not supported on this OS".to_string())
    }
}

/// Restore the original system DNS settings saved during install.
pub fn uninstall_system_dns() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        uninstall_macos()
    }
    #[cfg(target_os = "linux")]
    {
        uninstall_linux()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("system DNS configuration not supported on this OS".to_string())
    }
}

// --- macOS implementation ---

#[cfg(target_os = "macos")]
fn get_network_services() -> Result<Vec<String>, String> {
    let output = std::process::Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
        .map_err(|e| format!("failed to run networksetup: {}", e))?;

    let text = String::from_utf8_lossy(&output.stdout);
    let services: Vec<String> = text
        .lines()
        .skip(1) // first line is "An asterisk (*) denotes..."
        .map(|l| l.trim_start_matches('*').trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    Ok(services)
}

#[cfg(target_os = "macos")]
fn get_dns_servers(service: &str) -> Result<Vec<String>, String> {
    let output = std::process::Command::new("networksetup")
        .args(["-getdnsservers", service])
        .output()
        .map_err(|e| format!("failed to get DNS for {}: {}", service, e))?;

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.contains("aren't any DNS Servers") {
        Ok(vec![]) // using DHCP defaults
    } else {
        Ok(text.lines().map(|l| l.trim().to_string()).collect())
    }
}

#[cfg(target_os = "macos")]
fn install_macos() -> Result<(), String> {
    let services = get_network_services()?;
    let mut original: HashMap<String, Vec<String>> = HashMap::new();

    // Save current DNS for each service
    for service in &services {
        let servers = get_dns_servers(service)?;
        original.insert(service.clone(), servers);
    }

    // Save backup
    let dir = numa_data_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("failed to create {}: {}", dir.display(), e))?;

    let json = serde_json::to_string_pretty(&original)
        .map_err(|e| format!("failed to serialize backup: {}", e))?;
    std::fs::write(backup_path(), json).map_err(|e| format!("failed to write backup: {}", e))?;

    // Set DNS to 127.0.0.1 for each service
    for service in &services {
        let status = std::process::Command::new("networksetup")
            .args(["-setdnsservers", service, "127.0.0.1"])
            .status()
            .map_err(|e| format!("failed to set DNS for {}: {}", service, e))?;

        if status.success() {
            eprintln!("  set DNS for \"{}\" -> 127.0.0.1", service);
        } else {
            eprintln!("  warning: failed to set DNS for \"{}\"", service);
        }
    }

    eprintln!("\n  Original DNS saved to {}", backup_path().display());
    eprintln!("  Run 'sudo numa uninstall' to restore.\n");

    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_macos() -> Result<(), String> {
    let path = backup_path();
    let json = std::fs::read_to_string(&path)
        .map_err(|e| format!("no backup found at {}: {}", path.display(), e))?;

    let original: HashMap<String, Vec<String>> =
        serde_json::from_str(&json).map_err(|e| format!("invalid backup file: {}", e))?;

    for (service, servers) in &original {
        let args = if servers.is_empty() {
            // Restore to "empty" (DHCP default) by setting to "Empty"
            vec!["-setdnsservers", service, "Empty"]
        } else {
            let mut a = vec!["-setdnsservers", service];
            a.extend(servers.iter().map(|s| s.as_str()));
            a
        };

        let status = std::process::Command::new("networksetup")
            .args(&args)
            .status()
            .map_err(|e| format!("failed to restore DNS for {}: {}", service, e))?;

        if status.success() {
            let display = if servers.is_empty() {
                "DHCP default".to_string()
            } else {
                servers.join(", ")
            };
            eprintln!("  restored DNS for \"{}\" -> {}", service, display);
        } else {
            eprintln!("  warning: failed to restore DNS for \"{}\"", service);
        }
    }

    std::fs::remove_file(&path).ok();
    eprintln!("\n  System DNS restored. Backup removed.\n");

    Ok(())
}

// --- Linux stubs ---

#[cfg(target_os = "linux")]
fn install_linux() -> Result<(), String> {
    Err(
        "Linux auto-configuration not yet implemented. Manually set your DNS to 127.0.0.1"
            .to_string(),
    )
}

#[cfg(target_os = "linux")]
fn uninstall_linux() -> Result<(), String> {
    Err("Linux auto-configuration not yet implemented.".to_string())
}
