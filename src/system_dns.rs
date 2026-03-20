use std::net::SocketAddr;

use log::info;

/// A conditional forwarding rule: domains matching `suffix` are forwarded to `upstream`.
#[derive(Debug, Clone)]
pub struct ForwardingRule {
    pub suffix: String,
    dot_suffix: String, // pre-computed ".suffix" for zero-alloc matching
    pub upstream: SocketAddr,
}

/// Result of system DNS discovery — default upstream + conditional forwarding rules.
pub struct SystemDnsInfo {
    pub default_upstream: Option<String>,
    pub forwarding_rules: Vec<ForwardingRule>,
}

/// Discover system DNS configuration in a single pass.
/// On macOS: parses `scutil --dns` once for both the default upstream and forwarding rules.
/// On Linux: reads `/etc/resolv.conf` for upstream, no forwarding rules yet.
pub fn discover_system_dns() -> SystemDnsInfo {
    #[cfg(target_os = "macos")]
    {
        discover_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        SystemDnsInfo {
            default_upstream: detect_upstream_linux_or_backup(),
            forwarding_rules: Vec::new(),
        }
    }
}

#[cfg(target_os = "macos")]
fn discover_macos() -> SystemDnsInfo {
    use log::{debug, warn};

    let output = match std::process::Command::new("scutil").arg("--dns").output() {
        Ok(o) => o,
        Err(e) => {
            warn!("failed to run scutil --dns: {}", e);
            return SystemDnsInfo {
                default_upstream: None,
                forwarding_rules: Vec::new(),
            };
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut rules = Vec::new();
    let mut default_upstream: Option<String> = None;

    let mut current_domain: Option<String> = None;
    let mut current_nameserver: Option<String> = None;
    let mut is_supplemental = false;

    for line in text.lines() {
        let line = line.trim();

        if line.starts_with("resolver #") {
            // Emit previous supplemental block as forwarding rule
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
                if ns.parse::<std::net::Ipv4Addr>().is_ok() {
                    current_nameserver = Some(ns.clone());
                    // Capture first non-supplemental, non-loopback nameserver as default upstream
                    if !is_supplemental
                        && default_upstream.is_none()
                        && ns != "127.0.0.1"
                        && ns != "0.0.0.0"
                    {
                        default_upstream = Some(ns);
                    }
                }
            }
        } else if line.starts_with("flags") && line.contains("Supplemental") {
            is_supplemental = true;
        } else if line.starts_with("DNS configuration (for scoped") {
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
        debug!("no conditional forwarding rules discovered");
    }
    if let Some(ref ns) = default_upstream {
        info!("detected system upstream: {}", ns);
    }

    SystemDnsInfo {
        default_upstream,
        forwarding_rules: rules,
    }
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

/// Detect upstream from /etc/resolv.conf, falling back to backup file if resolv.conf
/// only has loopback (meaning numa install already ran).
#[cfg(not(target_os = "macos"))]
fn detect_upstream_linux_or_backup() -> Option<String> {
    // Try /etc/resolv.conf first
    if let Some(ns) = read_upstream_from_file("/etc/resolv.conf") {
        info!("detected system upstream: {}", ns);
        return Some(ns);
    }
    // If resolv.conf only has loopback, check the backup from `numa install`
    let backup = {
        let home = std::env::var("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("/root"));
        home.join(".numa").join("original-resolv.conf")
    };
    if let Some(ns) = read_upstream_from_file(backup.to_str().unwrap_or("")) {
        info!("detected original upstream from backup: {}", ns);
        return Some(ns);
    }
    None
}

#[cfg(not(target_os = "macos"))]
fn read_upstream_from_file(path: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("nameserver") {
            if let Some(ns) = line.split_whitespace().nth(1) {
                if ns != "127.0.0.1" && ns != "0.0.0.0" && ns != "::1" {
                    return Some(ns.to_string());
                }
            }
        }
    }
    None
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
fn numa_data_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("SUDO_USER").map(|u| format!("/Users/{}", u)))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/var/root"));
    home.join(".numa")
}

#[cfg(target_os = "macos")]
fn backup_path() -> std::path::PathBuf {
    numa_data_dir().join("original-dns.json")
}

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
    use std::collections::HashMap;

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
    use std::collections::HashMap;

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

// --- Service management ---

#[cfg(target_os = "macos")]
const PLIST_LABEL: &str = "com.numa.dns";
#[cfg(target_os = "macos")]
const PLIST_DEST: &str = "/Library/LaunchDaemons/com.numa.dns.plist";
#[cfg(target_os = "linux")]
const SYSTEMD_UNIT: &str = "/etc/systemd/system/numa.service";

/// Install Numa as a system service that starts on boot and auto-restarts.
pub fn install_service() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        install_service_macos()
    }
    #[cfg(target_os = "linux")]
    {
        install_service_linux()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("service installation not supported on this OS".to_string())
    }
}

/// Uninstall the Numa system service.
pub fn uninstall_service() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        uninstall_service_macos()
    }
    #[cfg(target_os = "linux")]
    {
        uninstall_service_linux()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("service uninstallation not supported on this OS".to_string())
    }
}

/// Restart the service (kill process, launchd/systemd auto-restarts with new binary).
pub fn restart_service() -> Result<(), String> {
    // Show version of the binary that will be running after restart
    let version = match std::process::Command::new("/usr/local/bin/numa")
        .arg("--version")
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stderr).trim().to_string(),
        Err(_) => "unknown".to_string(),
    };

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("launchctl")
            .args(["list", PLIST_LABEL])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                let _ = std::process::Command::new("pkill")
                    .args(["-f", "/usr/local/bin/numa"])
                    .status();
                eprintln!("  Service restarting → {}\n", version);
                Ok(())
            }
            _ => Err("Service is not installed. Run 'sudo numa service start' first.".to_string()),
        }
    }
    #[cfg(target_os = "linux")]
    {
        run_systemctl(&["restart", "numa"])?;
        eprintln!("  Service restarted → {}\n", version);
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("service restart not supported on this OS".to_string())
    }
}

/// Show the service status.
pub fn service_status() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        service_status_macos()
    }
    #[cfg(target_os = "linux")]
    {
        service_status_linux()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("service status not supported on this OS".to_string())
    }
}

#[cfg(target_os = "macos")]
fn install_service_macos() -> Result<(), String> {
    // Check binary exists
    if !std::path::Path::new("/usr/local/bin/numa").exists() {
        return Err("numa binary not found at /usr/local/bin/numa. Run: sudo cp target/release/numa /usr/local/bin/numa".to_string());
    }

    // Create log directory
    std::fs::create_dir_all("/usr/local/var/log")
        .map_err(|e| format!("failed to create log dir: {}", e))?;

    // Write plist
    let plist = include_str!("../com.numa.dns.plist");
    std::fs::write(PLIST_DEST, plist)
        .map_err(|e| format!("failed to write {}: {}", PLIST_DEST, e))?;

    // Load the service
    let status = std::process::Command::new("launchctl")
        .args(["load", "-w", PLIST_DEST])
        .status()
        .map_err(|e| format!("failed to run launchctl: {}", e))?;

    if !status.success() {
        return Err("launchctl load failed".to_string());
    }

    // Set system DNS to 127.0.0.1 now that the service is running
    eprintln!("  Service installed and started.");
    if let Err(e) = install_macos() {
        eprintln!("  warning: failed to configure system DNS: {}", e);
    }
    eprintln!("  Numa will auto-start on boot and restart if killed.");
    eprintln!("  Logs: /usr/local/var/log/numa.log");
    eprintln!("  Run 'sudo numa service stop' to fully uninstall.\n");
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_service_macos() -> Result<(), String> {
    // Restore DNS first, while numa is still running to handle any final queries
    if let Err(e) = uninstall_macos() {
        eprintln!("  warning: failed to restore system DNS: {}", e);
    }

    // Remove plist first so service won't restart on boot even if unload fails
    if let Err(e) = std::fs::remove_file(PLIST_DEST) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(format!("failed to remove {}: {}", PLIST_DEST, e));
        }
    }

    // Unload the service
    let status = std::process::Command::new("launchctl")
        .args(["unload", "-w", PLIST_DEST])
        .status();
    if let Ok(s) = status {
        if !s.success() {
            eprintln!(
                "  warning: launchctl unload returned non-zero (service may still be running)"
            );
        }
    }

    eprintln!("  Service uninstalled. Numa will no longer auto-start.\n");
    Ok(())
}

#[cfg(target_os = "macos")]
fn service_status_macos() -> Result<(), String> {
    let output = std::process::Command::new("launchctl")
        .args(["list", PLIST_LABEL])
        .output()
        .map_err(|e| format!("failed to run launchctl: {}", e))?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        eprintln!("  Numa service is loaded.\n");
        for line in text.lines() {
            eprintln!("  {}", line);
        }
        eprintln!();
    } else {
        eprintln!("  Numa service is not installed.\n");
    }
    Ok(())
}

// --- Linux implementation ---

#[cfg(target_os = "linux")]
fn backup_path_linux() -> std::path::PathBuf {
    let home = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/root"));
    home.join(".numa").join("original-resolv.conf")
}

#[cfg(target_os = "linux")]
fn is_systemd_resolved_active() -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "systemd-resolved"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn install_linux() -> Result<(), String> {
    // Detect systemd-resolved — direct resolv.conf manipulation won't persist
    if is_systemd_resolved_active() {
        let resolved_dir = std::path::Path::new("/etc/systemd/resolved.conf.d");
        std::fs::create_dir_all(resolved_dir)
            .map_err(|e| format!("failed to create {}: {}", resolved_dir.display(), e))?;

        let drop_in = resolved_dir.join("numa.conf");
        std::fs::write(&drop_in, "[Resolve]\nDNS=127.0.0.1\nDomains=~.\n")
            .map_err(|e| format!("failed to write {}: {}", drop_in.display(), e))?;

        let _ = run_systemctl(&["restart", "systemd-resolved"]);
        eprintln!("  systemd-resolved detected.");
        eprintln!("  Installed drop-in: {}", drop_in.display());
        eprintln!("  Run 'sudo numa uninstall' to remove.\n");
        return Ok(());
    }

    // Fallback: direct resolv.conf manipulation
    let resolv = std::path::Path::new("/etc/resolv.conf");
    let backup = backup_path_linux();

    // Ensure backup directory exists
    if let Some(parent) = backup.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;
    }

    // Back up current resolv.conf (ignore NotFound)
    match std::fs::copy(resolv, &backup) {
        Ok(_) => eprintln!("  Saved /etc/resolv.conf to {}", backup.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("failed to backup /etc/resolv.conf: {}", e)),
    }

    if resolv
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        eprintln!("  warning: /etc/resolv.conf is a symlink — changes may not persist.");
        eprintln!("  Consider using systemd-resolved or NetworkManager instead.\n");
    }

    let content =
        "# Generated by Numa — run 'sudo numa uninstall' to restore\nnameserver 127.0.0.1\n";
    std::fs::write(resolv, content)
        .map_err(|e| format!("failed to write /etc/resolv.conf: {}", e))?;

    eprintln!("  Set /etc/resolv.conf -> nameserver 127.0.0.1");
    eprintln!("  Run 'sudo numa uninstall' to restore.\n");
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_linux() -> Result<(), String> {
    // Check for systemd-resolved drop-in first
    let drop_in = std::path::Path::new("/etc/systemd/resolved.conf.d/numa.conf");
    if drop_in.exists() {
        std::fs::remove_file(drop_in)
            .map_err(|e| format!("failed to remove {}: {}", drop_in.display(), e))?;
        let _ = run_systemctl(&["restart", "systemd-resolved"]);
        eprintln!("  Removed systemd-resolved drop-in. DNS restored.\n");
        return Ok(());
    }

    // Fallback: restore resolv.conf from backup
    let backup = backup_path_linux();
    let resolv = std::path::Path::new("/etc/resolv.conf");

    match std::fs::copy(&backup, resolv) {
        Ok(_) => {
            std::fs::remove_file(&backup).ok();
            eprintln!("  Restored /etc/resolv.conf from backup. Backup removed.\n");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("  No backup found at {}.", backup.display());
            eprintln!("  Manually edit /etc/resolv.conf to restore your DNS.\n");
        }
        Err(e) => return Err(format!("failed to restore /etc/resolv.conf: {}", e)),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_binary_installed() -> Result<(), String> {
    if !std::path::Path::new("/usr/local/bin/numa").exists() {
        return Err("numa binary not found at /usr/local/bin/numa. Run: sudo cp target/release/numa /usr/local/bin/numa".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_service_linux() -> Result<(), String> {
    ensure_binary_installed()?;

    let unit = include_str!("../numa.service");
    std::fs::write(SYSTEMD_UNIT, unit)
        .map_err(|e| format!("failed to write {}: {}", SYSTEMD_UNIT, e))?;

    run_systemctl(&["daemon-reload"])?;
    run_systemctl(&["enable", "numa"])?;
    run_systemctl(&["start", "numa"])?;

    eprintln!("  Service installed and started.");

    // Set system DNS now that the service is running
    if let Err(e) = install_linux() {
        eprintln!("  warning: failed to configure system DNS: {}", e);
    }
    eprintln!("  Numa will auto-start on boot and restart if killed.");
    eprintln!("  Logs: journalctl -u numa -f");
    eprintln!("  Run 'sudo numa service stop' to fully uninstall.\n");
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_service_linux() -> Result<(), String> {
    // Restore DNS first, while numa is still running
    if let Err(e) = uninstall_linux() {
        eprintln!("  warning: failed to restore system DNS: {}", e);
    }

    if let Err(e) = run_systemctl(&["stop", "numa"]) {
        eprintln!("  warning: {}", e);
    }
    if let Err(e) = run_systemctl(&["disable", "numa"]) {
        eprintln!("  warning: {}", e);
    }

    if let Err(e) = std::fs::remove_file(SYSTEMD_UNIT) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(format!("failed to remove {}: {}", SYSTEMD_UNIT, e));
        }
    }
    let _ = run_systemctl(&["daemon-reload"]);

    eprintln!("  Service uninstalled. Numa will no longer auto-start.\n");
    Ok(())
}

#[cfg(target_os = "linux")]
fn service_status_linux() -> Result<(), String> {
    let output = std::process::Command::new("systemctl")
        .args(["status", "numa"])
        .output()
        .map_err(|e| format!("failed to run systemctl: {}", e))?;

    let text = String::from_utf8_lossy(&output.stdout);
    if text.is_empty() {
        eprintln!("  Numa service is not installed.\n");
    } else {
        for line in text.lines() {
            eprintln!("  {}", line);
        }
        eprintln!();
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_systemctl(args: &[&str]) -> Result<(), String> {
    let status = std::process::Command::new("systemctl")
        .args(args)
        .status()
        .map_err(|e| format!("systemctl {} failed: {}", args.join(" "), e))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "systemctl {} exited with {}",
            args.join(" "),
            status
        ))
    }
}
