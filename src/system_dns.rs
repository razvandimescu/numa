use std::net::SocketAddr;

use log::info;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::forward::Upstream;
use crate::forward::UpstreamPool;

fn print_recursive_hint() {
    let is_recursive = crate::config::load_config("numa.toml")
        .map(|c| c.config.upstream.mode == crate::config::UpstreamMode::Recursive)
        .unwrap_or(false);
    if !is_recursive {
        eprintln!("  Want full DNS sovereignty? Add to numa.toml:");
        eprintln!("    [upstream]");
        eprintln!("    mode = \"recursive\"\n");
    }
}

fn is_loopback_or_stub(addr: &str) -> bool {
    // fec0:0:0:ffff::1/2/3 are the deprecated IPv6 site-local stubs that
    // Get-DnsClientServerAddress returns for any IPv6-enabled adapter
    // without explicit DNS — they're not real upstreams.
    matches!(
        addr,
        "127.0.0.1"
            | "127.0.0.53"
            | "0.0.0.0"
            | "::1"
            | "fec0:0:0:ffff::1"
            | "fec0:0:0:ffff::2"
            | "fec0:0:0:ffff::3"
            | ""
    )
}

/// A conditional forwarding rule: domains matching `suffix` are forwarded to `upstream`.
#[derive(Clone)]
pub struct ForwardingRule {
    pub suffix: String,
    dot_suffix: String, // pre-computed ".suffix" for zero-alloc matching
    pub upstream: UpstreamPool,
}

impl ForwardingRule {
    pub fn new(suffix: String, upstream: UpstreamPool) -> Self {
        let dot_suffix = format!(".{}", suffix);
        Self {
            suffix,
            dot_suffix,
            upstream,
        }
    }
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
    #[cfg(target_os = "linux")]
    {
        discover_linux()
    }
    #[cfg(windows)]
    {
        discover_windows()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        log::debug!("no conditional forwarding rules discovered");
        SystemDnsInfo {
            default_upstream: None,
            forwarding_rules: Vec::new(),
        }
    }
}

/// Advisory for port-53 bind failures (EADDRINUSE or EACCES); `None`
/// if not applicable so the caller can fall back to the raw error.
pub fn try_port53_advisory(bind_addr: &str, err: &std::io::Error) -> Option<String> {
    if !is_port_53(bind_addr) {
        return None;
    }
    let (title, cause) = match err.kind() {
        std::io::ErrorKind::AddrInUse => (
            "port 53 is already in use",
            "Another process is already bound to port 53. On Linux this is\n  \
             typically systemd-resolved; on Windows, the DNS Client service.",
        ),
        std::io::ErrorKind::PermissionDenied => (
            "permission denied",
            "Port 53 is privileged — binding it requires root on Linux/macOS\n  \
             or Administrator on Windows.",
        ),
        _ => return None,
    };
    let o = "\x1b[1;38;2;192;98;58m"; // bold orange
    let r = "\x1b[0m";
    Some(format!(
        "
{o}Numa{r} — cannot bind to {bind_addr}: {title}.

  {cause}

  Fix — pick one:

    1. Install Numa as the system resolver (frees port 53):

         sudo numa install       (on Windows, run as Administrator)

    2. Run on a non-privileged port for testing.
       Create {} with:

         [server]
         bind_addr = \"127.0.0.1:5354\"
         api_port  = 5380

       Then run:  numa
       Test with: dig @127.0.0.1 -p 5354 example.com

",
        crate::suggested_config_path().display()
    ))
}

fn is_port_53(bind_addr: &str) -> bool {
    bind_addr
        .parse::<SocketAddr>()
        .map(|s| s.port() == 53)
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct ScutilState {
    rules: Vec<ForwardingRule>,
    default_upstream: Option<String>,
    current_domain: Option<String>,
    current_nameserver: Option<String>,
    is_supplemental: bool,
}

#[cfg(target_os = "macos")]
impl ScutilState {
    fn flush(&mut self) {
        if let (Some(domain), Some(ns), true) = (
            self.current_domain.take(),
            self.current_nameserver.take(),
            self.is_supplemental,
        ) {
            if let Some(rule) = make_rule(&domain, &ns) {
                self.rules.push(rule);
            }
        }
        self.is_supplemental = false;
    }

    fn set_domain(&mut self, line: &str) {
        let Some(val) = line.split(':').nth(1) else {
            return;
        };
        let domain = val.trim().trim_end_matches('.').to_lowercase();
        if !domain.is_empty()
            && domain != "local"
            && !domain.ends_with("in-addr.arpa")
            && !domain.ends_with("ip6.arpa")
        {
            self.current_domain = Some(domain);
        }
    }

    fn set_nameserver(&mut self, line: &str) {
        let Some(val) = line.split(':').nth(1) else {
            return;
        };
        let ns = val.trim().to_string();
        if ns.parse::<std::net::Ipv4Addr>().is_err() {
            return;
        }
        if !self.is_supplemental && self.default_upstream.is_none() && !is_loopback_or_stub(&ns) {
            self.default_upstream = Some(ns.clone());
        }
        self.current_nameserver = Some(ns);
    }

    /// Returns true when the parser should stop.
    fn handle_line(&mut self, line: &str) -> bool {
        if line.starts_with("resolver #") {
            self.flush();
        } else if line.starts_with("domain") && line.contains(':') {
            self.set_domain(line);
        } else if line.starts_with("nameserver[0]") && line.contains(':') {
            self.set_nameserver(line);
        } else if line.starts_with("flags") && line.contains("Supplemental") {
            self.is_supplemental = true;
        } else if line.starts_with("DNS configuration (for scoped") {
            self.flush();
            return true;
        }
        false
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
    let mut state = ScutilState::default();
    for line in text.lines() {
        if state.handle_line(line.trim()) {
            break;
        }
    }
    state.flush();

    let ScutilState {
        mut rules,
        default_upstream,
        ..
    } = state;
    rules.sort_by_key(|r| std::cmp::Reverse(r.suffix.len()));

    for rule in &rules {
        info!(
            "auto-discovered forwarding: *.{} -> {}",
            rule.suffix,
            rule.upstream.label()
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

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn make_rule(domain: &str, nameserver: &str) -> Option<ForwardingRule> {
    let addr = crate::forward::parse_upstream_addr(nameserver, 53).ok()?;
    let pool = UpstreamPool::new(vec![Upstream::Udp(addr)], vec![]);
    Some(ForwardingRule::new(domain.to_string(), pool))
}

#[cfg(target_os = "linux")]
const CLOUD_VPC_RESOLVER: &str = "169.254.169.253";

#[cfg(target_os = "linux")]
fn discover_linux() -> SystemDnsInfo {
    // Parse resolv.conf once for both upstream and search domains
    let (upstream, search_domains) = parse_resolv_conf("/etc/resolv.conf");

    let default_upstream = if let Some(ns) = upstream {
        info!("detected system upstream: {}", ns);
        Some(ns)
    } else if let Some(ns) = resolvectl_dns_server() {
        info!("detected system upstream via resolvectl: {}", ns);
        Some(ns)
    } else {
        // Fallback to backup from a previous `numa install`
        let backup = {
            let home = std::env::var("HOME")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("/root"));
            home.join(".numa").join("original-resolv.conf")
        };
        let (ns, _) = parse_resolv_conf(backup.to_str().unwrap_or(""));
        if let Some(ref ns) = ns {
            info!("detected original upstream from backup: {}", ns);
        }
        ns
    };

    // On cloud VMs (AWS/GCP), internal domains need to reach the VPC resolver
    let forwarding_rules = if search_domains.is_empty() {
        Vec::new()
    } else {
        let forwarder = resolvectl_dns_server().unwrap_or_else(|| CLOUD_VPC_RESOLVER.to_string());
        let rules: Vec<_> = search_domains
            .iter()
            .filter_map(|domain| {
                let rule = make_rule(domain, &forwarder)?;
                info!("forwarding .{} to {}", domain, forwarder);
                Some(rule)
            })
            .collect();
        if !rules.is_empty() {
            info!("detected {} search domain forwarding rules", rules.len());
        }
        rules
    };

    SystemDnsInfo {
        default_upstream,
        forwarding_rules,
    }
}

/// Yield each `nameserver` address from resolv.conf content. No filtering —
/// callers decide what counts as a real upstream.
#[cfg(any(target_os = "linux", test))]
fn iter_nameservers(content: &str) -> impl Iterator<Item = &str> {
    content.lines().filter_map(|line| {
        let mut parts = line.split_whitespace();
        (parts.next() == Some("nameserver")).then_some(())?;
        parts.next()
    })
}

/// Parse resolv.conf in a single pass, extracting the first non-loopback
/// nameserver and all search domains.
#[cfg(target_os = "linux")]
fn parse_resolv_conf(path: &str) -> (Option<String>, Vec<String>) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return (None, Vec::new()),
    };
    let upstream = iter_nameservers(&text)
        .find(|ns| !is_loopback_or_stub(ns))
        .map(str::to_string);
    let mut search_domains = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("search") || line.starts_with("domain") {
            for domain in line.split_whitespace().skip(1) {
                search_domains.push(domain.to_string());
            }
        }
    }
    (upstream, search_domains)
}

/// True if the resolv.conf *content* appears to be written by numa itself,
/// or has no real upstream — either way, it's not a safe source of truth
/// for a backup.
#[cfg(any(target_os = "linux", test))]
fn resolv_conf_is_numa_managed(content: &str) -> bool {
    content.contains("Generated by Numa") || !resolv_conf_has_real_upstream(content)
}

/// True if the resolv.conf content has at least one non-loopback, non-stub
/// nameserver. An all-loopback resolv.conf is self-referential.
#[cfg(any(target_os = "linux", test))]
fn resolv_conf_has_real_upstream(content: &str) -> bool {
    iter_nameservers(content).any(|ns| !is_loopback_or_stub(ns))
}

/// Query resolvectl for the real upstream DNS server (e.g. VPC resolver on AWS).
#[cfg(target_os = "linux")]
fn resolvectl_dns_server() -> Option<String> {
    let output = std::process::Command::new("resolvectl")
        .args(["status", "--no-pager"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.contains("DNS Servers") || line.contains("Current DNS Server") {
            if let Some(ip) = line.split(':').next_back() {
                let ip = ip.trim();
                if ip.parse::<std::net::IpAddr>().is_ok() && !is_loopback_or_stub(ip) {
                    return Some(ip.to_string());
                }
            }
        }
    }
    None
}

/// Detect DNS server from DHCP lease — fallback when scutil/resolv.conf only shows 127.0.0.1.
/// On macOS: parses `ipconfig getpacket en0` for domain_name_server.
/// On Linux/Windows: returns None (not implemented yet).
pub fn detect_dhcp_dns() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        detect_dhcp_dns_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
fn detect_dhcp_dns_macos() -> Option<String> {
    // Try common interfaces
    for iface in &["en0", "en1"] {
        let output = std::process::Command::new("ipconfig")
            .args(["getpacket", iface])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("domain_name_server") {
                // Format: "domain_name_server (ip_mult): {213.154.124.25, 1.0.0.1}"
                if let Some(braces) = line.split('{').nth(1) {
                    let inner = braces.trim_end_matches('}').trim();
                    // Take the first non-loopback DNS server
                    for addr in inner.split(',') {
                        let addr = addr.trim();
                        if !is_loopback_or_stub(addr) && addr.parse::<std::net::Ipv4Addr>().is_ok()
                        {
                            log::info!("detected DHCP DNS: {}", addr);
                            return Some(addr.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

// --- Windows implementation ---

#[cfg(windows)]
fn discover_windows() -> SystemDnsInfo {
    use log::{debug, warn};

    let output = match std::process::Command::new("ipconfig").arg("/all").output() {
        Ok(o) => o,
        Err(e) => {
            warn!("failed to run ipconfig /all: {}", e);
            return SystemDnsInfo {
                default_upstream: None,
                forwarding_rules: Vec::new(),
            };
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut upstream = None;

    for line in text.lines() {
        let trimmed = line.trim();
        // Match "DNS Servers" line (English) or similar localized variants
        if trimmed.contains("DNS Servers") || trimmed.contains("DNS-Server") {
            if let Some(ip) = trimmed.split(':').next_back() {
                let ip = ip.trim();
                if ip.parse::<std::net::IpAddr>().is_ok() && !is_loopback_or_stub(ip) {
                    upstream = Some(ip.to_string());
                    break;
                }
            }
        }
        // Continuation lines (indented IPs after DNS Servers line)
        if upstream.is_none() && trimmed.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            // Skip continuation lines — we only need the first DNS server
        }
    }

    if let Some(ref ns) = upstream {
        info!("detected Windows upstream: {}", ns);
    } else {
        debug!("no DNS servers found in ipconfig output");
    }

    SystemDnsInfo {
        default_upstream: upstream,
        forwarding_rules: Vec::new(),
    }
}

#[cfg(any(windows, test))]
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct WindowsInterfaceDns {
    // Live adapter index, resolved fresh from `Get-NetAdapter` and passed to
    // netsh as the [name=] argument — friendly names round-trip badly on
    // non-English locales (#160: "Ethernet" returned ERROR_INVALID_NAME on
    // ru-RU), the integer ifIndex doesn't. Skipped during serialize because
    // ifIndex isn't stable across reboots; the on-disk backup stays keyed
    // by friendly name and looks the index up live at restore time.
    #[serde(default, skip_serializing)]
    if_index: u32,
    servers: Vec<String>,
}

// PowerShell snippet that emits a JSON object keyed by adapter friendly name.
// Locale-invariant: cmdlet property names don't translate, unlike the
// `ipconfig /all` text we used to scrape — non-English Windows installs
// matched zero adapter headers and `numa install` aborted with "no active
// network interfaces found" (issue #146).
#[cfg(windows)]
const ENUMERATE_INTERFACES_PS: &str = r#"
$ErrorActionPreference = 'Stop'
$result = [ordered]@{}
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
foreach ($a in $adapters) {
    $v4 = @(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
    $v6 = @(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses
    # Drop nulls: ServerAddresses can be $null when an adapter has no
    # configured DNS for one family, and `$v4 + $null` appends a literal
    # null entry that ConvertTo-Json emits as JSON `null`, breaking the
    # `Vec<String>` deserialize on the Rust side.
    $result[$a.Name] = @{ if_index = $a.ifIndex; servers = @(($v4 + $v6) | Where-Object { $_ }) }
}
$result | ConvertTo-Json -Compress -Depth 4
"#;

#[cfg(any(windows, test))]
fn parse_powershell_interfaces(
    json: &str,
) -> Result<std::collections::HashMap<String, WindowsInterfaceDns>, String> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    serde_json::from_str(trimmed).map_err(|e| format!("invalid powershell JSON: {}", e))
}

#[cfg(windows)]
fn get_windows_interfaces() -> Result<std::collections::HashMap<String, WindowsInterfaceDns>, String>
{
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ENUMERATE_INTERFACES_PS,
        ])
        .output()
        .map_err(|e| format!("failed to run powershell: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "powershell adapter query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    parse_powershell_interfaces(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(windows)]
fn windows_backup_path() -> std::path::PathBuf {
    // Use ProgramData (not APPDATA) since install requires admin elevation
    // and APPDATA differs between user and admin contexts.
    std::path::PathBuf::from(
        std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".into()),
    )
    .join("numa")
    .join("original-dns.json")
}

#[cfg(windows)]
fn disable_dnscache() -> Result<bool, String> {
    // Check if Dnscache is running (it can hold port 53)
    let output = std::process::Command::new("sc")
        .args(["query", "Dnscache"])
        .output()
        .map_err(|e| format!("failed to query Dnscache: {}", e))?;
    let text = String::from_utf8_lossy(&output.stdout);
    if !text.contains("RUNNING") {
        return Ok(false);
    }

    eprintln!("  Disabling DNS Client (Dnscache) to free port 53...");
    // Dnscache can't be stopped via sc/net stop — must disable via registry
    let status = std::process::Command::new("reg")
        .args([
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache",
            "/v",
            "Start",
            "/t",
            "REG_DWORD",
            "/d",
            "4",
            "/f",
        ])
        .status()
        .map_err(|e| format!("failed to disable Dnscache: {}", e))?;

    if !status.success() {
        return Err("failed to disable Dnscache via registry (run as Administrator?)".into());
    }

    // Dnscache is disabled for next boot. Check whether port 53 is
    // actually blocked right now — on many Windows configurations
    // Dnscache doesn't bind port 53 even while running.
    let port_blocked = std::net::UdpSocket::bind("127.0.0.1:53").is_err();
    if port_blocked {
        eprintln!("  Dnscache disabled. A reboot is required to free port 53.");
    } else {
        eprintln!("  Dnscache disabled. Port 53 is free.");
    }
    Ok(port_blocked)
}

#[cfg(windows)]
fn enable_dnscache() {
    let _ = std::process::Command::new("reg")
        .args([
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache",
            "/v",
            "Start",
            "/t",
            "REG_DWORD",
            "/d",
            "2",
            "/f",
        ])
        .status();
}

/// True if the backup map has at least one real upstream (non-loopback, non-stub).
#[cfg(any(windows, test))]
fn backup_has_real_upstream_windows(
    interfaces: &std::collections::HashMap<String, WindowsInterfaceDns>,
) -> bool {
    interfaces
        .values()
        .any(|iface| iface.servers.iter().any(|s| !is_loopback_or_stub(s)))
}

#[cfg(windows)]
fn install_windows() -> Result<(), String> {
    let mut interfaces = get_windows_interfaces()?;
    if interfaces.is_empty() {
        return Err("no active network interfaces found".to_string());
    }

    let path = windows_backup_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;
    }

    // Preserve an existing useful backup rather than overwriting it with
    // numa-managed state (which would be self-referential after uninstall).
    let existing: Option<std::collections::HashMap<String, WindowsInterfaceDns>> =
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok());
    let has_useful_existing = existing
        .as_ref()
        .map(backup_has_real_upstream_windows)
        .unwrap_or(false);

    if has_useful_existing {
        eprintln!("  Existing DNS backup preserved at {}", path.display());
    } else {
        // Filter loopback/stub addresses before saving so a fresh backup
        // captured from already-numa-managed state isn't self-referential.
        for iface in interfaces.values_mut() {
            iface.servers.retain(|s| !is_loopback_or_stub(s));
        }
        let json = serde_json::to_string_pretty(&interfaces)
            .map_err(|e| format!("failed to serialize backup: {}", e))?;
        std::fs::write(&path, json).map_err(|e| format!("failed to write backup: {}", e))?;
    }

    // On re-install, stop the running service first so the binary can be
    // overwritten and port 53 is released for the Dnscache probe.
    if is_service_registered() {
        eprintln!("  Stopping existing service...");
        stop_service_scm();
    }

    let needs_reboot = disable_dnscache()?;

    // Copy the binary to a stable path under ProgramData and register it
    // as a real Windows service (SCM-managed, boot-time, auto-restart).
    let service_exe = install_service_binary()?;
    register_service_scm(&service_exe)?;

    if needs_reboot {
        // Dnscache still holds port 53 until reboot. Do NOT redirect DNS
        // yet — nothing is listening on 127.0.0.1:53, so redirecting now
        // would kill DNS. The service will call redirect_dns_to_localhost()
        // on its first startup after reboot.
    } else {
        redirect_dns_with_interfaces(&interfaces)?;

        match start_service_scm() {
            Ok(_) => eprintln!("  Service started."),
            Err(e) => eprintln!(
                "  warning: service registered but could not start now: {}",
                e
            ),
        }
    }

    eprintln!();
    if !has_useful_existing {
        eprintln!("  Original DNS saved to {}", path.display());
    }
    eprintln!("  Run 'numa uninstall' to restore.\n");
    if needs_reboot {
        eprintln!("  *** Reboot required. Numa will start automatically. ***\n");
    } else {
        eprintln!("  Numa is running.\n");
    }
    print_recursive_hint();
    Ok(())
}

/// Stable install location for the service binary. SCM keeps a handle to
/// this path; the user's Downloads folder (where `current_exe()` points at
/// install time) is not durable.
#[cfg(windows)]
fn windows_service_exe_path() -> std::path::PathBuf {
    crate::data_dir().join("bin").join("numa.exe")
}

/// Run `sc.exe` with the given args and return its merged stdout/stderr on
/// failure. `sc` emits errors on stdout (not stderr) on Windows, so the
/// caller reads stdout to format a useful error.
#[cfg(windows)]
fn run_sc(args: &[&str]) -> Result<std::process::Output, String> {
    let out = std::process::Command::new("sc")
        .args(args)
        .output()
        .map_err(|e| format!("failed to run sc {}: {}", args.first().unwrap_or(&""), e))?;
    Ok(out)
}

/// Point all active network interfaces at 127.0.0.1 so Numa handles DNS.
/// Called from the service on first boot after a reboot that freed Dnscache.
#[cfg(windows)]
pub fn redirect_dns_to_localhost() -> Result<(), String> {
    let interfaces = get_windows_interfaces()?;
    redirect_dns_with_interfaces(&interfaces)
}

#[cfg(windows)]
fn run_netsh_ipv4(args: &[&str]) -> std::io::Result<std::process::ExitStatus> {
    std::process::Command::new("netsh")
        .arg("interface")
        .arg("ipv4")
        .args(args)
        .status()
}

#[cfg(windows)]
fn redirect_dns_with_interfaces(
    interfaces: &std::collections::HashMap<String, WindowsInterfaceDns>,
) -> Result<(), String> {
    for (name, iface) in interfaces {
        let idx = iface.if_index.to_string();
        let status = run_netsh_ipv4(&["set", "dnsservers", &idx, "static", "127.0.0.1", "primary"])
            .map_err(|e| format!("failed to set DNS for {}: {}", name, e))?;

        if status.success() {
            eprintln!("  set DNS for \"{}\" -> 127.0.0.1", name);
        } else {
            eprintln!(
                "  warning: failed to set DNS for \"{}\" (run as Administrator?)",
                name
            );
        }
    }
    Ok(())
}

/// Copy the currently-running binary to the service install location. SCM
/// keeps a handle to this path, so it must be stable across user sessions.
#[cfg(windows)]
fn install_service_binary() -> Result<std::path::PathBuf, String> {
    let src = std::env::current_exe().map_err(|e| format!("current_exe(): {}", e))?;
    let dst = windows_service_exe_path();
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;
    }
    // Copy only if source and destination differ; running the binary from
    // its install location is a supported (re-install) case.
    if src != dst {
        std::fs::copy(&src, &dst).map_err(|e| {
            format!(
                "failed to copy {} -> {}: {}",
                src.display(),
                dst.display(),
                e
            )
        })?;
    }
    Ok(dst)
}

/// Remove the service binary on uninstall. Ignore failures — the service
/// is already deleted; a leftover file in ProgramData is not a hard error.
#[cfg(windows)]
fn remove_service_binary() {
    let _ = std::fs::remove_file(windows_service_exe_path());
}

/// Register numa with the Service Control Manager, boot-time auto-start,
/// LocalSystem context, with a failure policy of restart-after-5s.
#[cfg(windows)]
fn register_service_scm(exe: &std::path::Path) -> Result<(), String> {
    let bin_path = format!("\"{}\" --service", exe.display());
    let name = crate::windows_service::SERVICE_NAME;

    // sc.exe uses a leading space as its `name= value` delimiter; the space
    // after `=` is mandatory.
    let create = run_sc(&[
        "create",
        name,
        "binPath=",
        &bin_path,
        "DisplayName=",
        "Numa DNS",
        "start=",
        "auto",
        "obj=",
        "LocalSystem",
    ])?;
    if !create.status.success() {
        let out = String::from_utf8_lossy(&create.stdout);
        // "service already exists" is 1073 — treat as idempotent success.
        if !out.contains("1073") {
            return Err(format!("sc create failed: {}", out.trim()));
        }
    }

    let _ = run_sc(&[
        "description",
        name,
        "Self-sovereign DNS resolver (ad blocking, DoH/DoT, local zones).",
    ]);

    // Restart on crash: 5s, 5s, 10s; reset failure counter after 60s.
    let _ = run_sc(&[
        "failure",
        name,
        "reset=",
        "60",
        "actions=",
        "restart/5000/restart/5000/restart/10000",
    ]);

    eprintln!("  Registered service '{}' (boot-time).", name);
    Ok(())
}

/// Start the service. Safe to call on a freshly-registered service — SCM
/// will fail with 1056 ("already running") or 1058 ("disabled") and we
/// return the underlying error string rather than masking it.
#[cfg(windows)]
fn start_service_scm() -> Result<(), String> {
    let out = run_sc(&["start", crate::windows_service::SERVICE_NAME])?;
    if !out.status.success() {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("1056") {
            return Ok(()); // already running
        }
        return Err(format!("sc start failed: {}", text.trim()));
    }
    Ok(())
}

/// Stop the service and wait for it to fully exit. Idempotent —
/// already-stopped or missing service is not an error.
#[cfg(windows)]
fn stop_service_scm() {
    let name = crate::windows_service::SERVICE_NAME;
    let _ = run_sc(&["stop", name]);
    // Wait up to 10s for the service to reach STOPPED state so the
    // binary file handle is released before we try to overwrite it.
    for _ in 0..20 {
        if let Ok(out) = run_sc(&["query", name]) {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains("STOPPED") || text.contains("1060") {
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    eprintln!("  warning: service did not stop within 10s");
}

/// Remove the service from SCM. Idempotent — see `stop_service_scm`.
#[cfg(windows)]
fn delete_service_scm() {
    if let Err(e) = run_sc(&["delete", crate::windows_service::SERVICE_NAME]) {
        log::warn!("sc delete failed: {}", e);
    }
}

/// Check whether the service is registered with SCM (regardless of state).
#[cfg(windows)]
fn is_service_registered() -> bool {
    run_sc(&["query", crate::windows_service::SERVICE_NAME])
        .map(|o| parse_sc_registered(o.status.success(), &String::from_utf8_lossy(&o.stdout)))
        .unwrap_or(false)
}

/// Parse `sc query` output to determine if a service is registered.
/// Extracted for testability — the actual `sc` call is in `is_service_registered`.
#[cfg(any(windows, test))]
fn parse_sc_registered(exit_success: bool, stdout: &str) -> bool {
    if exit_success {
        return true;
    }
    // Error 1060 = "The specified service does not exist as an installed service."
    !stdout.contains("1060")
}

/// Print service state from SCM.
#[cfg(windows)]
fn service_status_windows() -> Result<(), String> {
    let out = run_sc(&["query", crate::windows_service::SERVICE_NAME])?;
    let text = String::from_utf8_lossy(&out.stdout);
    let display = parse_sc_state(&text);
    eprintln!("  {}\n", display);
    Ok(())
}

/// Parse the STATE line from `sc query` output. Returns a human-readable
/// string like "STATE : 4 RUNNING" or "Service is not installed."
#[cfg(any(windows, test))]
fn parse_sc_state(sc_output: &str) -> String {
    if sc_output.contains("1060") {
        return "Service is not installed.".to_string();
    }
    sc_output
        .lines()
        .find(|l| l.contains("STATE"))
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(windows)]
fn uninstall_windows() -> Result<(), String> {
    // Stop + remove the service before touching DNS, so port 53 is released
    // cleanly and the failure-restart policy doesn't resurrect it.
    stop_service_scm();
    delete_service_scm();
    remove_service_binary();
    let path = windows_backup_path();
    let json = std::fs::read_to_string(&path)
        .map_err(|e| format!("no backup found at {}: {}", path.display(), e))?;
    let original: std::collections::HashMap<String, WindowsInterfaceDns> =
        serde_json::from_str(&json).map_err(|e| format!("invalid backup file: {}", e))?;

    let live = get_windows_interfaces()?;

    for (name, dns_info) in &original {
        let Some(idx) = live.get(name).map(|i| i.if_index.to_string()) else {
            eprintln!("  warning: adapter \"{}\" not currently up; skipped", name);
            continue;
        };

        let real_servers: Vec<&str> = dns_info
            .servers
            .iter()
            .map(String::as_str)
            .filter(|s| !is_loopback_or_stub(s))
            .collect();

        if real_servers.is_empty() {
            let status = run_netsh_ipv4(&["set", "dnsservers", &idx, "dhcp"])
                .map_err(|e| format!("failed to restore DNS for {}: {}", name, e))?;

            if status.success() {
                eprintln!("  restored DNS for \"{}\" -> DHCP", name);
            } else {
                eprintln!("  warning: failed to restore DNS for \"{}\"", name);
            }
        } else {
            let status = run_netsh_ipv4(&[
                "set",
                "dnsservers",
                &idx,
                "static",
                real_servers[0],
                "primary",
            ])
            .map_err(|e| format!("failed to restore DNS for {}: {}", name, e))?;

            if !status.success() {
                eprintln!("  warning: failed to restore primary DNS for \"{}\"", name);
                continue;
            }

            for (i, server) in real_servers.iter().skip(1).enumerate() {
                let _ = run_netsh_ipv4(&[
                    "add",
                    "dnsservers",
                    &idx,
                    server,
                    &format!("index={}", i + 2),
                ]);
            }

            eprintln!(
                "  restored DNS for \"{}\" -> {}",
                name,
                real_servers.join(", ")
            );
        }
    }

    std::fs::remove_file(&path).ok();

    // Re-enable Dnscache
    enable_dnscache();
    eprintln!("\n  System DNS restored. DNS Client re-enabled.");
    eprintln!("  Reboot to fully restore the DNS Client service.\n");
    Ok(())
}

/// Find the upstream for a domain by checking forwarding rules.
/// Returns None if no rule matches (use default upstream).
/// Zero-allocation on the hot path — dot_suffix is pre-computed.
pub fn match_forwarding_rule<'a>(
    domain: &str,
    rules: &'a [ForwardingRule],
) -> Option<&'a UpstreamPool> {
    for rule in rules {
        if domain == rule.suffix || domain.ends_with(&rule.dot_suffix) {
            return Some(&rule.upstream);
        }
    }
    None
}

// --- System DNS configuration (install/uninstall) ---

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

/// True if the backup map has at least one real upstream (non-loopback, non-stub).
/// An all-loopback backup is self-referential — restoring it is a no-op.
#[cfg(any(target_os = "macos", test))]
fn backup_has_real_upstream_macos(
    servers: &std::collections::HashMap<String, Vec<String>>,
) -> bool {
    servers
        .values()
        .any(|list| list.iter().any(|s| !is_loopback_or_stub(s)))
}

#[cfg(target_os = "macos")]
fn install_macos() -> Result<(), String> {
    use std::collections::HashMap;

    let services = get_network_services()?;
    let dir = numa_data_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("failed to create {}: {}", dir.display(), e))?;

    // If a useful backup already exists (at least one non-loopback upstream),
    // preserve it — overwriting would destroy the original DNS state when
    // re-installing on top of a numa-managed configuration.
    let existing_backup: Option<HashMap<String, Vec<String>>> =
        std::fs::read_to_string(backup_path())
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok());
    let has_useful_existing = existing_backup
        .as_ref()
        .map(backup_has_real_upstream_macos)
        .unwrap_or(false);

    if has_useful_existing {
        eprintln!(
            "  Existing DNS backup preserved at {}",
            backup_path().display()
        );
    } else {
        // Capture fresh, filtering out loopback and stub addresses so we
        // never record a self-referential backup.
        let mut original: HashMap<String, Vec<String>> = HashMap::new();
        for service in &services {
            let servers: Vec<String> = get_dns_servers(service)?
                .into_iter()
                .filter(|s| !is_loopback_or_stub(s))
                .collect();
            original.insert(service.clone(), servers);
        }

        let json = serde_json::to_string_pretty(&original)
            .map_err(|e| format!("failed to serialize backup: {}", e))?;
        std::fs::write(backup_path(), json)
            .map_err(|e| format!("failed to write backup: {}", e))?;
    }

    // Set DNS to 127.0.0.1 and add "numa" search domain for each service
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

        // Add "numa" as search domain so browsers resolve .numa without trailing slash
        let _ = std::process::Command::new("networksetup")
            .args(["-setsearchdomains", service, "numa"])
            .status();
    }

    eprintln!();
    if !has_useful_existing {
        eprintln!("  Original DNS saved to {}", backup_path().display());
    }
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

        // Clear the "numa" search domain
        let _ = std::process::Command::new("networksetup")
            .args(["-setsearchdomains", service, "Empty"])
            .status();
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
    let result = install_service_macos();
    #[cfg(target_os = "linux")]
    let result = install_service_linux();
    #[cfg(windows)]
    let result = install_windows();
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    let result = Err::<(), String>("service installation not supported on this OS".to_string());

    if result.is_ok() {
        if let Err(e) = trust_ca() {
            eprintln!("  warning: could not trust CA: {}", e);
            eprintln!("  HTTPS proxy will work but browsers will show certificate warnings.\n");
        }
    }
    result
}

/// Start the service. If already installed, just starts it via the platform
/// service manager. If not installed, falls through to a full install.
pub fn start_service() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        install_service()
    }
    #[cfg(target_os = "linux")]
    {
        install_service()
    }
    #[cfg(windows)]
    {
        if is_service_registered() {
            start_service_scm()?;
            eprintln!("  Service started.\n");
            Ok(())
        } else {
            install_service()
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Err("service start not supported on this OS".to_string())
    }
}

/// Stop the service without uninstalling it.
pub fn stop_service() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        uninstall_service()
    }
    #[cfg(target_os = "linux")]
    {
        uninstall_service()
    }
    #[cfg(windows)]
    {
        let out = run_sc(&["stop", crate::windows_service::SERVICE_NAME])?;
        if !out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            // 1062 = not started, 1060 = does not exist
            if !text.contains("1062") && !text.contains("1060") {
                return Err(format!("sc stop failed: {}", text.trim()));
            }
        }
        eprintln!("  Service stopped.\n");
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Err("service stop not supported on this OS".to_string())
    }
}

/// Uninstall the Numa system service.
pub fn uninstall_service() -> Result<(), String> {
    let _ = untrust_ca();

    #[cfg(target_os = "macos")]
    {
        uninstall_service_macos()
    }
    #[cfg(target_os = "linux")]
    {
        uninstall_service_linux()
    }
    #[cfg(windows)]
    {
        uninstall_windows()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Err("service uninstallation not supported on this OS".to_string())
    }
}

/// Restart the service (kill process, launchd/systemd auto-restarts with new binary).
pub fn restart_service() -> Result<(), String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let exe_path =
        std::env::current_exe().map_err(|e| format!("failed to get current exe: {}", e))?;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let version = {
        match std::process::Command::new(&exe_path)
            .arg("--version")
            .output()
        {
            Ok(o) => String::from_utf8_lossy(&o.stderr).trim().to_string(),
            Err(_) => "unknown".to_string(),
        }
    };

    #[cfg(target_os = "macos")]
    {
        let exe_path = exe_path.to_string_lossy();
        let output = std::process::Command::new("launchctl")
            .args(["list", PLIST_LABEL])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                eprintln!("  Tip: use 'make deploy' instead — handles codesign + restart.\n");
                // Codesign, then kill service. Launchd KeepAlive respawns it.
                // This will kill us too (we ARE /usr/local/bin/numa), so
                // codesign and print output first.
                let _ = std::process::Command::new("codesign")
                    .args(["-f", "-s", "-", &exe_path])
                    .output(); // use output() to suppress codesign stderr
                eprintln!("  Service restarting → {}\n", version);
                let _ = std::process::Command::new("pkill")
                    .args(["-f", &exe_path])
                    .status();
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
    #[cfg(windows)]
    {
        stop_service_scm();
        start_service_scm()?;
        eprintln!("  Service restarted.\n");
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
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
    #[cfg(windows)]
    {
        service_status_windows()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Err("service status not supported on this OS".to_string())
    }
}

#[cfg(target_os = "macos")]
fn replace_exe_path(service: &str) -> Result<String, String> {
    let exe_path =
        std::env::current_exe().map_err(|e| format!("failed to get current exe: {}", e))?;
    Ok(service.replace("{{exe_path}}", &exe_path.to_string_lossy()))
}

#[cfg(target_os = "macos")]
fn install_service_macos() -> Result<(), String> {
    // Create log directory
    std::fs::create_dir_all("/usr/local/var/log")
        .map_err(|e| format!("failed to create log dir: {}", e))?;

    // Write plist
    let plist = include_str!("../com.numa.dns.plist");
    let plist = replace_exe_path(plist)?;

    std::fs::write(PLIST_DEST, plist)
        .map_err(|e| format!("failed to write {}: {}", PLIST_DEST, e))?;

    // Modern launchctl API: explicitly tear down any existing in-memory
    // state, then bootstrap fresh from the on-disk plist. The deprecated
    // `load -w` returns exit 0 even when it cannot actually reload (label
    // already in launchd state), silently leaving the daemon running a
    // stale binary path after `numa install` rewrites the plist on disk —
    // which is exactly what `brew upgrade numa` does.
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", "system", PLIST_DEST])
        .status();

    let status = std::process::Command::new("launchctl")
        .args(["bootstrap", "system", PLIST_DEST])
        .status()
        .map_err(|e| format!("failed to run launchctl: {}", e))?;

    if !status.success() {
        return Err("launchctl bootstrap failed".to_string());
    }

    // Wait for numa to be ready before redirecting DNS
    let api_up = (0..10).any(|i| {
        if i > 0 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        std::net::TcpStream::connect(("127.0.0.1", crate::config::DEFAULT_API_PORT)).is_ok()
    });
    if !api_up {
        // Service failed to start — don't redirect DNS to a dead endpoint
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", "system", PLIST_DEST])
            .status();
        return Err(
            "numa service did not start (port 53 may be in use). Service unloaded.".to_string(),
        );
    }

    if let Err(e) = install_macos() {
        eprintln!("  warning: failed to configure system DNS: {}", e);
    }

    eprintln!("  Service installed and started.");
    eprintln!("  Numa will auto-start on boot and restart if killed.");
    eprintln!("  Logs: /usr/local/var/log/numa.log");
    eprintln!("  Run 'sudo numa uninstall' to restore original DNS.\n");
    print_recursive_hint();
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_service_macos() -> Result<(), String> {
    // Restore DNS first, while numa is still running to handle any final queries
    if let Err(e) = uninstall_macos() {
        eprintln!("  warning: failed to restore system DNS: {}", e);
    }

    // Bootout the service from launchd's in-memory state BEFORE removing
    // the plist. The modern API needs the file path as the specifier;
    // doing this in the wrong order would leave the service loaded in
    // memory until reboot. (Deprecated `unload -w` had the same issue.)
    let bootout_status = std::process::Command::new("launchctl")
        .args(["bootout", "system", PLIST_DEST])
        .status();
    if let Ok(s) = bootout_status {
        if !s.success() {
            eprintln!(
                "  warning: launchctl bootout returned non-zero (service may not have been loaded)"
            );
        }
    }

    // Remove plist so the service won't restart on boot
    if let Err(e) = std::fs::remove_file(PLIST_DEST) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(format!("failed to remove {}: {}", PLIST_DEST, e));
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
        std::fs::write(
            &drop_in,
            "[Resolve]\nDNS=127.0.0.1\nDomains=~. numa\nDNSStubListener=no\n",
        )
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

    // Back up current resolv.conf, but never overwrite a useful existing
    // backup with a numa-managed file — that would leave uninstall with
    // nothing to restore to.
    let current = std::fs::read_to_string(resolv).ok();
    let current_is_numa_managed = current
        .as_deref()
        .map(resolv_conf_is_numa_managed)
        .unwrap_or(false);
    let existing_backup_is_useful = std::fs::read_to_string(&backup)
        .ok()
        .as_deref()
        .map(resolv_conf_has_real_upstream)
        .unwrap_or(false);

    if existing_backup_is_useful {
        eprintln!(
            "  Existing resolv.conf backup preserved at {}",
            backup.display()
        );
    } else if current_is_numa_managed {
        eprintln!("  warning: /etc/resolv.conf is already numa-managed; no fresh backup written");
    } else if let Some(content) = current.as_deref() {
        std::fs::write(&backup, content)
            .map_err(|e| format!("failed to backup /etc/resolv.conf: {}", e))?;
        eprintln!("  Saved /etc/resolv.conf to {}", backup.display());
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
        "# Generated by Numa — run 'sudo numa uninstall' to restore\nnameserver 127.0.0.1\nsearch numa\n";
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

/// Fallback install location when current_exe() sits on a path the
/// dynamic user cannot traverse (e.g. `/home/<user>/` mode 0700).
#[cfg(target_os = "linux")]
fn linux_service_exe_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/usr/local/bin/numa")
}

/// True iff every ancestor of `p` (excluding `/`) grants world-execute —
/// i.e. the `DynamicUser=yes` service account can traverse the path and
/// exec the binary without being in any group. Linuxbrew's
/// `/home/linuxbrew` is 0755 (traversable, keep brew's path, upgrades
/// via `brew` propagate). A build tree under `/home/<user>/` (0700) or
/// `~/.cargo/bin/` is not (copy to /usr/local/bin so systemd can reach it).
#[cfg(target_os = "linux")]
fn path_world_traversable_linux(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let mut current = p;
    while let Some(parent) = current.parent() {
        if parent.as_os_str().is_empty() || parent == std::path::Path::new("/") {
            break;
        }
        match std::fs::metadata(parent) {
            Ok(m) if m.permissions().mode() & 0o001 != 0 => {}
            _ => return false,
        }
        current = parent;
    }
    true
}

#[cfg(target_os = "linux")]
fn install_service_binary_linux() -> Result<std::path::PathBuf, String> {
    let src = std::env::current_exe().map_err(|e| format!("current_exe(): {}", e))?;
    if path_world_traversable_linux(&src) {
        return Ok(src);
    }
    let dst = linux_service_exe_path();
    if src == dst {
        return Ok(dst);
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;
    }
    // Atomic replace via temp + rename. Plain copy fails with ETXTBSY when
    // re-installing while the service is running the previous binary —
    // rename swaps the path while the running process keeps the old inode.
    let tmp = dst.with_extension("new");
    std::fs::copy(&src, &tmp).map_err(|e| {
        format!(
            "failed to copy {} -> {}: {}",
            src.display(),
            tmp.display(),
            e
        )
    })?;
    std::fs::rename(&tmp, &dst).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!(
            "failed to rename {} -> {}: {}",
            tmp.display(),
            dst.display(),
            e
        )
    })?;
    Ok(dst)
}

#[cfg(target_os = "linux")]
fn install_service_linux() -> Result<(), String> {
    let exe = install_service_binary_linux()?;
    let unit = include_str!("../numa.service").replace("{{exe_path}}", &exe.to_string_lossy());
    std::fs::write(SYSTEMD_UNIT, unit)
        .map_err(|e| format!("failed to write {}: {}", SYSTEMD_UNIT, e))?;

    run_systemctl(&["daemon-reload"])?;
    run_systemctl(&["enable", "numa"])?;

    // Configure system DNS before starting numa so resolved releases port 53 first
    if let Err(e) = install_linux() {
        eprintln!("  warning: failed to configure system DNS: {}", e);
    }

    // restart, not start: on re-install the service is already running
    // the previous binary; restart picks up the new one.
    run_systemctl(&["restart", "numa"])?;

    eprintln!("  Service installed and started.");
    eprintln!("  Numa will auto-start on boot and restart if killed.");
    eprintln!("  Logs: journalctl -u numa -f");
    eprintln!("  Run 'sudo numa uninstall' to restore original DNS.\n");
    print_recursive_hint();
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

// --- CA trust management ---

/// One Linux trust-store backend (Debian, Fedora pki, Arch p11-kit).
#[cfg(target_os = "linux")]
struct LinuxTrustStore {
    name: &'static str,
    anchor_dir: &'static str,
    anchor_file: &'static str,
    refresh_install: &'static [&'static str],
    refresh_uninstall: &'static [&'static str],
}

// If you change this table, update tests/docker/install-trust.sh to match —
// it asserts the same paths/commands against real distro images.
#[cfg(target_os = "linux")]
const LINUX_TRUST_STORES: &[LinuxTrustStore] = &[
    // Debian / Ubuntu / Mint
    LinuxTrustStore {
        name: "debian",
        anchor_dir: "/usr/local/share/ca-certificates",
        anchor_file: "numa-local-ca.crt",
        refresh_install: &["update-ca-certificates"],
        refresh_uninstall: &["update-ca-certificates", "--fresh"],
    },
    // Fedora / RHEL / CentOS / SUSE (p11-kit via update-ca-trust wrapper)
    LinuxTrustStore {
        name: "pki",
        anchor_dir: "/etc/pki/ca-trust/source/anchors",
        anchor_file: "numa-local-ca.pem",
        refresh_install: &["update-ca-trust", "extract"],
        refresh_uninstall: &["update-ca-trust", "extract"],
    },
    // Arch / Manjaro (raw p11-kit)
    LinuxTrustStore {
        name: "p11kit",
        anchor_dir: "/etc/ca-certificates/trust-source/anchors",
        anchor_file: "numa-local-ca.pem",
        refresh_install: &["trust", "extract-compat"],
        refresh_uninstall: &["trust", "extract-compat"],
    },
];

#[cfg(target_os = "linux")]
fn detect_linux_trust_store() -> Option<&'static LinuxTrustStore> {
    LINUX_TRUST_STORES
        .iter()
        .find(|s| std::path::Path::new(s.anchor_dir).is_dir())
}

fn trust_ca() -> Result<(), String> {
    let ca_path = crate::data_dir().join(crate::tls::CA_FILE_NAME);
    if !ca_path.exists() {
        return Err("CA not generated yet — start numa first to create certificates".into());
    }

    #[cfg(target_os = "macos")]
    let result = trust_ca_macos(&ca_path);
    #[cfg(target_os = "linux")]
    let result = trust_ca_linux(&ca_path);
    #[cfg(windows)]
    let result = trust_ca_windows(&ca_path);
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    let result = Err::<(), String>("CA trust not supported on this OS".to_string());

    result
}

fn untrust_ca() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let result = untrust_ca_macos();
    #[cfg(target_os = "linux")]
    let result = untrust_ca_linux();
    #[cfg(windows)]
    let result = untrust_ca_windows();
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    let result = Ok::<(), String>(());

    result
}

#[cfg(target_os = "macos")]
fn trust_ca_macos(ca_path: &std::path::Path) -> Result<(), String> {
    let status = std::process::Command::new("security")
        .args([
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
        ])
        .arg(ca_path)
        .status()
        .map_err(|e| format!("security: {}", e))?;
    if !status.success() {
        return Err("security add-trusted-cert failed".into());
    }
    eprintln!("  Trusted Numa CA in system keychain");
    Ok(())
}

#[cfg(target_os = "macos")]
fn untrust_ca_macos() -> Result<(), String> {
    if let Ok(out) = std::process::Command::new("security")
        .args([
            "find-certificate",
            "-c",
            crate::tls::CA_COMMON_NAME,
            "-a",
            "-Z",
            "/Library/Keychains/System.keychain",
        ])
        .output()
    {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if let Some(hash) = line.strip_prefix("SHA-1 hash: ") {
                let hash = hash.trim();
                let _ = std::process::Command::new("security")
                    .args([
                        "delete-certificate",
                        "-Z",
                        hash,
                        "/Library/Keychains/System.keychain",
                    ])
                    .output();
            }
        }
    }
    eprintln!("  Removed Numa CA from system keychain");
    Ok(())
}

#[cfg(target_os = "linux")]
fn trust_ca_linux(ca_path: &std::path::Path) -> Result<(), String> {
    let store = detect_linux_trust_store().ok_or_else(|| {
        let names: Vec<&str> = LINUX_TRUST_STORES.iter().map(|s| s.name).collect();
        format!(
            "no supported CA trust store found (tried: {}). \
             Please report at https://github.com/razvandimescu/numa/issues",
            names.join(", ")
        )
    })?;

    let dest = std::path::Path::new(store.anchor_dir).join(store.anchor_file);
    std::fs::copy(ca_path, &dest).map_err(|e| format!("copy CA to {}: {}", dest.display(), e))?;

    run_refresh(store.name, store.refresh_install)?;
    eprintln!("  Trusted Numa CA system-wide ({})", store.name);
    Ok(())
}

#[cfg(target_os = "linux")]
fn untrust_ca_linux() -> Result<(), String> {
    let Some(store) = detect_linux_trust_store() else {
        return Ok(());
    };

    let dest = std::path::Path::new(store.anchor_dir).join(store.anchor_file);
    match std::fs::remove_file(&dest) {
        Ok(()) => {
            let _ = run_refresh(store.name, store.refresh_uninstall);
            eprintln!("  Removed Numa CA from system trust store ({})", store.name);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {} // best-effort uninstall
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_refresh(store_name: &str, argv: &[&str]) -> Result<(), String> {
    let (cmd, args) = argv
        .split_first()
        .expect("refresh command must be non-empty");
    let status = std::process::Command::new(cmd)
        .args(args)
        .status()
        .map_err(|e| format!("{} ({}): {}", cmd, store_name, e))?;
    if !status.success() {
        return Err(format!("{} ({}) failed", cmd, store_name));
    }
    Ok(())
}

#[cfg(windows)]
fn trust_ca_windows(ca_path: &std::path::Path) -> Result<(), String> {
    let status = std::process::Command::new("certutil")
        .args(["-addstore", "-f", "Root"])
        .arg(ca_path)
        .status()
        .map_err(|e| format!("certutil: {}", e))?;
    if !status.success() {
        return Err("certutil -addstore Root failed (run as Administrator?)".into());
    }
    eprintln!("  Trusted Numa CA in Windows Root store");
    Ok(())
}

#[cfg(windows)]
fn untrust_ca_windows() -> Result<(), String> {
    let _ = std::process::Command::new("certutil")
        .args(["-delstore", "Root", crate::tls::CA_COMMON_NAME])
        .status();
    eprintln!("  Removed Numa CA from Windows Root store");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_powershell_servers() {
        // Shape emitted by ENUMERATE_INTERFACES_PS — adapter name keys, each
        // value carries the live ifIndex and a merged IPv4+IPv6 server list.
        // Legacy `dhcp` field (in pre-fix backups on disk) is silently
        // ignored on read.
        let sample = r#"{"Ethernet":{"if_index":12,"servers":["8.8.8.8","8.8.4.4"]},"Wi-Fi":{"dhcp":true,"if_index":7,"servers":["1.1.1.1"]}}"#;
        let result = parse_powershell_interfaces(sample).expect("parse failed");
        assert_eq!(result.len(), 2);
        assert_eq!(
            result["Ethernet"],
            WindowsInterfaceDns {
                if_index: 12,
                servers: vec!["8.8.8.8".into(), "8.8.4.4".into()],
            }
        );
        assert_eq!(
            result["Wi-Fi"],
            WindowsInterfaceDns {
                if_index: 7,
                servers: vec!["1.1.1.1".into()],
            }
        );
    }

    #[test]
    fn parse_powershell_legacy_backup_without_if_index() {
        let sample = r#"{"Ethernet":{"servers":["8.8.8.8"]}}"#;
        let result = parse_powershell_interfaces(sample).expect("parse failed");
        assert_eq!(result["Ethernet"].if_index, 0);
        assert_eq!(result["Ethernet"].servers, vec!["8.8.8.8".to_string()]);
    }

    #[test]
    fn parse_powershell_empty_when_no_adapters_up() {
        // Get-NetAdapter | Where Status=Up returns nothing → empty hashtable
        // → ConvertTo-Json emits "{}". Must produce an empty map, not error,
        // so install_windows() can surface the right "no active interfaces"
        // message instead of a JSON parse failure.
        assert!(parse_powershell_interfaces("{}").unwrap().is_empty());
        assert!(parse_powershell_interfaces("").unwrap().is_empty());
        assert!(parse_powershell_interfaces("   \n").unwrap().is_empty());
    }

    #[test]
    fn parse_powershell_rejects_garbage() {
        assert!(parse_powershell_interfaces("not json").is_err());
    }

    #[test]
    fn parse_powershell_rejects_null_server_entry() {
        // Locks in the PS-side null filter (Where-Object { $_ }) — a real
        // install on a dual-stack adapter without IPv6 DNS used to emit
        // `["10.0.0.1", null]`, failing deserialize at install time.
        let sample = r#"{"Wi-Fi":{"servers":["1.1.1.1",null]}}"#;
        assert!(parse_powershell_interfaces(sample).is_err());
    }

    #[test]
    fn install_templates_contain_exe_path_placeholder() {
        // Both files are substituted at install time — plist via
        // replace_exe_path on macOS, numa.service via inline .replace
        // in install_service_linux. Catch placeholder removal early.
        let plist = include_str!("../com.numa.dns.plist");
        let unit = include_str!("../numa.service");
        assert!(plist.contains("{{exe_path}}"), "plist missing placeholder");
        assert!(
            unit.contains("{{exe_path}}"),
            "unit file missing placeholder"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn replace_exe_path_substitutes_template() {
        let plist = include_str!("../com.numa.dns.plist");
        let result = replace_exe_path(plist).expect("replace_exe_path failed for plist");
        assert!(!result.contains("{{exe_path}}"));
    }

    #[test]
    fn macos_backup_real_upstream_detection() {
        use std::collections::HashMap;
        let mut map: HashMap<String, Vec<String>> = HashMap::new();

        // Empty backup → no real upstream
        assert!(!backup_has_real_upstream_macos(&map));

        // All-loopback backup → still no real upstream (the bug case)
        map.insert("Wi-Fi".into(), vec!["127.0.0.1".into()]);
        map.insert("Ethernet".into(), vec!["::1".into()]);
        assert!(!backup_has_real_upstream_macos(&map));

        // One real entry → useful
        map.insert("Tailscale".into(), vec!["192.168.1.1".into()]);
        assert!(backup_has_real_upstream_macos(&map));
    }

    #[test]
    fn windows_backup_filters_loopback() {
        use std::collections::HashMap;
        let mut map: HashMap<String, WindowsInterfaceDns> = HashMap::new();

        // Empty backup → no real upstream
        assert!(!backup_has_real_upstream_windows(&map));

        // All-loopback backup → still no real upstream (the bug case)
        map.insert(
            "Wi-Fi".into(),
            WindowsInterfaceDns {
                servers: vec!["127.0.0.1".into()],
                if_index: 0,
            },
        );
        map.insert(
            "Ethernet".into(),
            WindowsInterfaceDns {
                servers: vec!["::1".into(), "0.0.0.0".into()],
                if_index: 0,
            },
        );
        assert!(!backup_has_real_upstream_windows(&map));

        // fec0:0:0:ffff::1/2/3 leak into every VPN/virtual adapter via
        // Get-DnsClientServerAddress.
        map.insert(
            "Tailscale".into(),
            WindowsInterfaceDns {
                servers: vec![
                    "fec0:0:0:ffff::1".into(),
                    "fec0:0:0:ffff::2".into(),
                    "fec0:0:0:ffff::3".into(),
                ],
                if_index: 0,
            },
        );
        assert!(!backup_has_real_upstream_windows(&map));

        // One real entry alongside loopback → useful
        map.insert(
            "Ethernet 2".into(),
            WindowsInterfaceDns {
                servers: vec!["192.168.1.1".into()],
                if_index: 0,
            },
        );
        assert!(backup_has_real_upstream_windows(&map));
    }

    #[test]
    fn resolv_conf_real_upstream_detection() {
        let real = "nameserver 192.168.1.1\nsearch lan\n";
        assert!(resolv_conf_has_real_upstream(real));
        assert!(!resolv_conf_is_numa_managed(real));

        let self_ref = "nameserver 127.0.0.1\nsearch numa\n";
        assert!(!resolv_conf_has_real_upstream(self_ref));
        assert!(resolv_conf_is_numa_managed(self_ref));

        let numa_marker =
            "# Generated by Numa — run 'sudo numa uninstall' to restore\nnameserver 127.0.0.1\nsearch numa\n";
        assert!(resolv_conf_is_numa_managed(numa_marker));

        let systemd_stub = "nameserver 127.0.0.53\noptions edns0\n";
        assert!(!resolv_conf_has_real_upstream(systemd_stub));

        let mixed = "nameserver 127.0.0.1\nnameserver 1.1.1.1\n";
        assert!(resolv_conf_has_real_upstream(mixed));
        assert!(!resolv_conf_is_numa_managed(mixed));
    }

    #[test]
    fn try_port53_advisory_addr_in_use() {
        let err = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        let msg = try_port53_advisory("0.0.0.0:53", &err).expect("should advise on port 53");
        assert!(msg.contains("cannot bind to"));
        assert!(msg.contains("already in use"));
        assert!(msg.contains("numa install"));
        assert!(msg.contains("bind_addr"));
    }

    #[test]
    fn try_port53_advisory_permission_denied() {
        let err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let msg = try_port53_advisory("0.0.0.0:53", &err).expect("should advise on port 53");
        assert!(msg.contains("cannot bind to"));
        assert!(msg.contains("permission denied"));
        assert!(msg.contains("numa install"));
        assert!(msg.contains("bind_addr"));
    }

    #[test]
    fn try_port53_advisory_skips_non_53_ports() {
        let err = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        assert!(try_port53_advisory("127.0.0.1:5354", &err).is_none());
        assert!(try_port53_advisory("[::]:853", &err).is_none());
    }

    #[test]
    fn try_port53_advisory_skips_unrelated_error_kinds() {
        let err = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(try_port53_advisory("0.0.0.0:53", &err).is_none());
    }

    #[test]
    fn try_port53_advisory_skips_malformed_bind_addr() {
        let err = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        assert!(try_port53_advisory("not-an-address", &err).is_none());
    }

    #[test]
    fn sc_query_running_service_is_registered() {
        assert!(parse_sc_registered(true, ""));
    }

    #[test]
    fn sc_query_stopped_service_is_registered() {
        let output = "SERVICE_NAME: Numa\n        TYPE: 10  WIN32_OWN\n        STATE: 1  STOPPED\n";
        assert!(parse_sc_registered(true, output));
    }

    #[test]
    fn sc_query_missing_service_not_registered() {
        let output = "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\n\nThe specified service does not exist as an installed service.\n";
        assert!(!parse_sc_registered(false, output));
    }

    #[test]
    fn sc_query_other_error_assumes_registered() {
        // Permission denied or other errors — don't assume unregistered.
        let output = "[SC] OpenService FAILED 5:\n\nAccess is denied.\n";
        assert!(parse_sc_registered(false, output));
    }

    #[test]
    fn parse_sc_state_running() {
        let output = "SERVICE_NAME: Numa\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n        WIN32_EXIT_CODE    : 0\n";
        assert!(parse_sc_state(output).contains("RUNNING"));
    }

    #[test]
    fn parse_sc_state_stopped() {
        let output = "SERVICE_NAME: Numa\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 1  STOPPED\n";
        assert!(parse_sc_state(output).contains("STOPPED"));
    }

    #[test]
    fn parse_sc_state_not_installed() {
        let output = "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\n\n";
        assert_eq!(parse_sc_state(output), "Service is not installed.");
    }

    #[test]
    fn parse_sc_state_empty_output() {
        assert_eq!(parse_sc_state(""), "unknown");
    }

    #[cfg(windows)]
    #[test]
    fn windows_config_dir_equals_data_dir() {
        assert_eq!(crate::config_dir(), crate::data_dir());
    }
}
