use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use log::{error, info};
use tokio::net::UdpSocket;

use numa::blocklist::{download_blocklists, parse_blocklist, BlocklistStore};
use numa::buffer::BytePacketBuffer;
use numa::cache::DnsCache;
use numa::config::{build_zone_map, load_config, ConfigLoad};
use numa::ctx::{handle_query, ServerCtx};
use numa::forward::{parse_upstream, Upstream, UpstreamPool};
use numa::override_store::OverrideStore;
use numa::query_log::QueryLog;
use numa::service_store::ServiceStore;
use numa::stats::ServerStats;
use numa::system_dns::{
    discover_system_dns, install_service, restart_service, service_status, uninstall_service,
};

const QUAD9_IP: &str = "9.9.9.9";
const DOH_FALLBACK: &str = "https://9.9.9.9/dns-query";

#[tokio::main]
async fn main() -> numa::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    // Handle CLI subcommands
    let arg1 = std::env::args().nth(1).unwrap_or_default();
    match arg1.as_str() {
        "install" => {
            eprintln!("\x1b[1;38;2;192;98;58mNuma\x1b[0m — installing\n");
            return install_service().map_err(|e| e.into());
        }
        "uninstall" => {
            eprintln!("\x1b[1;38;2;192;98;58mNuma\x1b[0m — uninstalling\n");
            return uninstall_service().map_err(|e| e.into());
        }
        "service" => {
            let sub = std::env::args().nth(2).unwrap_or_default();
            eprintln!("\x1b[1;38;2;192;98;58mNuma\x1b[0m — service management\n");
            return match sub.as_str() {
                "start" => install_service().map_err(|e| e.into()),
                "stop" => uninstall_service().map_err(|e| e.into()),
                "restart" => restart_service().map_err(|e| e.into()),
                "status" => service_status().map_err(|e| e.into()),
                _ => {
                    eprintln!("Usage: numa service <start|stop|restart|status>");
                    Ok(())
                }
            };
        }
        "setup-phone" => {
            return numa::setup_phone::run().await.map_err(|e| e.into());
        }
        "lan" => {
            let sub = std::env::args().nth(2).unwrap_or_default();
            let config_path = std::env::args()
                .nth(3)
                .unwrap_or_else(|| "numa.toml".to_string());
            return match sub.as_str() {
                "on" => set_lan_enabled(true, &config_path),
                "off" => set_lan_enabled(false, &config_path),
                _ => {
                    eprintln!("Usage: numa lan <on|off> [config-path]");
                    Ok(())
                }
            };
        }
        "version" | "--version" | "-V" => {
            eprintln!("numa {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        "help" | "--help" | "-h" => {
            eprintln!("Usage: numa [command] [config-path]");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  (none)          Start the DNS server (default)");
            eprintln!("  install         Set system DNS to 127.0.0.1 (requires sudo)");
            eprintln!("  uninstall       Restore original system DNS settings");
            eprintln!("  service start   Install as system service (auto-start on boot)");
            eprintln!("  service stop    Uninstall the system service");
            eprintln!("  service restart Restart the service with updated binary");
            eprintln!("  service status  Check if the service is running");
            eprintln!("  lan on          Enable LAN service discovery (mDNS)");
            eprintln!("  lan off         Disable LAN service discovery");
            eprintln!("  setup-phone     Generate a QR code to install Numa DoT on a phone");
            eprintln!("  help            Show this help");
            eprintln!();
            eprintln!("Config path defaults to numa.toml");
            return Ok(());
        }
        _ => {
            if !arg1.is_empty()
                && arg1 != "run"
                && !arg1.contains('/')
                && !arg1.contains('\\')
                && !arg1.ends_with(".toml")
            {
                eprintln!(
                    "\x1b[1;38;2;192;98;58mNuma\x1b[0m — unknown command: \x1b[1m{}\x1b[0m\n",
                    arg1
                );
                eprintln!("Run \x1b[1mnuma help\x1b[0m for a list of commands.");
                std::process::exit(1);
            }
        }
    }

    let config_path = if arg1.is_empty() || arg1 == "run" {
        std::env::args()
            .nth(2)
            .unwrap_or_else(|| "numa.toml".to_string())
    } else {
        arg1 // treat as config path for backwards compatibility
    };
    let ConfigLoad {
        config,
        path: resolved_config_path,
        found: config_found,
    } = load_config(&config_path)?;

    // Discover system DNS in a single pass (upstream + forwarding rules)
    let system_dns = discover_system_dns();

    let root_hints = numa::recursive::parse_root_hints(&config.upstream.root_hints);

    let recursive_pool = || {
        let dummy = UpstreamPool::new(vec![Upstream::Udp("0.0.0.0:0".parse().unwrap())], vec![]);
        (dummy, "recursive (root hints)".to_string())
    };

    let (resolved_mode, upstream_auto, pool, upstream_label) = match config.upstream.mode {
        numa::config::UpstreamMode::Auto => {
            info!("auto mode: probing recursive resolution...");
            if numa::recursive::probe_recursive(&root_hints).await {
                info!("recursive probe succeeded — self-sovereign mode");
                let (pool, label) = recursive_pool();
                (numa::config::UpstreamMode::Recursive, false, pool, label)
            } else {
                log::warn!("recursive probe failed — falling back to Quad9 DoH");
                let client = reqwest::Client::builder()
                    .use_rustls_tls()
                    .build()
                    .unwrap_or_default();
                let url = DOH_FALLBACK.to_string();
                let label = url.clone();
                let pool = UpstreamPool::new(vec![Upstream::Doh { url, client }], vec![]);
                (numa::config::UpstreamMode::Forward, false, pool, label)
            }
        }
        numa::config::UpstreamMode::Recursive => {
            let (pool, label) = recursive_pool();
            (numa::config::UpstreamMode::Recursive, false, pool, label)
        }
        numa::config::UpstreamMode::Forward => {
            let addrs = if config.upstream.address.is_empty() {
                let detected = system_dns
                    .default_upstream
                    .or_else(numa::system_dns::detect_dhcp_dns)
                    .unwrap_or_else(|| {
                        info!("could not detect system DNS, falling back to Quad9 DoH");
                        DOH_FALLBACK.to_string()
                    });
                vec![detected]
            } else {
                config.upstream.address.clone()
            };

            let primary: Vec<Upstream> = addrs
                .iter()
                .map(|s| parse_upstream(s, config.upstream.port))
                .collect::<numa::Result<Vec<_>>>()?;
            let fallback: Vec<Upstream> = config
                .upstream
                .fallback
                .iter()
                .map(|s| parse_upstream(s, config.upstream.port))
                .collect::<numa::Result<Vec<_>>>()?;

            let pool = UpstreamPool::new(primary, fallback);
            let label = pool.label();
            (
                numa::config::UpstreamMode::Forward,
                config.upstream.address.is_empty(),
                pool,
                label,
            )
        }
    };
    let api_port = config.server.api_port;

    let mut blocklist = BlocklistStore::new();
    for domain in &config.blocking.allowlist {
        blocklist.add_to_allowlist(domain);
    }
    if !config.blocking.enabled {
        blocklist.set_enabled(false);
    }

    // Build service store: config services + persisted user services
    let mut service_store = ServiceStore::new();
    service_store.insert_from_config("numa", config.server.api_port, Vec::new());
    for svc in &config.services {
        service_store.insert_from_config(&svc.name, svc.target_port, svc.routes.clone());
    }
    service_store.load_persisted();

    for fwd in &config.forwarding {
        for suffix in &fwd.suffix {
            info!("forwarding .{} to {} (config rule)", suffix, fwd.upstream);
        }
    }
    let forwarding_rules =
        numa::config::merge_forwarding_rules(&config.forwarding, system_dns.forwarding_rules)?;

    // Resolve data_dir from config, falling back to the platform default.
    // Used for TLS CA storage below and stored on ServerCtx for runtime use.
    let resolved_data_dir = config
        .server
        .data_dir
        .clone()
        .unwrap_or_else(numa::data_dir);

    // Build initial TLS config before ServerCtx (so ArcSwap is ready at construction)
    let initial_tls = if config.proxy.enabled && config.proxy.tls_port > 0 {
        let service_names = service_store.names();
        match numa::tls::build_tls_config(
            &config.proxy.tld,
            &service_names,
            Vec::new(),
            &resolved_data_dir,
        ) {
            Ok(tls_config) => Some(ArcSwap::from(tls_config)),
            Err(e) => {
                if let Some(advisory) = numa::tls::try_data_dir_advisory(&e, &resolved_data_dir) {
                    eprint!("{}", advisory);
                } else {
                    log::warn!("TLS setup failed, HTTPS proxy disabled: {}", e);
                }
                None
            }
        }
    } else {
        None
    };

    let doh_enabled = initial_tls.is_some();
    let health_meta = numa::health::HealthMeta::build(
        &resolved_data_dir,
        config.dot.enabled,
        config.dot.port,
        config.mobile.port,
        config.dnssec.enabled,
        resolved_mode == numa::config::UpstreamMode::Recursive,
        config.lan.enabled,
        config.blocking.enabled,
        doh_enabled,
    );

    let ca_pem = std::fs::read_to_string(resolved_data_dir.join("ca.pem")).ok();

    let socket = match UdpSocket::bind(&config.server.bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            if let Some(advisory) =
                numa::system_dns::try_port53_advisory(&config.server.bind_addr, &e)
            {
                eprint!("{}", advisory);
                std::process::exit(1);
            }
            return Err(e.into());
        }
    };

    let ctx = Arc::new(ServerCtx {
        socket,
        zone_map: build_zone_map(&config.zones)?,
        cache: RwLock::new(DnsCache::new(
            config.cache.max_entries,
            config.cache.min_ttl,
            config.cache.max_ttl,
        )),
        stats: Mutex::new(ServerStats::new()),
        overrides: RwLock::new(OverrideStore::new()),
        blocklist: RwLock::new(blocklist),
        query_log: Mutex::new(QueryLog::new(1000)),
        services: Mutex::new(service_store),
        lan_peers: Mutex::new(numa::lan::PeerStore::new(config.lan.peer_timeout_secs)),
        forwarding_rules,
        upstream_pool: Mutex::new(pool),
        upstream_auto,
        upstream_port: config.upstream.port,
        lan_ip: Mutex::new(numa::lan::detect_lan_ip().unwrap_or(std::net::Ipv4Addr::LOCALHOST)),
        timeout: Duration::from_millis(config.upstream.timeout_ms),
        hedge_delay: Duration::from_millis(config.upstream.hedge_ms),
        proxy_tld_suffix: if config.proxy.tld.is_empty() {
            String::new()
        } else {
            format!(".{}", config.proxy.tld)
        },
        proxy_tld: config.proxy.tld.clone(),
        lan_enabled: config.lan.enabled,
        config_path: resolved_config_path,
        config_found,
        config_dir: numa::config_dir(),
        data_dir: resolved_data_dir,
        tls_config: initial_tls,
        upstream_mode: resolved_mode,
        root_hints,
        srtt: std::sync::RwLock::new(numa::srtt::SrttCache::new(config.upstream.srtt)),
        inflight: std::sync::Mutex::new(std::collections::HashMap::new()),
        dnssec_enabled: config.dnssec.enabled,
        dnssec_strict: config.dnssec.strict,
        health_meta,
        ca_pem,
        mobile_enabled: config.mobile.enabled,
        mobile_port: config.mobile.port,
    });

    let zone_count: usize = ctx.zone_map.values().map(|m| m.len()).sum();
    // Build banner rows, then size the box to fit the longest value
    let api_url = format!("http://localhost:{}", api_port);
    let proxy_label = if config.proxy.enabled {
        if config.proxy.tls_port > 0 {
            Some(format!(
                "http://:{} https://:{}",
                config.proxy.port, config.proxy.tls_port
            ))
        } else {
            Some(format!(
                "http://*.{} on :{}",
                config.proxy.tld, config.proxy.port
            ))
        }
    } else {
        None
    };
    let config_label = if ctx.config_found {
        ctx.config_path.clone()
    } else {
        format!("{} (defaults)", ctx.config_path)
    };
    let data_label = ctx.data_dir.display().to_string();
    let services_label = ctx.config_dir.join("services.json").display().to_string();

    // label (10) + value + padding (2) = inner width; minimum 40 for the title row
    let val_w = [
        config.server.bind_addr.len(),
        api_url.len(),
        upstream_label.len(),
        config_label.len(),
        data_label.len(),
        services_label.len(),
    ]
    .into_iter()
    .chain(proxy_label.as_ref().map(|s| s.len()))
    .max()
    .unwrap_or(30);
    let w = (val_w + 12).max(42); // 10 label + 2 padding, min 42 for title

    let o = "\x1b[38;2;192;98;58m"; // orange
    let g = "\x1b[38;2;107;124;78m"; // green
    let d = "\x1b[38;2;163;152;136m"; // dim
    let r = "\x1b[0m"; // reset
    let b = "\x1b[1;38;2;192;98;58m"; // bold orange
    let it = "\x1b[3;38;2;163;152;136m"; // italic dim

    let bar_top = "═".repeat(w);
    let bar_mid = "─".repeat(w);
    let row = |label: &str, color: &str, value: &str| {
        eprintln!(
            "{o}  ║{r}  {color}{:<9}{r} {:<vw$}{o}║{r}",
            label,
            value,
            vw = w - 12
        );
    };

    // Title row: center within the box
    let title = format!(
        "{b}NUMA{r}  {it}DNS that governs itself{r}  {d}v{}{r}",
        env!("CARGO_PKG_VERSION")
    );
    // The title contains ANSI codes; visible length is ~38 chars. Pad to fill the box.
    let title_visible_len = 4 + 2 + 24 + 2 + 1 + env!("CARGO_PKG_VERSION").len() + 1;
    let title_pad = w.saturating_sub(title_visible_len);
    eprintln!("\n{o}  ╔{bar_top}╗{r}");
    eprint!("{o}  ║{r} {title}");
    eprintln!("{}{o}║{r}", " ".repeat(title_pad));
    eprintln!("{o}  ╠{bar_top}╣{r}");
    row("DNS", g, &config.server.bind_addr);
    row("API", g, &api_url);
    row("Dashboard", g, &api_url);
    row(
        "Upstream",
        g,
        if ctx.upstream_mode == numa::config::UpstreamMode::Recursive {
            "recursive (root hints)"
        } else {
            &upstream_label
        },
    );
    row("Zones", g, &format!("{} records", zone_count));
    row(
        "Cache",
        g,
        &format!("max {} entries", config.cache.max_entries),
    );
    if !config.cache.warm.is_empty() {
        row("Warm", g, &format!("{} domains", config.cache.warm.len()));
    }
    row(
        "Blocking",
        g,
        &if config.blocking.enabled {
            format!("{} lists", config.blocking.lists.len())
        } else {
            "disabled".to_string()
        },
    );
    if let Some(ref label) = proxy_label {
        row("Proxy", g, label);
        if config.proxy.bind_addr == "127.0.0.1" {
            let y = "\x1b[38;2;204;176;59m"; // yellow
            row(
                "",
                y,
                &format!(
                    "⚠ proxy on 127.0.0.1 — .{} not LAN reachable",
                    config.proxy.tld
                ),
            );
        }
    }
    if config.dot.enabled {
        row("DoT", g, &format!("tls://:{}", config.dot.port));
    }
    if doh_enabled {
        row(
            "DoH",
            g,
            &format!("https://:{}/dns-query", config.proxy.tls_port),
        );
    }
    if config.lan.enabled {
        row("LAN", g, "mDNS (_numa._tcp.local)");
    }
    if !ctx.forwarding_rules.is_empty() {
        row(
            "Routing",
            g,
            &format!("{} conditional rules", ctx.forwarding_rules.len()),
        );
    }
    eprintln!("{o}  ╠{bar_mid}╣{r}");
    row("Config", d, &config_label);
    row("Data", d, &data_label);
    row("Services", d, &services_label);
    eprintln!("{o}  ╚{bar_top}╝{r}\n");

    info!(
        "numa listening on {}, upstream {}, {} zone records, cache max {}, API on port {}",
        config.server.bind_addr, upstream_label, zone_count, config.cache.max_entries, api_port,
    );

    // Download blocklists on startup
    let blocklist_lists = config.blocking.lists.clone();
    let refresh_hours = config.blocking.refresh_hours;
    if config.blocking.enabled && !blocklist_lists.is_empty() {
        let bl_ctx = Arc::clone(&ctx);
        let bl_lists = blocklist_lists.clone();
        tokio::spawn(async move {
            load_blocklists(&bl_ctx, &bl_lists).await;

            // Periodic refresh
            let mut interval = tokio::time::interval(Duration::from_secs(refresh_hours * 3600));
            interval.tick().await; // skip immediate tick
            loop {
                interval.tick().await;
                info!("refreshing blocklists...");
                load_blocklists(&bl_ctx, &bl_lists).await;
            }
        });
    }

    // Prime TLD cache (recursive mode only)
    if ctx.upstream_mode == numa::config::UpstreamMode::Recursive {
        let prime_ctx = Arc::clone(&ctx);
        let prime_tlds = config.upstream.prime_tlds;
        tokio::spawn(async move {
            numa::recursive::prime_tld_cache(
                &prime_ctx.cache,
                &prime_ctx.root_hints,
                &prime_tlds,
                &prime_ctx.srtt,
            )
            .await;
        });
    }

    // Spawn cache warming for user-configured domains
    if !config.cache.warm.is_empty() {
        let warm_ctx = Arc::clone(&ctx);
        let warm_domains = config.cache.warm.clone();
        tokio::spawn(async move {
            cache_warm_loop(warm_ctx, warm_domains).await;
        });
    }

    // Spawn DoH connection keepalive — prevents idle TLS teardown
    {
        let keepalive_ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            doh_keepalive_loop(keepalive_ctx).await;
        });
    }

    // Spawn HTTP API server
    let api_ctx = Arc::clone(&ctx);
    let api_addr: SocketAddr = format!("{}:{}", config.server.api_bind_addr, api_port).parse()?;
    tokio::spawn(async move {
        let app = numa::api::router(api_ctx);
        let listener = tokio::net::TcpListener::bind(api_addr).await.unwrap();
        info!("HTTP API listening on {}", api_addr);
        axum::serve(listener, app).await.unwrap();
    });

    // Spawn Mobile API listener (read-only subset for iOS/Android companion
    // apps, LAN-bound by default so phones can reach it). Only idempotent
    // GETs; no state-mutating routes are exposed here regardless of
    // the main API's bind address.
    if config.mobile.enabled {
        let mobile_ctx = Arc::clone(&ctx);
        let mobile_bind = config.mobile.bind_addr.clone();
        let mobile_port = config.mobile.port;
        tokio::spawn(async move {
            if let Err(e) = numa::mobile_api::start(mobile_ctx, mobile_bind, mobile_port).await {
                log::warn!("Mobile API listener failed: {}", e);
            }
        });
    }

    let proxy_bind: std::net::Ipv4Addr = config
        .proxy
        .bind_addr
        .parse()
        .unwrap_or(std::net::Ipv4Addr::LOCALHOST);

    // Spawn HTTP reverse proxy for .numa domains
    if config.proxy.enabled {
        let proxy_ctx = Arc::clone(&ctx);
        let proxy_port = config.proxy.port;
        tokio::spawn(async move {
            numa::proxy::start_proxy(proxy_ctx, proxy_port, proxy_bind).await;
        });
    }

    // Spawn HTTPS reverse proxy with TLS termination
    if config.proxy.enabled && config.proxy.tls_port > 0 && ctx.tls_config.is_some() {
        let proxy_ctx = Arc::clone(&ctx);
        let tls_port = config.proxy.tls_port;
        tokio::spawn(async move {
            numa::proxy::start_proxy_tls(proxy_ctx, tls_port, proxy_bind).await;
        });
    }

    // Spawn network change watcher (upstream re-detection, LAN IP update, peer flush)
    {
        let watch_ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            network_watch_loop(watch_ctx).await;
        });
    }

    // Spawn LAN service discovery
    if config.lan.enabled {
        let lan_ctx = Arc::clone(&ctx);
        let lan_config = config.lan.clone();
        tokio::spawn(async move {
            numa::lan::start_lan_discovery(lan_ctx, &lan_config).await;
        });
    }

    // Spawn DNS-over-TLS listener (RFC 7858)
    if config.dot.enabled {
        let dot_ctx = Arc::clone(&ctx);
        let dot_config = config.dot.clone();
        tokio::spawn(async move {
            numa::dot::start_dot(dot_ctx, &dot_config).await;
        });
    }

    // UDP DNS listener
    #[allow(clippy::infinite_loop)]
    loop {
        let mut buffer = BytePacketBuffer::new();
        let (len, src_addr) = match ctx.socket.recv_from(&mut buffer.buf).await {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                // Windows delivers ICMP port-unreachable as ConnectionReset on UDP sockets
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = handle_query(buffer, len, src_addr, &ctx).await {
                error!("{} | HANDLER ERROR | {}", src_addr, e);
            }
        });
    }
}

async fn network_watch_loop(ctx: Arc<numa::ctx::ServerCtx>) {
    let mut tick: u64 = 0;

    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.tick().await; // skip immediate tick

    loop {
        interval.tick().await;
        tick += 1;
        let mut changed = false;

        // Check LAN IP change (every 5s — cheap, one UDP socket call)
        if let Some(new_ip) = numa::lan::detect_lan_ip() {
            let mut current_ip = ctx.lan_ip.lock().unwrap();
            if new_ip != *current_ip {
                info!("LAN IP changed: {} → {}", current_ip, new_ip);
                *current_ip = new_ip;
                changed = true;
                numa::recursive::reset_udp_state();
            }
        }

        // Re-detect upstream every 30s or on LAN IP change (auto-detect only)
        if ctx.upstream_auto && (changed || tick.is_multiple_of(6)) {
            let dns_info = numa::system_dns::discover_system_dns();
            let new_addr = dns_info
                .default_upstream
                .or_else(numa::system_dns::detect_dhcp_dns)
                .unwrap_or_else(|| QUAD9_IP.to_string());
            let mut pool = ctx.upstream_pool.lock().unwrap();
            if pool.maybe_update_primary(&new_addr, ctx.upstream_port) {
                info!("upstream changed → {}", pool.label());
                changed = true;
            }
        }

        // Flush stale LAN peers on any network change
        if changed {
            ctx.lan_peers.lock().unwrap().clear();
            info!("flushed LAN peers after network change");
        }

        // Re-probe UDP every 5 minutes when disabled
        if tick.is_multiple_of(60) {
            numa::recursive::probe_udp(&ctx.root_hints).await;
        }
    }
}

fn set_lan_enabled(enabled: bool, path: &str) -> numa::Result<()> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::write(path, format!("[lan]\nenabled = {}\n", enabled))?;
            print_lan_status(enabled);
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    // Track current TOML section while scanning lines
    let mut in_lan = false;
    let mut found = false;
    let mut lines: Vec<String> = contents
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_lan = trimmed == "[lan]";
            }
            if in_lan && !found {
                if let Some((key, _)) = trimmed.split_once('=') {
                    if key.trim() == "enabled" {
                        found = true;
                        let indent = &line[..line.len() - trimmed.len()];
                        return format!("{}enabled = {}", indent, enabled);
                    }
                }
            }
            line.to_string()
        })
        .collect();

    if !found {
        if let Some(i) = lines.iter().position(|l| l.trim() == "[lan]") {
            lines.insert(i + 1, format!("enabled = {}", enabled));
        } else {
            lines.push(String::new());
            lines.push("[lan]".to_string());
            lines.push(format!("enabled = {}", enabled));
        }
    }

    let mut result = lines.join("\n");
    if !result.ends_with('\n') {
        result.push('\n');
    }
    std::fs::write(path, result)?;
    print_lan_status(enabled);
    Ok(())
}

fn print_lan_status(enabled: bool) {
    let label = if enabled { "enabled" } else { "disabled" };
    let color = if enabled { "32" } else { "33" };
    eprintln!(
        "\x1b[1;38;2;192;98;58mNuma\x1b[0m — LAN discovery \x1b[{}m{}\x1b[0m",
        color, label
    );
    if enabled {
        eprintln!("  Restart Numa to start mDNS discovery");
    }
}

async fn load_blocklists(ctx: &ServerCtx, lists: &[String]) {
    let downloaded = download_blocklists(lists).await;

    // Parse outside the lock to avoid blocking DNS queries during parse (~100ms)
    let mut all_domains = std::collections::HashSet::new();
    let mut sources = Vec::new();
    for (source, text) in &downloaded {
        let domains = parse_blocklist(text);
        info!("blocklist: {} domains from {}", domains.len(), source);
        all_domains.extend(domains);
        sources.push(source.clone());
    }
    let total = all_domains.len();

    // Swap under lock — sub-microsecond
    ctx.blocklist
        .write()
        .unwrap()
        .swap_domains(all_domains, sources);
    info!(
        "blocking enabled: {} unique domains from {} lists",
        total,
        downloaded.len()
    );
}

async fn warm_domain(ctx: &ServerCtx, domain: &str) {
    use numa::question::QueryType;

    for qtype in [QueryType::A, QueryType::AAAA] {
        if ctx.upstream_mode == numa::config::UpstreamMode::Recursive {
            let query = numa::packet::DnsPacket::query(0, domain, qtype);
            match numa::recursive::resolve_recursive(
                domain,
                qtype,
                &ctx.cache,
                &query,
                &ctx.root_hints,
                &ctx.srtt,
            )
            .await
            {
                Ok(resp) => {
                    ctx.cache.write().unwrap().insert(domain, qtype, &resp);
                    log::debug!("cache warm: {} {:?}", domain, qtype);
                }
                Err(e) => log::warn!("cache warm: {} {:?} failed: {}", domain, qtype, e),
            }
        } else {
            let query = numa::packet::DnsPacket::query(0, domain, qtype);
            let mut buf = numa::buffer::BytePacketBuffer::new();
            if query.write(&mut buf).is_err() {
                continue;
            }
            let pool = ctx.upstream_pool.lock().unwrap().clone();
            match numa::forward::forward_with_failover_raw(
                buf.filled(),
                &pool,
                &ctx.srtt,
                ctx.timeout,
                ctx.hedge_delay,
            )
            .await
            {
                Ok(wire) => {
                    ctx.cache.write().unwrap().insert_wire(
                        domain,
                        qtype,
                        &wire,
                        numa::cache::DnssecStatus::Indeterminate,
                    );
                    log::debug!("cache warm: {} {:?}", domain, qtype);
                }
                Err(e) => log::warn!("cache warm: {} {:?} failed: {}", domain, qtype, e),
            }
        }
    }
}

async fn doh_keepalive_loop(ctx: Arc<ServerCtx>) {
    let mut interval = tokio::time::interval(Duration::from_secs(25));
    interval.tick().await; // skip first immediate tick
    loop {
        interval.tick().await;
        let pool = ctx.upstream_pool.lock().unwrap().clone();
        if let Some(upstream) = pool.preferred() {
            numa::forward::keepalive_doh(upstream).await;
        }
    }
}

async fn cache_warm_loop(ctx: Arc<ServerCtx>, domains: Vec<String>) {
    tokio::time::sleep(Duration::from_secs(2)).await;

    for domain in &domains {
        warm_domain(&ctx, domain).await;
    }
    info!("cache warm: {} domains resolved at startup", domains.len());

    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.tick().await;
    loop {
        interval.tick().await;
        for domain in &domains {
            let refresh = ctx.cache.read().unwrap().needs_warm(domain);
            if refresh {
                warm_domain(&ctx, domain).await;
            }
        }
    }
}
