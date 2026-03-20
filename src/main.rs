use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use log::{error, info};
use tokio::net::UdpSocket;

use numa::blocklist::{download_blocklists, parse_blocklist, BlocklistStore};
use numa::buffer::BytePacketBuffer;
use numa::cache::DnsCache;
use numa::config::{build_zone_map, load_config};
use numa::ctx::{handle_query, ServerCtx};
use numa::override_store::OverrideStore;
use numa::query_log::QueryLog;
use numa::service_store::ServiceStore;
use numa::stats::ServerStats;
use numa::system_dns::{
    discover_system_dns, install_service, install_system_dns, restart_service, service_status,
    uninstall_service, uninstall_system_dns,
};

#[tokio::main]
async fn main() -> numa::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    // Handle CLI subcommands
    let arg1 = std::env::args().nth(1).unwrap_or_default();
    match arg1.as_str() {
        "install" => {
            eprintln!("\x1b[1;38;2;192;98;58mNuma\x1b[0m — configuring system DNS\n");
            return install_system_dns().map_err(|e| e.into());
        }
        "uninstall" => {
            eprintln!("\x1b[1;38;2;192;98;58mNuma\x1b[0m — restoring system DNS\n");
            return uninstall_system_dns().map_err(|e| e.into());
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
            eprintln!("  help            Show this help");
            eprintln!();
            eprintln!("Config path defaults to numa.toml");
            return Ok(());
        }
        _ => {}
    }

    let config_path = if arg1.is_empty() || arg1 == "run" {
        std::env::args()
            .nth(2)
            .unwrap_or_else(|| "numa.toml".to_string())
    } else {
        arg1 // treat as config path for backwards compatibility
    };
    let config = load_config(&config_path)?;

    // Discover system DNS in a single pass (upstream + forwarding rules)
    let system_dns = discover_system_dns();

    let upstream_addr = if config.upstream.address.is_empty() {
        system_dns.default_upstream.unwrap_or_else(|| {
            info!("could not detect system DNS, falling back to 9.9.9.9 (Quad9)");
            "9.9.9.9".to_string()
        })
    } else {
        config.upstream.address.clone()
    };
    let upstream: SocketAddr = format!("{}:{}", upstream_addr, config.upstream.port).parse()?;
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
    service_store.insert_from_config("numa", config.server.api_port);
    for svc in &config.services {
        service_store.insert_from_config(&svc.name, svc.target_port);
    }
    service_store.load_persisted();

    let forwarding_rules = system_dns.forwarding_rules;

    let ctx = Arc::new(ServerCtx {
        socket: UdpSocket::bind(&config.server.bind_addr).await?,
        zone_map: build_zone_map(&config.zones)?,
        cache: Mutex::new(DnsCache::new(
            config.cache.max_entries,
            config.cache.min_ttl,
            config.cache.max_ttl,
        )),
        stats: Mutex::new(ServerStats::new()),
        overrides: Mutex::new(OverrideStore::new()),
        blocklist: Mutex::new(blocklist),
        query_log: Mutex::new(QueryLog::new(1000)),
        services: Mutex::new(service_store),
        forwarding_rules,
        upstream,
        timeout: Duration::from_millis(config.upstream.timeout_ms),
        proxy_tld_suffix: if config.proxy.tld.is_empty() {
            String::new()
        } else {
            format!(".{}", config.proxy.tld)
        },
        proxy_tld: config.proxy.tld.clone(),
    });

    let zone_count: usize = ctx.zone_map.values().map(|m| m.len()).sum();
    eprintln!("\n\x1b[38;2;192;98;58m  ╔══════════════════════════════════════════╗\x1b[0m");
    eprintln!("\x1b[38;2;192;98;58m  ║\x1b[0m  \x1b[1;38;2;192;98;58mNUMA\x1b[0m  \x1b[3;38;2;163;152;136mDNS that governs itself\x1b[0m  \x1b[38;2;163;152;136mv{}\x1b[0m \x1b[38;2;192;98;58m║\x1b[0m", env!("CARGO_PKG_VERSION"));
    eprintln!("\x1b[38;2;192;98;58m  ╠══════════════════════════════════════════╣\x1b[0m");
    eprintln!("\x1b[38;2;192;98;58m  ║\x1b[0m  \x1b[38;2;107;124;78mDNS\x1b[0m       {:<30}\x1b[38;2;192;98;58m║\x1b[0m", config.server.bind_addr);
    eprintln!("\x1b[38;2;192;98;58m  ║\x1b[0m  \x1b[38;2;107;124;78mAPI\x1b[0m       http://localhost:{:<16}\x1b[38;2;192;98;58m║\x1b[0m", api_port);
    eprintln!("\x1b[38;2;192;98;58m  ║\x1b[0m  \x1b[38;2;107;124;78mDashboard\x1b[0m http://localhost:{:<16}\x1b[38;2;192;98;58m║\x1b[0m", api_port);
    eprintln!("\x1b[38;2;192;98;58m  ║\x1b[0m  \x1b[38;2;107;124;78mUpstream\x1b[0m  {:<30}\x1b[38;2;192;98;58m║\x1b[0m", upstream);
    eprintln!("\x1b[38;2;192;98;58m  ║\x1b[0m  \x1b[38;2;107;124;78mZones\x1b[0m     {:<30}\x1b[38;2;192;98;58m║\x1b[0m", format!("{} records", zone_count));
    eprintln!("\x1b[38;2;192;98;58m  ║\x1b[0m  \x1b[38;2;107;124;78mCache\x1b[0m     {:<30}\x1b[38;2;192;98;58m║\x1b[0m", format!("max {} entries", config.cache.max_entries));
    eprintln!("\x1b[38;2;192;98;58m  ║\x1b[0m  \x1b[38;2;107;124;78mBlocking\x1b[0m  {:<30}\x1b[38;2;192;98;58m║\x1b[0m",
        if config.blocking.enabled { format!("{} lists", config.blocking.lists.len()) } else { "disabled".to_string() });
    if config.proxy.enabled {
        let schemes = if config.proxy.tls_port > 0 {
            format!(
                "http://:{} https://:{}",
                config.proxy.port, config.proxy.tls_port
            )
        } else {
            format!("http://*.{} on :{}", config.proxy.tld, config.proxy.port)
        };
        eprintln!("\x1b[38;2;192;98;58m  ║\x1b[0m  \x1b[38;2;107;124;78mProxy\x1b[0m     {:<30}\x1b[38;2;192;98;58m║\x1b[0m", schemes);
    }
    if !ctx.forwarding_rules.is_empty() {
        eprintln!("\x1b[38;2;192;98;58m  ║\x1b[0m  \x1b[38;2;107;124;78mRouting\x1b[0m   {:<30}\x1b[38;2;192;98;58m║\x1b[0m",
            format!("{} conditional rules", ctx.forwarding_rules.len()));
    }
    eprintln!("\x1b[38;2;192;98;58m  ╚══════════════════════════════════════════╝\x1b[0m\n");

    info!(
        "numa listening on {}, upstream {}, {} zone records, cache max {}, API on port {}",
        config.server.bind_addr, upstream, zone_count, config.cache.max_entries, api_port,
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

    // Spawn HTTP API server
    let api_ctx = Arc::clone(&ctx);
    let api_addr: SocketAddr = format!("0.0.0.0:{}", api_port).parse()?;
    tokio::spawn(async move {
        let app = numa::api::router(api_ctx);
        let listener = tokio::net::TcpListener::bind(api_addr).await.unwrap();
        info!("HTTP API listening on {}", api_addr);
        axum::serve(listener, app).await.unwrap();
    });

    // Spawn HTTP reverse proxy for .numa domains
    if config.proxy.enabled {
        let proxy_ctx = Arc::clone(&ctx);
        let proxy_port = config.proxy.port;
        tokio::spawn(async move {
            numa::proxy::start_proxy(proxy_ctx, proxy_port).await;
        });
    }

    // Spawn HTTPS reverse proxy with TLS termination
    if config.proxy.enabled && config.proxy.tls_port > 0 {
        let service_names: Vec<String> = ctx
            .services
            .lock()
            .unwrap()
            .list()
            .iter()
            .map(|e| e.name.clone())
            .collect();
        match numa::tls::build_tls_config(&config.proxy.tld, &service_names) {
            Ok(tls_config) => {
                let proxy_ctx = Arc::clone(&ctx);
                let tls_port = config.proxy.tls_port;
                tokio::spawn(async move {
                    numa::proxy::start_proxy_tls(proxy_ctx, tls_port, tls_config).await;
                });
            }
            Err(e) => {
                log::warn!("TLS setup failed, HTTPS proxy disabled: {}", e);
            }
        }
    }

    // UDP DNS listener
    #[allow(clippy::infinite_loop)]
    loop {
        let mut buffer = BytePacketBuffer::new();
        let (_, src_addr) = ctx.socket.recv_from(&mut buffer.buf).await?;

        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = handle_query(buffer, src_addr, &ctx).await {
                error!("{} | HANDLER ERROR | {}", src_addr, e);
            }
        });
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
        .lock()
        .unwrap()
        .swap_domains(all_domains, sources);
    info!(
        "blocking enabled: {} unique domains from {} lists",
        total,
        downloaded.len()
    );
}
