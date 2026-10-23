//! The main DNS-server runtime.
//!
//! Extracted from `main.rs` so both the interactive CLI entry and the
//! Windows service dispatcher (`windows_service` module) can drive the
//! same startup/serve loop.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use log::{debug, error, info, warn};

use crate::blocklist::{
    download_blocklists, parse_blocklist_counted, source_defect, BlocklistStore, SourceKind,
    SourceResult,
};
use crate::blocklist_cache::BlocklistCache;
use crate::bootstrap_resolver::NumaResolver;
use crate::buffer::BytePacketBuffer;
use crate::cache::DnsCache;
use crate::config::{build_zone_map, ConfigLoad};
use crate::ctx::{handle_query, ServerCtx};
use crate::forward::{
    build_https_client_with_resolver, parse_upstream_list, Upstream, UpstreamPool,
};
use crate::odoh::OdohConfigCache;
use crate::override_store::OverrideStore;
use crate::query_log::QueryLog;
use crate::service_store::ServiceStore;
use crate::stats::{ServerStats, Transport};
use crate::system_dns::discover_system_dns;
use crate::udp_listener::UdpListener;

// Two operators, so one leaving a jurisdiction can't strand numa. DoH carries
// no SRTT, so failover keeps this order and Cloudflare only sees Quad9 misses.
const DOH_FALLBACK: [&str; 2] = ["https://9.9.9.9/dns-query", "https://1.1.1.1/dns-query"];
const BLOCKLIST_RETRY_SECS: u64 = 3600;

fn doh_fallback(client: reqwest::Client) -> Vec<Upstream> {
    DOH_FALLBACK
        .iter()
        .map(|url| Upstream::Doh {
            url: url.to_string(),
            client: client.clone(),
        })
        .collect()
}

/// Boot the DNS server and run until the UDP listener errors out.
pub async fn run(load: ConfigLoad) -> crate::Result<()> {
    let ConfigLoad {
        config,
        path: resolved_config_path,
        found: config_found,
    } = load;

    // Discover system DNS in a single pass (upstream + forwarding rules)
    let system_dns = discover_system_dns();

    let root_hints = crate::recursive::parse_root_hints(&config.upstream.root_hints);

    // Routes numa-originated HTTPS (DoH upstream, ODoH relay/target, blocklist
    // CDN) away from the system resolver so lookups don't loop back through
    // numa when it's its own system DNS.
    let resolver_overrides = match config.upstream.mode {
        crate::config::UpstreamMode::Odoh => config
            .upstream
            .odoh_upstream()
            .map(|o| o.host_ip_overrides())
            .unwrap_or_default(),
        _ => std::collections::BTreeMap::new(),
    };
    let bootstrap_resolver: Arc<NumaResolver> = Arc::new(NumaResolver::new(
        &config.upstream.fallback,
        resolver_overrides,
    ));

    let (resolved_mode, upstream_auto, pool, upstream_label) =
        resolve_upstream_pool(&config, &system_dns, &root_hints, &bootstrap_resolver).await?;
    let dnssec_enabled = effective_dnssec(&config, resolved_mode);
    let api_port = config.server.api_port;

    let (allow_sources, allow_domains) = config.blocking.split_allowlist();
    let mut blocklist = BlocklistStore::new(
        crate::domain_list::PersistedDomainList::new("blocking-allow.json", &allow_domains),
        crate::domain_list::PersistedDomainList::new("blocking-block.json", &[]),
    );
    // Seeded before the first fetch so the dashboard can tell a source that has
    // not loaded yet from one that is not configured at all. Seeded even when
    // blocking is off, or a disabled box reports its configured lists as though
    // it had none; `health` reports the switch separately.
    blocklist.set_sources(&config.blocking.lists);
    blocklist.set_allow_sources(&allow_sources);
    if !config.blocking.enabled {
        blocklist.set_enabled(false);
    }

    // Build service store: config services + persisted user services
    let mut service_store = ServiceStore::new();
    service_store.insert_from_config("numa", config.server.api_port, None, Vec::new());
    for svc in &config.services {
        service_store.insert_from_config(
            &svc.name,
            svc.target_port,
            svc.target_host.clone(),
            svc.routes.clone(),
        );
    }
    service_store.load_persisted();

    for fwd in &config.forwarding {
        for suffix in &fwd.suffix {
            info!(
                "forwarding .{} to {} (config rule)",
                suffix,
                fwd.upstream.join(", ")
            );
        }
    }
    let forwarding_rules =
        crate::config::merge_forwarding_rules(&config.forwarding, system_dns.forwarding_rules)?;

    // Resolve data_dir from config, falling back to the platform default.
    // Used for TLS CA storage below and stored on ServerCtx for runtime use.
    let resolved_data_dir = config
        .server
        .data_dir
        .as_deref()
        .map(|dir| std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf()))
        .unwrap_or_else(crate::data_dir);

    let (initial_tls, tls_byo) =
        crate::tls::build_proxy_tls(&config, &service_store, &resolved_data_dir);

    let doh_enabled = initial_tls.is_some();
    let health_meta = crate::health::HealthMeta::build(
        &resolved_data_dir,
        config.dot.enabled,
        config.dot.port,
        config.mobile.port,
        dnssec_enabled,
        resolved_mode == crate::config::UpstreamMode::Recursive,
        config.lan.enabled,
        config.blocking.enabled,
        doh_enabled,
        &config.server.bind_addr,
    );

    let ca_pem = std::fs::read_to_string(resolved_data_dir.join("ca.pem")).ok();

    let allow_from = crate::acl::AllowFromAcl::from_entries(&config.server.allow_from)
        .map_err(|e| format!("invalid [server].allow_from: {e}"))?;
    if allow_from.is_enabled() {
        info!(
            "client-IP allow_from enabled with {} entries (loopback always allowed)",
            config.server.allow_from.len()
        );
    }

    let client_policy = crate::client_policy::ClientPolicySet::from_configs(&config.client_policy)
        .map_err(|e| format!("invalid [[client_policy]]: {e}"))?;
    if client_policy.is_enabled() {
        info!(
            "per-client policies enabled: {} rule(s) (loopback always passthrough)",
            client_policy.rule_count()
        );
    }

    let rebind_allow = crate::domain_list::PersistedDomainList::new(
        "rebind-allow.json",
        &config.server.rebind_allowlist,
    );
    if config.server.rebind_protect {
        info!(
            "DNS rebinding protection enabled ({} allowlist entries)",
            rebind_allow.len()
        );
    }
    let rebind = crate::rebind::RebindFilter::new(
        config.server.rebind_protect,
        rebind_allow,
        &config.server.rebind_private_ranges,
    )
    .map_err(|e| format!("invalid [server] rebind config: {e}"))?;

    let sockets = bind_udp_listeners(&config.server.bind_addr).await?;

    let ctx = Arc::new(ServerCtx {
        zone_map: build_zone_map(&config.zones)?,
        cache: RwLock::new(DnsCache::new(
            config.cache.max_entries,
            config.cache.min_ttl,
            config.cache.max_ttl,
        )),
        refreshing: Mutex::new(std::collections::HashSet::new()),
        stats: Mutex::new(ServerStats::new()),
        overrides: RwLock::new(OverrideStore::new()),
        blocklist: RwLock::new(blocklist),
        query_log: Mutex::new(QueryLog::new(1000)),
        services: Mutex::new(service_store),
        lan_peers: Mutex::new(crate::lan::PeerStore::new(config.lan.peer_timeout_secs)),
        forwarding_rules,
        upstream_pool: Mutex::new(pool),
        upstream_auto,
        upstream_port: config.upstream.port,
        lan_ip: Mutex::new(crate::lan::detect_lan_ip().unwrap_or(std::net::Ipv4Addr::LOCALHOST)),
        timeout: Duration::from_millis(config.upstream.timeout_ms),
        hedge_delay: resolved_mode.hedge_delay(config.upstream.hedge_ms),
        proxy_tld_suffix: if config.proxy.tld.is_empty() {
            String::new()
        } else {
            format!(".{}", config.proxy.tld)
        },
        proxy_tld: config.proxy.tld.clone(),
        proxy_authoritative: config.proxy.authoritative,
        lan_enabled: config.lan.enabled,
        config_path: resolved_config_path,
        config_found,
        config_dir: crate::config_dir(),
        data_dir: resolved_data_dir,
        tls_config: initial_tls,
        tls_byo,
        upstream_mode: resolved_mode,
        root_hints,
        srtt: std::sync::RwLock::new(crate::srtt::SrttCache::new(config.upstream.srtt)),
        inflight: std::sync::Mutex::new(std::collections::HashMap::new()),
        admission: crate::admission::ResolutionAdmission::new(
            config.server.max_concurrent_resolutions,
        ),
        dnssec_enabled,
        dnssec_strict: config.dnssec.strict,
        health_meta,
        ca_pem,
        mobile_enabled: config.mobile.enabled,
        mobile_port: config.mobile.port,
        filter_aaaa: config.server.filter_aaaa,
        allow_from,
        client_policy,
        rebind: RwLock::new(rebind),
    });

    let zone_count: usize = ctx.zone_map.len();
    let api_url = format!("http://localhost:{}", api_port);
    print_banner(
        &config,
        &ctx,
        &api_url,
        &upstream_label,
        zone_count,
        doh_enabled,
    );

    info!(
        "numa listening on {}, upstream {}, {} zone records, cache max {}, API on port {}",
        config.server.bind_addr.join(", "),
        upstream_label,
        zone_count,
        config.cache.max_entries,
        api_port,
    );

    spawn_background_services(&ctx, &config, &bootstrap_resolver, api_port)?;

    // UDP DNS listener — shares `[server.proxy_protocol]` with TCP, which
    // already logged any parse error. Silently disable on Err.
    let udp_pp = crate::pp2::PpConfig::from_config(&config.server.proxy_protocol)
        .ok()
        .flatten();

    let mut handles = Vec::with_capacity(sockets.len());
    for socket in sockets {
        let ctx = Arc::clone(&ctx);
        let pp = udp_pp.clone();
        handles.push(tokio::spawn(async move {
            udp_serve_loop(&ctx, socket, pp.as_ref()).await
        }));
    }
    tokio::select! {
        (first, _, _) = futures::future::select_all(handles) => first?,
        () = crate::shutdown::signal() => {
            info!("shutting down");
            Ok(())
        }
    }
}

/// First port-53 bind failure routes through `try_port53_advisory` so the
/// "another resolver owns :53" UX still fires; any other bind error is fatal.
async fn bind_udp_listeners(addrs: &[String]) -> crate::Result<Vec<Arc<UdpListener>>> {
    if addrs.is_empty() {
        return Err("server.bind_addr is empty — set at least one address".into());
    }
    let mut sockets = Vec::with_capacity(addrs.len());
    for addr in addrs {
        let listener = match UdpListener::bind(addr).await {
            Ok(s) => s,
            Err(e) => {
                if let Some(advisory) = crate::system_dns::try_port53_advisory(addr, &e) {
                    eprint!("{}", advisory);
                    std::process::exit(1);
                }
                return Err(e.into());
            }
        };
        sockets.push(Arc::new(listener));
    }
    Ok(sockets)
}

fn spawn_background_services(
    ctx: &Arc<ServerCtx>,
    config: &crate::config::Config,
    bootstrap_resolver: &Arc<NumaResolver>,
    api_port: u16,
) -> crate::Result<()> {
    let blocklist_lists = config.blocking.lists.clone();
    let (allow_lists, _) = config.blocking.split_allowlist();
    let refresh_hours = config.blocking.refresh_hours;
    if config.blocking.enabled && !blocklist_lists.is_empty() {
        let bl_ctx = Arc::clone(ctx);
        let bl_resolver = bootstrap_resolver.clone();
        tokio::spawn(async move {
            loop {
                let loaded = load_blocklists_purging(
                    &bl_ctx,
                    &blocklist_lists,
                    &allow_lists,
                    Some(bl_resolver.clone()),
                )
                .await;
                // A refresh that left us with nothing is not blocking at all, so
                // waiting the full cycle to try again turns a brief upstream
                // outage into a day without blocking (issue #336). The config
                // rejects refresh_hours = 0, so the retry is never the longer wait.
                let wait = if loaded {
                    refresh_hours * 3600
                } else {
                    BLOCKLIST_RETRY_SECS
                };
                tokio::time::sleep(Duration::from_secs(wait)).await;
                info!("refreshing blocklists...");
            }
        });
    }

    if ctx.upstream_mode == crate::config::UpstreamMode::Recursive {
        let prime_ctx = Arc::clone(ctx);
        let prime_tlds = config.upstream.prime_tlds.clone();
        tokio::spawn(async move {
            crate::recursive::prime_tld_cache(
                &prime_ctx.cache,
                &prime_ctx.root_hints,
                &prime_tlds,
                &prime_ctx.srtt,
            )
            .await;
        });
    }

    if !config.cache.warm.is_empty() {
        let warm_ctx = Arc::clone(ctx);
        let warm_domains = config.cache.warm.clone();
        tokio::spawn(async move {
            cache_warm_loop(warm_ctx, warm_domains).await;
        });
    }

    {
        let keepalive_ctx = Arc::clone(ctx);
        tokio::spawn(async move {
            doh_keepalive_loop(keepalive_ctx).await;
        });
    }

    let api_ctx = Arc::clone(ctx);
    let api_addr: SocketAddr = format!("{}:{}", config.server.api_bind_addr, api_port).parse()?;
    let (api_auth, minted) =
        crate::api_auth::ensure_token(config.server.api_token.as_deref(), &ctx.data_dir);
    let api_auth = api_auth.with_proxy_tld_suffix(&ctx.proxy_tld_suffix);
    if let Some(m) = minted {
        info!(
            "generated an API token for the HTTP control plane: {}",
            m.token
        );
        match m.stored {
            Some(path) => info!("API token stored at {}", path.display()),
            None => warn!(
                "could not persist the API token under {} — it will change on restart; \
                 set [server] api_token or NUMA_API_TOKEN to pin it",
                ctx.data_dir.display()
            ),
        }
    }
    tokio::spawn(async move {
        let listener = bind_api(api_addr, Duration::from_secs(5)).await;
        let app = crate::api::router(api_ctx).layer(axum::middleware::from_fn_with_state(
            api_auth,
            crate::api_auth::require_auth,
        ));
        info!("HTTP API listening on {}", api_addr);
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    // Mobile API: read-only subset for iOS/Android companion apps, LAN-bound
    // by default. Only idempotent GETs; no state-mutating routes regardless
    // of the main API's bind address.
    if config.mobile.enabled {
        let mobile_ctx = Arc::clone(ctx);
        let mobile_bind = config.mobile.bind_addr.clone();
        let mobile_port = config.mobile.port;
        tokio::spawn(async move {
            if let Err(e) = crate::mobile_api::start(mobile_ctx, mobile_bind, mobile_port).await {
                log::warn!("Mobile API listener failed: {}", e);
            }
        });
    }

    let proxy_bind: std::net::Ipv4Addr = config
        .proxy
        .bind_addr
        .parse()
        .unwrap_or(std::net::Ipv4Addr::LOCALHOST);

    if config.proxy.enabled {
        let proxy_ctx = Arc::clone(ctx);
        let proxy_port = config.proxy.port;
        tokio::spawn(async move {
            crate::proxy::start_proxy(proxy_ctx, proxy_port, proxy_bind).await;
        });
    }

    if config.proxy.enabled && config.proxy.tls_port > 0 && ctx.tls_config.is_some() {
        let proxy_ctx = Arc::clone(ctx);
        let tls_port = config.proxy.tls_port;
        let pp_cfg = config.proxy.proxy_protocol.clone();
        tokio::spawn(async move {
            crate::proxy::start_proxy_tls(proxy_ctx, tls_port, proxy_bind, &pp_cfg).await;
        });
    }

    {
        let watch_ctx = Arc::clone(ctx);
        tokio::spawn(async move {
            network_watch_loop(watch_ctx).await;
        });
    }

    if config.lan.enabled {
        let lan_ctx = Arc::clone(ctx);
        let lan_config = config.lan.clone();
        tokio::spawn(async move {
            crate::lan::start_lan_discovery(lan_ctx, &lan_config).await;
        });
    }

    if config.dot.enabled {
        let dot_ctx = Arc::clone(ctx);
        let dot_config = config.dot.clone();
        tokio::spawn(async move {
            crate::dot::start_dot(dot_ctx, &dot_config).await;
        });
    }

    for tcp_bind in &config.server.bind_addr {
        let tcp_ctx = Arc::clone(ctx);
        let tcp_bind = tcp_bind.clone();
        let tcp_pp = config.server.proxy_protocol.clone();
        tokio::spawn(async move {
            crate::tcp::start_tcp(tcp_ctx, &tcp_bind, &tcp_pp).await;
        });
    }

    Ok(())
}

async fn udp_serve_loop(
    ctx: &Arc<ServerCtx>,
    socket: Arc<UdpListener>,
    udp_pp: Option<&crate::pp2::PpConfig>,
) -> crate::Result<()> {
    #[allow(clippy::infinite_loop)]
    loop {
        let mut buffer = BytePacketBuffer::new();
        let (len, peer, local_dst) = match socket.recv_from(&mut buffer.buf).await {
            Ok(r) => r,
            Err(e) if recv_error_is_per_datagram(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        let pp = crate::pp2_udp::parse_if_trusted(&buffer.buf[..len], peer, udp_pp, ctx);
        let Some((src_addr, dns_len, local_command)) = pp.apply(&mut buffer.buf, len, peer) else {
            continue;
        };
        if !ctx.allow_from.admits(src_addr.ip(), local_command) {
            // Silent drop: no reply means no amplification, no fingerprint.
            debug!("UDP: dropping {} — not in allow_from", src_addr);
            continue;
        }
        // Response goes to the kernel UDP peer (e.g. dnsdist), not the
        // PROXY-extracted logical source — otherwise the reply skips the
        // front-end and never reaches the original client.
        // `local_dst` pins the reply source on multi-homed wildcard binds.
        let ctx = Arc::clone(ctx);
        let reply_socket = Arc::clone(&socket);
        tokio::spawn(async move {
            if let Err(e) = handle_query(
                buffer,
                dns_len,
                src_addr,
                peer,
                local_dst,
                &ctx,
                &reply_socket,
                Transport::Udp,
            )
            .await
            {
                error!("{} | HANDLER ERROR | {}", src_addr, e);
            }
        });
    }
}

/// Winsock reports these on one datagram and drops it: ICMP port-unreachable
/// (ConnectionReset), a datagram over the buffer (WSAEMSGSIZE) and ICMP time
/// exceeded (WSAENETRESET). Unix truncates instead and never raises them.
fn recv_error_is_per_datagram(e: &std::io::Error) -> bool {
    const WSAEMSGSIZE: i32 = 10040;
    const WSAENETRESET: i32 = 10052;
    e.kind() == std::io::ErrorKind::ConnectionReset
        || matches!(e.raw_os_error(), Some(WSAEMSGSIZE | WSAENETRESET))
}

fn print_banner(
    config: &crate::config::Config,
    ctx: &ServerCtx,
    api_url: &str,
    upstream_label: &str,
    zone_count: usize,
    doh_enabled: bool,
) {
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
    let bind_label = config.server.bind_addr.join(", ");

    let tag_line = "DNS that governs itself";
    let v = crate::version();
    let title_plain = format!("NUMA  {tag_line}  v{v}");

    // label (10) + value + padding (2) = inner width; widen further if the
    // title row (variable-length once the version carries a +SHA suffix)
    // would overflow.
    let val_w = [
        bind_label.len(),
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
    let w = (val_w + 12).max(42).max(1 + title_plain.chars().count());

    let palette = crate::palette::get();
    let o = palette.brand;
    let g = palette.olive;
    let d = palette.dim;
    let r = palette.reset;
    let b = palette.brand_bold;
    let it = palette.dim_italic;

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

    let title = format!("{b}NUMA{r}  {it}{tag_line}{r}  {d}v{v}{r}");
    let title_pad = w - 1 - title_plain.chars().count();
    eprintln!("\n{o}  ╔{bar_top}╗{r}");
    eprint!("{o}  ║{r} {title}");
    eprintln!("{}{o}║{r}", " ".repeat(title_pad));
    eprintln!("{o}  ╠{bar_top}╣{r}");
    row("DNS", g, &bind_label);
    row("API", g, api_url);
    row("Dashboard", g, api_url);
    row(
        "Upstream",
        g,
        if ctx.upstream_mode == crate::config::UpstreamMode::Recursive {
            "recursive (root hints)"
        } else {
            upstream_label
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
            row(
                "",
                palette.warning,
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
}

fn effective_dnssec(
    config: &crate::config::Config,
    resolved_mode: crate::config::UpstreamMode,
) -> bool {
    let validates = resolved_mode.validates_dnssec() == Some(true);
    if config.dnssec.enabled && !validates {
        if config.upstream.mode == crate::config::UpstreamMode::Auto {
            warn!("[dnssec] enabled has no effect: the auto probe fell back to forward mode, a restart probes again");
        } else {
            warn!(
                "[dnssec] enabled has no effect in {} mode. {}",
                resolved_mode.as_str(),
                crate::config::DNSSEC_NEEDS_RECURSIVE
            );
        }
    }
    config.dnssec.enabled && validates
}

async fn resolve_upstream_pool(
    config: &crate::config::Config,
    system_dns: &crate::system_dns::SystemDnsInfo,
    root_hints: &[SocketAddr],
    bootstrap_resolver: &Arc<NumaResolver>,
) -> crate::Result<(crate::config::UpstreamMode, bool, UpstreamPool, String)> {
    let recursive_pool = || {
        let dummy = UpstreamPool::new(vec![Upstream::Udp("0.0.0.0:0".parse().unwrap())], vec![]);
        (dummy, "recursive (root hints)".to_string())
    };

    Ok(match config.upstream.mode {
        crate::config::UpstreamMode::Auto => {
            info!("auto mode: probing recursive resolution...");
            if crate::recursive::probe_recursive(root_hints).await {
                info!("recursive probe succeeded — self-sovereign mode");
                let (pool, label) = recursive_pool();
                (crate::config::UpstreamMode::Recursive, false, pool, label)
            } else {
                log::warn!("recursive probe failed — falling back to Quad9/Cloudflare DoH");
                let client = build_https_client_with_resolver(1, Some(bootstrap_resolver.clone()));
                let pool = UpstreamPool::new(doh_fallback(client), vec![]);
                let label = pool.label();
                (crate::config::UpstreamMode::Forward, false, pool, label)
            }
        }
        crate::config::UpstreamMode::Recursive => {
            let (pool, label) = recursive_pool();
            (crate::config::UpstreamMode::Recursive, false, pool, label)
        }
        crate::config::UpstreamMode::Forward => {
            let addrs = if config.upstream.address.is_empty() {
                match system_dns
                    .default_upstream
                    .clone()
                    .or_else(crate::system_dns::detect_dhcp_dns)
                {
                    Some(detected) => vec![detected],
                    None => {
                        info!("could not detect system DNS, falling back to Quad9/Cloudflare DoH");
                        DOH_FALLBACK.map(String::from).to_vec()
                    }
                }
            } else {
                config.upstream.address.clone()
            };

            let primary = parse_upstream_list(
                &addrs,
                config.upstream.port,
                Some(bootstrap_resolver.clone()),
            )?;
            let mut fallback = parse_upstream_list(
                &config.upstream.fallback,
                config.upstream.port,
                Some(bootstrap_resolver.clone()),
            )?;

            // Pair every UDP primary with a TCP sibling in fallback so
            // Forward mode survives carriers that drop outbound UDP:53
            // for amplification mitigation (BCP 38).
            for u in &primary {
                if let crate::forward::Upstream::Udp(addr) = u {
                    let tcp = crate::forward::Upstream::Tcp(*addr);
                    if !fallback.contains(&tcp) {
                        fallback.push(tcp);
                    }
                }
            }

            let pool = UpstreamPool::new(primary, fallback);
            let label = pool.label();
            (
                crate::config::UpstreamMode::Forward,
                config.upstream.address.is_empty(),
                pool,
                label,
            )
        }
        crate::config::UpstreamMode::Odoh => {
            let odoh = config.upstream.odoh_upstream()?;
            let client = build_https_client_with_resolver(1, Some(bootstrap_resolver.clone()));
            let target_config = Arc::new(OdohConfigCache::new(
                odoh.target_host.clone(),
                client.clone(),
            ));
            let primary = vec![Upstream::Odoh {
                relay_url: odoh.relay_url,
                target_path: odoh.target_path,
                client,
                target_config,
            }];
            let fallback = if odoh.strict {
                Vec::new()
            } else {
                parse_upstream_list(
                    &config.upstream.fallback,
                    config.upstream.port,
                    Some(bootstrap_resolver.clone()),
                )?
            };
            let pool = UpstreamPool::new(primary, fallback);
            let label = pool.label();
            (crate::config::UpstreamMode::Odoh, false, pool, label)
        }
    })
}

async fn network_watch_loop(ctx: Arc<ServerCtx>) {
    let mut tick: u64 = 0;

    // Built once. The URLs are IP literals, so they need no resolver and can't
    // loop back through numa.
    let defaults = doh_fallback(build_https_client_with_resolver(1, None));

    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.tick().await; // skip immediate tick

    loop {
        interval.tick().await;
        tick += 1;
        let mut changed = false;

        // Check LAN IP change (every 5s — cheap, one UDP socket call)
        if let Some(new_ip) = crate::lan::detect_lan_ip() {
            let mut current_ip = ctx.lan_ip.lock().unwrap();
            if new_ip != *current_ip {
                info!("LAN IP changed: {} → {}", current_ip, new_ip);
                *current_ip = new_ip;
                changed = true;
                crate::recursive::reset_udp_state();
            }
        }

        // Re-detect upstream every 30s or on LAN IP change (auto-detect only)
        if ctx.upstream_auto && (changed || tick.is_multiple_of(6)) {
            let dns_info = crate::system_dns::discover_system_dns();
            let detected = dns_info
                .default_upstream
                .or_else(crate::system_dns::detect_dhcp_dns);
            let mut pool = ctx.upstream_pool.lock().unwrap();
            // Undetectable system DNS resolves to the DoH fallback here exactly
            // as it does at startup. Synthesising a bare UDP Quad9 instead silently
            // downgraded the transport 30s in, stranding every client where
            // outbound UDP:53 is blocked (#169).
            let updated = match detected {
                Some(addr) => pool.maybe_update_primary(&addr, ctx.upstream_port),
                None => pool.maybe_replace_primary(defaults.clone()),
            };
            if updated {
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
            crate::recursive::probe_udp(&ctx.root_hints).await;
        }
    }
}

/// Extends the larger set with the smaller, so the bigger table is never rehashed.
fn merge_into(acc: &mut HashSet<String>, mut set: HashSet<String>) {
    if acc.len() < set.len() {
        std::mem::swap(acc, &mut set);
    }
    acc.extend(set);
}

fn live_domains(
    source: &str,
    fetched: &Result<String, String>,
    cache: &BlocklistCache,
    kind: SourceKind,
) -> Result<HashSet<String>, String> {
    let text = fetched.as_ref().map_err(Clone::clone)?;
    let parsed = parse_blocklist_counted(text, kind);
    if let Some(why) = source_defect(source, &parsed) {
        error!("list source failed: {source} — {why}");
        return Err("not a domain list".to_string());
    }
    info!("list: {} domains from {source}", parsed.domains.len());
    cache.store(source, text);
    Ok(parsed.domains)
}

// Index in the v2 and v3 headers of the pinned libmimalloc-sys 0.1.49, which does not export it.
#[cfg(target_env = "musl")]
const MI_OPTION_PURGE_DELAY: libmimalloc_sys::mi_option_t = 15;

// mimalloc keeps freed pages resident until a delayed purge, so every table a
// reload outgrows would stack into its peak, and the purge only runs on later
// activity in a loader that goes idle. Purge eagerly for the load alone: query
// throughput pays for eager purging, and queries are not what a reload is doing.
async fn load_blocklists_purging(
    ctx: &ServerCtx,
    block: &[String],
    allow: &[String],
    resolver: Option<Arc<NumaResolver>>,
) -> bool {
    #[cfg(target_env = "musl")]
    let delay = unsafe {
        let delay = libmimalloc_sys::mi_option_get(MI_OPTION_PURGE_DELAY);
        libmimalloc_sys::mi_option_set(MI_OPTION_PURGE_DELAY, 0);
        delay
    };
    let loaded = load_blocklists(ctx, block, allow, resolver).await;
    #[cfg(target_env = "musl")]
    unsafe {
        libmimalloc_sys::mi_collect(true);
        libmimalloc_sys::mi_option_set(MI_OPTION_PURGE_DELAY, delay);
    }
    loaded
}

async fn load_blocklists(
    ctx: &ServerCtx,
    block: &[String],
    allow: &[String],
    resolver: Option<Arc<NumaResolver>>,
) -> bool {
    let sources = crate::blocklist::dedup_sources(&[block, allow].concat());
    let downloaded = download_blocklists(&sources, resolver).await;
    apply_downloads(ctx, block, allow, &downloaded)
}

/// What the sources of one kind parsed to on this refresh.
struct ParsedSources {
    domains: HashSet<String>,
    outcomes: Vec<(String, SourceResult)>,
    failed: usize,
    stale: usize,
}

impl ParsedSources {
    /// Nothing to swap in is a failure only if something broke (issue #336);
    /// sources that all loaded and parsed to nothing are a deliberately emptied
    /// list and must be allowed to clear the old one.
    fn broke(&self) -> bool {
        self.domains.is_empty() && self.failed > 0
    }
}

fn parse_sources(
    sources: &[String],
    downloaded: &[(String, Result<String, String>)],
    cache: &BlocklistCache,
    kind: SourceKind,
) -> ParsedSources {
    let mut parsed = ParsedSources {
        domains: HashSet::new(),
        outcomes: Vec::with_capacity(sources.len()),
        failed: 0,
        stale: 0,
    };
    for (source, fetched) in downloaded.iter().filter(|(s, _)| sources.contains(s)) {
        let result = match live_domains(source, fetched, cache, kind) {
            Ok(domains) => {
                merge_into(&mut parsed.domains, domains);
                SourceResult::Loaded
            }
            // A stale list still blocks; nothing at all does not. The cached copy
            // is never refused for being old (issue #336).
            Err(error) => match cache.load(source) {
                Some(cached) => {
                    parsed.stale += 1;
                    let domains = parse_blocklist_counted(&cached.text, kind).domains;
                    merge_into(&mut parsed.domains, domains);
                    SourceResult::Cached {
                        error,
                        fetched_unix: cached.fetched_unix,
                    }
                }
                None => {
                    parsed.failed += 1;
                    SourceResult::Failed(error)
                }
            },
        };
        parsed.outcomes.push((source.clone(), result));
    }
    parsed
}

/// Returns `false` only when a failure left blocking with nothing loaded at all.
/// An emptied list is a successful load of nothing, and has nothing to retry.
fn apply_downloads(
    ctx: &ServerCtx,
    block: &[String],
    allow: &[String],
    downloaded: &[(String, Result<String, String>)],
) -> bool {
    // Parse outside the lock to avoid blocking DNS queries during parse (~100ms)
    let cache = BlocklistCache::new(&ctx.data_dir);
    let mut blocks = parse_sources(block, downloaded, &cache, SourceKind::Block);
    let mut allows = parse_sources(allow, downloaded, &cache, SourceKind::Allow);
    cache.prune(&[block, allow].concat());

    // Lock work stays sub-microsecond: record, then swap or keep.
    let mut store = ctx.blocklist.write().unwrap();
    store.record_outcomes(&blocks.outcomes);
    store.record_outcomes(&allows.outcomes);
    let (blocks_broke, allows_broke) = (blocks.broke(), allows.broke());
    if !blocks_broke {
        store.swap_domains(std::mem::take(&mut blocks.domains));
    }
    if !allows_broke {
        store.swap_allow_domains(std::mem::take(&mut allows.domains));
    }
    let (block_total, allow_total) = (store.domains_loaded(), store.allow_domains_loaded());
    drop(store);

    log_refresh("blocking", &blocks, blocks_broke, block_total);
    if !allow.is_empty() {
        log_refresh("allowlist", &allows, allows_broke, allow_total);
    }
    // A retry re-downloads every block list, so only blocking earns one.
    !blocks_broke || block_total > 0
}

/// `total` is what is live after the refresh, whether kept or swapped in.
fn log_refresh(label: &str, parsed: &ParsedSources, broke: bool, total: usize) {
    let (lists, failed, stale) = (parsed.outcomes.len(), parsed.failed, parsed.stale);
    if broke {
        error!(
            "{label} refresh failed for {failed} of {lists} lists — keeping {total} domains already loaded"
        );
        return;
    }
    // Live only. A cached source is contributing domains but is not evidence
    // its upstream works, and counting it as loaded is the overstatement this
    // reporting exists to remove.
    let loaded = lists - failed - stale;
    if failed > 0 {
        // Spells out stale too — the degraded branch wins the `if`, so a box
        // that is both would otherwise never mention its cached lists.
        warn!(
            "{label} degraded: {total} unique domains, {loaded} of {lists} lists live, {stale} from cache, {failed} failed"
        );
    } else if stale > 0 {
        warn!("{label} stale: {total} unique domains, {stale} of {lists} lists served from cache");
    } else {
        info!("{label} enabled: {total} unique domains from {loaded} lists");
    }
}

async fn warm_domain(ctx: &ServerCtx, domain: &str) {
    for qtype in [
        crate::question::QueryType::A,
        crate::question::QueryType::AAAA,
    ] {
        crate::ctx::refresh_entry(ctx, domain, qtype).await;
    }
}

async fn doh_keepalive_loop(ctx: Arc<ServerCtx>) {
    // First tick fires immediately so we surface bootstrap-resolver failures
    // (unreachable Quad9/Cloudflare, blocked :53, bad upstream hostname) in
    // the startup logs instead of on the first client query.
    let mut interval = tokio::time::interval(Duration::from_secs(25));
    loop {
        interval.tick().await;
        let pool = ctx.upstream_pool.lock().unwrap().clone();
        if let Some(upstream) = pool.preferred() {
            crate::forward::keepalive_doh(upstream).await;
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

/// DNS must not depend on the control plane: a taken API port is retried in
/// the background instead of failing startup (a failed start under launchd or
/// systemd takes the host's DNS down with it).
async fn bind_api(addr: SocketAddr, retry: Duration) -> tokio::net::TcpListener {
    let mut reported = false;
    loop {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => return listener,
            Err(e) if !reported => {
                error!("cannot bind the API on {addr}: {e} (DNS keeps serving, retrying every {retry:?})");
                reported = true;
            }
            Err(_) => {}
        }
        tokio::time::sleep(retry).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_datagram_recv_errors_do_not_stop_the_udp_loop() {
        for code in [10040, 10052] {
            let e = std::io::Error::from_raw_os_error(code);
            assert!(recv_error_is_per_datagram(&e), "{code}");
        }
        assert!(recv_error_is_per_datagram(
            &std::io::ErrorKind::ConnectionReset.into()
        ));
        assert!(!recv_error_is_per_datagram(
            &std::io::ErrorKind::NotConnected.into()
        ));
    }

    #[test]
    fn dnssec_counts_only_when_numa_resolves_recursively() {
        use crate::config::UpstreamMode::{Forward, Odoh, Recursive};
        let dnssec_on = |mode: &str| -> crate::config::Config {
            toml::from_str(&format!(
                "[upstream]\nmode = \"{mode}\"\n\n[dnssec]\nenabled = true\n"
            ))
            .unwrap()
        };
        assert!(effective_dnssec(&dnssec_on("recursive"), Recursive));
        assert!(effective_dnssec(&dnssec_on("auto"), Recursive));
        assert!(!effective_dnssec(&dnssec_on("auto"), Forward));
        assert!(!effective_dnssec(&dnssec_on("forward"), Forward));
        assert!(!effective_dnssec(&dnssec_on("odoh"), Odoh));
        assert!(!effective_dnssec(
            &crate::config::Config::default(),
            Recursive
        ));
    }

    #[test]
    fn merge_into_keeps_the_larger_table_in_either_order() {
        let small: HashSet<String> = ["a.com", "shared.com"].map(String::from).into();
        let large_ptr = |s: &HashSet<String>| s.get("d0.com").unwrap() as *const String;

        for large_first in [false, true] {
            let large: HashSet<String> = (0..1_000).map(|i| format!("d{i}.com")).collect();
            let kept = large_ptr(&large);
            let (first, second) = if large_first {
                (large, small.clone())
            } else {
                (small.clone(), large)
            };
            let mut acc = HashSet::new();
            merge_into(&mut acc, first);
            merge_into(&mut acc, second);
            assert_eq!(acc.len(), 1_002);
            assert!(acc.contains("a.com") && acc.contains("d999.com"));
            assert_eq!(large_ptr(&acc), kept, "large set was rehashed, not kept");
        }
    }

    #[tokio::test]
    async fn bind_api_waits_for_a_taken_port_instead_of_failing_startup() {
        let held = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = held.local_addr().unwrap();
        let bind = tokio::spawn(bind_api(addr, Duration::from_millis(10)));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!bind.is_finished(), "gave up while the port was taken");
        drop(held);
        let listener = tokio::time::timeout(Duration::from_secs(2), bind)
            .await
            .expect("port freed but bind kept retrying")
            .unwrap();
        assert_eq!(listener.local_addr().unwrap(), addr);
    }

    #[tokio::test]
    async fn bind_udp_listeners_rejects_empty() {
        let err = bind_udp_listeners(&[]).await.unwrap_err();
        assert!(err.to_string().contains("bind_addr is empty"));
    }

    /// Absolute so `local_path` recognises it on Windows too, where a leading
    /// `/` is not an absolute path.
    fn temp_path(name: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("numa_{name}_{nanos}.txt"))
            .display()
            .to_string()
    }

    fn temp_list(name: &str, body: &str) -> String {
        let path = temp_path(name);
        std::fs::write(&path, body).unwrap();
        path
    }

    async fn ctx_blocking(domains: &[&str]) -> ServerCtx {
        let ctx = crate::testutil::test_ctx().await;
        ctx.blocklist
            .write()
            .unwrap()
            .swap_domains(domains.iter().map(|d| d.to_string()).collect());
        ctx
    }

    /// A source that cannot be read is not an instruction to stop blocking:
    /// the working list must survive (issue #336).
    #[tokio::test]
    async fn failed_source_keeps_the_live_list() {
        let ctx = ctx_blocking(&["ads.example.com"]).await;
        let missing = temp_path("never_written");
        let loaded = load_blocklists(&ctx, std::slice::from_ref(&missing), &[], None).await;
        assert_eq!(ctx.blocklist.read().unwrap().domains_loaded(), 1);
        assert!(
            loaded,
            "a surviving list is still blocking, so wait a full cycle"
        );
    }

    /// The same failure with nothing to fall back on leaves blocking inactive,
    /// which is the one case that must not wait a full refresh cycle.
    #[tokio::test]
    async fn total_failure_with_no_live_list_asks_for_a_retry() {
        let ctx = ctx_blocking(&[]).await;
        let missing = temp_path("never_written_either");
        let loaded = load_blocklists(&ctx, std::slice::from_ref(&missing), &[], None).await;
        assert_eq!(ctx.blocklist.read().unwrap().domains_loaded(), 0);
        assert!(!loaded);
    }

    /// But deliberately emptying your own list means block nothing, and must
    /// not be mistaken for a failure.
    #[tokio::test]
    async fn emptied_local_list_clears_the_live_list() {
        let ctx = ctx_blocking(&["ads.example.com"]).await;
        let source = temp_list("emptied", "# all clear\n");
        let loaded = load_blocklists(&ctx, std::slice::from_ref(&source), &[], None).await;
        let _ = std::fs::remove_file(&source);
        assert_eq!(ctx.blocklist.read().unwrap().domains_loaded(), 0);
        assert!(
            loaded,
            "an emptied list loaded fine, there is nothing to retry"
        );
    }

    #[tokio::test]
    async fn healthy_local_list_is_swapped_in() {
        let ctx = ctx_blocking(&["ads.example.com"]).await;
        let source = temp_list("healthy", "a.com\nb.com\n");
        load_blocklists(&ctx, std::slice::from_ref(&source), &[], None).await;
        let _ = std::fs::remove_file(&source);
        assert_eq!(ctx.blocklist.read().unwrap().domains_loaded(), 2);
    }

    fn fetched(source: &str, body: &str) -> (String, Result<String, String>) {
        (source.to_string(), Ok(body.to_string()))
    }

    fn unfetched(source: &str) -> (String, Result<String, String>) {
        (source.to_string(), Err("unreadable".to_string()))
    }

    #[tokio::test]
    async fn allow_source_unblocks_after_load() {
        let ctx = ctx_blocking(&[]).await;
        let (block, allow) = (temp_path("block_src"), temp_path("allow_src"));
        let loaded = apply_downloads(
            &ctx,
            std::slice::from_ref(&block),
            std::slice::from_ref(&allow),
            &[
                fetched(&block, "example.com\n"),
                fetched(&allow, "go.example.com\n@@||other.example.com^\n"),
            ],
        );
        assert!(loaded);
        let store = ctx.blocklist.read().unwrap();
        assert!(store.is_blocked("ads.example.com"));
        assert!(!store.is_blocked("go.example.com"));
        assert!(!store.is_blocked("other.example.com"), "adblock @@ line");
    }

    #[tokio::test]
    async fn failed_allow_refresh_keeps_previous_allow_set() {
        let ctx = ctx_blocking(&["example.com"]).await;
        ctx.blocklist
            .write()
            .unwrap()
            .swap_allow_domains(["go.example.com".to_string()].into());
        let (block, allow) = (temp_path("block_ok"), temp_path("allow_gone"));
        apply_downloads(
            &ctx,
            std::slice::from_ref(&block),
            std::slice::from_ref(&allow),
            &[fetched(&block, "example.com\n"), unfetched(&allow)],
        );
        assert!(!ctx.blocklist.read().unwrap().is_blocked("go.example.com"));
    }

    /// Pruning by block sources alone would delete this copy on every refresh.
    #[tokio::test]
    async fn refresh_keeps_cached_copies_of_allow_sources() {
        let mut ctx = ctx_blocking(&[]).await;
        ctx.data_dir = std::path::PathBuf::from(temp_path("allow_cache_dir"));
        let allow = "https://allow.example/list.txt".to_string();
        BlocklistCache::new(&ctx.data_dir).store(&allow, "go.example.com\n");
        let block = temp_path("block_beside_cache");
        apply_downloads(
            &ctx,
            std::slice::from_ref(&block),
            std::slice::from_ref(&allow),
            &[fetched(&block, "example.com\n"), unfetched(&allow)],
        );
        assert!(!ctx.blocklist.read().unwrap().is_blocked("go.example.com"));
        assert!(BlocklistCache::new(&ctx.data_dir).load(&allow).is_some());
        let _ = std::fs::remove_dir_all(&ctx.data_dir);
    }

    /// Retrying soon re-downloads every block list, so only a dead block side
    /// earns it. A dead allow source waits for the next refresh.
    #[tokio::test]
    async fn allow_failure_does_not_force_a_block_refetch() {
        let ctx = ctx_blocking(&[]).await;
        let (block, allow) = (temp_path("block_fine"), temp_path("allow_never"));
        let loaded = apply_downloads(
            &ctx,
            std::slice::from_ref(&block),
            std::slice::from_ref(&allow),
            &[fetched(&block, "example.com\n"), unfetched(&allow)],
        );
        assert!(loaded, "blocking is healthy, so wait a full cycle");
    }
}
