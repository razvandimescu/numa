use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use log::{debug, error, info, warn};
use rustls::ServerConfig;
use tokio::sync::broadcast;

use crate::udp_listener::UdpListener;

type InflightMap = HashMap<(String, QueryType), broadcast::Sender<Option<DnsPacket>>>;

use crate::blocklist::BlocklistStore;
use crate::buffer::BytePacketBuffer;
use crate::cache::{DnsCache, DnssecStatus};
use crate::config::{UpstreamMode, ZoneMap};
#[cfg(test)]
use crate::forward::Upstream;
use crate::forward::{forward_with_failover_raw, UpstreamPool};
use crate::header::ResultCode;
use crate::health::HealthMeta;
use crate::lan::PeerStore;
use crate::override_store::OverrideStore;
use crate::packet::DnsPacket;
use crate::query_log::{QueryLog, QueryLogEntry};
use crate::question::QueryType;
use crate::record::DnsRecord;
use crate::service_store::ServiceStore;
use crate::srtt::SrttCache;
use crate::stats::{QueryPath, ServerStats, Transport};
use crate::system_dns::ForwardingRule;

pub struct ServerCtx {
    pub zone_map: ZoneMap,
    /// std::sync::RwLock (not tokio) — locks must never be held across .await points.
    pub cache: RwLock<DnsCache>,
    /// Domains currently being refreshed in the background (dedup guard).
    pub refreshing: Mutex<HashSet<(String, QueryType)>>,
    pub stats: Mutex<ServerStats>,
    pub overrides: RwLock<OverrideStore>,
    pub blocklist: RwLock<BlocklistStore>,
    pub query_log: Mutex<QueryLog>,
    pub services: Mutex<ServiceStore>,
    pub lan_peers: Mutex<PeerStore>,
    pub forwarding_rules: Vec<ForwardingRule>,
    pub upstream_pool: Mutex<UpstreamPool>,
    pub upstream_auto: bool,
    pub upstream_port: u16,
    pub lan_ip: Mutex<std::net::Ipv4Addr>,
    pub timeout: Duration,
    pub hedge_delay: Duration,
    pub proxy_tld: String,
    pub proxy_tld_suffix: String, // pre-computed ".{tld}" to avoid per-query allocation
    pub lan_enabled: bool,
    pub config_path: String,
    pub config_found: bool,
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub tls_config: Option<ArcSwap<ServerConfig>>,
    /// Set when `tls_config` is a user-supplied cert; suppresses regeneration.
    pub tls_byo: bool,
    pub upstream_mode: UpstreamMode,
    pub root_hints: Vec<SocketAddr>,
    pub srtt: RwLock<SrttCache>,
    pub inflight: Mutex<InflightMap>,
    pub dnssec_enabled: bool,
    pub dnssec_strict: bool,
    /// Cached health metadata (version, hostname, DoT config, CA
    /// fingerprint, features). Shared between the main and mobile
    /// API `/health` handlers. Built once at startup in `main.rs`.
    pub health_meta: HealthMeta,
    /// CA certificate in PEM form, cached at startup. `None` if no
    /// TLS-using feature is enabled and the CA hasn't been generated.
    /// Used by `/ca.pem`, `/mobileconfig`, and `/ca.mobileconfig`
    /// handlers to avoid per-request disk I/O on the hot path.
    pub ca_pem: Option<String>,
    pub mobile_enabled: bool,
    pub mobile_port: u16,
    /// When true, AAAA queries short-circuit with NODATA (NOERROR + empty
    /// answer) instead of hitting cache/forwarding/upstream. Local data
    /// (overrides, zones, .numa proxy, blocklist sinkhole) is unaffected.
    pub filter_aaaa: bool,
    pub allow_from: crate::acl::AllowFromAcl,
    pub client_policy: crate::client_policy::ClientPolicySet,
}

/// Transport-agnostic DNS resolution. Runs the full pipeline (overrides, blocklist,
/// cache, upstream, DNSSEC) and returns the serialized response in a buffer.
/// Callers use `.filled()` to get the response bytes without heap allocation.
/// Callers are responsible for parsing the incoming buffer into a `DnsPacket`
/// (and logging parse errors) before calling this function.
pub async fn resolve_query(
    query: DnsPacket,
    raw_wire: &[u8],
    src_addr: SocketAddr,
    ctx: &Arc<ServerCtx>,
    transport: Transport,
) -> crate::Result<(BytePacketBuffer, QueryPath)> {
    let start = Instant::now();

    let (qname, qtype) = match query.questions.first() {
        Some(q) => (q.name.clone(), q.qtype),
        None => return Err("empty question section".into()),
    };

    // Pipeline: overrides -> .localhost -> local zones -> special-use (unless forwarded)
    //        -> .tld proxy -> blocklist -> cache -> forwarding -> recursive/upstream
    // Each lock is scoped to avoid holding MutexGuard across await points.
    let (mut response, path, mut dnssec, upstream_transport) =
        resolve_with_cname_chase(&query, raw_wire, src_addr, &qname, qtype, ctx).await;

    // DNSSEC validation (recursive/forwarded responses only)
    if ctx.dnssec_enabled && path == QueryPath::Recursive {
        let (status, vstats) =
            crate::dnssec::validate_response(&response, &ctx.cache, &ctx.root_hints, &ctx.srtt)
                .await;

        debug!(
            "DNSSEC | {} | {:?} | {}ms | dnskey_hit={} dnskey_fetch={} ds_hit={} ds_fetch={}",
            qname,
            status,
            vstats.elapsed_ms,
            vstats.dnskey_cache_hits,
            vstats.dnskey_fetches,
            vstats.ds_cache_hits,
            vstats.ds_fetches,
        );

        dnssec = status;

        if status == DnssecStatus::Secure {
            response.header.authed_data = true;
        }

        if status == DnssecStatus::Bogus && ctx.dnssec_strict {
            response = DnsPacket::response_from(&query, ResultCode::SERVFAIL);
        }

        ctx.cache
            .write()
            .unwrap()
            .insert_with_status(&qname, qtype, &response, status);
    }

    shape_response_for_client(&mut response, &query, ctx.filter_aaaa);

    let elapsed = start.elapsed();

    info!(
        "{} | {:?} {} | {} | {} | {}ms",
        src_addr,
        qtype,
        qname,
        path.as_str(),
        response.header.rescode.as_str(),
        elapsed.as_millis(),
    );

    debug!(
        "response: {} answers, {} authorities, {} resources",
        response.answers.len(),
        response.authorities.len(),
        response.resources.len(),
    );

    let resp_buffer = serialize_with_fallback(&mut response, &query, &qname, ctx.filter_aaaa)?;

    // Record stats and query log
    {
        let mut s = ctx.stats.lock().unwrap();
        let total = s.record(path, transport, upstream_transport);
        if total.is_multiple_of(1000) {
            s.log_summary();
        }
    }

    ctx.query_log.lock().unwrap().push(QueryLogEntry {
        timestamp: SystemTime::now(),
        src_addr,
        domain: qname,
        query_type: qtype,
        path,
        transport,
        rescode: response.header.rescode,
        latency_us: elapsed.as_micros() as u64,
        dnssec,
    });

    Ok((resp_buffer, path))
}

/// Buffer-full → TC bit, serializer-rejected → SERVFAIL (#142).
/// TODO: TC is UDP-specific; once BytePacketBuffer supports >4096 bytes,
/// skip truncation for TCP/TLS (which can carry up to 65535).
fn serialize_with_fallback(
    response: &mut DnsPacket,
    query: &DnsPacket,
    qname: &str,
    filter_aaaa: bool,
) -> crate::Result<BytePacketBuffer> {
    let mut buf = BytePacketBuffer::new();
    match response.write(&mut buf) {
        Ok(()) => Ok(buf),
        Err(_) if buf.overflowed() => {
            debug!("response too large, setting TC bit for {}", qname);
            let mut tc = DnsPacket::response_from(query, response.header.rescode);
            tc.header.truncated_message = true;
            shape_response_for_client(&mut tc, query, filter_aaaa);
            let mut out = BytePacketBuffer::new();
            tc.write(&mut out)?;
            Ok(out)
        }
        Err(e) => {
            warn!("response serialize error for {}: {}", qname, e);
            // mirror to caller's rescode so the query log reflects SERVFAIL
            response.header.rescode = ResultCode::SERVFAIL;
            let mut servfail = DnsPacket::response_from(query, ResultCode::SERVFAIL);
            shape_response_for_client(&mut servfail, query, filter_aaaa);
            let mut out = BytePacketBuffer::new();
            servfail.write(&mut out)?;
            Ok(out)
        }
    }
}

/// RFC 1034 §3.6.2 CNAME chase across the local-or-remote pipeline. Bad
/// chains (loop, over `MAX_CNAME_DEPTH`) return SERVFAIL, never bare CNAME.
async fn resolve_with_cname_chase(
    query: &DnsPacket,
    raw_wire: &[u8],
    src_addr: SocketAddr,
    qname: &str,
    qtype: QueryType,
    ctx: &Arc<ServerCtx>,
) -> (
    DnsPacket,
    QueryPath,
    DnssecStatus,
    Option<crate::stats::UpstreamTransport>,
) {
    let mut visited = HashSet::new();
    visited.insert(qname.to_ascii_lowercase());

    let (mut resp, path, dnssec, mut ut) = match resolve_local(query, src_addr, qname, qtype, ctx) {
        Some((r, p, d)) => (r, p, d, None),
        None => resolve_remote(query, raw_wire, src_addr, qname, qtype, ctx).await,
    };
    let mut current_qname = qname.to_string();

    loop {
        if resp.answers.iter().any(|r| r.query_type() == qtype)
            || resp.header.rescode != ResultCode::NOERROR
        {
            return (resp, path, dnssec, ut);
        }
        let Some(target) = crate::recursive::extract_cname_target(&resp, &current_qname) else {
            return (resp, path, dnssec, ut);
        };
        if visited.len() > crate::recursive::MAX_CNAME_DEPTH as usize
            || !visited.insert(target.to_ascii_lowercase())
        {
            return (
                DnsPacket::response_from(query, ResultCode::SERVFAIL),
                path,
                dnssec,
                ut,
            );
        }

        let sub_query = DnsPacket::query(query.header.id, &target, qtype);
        let mut sub_buf = BytePacketBuffer::new();
        sub_query
            .write(&mut sub_buf)
            .expect("sub-query serialization");
        let (sub_resp, _, _, sub_ut) =
            match resolve_local(&sub_query, src_addr, &target, qtype, ctx) {
                Some((r, p, d)) => (r, p, d, None),
                None => {
                    resolve_remote(&sub_query, sub_buf.filled(), src_addr, &target, qtype, ctx)
                        .await
                }
            };

        resp.answers.extend(sub_resp.answers);
        resp.header.rescode = sub_resp.header.rescode;
        ut = ut.or(sub_ut);
        current_qname = target;
    }
}

/// Local resolution pipeline: overrides, .localhost, zones, special-use, .numa
/// proxy TLD, blocklist, AAAA filter. Returns `None` to fall through to remote
/// resolution (cache/forwarding/recursive/upstream).
fn resolve_local(
    query: &DnsPacket,
    src_addr: SocketAddr,
    qname: &str,
    qtype: QueryType,
    ctx: &ServerCtx,
) -> Option<(DnsPacket, QueryPath, DnssecStatus)> {
    if let Some(record) = ctx.overrides.read().unwrap().lookup(qname) {
        let mut resp = DnsPacket::response_from(query, ResultCode::NOERROR);
        resp.answers.push(record);
        return Some((resp, QueryPath::Overridden, DnssecStatus::Indeterminate));
    }
    if qname == "localhost" || qname.ends_with(".localhost") {
        // RFC 6761: .localhost always resolves to loopback
        let mut resp = DnsPacket::response_from(query, ResultCode::NOERROR);
        resp.answers.extend(answer_record(
            qname,
            qtype,
            Some(std::net::Ipv4Addr::LOCALHOST),
            Some(std::net::Ipv6Addr::LOCALHOST),
            300,
        ));
        return Some((resp, QueryPath::Local, DnssecStatus::Indeterminate));
    }
    // RFC 4592 §2.2.1: empty answers (NODATA) still answer locally — don't leak upstream.
    if let Some(records) = ctx.zone_map.lookup(qname, qtype) {
        let mut resp = DnsPacket::response_from(query, ResultCode::NOERROR);
        resp.answers = records;
        return Some((resp, QueryPath::Local, DnssecStatus::Indeterminate));
    }
    if is_special_use_domain(qname)
        && crate::system_dns::match_forwarding_rule(qname, &ctx.forwarding_rules).is_none()
    {
        // RFC 6761/8880: answer locally unless a forwarding rule covers this zone.
        let resp = special_use_response(query, qname, qtype);
        return Some((resp, QueryPath::Local, DnssecStatus::Indeterminate));
    }
    if !ctx.proxy_tld_suffix.is_empty()
        && (qname.ends_with(&ctx.proxy_tld_suffix) || qname == ctx.proxy_tld)
    {
        return Some(resolve_proxy_tld(query, src_addr, qname, qtype, ctx));
    }
    let mut policy_allow = false;
    if ctx.client_policy.is_enabled() {
        match ctx.client_policy.evaluate(src_addr.ip(), qname) {
            crate::client_policy::Decision::Block => {
                let mut resp = DnsPacket::response_from(query, ResultCode::NOERROR);
                resp.answers.extend(answer_record(
                    qname,
                    qtype,
                    Some(std::net::Ipv4Addr::UNSPECIFIED),
                    Some(std::net::Ipv6Addr::UNSPECIFIED),
                    60,
                ));
                return Some((resp, QueryPath::Blocked, DnssecStatus::Indeterminate));
            }
            crate::client_policy::Decision::Allow => policy_allow = true,
            crate::client_policy::Decision::Passthrough => {}
        }
    }
    if !policy_allow && ctx.blocklist.read().unwrap().is_blocked(qname) {
        let mut resp = DnsPacket::response_from(query, ResultCode::NOERROR);
        resp.answers.extend(answer_record(
            qname,
            qtype,
            Some(std::net::Ipv4Addr::UNSPECIFIED),
            Some(std::net::Ipv6Addr::UNSPECIFIED),
            60,
        ));
        return Some((resp, QueryPath::Blocked, DnssecStatus::Indeterminate));
    }
    if qtype == QueryType::AAAA && ctx.filter_aaaa {
        // RFC 2308 NODATA: NOERROR with empty answer section. Prevents
        // Happy Eyeballs clients from waiting on an AAAA they'll never use
        // on IPv4-only networks.
        let resp = DnsPacket::response_from(query, ResultCode::NOERROR);
        return Some((resp, QueryPath::Local, DnssecStatus::Indeterminate));
    }
    None
}

/// Resolve `.numa` queries:
///   - locally-registered service → loopback (local client) or LAN IP (remote)
///   - LAN peer learned via discovery → that peer's actual IP (v4 or v6 native)
///   - unknown name → NXDOMAIN (never silently sinkhole to loopback)
fn resolve_proxy_tld(
    query: &DnsPacket,
    src_addr: SocketAddr,
    qname: &str,
    qtype: QueryType,
    ctx: &ServerCtx,
) -> (DnsPacket, QueryPath, DnssecStatus) {
    let service_name = qname.strip_suffix(&ctx.proxy_tld_suffix).unwrap_or(qname);
    let is_remote = !src_addr.ip().is_loopback();

    if ctx.services.lock().unwrap().lookup(service_name).is_some() {
        let v4 = if is_remote {
            *ctx.lan_ip.lock().unwrap()
        } else {
            std::net::Ipv4Addr::LOCALHOST
        };
        let v6 = if v4 == std::net::Ipv4Addr::LOCALHOST {
            std::net::Ipv6Addr::LOCALHOST
        } else {
            v4.to_ipv6_mapped()
        };
        let mut resp = DnsPacket::response_from(query, ResultCode::NOERROR);
        resp.answers
            .extend(answer_record(qname, qtype, Some(v4), Some(v6), 300));
        return (resp, QueryPath::Local, DnssecStatus::Indeterminate);
    }

    if let Some((ip, _)) = ctx.lan_peers.lock().unwrap().lookup(service_name) {
        // A v6-only peer passes `v4 = None`, so an A query naturally yields NODATA.
        let (v4, v6) = match ip {
            std::net::IpAddr::V4(v4) => (Some(v4), Some(v4.to_ipv6_mapped())),
            std::net::IpAddr::V6(v6) => (None, Some(v6)),
        };
        let mut resp = DnsPacket::response_from(query, ResultCode::NOERROR);
        resp.answers
            .extend(answer_record(qname, qtype, v4, v6, 300));
        return (resp, QueryPath::Local, DnssecStatus::Indeterminate);
    }

    let resp = DnsPacket::response_from(query, ResultCode::NXDOMAIN);
    (resp, QueryPath::Local, DnssecStatus::Indeterminate)
}

/// Remote resolution: cache → conditional forwarding → recursive/upstream.
async fn resolve_remote(
    query: &DnsPacket,
    raw_wire: &[u8],
    src_addr: SocketAddr,
    qname: &str,
    qtype: QueryType,
    ctx: &Arc<ServerCtx>,
) -> (
    DnsPacket,
    QueryPath,
    DnssecStatus,
    Option<crate::stats::UpstreamTransport>,
) {
    let cached = ctx.cache.read().unwrap().lookup_with_status(qname, qtype);
    if let Some((cached, cached_dnssec, freshness)) = cached {
        if freshness.needs_refresh() {
            let key = (qname.to_string(), qtype);
            let already = !ctx.refreshing.lock().unwrap().insert(key.clone());
            if !already {
                let ctx = Arc::clone(ctx);
                tokio::spawn(async move {
                    refresh_entry(&ctx, &key.0, key.1).await;
                    ctx.refreshing.lock().unwrap().remove(&key);
                });
            }
        }
        let mut resp = cached;
        resp.header.id = query.header.id;
        resp.header.recursion_desired = query.header.recursion_desired;
        resp.header.recursion_available = true;
        resp.questions = query.questions.clone();
        if cached_dnssec == DnssecStatus::Secure {
            resp.header.authed_data = true;
        }
        return (resp, QueryPath::Cached, cached_dnssec, None);
    }

    if let Some(pool) = crate::system_dns::match_forwarding_rule(qname, &ctx.forwarding_rules) {
        // Conditional forwarding takes priority over recursive mode
        // (e.g. Tailscale .ts.net, VPC private zones)
        let key = (qname.to_string(), qtype);
        let (resp, path, err) =
            resolve_coalesced(&ctx.inflight, key, query, QueryPath::Forwarded, || async {
                let wire = forward_with_failover_raw(
                    raw_wire,
                    pool,
                    &ctx.srtt,
                    ctx.timeout,
                    ctx.hedge_delay,
                )
                .await?;
                cache_and_parse(ctx, qname, qtype, &wire)
            })
            .await;
        log_coalesced_outcome(src_addr, qtype, qname, path, err.as_deref(), "FORWARD");
        let upstream_transport = (path == QueryPath::Forwarded)
            .then(|| pool.preferred().map(|u| u.transport()))
            .flatten();
        return (resp, path, DnssecStatus::Indeterminate, upstream_transport);
    }

    if ctx.upstream_mode == UpstreamMode::Recursive {
        // Recursive resolution makes UDP hops to roots/TLDs/auths;
        // tag as Udp so the dashboard can aggregate plaintext-wire
        // egress honestly. Only mark on success — errors stay None.
        let key = (qname.to_string(), qtype);
        let (resp, path, err) =
            resolve_coalesced(&ctx.inflight, key, query, QueryPath::Recursive, || {
                crate::recursive::resolve_recursive(
                    qname,
                    qtype,
                    &ctx.cache,
                    query,
                    &ctx.root_hints,
                    &ctx.srtt,
                )
            })
            .await;
        log_coalesced_outcome(src_addr, qtype, qname, path, err.as_deref(), "RECURSIVE");
        let upstream_transport =
            (path == QueryPath::Recursive).then_some(crate::stats::UpstreamTransport::Udp);
        return (resp, path, DnssecStatus::Indeterminate, upstream_transport);
    }

    let pool = ctx.upstream_pool.lock().unwrap().clone();
    let key = (qname.to_string(), qtype);
    let (resp, path, err) =
        resolve_coalesced(&ctx.inflight, key, query, QueryPath::Upstream, || async {
            let wire =
                forward_with_failover_raw(raw_wire, &pool, &ctx.srtt, ctx.timeout, ctx.hedge_delay)
                    .await?;
            cache_and_parse(ctx, qname, qtype, &wire)
        })
        .await;
    log_coalesced_outcome(src_addr, qtype, qname, path, err.as_deref(), "UPSTREAM");
    let upstream_transport = (path == QueryPath::Upstream)
        .then(|| pool.preferred().map(|u| u.transport()))
        .flatten();
    (resp, path, DnssecStatus::Indeterminate, upstream_transport)
}

fn cache_and_parse(
    ctx: &ServerCtx,
    qname: &str,
    qtype: QueryType,
    resp_wire: &[u8],
) -> crate::Result<DnsPacket> {
    ctx.cache
        .write()
        .unwrap()
        .insert_wire(qname, qtype, resp_wire, DnssecStatus::Indeterminate);
    let mut buf = BytePacketBuffer::from_bytes(resp_wire);
    DnsPacket::from_buffer(&mut buf)
}

/// Re-resolve a single (domain, qtype) and update the cache.
/// Used for both stale-entry refresh and proactive cache warming.
pub async fn refresh_entry(ctx: &ServerCtx, qname: &str, qtype: QueryType) {
    let query = DnsPacket::query(0, qname, qtype);

    // Forwarding rules must win here, mirroring `resolve_query` — otherwise
    // refresh re-resolves private zones through the default upstream and
    // poisons the cache with NXDOMAIN.
    if let Some(pool) = crate::system_dns::match_forwarding_rule(qname, &ctx.forwarding_rules) {
        let mut buf = BytePacketBuffer::new();
        if query.write(&mut buf).is_ok() {
            if let Ok(wire) = forward_with_failover_raw(
                buf.filled(),
                pool,
                &ctx.srtt,
                ctx.timeout,
                ctx.hedge_delay,
            )
            .await
            {
                ctx.cache.write().unwrap().insert_wire(
                    qname,
                    qtype,
                    &wire,
                    DnssecStatus::Indeterminate,
                );
            }
        }
        return;
    }

    if ctx.upstream_mode == UpstreamMode::Recursive {
        if let Ok(resp) = crate::recursive::resolve_recursive(
            qname,
            qtype,
            &ctx.cache,
            &query,
            &ctx.root_hints,
            &ctx.srtt,
        )
        .await
        {
            ctx.cache.write().unwrap().insert(qname, qtype, &resp);
        }
    } else {
        let mut buf = BytePacketBuffer::new();
        if query.write(&mut buf).is_ok() {
            let pool = ctx.upstream_pool.lock().unwrap().clone();
            if let Ok(wire) = forward_with_failover_raw(
                buf.filled(),
                &pool,
                &ctx.srtt,
                ctx.timeout,
                ctx.hedge_delay,
            )
            .await
            {
                ctx.cache.write().unwrap().insert_wire(
                    qname,
                    qtype,
                    &wire,
                    DnssecStatus::Indeterminate,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_query(
    mut buffer: BytePacketBuffer,
    raw_len: usize,
    src_addr: SocketAddr,
    respond_to: SocketAddr,
    local_dst: Option<IpAddr>,
    ctx: &Arc<ServerCtx>,
    reply_socket: &Arc<UdpListener>,
    transport: Transport,
) -> crate::Result<()> {
    let query = match DnsPacket::from_buffer(&mut buffer) {
        Ok(packet) => packet,
        Err(e) => {
            warn!("{} | PARSE ERROR | {}", src_addr, e);
            return Ok(());
        }
    };
    match resolve_query(query, &buffer.buf[..raw_len], src_addr, ctx, transport).await {
        Ok((resp_buffer, _)) => {
            reply_socket
                .send_to(resp_buffer.filled(), respond_to, local_dst)
                .await?;
        }
        Err(e) => {
            warn!("{} | RESOLVE ERROR | {}", src_addr, e);
        }
    }
    Ok(())
}

fn is_dnssec_record(r: &DnsRecord) -> bool {
    matches!(
        r.query_type(),
        QueryType::RRSIG | QueryType::DNSKEY | QueryType::DS | QueryType::NSEC | QueryType::NSEC3
    )
}

fn strip_dnssec_records(pkt: &mut DnsPacket) {
    pkt.answers.retain(|r| !is_dnssec_record(r));
    pkt.authorities.retain(|r| !is_dnssec_record(r));
    pkt.resources.retain(|r| !is_dnssec_record(r));
}

fn strip_svcb_ipv6_hints(pkt: &mut DnsPacket) {
    let https_qtype = QueryType::HTTPS.to_num();
    let svcb_qtype = QueryType::SVCB.to_num();
    pkt.for_each_record_mut(|rec| {
        if let DnsRecord::UNKNOWN { qtype, data, .. } = rec {
            if *qtype == https_qtype || *qtype == svcb_qtype {
                if let Some(new_data) = crate::svcb::strip_ipv6hint(data) {
                    *data = new_data;
                }
            }
        }
    });
}

/// Final pass before serialization. Clears `aa`, mirrors the client's
/// OPT-or-absence (RFC 6891 §6.1.1) preserving upstream options such as
/// EDE, and strips DNSSEC + SVCB-ipv6hint for non-DO clients (RFC 4035
/// §3.2.1).
///
/// Call on every response built for a client: happy path, TC rebuild,
/// SERVFAIL/FORMERR. The pre-parse FORMERR is the exception — no parsed
/// query, no OPT to mirror.
pub(crate) fn shape_response_for_client(
    response: &mut DnsPacket,
    query: &DnsPacket,
    filter_aaaa: bool,
) {
    let client_do = query.edns.as_ref().is_some_and(|e| e.do_bit);

    response.header.authoritative_answer = false;

    if !client_do {
        strip_dnssec_records(response);
        if filter_aaaa {
            strip_svcb_ipv6_hints(response);
        }
    }

    response.edns = query.edns.as_ref().map(|_| {
        let mut e = response.edns.take().unwrap_or_default();
        e.do_bit = client_do;
        e
    });
}

fn is_special_use_domain(qname: &str) -> bool {
    if qname.ends_with(".in-addr.arpa") {
        // RFC 6303: private + loopback + link-local reverse DNS
        if qname.ends_with(".10.in-addr.arpa")
            || qname.ends_with(".168.192.in-addr.arpa")
            || qname.ends_with(".127.in-addr.arpa")
            || qname.ends_with(".254.169.in-addr.arpa")
            || qname.ends_with(".0.in-addr.arpa")
            || qname.contains("_dns-sd._udp")
        {
            return true;
        }
        // 172.16-31.x.x (RFC 1918) — extract second octet from reverse name
        if qname.ends_with(".172.in-addr.arpa") {
            if let Some(octet_str) = qname
                .strip_suffix(".172.in-addr.arpa")
                .and_then(|s| s.rsplit('.').next())
            {
                if let Ok(octet) = octet_str.parse::<u8>() {
                    return (16..=31).contains(&octet);
                }
            }
        }
        return false;
    }
    // DDR (RFC 9462)
    if qname == "_dns.resolver.arpa" || qname.ends_with("._dns.resolver.arpa") {
        return true;
    }
    // NAT64 (RFC 8880)
    if qname == "ipv4only.arpa" {
        return true;
    }
    // RFC 6762: .local is reserved for mDNS — never forward to upstream
    qname == "local" || qname.ends_with(".local")
}

/// Family-appropriate synthesized answer for a locally-handled name (sinkhole,
/// `.localhost`, `.numa`). Returns `None` (= NODATA) when the queried family is
/// absent or the qtype isn't an address type.
fn answer_record(
    domain: &str,
    qtype: QueryType,
    v4: Option<std::net::Ipv4Addr>,
    v6: Option<std::net::Ipv6Addr>,
    ttl: u32,
) -> Option<DnsRecord> {
    match qtype {
        QueryType::A => v4.map(|addr| DnsRecord::A {
            domain: domain.to_string(),
            addr,
            ttl,
        }),
        QueryType::AAAA => v6.map(|addr| DnsRecord::AAAA {
            domain: domain.to_string(),
            addr,
            ttl,
        }),
        _ => None,
    }
}

enum Disposition {
    Leader(broadcast::Sender<Option<DnsPacket>>),
    Follower(broadcast::Receiver<Option<DnsPacket>>),
}

fn acquire_inflight(inflight: &Mutex<InflightMap>, key: (String, QueryType)) -> Disposition {
    let mut map = inflight.lock().unwrap();
    if let Some(tx) = map.get(&key) {
        Disposition::Follower(tx.subscribe())
    } else {
        let (tx, _) = broadcast::channel::<Option<DnsPacket>>(1);
        map.insert(key, tx.clone());
        Disposition::Leader(tx)
    }
}

/// Run a resolve function with in-flight coalescing. Multiple concurrent calls
/// for the same key share a single resolution — the first caller (leader)
/// executes `resolve_fn`, and followers wait for the broadcast result. The
/// leader's successful path is tagged with `leader_path` so callers that
/// share this helper (recursive, forwarded-rule, forward-upstream) keep their
/// own observability without duplicating the inflight map.
async fn resolve_coalesced<F, Fut>(
    inflight: &Mutex<InflightMap>,
    key: (String, QueryType),
    query: &DnsPacket,
    leader_path: QueryPath,
    resolve_fn: F,
) -> (DnsPacket, QueryPath, Option<String>)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = crate::Result<DnsPacket>>,
{
    let disposition = acquire_inflight(inflight, key.clone());

    match disposition {
        Disposition::Follower(mut rx) => match rx.recv().await {
            Ok(Some(mut resp)) => {
                resp.header.id = query.header.id;
                (resp, QueryPath::Coalesced, None)
            }
            _ => (
                DnsPacket::response_from(query, ResultCode::SERVFAIL),
                QueryPath::UpstreamError,
                None,
            ),
        },
        Disposition::Leader(tx) => {
            let guard = InflightGuard { inflight, key };
            let result = resolve_fn().await;
            drop(guard);

            match result {
                Ok(resp) => {
                    let _ = tx.send(Some(resp.clone()));
                    (resp, leader_path, None)
                }
                Err(e) => {
                    let _ = tx.send(None);
                    let err_msg = e.to_string();
                    (
                        DnsPacket::response_from(query, ResultCode::SERVFAIL),
                        QueryPath::UpstreamError,
                        Some(err_msg),
                    )
                }
            }
        }
    }
}

struct InflightGuard<'a> {
    inflight: &'a Mutex<InflightMap>,
    key: (String, QueryType),
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.inflight.lock().unwrap().remove(&self.key);
    }
}

/// Emit the log lines shared by the three upstream branches (Forwarded,
/// Recursive, Upstream) after `resolve_coalesced` returns. Leader-success
/// and transport-tagging stay at the call site since they diverge per
/// branch, but the Coalesced debug and UpstreamError error are identical
/// except for the label.
fn log_coalesced_outcome(
    src_addr: SocketAddr,
    qtype: QueryType,
    qname: &str,
    path: QueryPath,
    err: Option<&str>,
    label: &str,
) {
    match path {
        QueryPath::Coalesced => debug!("{} | {:?} {} | COALESCED", src_addr, qtype, qname),
        QueryPath::UpstreamError => error!(
            "{} | {:?} {} | {} ERROR | {}",
            src_addr,
            qtype,
            qname,
            label,
            err.unwrap_or("leader failed")
        ),
        _ => {}
    }
}

fn special_use_response(query: &DnsPacket, qname: &str, qtype: QueryType) -> DnsPacket {
    use std::net::{Ipv4Addr, Ipv6Addr};
    if qname == "ipv4only.arpa" {
        // RFC 8880: well-known NAT64 addresses
        let mut resp = DnsPacket::response_from(query, ResultCode::NOERROR);
        let domain = qname.to_string();
        match qtype {
            QueryType::A => {
                resp.answers.push(DnsRecord::A {
                    domain: domain.clone(),
                    addr: Ipv4Addr::new(192, 0, 0, 170),
                    ttl: 300,
                });
                resp.answers.push(DnsRecord::A {
                    domain,
                    addr: Ipv4Addr::new(192, 0, 0, 171),
                    ttl: 300,
                });
            }
            QueryType::AAAA => {
                resp.answers.push(DnsRecord::AAAA {
                    domain,
                    addr: Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0xc000, 0x00aa),
                    ttl: 300,
                });
            }
            _ => {}
        }
        resp
    } else {
        DnsPacket::response_from(query, ResultCode::NXDOMAIN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};
    use tokio::sync::broadcast;

    // ---- InflightGuard unit tests ----

    #[test]
    fn inflight_guard_removes_key_on_drop() {
        let map: Mutex<InflightMap> = Mutex::new(HashMap::new());
        let key = ("example.com".to_string(), QueryType::A);
        let (tx, _) = broadcast::channel::<Option<DnsPacket>>(1);
        map.lock().unwrap().insert(key.clone(), tx);

        assert_eq!(map.lock().unwrap().len(), 1);
        {
            let _guard = InflightGuard {
                inflight: &map,
                key: key.clone(),
            };
        } // guard dropped here
        assert!(map.lock().unwrap().is_empty());
    }

    #[test]
    fn inflight_guard_only_removes_own_key() {
        let map: Mutex<InflightMap> = Mutex::new(HashMap::new());
        let key_a = ("a.com".to_string(), QueryType::A);
        let key_b = ("b.com".to_string(), QueryType::A);
        let (tx_a, _) = broadcast::channel::<Option<DnsPacket>>(1);
        let (tx_b, _) = broadcast::channel::<Option<DnsPacket>>(1);
        map.lock().unwrap().insert(key_a.clone(), tx_a);
        map.lock().unwrap().insert(key_b.clone(), tx_b);

        {
            let _guard = InflightGuard {
                inflight: &map,
                key: key_a,
            };
        }
        let m = map.lock().unwrap();
        assert_eq!(m.len(), 1);
        assert!(m.contains_key(&key_b));
    }

    #[test]
    fn inflight_guard_same_domain_different_qtype_independent() {
        let map: Mutex<InflightMap> = Mutex::new(HashMap::new());
        let key_a = ("example.com".to_string(), QueryType::A);
        let key_aaaa = ("example.com".to_string(), QueryType::AAAA);
        let (tx_a, _) = broadcast::channel::<Option<DnsPacket>>(1);
        let (tx_aaaa, _) = broadcast::channel::<Option<DnsPacket>>(1);
        map.lock().unwrap().insert(key_a.clone(), tx_a);
        map.lock().unwrap().insert(key_aaaa.clone(), tx_aaaa);

        {
            let _guard = InflightGuard {
                inflight: &map,
                key: key_a,
            };
        }
        let m = map.lock().unwrap();
        assert_eq!(m.len(), 1);
        assert!(m.contains_key(&key_aaaa));
    }

    // ---- Coalescing disposition tests (via acquire_inflight) ----

    #[test]
    fn first_caller_becomes_leader() {
        let map: Mutex<InflightMap> = Mutex::new(HashMap::new());
        let key = ("test.com".to_string(), QueryType::A);

        let d = acquire_inflight(&map, key.clone());
        assert!(matches!(d, Disposition::Leader(_)));
        assert_eq!(map.lock().unwrap().len(), 1);
    }

    #[test]
    fn second_caller_becomes_follower() {
        let map: Mutex<InflightMap> = Mutex::new(HashMap::new());
        let key = ("test.com".to_string(), QueryType::A);

        let _leader = acquire_inflight(&map, key.clone());
        let follower = acquire_inflight(&map, key);
        assert!(matches!(follower, Disposition::Follower(_)));
        // Map still has exactly 1 entry — follower subscribes, doesn't insert
        assert_eq!(map.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn leader_broadcast_reaches_follower() {
        let map: Mutex<InflightMap> = Mutex::new(HashMap::new());
        let key = ("test.com".to_string(), QueryType::A);

        let leader = acquire_inflight(&map, key.clone());
        let follower = acquire_inflight(&map, key);

        let tx = match leader {
            Disposition::Leader(tx) => tx,
            _ => panic!("expected leader"),
        };
        let mut rx = match follower {
            Disposition::Follower(rx) => rx,
            _ => panic!("expected follower"),
        };

        let mut resp = DnsPacket::new();
        resp.header.id = 42;
        resp.answers.push(DnsRecord::A {
            domain: "test.com".into(),
            addr: Ipv4Addr::new(1, 2, 3, 4),
            ttl: 300,
        });
        let _ = tx.send(Some(resp));

        let received = rx.recv().await.unwrap().unwrap();
        assert_eq!(received.header.id, 42);
        assert_eq!(received.answers.len(), 1);
    }

    #[tokio::test]
    async fn leader_none_signals_failure_to_follower() {
        let map: Mutex<InflightMap> = Mutex::new(HashMap::new());
        let key = ("test.com".to_string(), QueryType::A);

        let leader = acquire_inflight(&map, key.clone());
        let follower = acquire_inflight(&map, key);

        let tx = match leader {
            Disposition::Leader(tx) => tx,
            _ => panic!("expected leader"),
        };
        let mut rx = match follower {
            Disposition::Follower(rx) => rx,
            _ => panic!("expected follower"),
        };

        let _ = tx.send(None);
        assert!(rx.recv().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn multiple_followers_all_receive_via_acquire() {
        let map: Mutex<InflightMap> = Mutex::new(HashMap::new());
        let key = ("multi.com".to_string(), QueryType::A);

        let leader = acquire_inflight(&map, key.clone());
        let f1 = acquire_inflight(&map, key.clone());
        let f2 = acquire_inflight(&map, key.clone());
        let f3 = acquire_inflight(&map, key);

        let tx = match leader {
            Disposition::Leader(tx) => tx,
            _ => panic!("expected leader"),
        };

        let mut resp = DnsPacket::new();
        resp.answers.push(DnsRecord::A {
            domain: "multi.com".into(),
            addr: Ipv4Addr::new(10, 0, 0, 1),
            ttl: 60,
        });
        let _ = tx.send(Some(resp));

        for f in [f1, f2, f3] {
            let mut rx = match f {
                Disposition::Follower(rx) => rx,
                _ => panic!("expected follower"),
            };
            let r = rx.recv().await.unwrap().unwrap();
            assert_eq!(r.answers.len(), 1);
        }
    }

    // ---- Integration: resolve_coalesced with mock futures ----

    fn mock_response(domain: &str) -> DnsPacket {
        let mut resp = DnsPacket::new();
        resp.header.response = true;
        resp.header.rescode = ResultCode::NOERROR;
        resp.answers.push(DnsRecord::A {
            domain: domain.to_string(),
            addr: Ipv4Addr::new(10, 0, 0, 1),
            ttl: 300,
        });
        resp
    }

    #[tokio::test]
    async fn concurrent_queries_coalesce_to_single_resolution() {
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let resolve_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

        let mut handles = Vec::new();
        for i in 0..5u16 {
            let count = resolve_count.clone();
            let inf = inflight.clone();
            let key = ("coalesce.test".to_string(), QueryType::A);
            let query = DnsPacket::query(100 + i, "coalesce.test", QueryType::A);
            handles.push(tokio::spawn(async move {
                resolve_coalesced(&inf, key, &query, QueryPath::Recursive, || async {
                    count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Ok(mock_response("coalesce.test"))
                })
                .await
            }));
        }

        let mut paths = Vec::new();
        for h in handles {
            let (_, path, _) = h.await.unwrap();
            paths.push(path);
        }

        let actual = resolve_count.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(actual, 1, "expected 1 resolution, got {}", actual);

        let recursive = paths.iter().filter(|p| **p == QueryPath::Recursive).count();
        let coalesced = paths.iter().filter(|p| **p == QueryPath::Coalesced).count();
        assert_eq!(recursive, 1, "expected 1 RECURSIVE, got {}", recursive);
        assert_eq!(coalesced, 4, "expected 4 COALESCED, got {}", coalesced);

        assert!(inflight.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn different_qtypes_not_coalesced() {
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let resolve_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

        let inf1 = inflight.clone();
        let inf2 = inflight.clone();
        let count1 = resolve_count.clone();
        let count2 = resolve_count.clone();

        let query_a = DnsPacket::query(200, "same.domain", QueryType::A);
        let query_aaaa = DnsPacket::query(201, "same.domain", QueryType::AAAA);

        let h1 = tokio::spawn(async move {
            resolve_coalesced(
                &inf1,
                ("same.domain".to_string(), QueryType::A),
                &query_a,
                QueryPath::Recursive,
                || async {
                    count1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok(mock_response("same.domain"))
                },
            )
            .await
        });
        let h2 = tokio::spawn(async move {
            resolve_coalesced(
                &inf2,
                ("same.domain".to_string(), QueryType::AAAA),
                &query_aaaa,
                QueryPath::Recursive,
                || async {
                    count2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok(mock_response("same.domain"))
                },
            )
            .await
        });

        let (_, path1, _) = h1.await.unwrap();
        let (_, path2, _) = h2.await.unwrap();

        let actual = resolve_count.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(actual, 2, "A and AAAA should each resolve, got {}", actual);
        assert_eq!(path1, QueryPath::Recursive);
        assert_eq!(path2, QueryPath::Recursive);

        assert!(inflight.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn inflight_map_cleaned_after_error() {
        let inflight: Mutex<InflightMap> = Mutex::new(HashMap::new());
        let query = DnsPacket::query(300, "will-fail.test", QueryType::A);

        let (_, path, _) = resolve_coalesced(
            &inflight,
            ("will-fail.test".to_string(), QueryType::A),
            &query,
            QueryPath::Recursive,
            || async { Err::<DnsPacket, _>("upstream timeout".into()) },
        )
        .await;

        assert_eq!(path, QueryPath::UpstreamError);
        assert!(inflight.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn follower_gets_servfail_when_leader_fails() {
        let inflight = Arc::new(Mutex::new(HashMap::new()));

        let mut handles = Vec::new();
        for i in 0..3u16 {
            let inf = inflight.clone();
            let query = DnsPacket::query(400 + i, "fail.test", QueryType::A);
            handles.push(tokio::spawn(async move {
                resolve_coalesced(
                    &inf,
                    ("fail.test".to_string(), QueryType::A),
                    &query,
                    QueryPath::Recursive,
                    || async {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        Err::<DnsPacket, _>("upstream error".into())
                    },
                )
                .await
            }));
        }

        let mut paths = Vec::new();
        for h in handles {
            let (resp, path, _) = h.await.unwrap();
            assert_eq!(resp.header.rescode, ResultCode::SERVFAIL);
            assert_eq!(
                resp.questions.len(),
                1,
                "SERVFAIL must echo question section"
            );
            assert_eq!(resp.questions[0].name, "fail.test");
            paths.push(path);
        }

        let errors = paths
            .iter()
            .filter(|p| **p == QueryPath::UpstreamError)
            .count();
        assert_eq!(errors, 3, "all 3 should be UpstreamError, got {}", errors);

        assert!(inflight.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn servfail_leader_includes_question_section() {
        let inflight: Mutex<InflightMap> = Mutex::new(HashMap::new());
        let query = DnsPacket::query(500, "question.test", QueryType::A);

        let (resp, _, _) = resolve_coalesced(
            &inflight,
            ("question.test".to_string(), QueryType::A),
            &query,
            QueryPath::Recursive,
            || async { Err::<DnsPacket, _>("fail".into()) },
        )
        .await;

        assert_eq!(resp.header.rescode, ResultCode::SERVFAIL);
        assert_eq!(
            resp.questions.len(),
            1,
            "SERVFAIL must echo question section"
        );
        assert_eq!(resp.questions[0].name, "question.test");
        assert_eq!(resp.questions[0].qtype, QueryType::A);
        assert_eq!(resp.header.id, 500);
    }

    #[tokio::test]
    async fn leader_error_preserves_message() {
        let inflight: Mutex<InflightMap> = Mutex::new(HashMap::new());
        let query = DnsPacket::query(700, "err-msg.test", QueryType::A);

        let (_, path, err) = resolve_coalesced(
            &inflight,
            ("err-msg.test".to_string(), QueryType::A),
            &query,
            QueryPath::Recursive,
            || async { Err::<DnsPacket, _>("connection refused by upstream".into()) },
        )
        .await;

        assert_eq!(path, QueryPath::UpstreamError);
        assert_eq!(
            err.as_deref(),
            Some("connection refused by upstream"),
            "error message must be preserved for logging"
        );
    }

    // ---- Full-pipeline resolve_query tests ----

    /// Send a query through the full resolve_query pipeline and return
    /// the parsed response + query path.
    async fn resolve_in_test(
        ctx: &Arc<ServerCtx>,
        domain: &str,
        qtype: QueryType,
    ) -> (DnsPacket, QueryPath) {
        resolve_in_test_with_query(ctx, DnsPacket::query(0xBEEF, domain, qtype)).await
    }

    async fn resolve_in_test_with_query(
        ctx: &Arc<ServerCtx>,
        query: DnsPacket,
    ) -> (DnsPacket, QueryPath) {
        let mut buf = BytePacketBuffer::new();
        query.write(&mut buf).unwrap();
        let raw = &buf.buf[..buf.pos];
        let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        let (resp_buf, path) = resolve_query(query, raw, src, ctx, Transport::Udp)
            .await
            .unwrap();

        let mut resp_parse_buf = BytePacketBuffer::from_bytes(resp_buf.filled());
        let resp = DnsPacket::from_buffer(&mut resp_parse_buf).unwrap();
        (resp, path)
    }

    #[tokio::test]
    async fn special_use_private_ptr_returns_nxdomain() {
        let ctx = Arc::new(crate::testutil::test_ctx().await);
        let (resp, path) =
            resolve_in_test(&ctx, "153.188.168.192.in-addr.arpa", QueryType::PTR).await;
        assert_eq!(path, QueryPath::Local);
        assert_eq!(resp.header.rescode, ResultCode::NXDOMAIN);
    }

    #[tokio::test]
    async fn forwarding_rule_overrides_special_use_domain() {
        let mut resp = DnsPacket::new();
        resp.header.response = true;
        resp.header.rescode = ResultCode::NOERROR;
        let upstream_addr = crate::testutil::mock_upstream(resp).await;

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.forwarding_rules = vec![ForwardingRule::new(
            "168.192.in-addr.arpa".to_string(),
            UpstreamPool::new(vec![Upstream::Udp(upstream_addr)], vec![]),
        )];
        let ctx = Arc::new(ctx);

        let (resp, path) =
            resolve_in_test(&ctx, "153.188.168.192.in-addr.arpa", QueryType::PTR).await;

        assert_eq!(
            path,
            QueryPath::Forwarded,
            "forwarding rule must take precedence over special-use NXDOMAIN"
        );
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
    }

    #[tokio::test]
    async fn pipeline_override_takes_precedence() {
        let ctx = crate::testutil::test_ctx().await;
        ctx.overrides
            .write()
            .unwrap()
            .insert("override.test", "1.2.3.4", 60, None)
            .unwrap();
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "override.test", QueryType::A).await;
        assert_eq!(path, QueryPath::Overridden);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert_eq!(resp.answers.len(), 1);
    }

    #[tokio::test]
    async fn pipeline_localhost_resolves_to_loopback() {
        let ctx = Arc::new(crate::testutil::test_ctx().await);

        let (resp, path) = resolve_in_test(&ctx, "localhost", QueryType::A).await;
        assert_eq!(path, QueryPath::Local);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::LOCALHOST),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_localhost_subdomain_resolves_to_loopback() {
        let ctx = Arc::new(crate::testutil::test_ctx().await);

        let (resp, path) = resolve_in_test(&ctx, "app.localhost", QueryType::A).await;
        assert_eq!(path, QueryPath::Local);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::LOCALHOST),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_local_zone_returns_configured_record() {
        let mut ctx = crate::testutil::test_ctx().await;
        ctx.zone_map = crate::config::ZoneMap::from_exact(vec![DnsRecord::A {
            domain: "myapp.test".to_string(),
            addr: Ipv4Addr::new(10, 0, 0, 42),
            ttl: 300,
        }]);
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "myapp.test", QueryType::A).await;
        assert_eq!(path, QueryPath::Local);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 42)),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_wildcard_zone_synthesizes_with_qname_owner() {
        use crate::config::build_zone_map;
        let mut ctx = crate::testutil::test_ctx().await;
        ctx.zone_map = build_zone_map(&[crate::config::ZoneRecord {
            domain: "*.pool.ntp.org".into(),
            record_type: "A".into(),
            value: "10.20.30.40".into(),
            ttl: 300,
        }])
        .unwrap();
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "time2.pool.ntp.org", QueryType::A).await;
        assert_eq!(path, QueryPath::Local);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        match &resp.answers[0] {
            DnsRecord::A { domain, addr, .. } => {
                assert_eq!(domain, "time2.pool.ntp.org", "owner must be QNAME");
                assert_eq!(*addr, Ipv4Addr::new(10, 20, 30, 40));
            }
            other => panic!("expected A, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_wildcard_zone_nodata_does_not_fall_through() {
        // Wildcard parent matched but qtype absent → NOERROR/empty,
        // NOT an upstream lookup. Upstream points at a blackhole, so a
        // fall-through would SERVFAIL after timeout.
        use crate::config::build_zone_map;
        let mut ctx = crate::testutil::test_ctx().await;
        ctx.zone_map = build_zone_map(&[crate::config::ZoneRecord {
            domain: "*.foo".into(),
            record_type: "A".into(),
            value: "10.0.0.1".into(),
            ttl: 300,
        }])
        .unwrap();
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "x.foo", QueryType::AAAA).await;
        assert_eq!(path, QueryPath::Local, "must answer locally, not upstream");
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert!(resp.answers.is_empty(), "NoData must return empty answers");
    }

    #[tokio::test]
    async fn pipeline_tld_proxy_resolves_service() {
        let ctx = crate::testutil::test_ctx().await;
        ctx.services.lock().unwrap().insert("grafana", 3000, None);
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "grafana.numa", QueryType::A).await;
        assert_eq!(path, QueryPath::Local);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::LOCALHOST),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    /// Unknown name in the proxy TLD must NXDOMAIN, not silently return
    /// loopback. Returning loopback for unknown `.numa` names is a footgun:
    /// typo'd hostnames and stale references end up routing to the resolver
    /// host instead of failing fast.
    #[tokio::test]
    async fn pipeline_tld_proxy_unknown_returns_nxdomain() {
        let ctx = Arc::new(crate::testutil::test_ctx().await);

        let (resp_a, path_a) = resolve_in_test(&ctx, "no-such-service.numa", QueryType::A).await;
        assert_eq!(path_a, QueryPath::Local);
        assert_eq!(resp_a.header.rescode, ResultCode::NXDOMAIN);
        assert!(resp_a.answers.is_empty());

        let (resp_aaaa, path_aaaa) =
            resolve_in_test(&ctx, "no-such-service.numa", QueryType::AAAA).await;
        assert_eq!(path_aaaa, QueryPath::Local);
        assert_eq!(resp_aaaa.header.rescode, ResultCode::NXDOMAIN);
        assert!(resp_aaaa.answers.is_empty());
    }

    /// LAN peer with an IPv4 address: A → native v4, AAAA → v4-mapped v6.
    #[tokio::test]
    async fn pipeline_tld_proxy_v4_peer_returns_native_a_and_mapped_aaaa() {
        let ctx = crate::testutil::test_ctx().await;
        ctx.lan_peers
            .lock()
            .unwrap()
            .update("10.0.0.5".parse().unwrap(), &[("kiosk".into(), 8080)]);
        let ctx = Arc::new(ctx);

        let (resp_a, _) = resolve_in_test(&ctx, "kiosk.numa", QueryType::A).await;
        assert_eq!(resp_a.header.rescode, ResultCode::NOERROR);
        match &resp_a.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 5)),
            other => panic!("expected A record, got {:?}", other),
        }

        let (resp_aaaa, _) = resolve_in_test(&ctx, "kiosk.numa", QueryType::AAAA).await;
        assert_eq!(resp_aaaa.header.rescode, ResultCode::NOERROR);
        match &resp_aaaa.answers[0] {
            DnsRecord::AAAA { addr, .. } => {
                assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped())
            }
            other => panic!("expected AAAA record, got {:?}", other),
        }
    }

    /// LAN peer with only an IPv6 address: AAAA → native v6, A → NODATA
    /// (NOERROR with empty answer section, *not* loopback).
    #[tokio::test]
    async fn pipeline_tld_proxy_v6_only_peer_native_aaaa_nodata_a() {
        let v6: Ipv6Addr = "2001:db8::42".parse().unwrap();
        let ctx = crate::testutil::test_ctx().await;
        ctx.lan_peers
            .lock()
            .unwrap()
            .update(v6.into(), &[("ipv6host".into(), 22)]);
        let ctx = Arc::new(ctx);

        let (resp_aaaa, _) = resolve_in_test(&ctx, "ipv6host.numa", QueryType::AAAA).await;
        assert_eq!(resp_aaaa.header.rescode, ResultCode::NOERROR);
        match &resp_aaaa.answers[0] {
            DnsRecord::AAAA { addr, .. } => assert_eq!(*addr, v6),
            other => panic!("expected AAAA record, got {:?}", other),
        }

        let (resp_a, _) = resolve_in_test(&ctx, "ipv6host.numa", QueryType::A).await;
        assert_eq!(resp_a.header.rescode, ResultCode::NOERROR);
        assert!(
            resp_a.answers.is_empty(),
            "v6-only peer + A query must be NODATA, not loopback"
        );
    }

    #[tokio::test]
    async fn pipeline_filter_aaaa_returns_nodata() {
        let mut ctx = crate::testutil::test_ctx().await;
        ctx.filter_aaaa = true;
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "example.com", QueryType::AAAA).await;
        assert_eq!(path, QueryPath::Local);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert!(resp.answers.is_empty(), "AAAA must be filtered to NODATA");
    }

    #[tokio::test]
    async fn pipeline_filter_aaaa_leaves_a_queries_alone() {
        let upstream_resp =
            crate::testutil::a_record_response("example.com", Ipv4Addr::new(93, 184, 216, 34), 300);
        let upstream_addr = crate::testutil::mock_upstream(upstream_resp).await;

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.filter_aaaa = true;
        ctx.upstream_pool
            .lock()
            .unwrap()
            .set_primary(vec![Upstream::Udp(upstream_addr)]);
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "example.com", QueryType::A).await;
        assert_eq!(path, QueryPath::Upstream);
        assert_eq!(resp.answers.len(), 1);
    }

    #[tokio::test]
    async fn pipeline_filter_aaaa_respects_override() {
        let mut ctx = crate::testutil::test_ctx().await;
        ctx.filter_aaaa = true;
        ctx.overrides
            .write()
            .unwrap()
            .insert("v6.test", "2001:db8::1", 60, None)
            .unwrap();
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "v6.test", QueryType::AAAA).await;
        assert_eq!(path, QueryPath::Overridden);
        assert_eq!(resp.answers.len(), 1, "override must win over filter");
    }

    #[tokio::test]
    async fn pipeline_filter_aaaa_strips_ipv6hint_from_https_and_svcb() {
        let rdata = crate::svcb::build_rdata(
            1,
            &[],
            &[
                (1, vec![0x02, b'h', b'3']),
                (
                    6,
                    vec![
                        0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
                    ],
                ),
            ],
        );

        let mut pkt = DnsPacket::new();
        pkt.header.response = true;
        pkt.header.rescode = ResultCode::NOERROR;
        pkt.questions.push(crate::question::DnsQuestion {
            name: "hints.test".to_string(),
            qtype: QueryType::HTTPS,
        });
        pkt.answers.push(DnsRecord::UNKNOWN {
            domain: "hints.test".to_string(),
            qtype: 65,
            data: rdata.clone(),
            ttl: 300,
        });

        let mut svcb_pkt = pkt.clone();
        svcb_pkt.questions[0].name = "svc.test".to_string();
        svcb_pkt.questions[0].qtype = QueryType::SVCB;
        if let DnsRecord::UNKNOWN { domain, qtype, .. } = &mut svcb_pkt.answers[0] {
            *domain = "svc.test".to_string();
            *qtype = 64;
        }

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.filter_aaaa = true;
        ctx.cache
            .write()
            .unwrap()
            .insert("hints.test", QueryType::HTTPS, &pkt);
        ctx.cache
            .write()
            .unwrap()
            .insert("svc.test", QueryType::SVCB, &svcb_pkt);
        let ctx = Arc::new(ctx);

        for (name, qtype, label) in [
            ("hints.test", QueryType::HTTPS, "HTTPS"),
            ("svc.test", QueryType::SVCB, "SVCB"),
        ] {
            let (resp, path) = resolve_in_test(&ctx, name, qtype).await;
            assert_eq!(path, QueryPath::Cached, "{label}");
            assert_eq!(resp.answers.len(), 1, "{label}");
            match &resp.answers[0] {
                DnsRecord::UNKNOWN { data, .. } => {
                    assert!(
                        data.len() < rdata.len(),
                        "{label}: ipv6hint (20 bytes) must be removed"
                    );
                    // Bytes for key=6 must not appear at any 4-byte boundary in the
                    // params section — cheap structural check.
                    assert!(
                        !data.windows(4).any(|w| w == [0, 6, 0, 16]),
                        "{label}: ipv6hint TLV header must be absent"
                    );
                }
                other => panic!("{label}: expected UNKNOWN record, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn pipeline_filter_aaaa_preserves_ipv6hint_for_dnssec_clients() {
        // Regression guard for the DO-bit gate in resolve_query: modifying
        // HTTPS rdata invalidates any accompanying RRSIG, so a DO=1 client
        // must receive the record untouched even when filter_aaaa is on.
        let rdata = crate::svcb::build_rdata(
            1,
            &[],
            &[(
                6,
                vec![
                    0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
                ],
            )],
        );

        let mut pkt = DnsPacket::new();
        pkt.header.response = true;
        pkt.header.rescode = ResultCode::NOERROR;
        pkt.questions.push(crate::question::DnsQuestion {
            name: "hints.test".to_string(),
            qtype: QueryType::HTTPS,
        });
        pkt.answers.push(DnsRecord::UNKNOWN {
            domain: "hints.test".to_string(),
            qtype: 65,
            data: rdata.clone(),
            ttl: 300,
        });

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.filter_aaaa = true;
        ctx.cache
            .write()
            .unwrap()
            .insert("hints.test", QueryType::HTTPS, &pkt);
        let ctx = Arc::new(ctx);

        // Build a query with EDNS DO bit set — can't use resolve_in_test
        // because it constructs a plain query without EDNS.
        let mut query = DnsPacket::query(0xBEEF, "hints.test", QueryType::HTTPS);
        query.edns = Some(crate::packet::EdnsOpt {
            do_bit: true,
            ..Default::default()
        });
        let mut buf = BytePacketBuffer::new();
        query.write(&mut buf).unwrap();
        let raw = &buf.buf[..buf.pos];
        let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        let (resp_buf, _) = resolve_query(query, raw, src, &ctx, Transport::Udp)
            .await
            .unwrap();
        let mut resp_parse_buf = BytePacketBuffer::from_bytes(resp_buf.filled());
        let resp = DnsPacket::from_buffer(&mut resp_parse_buf).unwrap();

        match &resp.answers[0] {
            DnsRecord::UNKNOWN { data, .. } => {
                assert_eq!(
                    data, &rdata,
                    "ipv6hint must be preserved for DO-bit clients"
                );
            }
            other => panic!("expected UNKNOWN record, got {:?}", other),
        }
    }

    async fn resolve_from_src(
        ctx: &Arc<ServerCtx>,
        src: SocketAddr,
        domain: &str,
        qtype: QueryType,
    ) -> (DnsPacket, QueryPath) {
        let query = DnsPacket::query(0xBEEF, domain, qtype);
        let mut buf = BytePacketBuffer::new();
        query.write(&mut buf).unwrap();
        let raw = &buf.buf[..buf.pos];
        let (resp_buf, path) = resolve_query(query, raw, src, ctx, Transport::Udp)
            .await
            .unwrap();
        let mut resp_parse_buf = BytePacketBuffer::from_bytes(resp_buf.filled());
        let resp = DnsPacket::from_buffer(&mut resp_parse_buf).unwrap();
        (resp, path)
    }

    fn ctx_with_policy(
        from: &[&str],
        block: &[&str],
        allow: &[&str],
    ) -> crate::client_policy::ClientPolicySet {
        crate::client_policy::ClientPolicySet::from_configs(&[
            crate::client_policy::ClientPolicyConfig {
                from: from.iter().map(|s| s.to_string()).collect(),
                block: block.iter().map(|s| s.to_string()).collect(),
                allow: allow.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
        ])
        .unwrap()
    }

    #[tokio::test]
    async fn pipeline_client_policy_blocks_matching_client() {
        let mut ctx = crate::testutil::test_ctx().await;
        ctx.client_policy = ctx_with_policy(&["192.168.1.50/32"], &["youtube.com"], &[]);
        let ctx = Arc::new(ctx);

        let blocked_src: SocketAddr = "192.168.1.50:5000".parse().unwrap();
        let (resp, path) = resolve_from_src(&ctx, blocked_src, "m.youtube.com", QueryType::A).await;
        assert_eq!(path, QueryPath::Blocked);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::UNSPECIFIED),
            other => panic!("expected sinkhole A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_client_policy_skips_unmatched_client() {
        // Different client IP — policy must not apply. Falls through to
        // forwarding, so we set up an upstream that confirms the query escaped.
        let upstream_resp =
            crate::testutil::a_record_response("youtube.com", Ipv4Addr::new(8, 8, 8, 8), 60);
        let upstream_addr = crate::testutil::mock_upstream(upstream_resp).await;

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.client_policy = ctx_with_policy(&["192.168.1.50/32"], &["youtube.com"], &[]);
        ctx.forwarding_rules = vec![ForwardingRule::new(
            "youtube.com".to_string(),
            UpstreamPool::new(vec![Upstream::Udp(upstream_addr)], vec![]),
        )];
        let ctx = Arc::new(ctx);

        let other_src: SocketAddr = "192.168.1.99:5000".parse().unwrap();
        let (resp, path) = resolve_from_src(&ctx, other_src, "youtube.com", QueryType::A).await;
        assert_eq!(path, QueryPath::Forwarded);
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::new(8, 8, 8, 8)),
            other => panic!("expected forwarded A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_client_policy_allow_bypasses_global_blocklist() {
        // Domain is in the global blocklist; client has an allow rule for it.
        let upstream_resp =
            crate::testutil::a_record_response("ads.example.com", Ipv4Addr::new(1, 2, 3, 4), 60);
        let upstream_addr = crate::testutil::mock_upstream(upstream_resp).await;

        let mut ctx = crate::testutil::test_ctx().await;
        let mut domains = std::collections::HashSet::new();
        domains.insert("ads.example.com".to_string());
        ctx.blocklist.write().unwrap().swap_domains(domains, vec![]);
        ctx.client_policy = ctx_with_policy(&["192.168.1.50"], &[], &["ads.example.com"]);
        ctx.forwarding_rules = vec![ForwardingRule::new(
            "example.com".to_string(),
            UpstreamPool::new(vec![Upstream::Udp(upstream_addr)], vec![]),
        )];
        let ctx = Arc::new(ctx);

        let exempt_src: SocketAddr = "192.168.1.50:5000".parse().unwrap();
        let (resp, path) =
            resolve_from_src(&ctx, exempt_src, "ads.example.com", QueryType::A).await;
        assert_eq!(path, QueryPath::Forwarded);
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::new(1, 2, 3, 4)),
            other => panic!(
                "expected forwarded A record (allow bypass), got {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn pipeline_client_policy_loopback_falls_through_to_global_blocklist() {
        // A policy that would block this domain for 127/8 must NOT trap the
        // local stub resolver — loopback is always passthrough. Global
        // blocklist still applies.
        let mut ctx = crate::testutil::test_ctx().await;
        let mut domains = std::collections::HashSet::new();
        domains.insert("ads.tracker.test".to_string());
        ctx.blocklist.write().unwrap().swap_domains(domains, vec![]);
        ctx.client_policy = ctx_with_policy(&["127.0.0.0/8"], &["unrelated.test"], &[]);
        let ctx = Arc::new(ctx);

        let (_, path) = resolve_in_test(&ctx, "ads.tracker.test", QueryType::A).await;
        assert_eq!(path, QueryPath::Blocked, "global blocklist still applies");
    }

    #[tokio::test]
    async fn pipeline_blocklist_sinkhole() {
        let ctx = crate::testutil::test_ctx().await;
        let mut domains = std::collections::HashSet::new();
        domains.insert("ads.tracker.test".to_string());
        ctx.blocklist.write().unwrap().swap_domains(domains, vec![]);
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "ads.tracker.test", QueryType::A).await;
        assert_eq!(path, QueryPath::Blocked);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::UNSPECIFIED),
            other => panic!("expected sinkhole A record, got {:?}", other),
        }
    }

    #[test]
    fn answer_record_picks_family_or_nodata() {
        let v4 = Ipv4Addr::UNSPECIFIED;
        let v6 = Ipv6Addr::UNSPECIFIED;

        assert!(matches!(
            answer_record("x.test", QueryType::A, Some(v4), Some(v6), 60),
            Some(DnsRecord::A { .. })
        ));
        assert!(matches!(
            answer_record("x.test", QueryType::AAAA, Some(v4), Some(v6), 60),
            Some(DnsRecord::AAAA { .. })
        ));
        // Family absent → NODATA (v6-only peer answering an A query).
        assert!(answer_record("x.test", QueryType::A, None, Some(v6), 60).is_none());
        assert!(answer_record("x.test", QueryType::AAAA, Some(v4), None, 60).is_none());
        // Non-address qtype → NODATA regardless of available families.
        assert!(answer_record("x.test", QueryType::HTTPS, Some(v4), Some(v6), 60).is_none());
    }

    #[tokio::test]
    async fn pipeline_blocklist_nodata_for_non_address_qtype() {
        let ctx = crate::testutil::test_ctx().await;
        let mut domains = std::collections::HashSet::new();
        domains.insert("ads.tracker.test".to_string());
        ctx.blocklist.write().unwrap().swap_domains(domains, vec![]);
        let ctx = Arc::new(ctx);

        // Blocked A → 0.0.0.0 sinkhole.
        let (a_resp, a_path) = resolve_in_test(&ctx, "ads.tracker.test", QueryType::A).await;
        assert_eq!(a_path, QueryPath::Blocked);
        match &a_resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::UNSPECIFIED),
            other => panic!("expected sinkhole A record, got {:?}", other),
        }

        // Blocked HTTPS → clean NODATA (NOERROR, empty), not a qtype-mismatched A.
        let (https_resp, https_path) =
            resolve_in_test(&ctx, "ads.tracker.test", QueryType::HTTPS).await;
        assert_eq!(https_path, QueryPath::Blocked);
        assert_eq!(https_resp.header.rescode, ResultCode::NOERROR);
        assert!(https_resp.answers.is_empty());
    }

    #[tokio::test]
    async fn pipeline_cache_hit() {
        let ctx = Arc::new(crate::testutil::test_ctx().await);

        // Pre-populate cache with a response
        let mut pkt = DnsPacket::new();
        pkt.header.response = true;
        pkt.header.rescode = ResultCode::NOERROR;
        pkt.questions.push(crate::question::DnsQuestion {
            name: "cached.test".to_string(),
            qtype: QueryType::A,
        });
        pkt.answers.push(DnsRecord::A {
            domain: "cached.test".to_string(),
            addr: Ipv4Addr::new(5, 5, 5, 5),
            ttl: 3600,
        });
        ctx.cache
            .write()
            .unwrap()
            .insert("cached.test", QueryType::A, &pkt);

        let (resp, path) = resolve_in_test(&ctx, "cached.test", QueryType::A).await;
        assert_eq!(path, QueryPath::Cached);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
    }

    #[tokio::test]
    async fn pipeline_forwarding_returns_upstream_answer() {
        let upstream_resp =
            crate::testutil::a_record_response("internal.corp", Ipv4Addr::new(10, 1, 2, 3), 600);
        let upstream_addr = crate::testutil::mock_upstream(upstream_resp).await;

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.forwarding_rules = vec![ForwardingRule::new(
            "corp".to_string(),
            UpstreamPool::new(vec![Upstream::Udp(upstream_addr)], vec![]),
        )];
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "internal.corp", QueryType::A).await;
        assert_eq!(path, QueryPath::Forwarded);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0] {
            DnsRecord::A { domain, addr, .. } => {
                assert_eq!(domain, "internal.corp");
                assert_eq!(*addr, Ipv4Addr::new(10, 1, 2, 3));
            }
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_forwarding_fails_over_to_second_upstream() {
        let dead = crate::testutil::blackhole_upstream();

        let live_resp =
            crate::testutil::a_record_response("internal.corp", Ipv4Addr::new(10, 9, 9, 9), 600);
        let live = crate::testutil::mock_upstream(live_resp).await;

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.forwarding_rules = vec![ForwardingRule::new(
            "corp".to_string(),
            UpstreamPool::new(vec![Upstream::Udp(dead), Upstream::Udp(live)], vec![]),
        )];
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "internal.corp", QueryType::A).await;
        assert_eq!(path, QueryPath::Forwarded);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::new(10, 9, 9, 9)),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn pipeline_forwarding_malformed_upstream_yields_servfail() {
        // #142: pre-fix, a label byte with reserved high bits 01 was treated
        // as a length and silently consumed up to 191 bytes of garbage. This
        // packet's authority NS record starts with 0x40 (64 + reserved bits) —
        // pre-fix parsed cleanly and returned a bogus NS to the client.
        // Post-fix the parser rejects, surfacing as SERVFAIL.
        let mut wire = vec![
            0x01, 0x00, 0x81, 0x80, // id (patched), flags
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // QD=1 NS=1
            0x01, b'x', 0x04, b't', b'e', b's', b't', 0x00, // qname x.test
            0x00, 0x01, 0x00, 0x01, // A IN
            0x40, // authority name length: 64 with reserved bits 01
        ];
        wire.extend(std::iter::repeat_n(b'a', 64)); // 64 bytes of filler label
        wire.extend_from_slice(&[
            0x00, // name terminator
            0x00, 0x02, 0x00, 0x01, // NS IN
            0x00, 0x00, 0x0e, 0x10, // TTL 3600
            0x00, 0x02, 0xc0, 0x0c, // RDLEN=2, rdata = pointer to qname
        ]);

        let upstream_addr = crate::testutil::mock_upstream_raw(wire).await;

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.forwarding_rules = vec![ForwardingRule::new(
            "test".to_string(),
            UpstreamPool::new(vec![Upstream::Udp(upstream_addr)], vec![]),
        )];
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "x.test", QueryType::A).await;
        assert_eq!(path, QueryPath::UpstreamError);
        assert_eq!(resp.header.rescode, ResultCode::SERVFAIL);
        assert!(resp.answers.is_empty());
    }

    #[tokio::test]
    async fn pipeline_default_pool_reports_upstream_path() {
        let upstream_resp =
            crate::testutil::a_record_response("example.com", Ipv4Addr::new(93, 184, 216, 34), 300);
        let upstream_addr = crate::testutil::mock_upstream(upstream_resp).await;

        let ctx = crate::testutil::test_ctx().await;
        ctx.upstream_pool
            .lock()
            .unwrap()
            .set_primary(vec![Upstream::Udp(upstream_addr)]);
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "example.com", QueryType::A).await;
        assert_eq!(path, QueryPath::Upstream);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert_eq!(resp.answers.len(), 1);
    }

    #[tokio::test]
    async fn refresh_entry_honors_forwarding_rule() {
        let rule_resp =
            crate::testutil::a_record_response("internal.corp", Ipv4Addr::new(10, 0, 0, 42), 300);
        let rule_upstream = crate::testutil::mock_upstream(rule_resp).await;

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.forwarding_rules = vec![ForwardingRule::new(
            "corp".to_string(),
            UpstreamPool::new(vec![Upstream::Udp(rule_upstream)], vec![]),
        )];
        // Default pool points at a blackhole — if the refresh queries it
        // instead of the rule, the test fails because nothing is cached.
        ctx.upstream_pool
            .lock()
            .unwrap()
            .set_primary(vec![Upstream::Udp(crate::testutil::blackhole_upstream())]);
        let ctx = Arc::new(ctx);

        refresh_entry(&ctx, "internal.corp", QueryType::A).await;

        let cached = ctx
            .cache
            .read()
            .unwrap()
            .lookup("internal.corp", QueryType::A)
            .expect("refresh must populate cache via forwarding rule");
        match &cached.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 42)),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn refresh_entry_prefers_forwarding_rule_over_recursive() {
        let rule_resp =
            crate::testutil::a_record_response("db.internal.corp", Ipv4Addr::new(10, 0, 0, 7), 300);
        let rule_upstream = crate::testutil::mock_upstream(rule_resp).await;

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.upstream_mode = UpstreamMode::Recursive;
        ctx.forwarding_rules = vec![ForwardingRule::new(
            "corp".to_string(),
            UpstreamPool::new(vec![Upstream::Udp(rule_upstream)], vec![]),
        )];
        // No root_hints — recursion would fail immediately, proving that
        // the rule branch fired instead.
        let ctx = Arc::new(ctx);

        refresh_entry(&ctx, "db.internal.corp", QueryType::A).await;

        let cached = ctx
            .cache
            .read()
            .unwrap()
            .lookup("db.internal.corp", QueryType::A)
            .expect("recursive-mode refresh must still consult forwarding rules");
        match &cached.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 7)),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[test]
    fn serialize_with_fallback_passes_through_valid_response() {
        let query = DnsPacket::query(0x1234, "example.com", QueryType::A);
        let mut response = DnsPacket::response_from(&query, ResultCode::NOERROR);
        response.answers.push(DnsRecord::A {
            domain: "example.com".into(),
            addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 300,
        });
        let buf = serialize_with_fallback(&mut response, &query, "example.com", false).unwrap();
        let parsed =
            DnsPacket::from_buffer(&mut BytePacketBuffer::from_bytes(buf.filled())).unwrap();
        assert_eq!(parsed.header.rescode, ResultCode::NOERROR);
        assert!(!parsed.header.truncated_message);
        assert_eq!(parsed.answers.len(), 1);
    }

    #[test]
    fn serialize_with_fallback_sets_tc_on_buffer_overflow() {
        // 4096-byte buffer / ~24 bytes per TXT-as-UNKNOWN record → ~170+ fills it.
        let query = DnsPacket::query(0x1234, "example.com", QueryType::TXT);
        let mut response = DnsPacket::response_from(&query, ResultCode::NOERROR);
        for _ in 0..256 {
            response.answers.push(DnsRecord::UNKNOWN {
                domain: "example.com".into(),
                qtype: QueryType::TXT.to_num(),
                data: vec![0u8; 32],
                ttl: 300,
            });
        }
        let buf = serialize_with_fallback(&mut response, &query, "example.com", false).unwrap();
        let parsed =
            DnsPacket::from_buffer(&mut BytePacketBuffer::from_bytes(buf.filled())).unwrap();
        assert!(parsed.header.truncated_message, "TC bit must be set");
        assert_eq!(parsed.header.rescode, ResultCode::NOERROR);
    }

    #[test]
    fn serialize_with_fallback_returns_servfail_for_malformed_label() {
        // A >63-byte raw label reaches write_qname → reject as SERVFAIL,
        // not TC (TC would send the client to TCP for the same failure). #142.
        let query = DnsPacket::query(0x1234, "example.com", QueryType::A);
        let mut response = DnsPacket::response_from(&query, ResultCode::NOERROR);
        response.answers.push(DnsRecord::A {
            domain: format!("{}.example.com", "a".repeat(64)),
            addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 300,
        });
        let buf = serialize_with_fallback(&mut response, &query, "example.com", false).unwrap();
        let parsed =
            DnsPacket::from_buffer(&mut BytePacketBuffer::from_bytes(buf.filled())).unwrap();
        assert_eq!(parsed.header.rescode, ResultCode::SERVFAIL);
        assert!(
            !parsed.header.truncated_message,
            "must not set TC for parse errors"
        );
        assert_eq!(
            response.header.rescode,
            ResultCode::SERVFAIL,
            "caller-visible rescode must reflect SERVFAIL for query logging"
        );
    }

    /// #188: cache entries synthesized internally (e.g. NS delegation snapshots)
    /// have no question section and no rd/ra flags. The cache-hit serve path
    /// must restore these from the client query before returning to the wire.
    #[tokio::test]
    async fn cache_hit_restores_question_and_rd_ra_from_client_query() {
        let mut malformed = DnsPacket::new();
        malformed.header.response = true;
        malformed.header.rescode = ResultCode::NOERROR;
        malformed.answers.push(DnsRecord::NS {
            domain: "ikea.com".into(),
            host: "udns1.cscdns.net".into(),
            ttl: 86400,
        });

        let ctx = Arc::new(crate::testutil::test_ctx().await);
        ctx.cache
            .write()
            .unwrap()
            .insert("ikea.com", QueryType::NS, &malformed);

        let (resp, path) = resolve_in_test(&ctx, "ikea.com", QueryType::NS).await;

        assert_eq!(path, QueryPath::Cached);
        assert_eq!(resp.questions.len(), 1);
        assert_eq!(resp.questions[0].name, "ikea.com");
        assert_eq!(resp.questions[0].qtype, QueryType::NS);
        assert!(resp.header.recursion_desired);
        assert!(resp.header.recursion_available);
    }

    // ---- shape_response_for_client unit tests ----

    fn ede_opt_bytes(code: u16) -> Vec<u8> {
        // RFC 8914 OPT body: option-code=15 (EDE), option-length=2, INFO-CODE.
        let mut v = vec![0, 15, 0, 2];
        v.extend_from_slice(&code.to_be_bytes());
        v
    }

    #[test]
    fn shape_overrides_do_bit_to_match_client() {
        // RFC 4035 §3.2.1: response DO bit reflects the requestor's DO bit.
        let mut query = DnsPacket::query(0x1, "example.com", QueryType::A);
        query.edns = Some(crate::packet::EdnsOpt {
            do_bit: false,
            ..Default::default()
        });
        let mut response = DnsPacket::response_from(&query, ResultCode::NOERROR);
        response.edns = Some(crate::packet::EdnsOpt {
            do_bit: true,
            ..Default::default()
        });

        shape_response_for_client(&mut response, &query, false);

        assert!(!response.edns.unwrap().do_bit);
    }

    #[test]
    fn shape_synthesizes_minimal_opt_when_upstream_has_none() {
        // Client opted into EDNS but upstream omitted OPT (local zones,
        // synthesized responses) — emit a minimal OPT so the client sees
        // EDNS in the exchange.
        let mut query = DnsPacket::query(0x1, "example.com", QueryType::A);
        query.edns = Some(crate::packet::EdnsOpt::default());
        let mut response = DnsPacket::response_from(&query, ResultCode::NOERROR);
        assert!(response.edns.is_none());

        shape_response_for_client(&mut response, &query, false);

        assert!(response.edns.is_some());
    }

    #[test]
    fn shape_strips_dnssec_records_for_non_do_client() {
        let query = DnsPacket::query(0x1, "example.com", QueryType::A);
        let mut response = DnsPacket::response_from(&query, ResultCode::NOERROR);
        response.answers.push(DnsRecord::A {
            domain: "example.com".into(),
            addr: Ipv4Addr::new(192, 0, 2, 1),
            ttl: 300,
        });
        response.answers.push(DnsRecord::RRSIG {
            domain: "example.com".into(),
            type_covered: QueryType::A.to_num(),
            algorithm: 13,
            labels: 2,
            original_ttl: 300,
            expiration: 0,
            inception: 0,
            key_tag: 0,
            signer_name: "example.com".into(),
            signature: vec![],
            ttl: 300,
        });

        shape_response_for_client(&mut response, &query, false);

        assert_eq!(response.answers.len(), 1);
        assert!(matches!(response.answers[0], DnsRecord::A { .. }));
    }

    // ---- Wiring tests: shape_response_for_client must be called by resolve_query ----

    #[tokio::test]
    async fn pipeline_clears_aa_bit_from_forwarded_response() {
        // #192: even when upstream sets aa=1, the client must see aa=0.
        let mut upstream_resp =
            crate::testutil::a_record_response("aa.test", Ipv4Addr::new(1, 2, 3, 4), 60);
        upstream_resp.header.authoritative_answer = true;
        let upstream_addr = crate::testutil::mock_upstream(upstream_resp).await;

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.forwarding_rules = vec![ForwardingRule::new(
            "aa.test".to_string(),
            UpstreamPool::new(vec![Upstream::Udp(upstream_addr)], vec![]),
        )];
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "aa.test", QueryType::A).await;
        assert_eq!(path, QueryPath::Forwarded);
        assert!(
            !resp.header.authoritative_answer,
            "aa bit must be cleared even when upstream set it"
        );
    }

    #[tokio::test]
    async fn pipeline_drops_opt_when_client_sent_none() {
        // #193 / RFC 6891 §6.1.1: client sent no OPT -> response must have none,
        // even if upstream included one.
        let mut upstream_resp =
            crate::testutil::a_record_response("noedns.test", Ipv4Addr::new(1, 2, 3, 4), 60);
        upstream_resp.edns = Some(crate::packet::EdnsOpt::default());
        let upstream_addr = crate::testutil::mock_upstream(upstream_resp).await;

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.forwarding_rules = vec![ForwardingRule::new(
            "noedns.test".to_string(),
            UpstreamPool::new(vec![Upstream::Udp(upstream_addr)], vec![]),
        )];
        let ctx = Arc::new(ctx);

        let (resp, _) = resolve_in_test(&ctx, "noedns.test", QueryType::A).await;
        assert!(
            resp.edns.is_none(),
            "client sent no OPT, response must omit OPT"
        );
    }

    #[tokio::test]
    async fn pipeline_preserves_upstream_ede_for_edns_client() {
        // #136 angle: when the client opts into EDNS, upstream's EDE option
        // must survive the full pipeline (serialize -> reparse) so debuggers
        // and validators see *why* a response is empty.
        let ede = ede_opt_bytes(22); // 22 = "No Reachable Authority"
        let mut upstream_resp = DnsPacket::new();
        upstream_resp.header.response = true;
        upstream_resp.header.rescode = ResultCode::NOERROR;
        upstream_resp.edns = Some(crate::packet::EdnsOpt {
            options: ede.clone(),
            ..Default::default()
        });
        let upstream_addr = crate::testutil::mock_upstream(upstream_resp).await;

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.forwarding_rules = vec![ForwardingRule::new(
            "ede.test".to_string(),
            UpstreamPool::new(vec![Upstream::Udp(upstream_addr)], vec![]),
        )];
        let ctx = Arc::new(ctx);

        let mut query = DnsPacket::query(0xBEEF, "ede.test", QueryType::A);
        query.edns = Some(crate::packet::EdnsOpt::default());
        let (resp, _) = resolve_in_test_with_query(&ctx, query).await;

        let edns = resp.edns.expect("OPT must reach the client");
        assert_eq!(
            edns.options, ede,
            "EDE option bytes must survive serialize -> reparse"
        );
    }

    #[tokio::test]
    async fn pipeline_truncated_response_mirrors_client_opt() {
        // RFC 6891 §6.1.1: the OPT-mirror invariant must hold even on the
        // TC-bit rebuild path, which throws the original (shaped) response
        // away and synthesizes a fresh one when serialization overflows.
        let mut ctx = crate::testutil::test_ctx().await;
        let big_record = DnsRecord::UNKNOWN {
            domain: "huge.test".into(),
            qtype: 99,
            data: vec![0u8; 5000], // exceeds the 4096-byte serialization buffer
            ttl: 60,
        };
        ctx.zone_map = crate::config::ZoneMap::from_exact(vec![big_record]);
        let ctx = Arc::new(ctx);

        let mut query = DnsPacket::query(0xBEEF, "huge.test", QueryType::UNKNOWN(99));
        query.edns = Some(crate::packet::EdnsOpt::default());
        let (resp, _) = resolve_in_test_with_query(&ctx, query).await;

        assert!(resp.header.truncated_message, "TC bit must be set");
        assert!(resp.edns.is_some(), "TC response must mirror client's OPT");
    }

    #[tokio::test]
    async fn handle_query_reply_leaves_provided_socket() {
        let sock_a = Arc::new(UdpListener::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpListener::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.zone_map = crate::config::ZoneMap::from_exact(vec![DnsRecord::A {
            domain: "multi.test".into(),
            addr: Ipv4Addr::new(10, 0, 0, 1),
            ttl: 60,
        }]);
        let ctx = Arc::new(ctx);

        let query = DnsPacket::query(0xBEEF, "multi.test", QueryType::A);
        let mut tmp = BytePacketBuffer::new();
        query.write(&mut tmp).unwrap();
        let wire = tmp.buf[..tmp.pos].to_vec();

        let mut rbuf = [0u8; 512];
        for (sock, addr) in [(&sock_a, addr_a), (&sock_b, addr_b)] {
            handle_query(
                BytePacketBuffer::from_bytes(&wire),
                wire.len(),
                client_addr,
                client_addr,
                None,
                &ctx,
                sock,
                Transport::Udp,
            )
            .await
            .unwrap();
            let (_, src) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client.recv_from(&mut rbuf),
            )
            .await
            .expect("reply within 1s")
            .unwrap();
            assert_eq!(src, addr, "reply must come from the receiving socket");
        }
    }

    // ---- CNAME chase (issue #237) ----

    async fn ctx_with_zone(records: Vec<DnsRecord>) -> ServerCtx {
        let mut ctx = crate::testutil::test_ctx().await;
        ctx.zone_map = crate::config::ZoneMap::from_exact(records);
        ctx
    }

    #[tokio::test]
    async fn cname_chase_local_to_local_returns_combined_answer() {
        let ctx = Arc::new(
            ctx_with_zone(vec![
                crate::testutil::cname_record("app.example.com", "nas.lan", 60),
                crate::testutil::a_record("nas.lan", Ipv4Addr::new(192, 168, 1, 42), 60),
            ])
            .await,
        );

        let (resp, path) = resolve_in_test(&ctx, "app.example.com", QueryType::A).await;
        assert_eq!(path, QueryPath::Local);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert_eq!(resp.answers.len(), 2);
        assert!(matches!(&resp.answers[0], DnsRecord::CNAME { host, .. } if host == "nas.lan"));
        assert!(
            matches!(&resp.answers[1], DnsRecord::A { addr, .. } if *addr == Ipv4Addr::new(192, 168, 1, 42))
        );
    }

    #[tokio::test]
    async fn cname_chase_direct_cname_query_does_not_chase() {
        let ctx = Arc::new(
            ctx_with_zone(vec![
                crate::testutil::cname_record("app.example.com", "nas.lan", 60),
                crate::testutil::a_record("nas.lan", Ipv4Addr::new(192, 168, 1, 42), 60),
            ])
            .await,
        );

        let (resp, path) = resolve_in_test(&ctx, "app.example.com", QueryType::CNAME).await;
        assert_eq!(path, QueryPath::Local);
        assert_eq!(resp.answers.len(), 1);
        assert!(matches!(&resp.answers[0], DnsRecord::CNAME { .. }));
    }

    #[tokio::test]
    async fn cname_chase_loop_returns_servfail() {
        let ctx = Arc::new(
            ctx_with_zone(vec![
                crate::testutil::cname_record("a.test", "b.test", 60),
                crate::testutil::cname_record("b.test", "a.test", 60),
            ])
            .await,
        );
        let (resp, _) = resolve_in_test(&ctx, "a.test", QueryType::A).await;
        assert_eq!(resp.header.rescode, ResultCode::SERVFAIL);
    }

    #[tokio::test]
    async fn cname_chase_depth_cap_returns_servfail() {
        let chain: Vec<DnsRecord> = (0..10)
            .map(|i| {
                crate::testutil::cname_record(
                    &format!("n{}.test", i),
                    &format!("n{}.test", i + 1),
                    60,
                )
            })
            .collect();
        let ctx = Arc::new(ctx_with_zone(chain).await);
        let (resp, _) = resolve_in_test(&ctx, "n0.test", QueryType::A).await;
        assert_eq!(resp.header.rescode, ResultCode::SERVFAIL);
    }

    #[tokio::test]
    async fn cname_chase_local_to_upstream_returns_combined() {
        let upstream = crate::testutil::mock_upstream(crate::testutil::a_record_response(
            "public.example.org",
            Ipv4Addr::new(93, 184, 216, 34),
            300,
        ))
        .await;

        let mut ctx = ctx_with_zone(vec![crate::testutil::cname_record(
            "alias.test",
            "public.example.org",
            60,
        )])
        .await;
        ctx.upstream_pool = Mutex::new(crate::forward::UpstreamPool::new(
            vec![crate::forward::Upstream::Udp(upstream)],
            vec![],
        ));
        let ctx = Arc::new(ctx);

        let (resp, _) = resolve_in_test(&ctx, "alias.test", QueryType::A).await;
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert_eq!(resp.answers.len(), 2);
        assert!(
            matches!(&resp.answers[0], DnsRecord::CNAME { host, .. } if host == "public.example.org")
        );
        assert!(
            matches!(&resp.answers[1], DnsRecord::A { addr, .. } if *addr == Ipv4Addr::new(93, 184, 216, 34))
        );
    }
}
