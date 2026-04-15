use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use log::{debug, error, info, warn};
use rustls::ServerConfig;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;

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
    pub socket: UdpSocket,
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
    let (response, path, dnssec) = {
        let override_record = ctx.overrides.read().unwrap().lookup(&qname);
        if let Some(record) = override_record {
            let mut resp = DnsPacket::response_from(&query, ResultCode::NOERROR);
            resp.answers.push(record);
            (resp, QueryPath::Overridden, DnssecStatus::Indeterminate)
        } else if qname == "localhost" || qname.ends_with(".localhost") {
            // RFC 6761: .localhost always resolves to loopback
            let mut resp = DnsPacket::response_from(&query, ResultCode::NOERROR);
            resp.answers.push(sinkhole_record(
                &qname,
                qtype,
                std::net::Ipv4Addr::LOCALHOST,
                std::net::Ipv6Addr::LOCALHOST,
                300,
            ));
            (resp, QueryPath::Local, DnssecStatus::Indeterminate)
        } else if let Some(records) = ctx.zone_map.get(qname.as_str()).and_then(|m| m.get(&qtype)) {
            let mut resp = DnsPacket::response_from(&query, ResultCode::NOERROR);
            resp.answers = records.clone();
            (resp, QueryPath::Local, DnssecStatus::Indeterminate)
        } else if is_special_use_domain(&qname)
            && crate::system_dns::match_forwarding_rule(&qname, &ctx.forwarding_rules).is_none()
        {
            // RFC 6761/8880: answer locally unless a forwarding rule covers this zone.
            let resp = special_use_response(&query, &qname, qtype);
            (resp, QueryPath::Local, DnssecStatus::Indeterminate)
        } else if !ctx.proxy_tld_suffix.is_empty()
            && (qname.ends_with(&ctx.proxy_tld_suffix) || qname == ctx.proxy_tld)
        {
            // Resolve .numa: remote clients get LAN IP (can't reach 127.0.0.1), local get loopback
            let service_name = qname.strip_suffix(&ctx.proxy_tld_suffix).unwrap_or(&qname);
            let is_remote = !src_addr.ip().is_loopback();
            let resolve_ip = {
                let local = ctx.services.lock().unwrap();
                if local.lookup(service_name).is_some() {
                    if is_remote {
                        *ctx.lan_ip.lock().unwrap()
                    } else {
                        std::net::Ipv4Addr::LOCALHOST
                    }
                } else {
                    let mut peers = ctx.lan_peers.lock().unwrap();
                    peers
                        .lookup(service_name)
                        .and_then(|(ip, _)| match ip {
                            std::net::IpAddr::V4(v4) => Some(v4),
                            _ => None,
                        })
                        .unwrap_or(std::net::Ipv4Addr::LOCALHOST)
                }
            };
            let v6 = if resolve_ip == std::net::Ipv4Addr::LOCALHOST {
                std::net::Ipv6Addr::LOCALHOST
            } else {
                resolve_ip.to_ipv6_mapped()
            };
            let mut resp = DnsPacket::response_from(&query, ResultCode::NOERROR);
            resp.answers
                .push(sinkhole_record(&qname, qtype, resolve_ip, v6, 300));
            (resp, QueryPath::Local, DnssecStatus::Indeterminate)
        } else if ctx.blocklist.read().unwrap().is_blocked(&qname) {
            let mut resp = DnsPacket::response_from(&query, ResultCode::NOERROR);
            resp.answers.push(sinkhole_record(
                &qname,
                qtype,
                std::net::Ipv4Addr::UNSPECIFIED,
                std::net::Ipv6Addr::UNSPECIFIED,
                60,
            ));
            (resp, QueryPath::Blocked, DnssecStatus::Indeterminate)
        } else {
            let cached = ctx.cache.read().unwrap().lookup_with_status(&qname, qtype);
            if let Some((cached, cached_dnssec, freshness)) = cached {
                if freshness.needs_refresh() {
                    let key = (qname.clone(), qtype);
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
                if cached_dnssec == DnssecStatus::Secure {
                    resp.header.authed_data = true;
                }
                (resp, QueryPath::Cached, cached_dnssec)
            } else if let Some(pool) =
                crate::system_dns::match_forwarding_rule(&qname, &ctx.forwarding_rules)
            {
                // Conditional forwarding takes priority over recursive mode
                // (e.g. Tailscale .ts.net, VPC private zones)
                match forward_with_failover_raw(
                    raw_wire,
                    pool,
                    &ctx.srtt,
                    ctx.timeout,
                    ctx.hedge_delay,
                )
                .await
                {
                    Ok(resp_wire) => match cache_and_parse(ctx, &qname, qtype, &resp_wire) {
                        Ok(resp) => (resp, QueryPath::Forwarded, DnssecStatus::Indeterminate),
                        Err(e) => {
                            error!("{} | {:?} {} | PARSE ERROR | {}", src_addr, qtype, qname, e);
                            (
                                DnsPacket::response_from(&query, ResultCode::SERVFAIL),
                                QueryPath::UpstreamError,
                                DnssecStatus::Indeterminate,
                            )
                        }
                    },
                    Err(e) => {
                        error!(
                            "{} | {:?} {} | FORWARD ERROR | {}",
                            src_addr, qtype, qname, e
                        );
                        (
                            DnsPacket::response_from(&query, ResultCode::SERVFAIL),
                            QueryPath::UpstreamError,
                            DnssecStatus::Indeterminate,
                        )
                    }
                }
            } else if ctx.upstream_mode == UpstreamMode::Recursive {
                let key = (qname.clone(), qtype);
                let (resp, path, err) = resolve_coalesced(&ctx.inflight, key, &query, || {
                    crate::recursive::resolve_recursive(
                        &qname,
                        qtype,
                        &ctx.cache,
                        &query,
                        &ctx.root_hints,
                        &ctx.srtt,
                    )
                })
                .await;
                if path == QueryPath::Coalesced {
                    debug!("{} | {:?} {} | COALESCED", src_addr, qtype, qname);
                } else if path == QueryPath::UpstreamError {
                    error!(
                        "{} | {:?} {} | RECURSIVE ERROR | {}",
                        src_addr,
                        qtype,
                        qname,
                        err.as_deref().unwrap_or("leader failed")
                    );
                }
                (resp, path, DnssecStatus::Indeterminate)
            } else {
                let pool = ctx.upstream_pool.lock().unwrap().clone();
                match forward_with_failover_raw(
                    raw_wire,
                    &pool,
                    &ctx.srtt,
                    ctx.timeout,
                    ctx.hedge_delay,
                )
                .await
                {
                    Ok(resp_wire) => match cache_and_parse(ctx, &qname, qtype, &resp_wire) {
                        Ok(resp) => (resp, QueryPath::Upstream, DnssecStatus::Indeterminate),
                        Err(e) => {
                            error!("{} | {:?} {} | PARSE ERROR | {}", src_addr, qtype, qname, e);
                            (
                                DnsPacket::response_from(&query, ResultCode::SERVFAIL),
                                QueryPath::UpstreamError,
                                DnssecStatus::Indeterminate,
                            )
                        }
                    },
                    Err(e) => {
                        error!(
                            "{} | {:?} {} | UPSTREAM ERROR | {}",
                            src_addr, qtype, qname, e
                        );
                        (
                            DnsPacket::response_from(&query, ResultCode::SERVFAIL),
                            QueryPath::UpstreamError,
                            DnssecStatus::Indeterminate,
                        )
                    }
                }
            }
        }
    };

    let client_do = query.edns.as_ref().is_some_and(|e| e.do_bit);
    let mut response = response;

    // DNSSEC validation (recursive/forwarded responses only)
    let mut dnssec = dnssec;
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

    // Strip DNSSEC records if client didn't set DO bit
    if !client_do {
        strip_dnssec_records(&mut response);
    }

    // Echo EDNS back if client sent it
    if query.edns.is_some() {
        response.edns = Some(crate::packet::EdnsOpt {
            do_bit: client_do,
            ..Default::default()
        });
    }

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

    // Serialize response
    // TODO: TC bit is UDP-specific; DoT connections could carry up to 65535 bytes.
    // Once BytePacketBuffer supports larger buffers, skip truncation for TCP/TLS.
    let mut resp_buffer = BytePacketBuffer::new();
    if response.write(&mut resp_buffer).is_err() {
        // Response too large — set TC bit and send header + question only
        debug!("response too large, setting TC bit for {}", qname);
        let mut tc_response = DnsPacket::response_from(&query, response.header.rescode);
        tc_response.header.truncated_message = true;
        resp_buffer = BytePacketBuffer::new();
        tc_response.write(&mut resp_buffer)?;
    }

    // Record stats and query log
    {
        let mut s = ctx.stats.lock().unwrap();
        let total = s.record(path, transport);
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

pub async fn handle_query(
    mut buffer: BytePacketBuffer,
    raw_len: usize,
    src_addr: SocketAddr,
    ctx: &Arc<ServerCtx>,
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
            ctx.socket.send_to(resp_buffer.filled(), src_addr).await?;
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

fn sinkhole_record(
    domain: &str,
    qtype: QueryType,
    v4: std::net::Ipv4Addr,
    v6: std::net::Ipv6Addr,
    ttl: u32,
) -> DnsRecord {
    match qtype {
        QueryType::AAAA => DnsRecord::AAAA {
            domain: domain.to_string(),
            addr: v6,
            ttl,
        },
        _ => DnsRecord::A {
            domain: domain.to_string(),
            addr: v4,
            ttl,
        },
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
/// executes `resolve_fn`, and followers wait for the broadcast result.
async fn resolve_coalesced<F, Fut>(
    inflight: &Mutex<InflightMap>,
    key: (String, QueryType),
    query: &DnsPacket,
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
                    (resp, QueryPath::Recursive, None)
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
    use std::net::Ipv4Addr;
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
                resolve_coalesced(&inf, key, &query, || async {
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
        let query = DnsPacket::query(0xBEEF, domain, qtype);
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
        let mut inner = HashMap::new();
        inner.insert(
            QueryType::A,
            vec![DnsRecord::A {
                domain: "myapp.test".to_string(),
                addr: Ipv4Addr::new(10, 0, 0, 42),
                ttl: 300,
            }],
        );
        ctx.zone_map.insert("myapp.test".to_string(), inner);
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
    async fn pipeline_tld_proxy_resolves_service() {
        let ctx = crate::testutil::test_ctx().await;
        ctx.services.lock().unwrap().insert("grafana", 3000);
        let ctx = Arc::new(ctx);

        let (resp, path) = resolve_in_test(&ctx, "grafana.numa", QueryType::A).await;
        assert_eq!(path, QueryPath::Local);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::LOCALHOST),
            other => panic!("expected A record, got {:?}", other),
        }
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
        let mut upstream_resp = DnsPacket::new();
        upstream_resp.header.response = true;
        upstream_resp.header.rescode = ResultCode::NOERROR;
        upstream_resp.answers.push(DnsRecord::A {
            domain: "internal.corp".to_string(),
            addr: Ipv4Addr::new(10, 1, 2, 3),
            ttl: 600,
        });
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

        let mut live_resp = DnsPacket::new();
        live_resp.header.response = true;
        live_resp.header.rescode = ResultCode::NOERROR;
        live_resp.answers.push(DnsRecord::A {
            domain: "internal.corp".to_string(),
            addr: Ipv4Addr::new(10, 9, 9, 9),
            ttl: 600,
        });
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
    async fn pipeline_default_pool_reports_upstream_path() {
        let mut upstream_resp = DnsPacket::new();
        upstream_resp.header.response = true;
        upstream_resp.header.rescode = ResultCode::NOERROR;
        upstream_resp.answers.push(DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(93, 184, 216, 34),
            ttl: 300,
        });
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
}
