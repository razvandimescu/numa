use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
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
use crate::forward::{forward_query, Upstream};
use crate::header::ResultCode;
use crate::lan::PeerStore;
use crate::override_store::OverrideStore;
use crate::packet::DnsPacket;
use crate::query_log::{QueryLog, QueryLogEntry};
use crate::question::QueryType;
use crate::record::DnsRecord;
use crate::service_store::ServiceStore;
use crate::srtt::SrttCache;
use crate::stats::{QueryPath, ServerStats};
use crate::system_dns::ForwardingRule;

pub struct ServerCtx {
    pub socket: UdpSocket,
    pub zone_map: ZoneMap,
    /// std::sync::RwLock (not tokio) — locks must never be held across .await points.
    pub cache: RwLock<DnsCache>,
    pub stats: Mutex<ServerStats>,
    pub overrides: RwLock<OverrideStore>,
    pub blocklist: RwLock<BlocklistStore>,
    pub query_log: Mutex<QueryLog>,
    pub services: Mutex<ServiceStore>,
    pub lan_peers: Mutex<PeerStore>,
    pub forwarding_rules: Vec<ForwardingRule>,
    pub upstream: Mutex<Upstream>,
    pub upstream_auto: bool,
    pub upstream_port: u16,
    pub lan_ip: Mutex<std::net::Ipv4Addr>,
    pub timeout: Duration,
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
}

pub async fn handle_query(
    mut buffer: BytePacketBuffer,
    src_addr: SocketAddr,
    ctx: &ServerCtx,
) -> crate::Result<()> {
    let start = Instant::now();

    let query = match DnsPacket::from_buffer(&mut buffer) {
        Ok(packet) => packet,
        Err(e) => {
            warn!("{} | PARSE ERROR | {}", src_addr, e);
            return Ok(());
        }
    };

    let (qname, qtype) = match query.questions.first() {
        Some(q) => (q.name.clone(), q.qtype),
        None => return Ok(()),
    };

    // Pipeline: overrides -> .tld interception -> blocklist -> local zones -> cache -> upstream
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
            match qtype {
                QueryType::AAAA => resp.answers.push(DnsRecord::AAAA {
                    domain: qname.clone(),
                    addr: std::net::Ipv6Addr::LOCALHOST,
                    ttl: 300,
                }),
                _ => resp.answers.push(DnsRecord::A {
                    domain: qname.clone(),
                    addr: std::net::Ipv4Addr::LOCALHOST,
                    ttl: 300,
                }),
            }
            (resp, QueryPath::Local, DnssecStatus::Indeterminate)
        } else if is_special_use_domain(&qname) {
            // RFC 6761/8880: private PTR, DDR, NAT64 — answer locally
            let resp = special_use_response(&query, &qname, qtype);
            (resp, QueryPath::Local, DnssecStatus::Indeterminate)
        } else if !ctx.proxy_tld_suffix.is_empty()
            && (qname.ends_with(&ctx.proxy_tld_suffix) || qname == ctx.proxy_tld)
        {
            // Resolve .numa: local services → 127.0.0.1, LAN peers → peer IP
            let service_name = qname.strip_suffix(&ctx.proxy_tld_suffix).unwrap_or(&qname);
            let resolve_ip = {
                let local = ctx.services.lock().unwrap();
                if local.lookup(service_name).is_some() {
                    std::net::Ipv4Addr::LOCALHOST
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
            let mut resp = DnsPacket::response_from(&query, ResultCode::NOERROR);
            match qtype {
                QueryType::AAAA => resp.answers.push(DnsRecord::AAAA {
                    domain: qname.clone(),
                    addr: if resolve_ip == std::net::Ipv4Addr::LOCALHOST {
                        std::net::Ipv6Addr::LOCALHOST
                    } else {
                        resolve_ip.to_ipv6_mapped()
                    },
                    ttl: 300,
                }),
                _ => resp.answers.push(DnsRecord::A {
                    domain: qname.clone(),
                    addr: resolve_ip,
                    ttl: 300,
                }),
            }
            (resp, QueryPath::Local, DnssecStatus::Indeterminate)
        } else if ctx.blocklist.read().unwrap().is_blocked(&qname) {
            let mut resp = DnsPacket::response_from(&query, ResultCode::NOERROR);
            match qtype {
                QueryType::AAAA => resp.answers.push(DnsRecord::AAAA {
                    domain: qname.clone(),
                    addr: std::net::Ipv6Addr::UNSPECIFIED,
                    ttl: 60,
                }),
                _ => resp.answers.push(DnsRecord::A {
                    domain: qname.clone(),
                    addr: std::net::Ipv4Addr::UNSPECIFIED,
                    ttl: 60,
                }),
            }
            (resp, QueryPath::Blocked, DnssecStatus::Indeterminate)
        } else if let Some(records) = ctx.zone_map.get(qname.as_str()).and_then(|m| m.get(&qtype)) {
            let mut resp = DnsPacket::response_from(&query, ResultCode::NOERROR);
            resp.answers = records.clone();
            (resp, QueryPath::Local, DnssecStatus::Indeterminate)
        } else {
            let cached = ctx.cache.read().unwrap().lookup_with_status(&qname, qtype);
            if let Some((cached, cached_dnssec)) = cached {
                let mut resp = cached;
                resp.header.id = query.header.id;
                if cached_dnssec == DnssecStatus::Secure {
                    resp.header.authed_data = true;
                }
                (resp, QueryPath::Cached, cached_dnssec)
            } else if ctx.upstream_mode == UpstreamMode::Recursive {
                let key = (qname.clone(), qtype);

                enum Disposition {
                    Leader(broadcast::Sender<Option<DnsPacket>>),
                    Follower(broadcast::Receiver<Option<DnsPacket>>),
                }

                let disposition = {
                    let mut inflight = ctx.inflight.lock().unwrap();
                    if let Some(tx) = inflight.get(&key) {
                        Disposition::Follower(tx.subscribe())
                    } else {
                        let (tx, _) = broadcast::channel::<Option<DnsPacket>>(1);
                        inflight.insert(key.clone(), tx.clone());
                        Disposition::Leader(tx)
                    }
                };

                match disposition {
                    Disposition::Follower(mut rx) => {
                        debug!("{} | {:?} {} | COALESCED", src_addr, qtype, qname);
                        match rx.recv().await {
                            Ok(Some(mut resp)) => {
                                resp.header.id = query.header.id;
                                (resp, QueryPath::Coalesced, DnssecStatus::Indeterminate)
                            }
                            _ => (
                                DnsPacket::response_from(&query, ResultCode::SERVFAIL),
                                QueryPath::UpstreamError,
                                DnssecStatus::Indeterminate,
                            ),
                        }
                    }
                    Disposition::Leader(tx) => {
                        // Drop guard: remove inflight entry even on panic/cancellation
                        let guard = InflightGuard {
                            inflight: &ctx.inflight,
                            key: key.clone(),
                        };

                        let result = crate::recursive::resolve_recursive(
                            &qname,
                            qtype,
                            &ctx.cache,
                            &query,
                            &ctx.root_hints,
                            &ctx.srtt,
                        )
                        .await;

                        drop(guard);

                        match result {
                            Ok(resp) => {
                                let _ = tx.send(Some(resp.clone()));
                                (resp, QueryPath::Recursive, DnssecStatus::Indeterminate)
                            }
                            Err(e) => {
                                let _ = tx.send(None);
                                error!(
                                    "{} | {:?} {} | RECURSIVE ERROR | {}",
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
            } else {
                let upstream =
                    match crate::system_dns::match_forwarding_rule(&qname, &ctx.forwarding_rules) {
                        Some(addr) => Upstream::Udp(addr),
                        None => ctx.upstream.lock().unwrap().clone(),
                    };
                match forward_query(&query, &upstream, ctx.timeout).await {
                    Ok(resp) => {
                        ctx.cache.write().unwrap().insert(&qname, qtype, &resp);
                        (resp, QueryPath::Forwarded, DnssecStatus::Indeterminate)
                    }
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

    let mut resp_buffer = BytePacketBuffer::new();
    if response.write(&mut resp_buffer).is_err() {
        // Response too large for UDP — set TC bit and send header + question only
        debug!("response too large, setting TC bit for {}", qname);
        let mut tc_response = DnsPacket::response_from(&query, response.header.rescode);
        tc_response.header.truncated_message = true;
        let mut tc_buffer = BytePacketBuffer::new();
        tc_response.write(&mut tc_buffer)?;
        ctx.socket.send_to(tc_buffer.filled(), src_addr).await?;
    } else {
        ctx.socket.send_to(resp_buffer.filled(), src_addr).await?;
    }

    // Record stats and query log
    {
        let mut s = ctx.stats.lock().unwrap();
        let total = s.record(path);
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
        rescode: response.header.rescode,
        latency_us: elapsed.as_micros() as u64,
        dnssec,
    });

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

struct InflightGuard<'a> {
    inflight: &'a Mutex<InflightMap>,
    key: (String, QueryType),
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.inflight.lock().unwrap().remove(&self.key);
    }
}

/// Build a wire-format DNS query packet for the given domain and type.
#[cfg(test)]
fn build_wire_query(id: u16, domain: &str, qtype: QueryType) -> BytePacketBuffer {
    let mut pkt = DnsPacket::new();
    pkt.header.id = id;
    pkt.header.recursion_desired = true;
    pkt.header.questions = 1;
    pkt.questions
        .push(crate::question::DnsQuestion::new(domain.to_string(), qtype));
    let mut buf = BytePacketBuffer::new();
    pkt.write(&mut buf).unwrap();
    BytePacketBuffer::from_bytes(buf.filled())
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
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex, RwLock};
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

    // ---- Coalescing disposition tests ----

    #[test]
    fn leader_follower_disposition() {
        // First caller becomes leader, second becomes follower
        let map: Mutex<InflightMap> = Mutex::new(HashMap::new());
        let key = ("test.com".to_string(), QueryType::A);

        // First: no entry → insert and become leader
        let is_leader = {
            let mut m = map.lock().unwrap();
            if m.get(&key).is_some() {
                false
            } else {
                let (tx, _) = broadcast::channel::<Option<DnsPacket>>(1);
                m.insert(key.clone(), tx);
                true
            }
        };
        assert!(is_leader);

        // Second: entry exists → become follower
        let is_follower = {
            let m = map.lock().unwrap();
            m.get(&key).is_some()
        };
        assert!(is_follower);
    }

    #[tokio::test]
    async fn broadcast_delivers_result_to_follower() {
        let (tx, _) = broadcast::channel::<Option<DnsPacket>>(1);
        let mut rx = tx.subscribe();

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
    async fn broadcast_none_signals_failure() {
        let (tx, _) = broadcast::channel::<Option<DnsPacket>>(1);
        let mut rx = tx.subscribe();
        let _ = tx.send(None);

        let received = rx.recv().await.unwrap();
        assert!(received.is_none());
    }

    #[tokio::test]
    async fn multiple_followers_all_receive_result() {
        let (tx, _) = broadcast::channel::<Option<DnsPacket>>(1);
        let mut rx1 = tx.subscribe();
        let mut rx2 = tx.subscribe();
        let mut rx3 = tx.subscribe();

        let mut resp = DnsPacket::new();
        resp.answers.push(DnsRecord::A {
            domain: "multi.com".into(),
            addr: Ipv4Addr::new(10, 0, 0, 1),
            ttl: 60,
        });
        let _ = tx.send(Some(resp));

        for rx in [&mut rx1, &mut rx2, &mut rx3] {
            let r = rx.recv().await.unwrap().unwrap();
            assert_eq!(r.answers.len(), 1);
        }
    }

    // ---- Integration: concurrent handle_query coalescing ----

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawn a slow TCP DNS server that delays `delay` before responding.
    /// Returns (addr, query_count) where query_count is an Arc<AtomicU32>
    /// tracking how many queries were actually resolved (not coalesced).
    async fn spawn_slow_dns_server(
        delay: Duration,
    ) -> (SocketAddr, Arc<std::sync::atomic::AtomicU32>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let count_clone = count.clone();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let count = count_clone.clone();
                let delay = delay;
                tokio::spawn(async move {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut data = vec![0u8; len];
                    if stream.read_exact(&mut data).await.is_err() {
                        return;
                    }

                    let mut buf = BytePacketBuffer::from_bytes(&data);
                    let query = match DnsPacket::from_buffer(&mut buf) {
                        Ok(q) => q,
                        Err(_) => return,
                    };

                    count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // Deliberate delay to create coalescing window
                    tokio::time::sleep(delay).await;

                    let mut resp = DnsPacket::response_from(&query, ResultCode::NOERROR);
                    resp.header.authoritative_answer = true;
                    if let Some(q) = query.questions.first() {
                        resp.answers.push(DnsRecord::A {
                            domain: q.name.clone(),
                            addr: Ipv4Addr::new(10, 0, 0, 1),
                            ttl: 300,
                        });
                    }

                    let mut resp_buf = BytePacketBuffer::new();
                    if resp.write(&mut resp_buf).is_err() {
                        return;
                    }
                    let resp_bytes = resp_buf.filled();
                    let mut out = Vec::with_capacity(2 + resp_bytes.len());
                    out.extend_from_slice(&(resp_bytes.len() as u16).to_be_bytes());
                    out.extend_from_slice(resp_bytes);
                    let _ = stream.write_all(&out).await;
                });
            }
        });
        (addr, count)
    }

    async fn test_recursive_ctx(root_hint: SocketAddr) -> Arc<ServerCtx> {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Arc::new(ServerCtx {
            socket,
            zone_map: HashMap::new(),
            cache: RwLock::new(crate::cache::DnsCache::new(100, 60, 86400)),
            stats: Mutex::new(crate::stats::ServerStats::new()),
            overrides: RwLock::new(crate::override_store::OverrideStore::new()),
            blocklist: RwLock::new(crate::blocklist::BlocklistStore::new()),
            query_log: Mutex::new(crate::query_log::QueryLog::new(100)),
            services: Mutex::new(crate::service_store::ServiceStore::new()),
            lan_peers: Mutex::new(crate::lan::PeerStore::new(90)),
            forwarding_rules: Vec::new(),
            upstream: Mutex::new(crate::forward::Upstream::Udp(
                "127.0.0.1:53".parse().unwrap(),
            )),
            upstream_auto: false,
            upstream_port: 53,
            lan_ip: Mutex::new(Ipv4Addr::LOCALHOST),
            timeout: Duration::from_secs(3),
            proxy_tld: "numa".to_string(),
            proxy_tld_suffix: ".numa".to_string(),
            lan_enabled: false,
            config_path: "/tmp/test-numa.toml".to_string(),
            config_found: false,
            config_dir: std::path::PathBuf::from("/tmp"),
            data_dir: std::path::PathBuf::from("/tmp"),
            tls_config: None,
            upstream_mode: crate::config::UpstreamMode::Recursive,
            root_hints: vec![root_hint],
            srtt: RwLock::new(crate::srtt::SrttCache::new(true)),
            inflight: Mutex::new(HashMap::new()),
            dnssec_enabled: false,
            dnssec_strict: false,
        })
    }

    #[tokio::test]
    async fn concurrent_queries_coalesce_to_single_resolution() {
        // Force TCP-only so mock server works
        crate::recursive::UDP_DISABLED.store(true, std::sync::atomic::Ordering::Release);

        let (server_addr, query_count) = spawn_slow_dns_server(Duration::from_millis(200)).await;
        let ctx = test_recursive_ctx(server_addr).await;
        let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Fire 5 concurrent queries for the same (domain, A)
        let mut handles = Vec::new();
        for i in 0..5u16 {
            let ctx = ctx.clone();
            let buf = build_wire_query(100 + i, "coalesce-test.example.com", QueryType::A);
            handles.push(tokio::spawn(async move {
                handle_query(buf, src, &ctx).await
            }));
        }

        for h in handles {
            h.await.unwrap().unwrap();
        }

        // Only 1 resolution should have reached the upstream server
        let actual = query_count.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(actual, 1, "expected 1 upstream query, got {}", actual);

        // Inflight map must be empty after all queries complete
        assert!(ctx.inflight.lock().unwrap().is_empty());

        crate::recursive::reset_udp_state();
    }

    #[tokio::test]
    async fn different_qtypes_not_coalesced() {
        crate::recursive::UDP_DISABLED.store(true, std::sync::atomic::Ordering::Release);

        let (server_addr, query_count) = spawn_slow_dns_server(Duration::from_millis(100)).await;
        let ctx = test_recursive_ctx(server_addr).await;
        let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Fire A and AAAA concurrently — should NOT coalesce
        let ctx_ref = ctx.clone();
        let ctx_ref2 = ctx.clone();
        let buf_a = build_wire_query(200, "different-qt.example.com", QueryType::A);
        let buf_aaaa = build_wire_query(201, "different-qt.example.com", QueryType::AAAA);

        let h1 = tokio::spawn(async move { handle_query(buf_a, src, &ctx_ref).await });
        let h2 = tokio::spawn(async move { handle_query(buf_aaaa, src, &ctx_ref2).await });

        h1.await.unwrap().unwrap();
        h2.await.unwrap().unwrap();

        let actual = query_count.load(std::sync::atomic::Ordering::Relaxed);
        assert!(actual >= 2, "A and AAAA should resolve independently, got {}", actual);
        assert!(ctx.inflight.lock().unwrap().is_empty());

        crate::recursive::reset_udp_state();
    }

    #[tokio::test]
    async fn inflight_map_cleaned_after_upstream_error() {
        // Server that rejects everything — no server running at all
        let bogus_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let ctx = test_recursive_ctx(bogus_addr).await;
        let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let buf = build_wire_query(300, "will-fail.example.com", QueryType::A);
        let _ = handle_query(buf, src, &ctx).await;

        // Map must be clean even after error
        assert!(ctx.inflight.lock().unwrap().is_empty());
    }
}
