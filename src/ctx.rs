use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use log::{debug, error, info, warn};
use rustls::ServerConfig;
use tokio::net::UdpSocket;

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
                match crate::recursive::resolve_recursive(
                    &qname,
                    qtype,
                    &ctx.cache,
                    &query,
                    &ctx.root_hints,
                    &ctx.srtt,
                )
                .await
                {
                    Ok(resp) => (resp, QueryPath::Recursive, DnssecStatus::Indeterminate),
                    Err(e) => {
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
    qname == "ipv4only.arpa"
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
