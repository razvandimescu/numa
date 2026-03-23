use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use log::{debug, error, info, warn};
use tokio::net::UdpSocket;

use crate::blocklist::BlocklistStore;
use crate::buffer::BytePacketBuffer;
use crate::cache::DnsCache;
use crate::config::ZoneMap;
use crate::forward::forward_query;
use crate::header::ResultCode;
use crate::lan::PeerStore;
use crate::override_store::OverrideStore;
use crate::packet::DnsPacket;
use crate::query_log::{QueryLog, QueryLogEntry};
use crate::question::QueryType;
use crate::record::DnsRecord;
use crate::service_store::ServiceStore;
use crate::stats::{QueryPath, ServerStats};
use crate::system_dns::ForwardingRule;

pub struct ServerCtx {
    pub socket: UdpSocket,
    pub zone_map: ZoneMap,
    pub cache: Mutex<DnsCache>,
    pub stats: Mutex<ServerStats>,
    pub overrides: Mutex<OverrideStore>,
    pub blocklist: Mutex<BlocklistStore>,
    pub query_log: Mutex<QueryLog>,
    pub services: Mutex<ServiceStore>,
    pub lan_peers: Mutex<PeerStore>,
    pub forwarding_rules: Vec<ForwardingRule>,
    pub upstream: Mutex<SocketAddr>,
    pub upstream_auto: bool,
    pub upstream_port: u16,
    pub lan_ip: Mutex<std::net::Ipv4Addr>,
    pub timeout: Duration,
    pub proxy_tld: String,
    pub proxy_tld_suffix: String, // pre-computed ".{tld}" to avoid per-query allocation
    pub lan_enabled: bool,
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
    let (response, path) = {
        let override_record = ctx.overrides.lock().unwrap().lookup(&qname);
        if let Some(record) = override_record {
            let mut resp = DnsPacket::response_from(&query, ResultCode::NOERROR);
            resp.answers.push(record);
            (resp, QueryPath::Overridden)
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
            (resp, QueryPath::Local)
        } else if ctx.blocklist.lock().unwrap().is_blocked(&qname) {
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
            (resp, QueryPath::Blocked)
        } else if let Some(records) = ctx.zone_map.get(qname.as_str()).and_then(|m| m.get(&qtype)) {
            let mut resp = DnsPacket::response_from(&query, ResultCode::NOERROR);
            resp.answers = records.clone();
            (resp, QueryPath::Local)
        } else {
            let cached = ctx.cache.lock().unwrap().lookup(&qname, qtype);
            if let Some(cached) = cached {
                let mut resp = cached;
                resp.header.id = query.header.id;
                (resp, QueryPath::Cached)
            } else {
                let upstream =
                    crate::system_dns::match_forwarding_rule(&qname, &ctx.forwarding_rules)
                        .unwrap_or_else(|| *ctx.upstream.lock().unwrap());
                match forward_query(&query, upstream, ctx.timeout).await {
                    Ok(resp) => {
                        ctx.cache.lock().unwrap().insert(&qname, qtype, &resp);
                        (resp, QueryPath::Forwarded)
                    }
                    Err(e) => {
                        error!(
                            "{} | {:?} {} | UPSTREAM ERROR | {}",
                            src_addr, qtype, qname, e
                        );
                        (
                            DnsPacket::response_from(&query, ResultCode::SERVFAIL),
                            QueryPath::UpstreamError,
                        )
                    }
                }
            }
        }
    };

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
    });

    Ok(())
}
