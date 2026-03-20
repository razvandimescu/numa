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
use crate::override_store::OverrideStore;
use crate::packet::DnsPacket;
use crate::query_log::{QueryLog, QueryLogEntry};
use crate::record::DnsRecord;
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
    pub forwarding_rules: Vec<ForwardingRule>,
    pub upstream: SocketAddr,
    pub timeout: Duration,
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

    // Pipeline: overrides -> blocklist -> local zones -> cache -> upstream
    // Each lock is scoped to avoid holding MutexGuard across await points.
    let (response, path) = {
        let override_record = ctx.overrides.lock().unwrap().lookup(&qname);
        if let Some(record) = override_record {
            let mut resp = DnsPacket::response_from(&query, ResultCode::NOERROR);
            resp.answers.push(record);
            (resp, QueryPath::Overridden)
        } else if ctx.blocklist.lock().unwrap().is_blocked(&qname) {
            use crate::question::QueryType;
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
                        .unwrap_or(ctx.upstream);
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
    response.write(&mut resp_buffer)?;
    ctx.socket.send_to(resp_buffer.filled(), src_addr).await?;

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
