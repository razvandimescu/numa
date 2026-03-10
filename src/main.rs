use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::{debug, error, info, warn};
use tokio::net::UdpSocket;

use dns_fun::buffer::BytePacketBuffer;
use dns_fun::cache::DnsCache;
use dns_fun::config::{build_zone_map, load_config};
use dns_fun::forward::forward_query;
use dns_fun::header::ResultCode;
use dns_fun::packet::DnsPacket;
use dns_fun::question::QueryType;
use dns_fun::record::DnsRecord;
use dns_fun::stats::{QueryPath, ServerStats};

struct ServerCtx {
    socket: Arc<UdpSocket>,
    zone_map: HashMap<(String, QueryType), Vec<DnsRecord>>,
    cache: Mutex<DnsCache>,
    stats: Mutex<ServerStats>,
    upstream: SocketAddr,
    timeout: Duration,
}

#[tokio::main]
async fn main() -> dns_fun::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let config_path = std::env::args().nth(1).unwrap_or_else(|| "dns_fun.toml".to_string());
    let config = load_config(&config_path)?;

    let upstream: SocketAddr = format!("{}:{}", config.upstream.address, config.upstream.port).parse()?;
    let socket = Arc::new(UdpSocket::bind(&config.server.bind_addr).await?);

    let ctx = Arc::new(ServerCtx {
        socket: Arc::clone(&socket),
        zone_map: build_zone_map(&config.zones)?,
        cache: Mutex::new(DnsCache::new(
            config.cache.max_entries,
            config.cache.min_ttl,
            config.cache.max_ttl,
        )),
        stats: Mutex::new(ServerStats::new()),
        upstream,
        timeout: Duration::from_millis(config.upstream.timeout_ms),
    });

    info!(
        "dns_fun starting on {}, upstream {}, {} zone records, cache max {}",
        config.server.bind_addr,
        upstream,
        ctx.zone_map.len(),
        config.cache.max_entries,
    );

    loop {
        let mut buffer = BytePacketBuffer::new();
        let (_, src_addr) = socket.recv_from(&mut buffer.buf).await?;

        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = handle_query(buffer, src_addr, &ctx).await {
                error!("{} | HANDLER ERROR | {}", src_addr, e);
            }
        });
    }
}

async fn handle_query(
    mut buffer: BytePacketBuffer,
    src_addr: SocketAddr,
    ctx: &ServerCtx,
) -> dns_fun::Result<()> {
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

    // Pipeline: local zones -> cache -> upstream
    // Each lock is scoped to avoid holding MutexGuard across await points.
    let (response, path) = if let Some(records) = ctx.zone_map.get(&(qname.to_lowercase(), qtype)) {
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
            match forward_query(&query, ctx.upstream, ctx.timeout).await {
                Ok(resp) => {
                    ctx.cache.lock().unwrap().insert(&qname, qtype, &resp);
                    (resp, QueryPath::Forwarded)
                }
                Err(e) => {
                    error!("{} | {:?} {} | UPSTREAM ERROR | {}", src_addr, qtype, qname, e);
                    (DnsPacket::response_from(&query, ResultCode::SERVFAIL), QueryPath::UpstreamError)
                }
            }
        }
    };

    let elapsed = start.elapsed();

    info!(
        "{} | {:?} {} | {} | {} | {}ms",
        src_addr, qtype, qname, path.as_str(),
        response.header.rescode.as_str(), elapsed.as_millis(),
    );

    debug!(
        "response: {} answers, {} authorities, {} resources",
        response.answers.len(), response.authorities.len(), response.resources.len(),
    );

    let mut resp_buffer = BytePacketBuffer::new();
    response.write(&mut resp_buffer)?;
    ctx.socket.send_to(resp_buffer.filled(), src_addr).await?;

    // Record stats and log summary every 1000 queries (single lock acquisition)
    let mut s = ctx.stats.lock().unwrap();
    let total = s.record(path);
    if total % 1000 == 0 {
        s.log_summary();
    }

    Ok(())
}
