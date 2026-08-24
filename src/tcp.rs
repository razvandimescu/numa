//! Plain DNS-over-TCP listener (RFC 1035 §4.2.2, RFC 7766). Required so
//! clients can retry after a TC=1 truncated UDP response — without it, those
//! retries hit a closed port. Connection model mirrors `dot.rs`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::buffer::BytePacketBuffer;
use crate::config::ProxyProtocolConfig;
use crate::ctx::{resolve_query, ServerCtx};
use crate::header::ResultCode;
use crate::packet::DnsPacket;
use crate::pp2::{self, PpConfig};
use crate::stats::Transport;

const MAX_CONNECTIONS: usize = 512;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
// Matches BytePacketBuffer::BUF_SIZE — RFC 1035 allows up to 65535 but our
// buffer would silently truncate anything larger.
const MAX_MSG_LEN: usize = 4096;

/// Start the DNS-over-TCP listener on the same address as the UDP listener.
pub async fn start_tcp(ctx: Arc<ServerCtx>, bind_addr: &str, pp_cfg: &ProxyProtocolConfig) {
    let addr: SocketAddr = match bind_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            warn!(
                "TCP: invalid bind_addr {:?} ({}) — TCP DNS disabled",
                bind_addr, e
            );
            return;
        }
    };

    let Ok(pp) = pp2::init("TCP", pp_cfg) else {
        return;
    };

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("TCP: could not bind {} ({}) — TCP DNS disabled", addr, e);
            return;
        }
    };
    info!("TCP DNS listening on {}", addr);

    accept_loop(listener, pp, ctx).await;
}

async fn accept_loop(listener: TcpListener, pp: Option<Arc<PpConfig>>, ctx: Arc<ServerCtx>) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        let (tcp_stream, tcp_peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("TCP: accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!("TCP: connection limit reached, rejecting {}", tcp_peer);
                continue;
            }
        };
        let ctx = Arc::clone(&ctx);
        let pp = pp.clone();

        tokio::spawn(async move {
            let _permit = permit;

            let Some((stream, remote_addr, local_command)) =
                pp2::handshake(tcp_stream, tcp_peer, pp.as_deref(), &ctx).await
            else {
                return;
            };

            if !ctx.allow_from.admits(remote_addr.ip(), local_command) {
                debug!("TCP: dropping {} — not in allow_from", remote_addr);
                return;
            }

            handle_framed_dns_connection(stream, remote_addr, &ctx, Transport::Tcp).await;
        });
    }
}

/// Drive a length-prefixed DNS-over-stream connection (RFC 1035 §4.2.2,
/// RFC 7766 §6.2.1). Shared between plain TCP and DoT — DoT calls in after
/// TLS termination with `Transport::Dot`.
pub(crate) async fn handle_framed_dns_connection<S>(
    mut stream: S,
    remote_addr: SocketAddr,
    ctx: &Arc<ServerCtx>,
    transport: Transport,
) where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let proto = transport.as_str();
    loop {
        let mut len_buf = [0u8; 2];
        let Ok(Ok(_)) = tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await
        else {
            break;
        };
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len > MAX_MSG_LEN {
            debug!(
                "{}: oversized message {} from {}",
                proto, msg_len, remote_addr
            );
            break;
        }

        let mut buffer = BytePacketBuffer::new();
        let Ok(Ok(_)) =
            tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut buffer.buf[..msg_len])).await
        else {
            break;
        };

        let query = match DnsPacket::from_buffer(&mut buffer) {
            Ok(q) => q,
            Err(e) => {
                warn!("{} | PARSE ERROR | {}", remote_addr, e);
                // BytePacketBuffer is zero-initialized, so buf[0..2] reads as
                // 0x0000 for sub-2-byte messages — harmless FORMERR with id=0.
                let query_id = u16::from_be_bytes([buffer.buf[0], buffer.buf[1]]);
                let mut resp = DnsPacket::new();
                resp.header.id = query_id;
                resp.header.response = true;
                resp.header.rescode = ResultCode::FORMERR;
                if send_response(&mut stream, &resp, remote_addr, proto)
                    .await
                    .is_err()
                {
                    break;
                }
                continue;
            }
        };

        match resolve_query(
            query.clone(),
            &buffer.buf[..msg_len],
            remote_addr,
            ctx,
            transport,
        )
        .await
        {
            Ok((resp_buffer, _)) => {
                if write_framed(&mut stream, resp_buffer.filled())
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(e) => {
                warn!("{} | RESOLVE ERROR | {}", remote_addr, e);
                let mut resp = DnsPacket::response_from(&query, ResultCode::SERVFAIL);
                crate::ctx::shape_response_for_client(&mut resp, &query, ctx.filter_aaaa);
                if send_response(&mut stream, &resp, remote_addr, proto)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

async fn send_response<S>(
    stream: &mut S,
    resp: &DnsPacket,
    remote_addr: SocketAddr,
    proto: &str,
) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let mut out_buf = BytePacketBuffer::new();
    if resp.write(&mut out_buf).is_err() {
        debug!(
            "{}: failed to serialize {:?} response for {}",
            proto, resp.header.rescode, remote_addr
        );
        return Err(std::io::Error::other("serialize failed"));
    }
    write_framed(stream, out_buf.filled()).await
}

/// Write a DNS message with its 2-byte length prefix, coalesced into one syscall.
/// Bounded by WRITE_TIMEOUT so a stalled reader can't indefinitely hold a worker.
async fn write_framed<S>(stream: &mut S, msg: &[u8]) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let mut out = Vec::with_capacity(2 + msg.len());
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
    match tokio::time::timeout(WRITE_TIMEOUT, async {
        stream.write_all(&out).await?;
        stream.flush().await
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::other("write timeout")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use crate::buffer::BytePacketBuffer;
    use crate::header::ResultCode;
    use crate::packet::DnsPacket;
    use crate::question::QueryType;
    use crate::record::DnsRecord;

    async fn spawn_tcp_server() -> SocketAddr {
        let upstream_addr = crate::testutil::blackhole_upstream();

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.zone_map = crate::config::ZoneMap::from_exact(vec![DnsRecord::A {
            domain: "tcp-test.example".to_string(),
            addr: std::net::Ipv4Addr::new(10, 0, 0, 1),
            ttl: 300,
        }]);
        ctx.upstream_pool = Mutex::new(crate::forward::UpstreamPool::new(
            vec![crate::forward::Upstream::Udp(upstream_addr)],
            vec![],
        ));
        let ctx = Arc::new(ctx);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(accept_loop(listener, None, ctx));
        addr
    }

    async fn send_query(stream: &mut TcpStream, query: &DnsPacket) {
        let mut buf = BytePacketBuffer::new();
        query.write(&mut buf).unwrap();
        let msg = buf.filled();
        let mut out = Vec::with_capacity(2 + msg.len());
        out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        out.extend_from_slice(msg);
        stream.write_all(&out).await.unwrap();
    }

    /// The reply, or `None` if the resolver is still working on it.
    async fn read_reply(stream: &mut TcpStream, within: Duration) -> Option<DnsPacket> {
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(within, stream.read_exact(&mut len_buf))
            .await
            .ok()?
            .ok()?;
        let mut data = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        stream.read_exact(&mut data).await.ok()?;
        DnsPacket::from_buffer(&mut BytePacketBuffer::from_bytes(&data)).ok()
    }

    async fn tcp_exchange(stream: &mut TcpStream, query: &DnsPacket) -> DnsPacket {
        send_query(stream, query).await;
        read_reply(stream, Duration::from_secs(5))
            .await
            .expect("reply within 5s")
    }

    #[tokio::test]
    async fn tcp_resolves_local_zone() {
        let addr = spawn_tcp_server().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();

        let query = DnsPacket::query(0x1234, "tcp-test.example", QueryType::A);
        let resp = tcp_exchange(&mut stream, &query).await;

        assert_eq!(resp.header.id, 0x1234);
        assert!(resp.header.response);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0] {
            DnsRecord::A { domain, addr, ttl } => {
                assert_eq!(domain, "tcp-test.example");
                assert_eq!(*addr, std::net::Ipv4Addr::new(10, 0, 0, 1));
                assert_eq!(*ttl, 300);
            }
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn tcp_multiple_queries_on_persistent_connection() {
        // RFC 7766 §6.2.1: TCP connections must support multiple queries.
        let addr = spawn_tcp_server().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();

        for i in 0..3u16 {
            let query = DnsPacket::query(0xA000 + i, "tcp-test.example", QueryType::A);
            let resp = tcp_exchange(&mut stream, &query).await;
            assert_eq!(resp.header.id, 0xA000 + i);
            assert_eq!(resp.header.rescode, ResultCode::NOERROR);
            assert_eq!(resp.answers.len(), 1);
        }
    }

    #[tokio::test]
    async fn tcp_servfail_for_unreachable_upstream() {
        let addr = spawn_tcp_server().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();

        let query = DnsPacket::query(0xBEEF, "nonexistent.test", QueryType::A);
        let resp = tcp_exchange(&mut stream, &query).await;

        assert_eq!(resp.header.id, 0xBEEF);
        assert!(resp.header.response);
        // Blackhole upstream → SERVFAIL with original question echoed back.
        assert_eq!(resp.header.rescode, ResultCode::SERVFAIL);
        assert_eq!(resp.questions.len(), 1);
        assert_eq!(resp.questions[0].name, "nonexistent.test");
    }

    #[tokio::test]
    async fn tcp_servfail_mirrors_client_opt() {
        // RFC 6891 §6.1.1 on the Err-branch; empty-questions drives it.
        let addr = spawn_tcp_server().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();

        let mut query = DnsPacket::new();
        query.header.id = 0xBEEF;
        query.header.recursion_desired = true;
        query.edns = Some(crate::packet::EdnsOpt::default());
        let resp = tcp_exchange(&mut stream, &query).await;

        assert_eq!(resp.header.rescode, ResultCode::SERVFAIL);
        assert!(resp.edns.is_some(), "SERVFAIL must mirror client's OPT");
    }

    #[tokio::test]
    async fn tcp_oversize_message_closes_connection() {
        // A length prefix above MAX_MSG_LEN must drop the connection rather
        // than allocate and read the whole message.
        let addr = spawn_tcp_server().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();

        let oversize = (MAX_MSG_LEN + 1) as u16;
        stream.write_all(&oversize.to_be_bytes()).await.unwrap();

        let mut buf = [0u8; 2];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "server must close after an oversized length prefix");
    }

    #[tokio::test]
    async fn tcp_concurrent_connections() {
        let addr = spawn_tcp_server().await;

        let mut handles = Vec::new();
        for i in 0..5u16 {
            handles.push(tokio::spawn(async move {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                let query = DnsPacket::query(0xC000 + i, "tcp-test.example", QueryType::A);
                let resp = tcp_exchange(&mut stream, &query).await;
                assert_eq!(resp.header.id, 0xC000 + i);
                assert_eq!(resp.header.rescode, ResultCode::NOERROR);
                assert_eq!(resp.answers.len(), 1);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }
    }

    // PROXY protocol v2 wiring check. The pp2 module is exhaustively tested
    // via dot::tests::pp2_*; this confirms tcp::accept_loop calls
    // pp2::handshake before handing off to the framed handler. Mirrors
    // doh::tests::pp2_doh_happy_path_ipv4.
    async fn spawn_tcp_server_with_pp(pp_from: &[&str]) -> SocketAddr {
        let upstream_addr = crate::testutil::blackhole_upstream();

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.zone_map = crate::config::ZoneMap::from_exact(vec![DnsRecord::A {
            domain: "tcp-test.example".to_string(),
            addr: std::net::Ipv4Addr::new(10, 0, 0, 1),
            ttl: 300,
        }]);
        ctx.upstream_pool = Mutex::new(crate::forward::UpstreamPool::new(
            vec![crate::forward::Upstream::Udp(upstream_addr)],
            vec![],
        ));
        let ctx = Arc::new(ctx);

        let pp_cfg = crate::config::ProxyProtocolConfig {
            from: pp_from.iter().map(|s| s.to_string()).collect(),
            header_timeout_ms: 500,
        };
        let pp = PpConfig::from_config(&pp_cfg).unwrap().map(Arc::new);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(accept_loop(listener, pp, ctx));
        addr
    }

    fn pp2_v4_proxy_header(
        src_ip: std::net::Ipv4Addr,
        dst_ip: std::net::Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut h = Vec::with_capacity(28);
        h.extend_from_slice(&[
            0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
        ]);
        h.push(0x21); // v2 PROXY
        h.push(0x11); // TCP/IPv4
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&src_ip.octets());
        h.extend_from_slice(&dst_ip.octets());
        h.extend_from_slice(&src_port.to_be_bytes());
        h.extend_from_slice(&dst_port.to_be_bytes());
        h
    }

    #[tokio::test]
    async fn pp2_tcp_happy_path_ipv4() {
        let addr = spawn_tcp_server_with_pp(&["127.0.0.1"]).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let pp = pp2_v4_proxy_header(
            "203.0.113.42".parse().unwrap(),
            "10.0.0.5".parse().unwrap(),
            54321,
            53,
        );
        stream.write_all(&pp).await.unwrap();

        let query = DnsPacket::query(0xD001, "tcp-test.example", QueryType::A);
        let resp = tcp_exchange(&mut stream, &query).await;
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert_eq!(resp.answers.len(), 1);
    }

    // ---- Aggregate resolution admission (P0-1, issue #230) ----

    /// A resolver whose upstream never answers, so every admitted query stays
    /// in flight, plus the ctx to sample it through.
    async fn spawn_tcp_server_for_flood(limit: usize) -> (SocketAddr, Arc<ServerCtx>) {
        let mut ctx = crate::testutil::test_ctx().await;
        // Long enough that every admitted resolution is still in flight when
        // sampled, so nothing frees a permit and understates the peak.
        ctx.timeout = Duration::from_secs(30);
        ctx.admission = crate::admission::ResolutionAdmission::new(limit);
        ctx.upstream_pool = Mutex::new(crate::forward::UpstreamPool::new(
            vec![crate::forward::Upstream::Udp(
                crate::testutil::blackhole_upstream(),
            )],
            vec![],
        ));
        let ctx = Arc::new(ctx);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(accept_loop(listener, None, Arc::clone(&ctx)));
        (addr, ctx)
    }

    /// P0-1 of docs/implementation/public-resolver-security-hardening.md: the
    /// ceiling is shared across transports, and `MAX_CONNECTIONS` is not it.
    /// Below the connection cap every connection used to buy an unmetered
    /// resolution, so concurrent work scaled 1:1 with connections. A refused
    /// stream query gets SERVFAIL rather than the silent drop UDP gets.
    #[tokio::test]
    async fn tcp_connection_flood_is_capped_by_admission() {
        // Deliberately below MAX_CONNECTIONS so the connection cap, which is
        // not the mechanism under test, never engages.
        const FLOOD: usize = 300;
        const LIMIT: usize = 32;
        const _: () = assert!(FLOOD < MAX_CONNECTIONS);

        let (addr, ctx) = spawn_tcp_server_for_flood(LIMIT).await;

        let readers: Vec<_> = (0..FLOOD)
            .map(|i| {
                tokio::spawn(async move {
                    let mut stream = TcpStream::connect(addr).await.unwrap();
                    let query =
                        DnsPacket::query(0xBEEF, &format!("r{i}.flood.example"), QueryType::A);
                    send_query(&mut stream, &query).await;
                    // Admitted queries hang on the blackhole; refusals answer
                    // at once. Hold the stream open either way.
                    let reply = read_reply(&mut stream, Duration::from_millis(500)).await;
                    (stream, reply)
                })
            })
            .collect();

        let sample_ctx = Arc::clone(&ctx);
        let inflight = crate::testutil::wait_until_settled(
            move || sample_ctx.inflight.lock().unwrap().len(),
            Duration::from_secs(10),
        )
        .await;
        assert_eq!(
            inflight, LIMIT,
            "{FLOOD} TCP connections must not open more than {LIMIT} resolutions"
        );

        let mut refused = 0;
        let mut conns = Vec::with_capacity(FLOOD);
        for r in readers {
            let (stream, reply) = r.await.unwrap();
            if let Some(resp) = reply {
                assert_eq!(
                    resp.header.rescode,
                    ResultCode::SERVFAIL,
                    "a refused stream query answers, it does not hang"
                );
                refused += 1;
            }
            conns.push(stream);
        }
        assert_eq!(refused, FLOOD - LIMIT);
        drop(conns);
    }
}
