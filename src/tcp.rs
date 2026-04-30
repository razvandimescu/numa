//! Plain DNS-over-TCP listener (RFC 1035 §4.2.2, RFC 7766).
//!
//! TCP support is not optional: when a UDP response exceeds the client's
//! advertised buffer (or 512 bytes without EDNS0), numa sets the TC bit and
//! a compliant client retries the same query over TCP on the same `bind_addr`.
//! Without this listener, those retries silently fail.
//!
//! Connection model mirrors `dot.rs`: bounded concurrency, per-connection
//! idle timeout, length-prefixed framing, FORMERR for parse errors.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::buffer::BytePacketBuffer;
use crate::ctx::{resolve_query, ServerCtx};
use crate::header::ResultCode;
use crate::packet::DnsPacket;
use crate::stats::Transport;

const MAX_CONNECTIONS: usize = 512;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
// Matches BytePacketBuffer::BUF_SIZE — RFC 1035 allows up to 65535 but our
// buffer would silently truncate anything larger.
const MAX_MSG_LEN: usize = 4096;

/// Start the DNS-over-TCP listener on the same address as the UDP listener.
pub async fn start_tcp(ctx: Arc<ServerCtx>, bind_addr: &str) {
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

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("TCP: could not bind {} ({}) — TCP DNS disabled", addr, e);
            return;
        }
    };
    info!("TCP DNS listening on {}", addr);

    accept_loop(listener, ctx).await;
}

async fn accept_loop(listener: TcpListener, ctx: Arc<ServerCtx>) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        let (stream, peer) = match listener.accept().await {
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
                debug!("TCP: connection limit reached, rejecting {}", peer);
                continue;
            }
        };
        let ctx = Arc::clone(&ctx);

        tokio::spawn(async move {
            let _permit = permit;
            handle_tcp_connection(stream, peer, &ctx).await;
        });
    }
}

/// Handle a single persistent TCP connection (RFC 7766 §6.2.1).
/// Reads length-prefixed DNS queries until EOF, idle timeout, or error.
async fn handle_tcp_connection<S>(mut stream: S, remote_addr: SocketAddr, ctx: &Arc<ServerCtx>)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    loop {
        // Read 2-byte length prefix (RFC 1035 §4.2.2) with idle timeout.
        let mut len_buf = [0u8; 2];
        let Ok(Ok(_)) = tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await
        else {
            break;
        };
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len > MAX_MSG_LEN {
            debug!("TCP: oversized message {} from {}", msg_len, remote_addr);
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
                let query_id = u16::from_be_bytes([buffer.buf[0], buffer.buf[1]]);
                let mut resp = DnsPacket::new();
                resp.header.id = query_id;
                resp.header.response = true;
                resp.header.rescode = ResultCode::FORMERR;
                if send_response(&mut stream, &resp, remote_addr)
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
            Transport::Tcp,
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
                let resp = DnsPacket::response_from(&query, ResultCode::SERVFAIL);
                if send_response(&mut stream, &resp, remote_addr)
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
) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let mut out_buf = BytePacketBuffer::new();
    if resp.write(&mut out_buf).is_err() {
        debug!(
            "TCP: failed to serialize {:?} response for {}",
            resp.header.rescode, remote_addr
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
    use std::collections::HashMap;
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
        ctx.zone_map = {
            let mut m = HashMap::new();
            let mut inner = HashMap::new();
            inner.insert(
                QueryType::A,
                vec![DnsRecord::A {
                    domain: "tcp-test.example".to_string(),
                    addr: std::net::Ipv4Addr::new(10, 0, 0, 1),
                    ttl: 300,
                }],
            );
            m.insert("tcp-test.example".to_string(), inner);
            m
        };
        ctx.upstream_pool = Mutex::new(crate::forward::UpstreamPool::new(
            vec![crate::forward::Upstream::Udp(upstream_addr)],
            vec![],
        ));
        let ctx = Arc::new(ctx);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(accept_loop(listener, ctx));
        addr
    }

    async fn tcp_exchange(stream: &mut TcpStream, query: &DnsPacket) -> DnsPacket {
        let mut buf = BytePacketBuffer::new();
        query.write(&mut buf).unwrap();
        let msg = buf.filled();

        let mut out = Vec::with_capacity(2 + msg.len());
        out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        out.extend_from_slice(msg);
        stream.write_all(&out).await.unwrap();

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut data = vec![0u8; resp_len];
        stream.read_exact(&mut data).await.unwrap();

        let mut resp_buf = BytePacketBuffer::from_bytes(&data);
        DnsPacket::from_buffer(&mut resp_buf).unwrap()
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
}
