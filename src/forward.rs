use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::buffer::BytePacketBuffer;
use crate::packet::DnsPacket;
use crate::Result;

#[derive(Clone)]
pub enum Upstream {
    Udp(SocketAddr),
    Doh {
        url: String,
        client: reqwest::Client,
    },
}

impl PartialEq for Upstream {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Udp(a), Self::Udp(b)) => a == b,
            (Self::Doh { url: a, .. }, Self::Doh { url: b, .. }) => a == b,
            _ => false,
        }
    }
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Upstream::Udp(addr) => write!(f, "{}", addr),
            Upstream::Doh { url, .. } => f.write_str(url),
        }
    }
}

pub async fn forward_query(
    query: &DnsPacket,
    upstream: &Upstream,
    timeout_duration: Duration,
) -> Result<DnsPacket> {
    match upstream {
        Upstream::Udp(addr) => forward_udp(query, *addr, timeout_duration).await,
        Upstream::Doh { url, client } => forward_doh(query, url, client, timeout_duration).await,
    }
}

pub(crate) async fn forward_udp(
    query: &DnsPacket,
    upstream: SocketAddr,
    timeout_duration: Duration,
) -> Result<DnsPacket> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    let mut send_buffer = BytePacketBuffer::new();
    query.write(&mut send_buffer)?;

    socket.send_to(send_buffer.filled(), upstream).await?;

    let mut recv_buffer = BytePacketBuffer::new();
    let (size, _) = timeout(timeout_duration, socket.recv_from(&mut recv_buffer.buf)).await??;

    if size == recv_buffer.buf.len() {
        log::debug!(
            "upstream response truncated ({} bytes, buffer {})",
            size,
            recv_buffer.buf.len()
        );
    }

    DnsPacket::from_buffer(&mut recv_buffer)
}

/// DNS over TCP (RFC 1035 §4.2.2): 2-byte length prefix, then the DNS message.
pub(crate) async fn forward_tcp(
    query: &DnsPacket,
    upstream: SocketAddr,
    timeout_duration: Duration,
) -> Result<DnsPacket> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut send_buffer = BytePacketBuffer::new();
    query.write(&mut send_buffer)?;
    let msg = send_buffer.filled();

    let mut stream = timeout(timeout_duration, TcpStream::connect(upstream)).await??;

    // Write length-prefixed message
    stream.write_all(&(msg.len() as u16).to_be_bytes()).await?;
    stream.write_all(msg).await?;

    // Read length-prefixed response
    let mut len_buf = [0u8; 2];
    timeout(timeout_duration, stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut data = vec![0u8; resp_len];
    timeout(timeout_duration, stream.read_exact(&mut data)).await??;

    let mut recv_buffer = BytePacketBuffer::from_bytes(&data);
    DnsPacket::from_buffer(&mut recv_buffer)
}

async fn forward_doh(
    query: &DnsPacket,
    url: &str,
    client: &reqwest::Client,
    timeout_duration: Duration,
) -> Result<DnsPacket> {
    let mut send_buffer = BytePacketBuffer::new();
    query.write(&mut send_buffer)?;

    let resp = timeout(
        timeout_duration,
        client
            .post(url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(send_buffer.filled().to_vec())
            .send(),
    )
    .await??
    .error_for_status()?;

    let bytes = resp.bytes().await?;
    log::debug!("DoH response: {} bytes", bytes.len());

    let mut recv_buffer = BytePacketBuffer::from_bytes(&bytes);
    DnsPacket::from_buffer(&mut recv_buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::IntoFuture;

    use crate::header::ResultCode;
    use crate::question::{DnsQuestion, QueryType};
    use crate::record::DnsRecord;

    #[test]
    fn upstream_display_udp() {
        let u = Upstream::Udp("9.9.9.9:53".parse().unwrap());
        assert_eq!(u.to_string(), "9.9.9.9:53");
    }

    #[test]
    fn upstream_display_doh() {
        let u = Upstream::Doh {
            url: "https://dns.quad9.net/dns-query".to_string(),
            client: reqwest::Client::new(),
        };
        assert_eq!(u.to_string(), "https://dns.quad9.net/dns-query");
    }

    fn make_query() -> DnsPacket {
        let mut q = DnsPacket::new();
        q.header.id = 0xABCD;
        q.header.recursion_desired = true;
        q.questions
            .push(DnsQuestion::new("example.com".to_string(), QueryType::A));
        q
    }

    fn make_response(query: &DnsPacket) -> DnsPacket {
        let mut resp = DnsPacket::response_from(query, ResultCode::NOERROR);
        resp.answers.push(DnsRecord::A {
            domain: "example.com".to_string(),
            addr: "93.184.216.34".parse().unwrap(),
            ttl: 300,
        });
        resp
    }

    fn to_wire(pkt: &DnsPacket) -> Vec<u8> {
        let mut buf = BytePacketBuffer::new();
        pkt.write(&mut buf).unwrap();
        buf.filled().to_vec()
    }

    #[tokio::test]
    async fn doh_mock_server_resolves() {
        let query = make_query();
        let response_bytes = to_wire(&make_response(&query));

        let app = axum::Router::new().route(
            "/dns-query",
            axum::routing::post(move || {
                let body = response_bytes.clone();
                async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/dns-message")],
                        body,
                    )
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        let upstream = Upstream::Doh {
            url: format!("http://{}/dns-query", addr),
            client: reqwest::Client::new(),
        };

        let result = forward_query(&query, &upstream, Duration::from_secs(2))
            .await
            .expect("DoH forward should succeed");

        assert_eq!(result.header.id, 0xABCD);
        assert!(result.header.response);
        assert_eq!(result.header.rescode, ResultCode::NOERROR);
        assert_eq!(result.answers.len(), 1);
        match &result.answers[0] {
            DnsRecord::A { domain, addr, ttl } => {
                assert_eq!(domain, "example.com");
                assert_eq!(
                    *addr,
                    "93.184.216.34".parse::<std::net::Ipv4Addr>().unwrap()
                );
                assert_eq!(*ttl, 300);
            }
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn doh_http_error_propagates() {
        let app = axum::Router::new().route(
            "/dns-query",
            axum::routing::post(|| async {
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "bad")
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        let upstream = Upstream::Doh {
            url: format!("http://{}/dns-query", addr),
            client: reqwest::Client::new(),
        };

        let result = forward_query(&make_query(), &upstream, Duration::from_secs(2)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn doh_timeout() {
        let app = axum::Router::new().route(
            "/dns-query",
            axum::routing::post(|| async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                "never"
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        let upstream = Upstream::Doh {
            url: format!("http://{}/dns-query", addr),
            client: reqwest::Client::new(),
        };

        let result = forward_query(&make_query(), &upstream, Duration::from_millis(100)).await;
        assert!(result.is_err());
    }
}
