use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::buffer::BytePacketBuffer;
use crate::packet::DnsPacket;
use crate::srtt::SrttCache;
use crate::Result;

#[derive(Clone)]
pub enum Upstream {
    Udp(SocketAddr),
    Doh {
        url: String,
        client: reqwest::Client,
    },
    Dot {
        addr: SocketAddr,
        tls_name: Option<String>,
        connector: tokio_rustls::TlsConnector,
    },
}

impl PartialEq for Upstream {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Udp(a), Self::Udp(b)) => a == b,
            (Self::Doh { url: a, .. }, Self::Doh { url: b, .. }) => a == b,
            (Self::Dot { addr: a, .. }, Self::Dot { addr: b, .. }) => a == b,
            _ => false,
        }
    }
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Upstream::Udp(addr) => write!(f, "{}", addr),
            Upstream::Doh { url, .. } => f.write_str(url),
            Upstream::Dot { addr, tls_name, .. } => match tls_name {
                Some(name) => write!(f, "tls://{}#{}", addr, name),
                None => write!(f, "tls://{}", addr),
            },
        }
    }
}

pub fn parse_upstream_addr(s: &str, default_port: u16) -> std::result::Result<SocketAddr, String> {
    // Try full socket addr first: "1.2.3.4:5353" or "[::1]:5353"
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // Bare IP: "1.2.3.4" or "::1"
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    Err(format!("invalid upstream address: {}", s))
}

pub fn parse_upstream(s: &str, default_port: u16) -> Result<Upstream> {
    if s.starts_with("https://") {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .http2_initial_stream_window_size(65_535)
            .http2_initial_connection_window_size(65_535)
            .http2_keep_alive_interval(Duration::from_secs(15))
            .http2_keep_alive_while_idle(true)
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(1)
            .build()
            .unwrap_or_default();
        return Ok(Upstream::Doh {
            url: s.to_string(),
            client,
        });
    }
    // tls://IP:PORT#hostname  or  tls://IP#hostname  (default port 853)
    if let Some(rest) = s.strip_prefix("tls://") {
        let (addr_part, tls_name) = match rest.find('#') {
            Some(i) => (&rest[..i], Some(rest[i + 1..].to_string())),
            None => (rest, None),
        };
        let addr = parse_upstream_addr(addr_part, 853)?;
        let connector = build_dot_connector()?;
        return Ok(Upstream::Dot {
            addr,
            tls_name,
            connector,
        });
    }
    let addr = parse_upstream_addr(s, default_port)?;
    Ok(Upstream::Udp(addr))
}

fn build_dot_connector() -> Result<tokio_rustls::TlsConnector> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        config,
    )))
}

#[derive(Clone)]
pub struct UpstreamPool {
    primary: Vec<Upstream>,
    fallback: Vec<Upstream>,
}

impl UpstreamPool {
    pub fn new(primary: Vec<Upstream>, fallback: Vec<Upstream>) -> Self {
        Self { primary, fallback }
    }

    pub fn preferred(&self) -> Option<&Upstream> {
        self.primary.first().or(self.fallback.first())
    }

    pub fn set_primary(&mut self, primary: Vec<Upstream>) {
        self.primary = primary;
    }

    /// Update the primary upstream if `new_addr` (parsed with `port`) differs
    /// from the current preferred upstream. Returns `true` if the pool changed.
    pub fn maybe_update_primary(&mut self, new_addr: &str, port: u16) -> bool {
        let Ok(new_sock) = format!("{}:{}", new_addr, port).parse::<SocketAddr>() else {
            return false;
        };
        let new_upstream = Upstream::Udp(new_sock);
        if self.preferred() == Some(&new_upstream) {
            return false;
        }
        self.primary = vec![new_upstream];
        true
    }

    pub fn label(&self) -> String {
        match self.preferred() {
            Some(u) => {
                let total = self.primary.len() + self.fallback.len();
                if total > 1 {
                    format!("{} (+{} more)", u, total - 1)
                } else {
                    u.to_string()
                }
            }
            None => "none".to_string(),
        }
    }
}

pub async fn forward_with_failover(
    query: &DnsPacket,
    pool: &UpstreamPool,
    srtt: &RwLock<SrttCache>,
    timeout_duration: Duration,
) -> Result<DnsPacket> {
    // Build candidate list: primary (sorted by SRTT for UDP) then fallback
    let mut candidates: Vec<(usize, u64)> = pool
        .primary
        .iter()
        .enumerate()
        .map(|(i, u)| {
            let rtt = match u {
                Upstream::Udp(addr) => srtt.read().unwrap().get(addr.ip()),
                _ => 0, // DoH: keep config order (stable sort preserves it)
            };
            (i, rtt)
        })
        .collect();
    candidates.sort_by_key(|&(_, rtt)| rtt);

    let all_upstreams: Vec<&Upstream> = candidates
        .iter()
        .map(|&(i, _)| &pool.primary[i])
        .chain(pool.fallback.iter())
        .collect();

    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;

    for upstream in &all_upstreams {
        let start = Instant::now();
        match forward_query(query, upstream, timeout_duration).await {
            Ok(resp) => {
                if let Upstream::Udp(addr) = upstream {
                    let rtt_ms = start.elapsed().as_millis() as u64;
                    srtt.write().unwrap().record_rtt(addr.ip(), rtt_ms, false);
                }
                return Ok(resp);
            }
            Err(e) => {
                if let Upstream::Udp(addr) = upstream {
                    srtt.write().unwrap().record_failure(addr.ip());
                }
                log::debug!("upstream {} failed: {}", upstream, e);
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| "no upstream configured".into()))
}

pub async fn forward_query(
    query: &DnsPacket,
    upstream: &Upstream,
    timeout_duration: Duration,
) -> Result<DnsPacket> {
    match upstream {
        Upstream::Udp(addr) => forward_udp(query, *addr, timeout_duration).await,
        Upstream::Doh { url, client } => forward_doh(query, url, client, timeout_duration).await,
        Upstream::Dot {
            addr,
            tls_name,
            connector,
        } => forward_dot(query, *addr, tls_name, connector, timeout_duration).await,
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

    // Single write: Microsoft/Azure DNS servers close TCP connections on split segments
    let mut outbuf = Vec::with_capacity(2 + msg.len());
    outbuf.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    outbuf.extend_from_slice(msg);
    stream.write_all(&outbuf).await?;

    // Read length-prefixed response
    let mut len_buf = [0u8; 2];
    timeout(timeout_duration, stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut data = vec![0u8; resp_len];
    timeout(timeout_duration, stream.read_exact(&mut data)).await??;

    let mut recv_buffer = BytePacketBuffer::from_bytes(&data);
    DnsPacket::from_buffer(&mut recv_buffer)
}

async fn forward_dot(
    query: &DnsPacket,
    addr: SocketAddr,
    tls_name: &Option<String>,
    connector: &tokio_rustls::TlsConnector,
    timeout_duration: Duration,
) -> Result<DnsPacket> {
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let server_name = match tls_name {
        Some(name) => ServerName::try_from(name.clone())?,
        None => ServerName::try_from(addr.ip().to_string())?,
    };

    let tcp = timeout(timeout_duration, TcpStream::connect(addr)).await??;
    let mut tls = timeout(timeout_duration, connector.connect(server_name, tcp)).await??;

    let mut send_buffer = BytePacketBuffer::new();
    query.write(&mut send_buffer)?;
    let wire = send_buffer.filled();

    let mut outbuf = Vec::with_capacity(2 + wire.len());
    outbuf.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    outbuf.extend_from_slice(wire);
    timeout(timeout_duration, tls.write_all(&outbuf)).await??;

    let mut len_buf = [0u8; 2];
    timeout(timeout_duration, tls.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut data = vec![0u8; resp_len];
    timeout(timeout_duration, tls.read_exact(&mut data)).await??;

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

    let resp_bytes = forward_doh_raw(send_buffer.filled(), url, client, timeout_duration).await?;
    let mut recv_buffer = BytePacketBuffer::from_bytes(&resp_bytes);
    DnsPacket::from_buffer(&mut recv_buffer)
}

pub async fn forward_query_raw(
    wire: &[u8],
    upstream: &Upstream,
    timeout_duration: Duration,
) -> Result<Vec<u8>> {
    match upstream {
        Upstream::Udp(addr) => forward_udp_raw(wire, *addr, timeout_duration).await,
        Upstream::Doh { url, client } => forward_doh_raw(wire, url, client, timeout_duration).await,
    }
}

pub async fn forward_with_hedging_raw(
    wire: &[u8],
    primary: &Upstream,
    secondary: &Upstream,
    hedge_delay: Duration,
    timeout_duration: Duration,
) -> Result<Vec<u8>> {
    use tokio::time::sleep;

    let primary_fut = forward_query_raw(wire, primary, timeout_duration);
    tokio::pin!(primary_fut);

    let delay = sleep(hedge_delay);
    tokio::pin!(delay);

    // Phase 1: wait for either primary to return, or the hedge delay.
    tokio::select! {
        result = &mut primary_fut => return result,
        _ = &mut delay => {}
    }

    // Phase 2: hedge delay expired — fire secondary while still polling primary.
    let secondary_fut = forward_query_raw(wire, secondary, timeout_duration);
    tokio::pin!(secondary_fut);

    // First successful response wins. If one errors, wait for the other.
    let mut primary_err: Option<crate::Error> = None;
    let mut secondary_err: Option<crate::Error> = None;

    loop {
        tokio::select! {
            r = &mut primary_fut, if primary_err.is_none() => {
                match r {
                    Ok(resp) => return Ok(resp),
                    Err(e) => {
                        if let Some(se) = secondary_err.take() {
                            return Err(se);
                        }
                        primary_err = Some(e);
                    }
                }
            }
            r = &mut secondary_fut, if secondary_err.is_none() => {
                match r {
                    Ok(resp) => return Ok(resp),
                    Err(e) => {
                        if let Some(pe) = primary_err.take() {
                            return Err(pe);
                        }
                        secondary_err = Some(e);
                    }
                }
            }
        }

        match (primary_err, secondary_err) {
            (Some(pe), Some(_)) => return Err(pe),
            (pe, se) => { primary_err = pe; secondary_err = se; }
        }
    }
}

pub async fn forward_with_failover_raw(
    wire: &[u8],
    pool: &UpstreamPool,
    srtt: &RwLock<SrttCache>,
    timeout_duration: Duration,
    hedge_delay: Duration,
) -> Result<Vec<u8>> {
    let mut candidates: Vec<(usize, u64)> = pool
        .primary
        .iter()
        .enumerate()
        .map(|(i, u)| {
            let rtt = match u {
                Upstream::Udp(addr) => srtt.read().unwrap().get(addr.ip()),
                _ => 0,
            };
            (i, rtt)
        })
        .collect();
    candidates.sort_by_key(|&(_, rtt)| rtt);

    let all_upstreams: Vec<&Upstream> = candidates
        .iter()
        .map(|&(i, _)| &pool.primary[i])
        .chain(pool.fallback.iter())
        .collect();

    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;

    for upstream in &all_upstreams {
        let start = Instant::now();
        let result = if !hedge_delay.is_zero() && matches!(upstream, Upstream::Doh { .. }) {
            // Hedge against the same upstream: parallel h2 streams on same
            // connection. Independent stream scheduling rescues dispatch spikes.
            forward_with_hedging_raw(wire, upstream, upstream, hedge_delay, timeout_duration).await
        } else {
            forward_query_raw(wire, upstream, timeout_duration).await
        };
        match result {
            Ok(resp) => {
                if let Upstream::Udp(addr) = upstream {
                    let rtt_ms = start.elapsed().as_millis() as u64;
                    srtt.write().unwrap().record_rtt(addr.ip(), rtt_ms, false);
                }
                return Ok(resp);
            }
            Err(e) => {
                if let Upstream::Udp(addr) = upstream {
                    srtt.write().unwrap().record_failure(addr.ip());
                }
                log::debug!("upstream {} failed: {}", upstream, e);
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| "no upstream configured".into()))
}

async fn forward_udp_raw(
    wire: &[u8],
    upstream: SocketAddr,
    timeout_duration: Duration,
) -> Result<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(wire, upstream).await?;

    let mut recv_buf = vec![0u8; 4096];
    let (size, _) = timeout(timeout_duration, socket.recv_from(&mut recv_buf)).await??;
    recv_buf.truncate(size);
    Ok(recv_buf)
}

async fn forward_doh_raw(
    wire: &[u8],
    url: &str,
    client: &reqwest::Client,
    timeout_duration: Duration,
) -> Result<Vec<u8>> {
    let resp = timeout(
        timeout_duration,
        client
            .post(url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(wire.to_vec())
            .send(),
    )
    .await??
    .error_for_status()?;

    let bytes = resp.bytes().await?;
    log::debug!("DoH response: {} bytes", bytes.len());
    Ok(bytes.to_vec())
}

/// Send a lightweight keepalive query to a DoH upstream to prevent
/// the HTTP/2 + TLS connection from going idle and being torn down.
pub async fn keepalive_doh(upstream: &Upstream) {
    if let Upstream::Doh { url, client } = upstream {
        // Query for . NS — minimal, always succeeds, response is small
        let wire: &[u8] = &[
            0x00, 0x00, // ID
            0x01, 0x00, // flags: RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN=0, NS=0, AR=0
            0x00,       // root name (.)
            0x00, 0x02, // type NS
            0x00, 0x01, // class IN
        ];
        let _ = forward_doh_raw(wire, url, client, Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::IntoFuture;

    use crate::header::ResultCode;
    use crate::question::QueryType;
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
        DnsPacket::query(0xABCD, "example.com", QueryType::A)
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

    #[test]
    fn parse_addr_ip_only() {
        let addr = parse_upstream_addr("1.2.3.4", 53).unwrap();
        assert_eq!(addr, "1.2.3.4:53".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_addr_ip_port() {
        let addr = parse_upstream_addr("1.2.3.4:5353", 53).unwrap();
        assert_eq!(addr, "1.2.3.4:5353".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_addr_ipv6_bracketed() {
        let addr = parse_upstream_addr("[::1]:5553", 53).unwrap();
        assert_eq!(addr, "[::1]:5553".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_addr_ipv6_bare() {
        let addr = parse_upstream_addr("::1", 53).unwrap();
        assert_eq!(addr, "[::1]:53".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn pool_label_single() {
        let pool = UpstreamPool::new(vec![Upstream::Udp("1.2.3.4:53".parse().unwrap())], vec![]);
        assert_eq!(pool.label(), "1.2.3.4:53");
    }

    #[test]
    fn pool_label_multi() {
        let pool = UpstreamPool::new(
            vec![Upstream::Udp("1.2.3.4:53".parse().unwrap())],
            vec![Upstream::Udp("8.8.8.8:53".parse().unwrap())],
        );
        assert_eq!(pool.label(), "1.2.3.4:53 (+1 more)");
    }

    #[tokio::test]
    async fn failover_tries_next_on_failure() {
        // First upstream is unreachable, second responds
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
        let good_addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        // Unreachable UDP upstream + working DoH upstream
        let pool = UpstreamPool::new(
            vec![
                Upstream::Udp("127.0.0.1:1".parse().unwrap()), // will fail
                Upstream::Doh {
                    url: format!("http://{}/dns-query", good_addr),
                    client: reqwest::Client::new(),
                },
            ],
            vec![],
        );

        let srtt = RwLock::new(SrttCache::new(true));
        let result = forward_with_failover(&query, &pool, &srtt, Duration::from_millis(500))
            .await
            .expect("should fail over to second upstream");

        assert_eq!(result.header.id, 0xABCD);
        assert_eq!(result.answers.len(), 1);
    }

    #[test]
    fn maybe_update_primary_swaps_when_different() {
        let mut pool = UpstreamPool::new(
            vec![Upstream::Udp("1.2.3.4:53".parse().unwrap())],
            vec![Upstream::Udp("8.8.8.8:53".parse().unwrap())],
        );
        assert!(pool.maybe_update_primary("5.6.7.8", 53));
        assert_eq!(pool.preferred().unwrap().to_string(), "5.6.7.8:53");
    }

    #[test]
    fn maybe_update_primary_noop_when_same() {
        let mut pool =
            UpstreamPool::new(vec![Upstream::Udp("1.2.3.4:53".parse().unwrap())], vec![]);
        assert!(!pool.maybe_update_primary("1.2.3.4", 53));
    }

    #[test]
    fn maybe_update_primary_rejects_invalid_addr() {
        let mut pool =
            UpstreamPool::new(vec![Upstream::Udp("1.2.3.4:53".parse().unwrap())], vec![]);
        assert!(!pool.maybe_update_primary("not-an-ip", 53));
        assert_eq!(pool.preferred().unwrap().to_string(), "1.2.3.4:53");
    }
}
