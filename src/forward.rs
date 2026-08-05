use std::borrow::Cow;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::buffer::BytePacketBuffer;
use crate::odoh::{query_through_relay, OdohConfigCache};
use crate::packet::DnsPacket;
use crate::srtt::SrttCache;
use crate::stats::UpstreamTransport;
use crate::Result;

#[derive(Clone)]
pub enum Upstream {
    Udp(SocketAddr),
    /// Plain DNS over TCP (RFC 1035 §4.2.2). Used as a UDP-fallback transport
    /// on networks that block outbound UDP:53 to non-self resolvers — common
    /// at carriers running BCP 38-style amplification mitigation.
    Tcp(SocketAddr),
    Doh {
        url: String,
        client: reqwest::Client,
    },
    Dot {
        addr: SocketAddr,
        tls_name: Option<String>,
        connector: tokio_rustls::TlsConnector,
    },
    /// Oblivious DNS-over-HTTPS (RFC 9230). Queries are HPKE-sealed to the
    /// target and forwarded through an independent relay. Target host lives
    /// on `target_config` (single source of truth — the cache keys on it).
    Odoh {
        relay_url: String,
        target_path: String,
        client: reqwest::Client,
        target_config: Arc<OdohConfigCache>,
    },
}

impl Upstream {
    /// SRTT key, when the upstream has a stable IP. `Doh`/`Odoh` route
    /// through a URL + connection pool, so they never key here.
    pub fn tracked_key(&self) -> Option<(IpAddr, UpstreamTransport)> {
        let ip = match self {
            Upstream::Udp(a) | Upstream::Tcp(a) | Upstream::Dot { addr: a, .. } => a.ip(),
            Upstream::Doh { .. } | Upstream::Odoh { .. } => return None,
        };
        Some((ip, self.transport()))
    }

    pub fn transport(&self) -> UpstreamTransport {
        match self {
            Upstream::Udp(_) => UpstreamTransport::Udp,
            Upstream::Tcp(_) => UpstreamTransport::Tcp,
            Upstream::Doh { .. } => UpstreamTransport::Doh,
            Upstream::Dot { .. } => UpstreamTransport::Dot,
            Upstream::Odoh { .. } => UpstreamTransport::Odoh,
        }
    }
}

impl PartialEq for Upstream {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Udp(a), Self::Udp(b)) => a == b,
            (Self::Tcp(a), Self::Tcp(b)) => a == b,
            (Self::Doh { url: a, .. }, Self::Doh { url: b, .. }) => a == b,
            (Self::Dot { addr: a, .. }, Self::Dot { addr: b, .. }) => a == b,
            (
                Self::Odoh {
                    relay_url: ra,
                    target_path: pa,
                    target_config: ca,
                    ..
                },
                Self::Odoh {
                    relay_url: rb,
                    target_path: pb,
                    target_config: cb,
                    ..
                },
            ) => ra == rb && pa == pb && ca.target_host() == cb.target_host(),
            _ => false,
        }
    }
}

impl fmt::Debug for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Upstream::Udp(addr) => write!(f, "{}", addr),
            Upstream::Tcp(addr) => write!(f, "tcp://{}", addr),
            Upstream::Doh { url, .. } => f.write_str(url),
            Upstream::Dot { addr, tls_name, .. } => match tls_name {
                Some(name) => write!(f, "tls://{}#{}", addr, name),
                None => write!(f, "tls://{}", addr),
            },
            Upstream::Odoh {
                relay_url,
                target_path,
                target_config,
                ..
            } => write!(
                f,
                "odoh://{}{} via {}",
                target_config.target_host(),
                target_path,
                relay_url
            ),
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

/// Parse a slice of upstream address strings into `Upstream` values, failing
/// on the first invalid entry. DoH entries use `resolver` (when provided) as
/// their hostname resolver.
pub fn parse_upstream_list(
    addrs: &[String],
    default_port: u16,
    resolver: Option<Arc<crate::bootstrap_resolver::NumaResolver>>,
) -> Result<Vec<Upstream>> {
    addrs
        .iter()
        .map(|s| parse_upstream(s, default_port, resolver.clone()))
        .collect()
}

pub fn parse_upstream(
    s: &str,
    default_port: u16,
    resolver: Option<Arc<crate::bootstrap_resolver::NumaResolver>>,
) -> Result<Upstream> {
    if s.starts_with("https://") {
        return Ok(Upstream::Doh {
            url: s.to_string(),
            client: build_https_client_with_resolver(1, resolver),
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
    // tcp://IP:PORT  or  tcp://IP  (default port = `default_port`, typically 53)
    if let Some(rest) = s.strip_prefix("tcp://") {
        let addr = parse_upstream_addr(rest, default_port)?;
        return Ok(Upstream::Tcp(addr));
    }
    let addr = parse_upstream_addr(s, default_port)?;
    Ok(Upstream::Udp(addr))
}

/// HTTP/2 client tuned for DoH/ODoH: small windows for low latency, long-lived
/// keep-alive. Pool defaults to one idle conn per host — good for resolvers
/// that talk to a single upstream; relays that fan out to many targets
/// should use [`build_https_client_with_pool`].
///
/// Uses the system resolver. Callers running inside `serve::run` pass the
/// shared [`crate::bootstrap_resolver::NumaResolver`] via
/// [`build_https_client_with_resolver`] to avoid the self-loop (issue #122).
pub fn build_https_client() -> reqwest::Client {
    build_https_client_with_resolver(1, None)
}

/// Same shape as [`build_https_client`], but caller picks
/// `pool_max_idle_per_host`. Relay workloads hit many distinct target hosts
/// and benefit from a larger pool so warm connections survive concurrent
/// fan-out.
pub fn build_https_client_with_pool(pool_max_idle_per_host: usize) -> reqwest::Client {
    build_https_client_with_resolver(pool_max_idle_per_host, None)
}

/// [`build_https_client`] with an optional custom DNS resolver. Numa wires
/// [`crate::bootstrap_resolver::NumaResolver`] here.
pub fn build_https_client_with_resolver(
    pool_max_idle_per_host: usize,
    resolver: Option<Arc<crate::bootstrap_resolver::NumaResolver>>,
) -> reqwest::Client {
    let mut builder = https_client_builder(pool_max_idle_per_host);
    if let Some(r) = resolver {
        builder = builder.dns_resolver(r);
    }
    builder.build().unwrap_or_default()
}

/// The single place Numa configures reqwest TLS. Installs the ring
/// `CryptoProvider` (reqwest 0.13's `rustls-no-provider` ships none, so a
/// `Client` built without it panics; ring not aws-lc-rs keeps the armv6
/// cross-build) and pins validation to the bundled Mozilla roots, skipping
/// reqwest's default system-cert verifier (absent in the nix sandbox, a
/// liability for the static Pi binary; also restores Numa's 0.12 behaviour).
pub(crate) fn numa_tls_builder() -> reqwest::ClientBuilder {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|der| reqwest::Certificate::from_der(der).ok());
    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_certs_only(roots)
}

/// `Client::new()` for tests, but with Numa's TLS setup so it builds regardless
/// of test order or a missing system cert store.
#[cfg(test)]
pub(crate) fn default_client() -> reqwest::Client {
    numa_tls_builder().build().unwrap_or_default()
}

fn https_client_builder(pool_max_idle_per_host: usize) -> reqwest::ClientBuilder {
    numa_tls_builder()
        .http2_initial_stream_window_size(65_535)
        .http2_initial_connection_window_size(65_535)
        .http2_keep_alive_interval(Duration::from_secs(15))
        .http2_keep_alive_while_idle(true)
        .http2_keep_alive_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(300))
        .pool_max_idle_per_host(pool_max_idle_per_host)
}

fn build_dot_connector() -> Result<tokio_rustls::TlsConnector> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
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

    /// Replace the primary with `new` if it differs from the current preferred.
    /// Returns `true` if the pool changed.
    ///
    /// Keeps the TCP sibling in step with the primary. The sibling exists so
    /// Forward mode survives carriers that drop outbound UDP:53, but failover
    /// chains `fallback` *after* the primaries, so a sibling left over from the
    /// previous network is retried before anything reachable (#169).
    pub fn maybe_replace_primary(&mut self, new: Upstream) -> bool {
        if self.preferred() == Some(&new) {
            return false;
        }
        let stale_sibling = match self.primary.first() {
            Some(Upstream::Udp(addr)) => Some(Upstream::Tcp(*addr)),
            _ => None,
        };
        if let Some(stale) = stale_sibling {
            self.fallback.retain(|u| *u != stale);
        }
        if let Upstream::Udp(addr) = new {
            let sibling = Upstream::Tcp(addr);
            if !self.fallback.contains(&sibling) {
                self.fallback.push(sibling);
            }
        }
        self.primary = vec![new];
        true
    }

    /// Update the primary upstream if `new_addr` (parsed with `port`) differs
    /// from the current preferred upstream. Returns `true` if the pool changed.
    pub fn maybe_update_primary(&mut self, new_addr: &str, port: u16) -> bool {
        let Ok(new_sock) = format!("{}:{}", new_addr, port).parse::<SocketAddr>() else {
            return false;
        };
        self.maybe_replace_primary(Upstream::Udp(new_sock))
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

pub async fn forward_query(
    query: &DnsPacket,
    upstream: &Upstream,
    timeout_duration: Duration,
) -> Result<DnsPacket> {
    let mut send_buffer = BytePacketBuffer::new();
    query.write(&mut send_buffer)?;
    let data = forward_query_raw(send_buffer.filled(), upstream, timeout_duration).await?;
    let mut recv_buffer = BytePacketBuffer::from_bytes(&data);
    DnsPacket::from_buffer(&mut recv_buffer)
}

pub(crate) async fn forward_udp(
    query: &DnsPacket,
    upstream: SocketAddr,
    timeout_duration: Duration,
) -> Result<DnsPacket> {
    let mut send_buffer = BytePacketBuffer::new();
    query.write(&mut send_buffer)?;
    let data = forward_udp_raw(send_buffer.filled(), upstream, timeout_duration).await?;
    let mut recv_buffer = BytePacketBuffer::from_bytes(&data);
    DnsPacket::from_buffer(&mut recv_buffer)
}

/// DNS over TCP (RFC 1035 §4.2.2): 2-byte length prefix, then the DNS message.
pub(crate) async fn forward_tcp(
    query: &DnsPacket,
    upstream: SocketAddr,
    timeout_duration: Duration,
) -> Result<DnsPacket> {
    let mut send_buffer = BytePacketBuffer::new();
    query.write(&mut send_buffer)?;
    let data = forward_tcp_raw(send_buffer.filled(), upstream, timeout_duration).await?;
    let mut recv_buffer = BytePacketBuffer::from_bytes(&data);
    DnsPacket::from_buffer(&mut recv_buffer)
}

async fn forward_tcp_raw(
    wire: &[u8],
    upstream: SocketAddr,
    timeout_duration: Duration,
) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = timeout(timeout_duration, TcpStream::connect(upstream)).await??;

    // Single write: Microsoft/Azure DNS servers close TCP connections on split segments
    let mut outbuf = Vec::with_capacity(2 + wire.len());
    outbuf.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    outbuf.extend_from_slice(wire);
    stream.write_all(&outbuf).await?;

    // Read length-prefixed response
    let mut len_buf = [0u8; 2];
    timeout(timeout_duration, stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut data = vec![0u8; resp_len];
    timeout(timeout_duration, stream.read_exact(&mut data)).await??;

    Ok(data)
}

async fn forward_dot_raw(
    wire: &[u8],
    addr: SocketAddr,
    tls_name: &Option<String>,
    connector: &tokio_rustls::TlsConnector,
    timeout_duration: Duration,
) -> Result<Vec<u8>> {
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let server_name = match tls_name {
        Some(name) => ServerName::try_from(name.clone())?,
        None => ServerName::try_from(addr.ip().to_string())?,
    };

    let tcp = timeout(timeout_duration, TcpStream::connect(addr)).await??;
    let mut tls = timeout(timeout_duration, connector.connect(server_name, tcp)).await??;

    let mut outbuf = Vec::with_capacity(2 + wire.len());
    outbuf.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    outbuf.extend_from_slice(wire);
    timeout(timeout_duration, tls.write_all(&outbuf)).await??;

    let mut len_buf = [0u8; 2];
    timeout(timeout_duration, tls.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut data = vec![0u8; resp_len];
    timeout(timeout_duration, tls.read_exact(&mut data)).await??;

    Ok(data)
}

pub async fn forward_query_raw(
    wire: &[u8],
    upstream: &Upstream,
    timeout_duration: Duration,
) -> Result<Vec<u8>> {
    match upstream {
        Upstream::Udp(addr) => forward_udp_raw(wire, *addr, timeout_duration).await,
        Upstream::Tcp(addr) => forward_tcp_raw(wire, *addr, timeout_duration).await,
        Upstream::Doh { url, client } => forward_doh_raw(wire, url, client, timeout_duration).await,
        Upstream::Dot {
            addr,
            tls_name,
            connector,
        } => forward_dot_raw(wire, *addr, tls_name, connector, timeout_duration).await,
        Upstream::Odoh {
            relay_url,
            target_path,
            client,
            target_config,
        } => {
            query_through_relay(
                wire,
                relay_url,
                target_path,
                client,
                target_config,
                timeout_duration,
            )
            .await
        }
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
            (pe, se) => {
                primary_err = pe;
                secondary_err = se;
            }
        }
    }
}

const OPT_RECORD_TYPE: u16 = 41;
const DO_FLAG: u8 = 0x80;

enum OptSite {
    /// Offset of the OPT record's TTL field, whose third byte holds DO.
    Ttl(usize),
    Absent,
    Unparsable,
}

/// Make the outbound query carry DO=1 by patching the client's own bytes —
/// flip DO on an existing OPT, else append one. Never reserializes, so client
/// EDNS options, name compression and oversized wires all survive untouched.
/// Cached wires then always hold RRSIGs; `shape_response_for_client` strips
/// them for non-DO clients (issue #191).
fn ensure_do_bit(wire: &[u8]) -> Cow<'_, [u8]> {
    match locate_opt(wire) {
        OptSite::Ttl(ttl) if wire[ttl + 2] & DO_FLAG != 0 => Cow::Borrowed(wire),
        OptSite::Ttl(ttl) => {
            let mut out = wire.to_vec();
            out[ttl + 2] |= DO_FLAG;
            Cow::Owned(out)
        }
        OptSite::Absent => Cow::Owned(append_do_opt(wire)),
        OptSite::Unparsable => Cow::Borrowed(wire),
    }
}

fn append_do_opt(wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(wire.len() + 11);
    out.extend_from_slice(wire);
    let arcount = u16::from_be_bytes([out[10], out[11]]).saturating_add(1);
    out[10..12].copy_from_slice(&arcount.to_be_bytes());
    out.push(0); // root name
    out.extend_from_slice(&OPT_RECORD_TYPE.to_be_bytes());
    out.extend_from_slice(&crate::packet::DEFAULT_EDNS_PAYLOAD.to_be_bytes());
    out.extend_from_slice(&[0, 0, DO_FLAG, 0]); // ext-rcode, version, DO=1
    out.extend_from_slice(&[0, 0]); // RDLENGTH
    out
}

fn locate_opt(wire: &[u8]) -> OptSite {
    let Some(header) = wire.get(..12) else {
        return OptSite::Unparsable;
    };
    let count = |i: usize| u16::from_be_bytes([header[i], header[i + 1]]);

    let mut pos = 12;
    for _ in 0..count(4) {
        match skip_name(wire, pos) {
            Some(p) => pos = p + 4,
            None => return OptSite::Unparsable,
        }
    }
    for _ in 0..u32::from(count(6)) + u32::from(count(8)) {
        match skip_record(wire, pos) {
            Some(p) => pos = p,
            None => return OptSite::Unparsable,
        }
    }
    for _ in 0..count(10) {
        // skip_record validates the fixed fields, so TTL is in bounds below
        let (Some(after_name), Some(next)) = (skip_name(wire, pos), skip_record(wire, pos)) else {
            return OptSite::Unparsable;
        };
        if wire.get(after_name..after_name + 2) == Some(&OPT_RECORD_TYPE.to_be_bytes()[..]) {
            return OptSite::Ttl(after_name + 4);
        }
        pos = next;
    }
    if pos <= wire.len() {
        OptSite::Absent
    } else {
        OptSite::Unparsable
    }
}

/// Advance past one RR: name, then the 10-byte fixed fields plus RDATA.
fn skip_record(wire: &[u8], pos: usize) -> Option<usize> {
    let pos = skip_name(wire, pos)?;
    let rdlength = u16::from_be_bytes([*wire.get(pos + 8)?, *wire.get(pos + 9)?]) as usize;
    let end = pos + 10 + rdlength;
    (end <= wire.len()).then_some(end)
}

/// Advance past a wire-format name. A compression pointer ends it in 2 bytes.
fn skip_name(wire: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *wire.get(pos)?;
        match len & 0xC0 {
            0 if len == 0 => return Some(pos + 1),
            0 => pos += 1 + len as usize,
            0xC0 => return (pos + 2 <= wire.len()).then_some(pos + 2),
            _ => return None,
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
    let wire = &ensure_do_bit(wire)[..];
    let mut candidates: Vec<(usize, u64)> = {
        let srtt_read = srtt.read().unwrap();
        pool.primary
            .iter()
            .enumerate()
            .map(|(i, u)| {
                let rtt = u
                    .tracked_key()
                    .map(|(ip, t)| srtt_read.get(ip, t))
                    .unwrap_or(0);
                (i, rtt)
            })
            .collect()
    };
    candidates.sort_by_key(|&(_, rtt)| rtt);

    let has_fallback = !pool.fallback.is_empty();
    let all_upstreams: Vec<&Upstream> = candidates
        .iter()
        .filter(|&&(_, rtt)| !has_fallback || rtt < crate::srtt::PRIMARY_SKIP_SRTT_MS)
        .map(|&(i, _)| &pool.primary[i])
        .chain(pool.fallback.iter())
        .collect();

    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;

    for upstream in &all_upstreams {
        let start = Instant::now();
        let result = if !hedge_delay.is_zero() {
            // Hedge against the same upstream: independent h2 streams (DoH),
            // independent UDP packets (plain DNS), or independent TLS
            // connections (DoT). Rescues packet loss, dispatch spikes, and
            // TLS handshake stalls.
            forward_with_hedging_raw(wire, upstream, upstream, hedge_delay, timeout_duration).await
        } else {
            forward_query_raw(wire, upstream, timeout_duration).await
        };
        match result {
            Ok(resp) => {
                if let Some((ip, t)) = upstream.tracked_key() {
                    let rtt_ms = start.elapsed().as_millis() as u64;
                    srtt.write().unwrap().record_rtt(ip, t, rtt_ms);
                }
                return Ok(resp);
            }
            Err(e) => {
                if let Some((ip, t)) = upstream.tracked_key() {
                    srtt.write().unwrap().record_failure(ip, t);
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
/// The first call doubles as a startup warm-up: bootstrap-resolver failures
/// (unreachable Quad9/Cloudflare defaults, misconfigured hostname upstream)
/// surface here rather than on the first client query.
pub async fn keepalive_doh(upstream: &Upstream) {
    if let Upstream::Doh { url, client } = upstream {
        // Query for . NS — minimal, always succeeds, response is small
        let wire: &[u8] = &[
            0x00, 0x00, // ID
            0x01, 0x00, // flags: RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN=0, NS=0, AR=0
            0x00, // root name (.)
            0x00, 0x02, // type NS
            0x00, 0x01, // class IN
        ];
        if let Err(e) = forward_doh_raw(wire, url, client, Duration::from_secs(5)).await {
            log::warn!("DoH keepalive to {} failed: {}", url, e);
        }
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
            client: crate::forward::default_client(),
        };
        assert_eq!(u.to_string(), "https://dns.quad9.net/dns-query");
    }

    #[test]
    fn upstream_display_tcp() {
        let u = Upstream::Tcp("9.9.9.9:53".parse().unwrap());
        assert_eq!(u.to_string(), "tcp://9.9.9.9:53");
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
            client: crate::forward::default_client(),
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
            client: crate::forward::default_client(),
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
            client: crate::forward::default_client(),
        };

        let result = forward_query(&make_query(), &upstream, Duration::from_millis(100)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn failover_forward_sets_do_bit_upstream() {
        let (addr, mut seen) = crate::testutil::stub_udp_upstream().await;
        let pool = UpstreamPool::new(vec![Upstream::Udp(addr)], vec![]);
        let srtt = std::sync::RwLock::new(crate::srtt::SrttCache::new(true));

        // Client wire with no EDNS at all, the common stub-resolver case.
        let wire = to_wire(&make_query());
        forward_with_failover_raw(&wire, &pool, &srtt, Duration::from_secs(1), Duration::ZERO)
            .await
            .expect("forward should succeed");

        let sent = tokio::time::timeout(Duration::from_secs(1), seen.recv())
            .await
            .expect("stub upstream saw the query within 1s")
            .unwrap();
        let mut buf = BytePacketBuffer::from_bytes(&sent);
        let outbound = DnsPacket::from_buffer(&mut buf).unwrap();
        assert!(
            outbound.edns.is_some_and(|e| e.do_bit),
            "outbound upstream query must carry DO=1 regardless of the client wire, \
             or the cached answer has no RRSIGs to serve +dnssec clients (issue #191)"
        );
    }

    fn parse_wire(wire: &[u8]) -> DnsPacket {
        DnsPacket::from_buffer(&mut BytePacketBuffer::from_bytes(wire)).unwrap()
    }

    #[test]
    fn ensure_do_bit_appends_opt_when_client_sent_none() {
        let wire = to_wire(&make_query());
        let out = ensure_do_bit(&wire);

        assert_eq!(out.len(), wire.len() + 11, "one bare OPT appended");
        assert_eq!(&out[12..wire.len()], &wire[12..], "client bytes untouched");
        assert_eq!(&out[10..12], &1u16.to_be_bytes(), "ARCOUNT incremented");
        let edns = parse_wire(&out).edns.expect("OPT present");
        assert!(edns.do_bit);
        assert_eq!(edns.udp_payload_size, crate::packet::DEFAULT_EDNS_PAYLOAD);
    }

    #[test]
    fn ensure_do_bit_preserves_client_edns_options() {
        let mut query = make_query();
        query.edns = Some(crate::packet::EdnsOpt {
            udp_payload_size: 512,
            do_bit: false,
            // an EDNS cookie (opt code 10) the upstream must still see
            options: vec![0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8],
            ..Default::default()
        });
        let wire = to_wire(&query);
        let out = ensure_do_bit(&wire);

        assert_eq!(out.len(), wire.len(), "patched in place, not rebuilt");
        let edns = parse_wire(&out).edns.expect("OPT present");
        assert!(edns.do_bit);
        assert_eq!(edns.udp_payload_size, 512, "client payload size preserved");
        assert_eq!(edns.options, vec![0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn ensure_do_bit_leaves_do_queries_byte_identical() {
        let mut query = make_query();
        query.edns = Some(crate::packet::EdnsOpt {
            do_bit: true,
            ..Default::default()
        });
        let wire = to_wire(&query);
        assert_eq!(&ensure_do_bit(&wire)[..], &wire[..]);
    }

    #[test]
    fn ensure_do_bit_patches_wire_larger_than_the_packet_buffer() {
        // Parse-and-reserialize truncates at BytePacketBuffer's 4096 bytes;
        // a padded TCP/DoH query that size must still forward intact.
        let (wire, do_byte) = oversized_padded_query();
        let out = ensure_do_bit(&wire);

        assert!(wire.len() > 4096);
        assert_eq!(out.len(), wire.len(), "oversized wire kept whole");
        assert_eq!(out[do_byte] & DO_FLAG, DO_FLAG, "DO set in place");
        assert_eq!(&out[..do_byte], &wire[..do_byte]);
        assert_eq!(&out[do_byte + 1..], &wire[do_byte + 1..]);
    }

    /// Header + question + an OPT carrying 4096 bytes of EDNS padding, and
    /// the offset of its DO byte. Hand-built: `DnsPacket::write` caps at 4096.
    fn oversized_padded_query() -> (Vec<u8>, usize) {
        const PADDING: usize = 4096;
        let mut wire = to_wire(&make_query());
        wire[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT
        let do_byte = wire.len() + 7; // root name + type + class + 2 into TTL
        wire.push(0);
        wire.extend_from_slice(&OPT_RECORD_TYPE.to_be_bytes());
        wire.extend_from_slice(&crate::packet::DEFAULT_EDNS_PAYLOAD.to_be_bytes());
        wire.extend_from_slice(&[0, 0, 0, 0]); // TTL, DO clear
        wire.extend_from_slice(&((4 + PADDING) as u16).to_be_bytes()); // RDLENGTH
        wire.extend_from_slice(&[0, 12]); // opt code: padding (RFC 7830)
        wire.extend_from_slice(&(PADDING as u16).to_be_bytes());
        wire.extend(std::iter::repeat_n(0u8, PADDING));
        (wire, do_byte)
    }

    #[test]
    fn ensure_do_bit_passes_malformed_wires_through_untouched() {
        let truncated = &to_wire(&make_query())[..8];
        assert_eq!(&ensure_do_bit(truncated)[..], truncated);
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
    fn parse_tcp_scheme_default_port() {
        let u = parse_upstream("tcp://1.2.3.4", 53, None).unwrap();
        assert_eq!(u, Upstream::Tcp("1.2.3.4:53".parse().unwrap()));
    }

    #[test]
    fn parse_tcp_scheme_explicit_port() {
        let u = parse_upstream("tcp://1.2.3.4:5353", 53, None).unwrap();
        assert_eq!(u, Upstream::Tcp("1.2.3.4:5353".parse().unwrap()));
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
    async fn failover_skips_bad_srtt_primary_when_fallback_exists() {
        // UDP primary's SRTT is pre-pinned at FAILURE_PENALTY. With a
        // fallback present, the failover loop should skip the primary
        // entirely (no UDP timeout cost) and go straight to fallback.
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
        let doh_addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, app).into_future());

        let bad_udp_addr: SocketAddr = "192.0.2.99:53".parse().unwrap();
        let pool = UpstreamPool::new(
            vec![Upstream::Udp(bad_udp_addr)],
            vec![Upstream::Doh {
                url: format!("http://{}/dns-query", doh_addr),
                client: crate::forward::default_client(),
            }],
        );

        let srtt = RwLock::new(SrttCache::new(true));
        srtt.write()
            .unwrap()
            .record_failure(bad_udp_addr.ip(), UpstreamTransport::Udp);

        let wire = to_wire(&query);
        let start = Instant::now();
        let resp_wire = forward_with_failover_raw(
            &wire,
            &pool,
            &srtt,
            // High primary timeout — if the circuit-breaker fails to skip,
            // the test would block ~500ms on the unreachable UDP primary.
            Duration::from_millis(500),
            Duration::ZERO,
        )
        .await
        .expect("should fall through to DoH fallback");
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "primary was attempted, elapsed={:?}",
            start.elapsed()
        );

        let mut buf = BytePacketBuffer::from_bytes(&resp_wire);
        let result = DnsPacket::from_buffer(&mut buf).unwrap();
        assert_eq!(result.header.id, 0xABCD);
    }

    #[tokio::test]
    async fn failover_tries_bad_srtt_primary_when_no_fallback() {
        // No fallback means the circuit-breaker must NOT skip the only
        // upstream — better to try and fail with a timeout than to error
        // out without sending a single query.
        let bad_udp_addr: SocketAddr = "192.0.2.99:53".parse().unwrap();
        let pool = UpstreamPool::new(vec![Upstream::Udp(bad_udp_addr)], vec![]);
        let srtt = RwLock::new(SrttCache::new(true));
        srtt.write()
            .unwrap()
            .record_failure(bad_udp_addr.ip(), UpstreamTransport::Udp);

        let result = forward_with_failover_raw(
            &[0u8; 12],
            &pool,
            &srtt,
            Duration::from_millis(50),
            Duration::ZERO,
        )
        .await;
        assert!(result.is_err());
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
                    client: crate::forward::default_client(),
                },
            ],
            vec![],
        );

        let srtt = RwLock::new(SrttCache::new(true));
        let wire = to_wire(&query);
        let resp_wire = forward_with_failover_raw(
            &wire,
            &pool,
            &srtt,
            Duration::from_millis(500),
            Duration::ZERO,
        )
        .await
        .expect("should fail over to second upstream");

        let mut buf = BytePacketBuffer::from_bytes(&resp_wire);
        let result = DnsPacket::from_buffer(&mut buf).unwrap();
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

    // #169: on undetectable system DNS the rescan adopts the same Quad9 DoH
    // startup uses, instead of a bare UDP Quad9 that dies wherever outbound
    // UDP:53 is blocked.
    #[test]
    fn maybe_replace_primary_adopts_doh_over_udp() {
        let mut pool = UpstreamPool::new(
            vec![Upstream::Udp("192.168.1.1:53".parse().unwrap())],
            vec![],
        );
        let doh = Upstream::Doh {
            url: "https://9.9.9.9/dns-query".to_string(),
            client: crate::forward::default_client(),
        };
        assert!(pool.maybe_replace_primary(doh.clone()));
        assert_eq!(
            pool.preferred().unwrap().to_string(),
            "https://9.9.9.9/dns-query"
        );
        assert!(!pool.maybe_replace_primary(doh), "already on the fallback");
    }

    // Failover chains fallback after the primaries, so a sibling left behind by
    // the previous network would be retried before the reachable one (#169).
    #[test]
    fn maybe_update_primary_retargets_the_tcp_sibling() {
        let mut pool = UpstreamPool::new(
            vec![Upstream::Udp("1.2.3.4:53".parse().unwrap())],
            vec![Upstream::Tcp("1.2.3.4:53".parse().unwrap())],
        );
        assert!(pool.maybe_update_primary("5.6.7.8", 53));
        assert_eq!(
            pool.fallback,
            vec![Upstream::Tcp("5.6.7.8:53".parse().unwrap())]
        );
    }

    // Swapping away from DoH leaves no UDP sibling to strip.
    #[test]
    fn maybe_replace_primary_from_doh_keeps_fallback_clean() {
        let mut pool = UpstreamPool::new(
            vec![Upstream::Doh {
                url: "https://9.9.9.9/dns-query".to_string(),
                client: crate::forward::default_client(),
            }],
            vec![],
        );
        assert!(pool.maybe_update_primary("192.168.1.1", 53));
        assert_eq!(
            pool.fallback,
            vec![Upstream::Tcp("192.168.1.1:53".parse().unwrap())]
        );
    }

    fn tcp_closed_port() -> SocketAddr {
        // Bind a TCP listener, grab the port, drop → kernel returns RST on connect.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    #[tokio::test]
    async fn udp_failure_records_in_srtt() {
        let blackhole = crate::testutil::blackhole_upstream();
        let pool = UpstreamPool::new(vec![Upstream::Udp(blackhole)], vec![]);
        let srtt = RwLock::new(SrttCache::new(true));
        let _ = forward_with_failover_raw(
            &[0u8; 12],
            &pool,
            &srtt,
            Duration::from_millis(100),
            Duration::ZERO,
        )
        .await;
        assert!(srtt
            .read()
            .unwrap()
            .is_known(blackhole.ip(), UpstreamTransport::Udp));
    }

    #[tokio::test]
    async fn dot_failure_records_in_srtt() {
        let dead1 = tcp_closed_port();
        let dead2 = tcp_closed_port();
        let connector = build_dot_connector().unwrap();
        let pool = UpstreamPool::new(
            vec![
                Upstream::Dot {
                    addr: dead1,
                    tls_name: Some("dns.quad9.net".to_string()),
                    connector: connector.clone(),
                },
                Upstream::Dot {
                    addr: dead2,
                    tls_name: Some("dns.quad9.net".to_string()),
                    connector,
                },
            ],
            vec![],
        );
        let srtt = RwLock::new(SrttCache::new(true));
        let _ = forward_with_failover_raw(
            &[0u8; 12],
            &pool,
            &srtt,
            Duration::from_millis(500),
            Duration::ZERO,
        )
        .await;
        let cache = srtt.read().unwrap();
        assert!(cache.is_known(dead1.ip(), UpstreamTransport::Dot));
        assert!(cache.is_known(dead2.ip(), UpstreamTransport::Dot));
    }
}
