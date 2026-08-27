use std::borrow::Cow;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::time::{timeout, timeout_at};

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

/// Client for the ODoH relay's forward leg. Relay workloads hit many distinct
/// target hosts, so the caller picks a larger `pool_max_idle_per_host` to keep
/// warm connections through concurrent fan-out. Redirects are refused: the
/// relay must reach the host the client named and no other, or a target could
/// bounce it at addresses that never passed `is_valid_hostname`.
pub fn build_relay_client(pool_max_idle_per_host: usize) -> reqwest::Client {
    https_client_builder(pool_max_idle_per_host)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
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

    let socket = connected_udp(upstream).await?;
    socket.send(send_buffer.filled()).await?;

    // Loop until a datagram answers the exact question we asked, or the deadline
    // lapses. A spoof that raced the real reply onto our ephemeral port (SAD DNS
    // infers it) fails the match and must not end the wait — a single recv would
    // let the first forged packet win (§ RFC 5452 acceptance check). The txid is
    // the first two wire bytes, so reject the flood cheaply before a full parse.
    let want_id = query.header.id.to_be_bytes();
    let deadline = tokio::time::Instant::now() + timeout_duration;
    let mut recv_buf = vec![0u8; crate::wire::MAX_UPSTREAM_PAYLOAD as usize + 1];
    loop {
        let size = timeout_at(deadline, socket.recv(&mut recv_buf)).await??;
        // Over the cap: the kernel cut an oversized datagram to fit, and a cut
        // wire is indistinguishable from a full one. Under 12: no DNS header.
        if !(12..=crate::wire::MAX_UPSTREAM_PAYLOAD as usize).contains(&size)
            || recv_buf[..2] != want_id
        {
            continue;
        }
        let mut recv_buffer = BytePacketBuffer::from_bytes(&recv_buf[..size]);
        if let Ok(resp) = DnsPacket::from_buffer(&mut recv_buffer) {
            if response_matches(query, &resp) {
                return Ok(resp);
            }
        }
    }
}

/// A connected UDP socket to `upstream`: the kernel then drops datagrams from
/// anyone but it, leaving source-spoofed off-path injection as the only path in.
async fn connected_udp(upstream: SocketAddr) -> Result<UdpSocket> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(upstream).await?;
    Ok(socket)
}

/// A UDP reply we'll act on: QR=1, our transaction ID, and the same question we
/// asked (case-insensitive name, same type). The connected socket already drops
/// off-source datagrams; this rejects a source-spoofing off-path injection that
/// forged the upstream's address to race the real answer.
fn response_matches(query: &DnsPacket, resp: &DnsPacket) -> bool {
    if !resp.header.response || resp.header.id != query.header.id {
        return false;
    }
    match resp.questions.first() {
        Some(got) => query.questions.first().is_some_and(|asked| {
            asked.qtype == got.qtype && asked.name.eq_ignore_ascii_case(&got.name)
        }),
        // Some servers drop the question on errors (FORMERR/REFUSED). Accept
        // one only when it carries nothing to cache — a bare failure — so a
        // forged answer can't ride in without naming the question it answers.
        None => resp.answers.is_empty() && resp.authorities.is_empty(),
    }
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

/// One reply path for every transport: dispatch, validate, and resolve TC=1.
/// A truncated reply never leaves this function — it is uncacheable, and our
/// own clients' TCP retries re-enter this same path. UDP keeps the datagram
/// budget and escalates to TCP (RFC 1035 §4.2.1) within what remains of the
/// timeout; a stream transport already asked for our full ceiling, so its TC
/// means an answer past what we could parse — that, like a failed or unusable
/// retry, counts as a failed upstream and the caller's failover moves on.
pub async fn forward_query_raw(
    wire: &[u8],
    upstream: &Upstream,
    timeout_duration: Duration,
) -> Result<Vec<u8>> {
    let start = Instant::now();
    let sent = match upstream {
        Upstream::Udp(_) => Cow::Borrowed(wire),
        _ => crate::wire::maximize_payload(wire),
    };
    let resp = match upstream {
        Upstream::Udp(addr) => forward_udp_raw(&sent, *addr, timeout_duration).await,
        Upstream::Tcp(addr) => forward_tcp_raw(&sent, *addr, timeout_duration).await,
        Upstream::Doh { url, client } => {
            forward_doh_raw(&sent, url, client, timeout_duration).await
        }
        Upstream::Dot {
            addr,
            tls_name,
            connector,
        } => forward_dot_raw(&sent, *addr, tls_name, connector, timeout_duration).await,
        Upstream::Odoh {
            relay_url,
            target_path,
            client,
            target_config,
        } => {
            query_through_relay(
                &sent,
                relay_url,
                target_path,
                client,
                target_config,
                timeout_duration,
            )
            .await
        }
    }?;

    let resp = usable_reply(wire, resp)?;
    if matches!(upstream, Upstream::Udp(_)) && !udp_reply_answers_question(wire, &resp) {
        return Err("plain-UDP upstream answered a different question".into());
    }
    if !crate::wire::is_truncated(&resp) {
        return Ok(resp);
    }
    let Upstream::Udp(addr) = upstream else {
        return Err("upstream truncated a stream-transport reply".into());
    };
    let budget = timeout_duration.saturating_sub(start.elapsed());
    let retry = crate::wire::maximize_payload(wire);
    let full = timeout(budget, forward_tcp_raw(&retry, *addr, budget)).await??;
    let full = usable_reply(wire, full)?;
    if crate::wire::is_truncated(&full) {
        return Err("upstream truncated the TCP retry".into());
    }
    Ok(full)
}

/// Plain-UDP forwarding shares the recursive path's off-path exposure, so it
/// gets the same RFC 5452 check: `usable_reply` gates id + QR, this adds the
/// question match. The TLS/HTTPS transports authenticate the peer, so they skip
/// it. Byte-level because `forward_query_raw` trades in wire, not packets.
fn udp_reply_answers_question(query_wire: &[u8], resp: &[u8]) -> bool {
    let parse = |b: &[u8]| {
        let mut buf = BytePacketBuffer::from_bytes(b);
        DnsPacket::from_buffer(&mut buf).ok()
    };
    matches!((parse(query_wire), parse(resp)), (Some(q), Some(r)) if response_matches(&q, &r))
}

/// A reply the pipeline can act on: the ID we sent, QR=1, and within
/// `BytePacketBuffer`'s capacity — `from_bytes` silently cuts a larger wire
/// into one that parses as garbage, becoming SERVFAIL plus a cache entry that
/// never parses until TTL expiry.
fn usable_reply(wire: &[u8], resp: Vec<u8>) -> Result<Vec<u8>> {
    let usable = resp.len() <= crate::wire::MAX_UPSTREAM_PAYLOAD as usize
        && resp.len() >= 12
        && resp.get(..2) == wire.get(..2)
        && crate::wire::is_response(&resp);
    if !usable {
        return Err("unusable upstream reply".into());
    }
    Ok(resp)
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

pub async fn forward_with_failover_raw(
    wire: &[u8],
    pool: &UpstreamPool,
    srtt: &RwLock<SrttCache>,
    timeout_duration: Duration,
    hedge_delay: Duration,
) -> Result<Vec<u8>> {
    let wire = &crate::wire::ensure_do_bit(wire)[..];
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
    let socket = connected_udp(upstream).await?;
    socket.send(wire).await?;

    // One byte of headroom: a datagram sized exactly to the buffer cannot be
    // told from one the kernel cut to fit, and a cut wire parses as garbage.
    let mut recv_buf = vec![0u8; crate::wire::MAX_UPSTREAM_PAYLOAD as usize + 1];
    let size = timeout(timeout_duration, socket.recv(&mut recv_buf)).await??;
    if size > crate::wire::MAX_UPSTREAM_PAYLOAD as usize {
        return Err("upstream reply exceeds the maximum payload".into());
    }
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

    /// A DoH upstream answering `response`, plus the queries it received.
    async fn doh_upstream(
        response: Vec<u8>,
    ) -> (Upstream, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
        let (url, rx) = crate::testutil::doh_upstream_raw(response).await;
        let upstream = Upstream::Doh {
            url,
            client: crate::forward::default_client(),
        };
        (upstream, rx)
    }

    #[tokio::test]
    async fn doh_mock_server_resolves() {
        let query = make_query();
        let (upstream, _rx) = doh_upstream(to_wire(&make_response(&query))).await;

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
        let (good, _rx) = doh_upstream(to_wire(&make_response(&query))).await;

        let pool = UpstreamPool::new(
            vec![Upstream::Udp("127.0.0.1:1".parse().unwrap()), good],
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

    /// A TC=1 reply with no records — the shape of a signed response that
    /// outgrows the UDP budget.
    fn truncated_response(query: &DnsPacket) -> Vec<u8> {
        let mut tc = make_response(query);
        tc.answers.clear();
        tc.header.truncated_message = true;
        to_wire(&tc)
    }

    #[tokio::test]
    async fn failover_retries_truncated_udp_over_tcp() {
        // UDP and TCP share the port: UDP always answers TC=1, TCP has the
        // full answer. Without the TCP retry the TC reply is final: the
        // client's own TCP retry re-enters this same UDP path and loops
        // forever.
        let query = make_query();
        let addr = crate::testutil::mock_upstream_raw(truncated_response(&query)).await;
        crate::testutil::tcp_upstream_raw_on(addr, to_wire(&make_response(&query))).await;

        let pool = UpstreamPool::new(vec![Upstream::Udp(addr)], vec![]);
        let srtt = RwLock::new(SrttCache::new(true));
        let resp_wire = forward_with_failover_raw(
            &to_wire(&query),
            &pool,
            &srtt,
            Duration::from_millis(500),
            Duration::ZERO,
        )
        .await
        .expect("truncated UDP answer must resolve over TCP");

        assert!(!crate::wire::is_truncated(&resp_wire));
        let mut buf = BytePacketBuffer::from_bytes(&resp_wire);
        let result = DnsPacket::from_buffer(&mut buf).unwrap();
        assert_eq!(result.answers.len(), 1);
    }

    #[tokio::test]
    async fn failover_moves_on_when_the_tcp_retry_fails() {
        // Upstream A truncates and has no TCP listener (asymmetric port-53
        // filtering); upstream B holds the answer. The truncated reply must
        // not count as pool success, or B never fires.
        let query = make_query();
        let tc_addr = crate::testutil::mock_upstream_raw(truncated_response(&query)).await;
        let good_addr = crate::testutil::mock_upstream(make_response(&query)).await;

        let pool = UpstreamPool::new(
            vec![Upstream::Udp(tc_addr), Upstream::Udp(good_addr)],
            vec![],
        );
        let srtt = RwLock::new(SrttCache::new(true));
        let resp_wire = forward_with_failover_raw(
            &to_wire(&query),
            &pool,
            &srtt,
            Duration::from_millis(500),
            Duration::ZERO,
        )
        .await
        .expect("failed TCP retry must fail over to the next upstream");

        assert!(!crate::wire::is_truncated(&resp_wire));
        let mut buf = BytePacketBuffer::from_bytes(&resp_wire);
        let result = DnsPacket::from_buffer(&mut buf).unwrap();
        assert_eq!(result.answers.len(), 1);
    }

    #[tokio::test]
    async fn failover_moves_on_when_a_stream_transport_truncates() {
        // TC over DoH has nothing bigger to escalate to — the upstream must
        // count as failed, not answer the pool with an uncacheable TC wire.
        let query = make_query();
        let (truncating, _rx) = doh_upstream(truncated_response(&query)).await;
        let good_addr = crate::testutil::mock_upstream(make_response(&query)).await;

        let pool = UpstreamPool::new(vec![truncating, Upstream::Udp(good_addr)], vec![]);
        let srtt = RwLock::new(SrttCache::new(true));
        let resp_wire = forward_with_failover_raw(
            &to_wire(&query),
            &pool,
            &srtt,
            Duration::from_millis(500),
            Duration::ZERO,
        )
        .await
        .expect("truncating DoH upstream must fail over");

        assert!(!crate::wire::is_truncated(&resp_wire));
        let mut buf = BytePacketBuffer::from_bytes(&resp_wire);
        let result = DnsPacket::from_buffer(&mut buf).unwrap();
        assert_eq!(result.answers.len(), 1);
    }

    #[tokio::test]
    async fn tc_retry_refuses_a_reply_the_parse_buffer_would_cut() {
        // A TCP answer past BytePacketBuffer's capacity would be silently
        // cut into a parse error and a poisoned cache slot — refusing it
        // turns that into a plain upstream failure.
        let query = make_query();
        let addr = crate::testutil::mock_upstream_raw(truncated_response(&query)).await;
        crate::testutil::tcp_upstream_raw_on(addr, oversized_response(&query)).await;

        let result = forward_query_raw(
            &to_wire(&query),
            &Upstream::Udp(addr),
            Duration::from_millis(500),
        )
        .await;

        assert!(result.is_err(), "oversized TCP retry must not be returned");
    }

    /// A well-formed answer one byte past the ceiling we can receive.
    fn oversized_response(query: &DnsPacket) -> Vec<u8> {
        let mut big = to_wire(&make_response(query));
        big.resize(crate::wire::MAX_UPSTREAM_PAYLOAD as usize + 1, 0);
        big
    }

    #[tokio::test]
    async fn a_stream_upstream_is_asked_for_the_full_ceiling() {
        // The 1232 default is a datagram-fragmentation budget. Passing it to a
        // DoH server that honors it (RFC 8484 §5.1) earns a TC=1 the stream
        // path cannot escalate past, and the whole pool SERVFAILs.
        let query = make_query();
        let (upstream, mut rx) = doh_upstream(to_wire(&make_response(&query))).await;
        let wire = crate::wire::ensure_do_bit(&to_wire(&query)).into_owned();
        forward_query_raw(&wire, &upstream, Duration::from_secs(2))
            .await
            .expect("DoH forward should succeed");

        let sent = rx.recv().await.expect("upstream recorded the query");
        let mut buf = BytePacketBuffer::from_bytes(&sent);
        let asked = DnsPacket::from_buffer(&mut buf).unwrap();
        let edns = asked.edns.expect("OPT present");
        assert_eq!(edns.udp_payload_size, crate::wire::MAX_UPSTREAM_PAYLOAD);
        assert!(edns.do_bit, "DO survives the payload patch");
    }

    #[tokio::test]
    async fn forward_udp_refuses_a_reply_for_a_different_question() {
        // Right id (the stub patches it), well-formed, but its question names
        // another host — the off-path "answer for a name we didn't ask" shape.
        let query = make_query();
        let mut evil = DnsPacket::response_from(&query, ResultCode::NOERROR);
        evil.questions[0].name = "evil.example".to_string();
        evil.answers.push(DnsRecord::A {
            domain: "evil.example".to_string(),
            addr: "6.6.6.6".parse().unwrap(),
            ttl: 300,
        });
        let addr = crate::testutil::mock_upstream_raw(to_wire(&evil)).await;

        let result = forward_query_raw(
            &to_wire(&query),
            &Upstream::Udp(addr),
            Duration::from_millis(300),
        )
        .await;

        assert!(
            result.is_err(),
            "a reply for another question must be refused"
        );
    }

    #[tokio::test]
    async fn udp_ignores_a_reply_from_another_source() {
        // The stub reads the query on the addressed port but answers from a
        // different one — the shape of an off-path injection. A connected
        // socket never sees it.
        let query = make_query();
        let mut reply = to_wire(&make_response(&query));
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, src) = sock.recv_from(&mut buf).await.unwrap();
            crate::wire::patch_id(&mut reply, u16::from_be_bytes([buf[0], buf[1]]));
            let off_path = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let _ = off_path.send_to(&reply, src).await;
        });

        let result = forward_query_raw(
            &to_wire(&query),
            &Upstream::Udp(addr),
            Duration::from_millis(300),
        )
        .await;

        assert!(result.is_err(), "an off-path reply must not answer");
    }

    #[test]
    fn response_matches_accepts_the_echoed_question() {
        let query = make_query();
        assert!(response_matches(&query, &make_response(&query)));
    }

    #[test]
    fn response_matches_rejects_wrong_id_name_type_or_query() {
        let query = make_query();

        let mut wrong_id = make_response(&query);
        wrong_id.header.id ^= 0xFFFF;
        assert!(!response_matches(&query, &wrong_id), "id must match");

        let mut wrong_name = make_response(&query);
        wrong_name.questions[0].name = "evil.example".to_string();
        assert!(!response_matches(&query, &wrong_name), "qname must match");

        let mut wrong_type = make_response(&query);
        wrong_type.questions[0].qtype = QueryType::AAAA;
        assert!(!response_matches(&query, &wrong_type), "qtype must match");

        let mut not_a_response = make_response(&query);
        not_a_response.header.response = false;
        assert!(!response_matches(&query, &not_a_response), "QR must be set");
    }

    #[test]
    fn response_matches_handles_a_question_less_reply_by_cacheability() {
        let query = make_query();

        // A bare error that omitted the question is accepted so the caller can
        // fail fast instead of blocking to the deadline.
        let mut bare_error = make_response(&query);
        bare_error.questions.clear();
        bare_error.answers.clear();
        bare_error.header.rescode = ResultCode::SERVFAIL;
        assert!(
            response_matches(&query, &bare_error),
            "bare error is a match"
        );

        // The same reply carrying an answer must not ride in unnamed.
        let mut smuggled_answer = make_response(&query);
        smuggled_answer.questions.clear();
        assert!(
            !response_matches(&query, &smuggled_answer),
            "a question-less reply may not carry records"
        );
    }

    #[test]
    fn response_matches_is_case_insensitive_on_name() {
        let query = make_query();
        let mut mixed_case = make_response(&query);
        mixed_case.questions[0].name = "ExAmPlE.CoM".to_string();
        assert!(
            response_matches(&query, &mixed_case),
            "0x20 case must not reject"
        );
    }

    #[tokio::test]
    async fn forward_udp_discards_a_spoof_and_takes_the_match() {
        // The upstream sends a wrong-id spoof first, then the real reply, both
        // from the connected source. The recv loop must skip the spoof and
        // return the answer that matches the question we asked.
        let query = make_query();
        let good = to_wire(&make_response(&query));
        let mut spoof = good.clone();
        crate::wire::patch_id(&mut spoof, query.header.id ^ 0xFFFF);

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, src) = sock.recv_from(&mut buf).await.unwrap();
            let _ = sock.send_to(&spoof, src).await;
            let _ = sock.send_to(&good, src).await;
        });

        let resp = forward_udp(&query, addr, Duration::from_millis(500))
            .await
            .expect("the matching reply must win the race");
        assert_eq!(resp.header.id, query.header.id);
        assert_eq!(resp.answers.len(), 1);
    }

    #[tokio::test]
    async fn forward_udp_times_out_on_a_wrong_id_only_reply() {
        let query = make_query();
        let mut spoof = to_wire(&make_response(&query));
        crate::wire::patch_id(&mut spoof, query.header.id ^ 0xFFFF);

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, src) = sock.recv_from(&mut buf).await.unwrap();
            let _ = sock.send_to(&spoof, src).await;
        });

        let result = forward_udp(&query, addr, Duration::from_millis(200)).await;
        assert!(
            result.is_err(),
            "a reply that never matches must not be accepted"
        );
    }

    #[tokio::test]
    async fn udp_refuses_a_datagram_the_kernel_had_to_cut() {
        // The kernel cuts an oversized datagram to whatever the receive buffer
        // holds, so a cut wire and a legitimately full one are the same length
        // — only headroom past the cap tells them apart.
        let query = make_query();
        let addr = crate::testutil::mock_upstream_raw(oversized_response(&query)).await;

        let result = forward_query_raw(
            &to_wire(&query),
            &Upstream::Udp(addr),
            Duration::from_millis(500),
        )
        .await;

        assert!(result.is_err(), "cut UDP datagram must not be returned");
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
