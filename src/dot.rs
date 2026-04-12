use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, info, warn};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::buffer::BytePacketBuffer;
use crate::config::DotConfig;
use crate::ctx::{resolve_query, ServerCtx};
use crate::header::ResultCode;
use crate::packet::DnsPacket;

const MAX_CONNECTIONS: usize = 512;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
// Matches BytePacketBuffer::BUF_SIZE — RFC 7858 allows up to 65535 but our
// buffer would silently truncate anything larger.
const MAX_MSG_LEN: usize = 4096;

fn dot_alpn() -> Vec<Vec<u8>> {
    vec![b"dot".to_vec()]
}

/// Build a TLS ServerConfig for DoT from user-provided cert/key PEM files.
fn load_tls_config(cert_path: &Path, key_path: &Path) -> crate::Result<Arc<ServerConfig>> {
    // rustls needs a CryptoProvider installed before ServerConfig::builder().
    // The proxy's build_tls_config also does this; we repeat it here because
    // running DoT with user-provided certs while the proxy is disabled would
    // otherwise panic on first handshake (no default provider).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or("no private key found in key file")?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = dot_alpn();

    Ok(Arc::new(config))
}

/// Build a self-signed DoT TLS config. Can't reuse `ctx.tls_config` (the
/// proxy's shared config) because DoT needs its own ALPN advertisement.
///
/// Pass `proxy_tld` itself as a service name so the cert gets an explicit
/// `{tld}.{tld}` SAN (e.g. "numa.numa") matching the ServerName that
/// setup-phone's mobileconfig sends as SNI. The `*.{tld}` wildcard alone
/// is rejected by strict TLS clients under single-label TLDs (per the
/// note in tls.rs::generate_service_cert).
fn self_signed_tls(ctx: &ServerCtx) -> Option<Arc<ServerConfig>> {
    let service_names = [ctx.proxy_tld.clone()];
    match crate::tls::build_tls_config(&ctx.proxy_tld, &service_names, dot_alpn(), &ctx.data_dir) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            warn!(
                "DoT: failed to generate self-signed TLS: {} — DoT disabled",
                e
            );
            None
        }
    }
}

/// Start the DNS-over-TLS listener (RFC 7858).
pub async fn start_dot(ctx: Arc<ServerCtx>, config: &DotConfig) {
    let tls_config = match (&config.cert_path, &config.key_path) {
        (Some(cert), Some(key)) => match load_tls_config(cert, key) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!("DoT: failed to load TLS cert/key: {} — DoT disabled", e);
                return;
            }
        },
        _ => match self_signed_tls(&ctx) {
            Some(cfg) => cfg,
            None => return,
        },
    };

    let bind_addr: IpAddr = config
        .bind_addr
        .parse()
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let addr = SocketAddr::new(bind_addr, config.port);
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("DoT: could not bind {} ({}) — DoT disabled", addr, e);
            return;
        }
    };
    info!("DoT listening on {}", addr);

    accept_loop(listener, TlsAcceptor::from(tls_config), ctx).await;
}

async fn accept_loop(listener: TcpListener, acceptor: TlsAcceptor, ctx: Arc<ServerCtx>) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        let (tcp_stream, remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("DoT: TCP accept error: {}", e);
                // Back off to avoid tight-looping on persistent failures (e.g. fd exhaustion).
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!("DoT: connection limit reached, rejecting {}", remote_addr);
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let ctx = Arc::clone(&ctx);

        tokio::spawn(async move {
            let _permit = permit; // held until task exits

            let tls_stream =
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp_stream)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        debug!("DoT: TLS handshake failed from {}: {}", remote_addr, e);
                        return;
                    }
                    Err(_) => {
                        debug!("DoT: TLS handshake timeout from {}", remote_addr);
                        return;
                    }
                };

            handle_dot_connection(tls_stream, remote_addr, &ctx).await;
        });
    }
}

/// Handle a single persistent DoT connection (RFC 7858).
/// Reads length-prefixed DNS queries until EOF, idle timeout, or error.
async fn handle_dot_connection<S>(mut stream: S, remote_addr: SocketAddr, ctx: &ServerCtx)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    loop {
        // Read 2-byte length prefix (RFC 1035 §4.2.2) with idle timeout
        let mut len_buf = [0u8; 2];
        let Ok(Ok(_)) = tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await
        else {
            break;
        };
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len > MAX_MSG_LEN {
            debug!("DoT: oversized message {} from {}", msg_len, remote_addr);
            break;
        }

        let mut buffer = BytePacketBuffer::new();
        let Ok(Ok(_)) =
            tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut buffer.buf[..msg_len])).await
        else {
            break;
        };

        let raw_wire = buffer.buf[..msg_len].to_vec();
        let query = match DnsPacket::from_buffer(&mut buffer) {
            Ok(q) => q,
            Err(e) => {
                warn!("{} | PARSE ERROR | {}", remote_addr, e);
                // BytePacketBuffer is zero-initialized, so buf[0..2] reads as 0x0000
                // for sub-2-byte messages — harmless FORMERR with id=0.
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

        match resolve_query(query.clone(), &raw_wire, remote_addr, ctx).await {
            Ok(resp_buffer) => {
                if write_framed(&mut stream, resp_buffer.filled())
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(e) => {
                warn!("{} | RESOLVE ERROR | {}", remote_addr, e);
                // SERVFAIL that echoes the original question section.
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

/// Serialize a DNS response and send it framed. Logs serialization failures
/// and returns Err so the caller can tear down the connection.
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
            "DoT: failed to serialize {:?} response for {}",
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
    use std::sync::{Mutex, RwLock};

    use rcgen::{CertificateParams, DnType, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::buffer::BytePacketBuffer;
    use crate::header::ResultCode;
    use crate::packet::DnsPacket;
    use crate::question::QueryType;
    use crate::record::DnsRecord;

    /// Generate a self-signed DoT server config and return its leaf cert DER
    /// so callers can build matching client configs with arbitrary ALPN.
    fn test_tls_configs() -> (Arc<ServerConfig>, CertificateDer<'static>) {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Mirror production self_signed_tls SAN shape: *.numa wildcard plus
        // explicit numa.numa apex (the ServerName setup-phone uses as SNI).
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "Numa .numa services");
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName("*.numa".try_into().unwrap()),
            rcgen::SanType::DnsName("numa.numa".try_into().unwrap()),
        ];
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        server_config.alpn_protocols = dot_alpn();

        (Arc::new(server_config), cert_der)
    }

    /// Build a TLS client config that trusts `cert_der` and advertises the
    /// given ALPN protocols. Used by tests to vary ALPN per test case.
    fn dot_client(
        cert_der: &CertificateDer<'static>,
        alpn: Vec<Vec<u8>>,
    ) -> Arc<rustls::ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der.clone()).unwrap();
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = alpn;
        Arc::new(config)
    }

    /// Spin up a DoT listener with a test TLS config. Returns the bind addr
    /// and the leaf cert DER so callers can build clients with arbitrary ALPN.
    /// The upstream is pointed at a bound-but-unresponsive UDP socket we own, so
    /// any query that escapes to the upstream path times out deterministically
    /// (SERVFAIL) regardless of what the host has running on port 53.
    async fn spawn_dot_server() -> (SocketAddr, CertificateDer<'static>) {
        let (server_tls, cert_der) = test_tls_configs();

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Bind an unresponsive upstream and leak it so it lives for the test duration.
        let blackhole = Box::leak(Box::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap()));
        let upstream_addr = blackhole.local_addr().unwrap();
        let ctx = Arc::new(ServerCtx {
            socket,
            zone_map: {
                let mut m = HashMap::new();
                let mut inner = HashMap::new();
                inner.insert(
                    QueryType::A,
                    vec![DnsRecord::A {
                        domain: "dot-test.example".to_string(),
                        addr: std::net::Ipv4Addr::new(10, 0, 0, 1),
                        ttl: 300,
                    }],
                );
                m.insert("dot-test.example".to_string(), inner);
                m
            },
            cache: RwLock::new(crate::cache::DnsCache::new(100, 60, 86400)),
            stats: Mutex::new(crate::stats::ServerStats::new()),
            overrides: RwLock::new(crate::override_store::OverrideStore::new()),
            blocklist: RwLock::new(crate::blocklist::BlocklistStore::new()),
            query_log: Mutex::new(crate::query_log::QueryLog::new(100)),
            services: Mutex::new(crate::service_store::ServiceStore::new()),
            lan_peers: Mutex::new(crate::lan::PeerStore::new(90)),
            forwarding_rules: Vec::new(),
            upstream_pool: Mutex::new(crate::forward::UpstreamPool::new(
                vec![crate::forward::Upstream::Udp(upstream_addr)],
                vec![],
            )),
            upstream_auto: false,
            upstream_port: 53,
            lan_ip: Mutex::new(std::net::Ipv4Addr::LOCALHOST),
            timeout: Duration::from_millis(200),
            hedge_delay: Duration::ZERO,
            proxy_tld: "numa".to_string(),
            proxy_tld_suffix: ".numa".to_string(),
            lan_enabled: false,
            config_path: String::new(),
            config_found: false,
            config_dir: std::path::PathBuf::from("/tmp"),
            data_dir: std::path::PathBuf::from("/tmp"),
            tls_config: Some(arc_swap::ArcSwap::from(server_tls)),
            upstream_mode: crate::config::UpstreamMode::Forward,
            root_hints: Vec::new(),
            srtt: RwLock::new(crate::srtt::SrttCache::new(true)),
            inflight: Mutex::new(HashMap::new()),
            dnssec_enabled: false,
            dnssec_strict: false,
            health_meta: crate::health::HealthMeta::test_fixture(),
            ca_pem: None,
            mobile_enabled: false,
            mobile_port: 8765,
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let tls_config = Arc::clone(&*ctx.tls_config.as_ref().unwrap().load());
        let acceptor = TlsAcceptor::from(tls_config);

        tokio::spawn(accept_loop(listener, acceptor, ctx));

        (addr, cert_der)
    }

    /// Open a TLS connection to the DoT server and return the stream.
    /// Uses SNI "numa.numa" to mirror what setup-phone's mobileconfig sends.
    async fn dot_connect(
        addr: SocketAddr,
        client_config: &Arc<rustls::ClientConfig>,
    ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        connector
            .connect(ServerName::try_from("numa.numa").unwrap(), tcp)
            .await
            .unwrap()
    }

    /// Send a DNS query over a DoT stream and read the response.
    async fn dot_exchange(
        stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        query: &DnsPacket,
    ) -> DnsPacket {
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
    async fn dot_resolves_local_zone() {
        let (addr, cert_der) = spawn_dot_server().await;
        let client_config = dot_client(&cert_der, dot_alpn());
        let mut stream = dot_connect(addr, &client_config).await;

        let query = DnsPacket::query(0x1234, "dot-test.example", QueryType::A);
        let resp = dot_exchange(&mut stream, &query).await;

        assert_eq!(resp.header.id, 0x1234);
        assert!(resp.header.response);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0] {
            DnsRecord::A { domain, addr, ttl } => {
                assert_eq!(domain, "dot-test.example");
                assert_eq!(*addr, std::net::Ipv4Addr::new(10, 0, 0, 1));
                assert_eq!(*ttl, 300);
            }
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn dot_multiple_queries_on_persistent_connection() {
        let (addr, cert_der) = spawn_dot_server().await;
        let client_config = dot_client(&cert_der, dot_alpn());
        let mut stream = dot_connect(addr, &client_config).await;

        for i in 0..3u16 {
            let query = DnsPacket::query(0xA000 + i, "dot-test.example", QueryType::A);
            let resp = dot_exchange(&mut stream, &query).await;
            assert_eq!(resp.header.id, 0xA000 + i);
            assert_eq!(resp.header.rescode, ResultCode::NOERROR);
            assert_eq!(resp.answers.len(), 1);
        }
    }

    #[tokio::test]
    async fn dot_nxdomain_for_unknown() {
        let (addr, cert_der) = spawn_dot_server().await;
        let client_config = dot_client(&cert_der, dot_alpn());
        let mut stream = dot_connect(addr, &client_config).await;

        let query = DnsPacket::query(0xBEEF, "nonexistent.test", QueryType::A);
        let resp = dot_exchange(&mut stream, &query).await;

        assert_eq!(resp.header.id, 0xBEEF);
        assert!(resp.header.response);
        // Query goes to the blackhole upstream which never replies → SERVFAIL.
        // The SERVFAIL response echoes the question section.
        assert_eq!(resp.header.rescode, ResultCode::SERVFAIL);
        assert_eq!(resp.questions.len(), 1);
        assert_eq!(resp.questions[0].name, "nonexistent.test");
    }

    #[tokio::test]
    async fn dot_negotiates_alpn() {
        let (addr, cert_der) = spawn_dot_server().await;
        let client_config = dot_client(&cert_der, dot_alpn());
        let stream = dot_connect(addr, &client_config).await;
        let (_io, conn) = stream.get_ref();
        assert_eq!(conn.alpn_protocol(), Some(&b"dot"[..]));
    }

    #[tokio::test]
    async fn dot_rejects_non_dot_alpn() {
        // Cross-protocol confusion defense: a client that only offers "h2"
        // (e.g. an HTTP/2 client mistakenly hitting :853) must not complete
        // a TLS handshake with the DoT server. Verifies the rustls server
        // sends `no_application_protocol` rather than silently negotiating.
        let (addr, cert_der) = spawn_dot_server().await;
        let client_config = dot_client(&cert_der, vec![b"h2".to_vec()]);
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let result = connector
            .connect(ServerName::try_from("numa.numa").unwrap(), tcp)
            .await;
        assert!(
            result.is_err(),
            "DoT server must reject ALPN that doesn't include \"dot\""
        );
    }

    #[tokio::test]
    async fn dot_concurrent_connections() {
        let (addr, cert_der) = spawn_dot_server().await;
        let client_config = dot_client(&cert_der, dot_alpn());

        let mut handles = Vec::new();
        for i in 0..5u16 {
            let cfg = Arc::clone(&client_config);
            handles.push(tokio::spawn(async move {
                let mut stream = dot_connect(addr, &cfg).await;
                let query = DnsPacket::query(0xC000 + i, "dot-test.example", QueryType::A);
                let resp = dot_exchange(&mut stream, &query).await;
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
