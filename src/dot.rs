use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, info, warn};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::config::DotConfig;
use crate::ctx::ServerCtx;
use crate::pp2::{self, PpConfig};
use crate::stats::Transport;
use crate::tcp::handle_framed_dns_connection;

const MAX_CONNECTIONS: usize = 512;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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

    let pp = match PpConfig::from_config(&config.proxy_protocol) {
        Ok(p) => p,
        Err(e) => {
            warn!("DoT: invalid proxy_protocol config ({}) — DoT disabled", e);
            return;
        }
    };
    if pp.is_some() {
        info!(
            "DoT: PROXY v2 enabled, trusting {} CIDR(s)",
            config.proxy_protocol.from.len()
        );
    }

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

    accept_loop(listener, TlsAcceptor::from(tls_config), pp, ctx).await;
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    pp: Option<PpConfig>,
    ctx: Arc<ServerCtx>,
) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let pp = pp.map(Arc::new);

    loop {
        let (tcp_stream, tcp_peer) = match listener.accept().await {
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
                debug!("DoT: connection limit reached, rejecting {}", tcp_peer);
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let ctx = Arc::clone(&ctx);
        let pp = pp.clone();

        tokio::spawn(async move {
            let _permit = permit; // held until task exits

            let Some((stream, remote_addr)) =
                pp2::handshake(tcp_stream, tcp_peer, pp.as_deref(), &ctx).await
            else {
                return;
            };

            let tls_stream =
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
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

            handle_framed_dns_connection(tls_stream, remote_addr, &ctx, Transport::Dot).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

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

        let upstream_addr = crate::testutil::blackhole_upstream();

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.zone_map = {
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
        };
        ctx.upstream_pool = Mutex::new(crate::forward::UpstreamPool::new(
            vec![crate::forward::Upstream::Udp(upstream_addr)],
            vec![],
        ));
        ctx.tls_config = Some(arc_swap::ArcSwap::from(server_tls));
        let ctx = Arc::new(ctx);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let tls_config = Arc::clone(&*ctx.tls_config.as_ref().unwrap().load());
        let acceptor = TlsAcceptor::from(tls_config);

        tokio::spawn(accept_loop(listener, acceptor, None, ctx));

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

    // ----------------------------------------------------------------------
    // PROXY protocol v2 integration tests (`docs/implementation/proxy-protocol-v2.md`).
    // ----------------------------------------------------------------------

    /// Spin up a DoT listener with a PROXY v2 allowlist. `pp_from` is the list
    /// of CIDRs/IPs trusted to send PROXY v2 headers; empty = feature disabled.
    async fn spawn_dot_server_with_pp(
        pp_from: &[&str],
    ) -> (SocketAddr, CertificateDer<'static>) {
        let (server_tls, cert_der) = test_tls_configs();

        let upstream_addr = crate::testutil::blackhole_upstream();

        let mut ctx = crate::testutil::test_ctx().await;
        ctx.zone_map = {
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
        };
        ctx.upstream_pool = Mutex::new(crate::forward::UpstreamPool::new(
            vec![crate::forward::Upstream::Udp(upstream_addr)],
            vec![],
        ));
        ctx.tls_config = Some(arc_swap::ArcSwap::from(server_tls));
        let ctx = Arc::new(ctx);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let tls_config = Arc::clone(&*ctx.tls_config.as_ref().unwrap().load());
        let acceptor = TlsAcceptor::from(tls_config);

        let pp_cfg = crate::config::ProxyProtocolConfig {
            from: pp_from.iter().map(|s| s.to_string()).collect(),
            // Use a short timeout so the truncated-header test doesn't drag.
            header_timeout_ms: 500,
            ..Default::default()
        };
        let pp = PpConfig::from_config(&pp_cfg).unwrap();

        tokio::spawn(accept_loop(listener, acceptor, pp, ctx));

        (addr, cert_der)
    }

    /// Wire a PROXY v2 IPv4 PROXY-command header (28 bytes total: 16 fixed +
    /// 12 address block).
    fn pp2_v4_proxy(
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

    /// Wire a PROXY v2 IPv6 PROXY-command header (52 bytes total: 16 fixed +
    /// 36 address block). Used to verify cross-family parsing — peer is IPv4,
    /// header declares IPv6.
    fn pp2_v6_proxy(
        src_ip: std::net::Ipv6Addr,
        dst_ip: std::net::Ipv6Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut h = Vec::with_capacity(52);
        h.extend_from_slice(&[
            0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
        ]);
        h.push(0x21); // v2 PROXY
        h.push(0x21); // TCP/IPv6
        h.extend_from_slice(&36u16.to_be_bytes());
        h.extend_from_slice(&src_ip.octets());
        h.extend_from_slice(&dst_ip.octets());
        h.extend_from_slice(&src_port.to_be_bytes());
        h.extend_from_slice(&dst_port.to_be_bytes());
        h
    }

    /// Wire a PROXY v2 LOCAL-command header (16 bytes; no address block).
    /// Sent by L4 front-ends as a connection-test heartbeat.
    fn pp2_local() -> Vec<u8> {
        let mut h = Vec::with_capacity(16);
        h.extend_from_slice(&[
            0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
        ]);
        h.push(0x20); // v2 LOCAL
        h.push(0x00); // UNSPEC family/proto
        h.extend_from_slice(&0u16.to_be_bytes()); // addr_len = 0
        h
    }

    /// Open a TCP connection, write a raw PROXY v2 header, then complete the
    /// TLS handshake. Returns `Ok(stream)` on success or `Err` on any failure.
    async fn dot_connect_with_pp2(
        addr: SocketAddr,
        client_config: &Arc<rustls::ClientConfig>,
        pp2_header: &[u8],
    ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, Box<dyn std::error::Error>>
    {
        let mut tcp = tokio::net::TcpStream::connect(addr).await?;
        tcp.write_all(pp2_header).await?;
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
        let stream = connector
            .connect(ServerName::try_from("numa.numa")?, tcp)
            .await?;
        Ok(stream)
    }

    #[tokio::test]
    async fn pp2_dot_happy_path_ipv4() {
        // Trusted client (127.0.0.1) sends a v4 PROXY header declaring an
        // arbitrary upstream IP. Connection completes; query resolves.
        let (addr, cert_der) = spawn_dot_server_with_pp(&["127.0.0.1"]).await;
        let client_config = dot_client(&cert_der, dot_alpn());

        let pp = pp2_v4_proxy(
            "203.0.113.42".parse().unwrap(),
            "10.0.0.5".parse().unwrap(),
            54321,
            853,
        );
        let mut stream = dot_connect_with_pp2(addr, &client_config, &pp)
            .await
            .expect("PROXY v2 + TLS handshake must succeed for trusted peer");

        let query = DnsPacket::query(0xD001, "dot-test.example", QueryType::A);
        let resp = dot_exchange(&mut stream, &query).await;
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert_eq!(resp.answers.len(), 1);
    }

    #[tokio::test]
    async fn pp2_dot_required_drops_bare_client() {
        // Allowlist contains the loopback, but the client sends a bare TLS
        // ClientHello with no PROXY header. The first 12 bytes do not match
        // the v2 signature → connection dropped → TLS handshake fails.
        let (addr, cert_der) = spawn_dot_server_with_pp(&["127.0.0.1"]).await;
        let client_config = dot_client(&cert_der, dot_alpn());

        let connector = tokio_rustls::TlsConnector::from(client_config);
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let result = connector
            .connect(ServerName::try_from("numa.numa").unwrap(), tcp)
            .await;
        assert!(
            result.is_err(),
            "PROXY-required listener must reject clients that omit the header"
        );
    }

    #[tokio::test]
    async fn pp2_dot_untrusted_peer_dropped() {
        // Allowlist contains a non-loopback range only. Connections from
        // 127.0.0.1 must be dropped before any read.
        let (addr, cert_der) = spawn_dot_server_with_pp(&["192.0.2.0/24"]).await;
        let client_config = dot_client(&cert_der, dot_alpn());

        // Even with a valid PROXY v2 header, the listener must drop us
        // because our actual TCP peer (127.0.0.1) is not on the allowlist.
        let pp = pp2_v4_proxy(
            "203.0.113.42".parse().unwrap(),
            "10.0.0.5".parse().unwrap(),
            54321,
            853,
        );
        let result = dot_connect_with_pp2(addr, &client_config, &pp).await;
        assert!(
            result.is_err(),
            "untrusted TCP peer must be dropped before peeking at PROXY v2"
        );
    }

    #[tokio::test]
    async fn pp2_dot_cross_family_v4_peer_v6_header() {
        // The TCP peer is 127.0.0.1 (IPv4), but the PROXY v2 header declares
        // an IPv6 source. Real production case behind dnsdist on dual-stack
        // hosts. Numa must accept the connection and propagate the IPv6
        // source as the connection's remote_addr.
        let (addr, cert_der) = spawn_dot_server_with_pp(&["127.0.0.1"]).await;
        let client_config = dot_client(&cert_der, dot_alpn());

        let pp = pp2_v6_proxy(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::cafe".parse().unwrap(),
            54321,
            853,
        );
        let mut stream = dot_connect_with_pp2(addr, &client_config, &pp)
            .await
            .expect("cross-family PROXY v2 must parse");

        let query = DnsPacket::query(0xD002, "dot-test.example", QueryType::A);
        let resp = dot_exchange(&mut stream, &query).await;
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
    }

    #[tokio::test]
    async fn pp2_dot_local_command() {
        // LOCAL is the proxy's connection heartbeat (no proxied client).
        // Numa must accept the connection and use the actual TCP peer as
        // remote_addr instead of trying to dereference an absent address.
        let (addr, cert_der) = spawn_dot_server_with_pp(&["127.0.0.1"]).await;
        let client_config = dot_client(&cert_der, dot_alpn());

        let mut stream = dot_connect_with_pp2(addr, &client_config, &pp2_local())
            .await
            .expect("LOCAL command must keep the connection alive");

        let query = DnsPacket::query(0xD003, "dot-test.example", QueryType::A);
        let resp = dot_exchange(&mut stream, &query).await;
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
    }

    #[tokio::test]
    async fn pp2_dot_truncated_header_times_out() {
        // Sender writes the first 8 bytes of the signature and then sits
        // there. Numa's header timeout fires; the TLS handshake never
        // happens. On the client side the read returns EOF / connection
        // reset.
        let (addr, _cert_der) = spawn_dot_server_with_pp(&["127.0.0.1"]).await;

        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        tcp.write_all(&[0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51])
            .await
            .unwrap();
        // After the listener's 500ms header timeout, the server closes us.
        let mut buf = [0u8; 16];
        let read_res =
            tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut buf)).await;
        match read_res {
            Ok(Ok(0)) | Ok(Err(_)) => { /* expected: EOF or connection reset */ }
            Ok(Ok(n)) => panic!(
                "expected the server to drop the connection, got {n} bytes back"
            ),
            Err(_) => panic!("server did not drop the connection within 2s"),
        }
    }

    #[tokio::test]
    async fn pp2_dot_disabled_mode_passes_bare_client_through() {
        // Empty allowlist == feature off. Direct clients (no header) keep
        // working. This is the regression check that pp2 introduces no
        // behavior change for users who don't enable the feature.
        let (addr, cert_der) = spawn_dot_server_with_pp(&[]).await;
        let client_config = dot_client(&cert_der, dot_alpn());
        let mut stream = dot_connect(addr, &client_config).await;

        let query = DnsPacket::query(0xD004, "dot-test.example", QueryType::A);
        let resp = dot_exchange(&mut stream, &query).await;
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert_eq!(resp.answers.len(), 1);
    }
}
