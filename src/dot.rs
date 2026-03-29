use std::net::SocketAddr;
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

const MAX_CONNECTIONS: usize = 512;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Build a TLS ServerConfig for DoT from user-provided cert/key PEM files.
fn load_tls_config(cert_path: &Path, key_path: &Path) -> crate::Result<Arc<ServerConfig>> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or("no private key found in key file")?;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
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
        _ => match ctx.tls_config.as_ref() {
            Some(arc_swap) => Arc::clone(&*arc_swap.load()),
            None => match crate::tls::build_tls_config(&ctx.proxy_tld, &[]) {
                Ok(cfg) => cfg,
                Err(e) => {
                    warn!(
                        "DoT: failed to generate self-signed TLS: {} — DoT disabled",
                        e
                    );
                    return;
                }
            },
        },
    };

    let bind_addr: std::net::Ipv4Addr = config
        .bind_addr
        .parse()
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
    let addr: SocketAddr = (bind_addr, config.port).into();
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("DoT: could not bind {} ({}) — DoT disabled", addr, e);
            return;
        }
    };
    info!("DoT listening on {}", addr);

    let acceptor = TlsAcceptor::from(tls_config);
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        let (tcp_stream, remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("DoT: TCP accept error: {}", e);
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

            let mut tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("DoT: TLS handshake failed from {}: {}", remote_addr, e);
                    return;
                }
            };

            // RFC 7858: connection is persistent — read queries until EOF or idle timeout
            loop {
                // Read 2-byte length prefix (RFC 1035 §4.2.2) with idle timeout
                let mut len_buf = [0u8; 2];
                match tokio::time::timeout(IDLE_TIMEOUT, tls_stream.read_exact(&mut len_buf)).await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) => break, // read error or EOF
                    Err(_) => break,     // idle timeout
                }
                let msg_len = u16::from_be_bytes(len_buf) as usize;
                if msg_len == 0 || msg_len > 4096 {
                    debug!(
                        "DoT: invalid message length {} from {}",
                        msg_len, remote_addr
                    );
                    break;
                }

                let mut data = vec![0u8; msg_len];
                if tls_stream.read_exact(&mut data).await.is_err() {
                    break;
                }

                let buffer = BytePacketBuffer::from_bytes(&data);
                match resolve_query(buffer, remote_addr, &ctx).await {
                    Ok(resp_buffer) => {
                        let resp = resp_buffer.filled();
                        // Coalesce length prefix + response into a single TLS write
                        let mut out = Vec::with_capacity(2 + resp.len());
                        out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
                        out.extend_from_slice(resp);
                        if tls_stream.write_all(&out).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("DoT: resolve error from {}: {}", remote_addr, e);
                    }
                }
            }
        });
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

    /// Generate a self-signed cert + key in memory, return (ServerConfig, ClientConfig).
    fn test_tls_configs() -> (Arc<ServerConfig>, Arc<rustls::ClientConfig>) {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        params.subject_alt_names = vec![rcgen::SanType::DnsName("localhost".try_into().unwrap())];
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        (Arc::new(server_config), Arc::new(client_config))
    }

    /// Spin up a DoT listener with a test TLS config. Returns (addr, client_config).
    async fn spawn_dot_server() -> (SocketAddr, Arc<rustls::ClientConfig>) {
        let (server_tls, client_tls) = test_tls_configs();

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
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
            upstream: Mutex::new(crate::forward::Upstream::Udp(
                "127.0.0.1:53".parse().unwrap(),
            )),
            upstream_auto: false,
            upstream_port: 53,
            lan_ip: Mutex::new(std::net::Ipv4Addr::LOCALHOST),
            timeout: Duration::from_secs(3),
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
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let tls_config = Arc::clone(&*ctx.tls_config.as_ref().unwrap().load());
        let acceptor = TlsAcceptor::from(tls_config);
        let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

        tokio::spawn(async move {
            loop {
                let (tcp_stream, remote_addr) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => return,
                };
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let acceptor = acceptor.clone();
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    let _permit = permit;
                    let mut tls_stream = match acceptor.accept(tcp_stream).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    loop {
                        let mut len_buf = [0u8; 2];
                        match tokio::time::timeout(
                            IDLE_TIMEOUT,
                            tls_stream.read_exact(&mut len_buf),
                        )
                        .await
                        {
                            Ok(Ok(_)) => {}
                            _ => break,
                        }
                        let msg_len = u16::from_be_bytes(len_buf) as usize;
                        if msg_len == 0 || msg_len > 4096 {
                            break;
                        }
                        let mut data = vec![0u8; msg_len];
                        if tls_stream.read_exact(&mut data).await.is_err() {
                            break;
                        }
                        let buffer = BytePacketBuffer::from_bytes(&data);
                        match resolve_query(buffer, remote_addr, &ctx).await {
                            Ok(resp_buffer) => {
                                let resp = resp_buffer.filled();
                                let mut out = Vec::with_capacity(2 + resp.len());
                                out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
                                out.extend_from_slice(resp);
                                if tls_stream.write_all(&out).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => {}
                        }
                    }
                });
            }
        });

        (addr, client_tls)
    }

    /// Open a TLS connection to the DoT server and return the stream.
    async fn dot_connect(
        addr: SocketAddr,
        client_config: &Arc<rustls::ClientConfig>,
    ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
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
        let (addr, client_config) = spawn_dot_server().await;
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
        let (addr, client_config) = spawn_dot_server().await;
        let mut stream = dot_connect(addr, &client_config).await;

        // Send 3 queries on the same TLS connection
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
        let (addr, client_config) = spawn_dot_server().await;
        let mut stream = dot_connect(addr, &client_config).await;

        let query = DnsPacket::query(0xBEEF, "nonexistent.test", QueryType::A);
        let resp = dot_exchange(&mut stream, &query).await;

        assert_eq!(resp.header.id, 0xBEEF);
        assert!(resp.header.response);
        // Query goes to upstream (127.0.0.1:53), which will fail — expect SERVFAIL
        assert_eq!(resp.header.rescode, ResultCode::SERVFAIL);
    }

    #[tokio::test]
    async fn dot_concurrent_connections() {
        let (addr, client_config) = spawn_dot_server().await;

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

    #[tokio::test]
    async fn dot_localhost_resolution() {
        let (addr, client_config) = spawn_dot_server().await;
        let mut stream = dot_connect(addr, &client_config).await;

        let query = DnsPacket::query(0xD000, "localhost", QueryType::A);
        let resp = dot_exchange(&mut stream, &query).await;

        assert_eq!(resp.header.id, 0xD000);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, std::net::Ipv4Addr::LOCALHOST),
            other => panic!("expected A record, got {:?}", other),
        }
    }
}
