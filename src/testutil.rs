use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::blocklist::BlocklistStore;
use crate::buffer::BytePacketBuffer;
use crate::cache::DnsCache;
use crate::config::{UpstreamMode, ZoneMap};
use crate::ctx::ServerCtx;
use crate::forward::{Upstream, UpstreamPool};
use crate::header::ResultCode;
use crate::health::HealthMeta;
use crate::lan::PeerStore;
use crate::override_store::OverrideStore;
use crate::packet::DnsPacket;
use crate::query_log::QueryLog;
use crate::record::DnsRecord;
use crate::service_store::ServiceStore;
use crate::srtt::SrttCache;
use crate::stats::ServerStats;
/// Minimal `ServerCtx` for tests. Override fields after construction
/// (all fields are `pub`), then wrap in `Arc`.
pub async fn test_ctx() -> ServerCtx {
    ServerCtx {
        zone_map: ZoneMap::default(),
        cache: RwLock::new(DnsCache::new(100, 60, 86400)),
        refreshing: Mutex::new(HashSet::new()),
        stats: Mutex::new(ServerStats::new()),
        overrides: RwLock::new(OverrideStore::new()),
        blocklist: RwLock::new(BlocklistStore::new(
            crate::domain_list::PersistedDomainList::unpersisted(),
            crate::domain_list::PersistedDomainList::unpersisted(),
        )),
        query_log: Mutex::new(QueryLog::new(100)),
        services: Mutex::new(ServiceStore::new()),
        lan_peers: Mutex::new(PeerStore::new(90)),
        forwarding_rules: Vec::new(),
        upstream_pool: Mutex::new(UpstreamPool::new(
            vec![Upstream::Udp("127.0.0.1:53".parse().unwrap())],
            vec![],
        )),
        upstream_auto: false,
        upstream_port: 53,
        lan_ip: Mutex::new(Ipv4Addr::LOCALHOST),
        timeout: Duration::from_millis(200),
        hedge_delay: Duration::ZERO,
        proxy_tld: "numa".to_string(),
        proxy_tld_suffix: ".numa".to_string(),
        lan_enabled: false,
        config_path: "/tmp/test-numa.toml".to_string(),
        config_found: false,
        config_dir: PathBuf::from("/tmp"),
        data_dir: PathBuf::from("/tmp"),
        tls_config: None,
        tls_byo: false,
        upstream_mode: UpstreamMode::Forward,
        root_hints: Vec::new(),
        srtt: RwLock::new(SrttCache::new(true)),
        inflight: Mutex::new(HashMap::new()),
        dnssec_enabled: false,
        dnssec_strict: false,
        health_meta: HealthMeta::test_fixture(),
        ca_pem: None,
        mobile_enabled: false,
        mobile_port: 8765,
        filter_aaaa: false,
        allow_from: crate::acl::AllowFromAcl::default(),
        client_policy: crate::client_policy::ClientPolicySet::default(),
        rebind: std::sync::RwLock::new(
            crate::rebind::RebindFilter::new(
                false,
                crate::domain_list::PersistedDomainList::unpersisted(),
                &[],
            )
            .unwrap(),
        ),
    }
}

/// Build a `DnsRecord::A` — concise fixture for zone-map and pipeline tests.
pub fn a_record(domain: &str, addr: Ipv4Addr, ttl: u32) -> DnsRecord {
    DnsRecord::A {
        domain: domain.to_string(),
        addr,
        ttl,
    }
}

/// Build a `DnsRecord::CNAME` — concise fixture for zone-map and pipeline tests.
pub fn cname_record(domain: &str, host: &str, ttl: u32) -> DnsRecord {
    DnsRecord::CNAME {
        domain: domain.to_string(),
        host: host.to_string(),
        ttl,
    }
}

/// Build a NOERROR response with the given answer records.
pub fn noerror_response(answers: Vec<DnsRecord>) -> DnsPacket {
    let mut pkt = DnsPacket::new();
    pkt.header.response = true;
    pkt.header.rescode = ResultCode::NOERROR;
    pkt.answers = answers;
    pkt
}

/// Build a NOERROR response containing a single A record — the shape used
/// repeatedly by pipeline/forwarding tests to seed `mock_upstream`.
pub fn a_record_response(domain: &str, addr: Ipv4Addr, ttl: u32) -> DnsPacket {
    noerror_response(vec![a_record(domain, addr, ttl)])
}

/// AAAA counterpart of `a_record_response`, for filter_aaaa pipeline tests.
pub fn aaaa_record_response(domain: &str, addr: std::net::Ipv6Addr, ttl: u32) -> DnsPacket {
    noerror_response(vec![DnsRecord::AAAA {
        domain: domain.to_string(),
        addr,
        ttl,
    }])
}

/// Spawn a UDP socket that answers every DNS query with the given response
/// packet, honoring the query's advertised payload budget (TC=1 when the
/// answer does not fit) and patching the query ID. Returns the socket address.
pub async fn mock_upstream(response: DnsPacket) -> SocketAddr {
    let mut out = BytePacketBuffer::new();
    response.write(&mut out).unwrap();
    spawn_stub(out.filled().to_vec(), true, None).await
}

/// Like `mock_upstream` but sends raw wire bytes verbatim — for intentionally
/// malformed responses that can't survive our own serializer, which must reach
/// the resolver's parser untouched (no budget substitution).
pub async fn mock_upstream_raw(bytes: Vec<u8>) -> SocketAddr {
    spawn_stub(bytes, false, None).await
}

/// Spawn a UDP socket that answers every query by qname from the given table
/// (patching the query ID) — for chase tests where follow-up sub-queries hit
/// the same upstream.
pub async fn mock_upstream_by_qname(responses: Vec<(&str, DnsPacket)>) -> SocketAddr {
    let table: Vec<(String, Vec<u8>)> = responses
        .into_iter()
        .map(|(name, pkt)| {
            let mut out = BytePacketBuffer::new();
            pkt.write(&mut out).unwrap();
            (name.to_string(), out.filled().to_vec())
        })
        .collect();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, src)) = sock.recv_from(&mut buf).await {
            let mut query_buf = BytePacketBuffer::from_bytes(&buf[..n]);
            let Ok(query) = DnsPacket::from_buffer(&mut query_buf) else {
                continue;
            };
            let Some(question) = query.questions.first() else {
                continue;
            };
            if let Some((_, bytes)) = table.iter().find(|(name, _)| *name == question.name) {
                let mut reply = reply_within_budget(bytes, &buf[..n]);
                reply[0] = buf[0];
                reply[1] = buf[1];
                let _ = sock.send_to(&reply, src).await;
            }
        }
    });
    addr
}

/// Like `mock_upstream`, but also reports each inbound query wire on the
/// returned channel, so tests can assert what actually went upstream
/// (e.g. the DO bit, issue #191).
pub async fn recording_upstream(
    response: DnsPacket,
) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
    let mut out = BytePacketBuffer::new();
    response.write(&mut out).unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let addr = spawn_stub(out.filled().to_vec(), true, Some(tx)).await;
    (addr, rx)
}

/// The one stub-upstream socket loop behind `mock_upstream`,
/// `mock_upstream_raw` and `recording_upstream`: answer every query with
/// `bytes` (ID patched), optionally within the query's advertised budget,
/// optionally reporting each inbound query wire. The unbounded recorder
/// cannot block the reply loop, whatever the test's drain cadence.
async fn spawn_stub(
    bytes: Vec<u8>,
    honor_budget: bool,
    record: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, src)) = sock.recv_from(&mut buf).await {
            let mut reply = if honor_budget {
                reply_within_budget(&bytes, &buf[..n])
            } else {
                bytes.clone()
            };
            reply[0] = buf[0];
            reply[1] = buf[1];
            let _ = sock.send_to(&reply, src).await;
            if let Some(tx) = &record {
                if tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        }
    });
    addr
}

/// A resolver honors the requestor's advertised payload size: an answer that
/// does not fit comes back with TC=1 and no records (RFC 6891 §6.2.4). A stub
/// that always replies in full is blind to every bug the outbound OPT can
/// cause, since that OPT is precisely what upstream acts on (issue #191).
fn reply_within_budget(full: &[u8], query_wire: &[u8]) -> Vec<u8> {
    let mut parse = BytePacketBuffer::from_bytes(query_wire);
    let Ok(query) = DnsPacket::from_buffer(&mut parse) else {
        return full.to_vec();
    };
    let budget = query
        .edns
        .as_ref()
        .map_or(512, |e| e.udp_payload_size as usize);
    if full.len() <= budget {
        return echo_question(full, &query);
    }

    let mut tc = DnsPacket::response_from(&query, ResultCode::NOERROR);
    tc.header.truncated_message = true;
    let mut out = BytePacketBuffer::new();
    tc.write(&mut out).unwrap();
    out.filled().to_vec()
}

/// Real upstreams echo the query's question; the record-only fixture builders
/// (`noerror_response`, `a_record_response`) omit it. Graft it back so replies
/// pass the resolver's RFC 5452 question check, leaving already-questioned or
/// unparseable fixtures untouched.
fn echo_question(full: &[u8], query: &DnsPacket) -> Vec<u8> {
    let mut parse = BytePacketBuffer::from_bytes(full);
    let Ok(mut resp) = DnsPacket::from_buffer(&mut parse) else {
        return full.to_vec();
    };
    if !resp.questions.is_empty() {
        return full.to_vec();
    }
    resp.questions = query.questions.clone();
    let mut out = BytePacketBuffer::new();
    match resp.write(&mut out) {
        Ok(_) => out.filled().to_vec(),
        Err(_) => full.to_vec(),
    }
}

/// TCP counterpart of `mock_upstream_raw`, bound to the given address —
/// answers each length-prefixed query with `bytes` verbatim (ID patched).
/// Bind it to a UDP stub's address (disjoint port spaces) for TC=1 retry
/// tests, where UDP truncates and TCP holds the full answer.
pub async fn tcp_upstream_raw_on(addr: SocketAddr, bytes: Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                continue;
            }
            let mut query = vec![0u8; u16::from_be_bytes(len_buf) as usize];
            if stream.read_exact(&mut query).await.is_err() || query.len() < 2 {
                continue;
            }
            let mut reply = bytes.clone();
            crate::wire::patch_id(&mut reply, u16::from_be_bytes([query[0], query[1]]));
            let mut out = Vec::with_capacity(2 + reply.len());
            out.extend_from_slice(&(reply.len() as u16).to_be_bytes());
            out.extend_from_slice(&reply);
            let _ = stream.write_all(&out).await;
        }
    });
}

/// DoH counterpart of `mock_upstream_raw`: answers every POST to `/dns-query`
/// with `bytes` (ID patched), and reports each inbound query wire on the
/// returned channel. The URL is ready to hand an `Upstream::Doh`.
pub async fn doh_upstream_raw(
    bytes: Vec<u8>,
) -> (String, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
    use std::future::IntoFuture;

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let app = axum::Router::new().route(
        "/dns-query",
        axum::routing::post(move |query: axum::body::Bytes| {
            let mut reply = bytes.clone();
            let tx = tx.clone();
            async move {
                if query.len() >= 2 {
                    crate::wire::patch_id(&mut reply, u16::from_be_bytes([query[0], query[1]]));
                }
                let _ = tx.send(query.to_vec());
                (
                    [(axum::http::header::CONTENT_TYPE, "application/dns-message")],
                    reply,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app).into_future());
    (format!("http://{}/dns-query", addr), rx)
}

/// UDP socket that accepts connections but never replies.
/// Useful as an upstream that triggers timeouts.
pub fn blackhole_upstream() -> SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    // Leak so it stays bound for the duration of the test process.
    Box::leak(Box::new(sock));
    addr
}
