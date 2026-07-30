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

/// Spawn a UDP socket that replies to the first DNS query with the given
/// response packet (patching the query ID to match). Returns the socket address.
pub async fn mock_upstream(response: DnsPacket) -> SocketAddr {
    let mut out = BytePacketBuffer::new();
    response.write(&mut out).unwrap();
    mock_upstream_raw(out.filled().to_vec()).await
}

/// Like `mock_upstream` but sends raw wire bytes — for intentionally
/// malformed responses that can't survive our own serializer.
pub async fn mock_upstream_raw(mut bytes: Vec<u8>) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (_, src) = sock.recv_from(&mut buf).await.unwrap();
        bytes[0] = buf[0];
        bytes[1] = buf[1];
        sock.send_to(&bytes, src).await.unwrap();
    });
    addr
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
        let mut buf = [0u8; 512];
        while let Ok((n, src)) = sock.recv_from(&mut buf).await {
            let mut query_buf = BytePacketBuffer::from_bytes(&buf[..n]);
            let Ok(query) = DnsPacket::from_buffer(&mut query_buf) else {
                continue;
            };
            let Some(question) = query.questions.first() else {
                continue;
            };
            if let Some((_, bytes)) = table.iter().find(|(name, _)| *name == question.name) {
                let mut reply = bytes.clone();
                reply[0] = buf[0];
                reply[1] = buf[1];
                let _ = sock.send_to(&reply, src).await;
            }
        }
    });
    addr
}

/// Stub UDP upstream: answers every query NOERROR with one A record and
/// reports each inbound query wire on the returned channel, so tests can
/// assert what actually went upstream (e.g. the DO bit, issue #191).
pub async fn stub_udp_upstream() -> (SocketAddr, tokio::sync::mpsc::Receiver<Vec<u8>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let wire = buf[..n].to_vec();
            let mut pb = BytePacketBuffer::from_bytes(&wire);
            if let Ok(query) = DnsPacket::from_buffer(&mut pb) {
                let mut resp = DnsPacket::response_from(&query, ResultCode::NOERROR);
                resp.answers.push(a_record(
                    "example.com",
                    Ipv4Addr::new(93, 184, 216, 34),
                    300,
                ));
                let mut out = BytePacketBuffer::new();
                if resp.write(&mut out).is_ok() {
                    let _ = sock.send_to(out.filled(), peer).await;
                }
            }
            if tx.send(wire).await.is_err() {
                break;
            }
        }
    });
    (addr, rx)
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
