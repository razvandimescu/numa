use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::blocklist::BlocklistStore;
use crate::buffer::BytePacketBuffer;
use crate::cache::DnsCache;
use crate::config::UpstreamMode;
use crate::ctx::ServerCtx;
use crate::forward::{Upstream, UpstreamPool};
use crate::health::HealthMeta;
use crate::lan::PeerStore;
use crate::override_store::OverrideStore;
use crate::packet::DnsPacket;
use crate::query_log::QueryLog;
use crate::service_store::ServiceStore;
use crate::srtt::SrttCache;
use crate::stats::ServerStats;
/// Minimal `ServerCtx` for tests. Override fields after construction
/// (all fields are `pub`), then wrap in `Arc`.
pub async fn test_ctx() -> ServerCtx {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    ServerCtx {
        socket,
        zone_map: HashMap::new(),
        cache: RwLock::new(DnsCache::new(100, 60, 86400)),
        refreshing: Mutex::new(HashSet::new()),
        stats: Mutex::new(ServerStats::new()),
        overrides: RwLock::new(OverrideStore::new()),
        blocklist: RwLock::new(BlocklistStore::new()),
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
    }
}

/// Spawn a UDP socket that replies to the first DNS query with the given
/// response packet (patching the query ID to match). Returns the socket address.
pub async fn mock_upstream(response: DnsPacket) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (_, src) = sock.recv_from(&mut buf).await.unwrap();
        let query_id = u16::from_be_bytes([buf[0], buf[1]]);
        let mut resp = response;
        resp.header.id = query_id;
        let mut out = BytePacketBuffer::new();
        resp.write(&mut out).unwrap();
        sock.send_to(out.filled(), src).await.unwrap();
    });
    addr
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
