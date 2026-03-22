use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::config::LanConfig;
use crate::ctx::ServerCtx;

// --- Peer Store ---

pub struct PeerStore {
    peers: HashMap<String, (IpAddr, u16, Instant)>,
    timeout: Duration,
}

impl PeerStore {
    pub fn new(timeout_secs: u64) -> Self {
        PeerStore {
            peers: HashMap::new(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    pub fn update(&mut self, host: IpAddr, services: &[(String, u16)]) {
        let now = Instant::now();
        for (name, port) in services {
            self.peers.insert(name.to_lowercase(), (host, *port, now));
        }
    }

    pub fn lookup(&mut self, name: &str) -> Option<(IpAddr, u16)> {
        let key = name.to_lowercase();
        let entry = self.peers.get(&key)?;
        if entry.2.elapsed() > self.timeout {
            self.peers.remove(&key);
            return None;
        }
        Some((entry.0, entry.1))
    }

    pub fn list(&mut self) -> Vec<(String, IpAddr, u16, u64)> {
        let now = Instant::now();
        self.peers
            .retain(|_, (_, _, seen)| now.duration_since(*seen) < self.timeout);
        self.peers
            .iter()
            .map(|(name, (ip, port, seen))| {
                (
                    name.clone(),
                    *ip,
                    *port,
                    now.duration_since(*seen).as_secs(),
                )
            })
            .collect()
    }

    pub fn clear(&mut self) {
        self.peers.clear();
    }
}

// --- Multicast ---

#[derive(Serialize, Deserialize)]
struct Announcement {
    instance_id: u64,
    host: String,
    services: Vec<AnnouncedService>,
}

#[derive(Serialize, Deserialize)]
struct AnnouncedService {
    name: String,
    port: u16,
}

pub fn detect_lan_ip() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(addr) => Some(*addr.ip()),
        _ => None,
    }
}

pub async fn start_lan_discovery(ctx: Arc<ServerCtx>, config: &LanConfig) {
    let multicast_group: Ipv4Addr = match config.multicast_group.parse::<Ipv4Addr>() {
        Ok(g) if g.is_multicast() => g,
        Ok(g) => {
            warn!("LAN: {} is not a multicast address (224.0.0.0/4)", g);
            return;
        }
        Err(e) => {
            warn!(
                "LAN: invalid multicast group {}: {}",
                config.multicast_group, e
            );
            return;
        }
    };
    let port = config.port;
    let interval = Duration::from_secs(config.broadcast_interval_secs);

    let instance_id: u64 = {
        let pid = std::process::id() as u64;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        pid ^ ts
    };
    let local_ip = *ctx.lan_ip.lock().unwrap();
    info!(
        "LAN discovery on {}:{}, local IP {}, instance {:016x}",
        multicast_group, port, local_ip, instance_id
    );

    // Create socket with SO_REUSEADDR for multicast
    let std_socket = match create_multicast_socket(multicast_group, port) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "LAN: could not bind multicast socket: {} — LAN discovery disabled",
                e
            );
            return;
        }
    };
    let socket = match tokio::net::UdpSocket::from_std(std_socket) {
        Ok(s) => s,
        Err(e) => {
            warn!("LAN: tokio socket conversion failed: {}", e);
            return;
        }
    };
    let socket = Arc::new(socket);

    // Spawn sender
    let sender_ctx = Arc::clone(&ctx);
    let sender_socket = Arc::clone(&socket);
    let dest = SocketAddr::new(IpAddr::V4(multicast_group), port);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let services: Vec<AnnouncedService> = {
                let store = sender_ctx.services.lock().unwrap();
                store
                    .list()
                    .iter()
                    .map(|e| AnnouncedService {
                        name: e.name.clone(),
                        port: e.target_port,
                    })
                    .collect()
            };
            if services.is_empty() {
                continue;
            }
            let current_ip = sender_ctx.lan_ip.lock().unwrap().to_string();
            let announcement = Announcement {
                instance_id,
                host: current_ip,
                services,
            };
            if let Ok(json) = serde_json::to_vec(&announcement) {
                let _ = sender_socket.send_to(&json, dest).await;
            }
        }
    });

    // Receiver loop
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                debug!("LAN recv error: {}", e);
                continue;
            }
        };
        let announcement: Announcement = match serde_json::from_slice(&buf[..len]) {
            Ok(a) => a,
            Err(_) => continue,
        };
        // Skip self-announcements
        if announcement.instance_id == instance_id {
            continue;
        }
        let peer_ip: IpAddr = match announcement.host.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let services: Vec<(String, u16)> = announcement
            .services
            .iter()
            .map(|s| (s.name.clone(), s.port))
            .collect();
        let count = services.len();
        ctx.lan_peers.lock().unwrap().update(peer_ip, &services);
        debug!(
            "LAN: {} services from {} (via {})",
            count, announcement.host, src
        );
    }
}

fn create_multicast_socket(group: Ipv4Addr, port: u16) -> std::io::Result<std::net::UdpSocket> {
    use std::net::SocketAddrV4;

    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket2::SockAddr::from(addr))?;
    socket.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)?;
    Ok(socket.into())
}
