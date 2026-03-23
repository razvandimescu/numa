use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, info, warn};

use crate::buffer::BytePacketBuffer;
use crate::config::LanConfig;
use crate::ctx::ServerCtx;
use crate::header::DnsHeader;
use crate::question::{DnsQuestion, QueryType};

// --- Constants ---

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const SERVICE_TYPE: &str = "_numa._tcp.local";
const MDNS_TTL: u32 = 120;

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

// --- mDNS Discovery ---

pub fn detect_lan_ip() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(addr) => Some(*addr.ip()),
        _ => None,
    }
}

fn get_hostname() -> String {
    std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "numa".to_string())
}

/// Generate a per-process instance ID for self-filtering on multi-instance hosts
fn instance_id() -> String {
    format!("{}:{}", std::process::id(), std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() % 1_000_000)
}

pub async fn start_lan_discovery(ctx: Arc<ServerCtx>, config: &LanConfig) {
    let interval = Duration::from_secs(config.broadcast_interval_secs);
    let local_ip = *ctx.lan_ip.lock().unwrap();
    let hostname = get_hostname();
    let our_instance_id = instance_id();

    info!(
        "LAN discovery via mDNS on {}:{}, local IP {}, instance {}._numa._tcp.local",
        MDNS_ADDR, MDNS_PORT, local_ip, hostname
    );

    let std_socket = match create_mdns_socket() {
        Ok(s) => s,
        Err(e) => {
            warn!("LAN: could not bind mDNS socket: {} — LAN discovery disabled", e);
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
    let dest = SocketAddr::new(IpAddr::V4(MDNS_ADDR), MDNS_PORT);

    // Spawn sender: announce our services periodically
    let sender_ctx = Arc::clone(&ctx);
    let sender_socket = Arc::clone(&socket);
    let sender_hostname = hostname.clone();
    let sender_instance_id = our_instance_id.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let services: Vec<(String, u16)> = {
                let store = sender_ctx.services.lock().unwrap();
                store.list().iter().map(|e| (e.name.clone(), e.target_port)).collect()
            };
            if services.is_empty() {
                continue;
            }
            let current_ip = *sender_ctx.lan_ip.lock().unwrap();
            if let Ok(pkt) = build_announcement(&sender_hostname, current_ip, &services, &sender_instance_id) {
                let _ = sender_socket.send_to(pkt.filled(), dest).await;
            }
        }
    });

    // Send initial browse query
    if let Ok(pkt) = build_browse_query() {
        let _ = socket.send_to(pkt.filled(), dest).await;
    }

    // Receiver loop: parse mDNS responses for _numa._tcp
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, _src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                debug!("mDNS recv error: {}", e);
                continue;
            }
        };

        let data = &buf[..len];
        if let Some((services, peer_ip, peer_id)) = parse_mdns_response(data) {
            // Skip our own announcements via instance ID (works on multi-instance same-host)
            if peer_id.as_deref() == Some(our_instance_id.as_str()) {
                continue;
            }
            if !services.is_empty() {
                ctx.lan_peers.lock().unwrap().update(peer_ip, &services);
                debug!("LAN: {} services from {} (mDNS)", services.len(), peer_ip);
            }
        }
    }
}

// --- mDNS Packet Building ---

fn build_browse_query() -> crate::Result<BytePacketBuffer> {
    let mut buf = BytePacketBuffer::new();

    let mut header = DnsHeader::new();
    header.questions = 1;
    header.write(&mut buf)?;

    DnsQuestion::new(SERVICE_TYPE.to_string(), QueryType::PTR).write(&mut buf)?;

    Ok(buf)
}

fn build_announcement(
    hostname: &str,
    ip: Ipv4Addr,
    services: &[(String, u16)],
    inst_id: &str,
) -> crate::Result<BytePacketBuffer> {
    let mut buf = BytePacketBuffer::new();
    let instance_name = format!("{}._numa._tcp.local", hostname);
    let host_local = format!("{}.local", hostname);

    let mut header = DnsHeader::new();
    header.response = true;
    header.authoritative_answer = true;
    header.answers = 4; // PTR + SRV + TXT + A
    header.write(&mut buf)?;

    // PTR: _numa._tcp.local → <hostname>._numa._tcp.local
    write_record_header(&mut buf, SERVICE_TYPE, QueryType::PTR.to_num(), 1, MDNS_TTL)?;
    let rdlen_pos = buf.pos();
    buf.write_u16(0)?;
    let rdata_start = buf.pos();
    buf.write_qname(&instance_name)?;
    patch_rdlen(&mut buf, rdlen_pos, rdata_start)?;

    // SRV: <instance>._numa._tcp.local → <hostname>.local
    // Port in SRV is informational; actual service ports are in TXT
    write_record_header(&mut buf, &instance_name, QueryType::SRV.to_num(), 0x8001, MDNS_TTL)?;
    let rdlen_pos = buf.pos();
    buf.write_u16(0)?;
    let rdata_start = buf.pos();
    buf.write_u16(0)?;     // priority
    buf.write_u16(0)?;     // weight
    buf.write_u16(0)?;     // port (services have individual ports in TXT)
    buf.write_qname(&host_local)?;
    patch_rdlen(&mut buf, rdlen_pos, rdata_start)?;

    // TXT: services + instance ID for self-filtering
    write_record_header(&mut buf, &instance_name, QueryType::TXT.to_num(), 0x8001, MDNS_TTL)?;
    let rdlen_pos = buf.pos();
    buf.write_u16(0)?;
    let rdata_start = buf.pos();
    let svc_str = services
        .iter()
        .map(|(name, port)| format!("{}:{}", name, port))
        .collect::<Vec<_>>()
        .join(",");
    write_txt_string(&mut buf, &format!("services={}", svc_str))?;
    write_txt_string(&mut buf, &format!("id={}", inst_id))?;
    patch_rdlen(&mut buf, rdlen_pos, rdata_start)?;

    // A: <hostname>.local → IP
    write_record_header(&mut buf, &host_local, QueryType::A.to_num(), 0x8001, MDNS_TTL)?;
    buf.write_u16(4)?;
    for &b in &ip.octets() {
        buf.write_u8(b)?;
    }

    Ok(buf)
}

fn write_record_header(
    buf: &mut BytePacketBuffer,
    name: &str,
    rtype: u16,
    class: u16,
    ttl: u32,
) -> crate::Result<()> {
    buf.write_qname(name)?;
    buf.write_u16(rtype)?;
    buf.write_u16(class)?;
    buf.write_u32(ttl)?;
    Ok(())
}

fn patch_rdlen(buf: &mut BytePacketBuffer, rdlen_pos: usize, rdata_start: usize) -> crate::Result<()> {
    let rdlen = (buf.pos() - rdata_start) as u16;
    buf.set_u16(rdlen_pos, rdlen)
}

fn write_txt_string(buf: &mut BytePacketBuffer, s: &str) -> crate::Result<()> {
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(255) {
        buf.write_u8(chunk.len() as u8)?;
        for &b in chunk {
            buf.write_u8(b)?;
        }
    }
    Ok(())
}

// --- mDNS Packet Parsing ---

/// Returns (services, peer_ip, instance_id) if this is a Numa mDNS announcement
fn parse_mdns_response(data: &[u8]) -> Option<(Vec<(String, u16)>, IpAddr, Option<String>)> {
    if data.len() < 12 {
        return None;
    }

    let mut buf = BytePacketBuffer::new();
    buf.buf[..data.len()].copy_from_slice(data);

    let mut header = DnsHeader::new();
    header.read(&mut buf).ok()?;

    if !header.response || header.answers == 0 {
        return None;
    }

    // Skip questions
    for _ in 0..header.questions {
        let mut q = DnsQuestion::new(String::new(), QueryType::UNKNOWN(0));
        q.read(&mut buf).ok()?;
    }

    let total = header.answers + header.authoritative_entries + header.resource_entries;
    let mut txt_services: Option<Vec<(String, u16)>> = None;
    let mut peer_instance_id: Option<String> = None;
    let mut a_ip: Option<IpAddr> = None;
    let mut name = String::with_capacity(64);

    for _ in 0..total {
        if buf.pos() >= data.len() {
            break;
        }

        name.clear();
        if buf.read_qname(&mut name).is_err() {
            break;
        }

        let rtype = buf.read_u16().unwrap_or(0);
        let _rclass = buf.read_u16().unwrap_or(0);
        let _ttl = buf.read_u32().unwrap_or(0);
        let rdlength = buf.read_u16().unwrap_or(0) as usize;
        let rdata_start = buf.pos();

        match rtype {
            t if t == QueryType::TXT.to_num() && name.contains("_numa._tcp") => {
                let mut pos = rdata_start;
                while pos < rdata_start + rdlength && pos < data.len() {
                    let txt_len = data[pos] as usize;
                    pos += 1;
                    if pos + txt_len > data.len() {
                        break;
                    }
                    if let Ok(txt) = std::str::from_utf8(&data[pos..pos + txt_len]) {
                        if let Some(val) = txt.strip_prefix("services=") {
                            let svcs: Vec<(String, u16)> = val
                                .split(',')
                                .filter_map(|s| {
                                    let mut parts = s.splitn(2, ':');
                                    let svc_name = parts.next()?.to_string();
                                    let port = parts.next()?.parse().ok()?;
                                    Some((svc_name, port))
                                })
                                .collect();
                            if !svcs.is_empty() {
                                txt_services = Some(svcs);
                            }
                        } else if let Some(id) = txt.strip_prefix("id=") {
                            peer_instance_id = Some(id.to_string());
                        }
                    }
                    pos += txt_len;
                }
            }
            t if t == QueryType::A.to_num() && rdlength == 4 && rdata_start + 4 <= data.len() => {
                a_ip = Some(IpAddr::V4(Ipv4Addr::new(
                    data[rdata_start],
                    data[rdata_start + 1],
                    data[rdata_start + 2],
                    data[rdata_start + 3],
                )));
            }
            _ => {}
        }

        buf.seek(rdata_start + rdlength).ok();
    }

    let services = txt_services?;
    // Trust the A record IP if present, otherwise this isn't a complete announcement
    let peer_ip = a_ip?;

    Some((services, peer_ip, peer_instance_id))
}

fn create_mdns_socket() -> std::io::Result<std::net::UdpSocket> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
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
    socket.join_multicast_v4(&MDNS_ADDR, &Ipv4Addr::UNSPECIFIED)?;
    Ok(socket.into())
}
