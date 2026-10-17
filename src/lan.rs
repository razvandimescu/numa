use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, info, warn};

use crate::buffer::BytePacketBuffer;
use crate::config::LanConfig;
use crate::ctx::ServerCtx;
use crate::header::DnsHeader;
use crate::health::HealthMeta;
use crate::question::{DnsQuestion, QueryType};
use crate::record::TXT_STRING_MAX;

// --- Constants ---

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const SERVICE_TYPE: &str = "_numa._tcp.local";
const MDNS_TTL: u32 = 120;

// TXT record key prefixes (including the trailing `=`). Shared between
// the sender (`build_announcement`) and the receiver (`parse_mdns_response`)
// to prevent drift — both sides match on the same literal, not on two
// independent string constants that could diverge.
const TXT_ID: &str = "id=";
const TXT_VERSION: &str = "version=";
const TXT_API_PORT: &str = "api_port=";
const TXT_PROTO: &str = "proto=";
const TXT_DOT_PORT: &str = "dot_port=";
const TXT_CA_FP: &str = "ca_fp=";
// The services list is split into `services=`, `services2=`, `services3=`, ...
// RFC 6763 §6.4 lets a key appear once, and older peers read only `services=`.
const TXT_SERVICES_KEY: &str = "services";
// Room for any key up to `services99=`, so an entry is kept or left out the
// same way in every batch.
const MAX_SERVICE_ENTRY: usize = TXT_STRING_MAX - TXT_SERVICES_KEY.len() - "99=".len();

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

    /// Returns true if a previously-unseen name was inserted.
    pub fn update(&mut self, host: IpAddr, services: &[(String, u16)]) -> bool {
        let now = Instant::now();
        let mut changed = false;
        for (name, port) in services {
            let key = name.to_lowercase();
            if !self.peers.contains_key(&key) {
                changed = true;
            }
            self.peers.insert(key, (host, *port, now));
        }
        changed
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

    pub fn names(&mut self) -> Vec<String> {
        let now = Instant::now();
        self.peers
            .retain(|_, (_, _, seen)| now.duration_since(*seen) < self.timeout);
        self.peers.keys().cloned().collect()
    }

    pub fn clear(&mut self) {
        self.peers.clear();
    }
}

// --- mDNS Discovery ---

/// Source IPv4 the kernel would route from to reach `dest`. The UDP `connect`
/// sends no packet — it only consults the routing table.
pub fn local_ip_toward(dest: IpAddr) -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((dest, 53)).ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(addr) => Some(*addr.ip()),
        _ => None,
    }
}

pub fn detect_lan_ip() -> Option<Ipv4Addr> {
    local_ip_toward(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
}

/// Short hostname for mDNS instance names (`<short>._numa._tcp.local`).
/// Truncates at the first `.` so `macbook-pro.local` becomes `macbook-pro`.
/// Uses the shared `crate::hostname()` helper as the source.
fn get_hostname() -> String {
    crate::hostname()
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("numa")
        .to_string()
}

/// Generate a per-process instance ID for self-filtering on multi-instance hosts
fn instance_id() -> String {
    format!(
        "{}:{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            % 1_000_000
    )
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
            warn!(
                "LAN: could not bind mDNS socket: {} — LAN discovery disabled",
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
                store
                    .list()
                    .iter()
                    .map(|e| (e.name.clone(), e.target_port))
                    .collect()
            };
            // Note: we always announce ourselves, even when the
            // services list is empty. The announcement still carries
            // the mobile API port + version + CA fingerprint in TXT,
            // which is what the iOS companion app browses for via
            // NWBrowser on `_numa._tcp.local`. Other Numa peers
            // receive these empty-services announcements too and
            // correctly ignore them in parse_mdns_response (the
            // receiver only processes when services is non-empty).
            let current_ip = *sender_ctx.lan_ip.lock().unwrap();
            if let Ok(pkt) = build_announcement(
                &sender_hostname,
                current_ip,
                &services,
                &sender_instance_id,
                &sender_ctx.health_meta,
            ) {
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
        for ann in parse_mdns_response(data) {
            // Skip our own announcements via instance ID (works on multi-instance same-host)
            if ann.instance_id.as_deref() == Some(our_instance_id.as_str()) {
                continue;
            }
            if !ann.services.is_empty() {
                let changed = ctx
                    .lan_peers
                    .lock()
                    .unwrap()
                    .update(ann.peer_ip, &ann.services);
                if changed {
                    crate::tls::regenerate_tls(&ctx);
                }
                debug!(
                    "LAN: {} services from {} (mDNS)",
                    ann.services.len(),
                    ann.peer_ip
                );
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
    meta: &HealthMeta,
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
    // Port = mobile API port, which is what the iOS companion app resolves
    // the SRV record for. Legacy Numa peers don't read the SRV port (see
    // parse_mdns_response — it only uses TXT services= for peer discovery),
    // so changing the SRV port from "first service's port" to the mobile
    // API port is backwards compatible.
    write_record_header(
        &mut buf,
        &instance_name,
        QueryType::SRV.to_num(),
        0x8001,
        MDNS_TTL,
    )?;
    let rdlen_pos = buf.pos();
    buf.write_u16(0)?;
    let rdata_start = buf.pos();
    buf.write_u16(0)?; // priority
    buf.write_u16(0)?; // weight
    buf.write_u16(meta.api_port)?; // mobile API port, for iOS companion app
    buf.write_qname(&host_local)?;
    patch_rdlen(&mut buf, rdlen_pos, rdata_start)?;

    // TXT: legacy peer-discovery entries (services, id) + enriched entries
    // for the iOS companion app (version, api_port, proto, dot_port, ca_fp).
    // All in one TXT RRset per mDNS convention.
    write_record_header(
        &mut buf,
        &instance_name,
        QueryType::TXT.to_num(),
        0x8001,
        MDNS_TTL,
    )?;
    let rdlen_pos = buf.pos();
    buf.write_u16(0)?;
    let rdata_start = buf.pos();
    // Legacy peer-discovery entries (consumed by parse_mdns_response)
    for s in services_txt_strings(services) {
        write_txt_string(&mut buf, &s)?;
    }
    write_txt_string(&mut buf, &format!("{}{}", TXT_ID, inst_id))?;
    // Enriched entries (consumed by the iOS/Android companion apps)
    write_txt_string(&mut buf, &format!("{}{}", TXT_VERSION, meta.version))?;
    write_txt_string(&mut buf, &format!("{}{}", TXT_API_PORT, meta.api_port))?;
    if meta.dot_enabled {
        write_txt_string(&mut buf, &format!("{}dot", TXT_PROTO))?;
        write_txt_string(&mut buf, &format!("{}{}", TXT_DOT_PORT, meta.dot_port))?;
    } else {
        write_txt_string(&mut buf, &format!("{}plain", TXT_PROTO))?;
    }
    if let Some(fp) = &meta.ca_fingerprint_sha256 {
        write_txt_string(&mut buf, &format!("{}{}", TXT_CA_FP, fp))?;
    }
    patch_rdlen(&mut buf, rdlen_pos, rdata_start)?;

    // A: <hostname>.local → IP
    write_record_header(
        &mut buf,
        &host_local,
        QueryType::A.to_num(),
        0x8001,
        MDNS_TTL,
    )?;
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

fn patch_rdlen(
    buf: &mut BytePacketBuffer,
    rdlen_pos: usize,
    rdata_start: usize,
) -> crate::Result<()> {
    let rdlen = (buf.pos() - rdata_start) as u16;
    buf.set_u16(rdlen_pos, rdlen)
}

/// One TXT string per batch of whole entries, since peers parse each string on
/// its own. An entry longer than `MAX_SERVICE_ENTRY` is left out.
fn services_txt_strings(services: &[(String, u16)]) -> Vec<String> {
    let mut strings = vec![format!("{TXT_SERVICES_KEY}=")];
    for (name, port) in services {
        let entry = format!("{name}:{port}");
        if entry.len() > MAX_SERVICE_ENTRY {
            continue;
        }
        let last = strings.last_mut().expect("starts with one string");
        let sep = if last.ends_with('=') { "" } else { "," };
        if last.len() + sep.len() + entry.len() <= TXT_STRING_MAX {
            last.push_str(sep);
            last.push_str(&entry);
        } else {
            strings.push(format!("{TXT_SERVICES_KEY}{}={entry}", strings.len() + 1));
        }
    }
    strings
}

fn services_value(txt: &str) -> Option<&str> {
    let (key, value) = txt.split_once('=')?;
    let batch = key.strip_prefix(TXT_SERVICES_KEY)?;
    batch.bytes().all(|b| b.is_ascii_digit()).then_some(value)
}

fn write_txt_string(buf: &mut BytePacketBuffer, s: &str) -> crate::Result<()> {
    debug_assert!(
        s.len() <= TXT_STRING_MAX,
        "a DNS-SD key=value must fit one string"
    );
    buf.write_bytes(&crate::record::txt_rdata(s))
}

// --- mDNS Packet Parsing ---

struct MdnsAnnouncement {
    services: Vec<(String, u16)>,
    peer_ip: IpAddr,
    instance_id: Option<String>,
}

fn parse_mdns_response(data: &[u8]) -> Vec<MdnsAnnouncement> {
    if data.len() < 12 {
        return Vec::new();
    }

    let mut buf = BytePacketBuffer::new();
    buf.buf[..data.len()].copy_from_slice(data);

    let mut header = DnsHeader::new();
    if header.read(&mut buf).is_err() || !header.response || header.answers == 0 {
        return Vec::new();
    }

    // Skip questions
    for _ in 0..header.questions {
        let mut q = DnsQuestion::new(String::new(), QueryType::UNKNOWN(0));
        if q.read(&mut buf).is_err() {
            return Vec::new();
        }
    }

    let total = u32::from(header.answers)
        + u32::from(header.authoritative_entries)
        + u32::from(header.resource_entries);
    let mut txts = Vec::new();
    let mut srv_targets = Vec::new();
    let mut addrs = Vec::new();
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

        let is_numa = name.contains("_numa._tcp");
        match rtype {
            t if t == QueryType::TXT.to_num() && is_numa => {
                if let Some(rdata) = data.get(rdata_start..rdata_start + rdlength) {
                    let (services, id) = parse_numa_txt(rdata);
                    if !services.is_empty() {
                        txts.push((name.clone(), services, id));
                    }
                }
            }
            t if t == QueryType::SRV.to_num()
                && is_numa
                && rdlength > 6
                && rdata_start + rdlength <= data.len() =>
            {
                let mut target = String::new();
                // Pointers may jump anywhere earlier, but the target's own bytes
                // must end inside the record.
                if buf.seek(rdata_start + 6).is_ok()
                    && buf.read_qname(&mut target).is_ok()
                    && buf.pos() <= rdata_start + rdlength
                {
                    srv_targets.push((name.clone(), target));
                }
            }
            t if t == QueryType::A.to_num() && rdlength == 4 && rdata_start + 4 <= data.len() => {
                let ip = Ipv4Addr::new(
                    data[rdata_start],
                    data[rdata_start + 1],
                    data[rdata_start + 2],
                    data[rdata_start + 3],
                );
                addrs.push((name.clone(), IpAddr::V4(ip)));
            }
            _ => {}
        }

        buf.seek(rdata_start + rdlength).ok();
    }

    // One packet can carry several instances (an mDNS reflector merges them),
    // so each TXT reaches its address through its own SRV target.
    txts.into_iter()
        .filter_map(|(owner, services, instance_id)| {
            let (_, target) = srv_targets
                .iter()
                .find(|(o, _)| o.eq_ignore_ascii_case(&owner))?;
            let (_, peer_ip) = addrs.iter().find(|(o, _)| o.eq_ignore_ascii_case(target))?;
            Some(MdnsAnnouncement {
                services,
                peer_ip: *peer_ip,
                instance_id,
            })
        })
        .collect()
}

/// Services and instance id from one TXT record. Services from different
/// records are never merged: they may belong to different hosts.
fn parse_numa_txt(mut rdata: &[u8]) -> (Vec<(String, u16)>, Option<String>) {
    let mut services = Vec::new();
    let mut id = None;
    let mut seen_keys: Vec<&str> = Vec::new();
    while let Some((&len, rest)) = rdata.split_first() {
        let Some((string, rest)) = rest.split_at_checked(len as usize) else {
            break;
        };
        rdata = rest;
        let Ok(txt) = std::str::from_utf8(string) else {
            continue;
        };
        // RFC 6763 §6.4: only the first occurrence of a key counts.
        let key = txt.split_once('=').map_or(txt, |(k, _)| k);
        if seen_keys.contains(&key) {
            continue;
        }
        seen_keys.push(key);
        if let Some(val) = services_value(txt) {
            services.extend(val.split(',').filter_map(|s| {
                let (name, port) = s.split_once(':')?;
                Some((name.to_string(), port.parse().ok()?))
            }));
        } else if let Some(v) = txt.strip_prefix(TXT_ID) {
            id = Some(v.to_string());
        }
    }
    (services, id)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_ip_toward_loopback_dest_is_loopback() {
        assert_eq!(
            local_ip_toward(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Some(Ipv4Addr::LOCALHOST)
        );
    }

    #[test]
    fn announcement_round_trips_services_past_one_txt_string() {
        let services: Vec<(String, u16)> = (0..30)
            .map(|i| (format!("service-{i}"), 3000 + i))
            .collect();
        let meta = crate::health::HealthMeta::test_fixture();
        let buf = build_announcement(
            "host",
            Ipv4Addr::new(192, 168, 1, 7),
            &services,
            "id",
            &meta,
        )
        .unwrap();

        let parsed = parse_mdns_response(buf.filled());
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].services, services);
    }

    #[test]
    fn services_batches_fit_one_string_with_distinct_keys() {
        let services: Vec<(String, u16)> = (0..30)
            .map(|i| (format!("service-{i}"), 3000 + i))
            .collect();
        let strings = services_txt_strings(&services);

        let keys: Vec<&str> = strings
            .iter()
            .map(|s| s.split_once('=').unwrap().0)
            .collect();
        assert_eq!(keys, ["services", "services2"]);
        assert!(strings.iter().all(|s| s.len() <= TXT_STRING_MAX));
        // Older peers read only `services=`, so it keeps the head of the list.
        assert!(strings[0].starts_with("services=service-0:3000,"));
    }

    #[test]
    fn services_entry_too_long_is_skipped_wherever_it_lands() {
        let long = ("a".repeat(244), 1);
        assert_eq!(
            services_txt_strings(std::slice::from_ref(&long)),
            ["services="]
        );
        assert_eq!(
            services_txt_strings(&[("b".to_string(), 2), long]),
            ["services=b:2"]
        );
    }

    #[test]
    fn parse_keeps_the_first_of_repeated_txt_keys() {
        let mut buf = BytePacketBuffer::new();
        for s in ["services=a:1", "services=a:2", "id=x", "id=y"] {
            write_txt_string(&mut buf, s).unwrap();
        }
        let (services, id) = parse_numa_txt(buf.filled());
        assert_eq!(services, [("a".to_string(), 1)]);
        assert_eq!(id.as_deref(), Some("x"));
    }

    #[test]
    fn parse_matches_txt_keys_by_exact_case() {
        let mut buf = BytePacketBuffer::new();
        for s in ["Services=a:1", "services=a:2", "ID=first", "id=second"] {
            write_txt_string(&mut buf, s).unwrap();
        }
        let (services, id) = parse_numa_txt(buf.filled());
        assert_eq!(services, [("a".to_string(), 2)]);
        assert_eq!(id.as_deref(), Some("second"));
    }

    fn response(
        answers: u16,
        authorities: u16,
        records: impl FnOnce(&mut BytePacketBuffer),
    ) -> Vec<u8> {
        let mut buf = BytePacketBuffer::new();
        let mut header = DnsHeader::new();
        header.response = true;
        header.answers = answers;
        header.authoritative_entries = authorities;
        header.write(&mut buf).unwrap();
        records(&mut buf);
        buf.filled().to_vec()
    }

    fn write_txt(buf: &mut BytePacketBuffer, owner: &str, strings: &[&str]) {
        write_record_header(buf, owner, QueryType::TXT.to_num(), 1, MDNS_TTL).unwrap();
        let rdlen_pos = buf.pos();
        buf.write_u16(0).unwrap();
        let rdata_start = buf.pos();
        for s in strings {
            write_txt_string(buf, s).unwrap();
        }
        patch_rdlen(buf, rdlen_pos, rdata_start).unwrap();
    }

    fn write_a(buf: &mut BytePacketBuffer, host: &str, ip: Ipv4Addr) {
        write_record_header(buf, host, QueryType::A.to_num(), 1, MDNS_TTL).unwrap();
        buf.write_u16(4).unwrap();
        buf.write_bytes(&ip.octets()).unwrap();
    }

    fn write_srv(buf: &mut BytePacketBuffer, owner: &str, target: &str) {
        write_record_header(buf, owner, QueryType::SRV.to_num(), 1, MDNS_TTL).unwrap();
        let rdlen_pos = buf.pos();
        buf.write_u16(0).unwrap();
        let rdata_start = buf.pos();
        for priority_weight_port in [0, 0, 0] {
            buf.write_u16(priority_weight_port).unwrap();
        }
        buf.write_qname(target).unwrap();
        patch_rdlen(buf, rdlen_pos, rdata_start).unwrap();
    }

    #[test]
    fn parse_pairs_services_with_their_own_host() {
        let data = response(6, 0, |buf| {
            write_txt(buf, "a._numa._tcp.local", &["services=a:1", "id=a"]);
            write_txt(buf, "b._numa._tcp.local", &["services=b:2", "id=b"]);
            write_srv(buf, "a._numa._tcp.local", "a.local");
            write_srv(buf, "b._numa._tcp.local", "b.local");
            write_a(buf, "b.local", Ipv4Addr::new(192, 168, 1, 8));
            write_a(buf, "a.local", Ipv4Addr::new(192, 168, 1, 7));
        });
        let parsed: Vec<_> = parse_mdns_response(&data)
            .into_iter()
            .map(|a| (a.services, a.peer_ip, a.instance_id))
            .collect();
        assert_eq!(
            parsed,
            [
                (
                    vec![("a".to_string(), 1)],
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)),
                    Some("a".to_string())
                ),
                (
                    vec![("b".to_string(), 2)],
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)),
                    Some("b".to_string())
                ),
            ]
        );
    }

    #[test]
    fn parse_tolerates_record_counts_past_u16() {
        let data = response(u16::MAX, 1, |_| {});
        assert!(parse_mdns_response(&data).is_empty());
    }

    #[test]
    fn parse_reads_txt_strings_only_inside_the_record() {
        let data = response(3, 0, |buf| {
            write_srv(buf, "a._numa._tcp.local", "a.local");
            write_a(buf, "a.local", Ipv4Addr::new(192, 168, 1, 7));
            write_record_header(
                buf,
                "a._numa._tcp.local",
                QueryType::TXT.to_num(),
                1,
                MDNS_TTL,
            )
            .unwrap();
            buf.write_u16(1).unwrap();
            buf.write_u8(12).unwrap();
            buf.write_bytes(b"services=x:1").unwrap();
        });
        assert!(parse_mdns_response(&data).is_empty());
    }

    #[test]
    fn parse_reads_srv_target_only_inside_the_record() {
        let packet = |rdlength: u16, target: &[u8]| {
            response(3, 0, |buf| {
                write_a(buf, "a.local", Ipv4Addr::new(192, 168, 1, 7));
                write_txt(buf, "a._numa._tcp.local", &["services=a:1"]);
                write_record_header(
                    buf,
                    "a._numa._tcp.local",
                    QueryType::SRV.to_num(),
                    1,
                    MDNS_TTL,
                )
                .unwrap();
                buf.write_u16(rdlength).unwrap();
                buf.write_bytes(&[0; 6]).unwrap();
                buf.write_bytes(target).unwrap();
            })
        };
        let target = b"\x01a\x05local\x00";
        assert_eq!(parse_mdns_response(&packet(15, target)).len(), 1);
        // rdlength shorter than the target, then a packet that ends mid-target.
        assert!(parse_mdns_response(&packet(7, target)).is_empty());
        assert!(parse_mdns_response(&packet(15, &target[..8])).is_empty());
    }
}
