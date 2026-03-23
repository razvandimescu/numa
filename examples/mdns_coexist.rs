use socket2::{Domain, Protocol, Socket, Type};
/// Spike: can we bind to mDNS multicast (224.0.0.251:5353) alongside macOS mDNSResponder?
///
/// Tests:
/// 1. Bind UDP socket to 0.0.0.0:5353 with SO_REUSEPORT + SO_REUSEADDR
/// 2. Join multicast group 224.0.0.251
/// 3. Send a PTR query for _services._dns-sd._udp.local (standard browse)
/// 4. Listen for mDNS responses — do we see them alongside mDNSResponder?
/// 5. Send a _numa._tcp.local announcement — does it conflict?
///
/// Run: cargo run --example mdns_coexist
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

fn main() -> std::io::Result<()> {
    println!("=== mDNS coexistence spike ===\n");

    // Step 1: Create UDP socket with SO_REUSEPORT + SO_REUSEADDR
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    println!("[OK] Socket created with SO_REUSEADDR + SO_REUSEPORT");

    // Step 2: Bind to 0.0.0.0:5353
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
    match socket.bind(&bind_addr.into()) {
        Ok(()) => println!("[OK] Bound to 0.0.0.0:{}", MDNS_PORT),
        Err(e) => {
            println!("[FAIL] Cannot bind to port {}: {}", MDNS_PORT, e);
            println!("       mDNSResponder may not allow port sharing");
            return Ok(());
        }
    }

    // Step 3: Join multicast group
    match socket.join_multicast_v4(&MDNS_ADDR, &Ipv4Addr::UNSPECIFIED) {
        Ok(()) => println!("[OK] Joined multicast group {}", MDNS_ADDR),
        Err(e) => {
            println!("[FAIL] Cannot join multicast {}: {}", MDNS_ADDR, e);
            return Ok(());
        }
    }

    // Step 4: Send a PTR query for _services._dns-sd._udp.local
    let query = build_mdns_query("_services._dns-sd._udp.local");
    let dest = SocketAddrV4::new(MDNS_ADDR, MDNS_PORT);
    match socket.send_to(&query, &dest.into()) {
        Ok(n) => println!("[OK] Sent mDNS browse query ({} bytes)", n),
        Err(e) => {
            println!("[FAIL] Cannot send to multicast: {}", e);
            return Ok(());
        }
    }

    // Step 5: Listen for responses (3 second timeout)
    socket.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    let mut buf = [MaybeUninit::<u8>::zeroed(); 4096];
    let mut count = 0;

    println!("\nListening for mDNS responses (3s timeout)...\n");
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, addr)) => {
                let data: &[u8] =
                    unsafe { &*(&buf[..n] as *const [MaybeUninit<u8>] as *const [u8]) };
                count += 1;
                let flags = u16::from_be_bytes([data[2], data[3]]);
                let is_response = flags & 0x8000 != 0;
                let qdcount = u16::from_be_bytes([data[4], data[5]]);
                let ancount = u16::from_be_bytes([data[6], data[7]]);
                println!(
                    "  #{} from {} — {} bytes, {}, questions={}, answers={}",
                    count,
                    addr.as_socket().map(|s| s.to_string()).unwrap_or_default(),
                    n,
                    if is_response { "RESPONSE" } else { "QUERY" },
                    qdcount,
                    ancount,
                );
                if count >= 20 {
                    println!("\n  (capped at 20, stopping)");
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                println!("\n  Timeout — received {} packets total", count);
                break;
            }
            Err(e) => {
                println!("[FAIL] recv error: {}", e);
                break;
            }
        }
    }

    // Step 6: Send a _numa._tcp.local announcement
    let announcement =
        build_mdns_announcement("_numa._tcp.local", "test-numa._numa._tcp.local", 5380);
    match socket.send_to(&announcement, &dest.into()) {
        Ok(n) => println!("\n[OK] Sent _numa._tcp.local announcement ({} bytes)", n),
        Err(e) => println!("\n[FAIL] Cannot send announcement: {}", e),
    }

    // Verify we can see our own announcement
    socket.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    let mut buf2 = [MaybeUninit::<u8>::zeroed(); 4096];
    println!("Listening for our announcement echo (2s)...\n");
    loop {
        match socket.recv_from(&mut buf2) {
            Ok((n, addr)) => {
                let data: &[u8] =
                    unsafe { &*(&buf2[..n] as *const [MaybeUninit<u8>] as *const [u8]) };
                let flags = u16::from_be_bytes([data[2], data[3]]);
                let is_response = flags & 0x8000 != 0;
                if is_response {
                    println!(
                        "  Received response from {} ({} bytes) — multicast RX confirmed",
                        addr.as_socket().map(|s| s.to_string()).unwrap_or_default(),
                        n
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                println!("  Timeout");
                break;
            }
            Err(_) => break,
        }
    }

    // Verdict
    println!("\n=== Verdict ===");
    if count > 0 {
        println!(
            "[PASS] mDNS coexistence works — received {} packets alongside mDNSResponder",
            count
        );
        println!("       Safe to proceed with mDNS-based LAN discovery");
    } else {
        println!("[WARN] No mDNS packets received — may need further investigation");
        println!("       Possible causes: firewall, mDNSResponder not sharing port");
    }

    Ok(())
}

/// Build a minimal mDNS PTR query packet
fn build_mdns_query(name: &str) -> Vec<u8> {
    let mut pkt = Vec::new();

    // Header: ID=0, flags=0 (query), QDCOUNT=1
    pkt.extend_from_slice(&[0, 0]); // ID
    pkt.extend_from_slice(&[0, 0]); // Flags (standard query)
    pkt.extend_from_slice(&[0, 1]); // QDCOUNT = 1
    pkt.extend_from_slice(&[0, 0]); // ANCOUNT
    pkt.extend_from_slice(&[0, 0]); // NSCOUNT
    pkt.extend_from_slice(&[0, 0]); // ARCOUNT

    // Question: encode name as labels
    for label in name.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root label

    pkt.extend_from_slice(&[0, 12]); // QTYPE = PTR (12)
    pkt.extend_from_slice(&[0, 1]); // QCLASS = IN (1)

    pkt
}

/// Build a minimal mDNS announcement (response with PTR + SRV + TXT)
fn build_mdns_announcement(service_type: &str, instance_name: &str, port: u16) -> Vec<u8> {
    let mut pkt = Vec::new();

    // Header: ID=0, flags=0x8400 (response, authoritative), ANCOUNT=1
    pkt.extend_from_slice(&[0, 0]); // ID
    pkt.extend_from_slice(&[0x84, 0x00]); // Flags: QR=1, AA=1
    pkt.extend_from_slice(&[0, 0]); // QDCOUNT
    pkt.extend_from_slice(&[0, 1]); // ANCOUNT = 1 (just PTR for now)
    pkt.extend_from_slice(&[0, 0]); // NSCOUNT
    pkt.extend_from_slice(&[0, 0]); // ARCOUNT

    // PTR record: _numa._tcp.local → test-numa._numa._tcp.local
    encode_name(&mut pkt, service_type);
    pkt.extend_from_slice(&[0, 12]); // TYPE = PTR
    pkt.extend_from_slice(&[0, 1]); // CLASS = IN
    pkt.extend_from_slice(&[0, 0, 0, 120]); // TTL = 120s

    // RDATA: the instance name
    let mut rdata = Vec::new();
    encode_name(&mut rdata, instance_name);
    pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
    pkt.extend_from_slice(&rdata);

    let _ = port; // SRV record would use this — omitted for spike simplicity

    pkt
}

fn encode_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}
