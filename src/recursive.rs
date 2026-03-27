use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::RwLock;
use std::time::Duration;

use log::{debug, info};

use crate::cache::DnsCache;
use crate::forward::forward_udp;
use crate::header::ResultCode;
use crate::packet::DnsPacket;
use crate::question::{DnsQuestion, QueryType};
use crate::record::DnsRecord;

const MAX_REFERRAL_DEPTH: u8 = 10;
const MAX_CNAME_DEPTH: u8 = 8;
const NS_QUERY_TIMEOUT: Duration = Duration::from_millis(800);
const TCP_TIMEOUT: Duration = Duration::from_millis(1500);
const UDP_FAIL_THRESHOLD: u8 = 3;

static QUERY_ID: AtomicU16 = AtomicU16::new(1);
static UDP_FAILURES: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
static UDP_DISABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn next_id() -> u16 {
    QUERY_ID.fetch_add(1, Ordering::Relaxed)
}

fn dns_addr(ip: impl Into<IpAddr>) -> SocketAddr {
    SocketAddr::new(ip.into(), 53)
}

pub fn reset_udp_state() {
    UDP_DISABLED.store(false, Ordering::Relaxed);
    UDP_FAILURES.store(0, Ordering::Relaxed);
}

/// Probe whether UDP works again. Called periodically from the network watch loop.
pub async fn probe_udp(root_hints: &[SocketAddr]) {
    if !UDP_DISABLED.load(Ordering::Relaxed) {
        return;
    }
    let hint = match root_hints.first() {
        Some(h) => *h,
        None => return,
    };
    let mut probe = DnsPacket::new();
    probe.header.id = next_id();
    probe
        .questions
        .push(DnsQuestion::new(".".to_string(), QueryType::NS));
    if forward_udp(&probe, hint, Duration::from_millis(1500))
        .await
        .is_ok()
    {
        info!("UDP probe succeeded — re-enabling UDP");
        reset_udp_state();
    }
}

pub async fn prime_tld_cache(cache: &RwLock<DnsCache>, root_hints: &[SocketAddr], tlds: &[String]) {
    if root_hints.is_empty() || tlds.is_empty() {
        return;
    }

    let mut root_addr = root_hints[0];
    for hint in root_hints {
        info!("prime: probing root {}", hint);
        match send_query(".", QueryType::NS, *hint).await {
            Ok(_) => {
                info!("prime: root {} reachable", hint);
                root_addr = *hint;
                break;
            }
            Err(e) => {
                info!("prime: root {} failed: {}, trying next", hint, e);
            }
        }
    }

    // Fetch root DNSKEY (needed for DNSSEC chain-of-trust terminus)
    if let Ok(root_dnskey) = send_query(".", QueryType::DNSKEY, root_addr).await {
        cache
            .write()
            .unwrap()
            .insert(".", QueryType::DNSKEY, &root_dnskey);
        debug!("prime: cached root DNSKEY");
    }

    let mut primed = 0u16;

    for tld in tlds {
        // Fetch NS referral (includes DS in authority section from root)
        let response = match send_query(tld, QueryType::NS, root_addr).await {
            Ok(r) => r,
            Err(e) => {
                debug!("prime: failed to query NS for .{}: {}", tld, e);
                continue;
            }
        };

        let ns_names = extract_ns_names(&response);
        if ns_names.is_empty() {
            continue;
        }

        {
            let mut cache_w = cache.write().unwrap();
            cache_w.insert(tld, QueryType::NS, &response);
            cache_glue(&mut cache_w, &response, &ns_names);
            // Cache DS records from referral authority section
            cache_ds_from_authority(&mut cache_w, &response);
        }

        // Fetch DNSKEY for this TLD (needed for DNSSEC chain validation)
        let first_ns_name = ns_names.first().map(|s| s.as_str()).unwrap_or("");
        let first_ns = glue_addrs_for(&response, first_ns_name);
        if let Some(ns_addr) = first_ns.first() {
            if let Ok(dnskey_resp) = send_query(tld, QueryType::DNSKEY, *ns_addr).await {
                cache
                    .write()
                    .unwrap()
                    .insert(tld, QueryType::DNSKEY, &dnskey_resp);
            }
        }

        primed += 1;
    }

    info!(
        "primed {}/{} TLD caches (NS + glue + DS + DNSKEY)",
        primed,
        tlds.len()
    );
}

pub async fn resolve_recursive(
    qname: &str,
    qtype: QueryType,
    cache: &RwLock<DnsCache>,
    original_query: &DnsPacket,
    root_hints: &[SocketAddr],
) -> crate::Result<DnsPacket> {
    // No overall timeout — each hop is bounded by NS_QUERY_TIMEOUT (UDP + TCP fallback),
    // and MAX_REFERRAL_DEPTH caps the chain length.
    let mut resp = resolve_iterative(qname, qtype, cache, root_hints, 0, 0).await?;

    resp.header.id = original_query.header.id;
    resp.header.recursion_available = true;
    resp.header.recursion_desired = original_query.header.recursion_desired;
    resp.questions = original_query.questions.clone();
    Ok(resp)
}

pub(crate) fn resolve_iterative<'a>(
    qname: &'a str,
    qtype: QueryType,
    cache: &'a RwLock<DnsCache>,
    root_hints: &'a [SocketAddr],
    referral_depth: u8,
    cname_depth: u8,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::Result<DnsPacket>> + Send + 'a>> {
    Box::pin(async move {
        if referral_depth > MAX_REFERRAL_DEPTH {
            return Err("max referral depth exceeded".into());
        }

        if let Some(cached) = cache.read().unwrap().lookup(qname, qtype) {
            return Ok(cached);
        }

        let (mut current_zone, mut ns_addrs) = find_closest_ns(qname, cache, root_hints);
        let mut ns_idx = 0;

        for _ in 0..MAX_REFERRAL_DEPTH {
            let ns_addr = match ns_addrs.get(ns_idx) {
                Some(addr) => *addr,
                None => return Err("no nameserver available".into()),
            };

            let (q_name, q_type) = minimize_query(qname, qtype, &current_zone);

            debug!(
                "recursive: querying {} for {:?} {} (zone: {}, depth {})",
                ns_addr, q_type, q_name, current_zone, referral_depth
            );

            let response = match send_query(q_name, q_type, ns_addr).await {
                Ok(r) => r,
                Err(e) => {
                    debug!("recursive: NS {} failed: {}", ns_addr, e);
                    ns_idx += 1;
                    continue;
                }
            };

            // Minimized query response — treat as referral, not final answer
            if (q_type != qtype || !q_name.eq_ignore_ascii_case(qname))
                && (!response.authorities.is_empty() || !response.answers.is_empty())
            {
                if let Some(zone) = referral_zone(&response) {
                    current_zone = zone;
                }
                let mut all_ns = extract_ns_from_records(&response.answers);
                if all_ns.is_empty() {
                    all_ns = extract_ns_names(&response);
                }
                let new_addrs = resolve_ns_addrs_from_glue(&response, &all_ns, cache);
                if !new_addrs.is_empty() {
                    ns_addrs = new_addrs;
                    ns_idx = 0;
                    continue;
                }
                ns_idx += 1;
                continue;
            }

            if !response.answers.is_empty() {
                let has_target = response.answers.iter().any(|r| r.query_type() == qtype);

                if has_target || qtype == QueryType::CNAME {
                    cache.write().unwrap().insert(qname, qtype, &response);
                    return Ok(response);
                }

                if let Some(cname_target) = extract_cname_target(&response, qname) {
                    if cname_depth >= MAX_CNAME_DEPTH {
                        return Err("max CNAME depth exceeded".into());
                    }
                    debug!("recursive: chasing CNAME {} -> {}", qname, cname_target);
                    let final_resp = resolve_iterative(
                        &cname_target,
                        qtype,
                        cache,
                        root_hints,
                        0,
                        cname_depth + 1,
                    )
                    .await?;

                    let mut combined = response;
                    combined.answers.extend(final_resp.answers);
                    combined.header.rescode = final_resp.header.rescode;
                    cache.write().unwrap().insert(qname, qtype, &combined);
                    return Ok(combined);
                }

                cache.write().unwrap().insert(qname, qtype, &response);
                return Ok(response);
            }

            if response.header.rescode == ResultCode::NXDOMAIN
                || response.header.rescode == ResultCode::REFUSED
            {
                cache.write().unwrap().insert(qname, qtype, &response);
                return Ok(response);
            }

            // Referral — extract NS + glue, cache glue, resolve NS addresses
            // Update zone for query minimization
            if let Some(zone) = referral_zone(&response) {
                current_zone = zone;
            }
            let ns_names = extract_ns_names(&response);
            if ns_names.is_empty() {
                return Ok(response);
            }

            {
                let mut cache_w = cache.write().unwrap();
                cache_ds_from_authority(&mut cache_w, &response);
            }
            let mut new_ns_addrs = resolve_ns_addrs_from_glue(&response, &ns_names, cache);

            if new_ns_addrs.is_empty() {
                for ns_name in &ns_names {
                    if referral_depth < MAX_REFERRAL_DEPTH {
                        debug!("recursive: resolving glue-less NS {}", ns_name);
                        // Try A first, then AAAA
                        for qt in [QueryType::A, QueryType::AAAA] {
                            if let Ok(ns_resp) = resolve_iterative(
                                ns_name,
                                qt,
                                cache,
                                root_hints,
                                referral_depth + 1,
                                cname_depth,
                            )
                            .await
                            {
                                for rec in &ns_resp.answers {
                                    match rec {
                                        DnsRecord::A { addr, .. } => {
                                            new_ns_addrs.push(dns_addr(*addr));
                                        }
                                        DnsRecord::AAAA { addr, .. } => {
                                            new_ns_addrs.push(dns_addr(*addr));
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            if !new_ns_addrs.is_empty() {
                                break;
                            }
                        }
                    }

                    if !new_ns_addrs.is_empty() {
                        break;
                    }
                }
            }

            if new_ns_addrs.is_empty() {
                return Err(format!("could not resolve any NS for {}", qname).into());
            }

            ns_addrs = new_ns_addrs;
            ns_idx = 0;
        }

        Err(format!("recursive resolution exhausted for {}", qname).into())
    })
}

/// Find the closest cached NS zone and its resolved addresses.
/// Returns (zone_name, ns_addresses). Falls back to (".", root_hints).
fn find_closest_ns(
    qname: &str,
    cache: &RwLock<DnsCache>,
    root_hints: &[SocketAddr],
) -> (String, Vec<SocketAddr>) {
    let guard = cache.read().unwrap();

    let mut pos = 0;
    loop {
        let zone = &qname[pos..];
        if let Some(cached) = guard.lookup(zone, QueryType::NS) {
            let mut addrs = Vec::new();
            let ns_records = if cached
                .answers
                .iter()
                .any(|r| matches!(r, DnsRecord::NS { .. }))
            {
                &cached.answers
            } else {
                &cached.authorities
            };
            for ns_rec in ns_records {
                if let DnsRecord::NS { host, .. } = ns_rec {
                    for qt in [QueryType::A, QueryType::AAAA] {
                        if let Some(resp) = guard.lookup(host, qt) {
                            for rec in &resp.answers {
                                match rec {
                                    DnsRecord::A { addr, .. } => addrs.push(dns_addr(*addr)),
                                    DnsRecord::AAAA { addr, .. } => addrs.push(dns_addr(*addr)),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            if !addrs.is_empty() {
                debug!("recursive: starting from cached NS for zone '{}'", zone);
                return (zone.to_string(), addrs);
            }
        }

        match qname[pos..].find('.') {
            Some(dot) => pos += dot + 1,
            None => break,
        }
    }

    drop(guard);
    debug!(
        "recursive: starting from root hints ({} servers)",
        root_hints.len()
    );
    (".".to_string(), root_hints.to_vec())
}

/// Extract NS hostnames from any record section (answers or authorities).
fn extract_ns_from_records(records: &[DnsRecord]) -> Vec<String> {
    records
        .iter()
        .filter_map(|r| match r {
            DnsRecord::NS { host, .. } => Some(host.clone()),
            _ => None,
        })
        .collect()
}

/// Resolve NS addresses from glue records, then cache fallback.
fn resolve_ns_addrs_from_glue(
    response: &DnsPacket,
    ns_names: &[String],
    cache: &RwLock<DnsCache>,
) -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    {
        let mut cache_w = cache.write().unwrap();
        cache_glue(&mut cache_w, response, ns_names);
    }
    for ns_name in ns_names {
        let glue = glue_addrs_for(response, ns_name);
        if !glue.is_empty() {
            addrs.extend_from_slice(&glue);
            break;
        }
    }
    if addrs.is_empty() {
        for ns_name in ns_names {
            addrs.extend(addrs_from_cache(cache, ns_name));
            if !addrs.is_empty() {
                break;
            }
        }
    }
    addrs
}

fn referral_zone(response: &DnsPacket) -> Option<String> {
    response.authorities.iter().find_map(|r| match r {
        DnsRecord::NS { domain, .. } => Some(domain.clone()),
        _ => None,
    })
}

/// RFC 7816 query minimization (conservative): only minimize at root.
fn minimize_query<'a>(
    qname: &'a str,
    qtype: QueryType,
    current_zone: &str,
) -> (&'a str, QueryType) {
    if current_zone != "." {
        return (qname, qtype);
    }
    // At root: extract TLD (last label)
    match qname.rfind('.') {
        Some(dot) if dot > 0 => (&qname[dot + 1..], QueryType::NS),
        _ => (qname, qtype),
    }
}

fn addrs_from_cache(cache: &RwLock<DnsCache>, name: &str) -> Vec<SocketAddr> {
    let guard = cache.read().unwrap();
    let mut addrs = Vec::new();
    for qt in [QueryType::A, QueryType::AAAA] {
        if let Some(pkt) = guard.lookup(name, qt) {
            for rec in &pkt.answers {
                match rec {
                    DnsRecord::A { addr, .. } => addrs.push(dns_addr(*addr)),
                    DnsRecord::AAAA { addr, .. } => addrs.push(dns_addr(*addr)),
                    _ => {}
                }
            }
        }
    }
    addrs
}

fn glue_addrs_for(response: &DnsPacket, ns_name: &str) -> Vec<SocketAddr> {
    response
        .resources
        .iter()
        .filter_map(|r| match r {
            DnsRecord::A { domain, addr, .. } if domain.eq_ignore_ascii_case(ns_name) => {
                Some(dns_addr(*addr))
            }
            DnsRecord::AAAA { domain, addr, .. } if domain.eq_ignore_ascii_case(ns_name) => {
                Some(dns_addr(*addr))
            }
            _ => None,
        })
        .collect()
}

fn cache_glue(cache: &mut DnsCache, response: &DnsPacket, ns_names: &[String]) {
    for ns_name in ns_names {
        let mut a_pkt: Option<DnsPacket> = None;
        let mut aaaa_pkt: Option<DnsPacket> = None;

        for r in &response.resources {
            match r {
                DnsRecord::A { domain, addr, ttl } if domain.eq_ignore_ascii_case(ns_name) => {
                    a_pkt
                        .get_or_insert_with(make_glue_packet)
                        .answers
                        .push(DnsRecord::A {
                            domain: ns_name.clone(),
                            addr: *addr,
                            ttl: *ttl,
                        });
                }
                DnsRecord::AAAA { domain, addr, ttl } if domain.eq_ignore_ascii_case(ns_name) => {
                    aaaa_pkt
                        .get_or_insert_with(make_glue_packet)
                        .answers
                        .push(DnsRecord::AAAA {
                            domain: ns_name.clone(),
                            addr: *addr,
                            ttl: *ttl,
                        });
                }
                _ => {}
            }
        }

        if let Some(pkt) = a_pkt {
            cache.insert(ns_name, QueryType::A, &pkt);
        }
        if let Some(pkt) = aaaa_pkt {
            cache.insert(ns_name, QueryType::AAAA, &pkt);
        }
    }
}

/// Cache DS + DS-covering RRSIG records from referral authority sections.
fn cache_ds_from_authority(cache: &mut DnsCache, response: &DnsPacket) {
    let mut ds_by_domain: Vec<(String, DnsPacket)> = Vec::new();

    for r in &response.authorities {
        match r {
            DnsRecord::DS { domain, .. } => {
                let key = domain.to_lowercase();
                let pkt = match ds_by_domain.iter_mut().find(|(d, _)| *d == key) {
                    Some((_, pkt)) => pkt,
                    None => {
                        ds_by_domain.push((key, make_glue_packet()));
                        &mut ds_by_domain.last_mut().unwrap().1
                    }
                };
                pkt.answers.push(r.clone());
            }
            DnsRecord::RRSIG {
                domain,
                type_covered,
                ..
            } if QueryType::from_num(*type_covered) == QueryType::DS => {
                let key = domain.to_lowercase();
                let pkt = match ds_by_domain.iter_mut().find(|(d, _)| *d == key) {
                    Some((_, pkt)) => pkt,
                    None => {
                        ds_by_domain.push((key, make_glue_packet()));
                        &mut ds_by_domain.last_mut().unwrap().1
                    }
                };
                pkt.answers.push(r.clone());
            }
            _ => {}
        }
    }

    for (domain, pkt) in &ds_by_domain {
        if !pkt.answers.is_empty() {
            cache.insert(domain, QueryType::DS, pkt);
        }
    }
}

fn make_glue_packet() -> DnsPacket {
    let mut pkt = DnsPacket::new();
    pkt.header.response = true;
    pkt.header.rescode = ResultCode::NOERROR;
    pkt
}

async fn send_query(qname: &str, qtype: QueryType, server: SocketAddr) -> crate::Result<DnsPacket> {
    let mut query = DnsPacket::new();
    query.header.id = next_id();
    query.header.recursion_desired = false;
    query
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));
    query.edns = Some(crate::packet::EdnsOpt {
        do_bit: true,
        ..Default::default()
    });

    // Skip IPv6 if the socket can't handle it (bound to 0.0.0.0)
    if server.is_ipv6() {
        return crate::forward::forward_tcp(&query, server, TCP_TIMEOUT).await;
    }

    // If UDP has been detected as blocked, go TCP-first
    if UDP_DISABLED.load(Ordering::Relaxed) {
        return crate::forward::forward_tcp(&query, server, TCP_TIMEOUT).await;
    }

    match forward_udp(&query, server, NS_QUERY_TIMEOUT).await {
        Ok(resp) if resp.header.truncated_message => {
            debug!("send_query: truncated from {}, retrying TCP", server);
            crate::forward::forward_tcp(&query, server, TCP_TIMEOUT).await
        }
        Ok(resp) => {
            // UDP works — reset failure counter
            UDP_FAILURES.store(0, Ordering::Relaxed);
            Ok(resp)
        }
        Err(e) => {
            let fails = UDP_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
            if fails >= UDP_FAIL_THRESHOLD && !UDP_DISABLED.load(Ordering::Relaxed) {
                UDP_DISABLED.store(true, Ordering::Relaxed);
                info!(
                    "send_query: {} consecutive UDP failures — switching to TCP-first",
                    fails
                );
            }
            debug!("send_query: UDP failed for {}: {}, trying TCP", server, e);
            crate::forward::forward_tcp(&query, server, TCP_TIMEOUT).await
        }
    }
}

fn extract_cname_target(response: &DnsPacket, qname: &str) -> Option<String> {
    response.answers.iter().find_map(|r| match r {
        DnsRecord::CNAME { domain, host, .. } if domain.eq_ignore_ascii_case(qname) => {
            Some(host.clone())
        }
        _ => None,
    })
}

fn extract_ns_names(response: &DnsPacket) -> Vec<String> {
    response
        .authorities
        .iter()
        .filter_map(|r| match r {
            DnsRecord::NS { host, .. } => Some(host.clone()),
            _ => None,
        })
        .collect()
}

pub fn parse_root_hints(hints: &[String]) -> Vec<SocketAddr> {
    hints
        .iter()
        .filter_map(|s| {
            s.parse::<std::net::IpAddr>()
                .map(|ip| SocketAddr::new(ip, 53))
                .map_err(|e| log::warn!("invalid root hint '{}': {}", s, e))
                .ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn extract_ns_from_authority() {
        let mut pkt = DnsPacket::new();
        pkt.authorities.push(DnsRecord::NS {
            domain: "example.com".into(),
            host: "ns1.example.com".into(),
            ttl: 3600,
        });
        pkt.authorities.push(DnsRecord::NS {
            domain: "example.com".into(),
            host: "ns2.example.com".into(),
            ttl: 3600,
        });
        let names = extract_ns_names(&pkt);
        assert_eq!(names, vec!["ns1.example.com", "ns2.example.com"]);
    }

    #[test]
    fn glue_extraction_a() {
        let mut pkt = DnsPacket::new();
        pkt.resources.push(DnsRecord::A {
            domain: "ns1.example.com".into(),
            addr: Ipv4Addr::new(1, 2, 3, 4),
            ttl: 3600,
        });
        let addrs = glue_addrs_for(&pkt, "ns1.example.com");
        assert_eq!(addrs, vec![dns_addr(Ipv4Addr::new(1, 2, 3, 4))]);
        assert!(glue_addrs_for(&pkt, "ns3.example.com").is_empty());
    }

    #[test]
    fn glue_extraction_aaaa() {
        let mut pkt = DnsPacket::new();
        pkt.resources.push(DnsRecord::AAAA {
            domain: "ns1.example.com".into(),
            addr: "2001:db8::1".parse().unwrap(),
            ttl: 3600,
        });
        pkt.resources.push(DnsRecord::A {
            domain: "ns1.example.com".into(),
            addr: Ipv4Addr::new(1, 2, 3, 4),
            ttl: 3600,
        });
        let addrs = glue_addrs_for(&pkt, "ns1.example.com");
        assert_eq!(addrs.len(), 2);
        // AAAA first (order matches resources), then A
        assert_eq!(
            addrs[0],
            dns_addr("2001:db8::1".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(addrs[1], dns_addr(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn cname_extraction() {
        let mut pkt = DnsPacket::new();
        pkt.answers.push(DnsRecord::CNAME {
            domain: "www.example.com".into(),
            host: "example.com".into(),
            ttl: 300,
        });
        assert_eq!(
            extract_cname_target(&pkt, "www.example.com"),
            Some("example.com".into())
        );
        assert_eq!(extract_cname_target(&pkt, "other.com"), None);
    }

    #[test]
    fn parse_root_hints_valid() {
        let hints = vec!["198.41.0.4".into(), "199.9.14.201".into()];
        let addrs = parse_root_hints(&hints);
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], dns_addr(Ipv4Addr::new(198, 41, 0, 4)));
    }

    #[test]
    fn parse_root_hints_skips_invalid() {
        let hints = vec![
            "198.41.0.4".into(),
            "not-an-ip".into(),
            "192.33.4.12".into(),
        ];
        let addrs = parse_root_hints(&hints);
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn find_closest_ns_falls_back_to_hints() {
        let cache = RwLock::new(DnsCache::new(100, 60, 86400));
        let hints = vec![
            dns_addr(Ipv4Addr::new(198, 41, 0, 4)),
            dns_addr(Ipv4Addr::new(199, 9, 14, 201)),
        ];
        let (zone, addrs) = find_closest_ns("example.com", &cache, &hints);
        assert_eq!(zone, ".");
        assert_eq!(addrs, hints);
    }

    #[test]
    fn find_closest_ns_uses_authority_ns_records() {
        // Simulate what TLD priming does: cache a referral response where
        // NS records are in authorities (not answers), with glue in resources.
        let cache = RwLock::new(DnsCache::new(100, 60, 86400));
        let hints = vec![dns_addr(Ipv4Addr::new(198, 41, 0, 4))];

        // Build a referral-style response (NS in authorities, glue in resources)
        let mut referral = DnsPacket::new();
        referral.header.response = true;
        referral.authorities.push(DnsRecord::NS {
            domain: "com".into(),
            host: "ns1.com".into(),
            ttl: 3600,
        });
        referral.resources.push(DnsRecord::A {
            domain: "ns1.com".into(),
            addr: Ipv4Addr::new(192, 5, 6, 30),
            ttl: 3600,
        });

        // Cache the referral under "com" NS (same as prime_tld_cache does)
        {
            let mut c = cache.write().unwrap();
            c.insert("com", QueryType::NS, &referral);
            // Cache glue separately (as prime_tld_cache does)
            let mut glue_pkt = DnsPacket::new();
            glue_pkt.header.response = true;
            glue_pkt.answers.push(DnsRecord::A {
                domain: "ns1.com".into(),
                addr: Ipv4Addr::new(192, 5, 6, 30),
                ttl: 3600,
            });
            c.insert("ns1.com", QueryType::A, &glue_pkt);
        }

        // find_closest_ns should find "com" zone from authority NS records
        let (zone, addrs) = find_closest_ns("www.example.com", &cache, &hints);
        assert_eq!(zone, "com");
        assert_eq!(addrs, vec![dns_addr(Ipv4Addr::new(192, 5, 6, 30))]);
    }

    #[test]
    fn minimize_query_from_root() {
        // At root, only reveal TLD
        let (name, qt) = minimize_query("www.example.com", QueryType::A, ".");
        assert_eq!(name, "com");
        assert_eq!(qt, QueryType::NS);
    }

    #[test]
    fn minimize_query_beyond_root_sends_full() {
        // Beyond root, send full query (conservative minimization)
        let (name, qt) = minimize_query("www.example.com", QueryType::A, "com");
        assert_eq!(name, "www.example.com");
        assert_eq!(qt, QueryType::A);

        let (name, qt) = minimize_query("www.example.com", QueryType::A, "example.com");
        assert_eq!(name, "www.example.com");
        assert_eq!(qt, QueryType::A);
    }

    #[test]
    fn minimize_query_single_label() {
        // Single label (e.g., "com") from root — send as-is
        let (name, qt) = minimize_query("com", QueryType::NS, ".");
        assert_eq!(name, "com");
        assert_eq!(qt, QueryType::NS);
    }

    // ---- Mock DNS server (TCP-only) for fallback tests ----

    use crate::buffer::BytePacketBuffer;
    use crate::header::ResultCode;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawn a TCP-only DNS server on localhost. Returns the address.
    /// The handler receives each query and returns a response packet.
    async fn spawn_tcp_dns_server(
        handler: impl Fn(&DnsPacket) -> DnsPacket + Send + Sync + 'static,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = std::sync::Arc::new(handler);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let handler = handler.clone();
                tokio::spawn(async move {
                    // Read length-prefixed DNS query
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut data = vec![0u8; len];
                    if stream.read_exact(&mut data).await.is_err() {
                        return;
                    }

                    let mut buf = BytePacketBuffer::from_bytes(&data);
                    let query = match DnsPacket::from_buffer(&mut buf) {
                        Ok(q) => q,
                        Err(_) => return,
                    };

                    let response = handler(&query);

                    let mut resp_buf = BytePacketBuffer::new();
                    if response.write(&mut resp_buf).is_err() {
                        return;
                    }
                    let resp_bytes = resp_buf.filled();
                    let mut out = Vec::with_capacity(2 + resp_bytes.len());
                    out.extend_from_slice(&(resp_bytes.len() as u16).to_be_bytes());
                    out.extend_from_slice(resp_bytes);
                    let _ = stream.write_all(&out).await;
                });
            }
        });
        addr
    }

    /// TCP-only server returns authoritative answer directly.
    /// Verifies: UDP fails → TCP fallback → resolves.
    #[tokio::test]
    async fn tcp_fallback_resolves_when_udp_blocked() {
        UDP_DISABLED.store(false, Ordering::Relaxed);
        UDP_FAILURES.store(0, Ordering::Relaxed);

        let server_addr = spawn_tcp_dns_server(|query| {
            let mut resp = DnsPacket::response_from(query, ResultCode::NOERROR);
            resp.header.authoritative_answer = true;
            if let Some(q) = query.questions.first() {
                if q.qtype == QueryType::A || q.qtype == QueryType::NS {
                    resp.answers.push(DnsRecord::A {
                        domain: q.name.clone(),
                        addr: Ipv4Addr::new(10, 0, 0, 1),
                        ttl: 300,
                    });
                }
            }
            resp
        })
        .await;

        let result = send_query("test.example.com", QueryType::A, server_addr).await;

        let resp = result.expect("should resolve via TCP fallback");
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert!(!resp.answers.is_empty());
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 1)),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    /// Full iterative resolution through TCP-only mock: root referral → authoritative answer.
    /// The mock plays both roles (returns referral for NS queries, answer for A queries).
    #[tokio::test]
    async fn tcp_only_iterative_resolution() {
        UDP_DISABLED.store(true, Ordering::Relaxed); // Skip UDP entirely for speed

        let server_addr = spawn_tcp_dns_server(|query| {
            let q = match query.questions.first() {
                Some(q) => q,
                None => return DnsPacket::response_from(query, ResultCode::SERVFAIL),
            };

            if q.qtype == QueryType::NS || q.name == "com" {
                // Return referral — NS points back to ourselves (same IP, port 53 in glue
                // won't work, but cache will have our address from root_hints)
                let mut resp = DnsPacket::new();
                resp.header.id = query.header.id;
                resp.header.response = true;
                resp.header.rescode = ResultCode::NOERROR;
                resp.questions = query.questions.clone();
                resp.authorities.push(DnsRecord::NS {
                    domain: "com".into(),
                    host: "ns1.com".into(),
                    ttl: 3600,
                });
                resp
            } else {
                // Return authoritative answer
                let mut resp = DnsPacket::response_from(query, ResultCode::NOERROR);
                resp.header.authoritative_answer = true;
                resp.answers.push(DnsRecord::A {
                    domain: q.name.clone(),
                    addr: Ipv4Addr::new(10, 0, 0, 42),
                    ttl: 300,
                });
                resp
            }
        })
        .await;

        let result = send_query("hello.example.com", QueryType::A, server_addr).await;
        let resp = result.expect("TCP-only send_query should work");
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 42)),
            other => panic!("expected A, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn tcp_fallback_handles_nxdomain() {
        UDP_DISABLED.store(false, Ordering::Relaxed);
        UDP_FAILURES.store(0, Ordering::Relaxed);

        let server_addr = spawn_tcp_dns_server(|query| {
            let mut resp = DnsPacket::response_from(query, ResultCode::NXDOMAIN);
            resp.header.authoritative_answer = true;
            resp
        })
        .await;

        let cache = RwLock::new(DnsCache::new(100, 60, 86400));
        let root_hints = vec![server_addr];

        let result =
            resolve_iterative("nonexistent.test", QueryType::A, &cache, &root_hints, 0, 0).await;

        let resp = result.expect("NXDOMAIN should still return a response");
        assert_eq!(resp.header.rescode, ResultCode::NXDOMAIN);
        assert!(resp.answers.is_empty());
    }

    #[tokio::test]
    async fn udp_auto_disable_resets() {
        UDP_DISABLED.store(true, Ordering::Relaxed);
        UDP_FAILURES.store(5, Ordering::Relaxed);

        reset_udp_state();

        assert!(!UDP_DISABLED.load(Ordering::Relaxed));
        assert_eq!(UDP_FAILURES.load(Ordering::Relaxed), 0);
    }

    /// Test forward_tcp directly — verifies the length-prefixed wire format.
    #[tokio::test]
    async fn forward_tcp_wire_format() {
        let server_addr = spawn_tcp_dns_server(|query| {
            let mut resp = DnsPacket::response_from(query, ResultCode::NOERROR);
            resp.header.authoritative_answer = true;
            if let Some(q) = query.questions.first() {
                resp.answers.push(DnsRecord::A {
                    domain: q.name.clone(),
                    addr: Ipv4Addr::new(1, 2, 3, 4),
                    ttl: 60,
                });
            }
            resp
        })
        .await;

        let mut query = DnsPacket::new();
        query.header.id = 0xBEEF;
        query
            .questions
            .push(DnsQuestion::new("test.com".to_string(), QueryType::A));

        let resp = crate::forward::forward_tcp(&query, server_addr, Duration::from_secs(2))
            .await
            .expect("forward_tcp should succeed");

        assert_eq!(resp.header.id, 0xBEEF);
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert!(!resp.answers.is_empty());
    }

    /// Strict server: reads with a single read() call, rejecting split writes.
    /// Simulates Microsoft Azure DNS behavior that caused the early-eof bug.
    #[tokio::test]
    async fn forward_tcp_single_segment_write() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Single read — if length prefix arrives separately, this gets
            // only 2 bytes and the parse fails (simulating the Microsoft bug).
            let mut buf = vec![0u8; 4096];
            let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                .await
                .unwrap();

            assert!(
                n >= 2 + 12, // length prefix + DNS header minimum
                "got only {} bytes in first read — split write bug",
                n
            );

            let msg_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            assert_eq!(msg_len, n - 2, "length prefix doesn't match payload");

            // Parse and respond
            let mut pkt_buf = BytePacketBuffer::from_bytes(&buf[2..n]);
            let query = DnsPacket::from_buffer(&mut pkt_buf).unwrap();

            let mut resp = DnsPacket::response_from(&query, ResultCode::NOERROR);
            resp.answers.push(DnsRecord::A {
                domain: query.questions[0].name.clone(),
                addr: Ipv4Addr::new(5, 6, 7, 8),
                ttl: 60,
            });

            let mut resp_buf = BytePacketBuffer::new();
            resp.write(&mut resp_buf).unwrap();
            let resp_bytes = resp_buf.filled();

            let mut out = Vec::with_capacity(2 + resp_bytes.len());
            out.extend_from_slice(&(resp_bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(resp_bytes);
            tokio::io::AsyncWriteExt::write_all(&mut stream, &out)
                .await
                .unwrap();
        });

        let mut query = DnsPacket::new();
        query.header.id = 0xCAFE;
        query
            .questions
            .push(DnsQuestion::new("strict.test".to_string(), QueryType::A));

        let resp = crate::forward::forward_tcp(&query, addr, Duration::from_secs(2))
            .await
            .expect("forward_tcp must send length+message in single segment");

        assert_eq!(resp.header.id, 0xCAFE);
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::new(5, 6, 7, 8)),
            other => panic!("expected A, got {:?}", other),
        }
    }
}
