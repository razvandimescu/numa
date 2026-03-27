use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::RwLock;
use std::time::Duration;

use log::{debug, info};
use tokio::time::timeout;

use crate::cache::DnsCache;
use crate::forward::forward_udp;
use crate::header::ResultCode;
use crate::packet::DnsPacket;
use crate::question::{DnsQuestion, QueryType};
use crate::record::DnsRecord;

const MAX_REFERRAL_DEPTH: u8 = 10;
const MAX_CNAME_DEPTH: u8 = 8;
const NS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

static QUERY_ID: AtomicU16 = AtomicU16::new(1);

fn next_id() -> u16 {
    QUERY_ID.fetch_add(1, Ordering::Relaxed)
}

fn dns_addr(ip: impl Into<IpAddr>) -> SocketAddr {
    SocketAddr::new(ip.into(), 53)
}

/// Query root servers for common TLDs and cache NS + glue + DNSKEY + DS records.
/// Pre-warms the DNSSEC trust chain so first queries skip chain-walking I/O.
pub async fn prime_tld_cache(cache: &RwLock<DnsCache>, root_hints: &[SocketAddr], tlds: &[String]) {
    let root_addr = match root_hints.first() {
        Some(addr) => *addr,
        None => return,
    };
    if tlds.is_empty() {
        return;
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
    overall_timeout: Duration,
    original_query: &DnsPacket,
    root_hints: &[SocketAddr],
) -> crate::Result<DnsPacket> {
    let mut resp = match timeout(
        overall_timeout,
        resolve_iterative(qname, qtype, cache, root_hints, 0, 0),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => return Err(format!("recursive resolution timed out for {}", qname).into()),
    };

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

        let mut ns_addrs = find_starting_ns(qname, cache, root_hints);
        let mut ns_idx = 0;

        for _ in 0..MAX_REFERRAL_DEPTH {
            let ns_addr = match ns_addrs.get(ns_idx) {
                Some(addr) => *addr,
                None => return Err("no nameserver available".into()),
            };

            debug!(
                "recursive: querying {} for {:?} {} (depth {})",
                ns_addr, qtype, qname, referral_depth
            );

            let response = match send_query(qname, qtype, ns_addr).await {
                Ok(r) => r,
                Err(e) => {
                    debug!("recursive: NS {} failed: {}", ns_addr, e);
                    ns_idx += 1;
                    continue;
                }
            };

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
            let ns_names = extract_ns_names(&response);
            if ns_names.is_empty() {
                return Ok(response);
            }

            // Cache glue + DS from referral (avoids separate fetch during DNSSEC validation)
            let mut new_ns_addrs = Vec::new();
            {
                let mut cache_w = cache.write().unwrap();
                cache_glue(&mut cache_w, &response, &ns_names);
                cache_ds_from_authority(&mut cache_w, &response);
            }
            for ns_name in &ns_names {
                let glue = glue_addrs_for(&response, ns_name);
                if !glue.is_empty() {
                    new_ns_addrs.extend_from_slice(&glue);
                    break;
                }
            }

            // If no glue, try cache (A then AAAA) then recursive resolve
            if new_ns_addrs.is_empty() {
                for ns_name in &ns_names {
                    new_ns_addrs.extend(addrs_from_cache(cache, ns_name));

                    if new_ns_addrs.is_empty() && referral_depth < MAX_REFERRAL_DEPTH {
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

fn find_starting_ns(
    qname: &str,
    cache: &RwLock<DnsCache>,
    root_hints: &[SocketAddr],
) -> Vec<SocketAddr> {
    let guard = cache.read().unwrap();

    let mut pos = 0;
    loop {
        let zone = &qname[pos..];
        if let Some(cached) = guard.lookup(zone, QueryType::NS) {
            let mut addrs = Vec::new();
            for ns_rec in &cached.answers {
                if let DnsRecord::NS { host, .. } = ns_rec {
                    for qt in [QueryType::A, QueryType::AAAA] {
                        if let Some(resp) = guard.lookup(host, qt) {
                            for rec in &resp.answers {
                                match rec {
                                    DnsRecord::A { addr, .. } => {
                                        addrs.push(dns_addr(*addr));
                                    }
                                    DnsRecord::AAAA { addr, .. } => {
                                        addrs.push(dns_addr(*addr));
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            if !addrs.is_empty() {
                debug!("recursive: starting from cached NS for zone '{}'", zone);
                return addrs;
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
    root_hints.to_vec()
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
    forward_udp(&query, server, NS_QUERY_TIMEOUT).await
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
    fn find_starting_ns_falls_back_to_hints() {
        let cache = RwLock::new(DnsCache::new(100, 60, 86400));
        let hints = vec![
            dns_addr(Ipv4Addr::new(198, 41, 0, 4)),
            dns_addr(Ipv4Addr::new(199, 9, 14, 201)),
        ];
        let addrs = find_starting_ns("example.com", &cache, &hints);
        assert_eq!(addrs, hints);
    }
}
