use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use log::{debug, info};

use crate::cache::DnsCache;
use crate::forward::forward_udp;
use crate::header::ResultCode;
use crate::packet::DnsPacket;
use crate::question::QueryType;
use crate::record::DnsRecord;
use crate::srtt::SrttCache;

const MAX_REFERRAL_DEPTH: u8 = 10;
const MAX_CNAME_DEPTH: u8 = 8;
const NS_QUERY_TIMEOUT: Duration = Duration::from_millis(400);
const TCP_TIMEOUT: Duration = Duration::from_millis(400);
const UDP_FAIL_THRESHOLD: u8 = 3;

static QUERY_ID: AtomicU16 = AtomicU16::new(1);
static UDP_FAILURES: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
pub(crate) static UDP_DISABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn next_id() -> u16 {
    QUERY_ID.fetch_add(1, Ordering::Relaxed)
}

fn dns_addr(ip: impl Into<IpAddr>) -> SocketAddr {
    SocketAddr::new(ip.into(), 53)
}

fn record_to_addr(rec: &DnsRecord) -> Option<SocketAddr> {
    match rec {
        DnsRecord::A { addr, .. } => Some(dns_addr(*addr)),
        DnsRecord::AAAA { addr, .. } => Some(dns_addr(*addr)),
        _ => None,
    }
}

pub fn reset_udp_state() {
    UDP_DISABLED.store(false, Ordering::Release);
    UDP_FAILURES.store(0, Ordering::Release);
}

/// Probe whether UDP works again. Called periodically from the network watch loop.
pub async fn probe_udp(root_hints: &[SocketAddr]) {
    if !UDP_DISABLED.load(Ordering::Acquire) {
        return;
    }
    let hint = match root_hints.first() {
        Some(h) => *h,
        None => return,
    };
    let mut probe = DnsPacket::query(next_id(), ".", QueryType::NS);
    probe.header.recursion_desired = false;
    if forward_udp(&probe, hint, Duration::from_millis(1500))
        .await
        .is_ok()
    {
        info!("UDP probe succeeded — re-enabling UDP");
        reset_udp_state();
    }
}

/// Probe whether recursive resolution works by querying root servers.
/// Tries up to 3 hints before declaring failure.
pub async fn probe_recursive(root_hints: &[SocketAddr]) -> bool {
    let mut probe = DnsPacket::query(next_id(), ".", QueryType::NS);
    probe.header.recursion_desired = false;
    for hint in root_hints.iter().take(3) {
        if let Ok(resp) = forward_udp(&probe, *hint, Duration::from_secs(3)).await {
            if !resp.answers.is_empty() || !resp.authorities.is_empty() {
                return true;
            }
        }
    }
    false
}

pub async fn prime_tld_cache(
    cache: &RwLock<DnsCache>,
    root_hints: &[SocketAddr],
    tlds: &[String],
    srtt: &RwLock<SrttCache>,
) {
    if root_hints.is_empty() || tlds.is_empty() {
        return;
    }

    let mut root_addr = root_hints[0];
    for hint in root_hints {
        info!("prime: probing root {}", hint);
        match send_query(".", QueryType::NS, *hint, srtt).await {
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
    if let Ok(root_dnskey) = send_query(".", QueryType::DNSKEY, root_addr, srtt).await {
        cache
            .write()
            .unwrap()
            .insert(".", QueryType::DNSKEY, &root_dnskey);
        debug!("prime: cached root DNSKEY");
    }

    let mut primed = 0u16;

    for tld in tlds {
        // Fetch NS referral (includes DS in authority section from root)
        let response = match send_query(tld, QueryType::NS, root_addr, srtt).await {
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
            cache_ds_from_authority(&mut cache_w, &response);
        }

        // Fetch DNSKEY for this TLD (needed for DNSSEC chain validation)
        let first_ns_name = ns_names.first().map(|s| s.as_str()).unwrap_or("");
        let first_ns = glue_addrs_for(&response, first_ns_name);
        if let Some(ns_addr) = first_ns.first() {
            if let Ok(dnskey_resp) = send_query(tld, QueryType::DNSKEY, *ns_addr, srtt).await {
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
    srtt: &RwLock<SrttCache>,
) -> crate::Result<DnsPacket> {
    // No overall timeout — each hop is bounded by NS_QUERY_TIMEOUT (UDP + TCP fallback),
    // and MAX_REFERRAL_DEPTH caps the chain length.
    let mut resp = resolve_iterative(qname, qtype, cache, root_hints, srtt, 0, 0).await?;

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
    srtt: &'a RwLock<SrttCache>,
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
        srtt.read().unwrap().sort_by_rtt(&mut ns_addrs);
        let mut ns_idx = 0;

        for _ in 0..MAX_REFERRAL_DEPTH {
            if ns_idx >= ns_addrs.len() {
                return Err("no nameserver available".into());
            }

            let (q_name, q_type) = minimize_query(qname, qtype, &current_zone);

            debug!(
                "recursive: querying {} (+ hedge) for {:?} {} (zone: {}, depth {})",
                ns_addrs[ns_idx], q_type, q_name, current_zone, referral_depth
            );

            let response = match send_query_hedged(q_name, q_type, &ns_addrs[ns_idx..], srtt).await
            {
                Ok(r) => r,
                Err(e) => {
                    debug!("recursive: NS query failed: {}", e);
                    let remaining = ns_addrs.len().saturating_sub(ns_idx);
                    ns_idx += remaining.min(2);
                    continue;
                }
            };

            if (q_type != qtype || !q_name.eq_ignore_ascii_case(qname))
                && (!response.authorities.is_empty() || !response.answers.is_empty())
            {
                if let Some(zone) = referral_zone(&response) {
                    current_zone = zone;
                    let mut cache_w = cache.write().unwrap();
                    cache_ns_delegation(&mut cache_w, &current_zone, &response);
                    drop(cache_w);
                }
                let mut all_ns = extract_ns_from_records(&response.answers);
                if all_ns.is_empty() {
                    all_ns = extract_ns_names(&response);
                }
                let mut new_addrs = resolve_ns_addrs_from_glue(&response, &all_ns, cache);
                if !new_addrs.is_empty() {
                    srtt.read().unwrap().sort_by_rtt(&mut new_addrs);
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
                        srtt,
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

            if let Some(zone) = referral_zone(&response) {
                current_zone = zone;
            }
            let ns_names = extract_ns_names(&response);
            if ns_names.is_empty() {
                return Ok(response);
            }

            {
                let mut cache_w = cache.write().unwrap();
                cache_ns_delegation(&mut cache_w, &current_zone, &response);
                cache_ds_from_authority(&mut cache_w, &response);
            }
            let mut new_ns_addrs = resolve_ns_addrs_from_glue(&response, &ns_names, cache);

            if new_ns_addrs.is_empty() {
                for ns_name in &ns_names {
                    if referral_depth < MAX_REFERRAL_DEPTH {
                        debug!("recursive: resolving glue-less NS {}", ns_name);
                        for qt in [QueryType::A, QueryType::AAAA] {
                            if let Ok(ns_resp) = resolve_iterative(
                                ns_name,
                                qt,
                                cache,
                                root_hints,
                                srtt,
                                referral_depth + 1,
                                cname_depth,
                            )
                            .await
                            {
                                new_ns_addrs
                                    .extend(ns_resp.answers.iter().filter_map(record_to_addr));
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

            srtt.read().unwrap().sort_by_rtt(&mut new_ns_addrs);
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
                            addrs.extend(resp.answers.iter().filter_map(record_to_addr));
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
        addrs.extend_from_slice(&glue_addrs_for(response, ns_name));
    }
    if addrs.is_empty() {
        for ns_name in ns_names {
            addrs.extend(addrs_from_cache(cache, ns_name));
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
            addrs.extend(pkt.answers.iter().filter_map(record_to_addr));
        }
    }
    addrs
}

fn glue_addrs_for(response: &DnsPacket, ns_name: &str) -> Vec<SocketAddr> {
    response
        .resources
        .iter()
        .filter(|r| match r {
            DnsRecord::A { domain, .. } | DnsRecord::AAAA { domain, .. } => {
                domain.eq_ignore_ascii_case(ns_name)
            }
            _ => false,
        })
        .filter_map(record_to_addr)
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

/// Cache NS delegation records from a referral response so that
/// `find_closest_ns` can skip re-querying TLD servers on subsequent lookups.
fn cache_ns_delegation(cache: &mut DnsCache, zone: &str, response: &DnsPacket) {
    let ns_records: Vec<_> = response
        .authorities
        .iter()
        .filter(|r| matches!(r, DnsRecord::NS { .. }))
        .cloned()
        .collect();
    if ns_records.is_empty() {
        return;
    }
    let mut pkt = make_glue_packet();
    pkt.answers = ns_records;
    cache.insert(zone, QueryType::NS, &pkt);
}

fn make_glue_packet() -> DnsPacket {
    let mut pkt = DnsPacket::new();
    pkt.header.response = true;
    pkt.header.rescode = ResultCode::NOERROR;
    pkt
}

async fn tcp_with_srtt(
    query: &DnsPacket,
    server: SocketAddr,
    srtt: &RwLock<SrttCache>,
    start: Instant,
) -> crate::Result<DnsPacket> {
    match crate::forward::forward_tcp(query, server, TCP_TIMEOUT).await {
        Ok(resp) => {
            srtt.write()
                .unwrap()
                .record_rtt(server.ip(), start.elapsed().as_millis() as u64, true);
            Ok(resp)
        }
        Err(e) => {
            srtt.write().unwrap().record_failure(server.ip());
            Err(e)
        }
    }
}

/// Smart NS query: fire to two servers simultaneously when SRTT is unknown
/// (cold queries), or to the best server with SRTT-based hedge when known.
async fn send_query_hedged(
    qname: &str,
    qtype: QueryType,
    servers: &[SocketAddr],
    srtt: &RwLock<SrttCache>,
) -> crate::Result<DnsPacket> {
    if servers.is_empty() {
        return Err("no nameserver available".into());
    }
    if servers.len() == 1 {
        return send_query(qname, qtype, servers[0], srtt).await;
    }

    let primary = servers[0];
    let secondary = servers[1];
    let primary_known = srtt.read().unwrap().is_known(primary.ip());

    if !primary_known {
        // Cold: fire both simultaneously, first response wins
        debug!(
            "recursive: parallel query to {} and {} for {:?} {}",
            primary, secondary, qtype, qname
        );
        let fut_a = send_query(qname, qtype, primary, srtt);
        let fut_b = send_query(qname, qtype, secondary, srtt);
        tokio::pin!(fut_a);
        tokio::pin!(fut_b);

        // First Ok wins. If one errors, wait for the other.
        let mut a_done = false;
        let mut b_done = false;
        let mut a_err: Option<crate::Error> = None;
        let mut b_err: Option<crate::Error> = None;

        loop {
            tokio::select! {
                r = &mut fut_a, if !a_done => {
                    match r {
                        Ok(resp) => return Ok(resp),
                        Err(e) => { a_done = true; a_err = Some(e); }
                    }
                }
                r = &mut fut_b, if !b_done => {
                    match r {
                        Ok(resp) => return Ok(resp),
                        Err(e) => { b_done = true; b_err = Some(e); }
                    }
                }
            }
            match (a_err.take(), b_err.take()) {
                (Some(e), Some(_)) => return Err(e),
                (a, b) => {
                    a_err = a;
                    b_err = b;
                }
            }
        }
    } else {
        // Warm: send to best, hedge after SRTT × 3 if slow
        let hedge_ms = srtt.read().unwrap().get(primary.ip()) * 3;
        let hedge_delay = Duration::from_millis(hedge_ms.max(50));

        let fut_a = send_query(qname, qtype, primary, srtt);
        tokio::pin!(fut_a);
        let delay = tokio::time::sleep(hedge_delay);
        tokio::pin!(delay);

        tokio::select! {
            r = &mut fut_a => return r,
            _ = &mut delay => {}
        }

        debug!(
            "recursive: hedging {} -> {} after {}ms for {:?} {}",
            primary, secondary, hedge_ms, qtype, qname
        );
        let fut_b = send_query(qname, qtype, secondary, srtt);
        tokio::pin!(fut_b);

        // First Ok wins; if one errors, wait for the other.
        let mut a_err: Option<crate::Error> = None;
        let mut b_err: Option<crate::Error> = None;
        loop {
            tokio::select! {
                r = &mut fut_a, if a_err.is_none() => {
                    match r {
                        Ok(resp) => return Ok(resp),
                        Err(e) => {
                            if b_err.is_some() { return Err(e); }
                            a_err = Some(e);
                        }
                    }
                }
                r = &mut fut_b, if b_err.is_none() => {
                    match r {
                        Ok(resp) => return Ok(resp),
                        Err(e) => {
                            if let Some(ae) = a_err.take() { return Err(ae); }
                            b_err = Some(e);
                        }
                    }
                }
            }
        }
    }
}

async fn send_query(
    qname: &str,
    qtype: QueryType,
    server: SocketAddr,
    srtt: &RwLock<SrttCache>,
) -> crate::Result<DnsPacket> {
    let mut query = DnsPacket::query(next_id(), qname, qtype);
    query.header.recursion_desired = false;
    query.edns = Some(crate::packet::EdnsOpt {
        do_bit: true,
        ..Default::default()
    });

    let start = Instant::now();

    // IPv6 forced to TCP — our UDP socket is bound to 0.0.0.0
    if server.is_ipv6() {
        return tcp_with_srtt(&query, server, srtt, start).await;
    }

    // UDP detected as blocked — go TCP-first
    if UDP_DISABLED.load(Ordering::Acquire) {
        return tcp_with_srtt(&query, server, srtt, start).await;
    }

    match forward_udp(&query, server, NS_QUERY_TIMEOUT).await {
        Ok(resp) if resp.header.truncated_message => {
            debug!("send_query: truncated from {}, retrying TCP", server);
            tcp_with_srtt(&query, server, srtt, start).await
        }
        Ok(resp) => {
            UDP_FAILURES.store(0, Ordering::Release);
            srtt.write().unwrap().record_rtt(
                server.ip(),
                start.elapsed().as_millis() as u64,
                false,
            );
            Ok(resp)
        }
        Err(e) => {
            let fails = UDP_FAILURES.fetch_add(1, Ordering::AcqRel) + 1;
            if fails >= UDP_FAIL_THRESHOLD && !UDP_DISABLED.load(Ordering::Acquire) {
                UDP_DISABLED.store(true, Ordering::Release);
                info!(
                    "send_query: {} consecutive UDP failures — switching to TCP-first",
                    fails
                );
                // Now that UDP is disabled, retry this query via TCP
                return tcp_with_srtt(&query, server, srtt, start).await;
            }
            // UDP works in general (priming succeeded) but this server timed out.
            // Don't waste another 400ms on TCP — the server is unreachable.
            srtt.write().unwrap().record_failure(server.ip());
            Err(e)
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

    /// Tests that mutate the global UDP_DISABLED / UDP_FAILURES flags must hold
    /// this lock to avoid racing with each other under `cargo test` parallelism.
    static UDP_STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
                    let timeout = std::time::Duration::from_secs(5);
                    // Read length-prefixed DNS query
                    let mut len_buf = [0u8; 2];
                    if tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
                        .await
                        .ok()
                        .and_then(|r| r.ok())
                        .is_none()
                    {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut data = vec![0u8; len];
                    if tokio::time::timeout(timeout, stream.read_exact(&mut data))
                        .await
                        .ok()
                        .and_then(|r| r.ok())
                        .is_none()
                    {
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
    /// Verifies: when UDP is disabled, TCP-first resolves.
    #[tokio::test]
    async fn tcp_fallback_resolves_when_udp_blocked() {
        let _guard = UDP_STATE_LOCK.lock().unwrap();
        UDP_DISABLED.store(true, Ordering::Relaxed);
        UDP_FAILURES.store(0, Ordering::Release);

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

        let srtt = RwLock::new(SrttCache::new(true));
        let result = send_query("test.example.com", QueryType::A, server_addr, &srtt).await;

        let resp = result.expect("should resolve via TCP fallback");
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        assert!(!resp.answers.is_empty());
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 1)),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    /// TCP round-trip through mock: query → authoritative answer via forward_tcp.
    /// Uses forward_tcp directly to avoid dependence on the global UDP_DISABLED flag
    /// which is shared across concurrent tests.
    #[tokio::test]
    async fn tcp_only_iterative_resolution() {
        let server_addr = spawn_tcp_dns_server(|query| {
            let q = match query.questions.first() {
                Some(q) => q,
                None => return DnsPacket::response_from(query, ResultCode::SERVFAIL),
            };

            let mut resp = DnsPacket::response_from(query, ResultCode::NOERROR);
            resp.header.authoritative_answer = true;
            resp.answers.push(DnsRecord::A {
                domain: q.name.clone(),
                addr: Ipv4Addr::new(10, 0, 0, 42),
                ttl: 300,
            });
            resp
        })
        .await;

        let query = DnsPacket::query(0x1234, "hello.example.com", QueryType::A);
        let resp = crate::forward::forward_tcp(&query, server_addr, TCP_TIMEOUT)
            .await
            .expect("TCP query should work");
        assert_eq!(resp.header.rescode, ResultCode::NOERROR);
        match &resp.answers[0] {
            DnsRecord::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 42)),
            other => panic!("expected A, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn tcp_fallback_handles_nxdomain() {
        let _guard = UDP_STATE_LOCK.lock().unwrap();
        UDP_DISABLED.store(true, Ordering::Relaxed);
        UDP_FAILURES.store(0, Ordering::Release);

        let server_addr = spawn_tcp_dns_server(|query| {
            let mut resp = DnsPacket::response_from(query, ResultCode::NXDOMAIN);
            resp.header.authoritative_answer = true;
            resp
        })
        .await;

        let cache = RwLock::new(DnsCache::new(100, 60, 86400));
        let srtt = RwLock::new(SrttCache::new(true));
        let root_hints = vec![server_addr];

        let result = resolve_iterative(
            "nonexistent.test",
            QueryType::A,
            &cache,
            &root_hints,
            &srtt,
            0,
            0,
        )
        .await;

        let resp = result.expect("NXDOMAIN should still return a response");
        assert_eq!(resp.header.rescode, ResultCode::NXDOMAIN);
        assert!(resp.answers.is_empty());
    }

    #[tokio::test]
    async fn udp_auto_disable_resets() {
        let _guard = UDP_STATE_LOCK.lock().unwrap();
        UDP_DISABLED.store(true, Ordering::Release);
        UDP_FAILURES.store(5, Ordering::Relaxed);

        reset_udp_state();

        assert!(!UDP_DISABLED.load(Ordering::Acquire));
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

        let query = DnsPacket::query(0xBEEF, "test.com", QueryType::A);

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

        let query = DnsPacket::query(0xCAFE, "strict.test", QueryType::A);

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
