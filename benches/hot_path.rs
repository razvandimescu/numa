use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::net::Ipv4Addr;

use numa::buffer::BytePacketBuffer;
use numa::cache::DnsCache;
use numa::header::ResultCode;
use numa::packet::DnsPacket;
use numa::question::{DnsQuestion, QueryType};
use numa::record::DnsRecord;

fn make_response(domain: &str) -> DnsPacket {
    let mut pkt = DnsPacket::new();
    pkt.header.id = 0x1234;
    pkt.header.response = true;
    pkt.header.recursion_desired = true;
    pkt.header.recursion_available = true;
    pkt.header.rescode = ResultCode::NOERROR;
    pkt.questions
        .push(DnsQuestion::new(domain.to_string(), QueryType::A));
    pkt.answers.push(DnsRecord::A {
        domain: domain.to_string(),
        addr: Ipv4Addr::new(93, 184, 216, 34),
        ttl: 300,
    });
    // Typical response includes authority + additional records
    pkt.authorities.push(DnsRecord::NS {
        domain: domain.to_string(),
        host: format!("ns1.{domain}"),
        ttl: 172800,
    });
    pkt.authorities.push(DnsRecord::NS {
        domain: domain.to_string(),
        host: format!("ns2.{domain}"),
        ttl: 172800,
    });
    pkt.resources.push(DnsRecord::A {
        domain: format!("ns1.{domain}"),
        addr: Ipv4Addr::new(198, 51, 100, 1),
        ttl: 172800,
    });
    pkt
}

fn to_wire(pkt: &DnsPacket) -> Vec<u8> {
    let mut buf = BytePacketBuffer::new();
    pkt.write(&mut buf).unwrap();
    buf.filled().to_vec()
}

fn bench_buffer_parse(c: &mut Criterion) {
    let pkt = make_response("example.com");
    let wire = to_wire(&pkt);

    c.bench_function("buffer_parse", |b| {
        b.iter(|| {
            let mut buf = BytePacketBuffer::from_bytes(black_box(&wire));
            DnsPacket::from_buffer(&mut buf).unwrap()
        })
    });
}

fn bench_buffer_serialize(c: &mut Criterion) {
    let pkt = make_response("example.com");

    c.bench_function("buffer_serialize", |b| {
        b.iter(|| {
            let mut buf = BytePacketBuffer::new();
            black_box(&pkt).write(&mut buf).unwrap();
            black_box(buf.pos());
        })
    });
}

fn bench_packet_clone(c: &mut Criterion) {
    let pkt = make_response("example.com");

    c.bench_function("packet_clone", |b| b.iter(|| black_box(&pkt).clone()));
}

fn bench_cache_lookup_hit(c: &mut Criterion) {
    let mut cache = DnsCache::new(10_000, 60, 86400);
    let pkt = make_response("example.com");
    cache.insert("example.com", QueryType::A, &pkt);

    c.bench_function("cache_lookup_hit", |b| {
        b.iter(|| {
            cache
                .lookup(black_box("example.com"), QueryType::A)
                .unwrap()
        })
    });
}

fn bench_cache_lookup_miss(c: &mut Criterion) {
    let cache = DnsCache::new(10_000, 60, 86400);

    c.bench_function("cache_lookup_miss", |b| {
        b.iter(|| cache.lookup(black_box("nonexistent.com"), QueryType::A))
    });
}

fn bench_cache_insert(c: &mut Criterion) {
    let pkt = make_response("example.com");

    c.bench_function("cache_insert", |b| {
        let mut cache = DnsCache::new(10_000, 60, 86400);
        let mut i = 0u64;
        b.iter(|| {
            let domain = format!("bench-{i}.example.com");
            cache.insert(&domain, QueryType::A, black_box(&pkt));
            i += 1;
            // Reset cache periodically to avoid filling up
            if i % 5000 == 0 {
                cache.clear();
            }
        })
    });
}

fn bench_round_trip(c: &mut Criterion) {
    // Simulates the cached hot path: parse query → cache hit → serialize response
    let query_pkt = {
        let mut q = DnsPacket::new();
        q.header.id = 0xABCD;
        q.header.recursion_desired = true;
        q.questions
            .push(DnsQuestion::new("example.com".to_string(), QueryType::A));
        q
    };
    let query_wire = to_wire(&query_pkt);

    let response = make_response("example.com");
    let mut cache = DnsCache::new(10_000, 60, 86400);
    cache.insert("example.com", QueryType::A, &response);

    c.bench_function("round_trip_cached", |b| {
        b.iter(|| {
            // 1. Parse incoming query
            let mut buf = BytePacketBuffer::from_bytes(black_box(&query_wire));
            let query = DnsPacket::from_buffer(&mut buf).unwrap();
            let qname = &query.questions[0].name;
            let qtype = query.questions[0].qtype;

            // 2. Cache lookup
            let mut resp = cache.lookup(qname, qtype).unwrap();
            resp.header.id = query.header.id;

            // 3. Serialize response
            let mut resp_buf = BytePacketBuffer::new();
            resp.write(&mut resp_buf).unwrap();
            black_box(resp_buf.pos());
        })
    });
}

fn bench_cache_populated_lookup(c: &mut Criterion) {
    // Benchmark with a realistically populated cache (1000 entries)
    let mut cache = DnsCache::new(10_000, 60, 86400);
    for i in 0..1000 {
        let domain = format!("domain-{i}.example.com");
        let pkt = make_response(&domain);
        cache.insert(&domain, QueryType::A, &pkt);
    }

    c.bench_function("cache_lookup_hit_populated", |b| {
        b.iter(|| {
            cache
                .lookup(black_box("domain-500.example.com"), QueryType::A)
                .unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_buffer_parse,
    bench_buffer_serialize,
    bench_packet_clone,
    bench_cache_lookup_hit,
    bench_cache_lookup_miss,
    bench_cache_insert,
    bench_round_trip,
    bench_cache_populated_lookup,
);
criterion_main!(benches);
