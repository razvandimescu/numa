use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::net::Ipv4Addr;

use numa::buffer::BytePacketBuffer;
use numa::header::ResultCode;
use numa::packet::DnsPacket;
use numa::question::{DnsQuestion, QueryType};
use numa::record::DnsRecord;

fn make_query_wire(domain: &str) -> Vec<u8> {
    let mut q = DnsPacket::new();
    q.header.id = 0xABCD;
    q.header.recursion_desired = true;
    q.questions
        .push(DnsQuestion::new(domain.to_string(), QueryType::A));
    let mut buf = BytePacketBuffer::new();
    q.write(&mut buf).unwrap();
    buf.filled().to_vec()
}

fn make_response(domain: &str) -> DnsPacket {
    let mut pkt = DnsPacket::new();
    pkt.header.id = 0xABCD;
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
    pkt
}

/// Simulates the complete cached query pipeline (sans network I/O):
/// parse → cache lookup → TTL adjust → serialize response
fn simulate_cached_pipeline(query_wire: &[u8], cache: &numa::cache::DnsCache) -> usize {
    let mut buf = BytePacketBuffer::from_bytes(query_wire);
    let query = DnsPacket::from_buffer(&mut buf).unwrap();
    let q = &query.questions[0];

    let mut resp = cache.lookup(&q.name, q.qtype).unwrap();
    resp.header.id = query.header.id;

    let mut resp_buf = BytePacketBuffer::new();
    resp.write(&mut resp_buf).unwrap();
    resp_buf.pos()
}

fn bench_pipeline_throughput(c: &mut Criterion) {
    let domains: Vec<String> = (0..100)
        .map(|i| format!("domain-{i}.example.com"))
        .collect();

    let mut cache = numa::cache::DnsCache::new(10_000, 60, 86400);
    for d in &domains {
        cache.insert(d, QueryType::A, &make_response(d));
    }

    let query_wires: Vec<Vec<u8>> = domains.iter().map(|d| make_query_wire(d)).collect();

    let mut group = c.benchmark_group("pipeline_throughput");

    for count in [1, 10, 100] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            let mut idx = 0usize;
            b.iter(|| {
                for _ in 0..count {
                    let wire = &query_wires[idx % query_wires.len()];
                    simulate_cached_pipeline(wire, &cache);
                    idx += 1;
                }
            });
        });
    }
    group.finish();
}

/// Measures the overhead of BytePacketBuffer allocation + zero-init
fn bench_buffer_alloc(c: &mut Criterion) {
    c.bench_function("buffer_alloc", |b| {
        b.iter(|| {
            let buf = BytePacketBuffer::new();
            criterion::black_box(buf.pos());
        })
    });
}

criterion_group!(benches, bench_pipeline_throughput, bench_buffer_alloc,);
criterion_main!(benches);
