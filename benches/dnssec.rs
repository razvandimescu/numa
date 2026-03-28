use criterion::{black_box, criterion_group, criterion_main, Criterion};

use numa::dnssec;
use numa::question::QueryType;
use numa::record::DnsRecord;

// Realistic ECDSA P-256 key (64 bytes) and signature (64 bytes)
fn make_ecdsa_key() -> Vec<u8> {
    vec![0xAB; 64]
}
fn make_ecdsa_sig() -> Vec<u8> {
    vec![0xCD; 64]
}

// Realistic RSA-2048 key (RFC 3110 format: exp_len=3, exp=65537, mod=256 bytes)
fn make_rsa_key() -> Vec<u8> {
    let mut key = vec![3u8]; // exponent length
    key.extend(&[0x01, 0x00, 0x01]); // exponent = 65537
    key.extend(vec![0xFF; 256]); // modulus (256 bytes = 2048 bits)
    key
}

fn make_ed25519_key() -> Vec<u8> {
    vec![0xEF; 32]
}

fn make_dnskey(algorithm: u8, public_key: Vec<u8>) -> DnsRecord {
    DnsRecord::DNSKEY {
        domain: "example.com".into(),
        flags: 257,
        protocol: 3,
        algorithm,
        public_key,
        ttl: 3600,
    }
}

fn make_rrsig(algorithm: u8, signature: Vec<u8>) -> DnsRecord {
    DnsRecord::RRSIG {
        domain: "example.com".into(),
        type_covered: QueryType::A.to_num(),
        algorithm,
        labels: 2,
        original_ttl: 300,
        expiration: 2000000000,
        inception: 1600000000,
        key_tag: 12345,
        signer_name: "example.com".into(),
        signature,
        ttl: 300,
    }
}

fn make_rrset() -> Vec<DnsRecord> {
    vec![
        DnsRecord::A {
            domain: "example.com".into(),
            addr: "93.184.216.34".parse().unwrap(),
            ttl: 300,
        },
        DnsRecord::A {
            domain: "example.com".into(),
            addr: "93.184.216.35".parse().unwrap(),
            ttl: 300,
        },
    ]
}

fn bench_key_tag(c: &mut Criterion) {
    let key = make_rsa_key();
    c.bench_function("key_tag_rsa2048", |b| {
        b.iter(|| {
            dnssec::compute_key_tag(black_box(257), black_box(3), black_box(8), black_box(&key))
        })
    });

    let key = make_ecdsa_key();
    c.bench_function("key_tag_ecdsa_p256", |b| {
        b.iter(|| {
            dnssec::compute_key_tag(black_box(257), black_box(3), black_box(13), black_box(&key))
        })
    });
}

fn bench_name_to_wire(c: &mut Criterion) {
    c.bench_function("name_to_wire_short", |b| {
        b.iter(|| dnssec::name_to_wire(black_box("example.com")))
    });
    c.bench_function("name_to_wire_long", |b| {
        b.iter(|| dnssec::name_to_wire(black_box("sub.deep.nested.example.co.uk")))
    });
}

fn bench_build_signed_data(c: &mut Criterion) {
    let rrsig = make_rrsig(13, make_ecdsa_sig());
    let rrset = make_rrset();
    let rrset_refs: Vec<&DnsRecord> = rrset.iter().collect();

    c.bench_function("build_signed_data_2_A_records", |b| {
        b.iter(|| dnssec::build_signed_data(black_box(&rrsig), black_box(&rrset_refs)))
    });
}

fn bench_verify_signature(c: &mut Criterion) {
    // These will fail verification (keys/sigs are random), but we measure the
    // crypto overhead — ring still does the full algorithm before returning error.
    let data = vec![0u8; 128]; // typical signed data size

    let rsa_key = make_rsa_key();
    let rsa_sig = vec![0xAA; 256]; // RSA-2048 signature
    c.bench_function("verify_rsa_sha256_2048", |b| {
        b.iter(|| {
            dnssec::verify_signature(
                black_box(8),
                black_box(&rsa_key),
                black_box(&data),
                black_box(&rsa_sig),
            )
        })
    });

    let ecdsa_key = make_ecdsa_key();
    let ecdsa_sig = make_ecdsa_sig();
    c.bench_function("verify_ecdsa_p256", |b| {
        b.iter(|| {
            dnssec::verify_signature(
                black_box(13),
                black_box(&ecdsa_key),
                black_box(&data),
                black_box(&ecdsa_sig),
            )
        })
    });

    let ed_key = make_ed25519_key();
    let ed_sig = vec![0xBB; 64];
    c.bench_function("verify_ed25519", |b| {
        b.iter(|| {
            dnssec::verify_signature(
                black_box(15),
                black_box(&ed_key),
                black_box(&data),
                black_box(&ed_sig),
            )
        })
    });
}

fn bench_ds_verification(c: &mut Criterion) {
    let dk = make_dnskey(8, make_rsa_key());

    // Compute correct DS digest
    let owner_wire = dnssec::name_to_wire("example.com");
    let mut dnskey_rdata = vec![1u8, 1, 3, 8]; // flags=257, proto=3, algo=8
    dnskey_rdata.extend(&make_rsa_key());
    let mut input = Vec::new();
    input.extend(&owner_wire);
    input.extend(&dnskey_rdata);
    let digest = ring::digest::digest(&ring::digest::SHA256, &input);

    let ds = DnsRecord::DS {
        domain: "example.com".into(),
        key_tag: dnssec::compute_key_tag(257, 3, 8, &make_rsa_key()),
        algorithm: 8,
        digest_type: 2,
        digest: digest.as_ref().to_vec(),
        ttl: 86400,
    };

    c.bench_function("verify_ds_sha256", |b| {
        b.iter(|| dnssec::verify_ds(black_box(&ds), black_box(&dk), black_box("example.com")))
    });
}

criterion_group!(
    dnssec_benches,
    bench_key_tag,
    bench_name_to_wire,
    bench_build_signed_data,
    bench_verify_signature,
    bench_ds_verification,
);
criterion_main!(dnssec_benches);
