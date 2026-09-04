use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

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

/// Throwaway RSA-2048 public key and a PKCS#1 v1.5 SHA-256 signature over the
/// 128 zero bytes the verify benches sign. Ring cannot generate RSA keys, so
/// this pair is fixed; the EC algorithms mint a fresh key per run instead.
const RSA_MODULUS_HEX: &str = "a03ab6f62e05b7403092c526e11c879855208882e9b6911a12125c8d225039f54eb6007d8b08ab026c76ac9f8872b0cac48c6063f09a37571f824dc96949c0b5f4c2a46dcbc0d4f509fbf8d5902266f815172ca3788643d190c223dfa8bc3a4e4ae4c1dd7f34d9bfcc157b3139461f0fb0faf90c16dad80d5fb4e18ed7a0bbafce31b2d954b83b86b03f1a40ebef905e7602b6e1d3380e364e0725685a73a284f960cd86766fb64fdc79648bbfcf3ad489b163ba9ba0b6e91f4437a1e864a2e012ae8d2970ba4c12b13dca82f89955fad4b4739cf50d47202a458c0497c97abad4459c043219b186447cef1785accc874ed94cbc3ce3e89d27226adcc60c3257";
const RSA_SIG_HEX: &str = "238ac20f4cfd8abf07d29cce55abd23534d30d627e6e3342a613f3618ad5d178db6b512e4b19343ff422b04c7302e7d27880a073cdf50e2294aaede8d4ad07df8163f417b9072615776ef8e44df2270f1e722951b58b2392070842c705b1f8a5ed3670753fa3de62449d3d1a79b3e5a293597abea5eefa053d9117005d47da6ffc4142891e02debfafadef3097baa0ffe1333664dd12f4c6338e3ec572f813f85a59d9034d51518b8e003924c94e2f3e738b119027844449230c0052ff8be8f2cc3e1a9eacde1966d6838b46f91228426a4e3c0014c7ef01ee2afbd3f95ae707babe0c6f3ac0d8151cfb9e4f53ada1b56ab5f772b44611c56fd9fdc07c9ea8dc";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn real_rsa_key() -> Vec<u8> {
    let mut key = vec![3u8];
    key.extend(&[0x01, 0x00, 0x01]);
    key.extend(unhex(RSA_MODULUS_HEX));
    key
}

fn bench_verify_signature(c: &mut Criterion) {
    // Key material must be valid or the EC paths are rejected at point decode
    // and the numbers measure parsing, not crypto.
    let data = vec![0u8; 128];
    let rng = SystemRandom::new();

    let rsa_key = real_rsa_key();
    let rsa_sig = unhex(RSA_SIG_HEX);

    let ec_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let ec = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, ec_pkcs8.as_ref(), &rng)
        .unwrap();
    let ecdsa_key = ec.public_key().as_ref()[1..].to_vec();
    let ecdsa_sig = ec.sign(&rng, &data).unwrap().as_ref().to_vec();

    let ed_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let ed = Ed25519KeyPair::from_pkcs8(ed_pkcs8.as_ref()).unwrap();
    let ed_key = ed.public_key().as_ref().to_vec();
    let ed_sig = ed.sign(&data).as_ref().to_vec();

    for (algorithm, key, sig, name) in [
        (8u8, &rsa_key, &rsa_sig, "rsa_sha256_2048"),
        (13, &ecdsa_key, &ecdsa_sig, "ecdsa_p256"),
        (15, &ed_key, &ed_sig, "ed25519"),
    ] {
        assert!(
            dnssec::verify_signature(algorithm, key, &data, sig),
            "{name} vector must verify, else the bench times the reject path"
        );
    }

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
