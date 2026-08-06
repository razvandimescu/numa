#![no_main]
//! The wire helpers walk raw bytes without `BytePacketBuffer`'s bounds
//! discipline: `scan_ttl_offsets` runs over every upstream reply before it is
//! cached, `ensure_do_bit` over every client query before it is forwarded. Both
//! index slices directly, and the offsets the scan returns are handed to
//! `patch_ttls`, which does not re-check them — a bad offset there is an
//! out-of-bounds write on the cache path, reachable from any upstream reply.
use libfuzzer_sys::fuzz_target;
use numa::wire::{ensure_do_bit, min_ttl_from_wire, patch_ttls, scan_ttl_offsets};

fuzz_target!(|data: &[u8]| {
    if let Ok(meta) = scan_ttl_offsets(data) {
        assert!(meta.answer_count <= meta.ttl_offsets.len());
        for &off in &meta.ttl_offsets {
            // Not `off + 4 <= len`: that sum wraps in release, so the very
            // offset worth catching would slip through the assert.
            assert!(
                data.len().checked_sub(off).is_some_and(|rest| rest >= 4),
                "scan_ttl_offsets handed patch_ttls a TTL offset past the wire"
            );
        }
        let _ = min_ttl_from_wire(data, &meta);
        patch_ttls(&mut data.to_vec(), &meta.ttl_offsets, 60);
    }

    let patched = ensure_do_bit(data);
    // Uncounted trailing bytes are dropped, so a shorter result is legal — but
    // only from the append path, which ends in the OPT it just wrote. Any other
    // shrink means counted records went missing.
    const APPENDED_OPT: [u8; 11] = [0, 0, 41, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 0];
    assert!(
        patched.len() >= data.len() || patched.ends_with(&APPENDED_OPT),
        "ensure_do_bit dropped bytes without appending an OPT"
    );
    if data.len() >= 12 {
        // ID, flags and QDCOUNT are never ours to touch; only ARCOUNT and the
        // OPT's own DO byte may move.
        assert_eq!(
            &patched[..10],
            &data[..10],
            "ensure_do_bit rewrote the header"
        );
    }
    // An appended OPT the walker cannot find again is one the upstream cannot
    // find either — ARCOUNT and the record it counts must agree.
    assert_eq!(
        &ensure_do_bit(&patched)[..],
        &patched[..],
        "ensure_do_bit is not idempotent"
    );
});
