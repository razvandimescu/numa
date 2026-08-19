#![no_main]
//! The wire helpers walk raw bytes without `BytePacketBuffer`'s bounds
//! discipline: `scan_ttl_offsets` runs over every upstream reply before it is
//! cached, `ensure_do_bit` over every client query before it is forwarded. Both
//! index slices directly, and the offsets the scan returns are handed to
//! `patch_ttls`, which does not re-check them — a bad offset there is an
//! out-of-bounds write on the cache path, reachable from any upstream reply.
//! `maximize_payload` patches the same way over every client query bound for a
//! stream upstream, after `ensure_do_bit` — so both orders are exercised here.
use libfuzzer_sys::fuzz_target;
use numa::wire::{
    ensure_do_bit, maximize_payload, min_ttl_from_wire, patch_ttls, scan_ttl_offsets,
    APPENDED_DO_OPT, MAX_UPSTREAM_PAYLOAD,
};

/// The only legal edit is rewriting one OPT payload field to the receive
/// ceiling, in place: same length, same header, at most two adjacent bytes
/// changed, and those bytes now read as the ceiling.
fn assert_maximize_invariants(wire: &[u8]) {
    let maxed = maximize_payload(wire);
    assert_eq!(
        maxed.len(),
        wire.len(),
        "maximize_payload changed the wire's length"
    );
    if wire.len() >= 12 {
        assert_eq!(
            &maxed[..12],
            &wire[..12],
            "maximize_payload rewrote the header"
        );
    }
    let diffs: Vec<usize> = (0..wire.len()).filter(|&i| maxed[i] != wire[i]).collect();
    if let (Some(&first), Some(&last)) = (diffs.first(), diffs.last()) {
        assert!(
            last - first <= 1,
            "maximize_payload touched bytes outside one payload field"
        );
        let ceiling = MAX_UPSTREAM_PAYLOAD.to_be_bytes();
        let pair_at = |p: usize| maxed.get(p..p + 2) == Some(&ceiling[..]);
        assert!(
            pair_at(first) || (first > 0 && pair_at(first - 1)),
            "maximize_payload wrote something other than the receive ceiling"
        );
    }
    assert_eq!(
        &maximize_payload(&maxed)[..],
        &maxed[..],
        "maximize_payload is not idempotent"
    );
}

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
    assert!(
        patched.len() >= data.len() || patched.ends_with(&APPENDED_DO_OPT),
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

    assert_maximize_invariants(data);
    assert_maximize_invariants(&patched);
});
