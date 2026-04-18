//! Minimal SVCB/HTTPS (RFC 9460) RDATA parser — just enough to strip
//! the `ipv6hint` SvcParam. Used by the `filter_aaaa` feature so
//! HTTPS-record-aware clients (Chrome ≥103, Firefox, Safari) don't
//! receive v6 address hints on IPv4-only networks.

/// SvcParamKey = 6 (RFC 9460 §14.3.2).
const IPV6_HINT_KEY: u16 = 6;

/// Strip the `ipv6hint` SvcParam from an HTTPS/SVCB RDATA blob.
///
/// Returns `Some(new_rdata)` if `ipv6hint` was present and removed.
/// Returns `None` if the record had no `ipv6hint`, or if the RDATA
/// couldn't be parsed — in both cases the caller should keep the
/// original bytes untouched.
///
/// SVCB RDATA (RFC 9460 §2.2):
///   SvcPriority (u16)
///   TargetName  (uncompressed DNS name — labels terminated by 0 octet)
///   SvcParams   (series of {u16 key, u16 len, opaque[len] value}, sorted by key)
pub fn strip_ipv6hint(rdata: &[u8]) -> Option<Vec<u8>> {
    if rdata.len() < 2 {
        return None;
    }
    let mut pos = 2;

    // TargetName — uncompressed per RFC 9460 §2.2
    loop {
        let len = *rdata.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            // Pointer: forbidden in SVCB but defend against a broken upstream.
            return None;
        }
        pos = pos.checked_add(len)?;
        if pos > rdata.len() {
            return None;
        }
    }

    // Scan params once to decide whether we need to rebuild.
    let params_start = pos;
    let mut scan = pos;
    let mut has_ipv6hint = false;
    while scan < rdata.len() {
        if scan + 4 > rdata.len() {
            return None;
        }
        let key = u16::from_be_bytes([rdata[scan], rdata[scan + 1]]);
        let vlen = u16::from_be_bytes([rdata[scan + 2], rdata[scan + 3]]) as usize;
        let end = scan.checked_add(4)?.checked_add(vlen)?;
        if end > rdata.len() {
            return None;
        }
        if key == IPV6_HINT_KEY {
            has_ipv6hint = true;
        }
        scan = end;
    }
    if scan != rdata.len() || !has_ipv6hint {
        return None;
    }

    // Rebuild without ipv6hint, preserving param order (RFC 9460 requires
    // ascending key order, which we preserve by filtering in place).
    let mut out = Vec::with_capacity(rdata.len());
    out.extend_from_slice(&rdata[..params_start]);
    let mut pos = params_start;
    while pos < rdata.len() {
        let key = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let vlen = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        let end = pos + 4 + vlen;
        if key != IPV6_HINT_KEY {
            out.extend_from_slice(&rdata[pos..end]);
        }
        pos = end;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an SVCB RDATA blob from a priority, target labels, and
    /// (key, value) param pairs. Used for constructing test vectors.
    fn build(priority: u16, target: &[&str], params: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&priority.to_be_bytes());
        for label in target {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        for (key, value) in params {
            out.extend_from_slice(&key.to_be_bytes());
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
        }
        out
    }

    fn alpn_h3() -> (u16, Vec<u8>) {
        // alpn = ["h3"]: one length-prefixed ALPN id
        (1, vec![0x02, b'h', b'3'])
    }

    fn ipv4hint_single() -> (u16, Vec<u8>) {
        (4, vec![93, 184, 216, 34])
    }

    fn ipv6hint_single() -> (u16, Vec<u8>) {
        // 2606:4700::1
        (
            6,
            vec![
                0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ],
        )
    }

    #[test]
    fn strips_ipv6hint_and_keeps_other_params() {
        let rdata = build(1, &[], &[alpn_h3(), ipv4hint_single(), ipv6hint_single()]);
        let stripped = strip_ipv6hint(&rdata).expect("ipv6hint present → stripped");
        let expected = build(1, &[], &[alpn_h3(), ipv4hint_single()]);
        assert_eq!(stripped, expected);
    }

    #[test]
    fn no_ipv6hint_returns_none() {
        let rdata = build(1, &[], &[alpn_h3(), ipv4hint_single()]);
        assert!(strip_ipv6hint(&rdata).is_none());
    }

    #[test]
    fn alias_mode_empty_params_returns_none() {
        let rdata = build(0, &["example", "com"], &[]);
        assert!(strip_ipv6hint(&rdata).is_none());
    }

    #[test]
    fn only_ipv6hint_yields_empty_param_section() {
        let rdata = build(1, &[], &[ipv6hint_single()]);
        let stripped = strip_ipv6hint(&rdata).expect("ipv6hint present → stripped");
        let expected = build(1, &[], &[]);
        assert_eq!(stripped, expected);
    }

    #[test]
    fn preserves_target_name() {
        let rdata = build(1, &["svc", "example", "net"], &[ipv6hint_single()]);
        let stripped = strip_ipv6hint(&rdata).unwrap();
        assert!(stripped.starts_with(&[0x00, 0x01])); // priority
        assert_eq!(&stripped[2..6], b"\x03svc");
    }

    #[test]
    fn truncated_rdata_returns_none() {
        // Priority only, no target terminator.
        assert!(strip_ipv6hint(&[0, 1, 3, b'c', b'o', b'm']).is_none());
    }

    #[test]
    fn empty_input_returns_none() {
        assert!(strip_ipv6hint(&[]).is_none());
    }

    #[test]
    fn param_length_overflow_returns_none() {
        // key=6, length=0xFFFF but value is short — malformed.
        let rdata = vec![0, 1, 0, 0, 6, 0xFF, 0xFF, 0, 1, 2];
        assert!(strip_ipv6hint(&rdata).is_none());
    }
}
