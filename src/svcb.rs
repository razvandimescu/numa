//! Minimal SVCB/HTTPS (RFC 9460) RDATA parser. Two consumers:
//! `filter_aaaa` strips the whole `ipv6hint` SvcParam (so IPv4-only clients
//! see no v6 hints); rebind protection drops only the *private* addresses
//! from `ipv4hint`/`ipv6hint` (so a public name can't smuggle a private
//! address through a hint).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// SvcParamKey = 4 / 6 (RFC 9460 §14.3.2): `ipv4hint` / `ipv6hint`.
const IPV4_HINT_KEY: u16 = 4;
const IPV6_HINT_KEY: u16 = 6;

/// Skip the SVCB TargetName beginning at `pos`, returning the offset of the
/// first SvcParam. `None` if the name is truncated or uses a compression
/// pointer (forbidden in SVCB RDATA).
fn skip_target_name(rdata: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *rdata.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            return Some(pos);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        pos = pos.checked_add(len)?;
        if pos > rdata.len() {
            return None;
        }
    }
}

fn hint_stride(key: u16) -> Option<usize> {
    match key {
        IPV4_HINT_KEY => Some(4),
        IPV6_HINT_KEY => Some(16),
        _ => None,
    }
}

fn hint_addr(chunk: &[u8]) -> IpAddr {
    match chunk.len() {
        4 => IpAddr::V4(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3])),
        _ => {
            let mut b = [0u8; 16];
            b.copy_from_slice(chunk);
            IpAddr::V6(Ipv6Addr::from(b))
        }
    }
}

/// Concatenated `stride`-byte addresses, keeping only those `is_private`
/// rejects. Order is preserved.
fn filter_hint(value: &[u8], stride: usize, is_private: &impl Fn(IpAddr) -> bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    for chunk in value.chunks_exact(stride) {
        if !is_private(hint_addr(chunk)) {
            out.extend_from_slice(chunk);
        }
    }
    out
}

/// One SvcParam at `pos`: `(key, value, end)`, or `None` if its
/// {u16 key, u16 len, opaque[len]} framing runs past the RDATA.
fn read_param(rdata: &[u8], pos: usize) -> Option<(u16, &[u8], usize)> {
    if pos + 4 > rdata.len() {
        return None;
    }
    let key = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
    let vlen = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
    let end = pos.checked_add(4)?.checked_add(vlen)?;
    if end > rdata.len() {
        return None;
    }
    Some((key, &rdata[pos + 4..end], end))
}

enum Edit {
    Keep,
    /// Replace the value; an empty `Vec` drops the param entirely.
    Rewrite(Vec<u8>),
}

/// Apply `edit` to each SvcParam of an HTTPS/SVCB RDATA blob (RFC 9460 §2.2:
/// priority, uncompressed target name, then key-sorted params). `None` when
/// nothing changed, the RDATA is unparseable, or `edit` rejects a malformed
/// param — so the caller keeps the original bytes. The first pass validates
/// framing and skips the allocation entirely when no param is rewritten.
fn edit_svcparams(rdata: &[u8], edit: impl Fn(u16, &[u8]) -> Option<Edit>) -> Option<Vec<u8>> {
    if rdata.len() < 2 {
        return None;
    }
    let params_start = skip_target_name(rdata, 2)?;

    let mut pos = params_start;
    let mut changed = false;
    while pos < rdata.len() {
        let (key, value, end) = read_param(rdata, pos)?;
        if !matches!(edit(key, value)?, Edit::Keep) {
            changed = true;
        }
        pos = end;
    }
    if !changed {
        return None;
    }

    let mut out = Vec::with_capacity(rdata.len());
    out.extend_from_slice(&rdata[..params_start]);
    let mut pos = params_start;
    while pos < rdata.len() {
        let (key, value, end) = read_param(rdata, pos)?;
        match edit(key, value)? {
            Edit::Keep => out.extend_from_slice(&rdata[pos..end]),
            Edit::Rewrite(v) if !v.is_empty() => {
                out.extend_from_slice(&key.to_be_bytes());
                out.extend_from_slice(&(v.len() as u16).to_be_bytes());
                out.extend_from_slice(&v);
            }
            Edit::Rewrite(_) => {}
        }
        pos = end;
    }
    Some(out)
}

/// Strip private address values from `ipv4hint`/`ipv6hint` SvcParams, keeping
/// public ones. A hint left empty is dropped entirely; all other SvcParams
/// (alpn, port, ech, …) are preserved untouched. `is_private` receives the
/// address as-is — callers that canonicalize v4-mapped IPv6 (e.g.
/// `CidrMatcher`) catch `::ffff:10.0.0.1` via their v4 ranges.
///
/// Returns `Some(new_rdata)` if any private value was removed, `None` if
/// nothing changed or the RDATA couldn't be parsed (caller keeps the
/// original bytes).
pub fn strip_private_hints(rdata: &[u8], is_private: impl Fn(IpAddr) -> bool) -> Option<Vec<u8>> {
    edit_svcparams(rdata, |key, value| match hint_stride(key) {
        Some(stride) => {
            if !value.len().is_multiple_of(stride) {
                return None;
            }
            let kept = filter_hint(value, stride, &is_private);
            Some(if kept.len() == value.len() {
                Edit::Keep
            } else {
                Edit::Rewrite(kept)
            })
        }
        None => Some(Edit::Keep),
    })
}

/// Strip the `ipv6hint` SvcParam from an HTTPS/SVCB RDATA blob.
///
/// Returns `Some(new_rdata)` if `ipv6hint` was present and removed, `None` if
/// the record had no `ipv6hint` or the RDATA couldn't be parsed — in both
/// cases the caller keeps the original bytes untouched.
pub fn strip_ipv6hint(rdata: &[u8]) -> Option<Vec<u8>> {
    edit_svcparams(rdata, |key, _| {
        Some(if key == IPV6_HINT_KEY {
            Edit::Rewrite(Vec::new())
        } else {
            Edit::Keep
        })
    })
}

/// Build an SVCB RDATA blob from a priority, target labels, and
/// (key, value) param pairs. Shared by `svcb` unit tests and `ctx`
/// pipeline tests that need to seed the cache with a synthetic HTTPS RR.
#[cfg(test)]
pub(crate) fn build_rdata(priority: u16, target: &[&str], params: &[(u16, Vec<u8>)]) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let rdata = build_rdata(1, &[], &[alpn_h3(), ipv4hint_single(), ipv6hint_single()]);
        let stripped = strip_ipv6hint(&rdata).expect("ipv6hint present → stripped");
        let expected = build_rdata(1, &[], &[alpn_h3(), ipv4hint_single()]);
        assert_eq!(stripped, expected);
    }

    #[test]
    fn no_ipv6hint_returns_none() {
        let rdata = build_rdata(1, &[], &[alpn_h3(), ipv4hint_single()]);
        assert!(strip_ipv6hint(&rdata).is_none());
    }

    #[test]
    fn alias_mode_empty_params_returns_none() {
        let rdata = build_rdata(0, &["example", "com"], &[]);
        assert!(strip_ipv6hint(&rdata).is_none());
    }

    #[test]
    fn only_ipv6hint_yields_empty_param_section() {
        let rdata = build_rdata(1, &[], &[ipv6hint_single()]);
        let stripped = strip_ipv6hint(&rdata).expect("ipv6hint present → stripped");
        let expected = build_rdata(1, &[], &[]);
        assert_eq!(stripped, expected);
    }

    #[test]
    fn preserves_target_name() {
        let rdata = build_rdata(1, &["svc", "example", "net"], &[ipv6hint_single()]);
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

    fn is_priv(ip: std::net::IpAddr) -> bool {
        match ip.to_canonical() {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                o[0] == 10 || (o[0] == 192 && o[1] == 168)
            }
            std::net::IpAddr::V6(v6) => v6.segments()[0] & 0xfe00 == 0xfc00, // fc00::/7
        }
    }

    fn ipv4hint(addrs: &[[u8; 4]]) -> (u16, Vec<u8>) {
        (4, addrs.concat())
    }

    fn ipv6hint(addrs: &[[u8; 16]]) -> (u16, Vec<u8>) {
        (6, addrs.concat())
    }

    const PUB4: [u8; 4] = [93, 184, 216, 34];
    const PRIV4: [u8; 4] = [192, 168, 1, 1];
    const PUB6: [u8; 16] = [0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // 2606:4700::1
    const ULA6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // fd00::1

    #[test]
    fn private_hints_keeps_public_drops_private() {
        let rdata = build_rdata(1, &[], &[alpn_h3(), ipv4hint(&[PUB4, PRIV4])]);
        let out = strip_private_hints(&rdata, is_priv).expect("private hint → rewritten");
        let expected = build_rdata(1, &[], &[alpn_h3(), ipv4hint(&[PUB4])]);
        assert_eq!(out, expected);
    }

    #[test]
    fn private_hints_drops_emptied_param_but_keeps_alpn() {
        let rdata = build_rdata(1, &[], &[alpn_h3(), ipv4hint(&[PRIV4])]);
        let out = strip_private_hints(&rdata, is_priv).expect("all-private hint → param dropped");
        let expected = build_rdata(1, &[], &[alpn_h3()]);
        assert_eq!(out, expected);
    }

    #[test]
    fn private_hints_filters_ipv6() {
        let rdata = build_rdata(1, &[], &[ipv6hint(&[PUB6, ULA6])]);
        let out = strip_private_hints(&rdata, is_priv).expect("ULA hint → rewritten");
        let expected = build_rdata(1, &[], &[ipv6hint(&[PUB6])]);
        assert_eq!(out, expected);
    }

    #[test]
    fn private_hints_all_public_returns_none() {
        let rdata = build_rdata(1, &[], &[alpn_h3(), ipv4hint(&[PUB4]), ipv6hint(&[PUB6])]);
        assert!(strip_private_hints(&rdata, is_priv).is_none());
    }

    #[test]
    fn private_hints_malformed_ipv4hint_returns_none() {
        // ipv4hint value length 5 is not a multiple of 4.
        let rdata = build_rdata(1, &[], &[(4, vec![1, 2, 3, 4, 5])]);
        assert!(strip_private_hints(&rdata, is_priv).is_none());
    }
}
