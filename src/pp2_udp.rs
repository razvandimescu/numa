//! PROXY protocol v2 — slice-flavored parser for the UDP listener.
//!
//! The TCP path in [`crate::pp2`] wraps a stream and consumes the header
//! before handing bytes to the DNS layer. UDP has no stream — each datagram
//! is independent and carries its own PROXY header up front when the
//! sender (e.g. dnsdist with `useProxyProtocol=true`) is configured to do
//! so. This module parses that prefix from a single buffer and reports
//! how many bytes to skip before the DNS message starts.
//!
//! The trust gate, allowlist semantics, and stats counters are shared
//! with the TCP path: an empty `from` allowlist disables the feature on
//! this listener; a non-empty allowlist puts the listener in
//! PROXY-required mode for permitted senders.
//!
//! ## EDNS0 buffer math
//!
//! A PROXY v2 IPv4 address block consumes 28 bytes; IPv6 consumes 52.
//! Operators running PROXY-on-UDP get correspondingly fewer DNS payload
//! bytes per datagram before truncation kicks in. dnsdist already accounts
//! for this in its own MTU calculations, but operators sizing custom EDNS0
//! buffers should subtract the header bytes from the available budget.

use std::net::SocketAddr;
use std::sync::Arc;

use log::debug;
use proxy_header::{ParseConfig, ProxyHeader};

use crate::ctx::ServerCtx;
use crate::pp2::PpConfig;

/// Outcome of inspecting an inbound UDP datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum UdpPp {
    /// Pass the datagram through unmodified — feature disabled on this
    /// listener.
    Bare,
    /// Trusted sender prepended a valid PROXY v2 header. Use `src` as the
    /// real client and skip the first `hdr_len` bytes of the buffer.
    Proxied { src: SocketAddr, hdr_len: usize },
    /// Drop the datagram silently. Either the peer is not on the
    /// allowlist, or the header was malformed.
    Drop,
}

/// Inspect the front of a UDP datagram for a PROXY v2 header.
///
/// Returns [`UdpPp::Bare`] when the feature is disabled on this listener
/// (zero overhead — no signature peek). Otherwise enforces the same
/// allowlist + signature-validity rules as the TCP handshake. Stats are
/// recorded as a side effect.
pub fn parse_if_trusted(
    bytes: &[u8],
    peer: SocketAddr,
    pp: Option<&PpConfig>,
    ctx: &Arc<ServerCtx>,
) -> UdpPp {
    let pp = match pp {
        Some(p) => p,
        None => return UdpPp::Bare,
    };

    if !pp.from.iter().any(|n| n.contains(&peer.ip())) {
        ctx.stats.lock().unwrap().proxy_v2_rejected_untrusted += 1;
        debug!("pp2_udp: untrusted peer {peer}, dropping");
        return UdpPp::Drop;
    }

    let parse_cfg = ParseConfig {
        allow_v1: false,
        allow_v2: true,
        include_tlvs: false,
    };

    let (header, hdr_len) = match ProxyHeader::parse(bytes, parse_cfg) {
        Ok(p) => p,
        Err(e) => {
            ctx.stats.lock().unwrap().proxy_v2_rejected_signature += 1;
            debug!("pp2_udp parse from {peer}: {e}");
            return UdpPp::Drop;
        }
    };

    match header.proxied_address() {
        Some(addr) => {
            ctx.stats.lock().unwrap().proxy_v2_accepted += 1;
            UdpPp::Proxied {
                src: addr.source,
                hdr_len,
            }
        }
        None => {
            // LOCAL command (sender health probe); use peer as the real
            // client and treat the rest of the datagram as DNS.
            ctx.stats.lock().unwrap().proxy_v2_local_command += 1;
            UdpPp::Proxied { src: peer, hdr_len }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyProtocolConfig;
    use crate::testutil::test_ctx;
    use proxy_header::{ProxiedAddress, ProxyHeader};

    fn pp_cfg(from: &[&str]) -> Arc<PpConfig> {
        let cfg = ProxyProtocolConfig {
            from: from.iter().map(|s| s.to_string()).collect(),
            header_timeout_ms: 5000,
        };
        Arc::new(PpConfig::from_config(&cfg).unwrap().unwrap())
    }

    fn proxied_v4_datagram(client: &str, server: &str, dns_payload: &[u8]) -> Vec<u8> {
        let header = ProxyHeader::with_address(ProxiedAddress::datagram(
            client.parse().unwrap(),
            server.parse().unwrap(),
        ));
        let mut buf = vec![0u8; 256];
        let len = header.encode_to_slice_v2(&mut buf).unwrap();
        buf.truncate(len);
        buf.extend_from_slice(dns_payload);
        buf
    }

    #[tokio::test]
    async fn disabled_returns_bare_without_signature_peek() {
        let ctx = Arc::new(test_ctx().await);
        let datagram = b"\x12\x34\x01\x00\x00\x01\x00\x00";
        let peer: SocketAddr = "8.8.8.8:53".parse().unwrap();
        assert_eq!(parse_if_trusted(datagram, peer, None, &ctx), UdpPp::Bare);
    }

    #[tokio::test]
    async fn untrusted_peer_drops() {
        let ctx = Arc::new(test_ctx().await);
        let pp = pp_cfg(&["10.0.0.0/8"]);
        let dns = b"\x12\x34\x01\x00\x00\x01\x00\x00";
        let datagram = proxied_v4_datagram("203.0.113.5:55000", "10.0.0.1:53", dns);
        let peer: SocketAddr = "8.8.8.8:33333".parse().unwrap();
        assert_eq!(
            parse_if_trusted(&datagram, peer, Some(&pp), &ctx),
            UdpPp::Drop
        );
        assert_eq!(ctx.stats.lock().unwrap().proxy_v2_rejected_untrusted, 1);
    }

    #[tokio::test]
    async fn trusted_peer_with_valid_v4_header_extracts_src_and_offset() {
        let ctx = Arc::new(test_ctx().await);
        let pp = pp_cfg(&["172.16.0.0/12"]);
        let dns = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                    \x07example\x03com\x00\x00\x01\x00\x01";
        let datagram = proxied_v4_datagram("203.0.113.5:55000", "172.29.0.10:53", dns);
        let peer: SocketAddr = "172.29.0.20:44444".parse().unwrap();

        match parse_if_trusted(&datagram, peer, Some(&pp), &ctx) {
            UdpPp::Proxied { src, hdr_len } => {
                assert_eq!(src.to_string(), "203.0.113.5:55000");
                assert_eq!(&datagram[hdr_len..], dns);
            }
            other => panic!("expected Proxied, got {other:?}"),
        }
        assert_eq!(ctx.stats.lock().unwrap().proxy_v2_accepted, 1);
    }

    #[tokio::test]
    async fn trusted_peer_with_garbled_signature_drops() {
        let ctx = Arc::new(test_ctx().await);
        let pp = pp_cfg(&["127.0.0.0/8"]);
        // Looks like a v2 attempt (starts with \r) but truncated/bogus.
        let datagram = b"\r\n\r\n\x00\r\nQUIT\nGARBAGE_PAYLOAD";
        let peer: SocketAddr = "127.0.0.1:55555".parse().unwrap();
        assert_eq!(
            parse_if_trusted(datagram, peer, Some(&pp), &ctx),
            UdpPp::Drop
        );
        assert_eq!(ctx.stats.lock().unwrap().proxy_v2_rejected_signature, 1);
    }

    #[tokio::test]
    async fn trusted_peer_with_bare_dns_drops_in_required_mode() {
        // Same posture as TCP: an enabled allowlist puts the listener in
        // PROXY-required mode for permitted senders. A bare DNS datagram
        // from an allowlisted IP is a misconfigured sender, not a bypass.
        let ctx = Arc::new(test_ctx().await);
        let pp = pp_cfg(&["127.0.0.0/8"]);
        let bare_dns = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                         \x07example\x03com\x00\x00\x01\x00\x01";
        let peer: SocketAddr = "127.0.0.1:55555".parse().unwrap();
        assert_eq!(
            parse_if_trusted(bare_dns, peer, Some(&pp), &ctx),
            UdpPp::Drop
        );
        assert_eq!(ctx.stats.lock().unwrap().proxy_v2_rejected_signature, 1);
    }
}
