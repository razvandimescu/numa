//! PROXY v2 slice parser for the UDP listener — datagram counterpart to
//! [`crate::pp2`]'s stream wrapper. Trust gate, allowlist semantics, and
//! stats counters are shared.

use std::net::SocketAddr;
use std::sync::Arc;

use log::debug;
use proxy_header::ProxyHeader;

use crate::ctx::ServerCtx;
use crate::pp2::{PpConfig, PARSE_CFG};

#[derive(Debug, PartialEq, Eq)]
pub enum UdpPp {
    Bare,
    Proxied { src: SocketAddr, hdr_len: usize },
    Drop,
}

impl UdpPp {
    /// Resolve to the (real client, dns-payload length) pair for the recv
    /// loop. On `Proxied`, shifts the DNS payload to offset 0 so the caller
    /// can pass `&buf[..len]` unchanged. Returns `None` to discard.
    pub fn apply(
        self,
        buf: &mut [u8],
        len: usize,
        peer: SocketAddr,
    ) -> Option<(SocketAddr, usize)> {
        match self {
            UdpPp::Bare => Some((peer, len)),
            UdpPp::Proxied { src, hdr_len } => {
                buf.copy_within(hdr_len..len, 0);
                Some((src, len - hdr_len))
            }
            UdpPp::Drop => None,
        }
    }
}

/// Inspect a UDP datagram for a PROXY v2 prefix. Zero-overhead when the
/// feature is disabled (early `Bare` return — no signature peek). Stats
/// are recorded as a side effect.
pub fn parse_if_trusted(
    bytes: &[u8],
    peer: SocketAddr,
    pp: Option<&PpConfig>,
    ctx: &Arc<ServerCtx>,
) -> UdpPp {
    let Some(pp) = pp else { return UdpPp::Bare };

    if !pp.allows(peer.ip()) {
        ctx.stats.lock().unwrap().proxy_v2_rejected_untrusted += 1;
        debug!("pp2_udp: untrusted peer {peer}, dropping");
        return UdpPp::Drop;
    }

    let (header, hdr_len) = match ProxyHeader::parse(bytes, PARSE_CFG) {
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
            // LOCAL command (sender health probe): use peer as the real
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

    #[tokio::test]
    async fn apply_bare_passes_through() {
        let mut buf = *b"hello-world";
        let peer: SocketAddr = "1.2.3.4:53".parse().unwrap();
        assert_eq!(UdpPp::Bare.apply(&mut buf, 11, peer), Some((peer, 11)));
        assert_eq!(&buf, b"hello-world");
    }

    #[tokio::test]
    async fn apply_proxied_shifts_buffer_and_swaps_source() {
        let mut buf = *b"PROXY-HDRdns-payload"; // 9-byte fake header
        let peer: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let real: SocketAddr = "203.0.113.5:55000".parse().unwrap();
        let r = UdpPp::Proxied {
            src: real,
            hdr_len: 9,
        }
        .apply(&mut buf, 20, peer);
        assert_eq!(r, Some((real, 11)));
        assert_eq!(&buf[..11], b"dns-payload");
    }

    #[tokio::test]
    async fn apply_drop_returns_none() {
        let mut buf = [0u8; 4];
        let peer: SocketAddr = "1.2.3.4:53".parse().unwrap();
        assert_eq!(UdpPp::Drop.apply(&mut buf, 4, peer), None);
    }
}
