//! PROXY protocol v2 — client IP preservation behind L4 front-ends.
//!
//! Wraps [`proxy_header::io::ProxiedStream`] with a trusted-peer CIDR gate,
//! a header-read timeout, and stats hooks. Used by the DoT and DoH accept
//! loops; see `docs/implementation/proxy-protocol-v2.md` for the design.
//!
//! Naming and semantics mirror PowerDNS Recursor's `proxy-protocol-from`:
//! an empty allowlist disables the feature; a non-empty one puts the
//! listener in PROXY-required mode.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ipnet::IpNet;
use log::{debug, info, warn};
use proxy_header::io::ProxiedStream;
use proxy_header::ParseConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::config::ProxyProtocolConfig;
use crate::ctx::ServerCtx;

pub(crate) const PARSE_CFG: ParseConfig = ParseConfig {
    allow_v1: false,
    allow_v2: true,
    include_tlvs: false,
};

/// Runtime form of [`ProxyProtocolConfig`]: parsed CIDR list + already-typed
/// timeout. Built once per listener at startup.
#[derive(Clone, Debug)]
pub struct PpConfig {
    pub from: Vec<IpNet>,
    pub header_timeout: Duration,
}

impl PpConfig {
    /// Returns `Ok(None)` if the feature is disabled (empty `from`).
    /// Returns `Err` if any allowlist entry fails to parse.
    pub fn from_config(cfg: &ProxyProtocolConfig) -> Result<Option<Self>, String> {
        if cfg.from.is_empty() {
            return Ok(None);
        }
        let mut from = Vec::with_capacity(cfg.from.len());
        for entry in &cfg.from {
            let net: IpNet = entry
                .parse()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| format!("invalid CIDR or IP in proxy_protocol.from: {entry:?}"))?;
            if matches!(&net, IpNet::V4(n) if n.prefix_len() == 0)
                || matches!(&net, IpNet::V6(n) if n.prefix_len() == 0)
            {
                warn!(
                    "proxy_protocol.from contains world-routable {} — any sender on the Internet will be permitted to spoof source IPs",
                    entry
                );
            }
            from.push(net);
        }
        Ok(Some(PpConfig {
            from,
            header_timeout: Duration::from_millis(cfg.header_timeout_ms),
        }))
    }

    pub(crate) fn allows(&self, peer: IpAddr) -> bool {
        self.from.iter().any(|n| n.contains(&peer))
    }
}

/// Parse a listener's `proxy_protocol` config and log the outcome.
/// Returns `Err(())` if the config is invalid (caller should disable the
/// listener). Returns `Ok(None)` when the feature is off, `Ok(Some(_))`
/// when enabled.
#[allow(clippy::result_unit_err)]
pub fn init(listener: &str, cfg: &ProxyProtocolConfig) -> Result<Option<Arc<PpConfig>>, ()> {
    match PpConfig::from_config(cfg) {
        Ok(Some(pp)) => {
            info!(
                "{listener}: PROXY v2 enabled, trusting {} CIDR(s)",
                cfg.from.len()
            );
            Ok(Some(Arc::new(pp)))
        }
        Ok(None) => Ok(None),
        Err(e) => {
            warn!("{listener}: invalid proxy_protocol config ({e}) — listener disabled");
            Err(())
        }
    }
}

/// Read either the raw `TcpStream` (when PROXY v2 is disabled or this peer
/// isn't an allowed sender) or a [`ProxiedStream`] wrapper, returning the
/// stream and the resolved client `SocketAddr` (parsed from the header when
/// present, otherwise the actual TCP peer).
///
/// Returns `None` when the connection should be dropped — either because
/// the peer is not on the allowlist, or because the header failed to parse
/// or arrive before the timeout. Stats are recorded as a side effect.
pub async fn handshake(
    tcp_stream: TcpStream,
    tcp_peer: SocketAddr,
    pp: Option<&PpConfig>,
    ctx: &Arc<ServerCtx>,
) -> Option<(Stream, SocketAddr)> {
    let pp = match pp {
        Some(p) => p,
        // Feature disabled on this listener; passthrough.
        None => return Some((Stream::Bare(tcp_stream), tcp_peer)),
    };

    if !pp.allows(tcp_peer.ip()) {
        ctx.stats.lock().unwrap().proxy_v2_rejected_untrusted += 1;
        debug!("pp2: untrusted peer {tcp_peer}, dropping");
        return None;
    }

    let proxied = match tokio::time::timeout(
        pp.header_timeout,
        ProxiedStream::create_from_tokio(tcp_stream, PARSE_CFG),
    )
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            // proxy-header returns one error type for parse failures; we
            // can't easily split signature/version/family without inspecting
            // the message. Bucket as "signature" until the crate exposes
            // structured error variants.
            ctx.stats.lock().unwrap().proxy_v2_rejected_signature += 1;
            debug!("pp2 parse from {tcp_peer}: {e}");
            return None;
        }
        Err(_) => {
            ctx.stats.lock().unwrap().proxy_v2_timeout += 1;
            debug!("pp2: header read timeout from {tcp_peer}");
            return None;
        }
    };

    let header = proxied.proxy_header();
    let real_addr = match header.proxied_address() {
        Some(addr) => {
            ctx.stats.lock().unwrap().proxy_v2_accepted += 1;
            addr.source
        }
        None => {
            // LOCAL command (proxy health check) or an address-less header.
            // Use the TCP peer as the connection's remote_addr.
            ctx.stats.lock().unwrap().proxy_v2_local_command += 1;
            tcp_peer
        }
    };

    Some((Stream::Proxied(Box::new(proxied)), real_addr))
}

/// `Either`-style enum covering the two states the listener may produce:
/// the bare `TcpStream` (PROXY v2 disabled or peer-not-trusted-and-allowed
/// path), or the `ProxiedStream` wrapper (header consumed, post-header
/// bytes available for the next layer — TLS or plain DNS).
///
/// Both arms implement `AsyncRead + AsyncWrite + Unpin`, so callers hand
/// the value straight to `TlsAcceptor::accept` or to a hyper service.
pub enum Stream {
    Bare(TcpStream),
    Proxied(Box<ProxiedStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Bare(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Stream::Proxied(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Bare(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Stream::Proxied(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Bare(s) => std::pin::Pin::new(s).poll_flush(cx),
            Stream::Proxied(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Bare(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Stream::Proxied(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(from: &[&str]) -> ProxyProtocolConfig {
        ProxyProtocolConfig {
            from: from.iter().map(|s| s.to_string()).collect(),
            header_timeout_ms: 5000,
        }
    }

    #[test]
    fn empty_from_disables_feature() {
        let pp = PpConfig::from_config(&cfg(&[])).unwrap();
        assert!(pp.is_none());
    }

    #[test]
    fn parses_exact_ipv4() {
        let pp = PpConfig::from_config(&cfg(&["127.0.0.1"]))
            .unwrap()
            .unwrap();
        assert!(pp.allows("127.0.0.1".parse().unwrap()));
        assert!(!pp.allows("127.0.0.2".parse().unwrap()));
    }

    #[test]
    fn parses_ipv4_cidr() {
        let pp = PpConfig::from_config(&cfg(&["10.0.0.0/8"]))
            .unwrap()
            .unwrap();
        assert!(pp.allows("10.255.255.255".parse().unwrap()));
        assert!(!pp.allows("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parses_ipv6_cidr() {
        let pp = PpConfig::from_config(&cfg(&["fd00::/8"])).unwrap().unwrap();
        assert!(pp.allows("fd00::1".parse().unwrap()));
        assert!(!pp.allows("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn rejects_garbage() {
        assert!(PpConfig::from_config(&cfg(&["not-a-cidr"])).is_err());
    }

    #[test]
    fn mixed_v4_v6_allowlist() {
        let pp = PpConfig::from_config(&cfg(&["127.0.0.1", "::1", "10.0.0.0/8"]))
            .unwrap()
            .unwrap();
        assert!(pp.allows("127.0.0.1".parse().unwrap()));
        assert!(pp.allows("::1".parse().unwrap()));
        assert!(pp.allows("10.5.5.5".parse().unwrap()));
        assert!(!pp.allows("8.8.8.8".parse().unwrap()));
    }
}
