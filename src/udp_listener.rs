//! UDP listener that survives multi-homed wildcard binds.
//!
//! Plain `tokio::net::UdpSocket::send_to` lets the kernel pick the source
//! address. On a host with multiple IPs bound via `0.0.0.0`, the kernel
//! typically picks the primary — so a query to a secondary IP gets a reply
//! from the primary, which RFC-compliant clients drop as "unexpected source".
//! See issue #227 (reporter ran two IPs on FreeBSD bge1).
//!
//! Fix: on Unix wildcard binds, capture the incoming destination IP via
//! `IP_PKTINFO`/`IP_RECVDSTADDR`/`IPV6_PKTINFO` cmsg and echo it as the reply
//! source via the matching send-side cmsg. Specific-IP binds and Windows
//! still use the plain socket.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;

#[cfg(unix)]
mod pktinfo;

#[cfg(unix)]
use pktinfo::PktInfoSocket;

#[derive(Debug)]
pub enum UdpListener {
    Plain(Arc<UdpSocket>),
    #[cfg(unix)]
    PktInfo(Arc<PktInfoSocket>),
}

impl UdpListener {
    pub async fn bind(addr: &str) -> io::Result<Self> {
        let parsed: SocketAddr = addr.parse().map_err(|e: std::net::AddrParseError| {
            io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
        })?;
        #[cfg(unix)]
        if parsed.ip().is_unspecified() {
            return PktInfoSocket::bind(parsed).map(|s| Self::PktInfo(Arc::new(s)));
        }
        let sock = UdpSocket::bind(parsed).await?;
        Ok(Self::Plain(Arc::new(sock)))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Plain(s) => s.local_addr(),
            #[cfg(unix)]
            Self::PktInfo(s) => s.local_addr(),
        }
    }

    /// Returns `(bytes_read, peer, local_destination)`. The local destination
    /// is `Some` only on wildcard-bound sockets where it was captured via
    /// cmsg; callers should pass it back to `send_to` to fix the reply source.
    pub async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
        match self {
            Self::Plain(s) => {
                let (n, peer) = s.recv_from(buf).await?;
                Ok((n, peer, None))
            }
            #[cfg(unix)]
            Self::PktInfo(s) => s.recv_from(buf).await,
        }
    }

    /// `src` should be the destination IP captured from the matching
    /// `recv_from`. Plain sockets ignore it (kernel chooses the source —
    /// safe because the socket is bound to a specific IP, not wildcard).
    pub async fn send_to(
        &self,
        buf: &[u8],
        dst: SocketAddr,
        src: Option<IpAddr>,
    ) -> io::Result<usize> {
        match self {
            Self::Plain(s) => {
                let _ = src;
                s.send_to(buf, dst).await
            }
            #[cfg(unix)]
            Self::PktInfo(s) => s.send_to(buf, dst, src).await,
        }
    }
}
