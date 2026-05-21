//! UDP listener that returns the per-packet destination IP from `recv_from`,
//! so the caller can thread it back into `send_to` and reply from the same
//! IP the query arrived on. Otherwise the kernel picks the primary on a
//! wildcard bind and replies are dropped as "unexpected source".

use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};

use quinn_udp::{RecvMeta, Transmit, UdpSocketState};
use tokio::io::Interest;
use tokio::net::UdpSocket;

#[derive(Debug)]
pub struct UdpListener {
    inner: UdpSocket,
    state: UdpSocketState,
}

impl UdpListener {
    pub async fn bind(addr: &str) -> io::Result<Self> {
        let parsed: SocketAddr = addr.parse().map_err(|e: std::net::AddrParseError| {
            io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
        })?;
        let std_sock = std::net::UdpSocket::bind(parsed)?;
        std_sock.set_nonblocking(true)?;
        let state = UdpSocketState::new((&std_sock).into())?;
        // UDP_GRO would pack multiple datagrams per recv (see RecvMeta::stride).
        // DNS recv_from is single-datagram by contract; disable so callers stay
        // simple. Best-effort: ignored on kernels without UDP_GRO.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        disable_udp_gro(&std_sock);
        let inner = UdpSocket::from_std(std_sock)?;
        Ok(Self { inner, state })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    pub async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
        loop {
            self.inner.readable().await?;
            let mut meta = [RecvMeta::default()];
            let mut bufs = [IoSliceMut::new(buf)];
            match self.inner.try_io(Interest::READABLE, || {
                self.state.recv((&self.inner).into(), &mut bufs, &mut meta)
            }) {
                Ok(n) if n >= 1 => {
                    let m = &meta[0];
                    return Ok((m.len, m.addr, m.dst_ip));
                }
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    pub async fn send_to(
        &self,
        buf: &[u8],
        dst: SocketAddr,
        src: Option<IpAddr>,
    ) -> io::Result<usize> {
        let transmit = Transmit {
            destination: dst,
            ecn: None,
            contents: buf,
            segment_size: None,
            src_ip: src,
        };
        loop {
            self.inner.writable().await?;
            match self.inner.try_io(Interest::WRITABLE, || {
                self.state.try_send((&self.inner).into(), &transmit)
            }) {
                Ok(()) => return Ok(buf.len()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn disable_udp_gro(sock: &std::net::UdpSocket) {
    use std::os::unix::io::AsRawFd;
    let off: libc::c_int = 0;
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_UDP,
            libc::UDP_GRO,
            &off as *const _ as *const libc::c_void,
            std::mem::size_of_val(&off) as libc::socklen_t,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    async fn recv_reply(client: &tokio::net::UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = [0u8; 64];
        let (n, src) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .expect("reply within 1s")
            .unwrap();
        (buf[..n].to_vec(), src)
    }

    #[tokio::test]
    async fn specific_bind_v4_round_trip() {
        let server = UdpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"hi", server_addr).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, peer, dst) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hi");
        assert!(matches!(peer.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST));
        // quinn-udp populates dst_ip even on specific binds; either Some(LOCALHOST) or None is acceptable.
        assert!(dst.is_none() || dst == Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));

        server.send_to(b"yo", peer, dst).await.unwrap();
        let (payload, reply_src) = recv_reply(&client).await;
        assert_eq!(payload, b"yo");
        assert_eq!(reply_src, server_addr);
    }

    #[tokio::test]
    async fn wildcard_bind_v4_pins_reply_source() {
        let server = UdpListener::bind("0.0.0.0:0").await.unwrap();
        let server_port = server.local_addr().unwrap().port();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        client.send_to(b"hi", target).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, peer, dst) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hi");
        assert_eq!(
            dst,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "wildcard bind must capture per-packet dst via PKTINFO cmsg"
        );

        server.send_to(b"yo", peer, dst).await.unwrap();
        let (payload, reply_src) = recv_reply(&client).await;
        assert_eq!(payload, b"yo");
        assert_eq!(
            reply_src.ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "reply must come from the IP the query arrived on, not 0.0.0.0"
        );
        assert_eq!(reply_src.port(), server_port);
    }

    #[tokio::test]
    async fn wildcard_bind_v6_pins_reply_source() {
        let server = match UdpListener::bind("[::]:0").await {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable => {
                eprintln!("skipping: IPv6 not available ({e})");
                return;
            }
            Err(e) => panic!("bind [::]:0 failed: {e}"),
        };
        let server_port = server.local_addr().unwrap().port();

        let client = match tokio::net::UdpSocket::bind("[::1]:0").await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping: IPv6 loopback not available ({e})");
                return;
            }
        };
        let target = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), server_port);
        client.send_to(b"hi", target).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, peer, dst) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hi");
        assert_eq!(
            dst,
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            "wildcard v6 bind must capture per-packet dst via IPV6_PKTINFO cmsg"
        );

        server.send_to(b"yo", peer, dst).await.unwrap();
        let (payload, reply_src) = recv_reply(&client).await;
        assert_eq!(payload, b"yo");
        assert_eq!(reply_src.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(reply_src.port(), server_port);
    }
}
