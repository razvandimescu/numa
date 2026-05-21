//! UDP listener that preserves the per-packet destination IP on multi-homed
//! wildcard binds (issue #227), via quinn-udp's portable PKTINFO/RECVDSTADDR/
//! IPV6_PKTINFO handling. `dst_ip` returned by `recv_from` should be threaded
//! back into `send_to` so the reply source matches the IP that received the
//! query — otherwise the kernel picks the primary, RFC-compliant clients drop
//! the reply as "unexpected source".

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
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn wildcard_v4_echoes_source_on_loopback() {
        let server = UdpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"hi", server_addr).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, peer, dst) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hi");
        assert!(matches!(peer.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST));
        assert_eq!(dst, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));

        server
            .send_to(b"yo", peer, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)))
            .await
            .unwrap();
        let mut rbuf = [0u8; 64];
        let (m, reply_src) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut rbuf),
        )
        .await
        .expect("reply within 1s")
        .unwrap();
        assert_eq!(&rbuf[..m], b"yo");
        assert_eq!(reply_src, server_addr);
    }
}
