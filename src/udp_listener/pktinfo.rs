//! Async UDP socket that captures and overrides the per-packet local IP
//! using `IP_PKTINFO`/`IP_RECVDSTADDR`/`IPV6_PKTINFO` cmsg.
//!
//! Platform map:
//!   v4 send/recv:
//!     - Linux, macOS, NetBSD: `IP_PKTINFO` + `in_pktinfo` (recv: `ipi_addr`,
//!       send: `ipi_spec_dst`).
//!     - FreeBSD, OpenBSD, DragonFly: `IP_RECVDSTADDR` (recv) /
//!       `IP_SENDSRCADDR` (send), payload `in_addr`.
//!   v6 send/recv (all unices): `IPV6_RECVPKTINFO` to enable, cmsg type
//!     `IPV6_PKTINFO`, payload `in6_pktinfo.ipi6_addr`.

use std::io;
use std::mem::{self, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;

const CONTROL_BUF_SIZE: usize = 128;

#[derive(Debug)]
pub struct PktInfoSocket {
    inner: AsyncFd<Socket>,
    local_addr: SocketAddr,
    is_v6: bool,
}

impl PktInfoSocket {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let (domain, is_v6) = match addr {
            SocketAddr::V4(_) => (Domain::IPV4, false),
            SocketAddr::V6(_) => (Domain::IPV6, true),
        };
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_nonblocking(true)?;
        sock.set_reuse_address(true)?;
        enable_pktinfo(sock.as_raw_fd(), is_v6)?;
        sock.bind(&SockAddr::from(addr))?;
        let local_addr = sock
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("non-IP local_addr"))?;
        Ok(Self {
            inner: AsyncFd::new(sock)?,
            local_addr,
            is_v6,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    pub async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| recvmsg_one(inner.get_ref().as_raw_fd(), buf, self.is_v6)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn send_to(
        &self,
        buf: &[u8],
        dst: SocketAddr,
        src: Option<IpAddr>,
    ) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| sendmsg_one(inner.get_ref().as_raw_fd(), buf, dst, src)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

fn enable_pktinfo(fd: RawFd, is_v6: bool) -> io::Result<()> {
    let on: libc::c_int = 1;
    let (level, opt) = if is_v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    } else {
        (libc::IPPROTO_IP, v4_recv_opt())
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &on as *const _ as *const libc::c_void,
            mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "netbsd"
))]
fn v4_recv_opt() -> libc::c_int {
    libc::IP_PKTINFO
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
fn v4_recv_opt() -> libc::c_int {
    libc::IP_RECVDSTADDR
}

fn recvmsg_one(
    fd: RawFd,
    buf: &mut [u8],
    is_v6: bool,
) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    let mut name = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut control = [MaybeUninit::<u8>::uninit(); CONTROL_BUF_SIZE];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = name.as_mut_ptr() as *mut libc::c_void;
    msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1 as _;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len() as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let peer = sockaddr_storage_to_addr(unsafe { name.assume_init_ref() }, msg.msg_namelen)?;
    let dst = parse_dst_cmsg(&msg, is_v6);
    Ok((n as usize, peer, dst))
}

fn sendmsg_one(fd: RawFd, buf: &[u8], dst: SocketAddr, src: Option<IpAddr>) -> io::Result<usize> {
    let dst_sa = SockAddr::from(dst);
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut control = [0u8; CONTROL_BUF_SIZE];
    let control_len = match src {
        Some(src_ip) => write_src_cmsg(&mut control, src_ip),
        None => 0,
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = dst_sa.as_ptr() as *mut libc::c_void;
    msg.msg_namelen = dst_sa.len();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1 as _;
    if control_len > 0 {
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control_len as _;
    }
    let n = unsafe { libc::sendmsg(fd, &msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

fn sockaddr_storage_to_addr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    let len = len as usize;
    match storage.ss_family as libc::c_int {
        libc::AF_INET if len >= mem::size_of::<libc::sockaddr_in>() => {
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        libc::AF_INET6 if len >= mem::size_of::<libc::sockaddr_in6>() => {
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sin.sin6_addr.s6_addr);
            let port = u16::from_be(sin.sin6_port);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported sockaddr family",
        )),
    }
}

fn parse_dst_cmsg(msg: &libc::msghdr, is_v6: bool) -> Option<IpAddr> {
    if msg.msg_controllen == 0 {
        return None;
    }
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        let (level, ctype) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
        let data = unsafe { libc::CMSG_DATA(cmsg) };
        if is_v6 && level == libc::IPPROTO_IPV6 && ctype == libc::IPV6_PKTINFO {
            let pi = unsafe { ptr::read_unaligned(data as *const libc::in6_pktinfo) };
            return Some(IpAddr::V6(Ipv6Addr::from(pi.ipi6_addr.s6_addr)));
        }
        if !is_v6 && level == libc::IPPROTO_IP {
            if let Some(ip) = parse_v4_dst(ctype, data) {
                return Some(IpAddr::V4(ip));
            }
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
    None
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "netbsd"
))]
fn parse_v4_dst(ctype: libc::c_int, data: *const u8) -> Option<Ipv4Addr> {
    if ctype == libc::IP_PKTINFO {
        let pi = unsafe { ptr::read_unaligned(data as *const libc::in_pktinfo) };
        Some(Ipv4Addr::from(u32::from_be(pi.ipi_addr.s_addr)))
    } else {
        None
    }
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
fn parse_v4_dst(ctype: libc::c_int, data: *const u8) -> Option<Ipv4Addr> {
    if ctype == libc::IP_RECVDSTADDR {
        let addr = unsafe { ptr::read_unaligned(data as *const libc::in_addr) };
        Some(Ipv4Addr::from(u32::from_be(addr.s_addr)))
    } else {
        None
    }
}

fn write_src_cmsg(buf: &mut [u8], src: IpAddr) -> usize {
    match src {
        IpAddr::V4(ip4) => write_v4_src(buf, ip4),
        IpAddr::V6(ip6) => write_v6_src(buf, ip6),
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "netbsd"
))]
fn write_v4_src(buf: &mut [u8], src: Ipv4Addr) -> usize {
    let payload_len = mem::size_of::<libc::in_pktinfo>();
    let cmsg_len = cmsg_len_for(payload_len);
    let total = cmsg_space_for(payload_len);
    buf[..total].fill(0);
    unsafe {
        let hdr = buf.as_mut_ptr() as *mut libc::cmsghdr;
        (*hdr).cmsg_len = cmsg_len as _;
        (*hdr).cmsg_level = libc::IPPROTO_IP;
        (*hdr).cmsg_type = libc::IP_PKTINFO;
        let pi = libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from(src).to_be(),
            },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };
        ptr::write_unaligned(libc::CMSG_DATA(hdr) as *mut libc::in_pktinfo, pi);
    }
    total
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly"))]
fn write_v4_src(buf: &mut [u8], src: Ipv4Addr) -> usize {
    let payload_len = mem::size_of::<libc::in_addr>();
    let cmsg_len = cmsg_len_for(payload_len);
    let total = cmsg_space_for(payload_len);
    buf[..total].fill(0);
    unsafe {
        let hdr = buf.as_mut_ptr() as *mut libc::cmsghdr;
        (*hdr).cmsg_len = cmsg_len as _;
        (*hdr).cmsg_level = libc::IPPROTO_IP;
        (*hdr).cmsg_type = libc::IP_SENDSRCADDR;
        let addr = libc::in_addr {
            s_addr: u32::from(src).to_be(),
        };
        ptr::write_unaligned(libc::CMSG_DATA(hdr) as *mut libc::in_addr, addr);
    }
    total
}

fn write_v6_src(buf: &mut [u8], src: Ipv6Addr) -> usize {
    let payload_len = mem::size_of::<libc::in6_pktinfo>();
    let cmsg_len = cmsg_len_for(payload_len);
    let total = cmsg_space_for(payload_len);
    buf[..total].fill(0);
    unsafe {
        let hdr = buf.as_mut_ptr() as *mut libc::cmsghdr;
        (*hdr).cmsg_len = cmsg_len as _;
        (*hdr).cmsg_level = libc::IPPROTO_IPV6;
        (*hdr).cmsg_type = libc::IPV6_PKTINFO;
        let pi = libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr {
                s6_addr: src.octets(),
            },
            ipi6_ifindex: 0,
        };
        ptr::write_unaligned(libc::CMSG_DATA(hdr) as *mut libc::in6_pktinfo, pi);
    }
    total
}

fn cmsg_len_for(payload: usize) -> usize {
    unsafe { libc::CMSG_LEN(payload as libc::c_uint) as usize }
}

fn cmsg_space_for(payload: usize) -> usize {
    unsafe { libc::CMSG_SPACE(payload as libc::c_uint) as usize }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn wildcard_v4_echoes_source_on_loopback() {
        let server = PktInfoSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
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
