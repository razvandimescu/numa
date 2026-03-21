use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::buffer::BytePacketBuffer;
use crate::packet::DnsPacket;
use crate::Result;

pub async fn forward_query(
    query: &DnsPacket,
    upstream: SocketAddr,
    timeout_duration: Duration,
) -> Result<DnsPacket> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    let mut send_buffer = BytePacketBuffer::new();
    query.write(&mut send_buffer)?;

    socket.send_to(send_buffer.filled(), upstream).await?;

    let mut recv_buffer = BytePacketBuffer::new();
    let (size, _) = timeout(timeout_duration, socket.recv_from(&mut recv_buffer.buf)).await??;

    if size >= recv_buffer.buf.len() {
        log::debug!(
            "upstream response truncated ({} bytes, buffer {})",
            size,
            recv_buffer.buf.len()
        );
    }

    DnsPacket::from_buffer(&mut recv_buffer)
}
