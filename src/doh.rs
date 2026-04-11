use std::net::SocketAddr;

use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use hyper::StatusCode;
use log::warn;

use crate::buffer::BytePacketBuffer;
use crate::ctx::{resolve_query, ServerCtx};
use crate::header::ResultCode;
use crate::packet::DnsPacket;

const MAX_DNS_MSG: usize = 4096;
const DOH_CONTENT_TYPE: &str = "application/dns-message";

pub async fn doh_post(State(state): State<super::proxy::DohState>, req: Request) -> Response {
    let host = super::proxy::extract_host(&req);
    if !is_doh_host(host.as_deref(), &state.ctx.proxy_tld) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let content_type = req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with(DOH_CONTENT_TYPE) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }

    let body = match axum::body::to_bytes(req.into_body(), MAX_DNS_MSG).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "body exceeds 4096 bytes").into_response()
        }
    };

    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty body").into_response();
    }

    let src = state
        .remote_addr
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));

    resolve_doh(&body, src, &state.ctx).await
}

fn is_doh_host(host: Option<&str>, tld: &str) -> bool {
    match host {
        Some(h) if h == tld => true,
        Some(h) => {
            h.len() == 2 * tld.len() + 1
                && h.starts_with(tld)
                && h.as_bytes().get(tld.len()) == Some(&b'.')
                && h.ends_with(tld)
        }
        None => false,
    }
}

async fn resolve_doh(dns_bytes: &[u8], src: SocketAddr, ctx: &ServerCtx) -> Response {
    let mut buffer = BytePacketBuffer::from_bytes(dns_bytes);
    let query = match DnsPacket::from_buffer(&mut buffer) {
        Ok(q) => q,
        Err(e) => {
            warn!("DoH: parse error from {}: {}", src, e);
            let query_id = u16::from_be_bytes([
                dns_bytes.first().copied().unwrap_or(0),
                dns_bytes.get(1).copied().unwrap_or(0),
            ]);
            let mut resp = DnsPacket::new();
            resp.header.id = query_id;
            resp.header.response = true;
            resp.header.rescode = ResultCode::FORMERR;
            return serialize_response(&resp);
        }
    };

    let query_id = query.header.id;
    let query_rd = query.header.recursion_desired;
    let questions = query.questions.clone();

    match resolve_query(query, src, ctx).await {
        Ok(resp_buffer) => {
            let min_ttl = extract_min_ttl(resp_buffer.filled());
            dns_response(resp_buffer.filled(), min_ttl)
        }
        Err(e) => {
            warn!("DoH: resolve error for {}: {}", src, e);
            let mut resp = DnsPacket::new();
            resp.header.id = query_id;
            resp.header.response = true;
            resp.header.recursion_desired = query_rd;
            resp.header.recursion_available = true;
            resp.header.rescode = ResultCode::SERVFAIL;
            resp.questions = questions;
            serialize_response(&resp)
        }
    }
}

fn extract_min_ttl(wire: &[u8]) -> u32 {
    let mut buf = BytePacketBuffer::from_bytes(wire);
    match DnsPacket::from_buffer(&mut buf) {
        Ok(pkt) => pkt.answers.iter().map(|r| r.ttl()).min().unwrap_or(0),
        Err(_) => 0,
    }
}

fn dns_response(wire: &[u8], min_ttl: u32) -> Response {
    (
        StatusCode::OK,
        [
            (hyper::header::CONTENT_TYPE, DOH_CONTENT_TYPE),
            (
                hyper::header::CACHE_CONTROL,
                &format!("max-age={}", min_ttl),
            ),
        ],
        Bytes::copy_from_slice(wire),
    )
        .into_response()
}

fn serialize_response(pkt: &DnsPacket) -> Response {
    let mut buf = BytePacketBuffer::new();
    match pkt.write(&mut buf) {
        Ok(_) => dns_response(buf.filled(), 0),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::BytePacketBuffer;
    use crate::header::ResultCode;
    use crate::packet::DnsPacket;
    use crate::record::DnsRecord;

    #[test]
    fn is_doh_host_matches_tld() {
        assert!(is_doh_host(Some("numa"), "numa"));
        assert!(is_doh_host(Some("numa.numa"), "numa"));
        assert!(!is_doh_host(Some("foo.numa"), "numa"));
        assert!(!is_doh_host(None, "numa"));
    }

    #[test]
    fn extract_min_ttl_from_response() {
        let mut pkt = DnsPacket::new();
        pkt.header.response = true;
        pkt.answers.push(DnsRecord::A {
            domain: "example.com".to_string(),
            addr: std::net::Ipv4Addr::new(1, 2, 3, 4),
            ttl: 300,
        });
        pkt.answers.push(DnsRecord::A {
            domain: "example.com".to_string(),
            addr: std::net::Ipv4Addr::new(5, 6, 7, 8),
            ttl: 60,
        });
        let mut buf = BytePacketBuffer::new();
        pkt.write(&mut buf).unwrap();
        assert_eq!(extract_min_ttl(buf.filled()), 60);
    }

    #[test]
    fn extract_min_ttl_no_answers() {
        let mut pkt = DnsPacket::new();
        pkt.header.response = true;
        let mut buf = BytePacketBuffer::new();
        pkt.write(&mut buf).unwrap();
        assert_eq!(extract_min_ttl(buf.filled()), 0);
    }

    #[test]
    fn serialize_formerr_response() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 0xABCD;
        pkt.header.response = true;
        pkt.header.rescode = ResultCode::FORMERR;
        let resp = serialize_response(&pkt);
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
