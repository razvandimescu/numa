use base64::Engine;
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
use crate::stats::Transport;

const MAX_DNS_MSG: usize = 4096;
const DOH_CONTENT_TYPE: &str = "application/dns-message";

pub async fn doh_post(State(state): State<super::proxy::DohState>, req: Request) -> Response {
    let host = super::proxy::extract_host(&req);
    let src = match doh_validate(&state, host.as_deref()) {
        Ok(src) => src,
        Err(code) => return code.into_response(),
    };

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
            return (StatusCode::PAYLOAD_TOO_LARGE, "body exceeds 4096 bytes").into_response();
        }
    };

    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty body").into_response();
    }

    resolve_doh(&body, src, &state.ctx).await
}

pub async fn doh_get(State(state): State<super::proxy::DohState>, req: Request) -> Response {
    let host = super::proxy::extract_host(&req);
    let src = match doh_validate(&state, host.as_deref()) {
        Ok(src) => src,
        Err(code) => return code.into_response(),
    };

    let dns_param = req
        .uri()
        .query()
        .and_then(|q| q.split('&').find_map(|pair| pair.strip_prefix("dns=")))
        .unwrap_or("");

    if dns_param.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing dns query parameter").into_response();
    }

    let body = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(dns_param) {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid base64url encoding").into_response();
        }
    };

    if body.len() > MAX_DNS_MSG {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body exceeds 4096 bytes").into_response();
    }

    resolve_doh(&body, src, &state.ctx).await
}

fn doh_validate(
    state: &super::proxy::DohState,
    host: Option<&str>,
) -> Result<SocketAddr, StatusCode> {
    if !is_doh_host(host, &state.ctx.proxy_tld) {
        return Err(StatusCode::NOT_FOUND);
    }

    // Gate DoH only — service-proxy routes on the same TLS listener
    // aren't subject to the DNS ACL. Fail closed when the peer is unknown.
    if state.ctx.allow_from.is_enabled() {
        let allowed = state
            .remote_addr
            .is_some_and(|a| state.ctx.allow_from.allows(a.ip()));
        if !allowed {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    Ok(state
        .remote_addr
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0))))
}

fn is_doh_host(host: Option<&str>, tld: &str) -> bool {
    let h = match host {
        Some(h) => h,
        None => return false,
    };
    let base = strip_port(h).unwrap_or(h);
    is_loopback_host(base) || is_tld_match(base, tld)
}

fn strip_port(h: &str) -> Option<&str> {
    if h.starts_with('[') {
        // [::1]:443 → [::1]
        let (base, port) = h.rsplit_once("]:")?;
        port.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| &h[..base.len() + 1])
    } else {
        let (base, port) = h.rsplit_once(':')?;
        // Bare IPv6 like "::1" has multiple colons — not a port suffix
        if base.contains(':') {
            return None;
        }
        port.bytes().all(|b| b.is_ascii_digit()).then_some(base)
    }
}

fn is_loopback_host(h: &str) -> bool {
    matches!(h, "127.0.0.1" | "::1" | "[::1]" | "localhost")
}

fn is_tld_match(h: &str, tld: &str) -> bool {
    h == tld
        || (h.len() == 2 * tld.len() + 1
            && h.starts_with(tld)
            && h.as_bytes().get(tld.len()) == Some(&b'.')
            && h.ends_with(tld))
}

async fn resolve_doh(
    dns_bytes: &[u8],
    src: SocketAddr,
    ctx: &std::sync::Arc<ServerCtx>,
) -> Response {
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

    let query_for_error = query.clone();

    match resolve_query(query, dns_bytes, src, ctx, Transport::Doh).await {
        Ok((resp_buffer, _)) => {
            let min_ttl = extract_min_ttl(resp_buffer.filled());
            dns_response(resp_buffer.filled(), min_ttl)
        }
        Err(e) => {
            warn!("DoH: resolve error for {}: {}", src, e);
            let mut resp = DnsPacket::response_from(&query_for_error, ResultCode::SERVFAIL);
            crate::ctx::shape_response_for_client(&mut resp, &query_for_error, ctx.filter_aaaa);
            serialize_response(&resp)
        }
    }
}

fn extract_min_ttl(wire: &[u8]) -> u32 {
    crate::wire::scan_ttl_offsets(wire)
        .ok()
        .and_then(|meta| crate::wire::min_ttl_from_wire(wire, &meta))
        .unwrap_or(0)
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
    use axum::extract::State;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    #[test]
    fn is_doh_host_matches_tld() {
        assert!(is_doh_host(Some("numa"), "numa"));
        assert!(is_doh_host(Some("numa.numa"), "numa"));
        assert!(is_doh_host(Some("127.0.0.1"), "numa"));
        assert!(is_doh_host(Some("127.0.0.1:443"), "numa"));
        assert!(is_doh_host(Some("::1"), "numa"));
        assert!(is_doh_host(Some("[::1]"), "numa"));
        assert!(is_doh_host(Some("[::1]:443"), "numa"));
        assert!(is_doh_host(Some("localhost"), "numa"));
        assert!(is_doh_host(Some("localhost:443"), "numa"));
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

    #[tokio::test]
    async fn doh_servfail_mirrors_client_opt() {
        // RFC 6891 §6.1.1 on the Err-branch; empty-questions drives it.
        let mut query = DnsPacket::new();
        query.header.id = 0x1234;
        query.header.recursion_desired = true;
        query.edns = Some(crate::packet::EdnsOpt::default());
        let mut buf = BytePacketBuffer::new();
        query.write(&mut buf).unwrap();

        let ctx = std::sync::Arc::new(crate::testutil::test_ctx().await);
        let src: std::net::SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let response = resolve_doh(buf.filled(), src, &ctx).await;

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let mut parse = BytePacketBuffer::from_bytes(&body);
        let resp = DnsPacket::from_buffer(&mut parse).unwrap();

        assert_eq!(resp.header.rescode, ResultCode::SERVFAIL);
        assert!(resp.edns.is_some(), "DoH SERVFAIL must mirror client's OPT");
    }

    async fn doh_get_response(query: &str) -> Response {
        let ctx = std::sync::Arc::new(crate::testutil::test_ctx().await);
        let state = crate::proxy::DohState {
            ctx,
            remote_addr: Some("127.0.0.1:1234".parse().unwrap()),
        };
        let req = Request::builder()
            .uri(format!("/dns-query?{query}"))
            .header(hyper::header::HOST, "localhost")
            .body(axum::body::Body::empty())
            .unwrap();
        doh_get(State(state), req).await
    }

    #[tokio::test]
    async fn doh_get_rejects_missing_param() {
        let resp = doh_get_response("name=example.com").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn doh_get_rejects_invalid_base64url() {
        // valid URI char, invalid base64url (one symbol can't form a byte)
        let resp = doh_get_response("dns=A").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn doh_get_rejects_oversized() {
        let param = URL_SAFE_NO_PAD.encode(vec![0u8; MAX_DNS_MSG + 1]);
        let resp = doh_get_response(&format!("dns={param}")).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn doh_get_decodes_param_and_resolves() {
        // base64url(dns) → decode → resolve; empty-questions drives SERVFAIL.
        let query = DnsPacket::new();
        let mut buf = BytePacketBuffer::new();
        query.write(&mut buf).unwrap();
        let param = URL_SAFE_NO_PAD.encode(buf.filled());

        let resp = doh_get_response(&format!("dns={param}")).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), MAX_DNS_MSG)
            .await
            .unwrap();
        let mut parse = BytePacketBuffer::from_bytes(&body);
        let parsed = DnsPacket::from_buffer(&mut parse).unwrap();
        assert_eq!(parsed.header.rescode, ResultCode::SERVFAIL);
    }
}
