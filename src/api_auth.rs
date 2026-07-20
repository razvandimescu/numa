//! Authentication for the HTTP control plane (dashboard + REST API), which can
//! mutate how Numa resolves DNS. Loopback is always allowed (local dashboard +
//! CLI), mirroring `acl.rs`; any other peer must present `api_token` via HTTP
//! `Bearer` or `Basic` (so browsers prompt natively). The token is drive-by
//! protection, not wire encryption — the API is plain HTTP, so for internet
//! exposure terminate TLS in front. See `recipes/dnsdist-front.md`.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;

const TOKEN_ENV: &str = "NUMA_API_TOKEN";

/// Header the `.numa` reverse proxy stamps with the real client IP. The proxy
/// re-originates from loopback, which would otherwise read as exempt; we trust
/// this header *only* on a loopback connection (so only our own proxy, or a
/// genuine local process, can set it). See `proxy.rs`.
pub const CLIENT_IP_HEADER: &str = "x-numa-client-ip";

#[derive(Clone)]
pub struct ApiAuth {
    token: Option<String>,
}

impl ApiAuth {
    fn new(token: Option<String>) -> Self {
        ApiAuth {
            token: token.filter(|t| !t.is_empty()),
        }
    }

    /// `NUMA_API_TOKEN` wins over config so secrets can be injected at runtime.
    pub fn from_config(config_token: &Option<String>) -> Self {
        Self::new(
            std::env::var(TOKEN_ENV)
                .ok()
                .filter(|t| !t.is_empty())
                .or_else(|| config_token.clone()),
        )
    }

    pub fn is_configured(&self) -> bool {
        self.token.is_some()
    }

    fn permits(&self, peer: IpAddr, headers: &HeaderMap) -> bool {
        if peer.to_canonical().is_loopback() {
            return true;
        }
        match &self.token {
            Some(expected) => credential(headers).is_some_and(|given| ct_eq(expected, &given)),
            None => false,
        }
    }
}

/// Real client IP for the auth decision. A loopback peer may be our `.numa`
/// proxy forwarding a remote client — trust its `CLIENT_IP_HEADER` stamp in
/// that case only. A non-loopback peer is the genuine L4 client; ignore the
/// header so a direct client can't forge a loopback IP to bypass the gate.
fn effective_peer(peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    if !peer.to_canonical().is_loopback() {
        return peer;
    }
    headers
        .get(CLIENT_IP_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(peer)
}

/// For `Basic <base64(user:token)>`, the password is the token (username ignored).
fn credential(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if let Some(token) = value.strip_prefix("Bearer ") {
        return Some(token.to_string());
    }
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let pair = String::from_utf8(decoded).ok()?;
    pair.split_once(':').map(|(_, pass)| pass.to_string())
}

/// Constant-time equality; differing lengths short-circuit (leaks only length,
/// irrelevant for a random token).
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub async fn require_auth(
    State(auth): State<ApiAuth>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let client = effective_peer(peer.ip(), req.headers());
    if req.uri().path() == "/health" || auth.permits(client, req.headers()) {
        return next.run(req).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"numa\"")],
        "unauthorized\n",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(token: Option<&str>) -> ApiAuth {
        ApiAuth::new(token.map(str::to_string))
    }

    fn headers(authorization: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = authorization {
            h.insert(header::AUTHORIZATION, v.parse().unwrap());
        }
        h
    }

    fn basic(user: &str, pass: &str) -> String {
        let enc = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        format!("Basic {enc}")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_always_permitted_without_credential() {
        let a = auth(Some("secret"));
        assert!(a.permits(ip("127.0.0.1"), &headers(None)));
        assert!(a.permits(ip("::1"), &headers(None)));
        assert!(a.permits(ip("::ffff:127.0.0.1"), &headers(None)));
    }

    #[test]
    fn non_loopback_requires_credential() {
        let a = auth(Some("secret"));
        assert!(!a.permits(ip("203.0.113.7"), &headers(None)));
        assert!(!a.permits(ip("203.0.113.7"), &headers(Some("Bearer wrong"))));
        assert!(a.permits(ip("203.0.113.7"), &headers(Some("Bearer secret"))));
    }

    #[test]
    fn basic_auth_password_is_the_token() {
        let a = auth(Some("secret"));
        assert!(a.permits(ip("203.0.113.7"), &headers(Some(&basic("admin", "secret")))));
        assert!(a.permits(ip("203.0.113.7"), &headers(Some(&basic("", "secret")))));
        assert!(!a.permits(ip("203.0.113.7"), &headers(Some(&basic("secret", "")))));
    }

    #[test]
    fn no_token_configured_denies_non_loopback() {
        let a = auth(None);
        assert!(!a.is_configured());
        assert!(!a.permits(ip("203.0.113.7"), &headers(Some("Bearer anything"))));
    }

    #[test]
    fn is_configured_reflects_token() {
        assert!(!auth(None).is_configured());
        assert!(auth(Some("t")).is_configured());
        assert!(!auth(Some("")).is_configured());
    }

    fn with_client_ip(ip: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(CLIENT_IP_HEADER, ip.parse().unwrap());
        h
    }

    #[test]
    fn loopback_peer_trusts_client_ip_header() {
        // The proxy forwards from loopback and stamps the real client IP.
        assert_eq!(
            effective_peer(ip("127.0.0.1"), &with_client_ip("192.168.1.9")),
            ip("192.168.1.9")
        );
        assert_eq!(
            effective_peer(ip("::1"), &with_client_ip("203.0.113.7")),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn non_loopback_peer_ignores_client_ip_header() {
        // A direct client can't forge a loopback IP to bypass the gate.
        assert_eq!(
            effective_peer(ip("203.0.113.7"), &with_client_ip("127.0.0.1")),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn loopback_peer_without_header_stays_loopback() {
        assert_eq!(
            effective_peer(ip("127.0.0.1"), &headers(None)),
            ip("127.0.0.1")
        );
    }

    #[test]
    fn proxied_lan_client_is_gated_without_token() {
        // Loopback proxy peer + stamped LAN IP → resolves to the LAN IP → gated.
        let a = auth(Some("secret"));
        let client = effective_peer(ip("127.0.0.1"), &with_client_ip("192.168.1.9"));
        assert!(!a.permits(client, &with_client_ip("192.168.1.9")));
    }

    #[test]
    fn malformed_authorization_is_rejected() {
        let a = auth(Some("secret"));
        for bad in ["", "secret", "Bearer", "Basic !!!", "Basic", "Token secret"] {
            assert!(
                !a.permits(ip("203.0.113.7"), &headers(Some(bad))),
                "{bad:?} must not authenticate"
            );
        }
    }
}
