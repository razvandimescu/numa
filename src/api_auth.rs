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

#[derive(Clone)]
pub struct ApiAuth {
    token: Option<String>,
}

impl ApiAuth {
    pub fn new(token: Option<String>) -> Self {
        ApiAuth {
            token: token.filter(|t| !t.is_empty()),
        }
    }

    /// `NUMA_API_TOKEN` wins over config so secrets can be injected at runtime.
    pub fn resolve_token(config_token: &Option<String>) -> Option<String> {
        std::env::var(TOKEN_ENV)
            .ok()
            .filter(|t| !t.is_empty())
            .or_else(|| config_token.clone())
    }

    /// Drives the startup guard: a non-loopback bind with no token is refused.
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

/// Token from an `Authorization` header: `Bearer <token>`, or `Basic
/// <base64(user:token)>` where the password is the token (username ignored).
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

/// Auth layer over the whole router; `/health` is exempt for liveness probes.
pub async fn require_auth(
    State(auth): State<ApiAuth>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if req.uri().path() == "/health" || auth.permits(peer.ip(), req.headers()) {
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
