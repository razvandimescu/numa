//! Authentication for the HTTP control plane (dashboard + REST API), which can
//! mutate how Numa resolves DNS. Loopback is always allowed (local dashboard +
//! CLI), mirroring `acl.rs`; any other peer must present `api_token` via HTTP
//! `Bearer` or `Basic` (so browsers prompt natively). The token is drive-by
//! protection, not wire encryption — the API is plain HTTP. Because loopback is
//! exempt, a same-host TLS terminator pointed at the loopback API forwards
//! *unauthenticated*; front it via a non-loopback bind instead. See
//! `recipes/dnsdist-front.md`.
//!
//! A token is minted on first start when none is supplied, so no deployment is
//! ever unauthenticated. Numa is a resolver first: nothing here may stop it from
//! starting, or the host loses DNS and with it the means to read the docs.

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use rand_core::{OsRng, TryRngCore};

const TOKEN_ENV: &str = "NUMA_API_TOKEN";
const TOKEN_FILE: &str = "api_token";

/// Set by the `.numa` reverse proxy; trusted only on a loopback peer — see
/// `effective_peer`.
pub(crate) const CLIENT_IP_HEADER: &str = "x-numa-client-ip";

#[derive(Clone)]
pub(crate) struct ApiAuth {
    token: String,
}

impl ApiAuth {
    fn permits(&self, peer: IpAddr, headers: &HeaderMap) -> bool {
        // `effective_peer` may hand back a v4-mapped address, either the raw peer
        // or one parsed out of the header, so canonicalize before judging it.
        effective_peer(peer, headers).to_canonical().is_loopback()
            || credential(headers).is_some_and(|given| ct_eq(&self.token, &given))
    }
}

/// The operator has no other copy of a freshly minted token, so startup must log
/// it; `stored` is `None` when `data_dir` was not writable.
pub(crate) struct MintedToken {
    pub token: String,
    pub stored: Option<PathBuf>,
}

/// Precedence: `NUMA_API_TOKEN` > `[server] api_token` > `<data_dir>/api_token`
/// > freshly minted.
pub(crate) fn ensure_token(
    config_token: Option<&str>,
    data_dir: &Path,
) -> (ApiAuth, Option<MintedToken>) {
    let existing = std::env::var(TOKEN_ENV)
        .ok()
        .filter(|t| !t.is_empty())
        .or_else(|| config_token.filter(|t| !t.is_empty()).map(str::to_string))
        .or_else(|| read_token(&data_dir.join(TOKEN_FILE)));
    if let Some(token) = existing {
        return (ApiAuth { token }, None);
    }

    let token = mint_token();
    let path = data_dir.join(TOKEN_FILE);
    let stored = store_token(&path, &token).is_ok().then_some(path);
    (
        ApiAuth {
            token: token.clone(),
        },
        Some(MintedToken { token, stored }),
    )
}

fn read_token(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn mint_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `create_new` so a concurrent start can't be clobbered, and 0600 *at* creation
/// so the secret is never briefly world-readable.
fn store_token(path: &Path, token: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    writeln!(opts.open(path)?, "{token}")
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

pub(crate) async fn require_auth(
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
        // Name no filesystem path to an unauthenticated caller.
        "unauthorized — numa logs its API token on first start and stores it as `api_token` in \
         its data dir\n",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(token: &str) -> ApiAuth {
        ApiAuth {
            token: token.to_string(),
        }
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
        let a = auth("secret");
        assert!(a.permits(ip("127.0.0.1"), &headers(None)));
        assert!(a.permits(ip("::1"), &headers(None)));
        assert!(a.permits(ip("::ffff:127.0.0.1"), &headers(None)));
    }

    #[test]
    fn non_loopback_requires_credential() {
        let a = auth("secret");
        assert!(!a.permits(ip("203.0.113.7"), &headers(None)));
        assert!(!a.permits(ip("203.0.113.7"), &headers(Some("Bearer wrong"))));
        assert!(a.permits(ip("203.0.113.7"), &headers(Some("Bearer secret"))));
    }

    #[test]
    fn basic_auth_password_is_the_token() {
        let a = auth("secret");
        assert!(a.permits(ip("203.0.113.7"), &headers(Some(&basic("admin", "secret")))));
        assert!(a.permits(ip("203.0.113.7"), &headers(Some(&basic("", "secret")))));
        assert!(!a.permits(ip("203.0.113.7"), &headers(Some(&basic("secret", "")))));
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
        let a = auth("secret");
        assert!(!a.permits(ip("127.0.0.1"), &with_client_ip("192.168.1.9")));
    }

    #[test]
    fn malformed_authorization_is_rejected() {
        let a = auth("secret");
        for bad in ["", "secret", "Bearer", "Basic !!!", "Basic", "Token secret"] {
            assert!(
                !a.permits(ip("203.0.113.7"), &headers(Some(bad))),
                "{bad:?} must not authenticate"
            );
        }
    }

    fn fresh_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "numa-api-token-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn bearer(token: &str) -> HeaderMap {
        headers(Some(&format!("Bearer {token}")))
    }

    #[test]
    fn mints_persists_and_reuses_the_token() {
        let dir = fresh_dir("mint");
        let (first, minted) = ensure_token(None, &dir);
        let minted = minted.expect("first start must mint a token");
        assert_eq!(minted.stored, Some(dir.join(TOKEN_FILE)));
        assert_eq!(minted.token.len(), 64, "32 random bytes as hex");
        assert!(minted.token.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(first.permits(ip("203.0.113.7"), &bearer(&minted.token)));

        let (second, again) = ensure_token(None, &dir);
        assert!(again.is_none(), "restart must not mint again");
        assert!(
            second.permits(ip("203.0.113.7"), &bearer(&minted.token)),
            "restart must not invalidate the operator's token"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn configured_token_wins_over_persisted_and_empty_falls_through() {
        let dir = fresh_dir("cfg");
        ensure_token(None, &dir);

        let (auth, minted) = ensure_token(Some("configured"), &dir);
        assert!(minted.is_none());
        assert!(auth.permits(ip("203.0.113.7"), &bearer("configured")));

        let (_, minted) = ensure_token(Some(""), &dir);
        assert!(
            minted.is_none(),
            "an empty api_token is not a credential, and the stored one still stands"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unwritable_data_dir_still_yields_a_token() {
        // data_dir is a *file*, so create_dir_all fails. Numa must still start:
        // a resolver that won't run costs the host its DNS.
        let dir = fresh_dir("unwritable");
        let blocker = dir.join("not-a-dir");
        std::fs::write(&blocker, b"x").unwrap();

        let (auth, minted) = ensure_token(None, &blocker);
        let minted = minted.expect("must mint in memory when the data dir is unusable");
        assert!(minted.stored.is_none(), "nothing could be persisted");
        assert!(auth.permits(ip("203.0.113.7"), &bearer(&minted.token)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn stored_token_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_dir("perms");
        ensure_token(None, &dir);
        let mode = std::fs::metadata(dir.join(TOKEN_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
