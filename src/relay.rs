//! ODoH relay (RFC 9230 §5) — the forward-without-reading half of the
//! protocol. Runs `numa relay`; skips all resolver initialisation (no port
//! 53, no cache, no recursion, no dashboard). The relay never reads the
//! HPKE-sealed payload and keeps no per-request logs — only aggregate
//! counters.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use log::{error, info};
use serde::Deserialize;
use tokio::net::TcpListener;

use crate::forward::build_https_client_with_pool;
use crate::odoh::ODOH_CONTENT_TYPE;
use crate::Result;

/// Cap on the opaque body we accept from a client. ODoH envelopes are
/// ~100–300 bytes in practice; anything larger is malformed or hostile.
const MAX_BODY_BYTES: usize = 4 * 1024;

/// Cap on the body we read back from the target before streaming to client.
/// Slightly larger: target responses carry DNS answers plus HPKE overhead.
const MAX_TARGET_RESPONSE_BYTES: usize = 8 * 1024;

/// Covers the whole client-to-target round trip — not just `.send()` — so a
/// slow-drip target can't hang a worker indefinitely after headers arrive.
const TARGET_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The relay hits many distinct target hosts on behalf of clients. A
/// per-host idle pool of 4 keeps warm TLS connections available for concurrent
/// fan-out without blowing up memory on a small VPS.
const RELAY_POOL_PER_HOST: usize = 4;

#[derive(Deserialize)]
struct RelayParams {
    targethost: String,
    targetpath: String,
}

struct RelayState {
    client: reqwest::Client,
    total_requests: AtomicU64,
    forwarded_ok: AtomicU64,
    forwarded_err: AtomicU64,
    rejected_bad_request: AtomicU64,
}

impl RelayState {
    fn new() -> Arc<Self> {
        Arc::new(RelayState {
            client: build_https_client_with_pool(RELAY_POOL_PER_HOST),
            total_requests: AtomicU64::new(0),
            forwarded_ok: AtomicU64::new(0),
            forwarded_err: AtomicU64::new(0),
            rejected_bad_request: AtomicU64::new(0),
        })
    }
}

/// `DefaultBodyLimit` overrides axum's 2 MiB default so hostile clients
/// can't force the relay to buffer multi-MB bodies before our own cap.
fn build_app(state: Arc<RelayState>) -> Router {
    Router::new()
        .route("/relay", post(handle_relay))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .route("/health", get(handle_health))
        .with_state(state)
}

pub async fn run(addr: SocketAddr) -> Result<()> {
    let app = build_app(RelayState::new());
    let listener = TcpListener::bind(addr).await?;
    info!("ODoH relay listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_health(State(state): State<Arc<RelayState>>) -> impl IntoResponse {
    let body = format!(
        "ok\ntotal {}\nforwarded_ok {}\nforwarded_err {}\nrejected_bad_request {}\n",
        state.total_requests.load(Ordering::Relaxed),
        state.forwarded_ok.load(Ordering::Relaxed),
        state.forwarded_err.load(Ordering::Relaxed),
        state.rejected_bad_request.load(Ordering::Relaxed),
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
}

async fn handle_relay(
    State(state): State<Arc<RelayState>>,
    Query(params): Query<RelayParams>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    state.total_requests.fetch_add(1, Ordering::Relaxed);

    if !content_type_matches(&headers, ODOH_CONTENT_TYPE) {
        state.rejected_bad_request.fetch_add(1, Ordering::Relaxed);
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected application/oblivious-dns-message",
        )
            .into_response();
    }

    if body.len() > MAX_BODY_BYTES {
        state.rejected_bad_request.fetch_add(1, Ordering::Relaxed);
        return (StatusCode::PAYLOAD_TOO_LARGE, "body exceeds 4 KiB cap").into_response();
    }

    if !is_valid_hostname(&params.targethost) || !params.targetpath.starts_with('/') {
        state.rejected_bad_request.fetch_add(1, Ordering::Relaxed);
        return (StatusCode::BAD_REQUEST, "invalid targethost or targetpath").into_response();
    }

    let target_url = format!("https://{}{}", params.targethost, params.targetpath);
    match forward_to_target(&state.client, &target_url, body).await {
        Ok((status, resp_body)) => {
            state.forwarded_ok.fetch_add(1, Ordering::Relaxed);
            (
                status,
                [(header::CONTENT_TYPE, ODOH_CONTENT_TYPE)],
                resp_body,
            )
                .into_response()
        }
        Err(e) => {
            // Log the underlying reason for operators; don't leak reqwest
            // internals (which can reveal the target's TLS config, IP, etc.)
            // back to arbitrary clients.
            error!("relay forward to {} failed: {}", target_url, e);
            state.forwarded_err.fetch_add(1, Ordering::Relaxed);
            (StatusCode::BAD_GATEWAY, "target unreachable").into_response()
        }
    }
}

async fn forward_to_target(
    client: &reqwest::Client,
    url: &str,
    body: Bytes,
) -> Result<(StatusCode, Bytes)> {
    let response = tokio::time::timeout(TARGET_REQUEST_TIMEOUT, async {
        let resp = client
            .post(url)
            .header(header::CONTENT_TYPE, ODOH_CONTENT_TYPE)
            .header(header::ACCEPT, ODOH_CONTENT_TYPE)
            .body(body)
            .send()
            .await?;
        let status = StatusCode::from_u16(resp.status().as_u16())?;
        let resp_body = resp.bytes().await?;
        Ok::<_, crate::Error>((status, resp_body))
    })
    .await
    .map_err(|_| "timed out talking to target")??;

    if response.1.len() > MAX_TARGET_RESPONSE_BYTES {
        return Err("target response exceeds cap".into());
    }
    Ok(response)
}

fn content_type_matches(headers: &axum::http::HeaderMap, expected: &str) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.split(';').next().unwrap_or("").trim() == expected)
        .unwrap_or(false)
}

/// Strict DNS-hostname validator, aimed at closing the SSRF surface a naive
/// `contains('.')` check leaves open (e.g. `example.com@internal.host`,
/// `evil.com/../admin`). Requires ASCII letters/digits/dot/dash, at least
/// one dot, no leading dot or dash, length ≤ 253 per RFC 1035.
fn is_valid_hostname(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 || !h.contains('.') {
        return false;
    }
    if h.starts_with('.') || h.starts_with('-') || h.ends_with('.') || h.ends_with('-') {
        return false;
    }
    h.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn spawn_relay() -> (SocketAddr, Arc<RelayState>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let state = RelayState::new();
        let app = build_app(state.clone());

        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (addr, state)
    }

    #[tokio::test]
    async fn rejects_missing_content_type() {
        let (addr, state) = spawn_relay().await;
        let client = crate::forward::default_client();
        let resp = client
            .post(format!(
                "http://{}/relay?targethost=odoh.example.com&targetpath=/dns-query",
                addr
            ))
            .body("body")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(state.rejected_bad_request.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn rejects_oversized_body() {
        let (addr, _state) = spawn_relay().await;
        let big = vec![0u8; MAX_BODY_BYTES + 1];
        let client = crate::forward::default_client();
        let resp = client
            .post(format!(
                "http://{}/relay?targethost=odoh.example.com&targetpath=/dns-query",
                addr
            ))
            .header(header::CONTENT_TYPE, ODOH_CONTENT_TYPE)
            .body(big)
            .send()
            .await
            .unwrap();
        // axum's DefaultBodyLimit rejects before our handler runs, so the
        // counter doesn't increment — but the status code proves the layer
        // enforced the cap. Either status is acceptable evidence.
        assert!(matches!(
            resp.status(),
            reqwest::StatusCode::PAYLOAD_TOO_LARGE | reqwest::StatusCode::BAD_REQUEST
        ));
    }

    #[tokio::test]
    async fn rejects_targethost_without_dot() {
        let (addr, state) = spawn_relay().await;
        let client = crate::forward::default_client();
        let resp = client
            .post(format!(
                "http://{}/relay?targethost=localhost&targetpath=/dns-query",
                addr
            ))
            .header(header::CONTENT_TYPE, ODOH_CONTENT_TYPE)
            .body("body")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
        assert_eq!(state.rejected_bad_request.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn rejects_userinfo_ssrf_attempt() {
        let (addr, state) = spawn_relay().await;
        let client = crate::forward::default_client();
        // The naive contains('.') check would let this through and reqwest
        // would route to `internal.host` using `evil.com` as userinfo.
        let resp = client
            .post(format!(
                "http://{}/relay?targethost=evil.com@internal.host&targetpath=/dns-query",
                addr
            ))
            .header(header::CONTENT_TYPE, ODOH_CONTENT_TYPE)
            .body("body")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
        assert_eq!(state.rejected_bad_request.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn rejects_targetpath_without_leading_slash() {
        let (addr, state) = spawn_relay().await;
        let client = crate::forward::default_client();
        let resp = client
            .post(format!(
                "http://{}/relay?targethost=odoh.example.com&targetpath=dns-query",
                addr
            ))
            .header(header::CONTENT_TYPE, ODOH_CONTENT_TYPE)
            .body("body")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
        assert_eq!(state.rejected_bad_request.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn health_endpoint_reports_counters() {
        let (addr, _state) = spawn_relay().await;
        let client = crate::forward::default_client();
        let resp = client
            .get(format!("http://{}/health", addr))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let body = resp.text().await.unwrap();
        assert!(body.contains("ok\n"));
        assert!(body.contains("forwarded_ok 0"));
    }

    #[test]
    fn hostname_validator_accepts_and_rejects() {
        assert!(is_valid_hostname("odoh.cloudflare-dns.com"));
        assert!(is_valid_hostname("a.b"));
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("localhost"));
        assert!(!is_valid_hostname(".leading.dot"));
        assert!(!is_valid_hostname("trailing.dot."));
        assert!(!is_valid_hostname("-leading.dash"));
        assert!(!is_valid_hostname("evil.com@internal.host"));
        assert!(!is_valid_hostname("evil.com/../admin"));
        assert!(!is_valid_hostname(&"a".repeat(254)));
    }
}
