//! Mobile API — persistent HTTP listener for iOS/Android companion apps.
//!
//! Read-only subset of Numa's HTTP surface served on a separate port
//! (default 8765) bound to the LAN. Unlike the main API on port 5380
//! (which defaults to `127.0.0.1` and serves mutating routes like
//! `DELETE /services/{name}` or `PUT /blocking/toggle`), this listener
//! is safe to expose on the LAN because every route is idempotent and
//! read-only.
//!
//! Routes (all GET):
//!
//! - `/health` — enriched status + metadata, shares the handler with the
//!   main API via `crate::api::health`
//! - `/ca.pem` — Numa local CA in PEM form, shares the handler with the
//!   main API via `crate::api::serve_ca`
//! - `/mobileconfig` — combined CA + DNS settings profile (Full mode)
//! - `/ca.mobileconfig` — CA-only trust profile (no DNS override)
//!
//! The mobile API does NOT include the mutating routes (overrides, cache
//! flush, blocking toggle, service CRUD, etc.). Even if a user sets
//! `api_bind_addr` to `0.0.0.0` for the main API, those routes stay on
//! port 5380; the mobile API on port 8765 never serves them. This is the
//! primary security boundary: anything exposed to the LAN is read-only.

use std::net::Ipv4Addr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use log::info;

use crate::ctx::ServerCtx;
use crate::mobileconfig::{build_mobileconfig, ProfileMode};

/// Content-Disposition for the full CA + DNS profile download.
const FULL_PROFILE_DISPOSITION: &str = "attachment; filename=\"numa.mobileconfig\"";

/// Content-Disposition for the CA-only profile download.
const CA_ONLY_PROFILE_DISPOSITION: &str = "attachment; filename=\"numa-ca.mobileconfig\"";

/// Build the axum router for the mobile API.
///
/// Shares handler functions with the main API where possible (`health`,
/// `serve_ca`) so the response shapes are identical across both ports.
pub fn router(ctx: Arc<ServerCtx>) -> Router {
    Router::new()
        .route("/health", get(crate::api::health))
        .route("/ca.pem", get(crate::api::serve_ca))
        .route("/mobileconfig", get(serve_full_mobileconfig))
        .route("/ca.mobileconfig", get(serve_ca_only_mobileconfig))
        .with_state(ctx)
}

/// Start the mobile API listener on `bind_addr:port`. Runs until the
/// caller cancels the spawned task. Logs the URL on successful bind.
pub async fn start(ctx: Arc<ServerCtx>, bind_addr: String, port: u16) -> crate::Result<()> {
    let addr: std::net::SocketAddr = format!("{}:{}", bind_addr, port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!("Mobile API listening on http://{}", addr);

    let app = router(ctx);
    axum::serve(listener, app).await?;

    Ok(())
}

/// Serve the full mobileconfig profile (CA + DNS settings), with the
/// DNS payload pointing at the current LAN IP. Each request reads the
/// fresh LAN IP from `ctx.lan_ip` so the profile always reflects the
/// laptop's current network state.
async fn serve_full_mobileconfig(
    State(ctx): State<Arc<ServerCtx>>,
) -> Result<impl IntoResponse, StatusCode> {
    let ca_pem = ctx.ca_pem.as_deref().ok_or(StatusCode::NOT_FOUND)?;
    let lan_ip: Ipv4Addr = *ctx.lan_ip.lock().unwrap();
    let profile = build_mobileconfig(ProfileMode::Full { lan_ip }, ca_pem);
    Ok(profile_response(profile, FULL_PROFILE_DISPOSITION))
}

/// Serve the CA-only mobileconfig profile. Trusts the Numa local CA but
/// does NOT change the device's DNS settings. Used by the iOS companion
/// app's DoT mode, where the app configures DNS via `NEDNSSettingsManager`
/// and only needs the system trust store to accept Numa's self-signed cert.
async fn serve_ca_only_mobileconfig(
    State(ctx): State<Arc<ServerCtx>>,
) -> Result<impl IntoResponse, StatusCode> {
    let ca_pem = ctx.ca_pem.as_deref().ok_or(StatusCode::NOT_FOUND)?;
    let profile = build_mobileconfig(ProfileMode::CaOnly, ca_pem);
    Ok(profile_response(profile, CA_ONLY_PROFILE_DISPOSITION))
}

/// Shared response constructor for both mobileconfig variants.
/// Identical headers; only the Content-Disposition filename differs.
fn profile_response(profile: String, disposition: &'static str) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/x-apple-aspen-config"),
            (header::CONTENT_DISPOSITION, disposition),
            (header::CACHE_CONTROL, "no-store"),
        ],
        profile,
    )
}
