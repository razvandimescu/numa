use std::sync::Arc;
use std::time::UNIX_EPOCH;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::ctx::ServerCtx;
use crate::forward::{forward_query, Upstream};
use crate::query_log::QueryLogFilter;
use crate::question::QueryType;
use crate::stats::QueryPath;

const DASHBOARD_HTML: &str = include_str!("../site/dashboard.html");
const FONTS_CSS: &str = include_str!("../site/fonts/fonts.css");
const FONT_DM_SANS: &[u8] = include_bytes!("../site/fonts/dm-sans-latin.woff2");
const FONT_DM_SANS_ITALIC: &[u8] = include_bytes!("../site/fonts/dm-sans-italic-latin.woff2");
const FONT_INSTRUMENT: &[u8] = include_bytes!("../site/fonts/instrument-serif-latin.woff2");
const FONT_INSTRUMENT_ITALIC: &[u8] =
    include_bytes!("../site/fonts/instrument-serif-italic-latin.woff2");
const FONT_JETBRAINS: &[u8] = include_bytes!("../site/fonts/jetbrains-mono-latin.woff2");

pub fn router(ctx: Arc<ServerCtx>) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/overrides", post(create_overrides))
        .route("/overrides", get(list_overrides))
        .route("/overrides", delete(clear_overrides))
        .route("/overrides/environment", post(load_environment))
        .route("/overrides/{domain}", get(get_override))
        .route("/overrides/{domain}", delete(remove_override))
        .route("/diagnose/{domain}", get(diagnose))
        .route("/query-log", get(query_log))
        .route("/stats", get(stats))
        .route("/cache", get(list_cache))
        .route("/cache", delete(flush_cache))
        .route("/cache/{domain}", delete(flush_cache_domain))
        .route("/health", get(health))
        .route("/blocking/stats", get(blocking_stats))
        .route("/blocking/toggle", put(blocking_toggle))
        .route("/blocking/pause", post(blocking_pause))
        .route("/blocking/unpause", post(blocking_unpause))
        .route("/blocking/allowlist", get(blocking_allowlist))
        .route("/blocking/allowlist", post(blocking_allowlist_add))
        .route("/blocking/check/{domain}", get(blocking_check))
        .route(
            "/blocking/allowlist/{domain}",
            delete(blocking_allowlist_remove),
        )
        .route("/services", get(list_services))
        .route("/services", post(create_service))
        .route("/services/{name}", delete(remove_service))
        .route("/services/{name}/routes", get(list_routes))
        .route("/services/{name}/routes", post(add_route))
        .route("/services/{name}/routes", delete(remove_route))
        .route("/ca.pem", get(serve_ca))
        .route("/qr", get(serve_qr))
        .route("/fonts/fonts.css", get(serve_fonts_css))
        .route(
            "/fonts/dm-sans-latin.woff2",
            get(|| async { serve_font(FONT_DM_SANS) }),
        )
        .route(
            "/fonts/dm-sans-italic-latin.woff2",
            get(|| async { serve_font(FONT_DM_SANS_ITALIC) }),
        )
        .route(
            "/fonts/instrument-serif-latin.woff2",
            get(|| async { serve_font(FONT_INSTRUMENT) }),
        )
        .route(
            "/fonts/instrument-serif-italic-latin.woff2",
            get(|| async { serve_font(FONT_INSTRUMENT_ITALIC) }),
        )
        .route(
            "/fonts/jetbrains-mono-latin.woff2",
            get(|| async { serve_font(FONT_JETBRAINS) }),
        )
        .with_state(ctx)
}

async fn dashboard() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        DASHBOARD_HTML,
    )
}

// --- Request/Response DTOs ---

#[derive(Deserialize)]
struct CreateOverrideRequest {
    domain: String,
    target: String,
    #[serde(default = "default_ttl")]
    ttl: u32,
    duration_secs: Option<u64>,
}

fn default_ttl() -> u32 {
    60
}

#[derive(Serialize)]
struct OverrideResponse {
    domain: String,
    target: String,
    record_type: String,
    ttl: u32,
    remaining_secs: Option<u64>,
}

impl From<&crate::override_store::OverrideEntry> for OverrideResponse {
    fn from(e: &crate::override_store::OverrideEntry) -> Self {
        OverrideResponse {
            domain: e.domain.clone(),
            target: e.target.clone(),
            record_type: e.query_type.as_str().to_string(),
            ttl: e.ttl,
            remaining_secs: e.remaining_secs(),
        }
    }
}

#[derive(Deserialize)]
struct EnvironmentRequest {
    #[serde(default)]
    duration_secs: Option<u64>,
    overrides: Vec<CreateOverrideRequest>,
}

#[derive(Serialize)]
struct EnvironmentResponse {
    created: usize,
}

#[derive(Deserialize)]
struct QueryLogParams {
    domain: Option<String>,
    r#type: Option<String>,
    path: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct QueryLogResponse {
    timestamp_epoch: f64,
    src: String,
    domain: String,
    query_type: String,
    path: String,
    rescode: String,
    latency_ms: f64,
    dnssec: String,
}

#[derive(Serialize)]
struct StatsResponse {
    uptime_secs: u64,
    upstream: String,
    mode: &'static str, // "recursive" or "forward" — never "auto" at runtime
    config_path: String,
    data_dir: String,
    dnssec: bool,
    srtt: bool,
    queries: QueriesStats,
    cache: CacheStats,
    overrides: OverrideStats,
    blocking: BlockingStatsResponse,
    lan: LanStatsResponse,
    mobile: MobileStatsResponse,
    memory: MemoryStats,
}

#[derive(Serialize)]
struct MobileStatsResponse {
    enabled: bool,
    port: u16,
}

#[derive(Serialize)]
struct LanStatsResponse {
    enabled: bool,
    peers: usize,
}

#[derive(Serialize)]
struct QueriesStats {
    total: u64,
    forwarded: u64,
    recursive: u64,
    coalesced: u64,
    cached: u64,
    local: u64,
    overridden: u64,
    blocked: u64,
    errors: u64,
}

#[derive(Serialize)]
struct CacheStats {
    entries: usize,
    max_entries: usize,
}

#[derive(Serialize)]
struct OverrideStats {
    active: usize,
}

#[derive(Serialize)]
struct BlockingStatsResponse {
    enabled: bool,
    paused: bool,
    domains_loaded: usize,
    allowlist_size: usize,
}

#[derive(Serialize)]
struct MemoryStats {
    cache_bytes: usize,
    blocklist_bytes: usize,
    query_log_bytes: usize,
    query_log_entries: usize,
    srtt_bytes: usize,
    srtt_entries: usize,
    overrides_bytes: usize,
    total_estimated_bytes: usize,
    process_memory_bytes: usize,
}

#[derive(Serialize)]
struct DiagnoseResponse {
    domain: String,
    query_type: String,
    steps: Vec<DiagnoseStep>,
}

#[derive(Serialize)]
struct DiagnoseStep {
    source: String,
    matched: bool,
    detail: Option<String>,
}

#[derive(Serialize)]
struct CacheEntryResponse {
    domain: String,
    query_type: String,
    ttl_remaining: u32,
}

// --- Handlers ---

async fn create_overrides(
    State(ctx): State<Arc<ServerCtx>>,
    Json(req): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<Vec<OverrideResponse>>), (StatusCode, String)> {
    let requests: Vec<CreateOverrideRequest> = if req.is_array() {
        serde_json::from_value(req).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    } else {
        let single: CreateOverrideRequest =
            serde_json::from_value(req).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        vec![single]
    };

    // Parse and validate all requests before acquiring the lock
    let parsed: Vec<_> = requests
        .into_iter()
        .map(|req| {
            let domain_lower = req.domain.to_lowercase();
            Ok((domain_lower, req.target, req.ttl, req.duration_secs))
        })
        .collect::<Result<Vec<_>, (StatusCode, String)>>()?;

    let mut store = ctx.overrides.write().unwrap();
    let mut responses = Vec::with_capacity(parsed.len());

    for (domain, target, ttl, duration_secs) in parsed {
        let qtype = store
            .insert(&domain, &target, ttl, duration_secs)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        responses.push(OverrideResponse {
            domain,
            target,
            record_type: qtype.as_str().to_string(),
            ttl,
            remaining_secs: duration_secs,
        });
    }

    Ok((StatusCode::CREATED, Json(responses)))
}

async fn list_overrides(State(ctx): State<Arc<ServerCtx>>) -> Json<Vec<OverrideResponse>> {
    let store = ctx.overrides.read().unwrap();
    let entries: Vec<OverrideResponse> = store
        .list()
        .into_iter()
        .map(OverrideResponse::from)
        .collect();
    Json(entries)
}

async fn get_override(
    State(ctx): State<Arc<ServerCtx>>,
    Path(domain): Path<String>,
) -> Result<Json<OverrideResponse>, StatusCode> {
    let store = ctx.overrides.read().unwrap();
    let entry = store.get(&domain).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(OverrideResponse::from(entry)))
}

async fn remove_override(
    State(ctx): State<Arc<ServerCtx>>,
    Path(domain): Path<String>,
) -> StatusCode {
    let mut store = ctx.overrides.write().unwrap();
    if store.remove(&domain) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn clear_overrides(State(ctx): State<Arc<ServerCtx>>) -> StatusCode {
    ctx.overrides.write().unwrap().clear();
    StatusCode::NO_CONTENT
}

async fn load_environment(
    State(ctx): State<Arc<ServerCtx>>,
    Json(req): Json<EnvironmentRequest>,
) -> Result<(StatusCode, Json<EnvironmentResponse>), (StatusCode, String)> {
    let mut store = ctx.overrides.write().unwrap();

    for entry in &req.overrides {
        let duration = entry.duration_secs.or(req.duration_secs);
        store
            .insert(&entry.domain, &entry.target, entry.ttl, duration)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    }

    Ok((
        StatusCode::CREATED,
        Json(EnvironmentResponse {
            created: req.overrides.len(),
        }),
    ))
}

async fn diagnose(
    State(ctx): State<Arc<ServerCtx>>,
    Path(domain): Path<String>,
) -> Json<DiagnoseResponse> {
    let domain_lower = domain.to_lowercase();
    let qtype = QueryType::A;
    let mut steps = Vec::new();

    // Check overrides
    {
        let store = ctx.overrides.read().unwrap();
        let entry = store.get(&domain_lower);
        steps.push(DiagnoseStep {
            source: "override".to_string(),
            matched: entry.is_some(),
            detail: entry
                .map(|e| format!("{} -> {} ({})", e.domain, e.target, e.query_type.as_str())),
        });
    }

    // Check blocklist
    {
        let bl = ctx.blocklist.read().unwrap();
        let blocked = bl.is_blocked(&domain_lower);
        steps.push(DiagnoseStep {
            source: "blocklist".to_string(),
            matched: blocked,
            detail: if blocked {
                Some("domain is in blocklist".to_string())
            } else {
                None
            },
        });
    }

    // Check local zones
    let zone_match = ctx
        .zone_map
        .get(domain_lower.as_str())
        .and_then(|m| m.get(&qtype));
    steps.push(DiagnoseStep {
        source: "local_zone".to_string(),
        matched: zone_match.is_some(),
        detail: zone_match.map(|records| format!("{} records", records.len())),
    });

    // Check cache
    {
        let cache = ctx.cache.read().unwrap();
        let cached = cache.lookup(&domain_lower, qtype);
        steps.push(DiagnoseStep {
            source: "cache".to_string(),
            matched: cached.is_some(),
            detail: cached.map(|p| format!("{} answers", p.answers.len())),
        });
    }

    // Check upstream (async, no locks held)
    let upstream = ctx.upstream_pool.lock().unwrap().preferred().cloned();
    let (upstream_matched, upstream_detail) = if let Some(ref u) = upstream {
        forward_query_for_diagnose(&domain_lower, u, ctx.timeout).await
    } else {
        (false, "no upstream configured".to_string())
    };
    steps.push(DiagnoseStep {
        source: "upstream".to_string(),
        matched: upstream_matched,
        detail: Some(upstream_detail),
    });

    Json(DiagnoseResponse {
        domain: domain_lower,
        query_type: qtype.as_str().to_string(),
        steps,
    })
}

async fn forward_query_for_diagnose(
    domain: &str,
    upstream: &Upstream,
    timeout: std::time::Duration,
) -> (bool, String) {
    use crate::packet::DnsPacket;

    let query = DnsPacket::query(0xBEEF, domain, QueryType::A);

    match forward_query(&query, upstream, timeout).await {
        Ok(resp) => (
            true,
            format!(
                "{} ({} answers)",
                resp.header.rescode.as_str(),
                resp.answers.len()
            ),
        ),
        Err(e) => (false, format!("error: {}", e)),
    }
}

async fn query_log(
    State(ctx): State<Arc<ServerCtx>>,
    Query(params): Query<QueryLogParams>,
) -> Json<Vec<QueryLogResponse>> {
    let qtype = params.r#type.as_deref().and_then(QueryType::parse_str);
    let path = params.path.as_deref().and_then(QueryPath::parse_str);

    let filter = QueryLogFilter {
        domain: params.domain,
        query_type: qtype,
        path,
        since: None,
        limit: params.limit,
    };

    let raw_entries: Vec<QueryLogResponse> = {
        let log = ctx.query_log.lock().unwrap();
        log.query(&filter)
            .into_iter()
            .map(|e| {
                let epoch = e
                    .timestamp
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64();
                QueryLogResponse {
                    timestamp_epoch: epoch,
                    src: e.src_addr.to_string(),
                    domain: e.domain.clone(),
                    query_type: e.query_type.as_str().to_string(),
                    path: e.path.as_str().to_string(),
                    rescode: e.rescode.as_str().to_string(),
                    latency_ms: e.latency_us as f64 / 1000.0,
                    dnssec: e.dnssec.as_str().to_string(),
                }
            })
            .collect()
    };

    Json(raw_entries)
}

async fn stats(State(ctx): State<Arc<ServerCtx>>) -> Json<StatsResponse> {
    let snap = ctx.stats.lock().unwrap().snapshot();
    let (cache_len, cache_max, cache_bytes) = {
        let cache = ctx.cache.read().unwrap();
        (cache.len(), cache.max_entries(), cache.heap_bytes())
    };
    let (override_count, overrides_bytes) = {
        let ov = ctx.overrides.read().unwrap();
        (ov.active_count(), ov.heap_bytes())
    };
    let (bl_stats, blocklist_bytes) = {
        let bl = ctx.blocklist.read().unwrap();
        (bl.stats(), bl.heap_bytes())
    };
    let (query_log_bytes, query_log_entries) = {
        let log = ctx.query_log.lock().unwrap();
        (log.heap_bytes(), log.len())
    };
    let (srtt_bytes, srtt_entries, srtt_enabled) = {
        let s = ctx.srtt.read().unwrap();
        (s.heap_bytes(), s.len(), s.is_enabled())
    };

    let total_estimated =
        cache_bytes + blocklist_bytes + query_log_bytes + srtt_bytes + overrides_bytes;

    let upstream = if ctx.upstream_mode == crate::config::UpstreamMode::Recursive {
        "recursive (root hints)".to_string()
    } else {
        ctx.upstream_pool.lock().unwrap().label()
    };

    Json(StatsResponse {
        uptime_secs: snap.uptime_secs,
        upstream,
        mode: ctx.upstream_mode.as_str(),
        config_path: ctx.config_path.clone(),
        data_dir: ctx.data_dir.to_string_lossy().to_string(),
        dnssec: ctx.dnssec_enabled,
        srtt: srtt_enabled,
        queries: QueriesStats {
            total: snap.total,
            forwarded: snap.forwarded,
            recursive: snap.recursive,
            coalesced: snap.coalesced,
            cached: snap.cached,
            local: snap.local,
            overridden: snap.overridden,
            blocked: snap.blocked,
            errors: snap.errors,
        },
        cache: CacheStats {
            entries: cache_len,
            max_entries: cache_max,
        },
        overrides: OverrideStats {
            active: override_count,
        },
        blocking: BlockingStatsResponse {
            enabled: bl_stats.enabled,
            paused: bl_stats.paused,
            domains_loaded: bl_stats.domains_loaded,
            allowlist_size: bl_stats.allowlist_size,
        },
        lan: LanStatsResponse {
            enabled: ctx.lan_enabled,
            peers: ctx.lan_peers.lock().unwrap().list().len(),
        },
        mobile: MobileStatsResponse {
            enabled: ctx.mobile_enabled,
            port: ctx.mobile_port,
        },
        memory: MemoryStats {
            cache_bytes,
            blocklist_bytes,
            query_log_bytes,
            query_log_entries,
            srtt_bytes,
            srtt_entries,
            overrides_bytes,
            total_estimated_bytes: total_estimated,
            process_memory_bytes: crate::stats::process_memory_bytes(),
        },
    })
}

async fn list_cache(State(ctx): State<Arc<ServerCtx>>) -> Json<Vec<CacheEntryResponse>> {
    let cache = ctx.cache.read().unwrap();
    let entries: Vec<CacheEntryResponse> = cache
        .list()
        .into_iter()
        .map(|info| CacheEntryResponse {
            domain: info.domain,
            query_type: info.query_type.as_str().to_string(),
            ttl_remaining: info.ttl_remaining,
        })
        .collect();
    Json(entries)
}

async fn flush_cache(State(ctx): State<Arc<ServerCtx>>) -> StatusCode {
    ctx.cache.write().unwrap().clear();
    StatusCode::NO_CONTENT
}

async fn flush_cache_domain(
    State(ctx): State<Arc<ServerCtx>>,
    Path(domain): Path<String>,
) -> StatusCode {
    ctx.cache.write().unwrap().remove(&domain);
    StatusCode::NO_CONTENT
}

/// Enriched `/health` handler shared between the main API and the mobile API.
///
/// Returns the cached `HealthMeta` assembled with live fields (LAN IP,
/// uptime). Backward compatible with the previous minimal response in
/// that `status` is still the first field and `"ok"` is still the value.
/// The iOS companion app's `HealthInfo` Swift struct decodes the full
/// response; any HTTP client asserting only on `"status"` keeps working.
pub async fn health(State(ctx): State<Arc<ServerCtx>>) -> Json<crate::health::HealthResponse> {
    let lan_ip = Some(*ctx.lan_ip.lock().unwrap());
    Json(crate::health::HealthResponse::build(
        &ctx.health_meta,
        lan_ip,
    ))
}

// --- Blocking handlers ---

async fn blocking_stats(State(ctx): State<Arc<ServerCtx>>) -> Json<serde_json::Value> {
    let stats = ctx.blocklist.read().unwrap().stats();
    Json(serde_json::json!({
        "enabled": stats.enabled,
        "paused": stats.paused,
        "domains_loaded": stats.domains_loaded,
        "allowlist_size": stats.allowlist_size,
        "list_sources": stats.list_sources,
        "last_refresh_secs_ago": stats.last_refresh_secs_ago,
    }))
}

#[derive(Deserialize)]
struct BlockingToggleRequest {
    enabled: bool,
}

async fn blocking_toggle(
    State(ctx): State<Arc<ServerCtx>>,
    Json(req): Json<BlockingToggleRequest>,
) -> Json<serde_json::Value> {
    ctx.blocklist.write().unwrap().set_enabled(req.enabled);
    Json(serde_json::json!({ "enabled": req.enabled }))
}

#[derive(Deserialize)]
struct BlockingPauseRequest {
    #[serde(default = "default_pause_minutes")]
    minutes: u64,
}

fn default_pause_minutes() -> u64 {
    5
}

async fn blocking_pause(
    State(ctx): State<Arc<ServerCtx>>,
    Json(req): Json<BlockingPauseRequest>,
) -> Json<serde_json::Value> {
    ctx.blocklist.write().unwrap().pause(req.minutes * 60);
    Json(serde_json::json!({ "paused_minutes": req.minutes }))
}

async fn blocking_unpause(State(ctx): State<Arc<ServerCtx>>) -> Json<serde_json::Value> {
    ctx.blocklist.write().unwrap().unpause();
    Json(serde_json::json!({ "paused": false }))
}

async fn blocking_check(
    State(ctx): State<Arc<ServerCtx>>,
    Path(domain): Path<String>,
) -> Json<crate::blocklist::BlockCheckResult> {
    let result = ctx.blocklist.read().unwrap().check(&domain);
    Json(result)
}

async fn blocking_allowlist(State(ctx): State<Arc<ServerCtx>>) -> Json<Vec<String>> {
    let list = ctx.blocklist.read().unwrap().allowlist();
    Json(list)
}

#[derive(Deserialize)]
struct AllowlistRequest {
    domain: String,
}

async fn blocking_allowlist_add(
    State(ctx): State<Arc<ServerCtx>>,
    Json(req): Json<AllowlistRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    ctx.blocklist.write().unwrap().add_to_allowlist(&req.domain);
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "allowed": req.domain })),
    )
}

async fn blocking_allowlist_remove(
    State(ctx): State<Arc<ServerCtx>>,
    Path(domain): Path<String>,
) -> StatusCode {
    if ctx
        .blocklist
        .write()
        .unwrap()
        .remove_from_allowlist(&domain)
    {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

// --- Service proxy handlers ---

#[derive(Serialize)]
struct ServiceResponse {
    name: String,
    target_port: u16,
    url: String,
    healthy: bool,
    lan_accessible: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    routes: Vec<crate::service_store::RouteEntry>,
    source: String,
}

#[derive(Deserialize)]
struct CreateServiceRequest {
    name: String,
    target_port: u16,
}

async fn list_services(State(ctx): State<Arc<ServerCtx>>) -> Json<Vec<ServiceResponse>> {
    let entries: Vec<_> = {
        let store = ctx.services.lock().unwrap();
        store
            .list()
            .into_iter()
            .map(|e| {
                let source = if store.is_config_service(&e.name) {
                    "config"
                } else {
                    "api"
                };
                (
                    e.name.clone(),
                    e.target_port,
                    e.routes.clone(),
                    source.to_string(),
                )
            })
            .collect()
    };
    let tld = &ctx.proxy_tld;

    let lan_ip = crate::lan::detect_lan_ip();

    let check_futures: Vec<_> = entries
        .iter()
        .map(|(_, port, _, _)| {
            let port = *port;
            let localhost = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            let lan_addr = lan_ip.map(|ip| std::net::SocketAddr::new(ip.into(), port));
            async move {
                let healthy = check_tcp(localhost).await;
                let lan_accessible = match lan_addr {
                    Some(addr) => check_tcp(addr).await,
                    None => false,
                };
                (healthy, lan_accessible)
            }
        })
        .collect();
    let check_results = futures::future::join_all(check_futures).await;

    let results: Vec<_> = entries
        .into_iter()
        .zip(check_results)
        .map(
            |((name, port, routes, source), (healthy, lan_accessible))| ServiceResponse {
                url: format!("http://{}.{}", name, tld),
                name,
                target_port: port,
                healthy,
                lan_accessible,
                routes,
                source,
            },
        )
        .collect();
    Json(results)
}

async fn create_service(
    State(ctx): State<Arc<ServerCtx>>,
    Json(req): Json<CreateServiceRequest>,
) -> Result<(StatusCode, Json<ServiceResponse>), (StatusCode, String)> {
    let name = req.name.to_lowercase();

    // Validate name: alphanumeric + hyphens only, 1-63 chars
    if name.is_empty() || name.len() > 63 {
        return Err((
            StatusCode::BAD_REQUEST,
            "name must be 1-63 characters".into(),
        ));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err((
            StatusCode::BAD_REQUEST,
            "name must contain only alphanumeric characters and hyphens".into(),
        ));
    }
    if req.target_port == 0 {
        return Err((StatusCode::BAD_REQUEST, "target_port must be > 0".into()));
    }

    let tld = &ctx.proxy_tld;
    let is_new = !ctx.services.lock().unwrap().has_name(&name);
    ctx.services.lock().unwrap().insert(&name, req.target_port);
    if is_new {
        crate::tls::regenerate_tls(&ctx);
    }

    let localhost = std::net::SocketAddr::from(([127, 0, 0, 1], req.target_port));
    let lan_addr =
        crate::lan::detect_lan_ip().map(|ip| std::net::SocketAddr::new(ip.into(), req.target_port));
    let (healthy, lan_accessible) = tokio::join!(check_tcp(localhost), async {
        match lan_addr {
            Some(a) => check_tcp(a).await,
            None => false,
        }
    });
    Ok((
        StatusCode::CREATED,
        Json(ServiceResponse {
            url: format!("http://{}.{}", name, tld),
            name,
            target_port: req.target_port,
            healthy,
            lan_accessible,
            routes: Vec::new(),
            source: "api".to_string(),
        }),
    ))
}

async fn remove_service(State(ctx): State<Arc<ServerCtx>>, Path(name): Path<String>) -> StatusCode {
    if name.eq_ignore_ascii_case("numa") {
        return StatusCode::FORBIDDEN;
    }
    let removed = ctx.services.lock().unwrap().remove(&name);
    if removed {
        crate::tls::regenerate_tls(&ctx);
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

// --- Route handlers ---

#[derive(Deserialize)]
struct AddRouteRequest {
    path: String,
    port: u16,
    #[serde(default)]
    strip: bool,
}

#[derive(Deserialize)]
struct RemoveRouteRequest {
    path: String,
}

async fn list_routes(
    State(ctx): State<Arc<ServerCtx>>,
    Path(name): Path<String>,
) -> Result<Json<Vec<crate::service_store::RouteEntry>>, StatusCode> {
    let store = ctx.services.lock().unwrap();
    match store.lookup(&name) {
        Some(entry) => Ok(Json(entry.routes.clone())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn add_route(
    State(ctx): State<Arc<ServerCtx>>,
    Path(name): Path<String>,
    Json(req): Json<AddRouteRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if req.path.is_empty() || !req.path.starts_with('/') {
        return Err((StatusCode::BAD_REQUEST, "path must start with /".into()));
    }
    if req.path.contains("/../") || req.path.ends_with("/..") || req.path.contains("%") {
        return Err((
            StatusCode::BAD_REQUEST,
            "path must not contain '..' or percent-encoding".into(),
        ));
    }
    if req.port == 0 {
        return Err((StatusCode::BAD_REQUEST, "port must be > 0".into()));
    }
    let mut store = ctx.services.lock().unwrap();
    if store.add_route(&name, req.path, req.port, req.strip) {
        Ok(StatusCode::CREATED)
    } else {
        Err((
            StatusCode::NOT_FOUND,
            format!("service '{}' not found", name),
        ))
    }
}

async fn remove_route(
    State(ctx): State<Arc<ServerCtx>>,
    Path(name): Path<String>,
    Json(req): Json<RemoveRouteRequest>,
) -> StatusCode {
    let mut store = ctx.services.lock().unwrap();
    if store.remove_route(&name, &req.path) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

pub async fn serve_ca(State(ctx): State<Arc<ServerCtx>>) -> Result<impl IntoResponse, StatusCode> {
    let pem = ctx.ca_pem.as_deref().ok_or(StatusCode::NOT_FOUND)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"numa-ca.pem\"",
            ),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        pem.to_string(),
    ))
}

async fn serve_qr(State(ctx): State<Arc<ServerCtx>>) -> Result<impl IntoResponse, StatusCode> {
    if !ctx.mobile_enabled {
        return Err(StatusCode::NOT_FOUND);
    }
    let lan_ip = *ctx.lan_ip.lock().unwrap();
    let url = format!("http://{}:{}/mobileconfig", lan_ip, ctx.mobile_port);
    let code = qrcode::QrCode::new(&url).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(180, 180)
        .dark_color(qrcode::render::svg::Color("#2c2418"))
        .light_color(qrcode::render::svg::Color("#faf7f2"))
        .build();
    Ok((
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        svg,
    ))
}

async fn serve_fonts_css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css"),
            (header::CACHE_CONTROL, "public, max-age=31536000"),
        ],
        FONTS_CSS,
    )
}

fn serve_font(data: &'static [u8]) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "public, max-age=31536000"),
        ],
        data,
    )
}

async fn check_tcp(addr: std::net::SocketAddr) -> bool {
    tokio::time::timeout(
        std::time::Duration::from_millis(100),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use std::sync::{Mutex, RwLock};
    use tower::ServiceExt;

    async fn test_ctx() -> Arc<ServerCtx> {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Arc::new(ServerCtx {
            socket,
            zone_map: std::collections::HashMap::new(),
            cache: RwLock::new(crate::cache::DnsCache::new(100, 60, 86400)),
            stats: Mutex::new(crate::stats::ServerStats::new()),
            overrides: RwLock::new(crate::override_store::OverrideStore::new()),
            blocklist: RwLock::new(crate::blocklist::BlocklistStore::new()),
            query_log: Mutex::new(crate::query_log::QueryLog::new(100)),
            services: Mutex::new(crate::service_store::ServiceStore::new()),
            lan_peers: Mutex::new(crate::lan::PeerStore::new(90)),
            forwarding_rules: Vec::new(),
            upstream_pool: Mutex::new(crate::forward::UpstreamPool::new(
                vec![crate::forward::Upstream::Udp(
                    "127.0.0.1:53".parse().unwrap(),
                )],
                vec![],
            )),
            upstream_auto: false,
            upstream_port: 53,
            lan_ip: Mutex::new(std::net::Ipv4Addr::LOCALHOST),
            timeout: std::time::Duration::from_secs(3),
            proxy_tld: "numa".to_string(),
            proxy_tld_suffix: ".numa".to_string(),
            lan_enabled: false,
            config_path: "/tmp/test-numa.toml".to_string(),
            config_found: false,
            config_dir: std::path::PathBuf::from("/tmp"),
            data_dir: std::path::PathBuf::from("/tmp"),
            tls_config: None,
            upstream_mode: crate::config::UpstreamMode::Forward,
            root_hints: Vec::new(),
            srtt: RwLock::new(crate::srtt::SrttCache::new(true)),
            inflight: Mutex::new(std::collections::HashMap::new()),
            dnssec_enabled: false,
            dnssec_strict: false,
            health_meta: crate::health::HealthMeta::test_fixture(),
            ca_pem: None,
            mobile_enabled: false,
            mobile_port: 8765,
        })
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let ctx = test_ctx().await;
        let resp = router(ctx)
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 1000).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn stats_returns_json() {
        let ctx = test_ctx().await;
        let resp = router(ctx)
            .oneshot(Request::get("/stats").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["uptime_secs"].is_number());
        assert!(json["queries"]["total"].is_number());
    }

    #[tokio::test]
    async fn query_log_empty() {
        let ctx = test_ctx().await;
        let resp = router(ctx)
            .oneshot(
                Request::get("/query-log?limit=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn overrides_crud() {
        let ctx = test_ctx().await;
        let a = router(ctx.clone());

        // Create
        let resp = a
            .clone()
            .oneshot(
                Request::post("/overrides")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"domain":"test.dev","target":"1.2.3.4","duration_secs":60}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(resp.status().is_success());

        // List
        let resp = a
            .clone()
            .oneshot(Request::get("/overrides").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("test.dev"));

        // Get
        let resp = a
            .clone()
            .oneshot(
                Request::get("/overrides/test.dev")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // Delete
        let resp = a
            .clone()
            .oneshot(
                Request::delete("/overrides/test.dev")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(resp.status().is_success());

        // Verify deleted
        let resp = a
            .oneshot(
                Request::get("/overrides/test.dev")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn cache_list_and_flush() {
        let ctx = test_ctx().await;
        let a = router(ctx.clone());

        // List (empty)
        let resp = a
            .clone()
            .oneshot(Request::get("/cache").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // Flush
        let resp = a
            .oneshot(Request::delete("/cache").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    #[tokio::test]
    async fn blocking_stats_returns_json() {
        let ctx = test_ctx().await;
        let resp = router(ctx)
            .oneshot(Request::get("/blocking/stats").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["enabled"].is_boolean());
    }

    #[tokio::test]
    async fn services_crud() {
        let ctx = test_ctx().await;
        let a = router(ctx);

        // Add service
        let resp = a
            .clone()
            .oneshot(
                Request::post("/services")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"testapp","target_port":3000}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(resp.status().is_success());

        // List
        let resp = a
            .clone()
            .oneshot(Request::get("/services").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("testapp"));

        // Delete
        let resp = a
            .clone()
            .oneshot(
                Request::delete("/services/testapp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(resp.status().is_success());

        // Verify deleted
        let resp = a
            .oneshot(Request::get("/services").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("testapp"));
    }

    #[tokio::test]
    async fn dashboard_returns_html() {
        let ctx = test_ctx().await;
        let resp = router(ctx)
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 100000)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Numa"));
    }
}
