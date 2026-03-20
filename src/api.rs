use std::sync::Arc;
use std::time::UNIX_EPOCH;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::ctx::ServerCtx;
use crate::forward::forward_query;
use crate::query_log::QueryLogFilter;
use crate::question::QueryType;
use crate::stats::QueryPath;

const DASHBOARD_HTML: &str = include_str!("../site/dashboard.html");

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
        .route("/blocking/allowlist", get(blocking_allowlist))
        .route("/blocking/allowlist", post(blocking_allowlist_add))
        .route("/blocking/check/{domain}", get(blocking_check))
        .route(
            "/blocking/allowlist/{domain}",
            delete(blocking_allowlist_remove),
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
}

#[derive(Serialize)]
struct StatsResponse {
    uptime_secs: u64,
    queries: QueriesStats,
    cache: CacheStats,
    overrides: OverrideStats,
    blocking: BlockingStatsResponse,
}

#[derive(Serialize)]
struct QueriesStats {
    total: u64,
    forwarded: u64,
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

    let mut store = ctx.overrides.lock().unwrap();
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
    let store = ctx.overrides.lock().unwrap();
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
    let store = ctx.overrides.lock().unwrap();
    let entry = store.get(&domain).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(OverrideResponse::from(entry)))
}

async fn remove_override(
    State(ctx): State<Arc<ServerCtx>>,
    Path(domain): Path<String>,
) -> StatusCode {
    let mut store = ctx.overrides.lock().unwrap();
    if store.remove(&domain) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn clear_overrides(State(ctx): State<Arc<ServerCtx>>) -> StatusCode {
    ctx.overrides.lock().unwrap().clear();
    StatusCode::NO_CONTENT
}

async fn load_environment(
    State(ctx): State<Arc<ServerCtx>>,
    Json(req): Json<EnvironmentRequest>,
) -> Result<(StatusCode, Json<EnvironmentResponse>), (StatusCode, String)> {
    let mut store = ctx.overrides.lock().unwrap();

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
        let store = ctx.overrides.lock().unwrap();
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
        let bl = ctx.blocklist.lock().unwrap();
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
        let mut cache = ctx.cache.lock().unwrap();
        let cached = cache.lookup(&domain_lower, qtype);
        steps.push(DiagnoseStep {
            source: "cache".to_string(),
            matched: cached.is_some(),
            detail: cached.map(|p| format!("{} answers", p.answers.len())),
        });
    }

    // Check upstream (async, no locks held)
    let (upstream_matched, upstream_detail) =
        forward_query_for_diagnose(&domain_lower, ctx.upstream, ctx.timeout).await;
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
    upstream: std::net::SocketAddr,
    timeout: std::time::Duration,
) -> (bool, String) {
    use crate::packet::DnsPacket;
    use crate::question::DnsQuestion;

    let mut query = DnsPacket::new();
    query.header.id = 0xBEEF;
    query.header.recursion_desired = true;
    query
        .questions
        .push(DnsQuestion::new(domain.to_string(), QueryType::A));

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
                }
            })
            .collect()
    };

    Json(raw_entries)
}

async fn stats(State(ctx): State<Arc<ServerCtx>>) -> Json<StatsResponse> {
    let snap = ctx.stats.lock().unwrap().snapshot();
    let (cache_len, cache_max) = {
        let cache = ctx.cache.lock().unwrap();
        (cache.len(), cache.max_entries())
    };
    let override_count = ctx.overrides.lock().unwrap().active_count();
    let bl_stats = ctx.blocklist.lock().unwrap().stats();

    Json(StatsResponse {
        uptime_secs: snap.uptime_secs,
        queries: QueriesStats {
            total: snap.total,
            forwarded: snap.forwarded,
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
    })
}

async fn list_cache(State(ctx): State<Arc<ServerCtx>>) -> Json<Vec<CacheEntryResponse>> {
    let cache = ctx.cache.lock().unwrap();
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
    ctx.cache.lock().unwrap().clear();
    StatusCode::NO_CONTENT
}

async fn flush_cache_domain(
    State(ctx): State<Arc<ServerCtx>>,
    Path(domain): Path<String>,
) -> StatusCode {
    ctx.cache.lock().unwrap().remove(&domain);
    StatusCode::NO_CONTENT
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

// --- Blocking handlers ---

async fn blocking_stats(State(ctx): State<Arc<ServerCtx>>) -> Json<serde_json::Value> {
    let stats = ctx.blocklist.lock().unwrap().stats();
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
    ctx.blocklist.lock().unwrap().set_enabled(req.enabled);
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
    ctx.blocklist.lock().unwrap().pause(req.minutes * 60);
    Json(serde_json::json!({ "paused_minutes": req.minutes }))
}

async fn blocking_check(
    State(ctx): State<Arc<ServerCtx>>,
    Path(domain): Path<String>,
) -> Json<crate::blocklist::BlockCheckResult> {
    let result = ctx.blocklist.lock().unwrap().check(&domain);
    Json(result)
}

async fn blocking_allowlist(State(ctx): State<Arc<ServerCtx>>) -> Json<Vec<String>> {
    let list = ctx.blocklist.lock().unwrap().allowlist();
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
    ctx.blocklist.lock().unwrap().add_to_allowlist(&req.domain);
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "allowed": req.domain })),
    )
}

async fn blocking_allowlist_remove(
    State(ctx): State<Arc<ServerCtx>>,
    Path(domain): Path<String>,
) -> StatusCode {
    if ctx.blocklist.lock().unwrap().remove_from_allowlist(&domain) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}
