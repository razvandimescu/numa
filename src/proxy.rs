use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use http_body_util::BodyExt;
use hyper::StatusCode;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use log::{debug, error, info, warn};
use tokio::io::copy_bidirectional;

use crate::ctx::ServerCtx;

type HttpClient = Client<hyper_util::client::legacy::connect::HttpConnector, Body>;

#[derive(Clone)]
struct ProxyState {
    ctx: Arc<ServerCtx>,
    client: HttpClient,
    tld_suffix: String, // pre-computed ".{tld}"
}

pub async fn start_proxy(ctx: Arc<ServerCtx>, port: u16, tld: &str) {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(
                "proxy: could not bind port {} ({}) — proxy disabled",
                port, e
            );
            return;
        }
    };
    info!("HTTP proxy listening on {}", addr);

    let client: HttpClient = Client::builder(TokioExecutor::new())
        .http1_preserve_header_case(true)
        .build_http();

    let state = ProxyState {
        ctx,
        client,
        tld_suffix: format!(".{}", tld),
    };

    let app = Router::new().fallback(any(proxy_handler)).with_state(state);

    axum::serve(listener, app).await.unwrap();
}

fn extract_host(req: &Request) -> Option<String> {
    req.headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_lowercase())
}

async fn proxy_handler(State(state): State<ProxyState>, req: Request) -> axum::response::Response {
    let hostname = match extract_host(&req) {
        Some(h) => h,
        None => {
            return (StatusCode::BAD_REQUEST, "missing Host header").into_response();
        }
    };

    let service_name = match hostname.strip_suffix(state.tld_suffix.as_str()) {
        Some(name) => name.to_string(),
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("not a {} domain: {}", state.tld_suffix, hostname),
            )
                .into_response()
        }
    };

    let target_port = {
        let store = state.ctx.services.lock().unwrap();
        match store.lookup(&service_name) {
            Some(entry) => entry.target_port,
            None => {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("unknown service: {}{}", service_name, state.tld_suffix),
                )
                    .into_response()
            }
        }
    };

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let target_uri: hyper::Uri = format!("http://127.0.0.1:{}{}", target_port, path_and_query)
        .parse()
        .unwrap();

    // Check for upgrade request (WebSocket, etc.)
    let is_upgrade = req.headers().get(hyper::header::UPGRADE).is_some();

    if is_upgrade {
        return handle_upgrade(req, target_uri, state.client.clone()).await;
    }

    // Regular HTTP proxy
    let (mut parts, body) = req.into_parts();
    parts.uri = target_uri;
    let proxied_req = Request::from_parts(parts, body);

    match state.client.request(proxied_req).await {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            let body = Body::new(body.map_err(axum::Error::new));
            axum::response::Response::from_parts(parts, body)
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("proxy error: {}", e)).into_response(),
    }
}

async fn handle_upgrade(
    mut req: Request,
    target_uri: hyper::Uri,
    client: HttpClient,
) -> axum::response::Response {
    // Save the client-side upgrade future before forwarding
    let client_upgrade = hyper::upgrade::on(&mut req);

    // Forward the request to backend
    let (mut parts, body) = req.into_parts();
    parts.uri = target_uri;
    let backend_req = Request::from_parts(parts, body);

    let mut backend_resp = match client.request(backend_req).await {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_GATEWAY, format!("upgrade error: {}", e)).into_response()
        }
    };

    if backend_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        let (parts, body) = backend_resp.into_parts();
        let body = Body::new(body.map_err(axum::Error::new));
        return axum::response::Response::from_parts(parts, body);
    }

    // Save response headers before consuming for upgrade
    let resp_headers = backend_resp.headers().clone();
    let backend_upgrade = hyper::upgrade::on(&mut backend_resp);

    // Spawn bidirectional pipe once both sides are upgraded
    tokio::spawn(async move {
        let (client_io, backend_io) = match tokio::try_join!(client_upgrade, backend_upgrade) {
            Ok((c, b)) => (c, b),
            Err(e) => {
                error!("proxy upgrade failed: {}", e);
                return;
            }
        };

        let mut client_rw = hyper_util::rt::TokioIo::new(client_io);
        let mut backend_rw = hyper_util::rt::TokioIo::new(backend_io);

        match copy_bidirectional(&mut client_rw, &mut backend_rw).await {
            Ok((up, down)) => debug!("ws proxy closed: {} up, {} down bytes", up, down),
            Err(e) => debug!("ws proxy error: {}", e),
        }
    });

    // Return 101 to client with the backend's upgrade headers
    let mut resp = axum::response::Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (key, value) in &resp_headers {
        resp = resp.header(key, value);
    }
    resp.body(Body::empty()).unwrap()
}
