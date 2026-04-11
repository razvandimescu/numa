use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::IntoResponse;
use axum::routing::{any, post};
use axum::Router;
use http_body_util::BodyExt;
use hyper::StatusCode;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use log::{debug, error, info, warn};
use tokio::io::copy_bidirectional;
use tokio_rustls::TlsAcceptor;

use crate::ctx::ServerCtx;

type HttpClient = Client<hyper_util::client::legacy::connect::HttpConnector, Body>;

/// State passed to the DoH handler. Includes the remote address so
/// `resolve_query` can log the client IP.
#[derive(Clone)]
pub struct DohState {
    pub ctx: Arc<ServerCtx>,
    pub remote_addr: Option<std::net::SocketAddr>,
}

#[derive(Clone)]
struct ProxyState {
    ctx: Arc<ServerCtx>,
    client: HttpClient,
}

pub async fn start_proxy(ctx: Arc<ServerCtx>, port: u16, bind_addr: Ipv4Addr) {
    let addr: SocketAddr = (bind_addr, port).into();
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

    let state = ProxyState { ctx, client };

    let app = Router::new().fallback(any(proxy_handler)).with_state(state);

    axum::serve(listener, app).await.unwrap();
}

pub async fn start_proxy_tls(ctx: Arc<ServerCtx>, port: u16, bind_addr: Ipv4Addr) {
    let addr: SocketAddr = (bind_addr, port).into();
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(
                "proxy: could not bind TLS port {} ({}) — HTTPS proxy disabled",
                port, e
            );
            return;
        }
    };
    info!("HTTPS proxy listening on {}", addr);

    if ctx.tls_config.is_none() {
        warn!("proxy: no TLS config — HTTPS proxy disabled");
        return;
    }

    let client: HttpClient = Client::builder(TokioExecutor::new())
        .http1_preserve_header_case(true)
        .build_http();

    // Hold a separate Arc so we can access tls_config after ctx moves into ProxyState
    let tls_holder = Arc::clone(&ctx);
    let proxy_state = ProxyState {
        ctx: Arc::clone(&ctx),
        client,
    };

    // DoH route (RFC 8484) served only on the TLS listener.
    // DohState.remote_addr is set per-connection below.
    let doh_state = DohState {
        ctx,
        remote_addr: None,
    };

    loop {
        let (tcp_stream, remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("TLS accept error: {}", e);
                continue;
            }
        };

        // Load the latest TLS config on each connection (picks up new service certs)
        // unwrap safe: guarded by is_none() check above
        let acceptor =
            TlsAcceptor::from(Arc::clone(&*tls_holder.tls_config.as_ref().unwrap().load()));

        let mut conn_doh_state = doh_state.clone();
        conn_doh_state.remote_addr = Some(remote_addr);

        let app = Router::new()
            .route(
                "/dns-query",
                post(crate::doh::doh_post).with_state(conn_doh_state),
            )
            .fallback(any(proxy_handler))
            .with_state(proxy_state.clone());

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("TLS handshake failed from {}: {}", remote_addr, e);
                    return;
                }
            };

            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let svc = hyper_util::service::TowerToHyperService::new(app.into_service());

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                debug!("TLS connection error from {}: {}", remote_addr, e);
            }
        });
    }
}

fn error_page(title: &str, body: &str) -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Numa</title>
<style>
*,*::before,*::after {{ margin:0;padding:0;box-sizing:border-box }}
body {{
  font-family: system-ui, -apple-system, sans-serif;
  background: #f5f0e8;
  color: #2c2418;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  -webkit-font-smoothing: antialiased;
  position: relative;
  overflow: hidden;
}}
body::before {{
  content: '';
  position: fixed;
  inset: 0;
  background-image: url("data:image/svg+xml,%3Csvg width='120' height='60' xmlns='http://www.w3.org/2000/svg'%3E%3Crect x='1' y='1' width='56' height='27' rx='1' fill='none' stroke='%23a39888' stroke-width='0.5' opacity='0.12'/%3E%3Crect x='61' y='1' width='56' height='27' rx='1' fill='none' stroke='%23a39888' stroke-width='0.5' opacity='0.12'/%3E%3Crect x='31' y='31' width='56' height='27' rx='1' fill='none' stroke='%23a39888' stroke-width='0.5' opacity='0.12'/%3E%3C/svg%3E");
  background-size: 120px 60px;
  pointer-events: none;
  opacity: 0.5;
  -webkit-mask-image: radial-gradient(ellipse at center, transparent 20%, rgba(0,0,0,0.4) 70%);
  mask-image: radial-gradient(ellipse at center, transparent 20%, rgba(0,0,0,0.4) 70%);
}}
.container {{
  position: relative;
  z-index: 1;
  text-align: center;
  max-width: 480px;
  padding: 2rem;
  animation: rise 0.6s cubic-bezier(0.22,1,0.36,1);
}}
@keyframes rise {{
  from {{ opacity:0; transform:translateY(20px) }}
  to {{ opacity:1; transform:translateY(0) }}
}}
.hero-text {{
  font-family: Georgia, 'Times New Roman', serif;
  font-size: 6rem;
  line-height: 1;
  color: #c0623a;
  letter-spacing: 0.04em;
  opacity: 0.85;
}}
.label {{
  font-family: ui-monospace, 'SF Mono', monospace;
  font-size: 0.7rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #b5443a;
  margin-bottom: 1rem;
}}
.domain {{
  font-family: ui-monospace, 'SF Mono', monospace;
  font-size: 1.1rem;
  color: #2c2418;
  margin-top: 1rem;
  padding: 0.4rem 1rem;
  background: rgba(192,98,58,0.08);
  border: 1px solid rgba(192,98,58,0.15);
  border-radius: 6px;
  display: inline-block;
}}
.message {{
  color: #6b5e4f;
  margin-top: 1.2rem;
  line-height: 1.7;
  font-size: 0.95rem;
}}
.message a {{
  color: #c0623a;
  text-decoration: none;
  border-bottom: 1px solid rgba(192,98,58,0.3);
}}
.message a:hover {{ border-bottom-color: #c0623a }}
pre {{
  text-align: left;
  background: #1a1814;
  color: #e8e0d4;
  padding: 1rem 1.2rem;
  border-radius: 8px;
  font-family: ui-monospace, 'SF Mono', monospace;
  font-size: 0.78rem;
  line-height: 1.7;
  margin-top: 1.2rem;
  overflow-x: auto;
}}
pre .prompt {{ color: #8baa6e }}
pre .flag {{ color: #8b9fbb }}
pre .str {{ color: #d48a5a }}
.aside {{
  margin-top: 2.5rem;
  font-family: Georgia, 'Times New Roman', serif;
  font-style: italic;
  font-size: 0.85rem;
  color: #a39888;
  letter-spacing: 0.03em;
  opacity: 0;
  animation: fade 0.8s 1.5s forwards;
}}
@keyframes fade {{ to {{ opacity: 1 }} }}
</style></head><body>
<div class="container">
{body}
</div>
</body></html>"##
    )
}

pub fn extract_host(req: &Request) -> Option<String> {
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

    let service_name = match hostname.strip_suffix(state.ctx.proxy_tld_suffix.as_str()) {
        Some(name) => name.to_string(),
        None => {
            // Check if this domain was blocked — show a helpful styled page
            if state.ctx.blocklist.read().unwrap().is_blocked(&hostname) {
                let body = format!(
                    r#"  <div class="hero-text">&#x1f6e1;</div>
  <div class="label">Blocked by Numa</div>
  <div class="domain">{0}</div>
  <p class="message">This domain is on the ad &amp; tracker blocklist.<br>To allow it, use the <a href="http://numa.numa">dashboard</a> or:</p>
  <pre><span class="prompt">$</span> <span class="str">curl</span> <span class="flag">-X POST</span> localhost:5380/blocking/allowlist \
    <span class="flag">-d</span> '<span class="str">{{"domain":"{0}"}}</span>'</pre>"#,
                    hostname
                );
                return (
                    StatusCode::FORBIDDEN,
                    [(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    error_page(&format!("Blocked — {}", hostname), &body),
                )
                    .into_response();
            }
            return (
                StatusCode::BAD_GATEWAY,
                format!("not a {} domain: {}", state.ctx.proxy_tld_suffix, hostname),
            )
                .into_response();
        }
    };

    let request_path = req.uri().path().to_string();

    let (target_host, target_port, rewritten_path) = {
        let store = state.ctx.services.lock().unwrap();
        if let Some(entry) = store.lookup(&service_name) {
            let (port, path) = entry.resolve_route(&request_path);
            ("localhost".to_string(), port, path)
        } else {
            let mut peers = state.ctx.lan_peers.lock().unwrap();
            match peers.lookup(&service_name) {
                Some((ip, port)) => (ip.to_string(), port, request_path.clone()),
                None => {
                    let body = format!(
                        r#"  <div class="hero-text">404</div>
  <div class="domain">{0}{1}</div>
  <p class="message">This service isn't registered yet.<br>Add it from the <a href="http://numa.numa">dashboard</a> or:</p>
  <pre><span class="prompt">$</span> <span class="str">curl</span> <span class="flag">-X POST</span> numa.numa:5380/services \
    <span class="flag">-H</span> 'Content-Type: application/json' \
    <span class="flag">-d</span> '<span class="str">{{"name":"{0}","target_port":3000}}</span>'</pre>
  <div class="aside">ma-ia hii, ma-ia huu, ma-ia haa, ma-ia ha-ha</div>"#,
                        service_name, state.ctx.proxy_tld_suffix
                    );
                    return (
                        StatusCode::NOT_FOUND,
                        [(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                        error_page(
                            &format!("404 — {}{}", service_name, state.ctx.proxy_tld_suffix),
                            &body,
                        ),
                    )
                        .into_response();
                }
            }
        }
    };

    let query_string = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let target_uri: hyper::Uri = format!(
        "http://{}:{}{}{}",
        target_host, target_port, rewritten_path, query_string
    )
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
