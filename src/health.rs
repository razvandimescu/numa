//! Health metadata and `/health` response shape, shared between the main
//! HTTP API and the mobile API.
//!
//! The static fields (version, hostname, DoT config, CA fingerprint,
//! feature list) are computed once at startup and stored in [`HealthMeta`]
//! on `ServerCtx`. Per-request fields (uptime, LAN IP) are computed live.
//! Both handlers call [`HealthResponse::build`] to assemble the JSON
//! response from `HealthMeta` + live inputs.
//!
//! JSON schema is documented in `docs/implementation/ios-companion-app.md`
//! §4.2. The iOS companion app's `HealthInfo` struct is the canonical
//! consumer; any change to this response must keep that struct decoding
//! cleanly (all consumed fields are optional on the Swift side, but
//! `lan_ip` is load-bearing for the pipeline).

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Instant;

use ring::digest::{digest, SHA256};
use serde::Serialize;

/// Immutable health metadata cached on `ServerCtx`. Built once at startup
/// from config + file-system state (CA cert).
#[derive(Clone)]
pub struct HealthMeta {
    pub version: &'static str,
    pub hostname: String,
    pub sni: String,
    pub dot_enabled: bool,
    pub dot_port: u16,
    pub api_port: u16,
    pub ca_fingerprint_sha256: Option<String>,
    pub features: Vec<String>,
    pub started_at: Instant,
}

impl HealthMeta {
    /// Minimal `HealthMeta` for unit tests that construct a `ServerCtx`
    /// without needing the real startup flow (CA file reads, hostname
    /// detection, etc.). Deterministic values so test JSON assertions
    /// stay stable.
    #[cfg(test)]
    pub fn test_fixture() -> Self {
        HealthMeta {
            version: env!("CARGO_PKG_VERSION"),
            hostname: "test-host".to_string(),
            sni: "numa.numa".to_string(),
            dot_enabled: false,
            dot_port: 853,
            api_port: 8765,
            ca_fingerprint_sha256: None,
            features: vec![],
            started_at: Instant::now(),
        }
    }

    /// Build a new HealthMeta from config + startup-time environment.
    /// Call once at server boot; the returned value is cheap to clone
    /// (small number of short strings) and lives on `ServerCtx`.
    ///
    /// The argument count is deliberate — each flag corresponds to a
    /// specific config value and is clearly named at the call site.
    /// Collapsing into a struct hides nothing meaningful for a one-call
    /// initializer.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        data_dir: &Path,
        dot_enabled: bool,
        dot_port: u16,
        api_port: u16,
        dnssec_enabled: bool,
        recursive_enabled: bool,
        mdns_enabled: bool,
        blocking_enabled: bool,
        doh_enabled: bool,
    ) -> Self {
        let ca_path = data_dir.join("ca.pem");
        let ca_fingerprint_sha256 = compute_ca_fingerprint(&ca_path);

        let mut features = Vec::new();
        if doh_enabled {
            features.push("doh".to_string());
        }
        if dot_enabled {
            features.push("dot".to_string());
        }
        if recursive_enabled {
            features.push("recursive".to_string());
        }
        if blocking_enabled {
            features.push("blocking".to_string());
        }
        if mdns_enabled {
            features.push("mdns".to_string());
        }
        if dnssec_enabled {
            features.push("dnssec".to_string());
        }

        HealthMeta {
            version: env!("CARGO_PKG_VERSION"),
            hostname: crate::hostname(),
            sni: "numa.numa".to_string(),
            dot_enabled,
            dot_port,
            api_port,
            ca_fingerprint_sha256,
            features,
            started_at: Instant::now(),
        }
    }
}

/// JSON response shape returned by `GET /health` on both main and mobile APIs.
///
/// Fields are organized to match the iOS companion app's
/// `HealthInfo` Swift struct — see `ios-companion-app.md` §4.2.
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_secs: u64,
    pub hostname: String,
    pub lan_ip: Option<String>,
    pub sni: String,
    pub dot: DotBlock,
    pub api: ApiBlock,
    pub ca: CaBlock,
    pub features: Vec<String>,
}

#[derive(Serialize)]
pub struct DotBlock {
    pub enabled: bool,
    pub port: Option<u16>,
}

#[derive(Serialize)]
pub struct ApiBlock {
    pub port: u16,
}

#[derive(Serialize)]
pub struct CaBlock {
    pub present: bool,
    pub fingerprint_sha256: Option<String>,
}

impl HealthResponse {
    /// Assemble a fresh `HealthResponse` from the cached metadata and
    /// the current LAN IP (which may change across network transitions).
    /// Pass `None` for `lan_ip` if detection fails — the response still
    /// returns 200 OK, just without the LAN address.
    pub fn build(meta: &HealthMeta, lan_ip: Option<Ipv4Addr>) -> Self {
        HealthResponse {
            status: "ok",
            version: meta.version,
            uptime_secs: meta.started_at.elapsed().as_secs(),
            hostname: meta.hostname.clone(),
            lan_ip: lan_ip.map(|ip| ip.to_string()),
            sni: meta.sni.clone(),
            dot: DotBlock {
                enabled: meta.dot_enabled,
                port: if meta.dot_enabled {
                    Some(meta.dot_port)
                } else {
                    None
                },
            },
            api: ApiBlock {
                port: meta.api_port,
            },
            ca: CaBlock {
                present: meta.ca_fingerprint_sha256.is_some(),
                fingerprint_sha256: meta.ca_fingerprint_sha256.clone(),
            },
            features: meta.features.clone(),
        }
    }
}

/// Read the CA cert at `ca_path` and return its SHA-256 fingerprint as a
/// lowercase hex string, or None if the file doesn't exist or can't be read.
///
/// Hashes the raw PEM bytes for simplicity. A more canonical SPKI-based
/// fingerprint would require parsing the PEM → DER → extracting
/// SubjectPublicKeyInfo, which adds complexity without meaningful benefit
/// for our use case (the iOS app uses the fingerprint only for display
/// and to detect rotation).
fn compute_ca_fingerprint(ca_path: &Path) -> Option<String> {
    let pem = std::fs::read(ca_path).ok()?;
    let hash = digest(&SHA256, &pem);
    let hex: String = hash.as_ref().iter().map(|b| format!("{:02x}", b)).collect();
    Some(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_response_contains_required_fields() {
        let meta = HealthMeta {
            version: "0.10.0",
            hostname: "test-host".to_string(),
            sni: "numa.numa".to_string(),
            dot_enabled: true,
            dot_port: 853,
            api_port: 8765,
            ca_fingerprint_sha256: Some("abcd1234".to_string()),
            features: vec!["dot".to_string(), "dnssec".to_string()],
            started_at: Instant::now(),
        };

        let response = HealthResponse::build(&meta, Some(Ipv4Addr::new(192, 168, 1, 50)));
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"version\":\"0.10.0\""));
        assert!(json.contains("\"hostname\":\"test-host\""));
        assert!(json.contains("\"lan_ip\":\"192.168.1.50\""));
        assert!(json.contains("\"sni\":\"numa.numa\""));
        assert!(json.contains("\"port\":853"));
        assert!(json.contains("\"port\":8765"));
        assert!(json.contains("\"fingerprint_sha256\":\"abcd1234\""));
        assert!(json.contains("\"features\":[\"dot\",\"dnssec\"]"));
    }

    #[test]
    fn health_response_omits_dot_port_when_disabled() {
        let meta = HealthMeta {
            version: "0.10.0",
            hostname: "t".to_string(),
            sni: "numa.numa".to_string(),
            dot_enabled: false,
            dot_port: 853,
            api_port: 8765,
            ca_fingerprint_sha256: None,
            features: vec![],
            started_at: Instant::now(),
        };

        let response = HealthResponse::build(&meta, None);
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"enabled\":false"));
        assert!(json.contains("\"dot\":{\"enabled\":false,\"port\":null}"));
        assert!(json.contains("\"present\":false"));
        assert!(json.contains("\"lan_ip\":null"));
    }

    #[test]
    fn ca_fingerprint_returns_none_for_missing_file() {
        let fp = compute_ca_fingerprint(Path::new("/nonexistent/ca.pem"));
        assert!(fp.is_none());
    }
}
