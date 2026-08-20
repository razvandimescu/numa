//! ODoH target-config fetcher and TTL cache (RFC 9230 §6).
//!
//! ## Ciphersuite policy
//! `odoh-rs` deserialization rejects any config whose KEM/KDF/AEAD triple is
//! not the mandatory `(X25519, HKDF-SHA256, AES-128-GCM)` (see
//! `ObliviousDoHConfigContents::deserialize`). This is stricter than the
//! plan's "pick the mandatory suite if mixed": a response containing *any*
//! non-mandatory config fails parse entirely. Real-world targets publish a
//! single mandatory config, so this is fine in practice; revisit if a target
//! that matters starts mixing suites.

use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use odoh_rs::{
    ObliviousDoHConfigContents, ObliviousDoHConfigs, ObliviousDoHMessage,
    ObliviousDoHMessagePlaintext,
};
use rand_core::{OsRng, TryRngCore};
use reqwest::header::HeaderMap;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::Result;

/// MIME type used for both directions of the ODoH exchange (RFC 9230 §4).
pub(crate) const ODOH_CONTENT_TYPE: &str = "application/oblivious-dns-message";

/// Cap on the response body we read into memory when the relay returns
/// non-success. Protects against a hostile relay streaming a huge body on
/// the error path; keeps enough room to carry a human-readable reason.
const ERROR_BODY_PREVIEW_BYTES: usize = 1024;

/// Fallback TTL when the target's response lacks a usable `Cache-Control`
/// directive. RFC 9230 §6.2 places no hard floor; 24 h matches what Cloudflare
/// publishes in practice.
const DEFAULT_CONFIG_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Cap on any TTL we'll honour, regardless of what the target advertises.
/// Keeps a misconfigured server from pinning an old key indefinitely.
const MAX_CONFIG_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// After a failed `/.well-known/odohconfigs` fetch, refuse to refetch again
/// within this window — a target that is genuinely broken would otherwise
/// receive one request per query. Queries that arrive during the backoff
/// return the cached error immediately.
const REFRESH_BACKOFF: Duration = Duration::from_secs(60);

/// Parsed ODoH target config plus the freshness metadata needed to age it out.
#[derive(Debug)]
pub struct OdohTargetConfig {
    pub contents: ObliviousDoHConfigContents,
    pub key_id: Vec<u8>,
    expires_at: Instant,
}

impl OdohTargetConfig {
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

struct FailedRefresh {
    at: Instant,
    err: String,
}

/// TTL-gated cache of a single target's HPKE config.
///
/// Reads go through `ArcSwapOption` (lock-free hot path). Refreshes serialize
/// on an async mutex so a burst of simultaneous misses produces a single
/// outbound fetch, and a failed refresh blocks subsequent refetches for
/// [`REFRESH_BACKOFF`] to prevent hot-looping against a broken target.
pub struct OdohConfigCache {
    target_host: String,
    configs_url: String,
    client: reqwest::Client,
    current: ArcSwapOption<OdohTargetConfig>,
    last_failure: ArcSwapOption<FailedRefresh>,
    refresh_lock: Mutex<()>,
}

impl OdohConfigCache {
    pub fn new(target_host: String, client: reqwest::Client) -> Self {
        let configs_url = format!("https://{}/.well-known/odohconfigs", target_host);
        Self {
            target_host,
            configs_url,
            client,
            current: ArcSwapOption::from(None),
            last_failure: ArcSwapOption::from(None),
            refresh_lock: Mutex::new(()),
        }
    }

    pub fn target_host(&self) -> &str {
        &self.target_host
    }

    /// Return a valid config, refetching when the cache is cold or expired.
    /// Within [`REFRESH_BACKOFF`] of a failed refresh, returns the cached
    /// error without issuing another fetch.
    pub async fn get(&self) -> Result<Arc<OdohTargetConfig>> {
        if let Some(cfg) = self.current.load_full() {
            if !cfg.is_expired() {
                return Ok(cfg);
            }
        }

        if let Some(err) = self.backoff_error() {
            return Err(err);
        }

        let _guard = self.refresh_lock.lock().await;

        // Another task may have refreshed or failed while we waited.
        if let Some(cfg) = self.current.load_full() {
            if !cfg.is_expired() {
                return Ok(cfg);
            }
        }
        if let Some(err) = self.backoff_error() {
            return Err(err);
        }

        match fetch_odoh_config(&self.client, &self.configs_url).await {
            Ok(fresh) => {
                let fresh = Arc::new(fresh);
                self.current.store(Some(fresh.clone()));
                self.last_failure.store(None);
                Ok(fresh)
            }
            Err(e) => {
                let msg = format!("ODoH config fetch failed: {e}");
                self.last_failure.store(Some(Arc::new(FailedRefresh {
                    at: Instant::now(),
                    err: msg.clone(),
                })));
                Err(msg.into())
            }
        }
    }

    /// Drop the cached config. Called after the target rejects ciphertext
    /// (key rotation race) so the next `get()` refetches.
    pub fn invalidate(&self) {
        self.current.store(None);
    }

    fn backoff_error(&self) -> Option<crate::Error> {
        let fail = self.last_failure.load_full()?;
        if fail.at.elapsed() < REFRESH_BACKOFF {
            Some(format!("{} (backoff active)", fail.err).into())
        } else {
            None
        }
    }
}

/// Fetch `/.well-known/odohconfigs` from `configs_url` and parse it into an
/// [`OdohTargetConfig`]. The TTL is taken from the response's
/// `Cache-Control: max-age=`, clamped to [`DEFAULT_CONFIG_TTL`,
/// [`MAX_CONFIG_TTL`]] when absent or obviously wrong.
pub async fn fetch_odoh_config(
    client: &reqwest::Client,
    configs_url: &str,
) -> Result<OdohTargetConfig> {
    let resp = client.get(configs_url).send().await?.error_for_status()?;
    let ttl = cache_control_ttl(resp.headers()).unwrap_or(DEFAULT_CONFIG_TTL);
    let body = resp.bytes().await?;
    parse_odoh_config(&body, ttl)
}

fn parse_odoh_config(body: &[u8], ttl: Duration) -> Result<OdohTargetConfig> {
    let mut buf = body;
    let configs: ObliviousDoHConfigs = odoh_rs::parse(&mut buf)
        .map_err(|e| format!("failed to parse ObliviousDoHConfigs: {e}"))?;
    let first = configs
        .into_iter()
        .next()
        .ok_or("target published no ODoH configs with a supported version + ciphersuite")?;
    let contents: ObliviousDoHConfigContents = first.into();
    let key_id = contents
        .identifier()
        .map_err(|e| format!("failed to derive key_id from ODoH config: {e}"))?;
    Ok(OdohTargetConfig {
        contents,
        key_id,
        expires_at: Instant::now() + ttl.min(MAX_CONFIG_TTL),
    })
}

/// Send a DNS wire query through an ODoH relay to a target and return the
/// plaintext DNS wire response.
///
/// Flow: fetch the target's HPKE config (cached), seal the query, POST to the
/// relay with `Targethost`/`Targetpath` headers, then unseal the response.
/// On seal/unseal failure we invalidate the cache and retry once — this
/// handles the benign race where the target rotated its key between our
/// cached config and the POST.
pub async fn query_through_relay(
    wire: &[u8],
    relay_url: &str,
    target_path: &str,
    client: &reqwest::Client,
    cache: &OdohConfigCache,
    timeout_duration: Duration,
) -> Result<Vec<u8>> {
    let req = OdohRequest {
        wire,
        relay_url,
        target_path,
        client,
        cache,
        timeout: timeout_duration,
    };
    match attempt_query(&req).await {
        Ok(v) => Ok(v),
        Err(AttemptError::KeyRotation(_)) => {
            cache.invalidate();
            attempt_query(&req).await.map_err(AttemptError::into_error)
        }
        Err(e) => Err(e.into_error()),
    }
}

struct OdohRequest<'a> {
    wire: &'a [u8],
    relay_url: &'a str,
    target_path: &'a str,
    client: &'a reqwest::Client,
    cache: &'a OdohConfigCache,
    timeout: Duration,
}

/// Classification used only by the retry path in [`query_through_relay`].
enum AttemptError {
    /// Target signalled the config we used is stale (key rotation race).
    /// Callers should invalidate the cache and retry exactly once.
    KeyRotation(String),
    /// Any other failure — transport, timeout, malformed response.
    Other(crate::Error),
}

impl AttemptError {
    fn into_error(self) -> crate::Error {
        match self {
            AttemptError::KeyRotation(m) => format!("ODoH key rotation race: {m}").into(),
            AttemptError::Other(e) => e,
        }
    }
}

async fn attempt_query(req: &OdohRequest<'_>) -> std::result::Result<Vec<u8>, AttemptError> {
    let cfg = req.cache.get().await.map_err(AttemptError::Other)?;

    let plaintext = ObliviousDoHMessagePlaintext::new(req.wire, 0);
    // rand_core 0.9's OsRng is fallible-only; wrap for the infallible bound.
    let mut os = OsRng;
    let mut rng = os.unwrap_mut();
    let (encrypted_query, client_secret) =
        odoh_rs::encrypt_query(&plaintext, &cfg.contents, &mut rng)
            .map_err(|e| AttemptError::Other(format!("ODoH encrypt failed: {e}").into()))?;
    let body = odoh_rs::compose(&encrypted_query)
        .map_err(|e| AttemptError::Other(format!("ODoH compose failed: {e}").into()))?
        .freeze();

    // RFC 9230 §5 and the reference client use URL query parameters, not
    // HTTP headers, to carry the target routing. `Targethost`/`Targetpath`
    // headers cause relays to treat the request as an unspecified-target and
    // reject it.
    let (status, resp_body) = timeout(req.timeout, async {
        let resp = req
            .client
            .post(req.relay_url)
            .header(reqwest::header::CONTENT_TYPE, ODOH_CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, ODOH_CONTENT_TYPE)
            .header(reqwest::header::CACHE_CONTROL, "no-cache, no-store")
            .query(&[
                ("targethost", req.cache.target_host()),
                ("targetpath", req.target_path),
            ])
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        Ok::<_, reqwest::Error>((status, body))
    })
    .await
    .map_err(|_| AttemptError::Other("ODoH relay request timed out".into()))?
    .map_err(|e| AttemptError::Other(format!("ODoH relay request failed: {e}").into()))?;

    // RFC 9230 §4.3 expects a target that can't decrypt to reply with a DNS
    // error in a sealed 200 response; a 401 from the relay/target is the
    // practical signal that our cached HPKE key is stale. Treat 400 as a
    // client-side bug (malformed ODoH envelope) — retrying would loop-fail.
    if !status.is_success() {
        let preview_len = resp_body.len().min(ERROR_BODY_PREVIEW_BYTES);
        let body_preview = String::from_utf8_lossy(&resp_body[..preview_len]);
        let msg = format!("ODoH relay returned {status}: {}", body_preview.trim());
        return Err(if status.as_u16() == 401 {
            AttemptError::KeyRotation(msg)
        } else {
            AttemptError::Other(msg.into())
        });
    }

    let mut buf = resp_body;
    let encrypted_response: ObliviousDoHMessage = odoh_rs::parse(&mut buf)
        .map_err(|e| AttemptError::Other(format!("ODoH response parse failed: {e}").into()))?;
    let plaintext_response =
        odoh_rs::decrypt_response(&plaintext, &encrypted_response, client_secret)
            .map_err(|e| AttemptError::KeyRotation(format!("ODoH decrypt failed: {e}")))?;

    Ok(plaintext_response.into_msg().to_vec())
}

fn cache_control_ttl(headers: &HeaderMap) -> Option<Duration> {
    let cc = headers.get(reqwest::header::CACHE_CONTROL)?.to_str().ok()?;
    for directive in cc.split(',') {
        let directive = directive.trim();
        if let Some(rest) = directive.strip_prefix("max-age=") {
            if let Ok(secs) = rest.trim().parse::<u64>() {
                if secs > 0 {
                    return Some(Duration::from_secs(secs));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use odoh_rs::{ObliviousDoHConfig, ObliviousDoHKeyPair};

    // RFC 9180 HPKE IDs for the sole ODoH mandatory suite:
    // KEM = X25519, KDF = HKDF-SHA256, AEAD = AES-128-GCM.
    const KEM_X25519: u16 = 0x0020;
    const KDF_SHA256: u16 = 0x0001;
    const AEAD_AES128GCM: u16 = 0x0001;

    fn synth_configs_bytes() -> Vec<u8> {
        let kp = ObliviousDoHKeyPair::from_parameters(
            KEM_X25519,
            KDF_SHA256,
            AEAD_AES128GCM,
            &[0u8; 32],
        );
        let pk = kp.public().clone();
        let configs: ObliviousDoHConfigs = vec![ObliviousDoHConfig::from(pk)].into();
        odoh_rs::compose(&configs).unwrap().to_vec()
    }

    #[test]
    fn parse_accepts_well_formed_config() {
        let bytes = synth_configs_bytes();
        let cfg = parse_odoh_config(&bytes, Duration::from_secs(3600)).unwrap();
        assert!(!cfg.key_id.is_empty());
        assert!(!cfg.is_expired());
    }

    #[test]
    fn parse_rejects_garbage() {
        let bytes = [0xffu8; 16];
        assert!(parse_odoh_config(&bytes, Duration::from_secs(3600)).is_err());
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(parse_odoh_config(&[], Duration::from_secs(3600)).is_err());
    }

    #[test]
    fn ttl_capped_at_max() {
        let bytes = synth_configs_bytes();
        let cfg = parse_odoh_config(&bytes, Duration::from_secs(100 * 24 * 60 * 60)).unwrap();
        let remaining = cfg.expires_at.saturating_duration_since(Instant::now());
        assert!(remaining <= MAX_CONFIG_TTL);
        assert!(remaining >= MAX_CONFIG_TTL - Duration::from_secs(1));
    }

    #[test]
    fn cache_control_parses_max_age() {
        let mut h = HeaderMap::new();
        h.insert("cache-control", "public, max-age=86400".parse().unwrap());
        assert_eq!(cache_control_ttl(&h), Some(Duration::from_secs(86400)));
    }

    #[test]
    fn cache_control_ignores_max_age_zero() {
        let mut h = HeaderMap::new();
        h.insert("cache-control", "max-age=0, no-store".parse().unwrap());
        assert_eq!(cache_control_ttl(&h), None);
    }

    #[test]
    fn cache_control_missing_falls_back() {
        let h = HeaderMap::new();
        assert_eq!(cache_control_ttl(&h), None);
    }

    #[test]
    fn is_expired_tracks_ttl() {
        let bytes = synth_configs_bytes();
        let mut cfg = parse_odoh_config(&bytes, Duration::from_secs(3600)).unwrap();
        assert!(!cfg.is_expired());
        cfg.expires_at = Instant::now() - Duration::from_secs(1);
        assert!(cfg.is_expired());
    }

    #[tokio::test]
    async fn cache_backoff_blocks_refetch_after_failure() {
        // Point the cache at a host that does not exist so the fetch fails
        // deterministically; this exercises the backoff wiring without a
        // network round-trip succeeding.
        let cache = OdohConfigCache::new(
            "odoh-target.invalid".to_string(),
            crate::forward::numa_tls_builder()
                .timeout(Duration::from_millis(200))
                .build()
                .unwrap(),
        );

        let first = cache.get().await;
        assert!(first.is_err(), "first fetch must fail against invalid host");

        // Within the backoff window, the cached error is returned immediately.
        let second = cache.get().await.unwrap_err().to_string();
        assert!(
            second.contains("backoff active"),
            "expected backoff hint, got: {second}"
        );

        // Reaching past the backoff window allows a fresh attempt — simulate
        // by rewinding the recorded failure timestamp.
        cache.last_failure.store(Some(Arc::new(FailedRefresh {
            at: Instant::now() - (REFRESH_BACKOFF + Duration::from_secs(1)),
            err: "prior".to_string(),
        })));
        let third = cache.get().await.unwrap_err().to_string();
        assert!(
            !third.contains("backoff active"),
            "expected fresh fetch attempt, got: {third}"
        );
    }

    /// Round-trip the HPKE seal/unseal path in isolation from HTTP, using the
    /// odoh-rs primitives that `query_through_relay` wires together. Guards
    /// against silently breaking the crypto glue if we refactor that path.
    #[test]
    fn seal_unseal_round_trip() {
        use odoh_rs::{decrypt_query, encrypt_response, ResponseNonce};

        let kp = ObliviousDoHKeyPair::from_parameters(
            KEM_X25519,
            KDF_SHA256,
            AEAD_AES128GCM,
            &[0u8; 32],
        );

        let query_wire = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let query_pt = ObliviousDoHMessagePlaintext::new(query_wire, 0);
        let mut os = OsRng;
        let mut rng = os.unwrap_mut();
        let (query_enc, client_secret) =
            odoh_rs::encrypt_query(&query_pt, kp.public(), &mut rng).unwrap();

        let (query_back, server_secret) = decrypt_query(&query_enc, &kp).unwrap();
        assert_eq!(query_back.into_msg().as_ref(), query_wire);

        let response_wire = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00";
        let response_pt = ObliviousDoHMessagePlaintext::new(response_wire, 0);
        let response_enc = encrypt_response(
            &query_pt,
            &response_pt,
            server_secret,
            ResponseNonce::default(),
        )
        .unwrap();

        let response_back =
            odoh_rs::decrypt_response(&query_pt, &response_enc, client_secret).unwrap();
        assert_eq!(response_back.into_msg().as_ref(), response_wire);
    }
}
