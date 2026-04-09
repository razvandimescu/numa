use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use log::{info, warn};

use crate::ctx::ServerCtx;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};

const CA_VALIDITY_DAYS: i64 = 3650; // 10 years
const CERT_VALIDITY_DAYS: i64 = 365; // 1 year

/// Common Name on Numa's local CA. Referenced by trust-store helpers
/// (`security`, `certutil`) when locating the cert for removal.
pub const CA_COMMON_NAME: &str = "Numa Local CA";

/// Filename of the CA certificate inside the data dir.
pub const CA_FILE_NAME: &str = "ca.pem";

/// Collect all service + LAN peer names and regenerate the TLS cert.
pub fn regenerate_tls(ctx: &ServerCtx) {
    let tls = match &ctx.tls_config {
        Some(t) => t,
        None => return,
    };

    let mut names: HashSet<String> = ctx.services.lock().unwrap().names().into_iter().collect();
    names.extend(ctx.lan_peers.lock().unwrap().names());
    let names: Vec<String> = names.into_iter().collect();

    match build_tls_config(&ctx.proxy_tld, &names, Vec::new(), &ctx.data_dir) {
        Ok(new_config) => {
            tls.store(new_config);
            info!("TLS cert regenerated for {} services", names.len());
        }
        Err(e) => warn!("TLS regeneration failed: {}", e),
    }
}

/// Human-readable diagnostic for TLS data-dir permission failures.
/// Triggered when numa can't write its local CA to the configured
/// data dir (typically `/usr/local/var/numa` without root). HTTPS
/// proxy is disabled; DNS resolution and plain-HTTP proxy keep
/// working.
pub fn data_dir_permission_advisory(data_dir: &Path) -> String {
    let o = "\x1b[1;38;2;192;98;58m"; // bold orange
    let r = "\x1b[0m";
    format!(
        "
{o}Numa{r} — HTTPS proxy disabled: cannot write TLS CA to {}.

  The data directory is not writable by the current user. Numa needs
  to persist a local Certificate Authority there to serve .numa over
  HTTPS. DNS resolution and plain-HTTP proxy continue to work.

  Fix — pick one:

    1. Install Numa as the system resolver (sets up a writable data dir):

         sudo numa install       (on Windows, run as Administrator)

    2. Point data_dir at a path you can write.
       Create ~/.config/numa/numa.toml with:

         [server]
         data_dir = \"/path/you/can/write\"

",
        data_dir.display()
    )
}

/// Build a TLS config with a cert covering all provided service names.
/// Wildcards under single-label TLDs (*.numa) are rejected by browsers,
/// so we list each service explicitly as a SAN.
/// `alpn` is advertised in the TLS ServerHello — pass empty for the proxy
/// (which accepts any ALPN), or `[b"dot"]` for DoT (RFC 7858 §3.2).
/// `data_dir` is where the CA material is stored — taken from
/// `[server] data_dir` in numa.toml (defaults to `crate::data_dir()`).
pub fn build_tls_config(
    tld: &str,
    service_names: &[String],
    alpn: Vec<Vec<u8>>,
    data_dir: &Path,
) -> crate::Result<Arc<ServerConfig>> {
    let (ca_cert, ca_key) = ensure_ca(data_dir)?;
    let (cert_chain, key) = generate_service_cert(&ca_cert, &ca_key, tld, service_names)?;

    // Ensure a crypto provider is installed (rustls needs one)
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    config.alpn_protocols = alpn;

    info!(
        "TLS configured for {} .{} domains",
        service_names.len(),
        tld
    );
    Ok(Arc::new(config))
}

fn ensure_ca(dir: &Path) -> crate::Result<(rcgen::Certificate, KeyPair)> {
    let ca_key_path = dir.join("ca.key");
    let ca_cert_path = dir.join(CA_FILE_NAME);

    if ca_key_path.exists() && ca_cert_path.exists() {
        let key_pem = std::fs::read_to_string(&ca_key_path)?;
        let cert_pem = std::fs::read_to_string(&ca_cert_path)?;
        let key_pair = KeyPair::from_pem(&key_pem)?;
        let params = CertificateParams::from_ca_cert_pem(&cert_pem)?;
        let cert = params.self_signed(&key_pair)?;
        info!("loaded CA from {:?}", ca_cert_path);
        return Ok((cert, key_pair));
    }

    // Generate new CA
    std::fs::create_dir_all(dir)?;

    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(CA_VALIDITY_DAYS);

    let cert = params.self_signed(&key_pair)?;

    std::fs::write(&ca_key_path, key_pair.serialize_pem())?;
    std::fs::write(&ca_cert_path, cert.pem())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ca_key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!("generated CA at {:?}", ca_cert_path);
    Ok((cert, key_pair))
}

/// Generate a cert with explicit SANs for each service name.
/// Always regenerated at startup (~5ms) — no disk caching needed.
fn generate_service_cert(
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
    tld: &str,
    service_names: &[String],
) -> crate::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("Numa .{} services", tld));

    // Add a wildcard SAN so any .numa domain gets a valid cert (including
    // unregistered services — lets the proxy show a styled 404 over HTTPS).
    // Also add each service explicitly for clients that don't match wildcards.
    let mut sans = Vec::new();
    let wildcard = format!("*.{}", tld);
    match wildcard.clone().try_into() {
        Ok(ia5) => sans.push(SanType::DnsName(ia5)),
        Err(e) => warn!("invalid wildcard SAN {}: {}", wildcard, e),
    }
    for name in service_names {
        let fqdn = format!("{}.{}", name, tld);
        match fqdn.clone().try_into() {
            Ok(ia5) => sans.push(SanType::DnsName(ia5)),
            Err(e) => warn!("invalid SAN {}: {}", fqdn, e),
        }
    }

    if sans.is_empty() {
        return Err("no valid service names for TLS cert".into());
    }

    params.subject_alt_names = sans;
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(CERT_VALIDITY_DAYS);

    let cert = params.signed_by(&key_pair, ca_cert, ca_key)?;

    info!(
        "generated TLS cert for: {}",
        service_names
            .iter()
            .map(|n| format!("{}.{}", n, tld))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let ca_der = CertificateDer::from(ca_cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Ok((vec![cert_der, ca_der], key_der))
}
