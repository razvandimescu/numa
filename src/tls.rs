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

/// Collect all service + LAN peer names and regenerate the TLS cert.
pub fn regenerate_tls(ctx: &ServerCtx) {
    let tls = match &ctx.tls_config {
        Some(t) => t,
        None => return,
    };

    let mut names: HashSet<String> = ctx.services.lock().unwrap().names().into_iter().collect();
    names.extend(ctx.lan_peers.lock().unwrap().names());
    let names: Vec<String> = names.into_iter().collect();

    match build_tls_config(&ctx.proxy_tld, &names) {
        Ok(new_config) => {
            tls.store(new_config);
            info!("TLS cert regenerated for {} services", names.len());
        }
        Err(e) => warn!("TLS regeneration failed: {}", e),
    }
}

/// Build a TLS config with a cert covering all provided service names.
/// Wildcards under single-label TLDs (*.numa) are rejected by browsers,
/// so we list each service explicitly as a SAN.
pub fn build_tls_config(tld: &str, service_names: &[String]) -> crate::Result<Arc<ServerConfig>> {
    let dir = crate::data_dir();
    let (ca_cert, ca_key) = ensure_ca(&dir)?;
    let (cert_chain, key) = generate_service_cert(&ca_cert, &ca_key, tld, service_names)?;

    // Ensure a crypto provider is installed (rustls needs one)
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    info!(
        "TLS configured for {} .{} domains",
        service_names.len(),
        tld
    );
    Ok(Arc::new(config))
}

fn ensure_ca(dir: &Path) -> crate::Result<(rcgen::Certificate, KeyPair)> {
    let ca_key_path = dir.join("ca.key");
    let ca_cert_path = dir.join("ca.pem");

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
        .push(DnType::CommonName, "Numa Local CA");
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

    // Add each service as an explicit SAN: numa.numa, peekm.numa, api.numa, etc.
    let mut sans = Vec::new();
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
