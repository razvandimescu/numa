use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use log::{error, info, warn};

use crate::config::Config;
use crate::ctx::ServerCtx;
use crate::service_store::ServiceStore;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
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
    if ctx.tls_byo {
        // User-provided cert: numa doesn't own it, can't reissue.
        return;
    }

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

/// Decide the HTTPS proxy's initial TLS config: BYO cert if both paths
/// are set, local-CA otherwise. Returns `(_, true)` for BYO so callers
/// know to suppress regeneration.
pub fn build_proxy_tls(
    config: &Config,
    service_store: &ServiceStore,
    data_dir: &Path,
) -> (Option<ArcSwap<ServerConfig>>, bool) {
    if !config.proxy.enabled || config.proxy.tls_port == 0 {
        return (None, false);
    }
    match (&config.proxy.cert_path, &config.proxy.key_path) {
        (Some(cert), Some(key)) => match load_pem_tls_config(cert, key, Vec::new()) {
            Ok(cfg) => {
                info!(
                    "HTTPS proxy: serving user-provided cert from {}",
                    cert.display()
                );
                (Some(ArcSwap::from(cfg)), true)
            }
            Err(e) => {
                warn!(
                    "HTTPS proxy disabled: failed to load {}: {}",
                    cert.display(),
                    e
                );
                (None, false)
            }
        },
        (Some(_), None) | (None, Some(_)) => {
            error!("[proxy] cert_path and key_path must both be set — HTTPS proxy disabled");
            (None, false)
        }
        (None, None) => {
            let names = service_store.names();
            match build_tls_config(&config.proxy.tld, &names, Vec::new(), data_dir) {
                Ok(cfg) => (Some(ArcSwap::from(cfg)), false),
                Err(e) => {
                    if let Some(advisory) = try_data_dir_advisory(&e, data_dir) {
                        eprint!("{}", advisory);
                    } else {
                        warn!("TLS setup failed, HTTPS proxy disabled: {}", e);
                    }
                    (None, false)
                }
            }
        }
    }
}

/// Load a TLS server config from user-supplied cert + key PEM files.
/// Shared by the HTTPS proxy and DoT listener for their respective BYO
/// cert paths. `alpn` is advertised in the ServerHello — empty for the
/// proxy (negotiates per-connection), `[b"dot"]` for DoT (RFC 7858 §3.2).
pub fn load_pem_tls_config(
    cert_path: &Path,
    key_path: &Path,
    alpn: Vec<Vec<u8>>,
) -> crate::Result<Arc<ServerConfig>> {
    // rustls needs a CryptoProvider installed before ServerConfig::builder().
    // Idempotent: returns Err if one is already installed (which we ignore).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", cert_path.display()).into());
    }
    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or_else(|| format!("no private key found in {}", key_path.display()))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = alpn;

    Ok(Arc::new(config))
}

/// Advisory for TLS-setup failures caused by a non-writable data dir;
/// `None` if not applicable so the caller can fall back to the raw error.
pub fn try_data_dir_advisory(err: &crate::Error, data_dir: &Path) -> Option<String> {
    let io_err = err.downcast_ref::<std::io::Error>()?;
    if io_err.kind() != std::io::ErrorKind::PermissionDenied {
        return None;
    }
    let o = "\x1b[1;38;2;192;98;58m";
    let r = "\x1b[0m";
    Some(format!(
        "
{o}Numa{r} — HTTPS proxy disabled: cannot write TLS CA to {}.

  The data directory is not writable by the current user. Numa needs
  to persist a local Certificate Authority there to serve .numa over
  HTTPS. DNS resolution and plain-HTTP proxy continue to work.

  Fix — pick one:

    1. Install Numa as the system resolver (sets up a writable data dir):

         sudo numa install       (on Windows, run as Administrator)

    2. Point data_dir at a path you can write.
       Create {} with:

         [server]
         data_dir = \"/path/you/can/write\"

",
        data_dir.display(),
        crate::suggested_config_path().display()
    ))
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
    let (ca_der, issuer) = ensure_ca(data_dir)?;
    let (cert_chain, key) = generate_service_cert(&ca_der, &issuer, tld, service_names)?;

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

fn ensure_ca(dir: &Path) -> crate::Result<(CertificateDer<'static>, Issuer<'static, KeyPair>)> {
    let ca_key_path = dir.join("ca.key");
    let ca_cert_path = dir.join(CA_FILE_NAME);

    if ca_key_path.exists() && ca_cert_path.exists() {
        let key_pem = std::fs::read_to_string(&ca_key_path)?;
        let cert_pem = std::fs::read_to_string(&ca_cert_path)?;
        let key_pair = KeyPair::from_pem(&key_pem)?;
        let ca_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .ok_or("empty CA PEM file")??;
        let issuer = Issuer::from_ca_cert_der(&ca_der, key_pair)?;
        info!("loaded CA from {:?}", ca_cert_path);
        return Ok((ca_der, issuer));
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
    let ca_der = cert.der().clone();
    let issuer = Issuer::new(params, key_pair);
    Ok((ca_der, issuer))
}

/// Generate a cert with explicit SANs for each service name.
/// Always regenerated at startup (~5ms) — no disk caching needed.
fn generate_service_cert(
    ca_der: &CertificateDer<'static>,
    issuer: &Issuer<'_, KeyPair>,
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

    // Loopback IP SANs so browsers can reach DoH at https://127.0.0.1/dns-query
    sans.push(SanType::IpAddress(std::net::IpAddr::V4(
        std::net::Ipv4Addr::LOCALHOST,
    )));
    sans.push(SanType::IpAddress(std::net::IpAddr::V6(
        std::net::Ipv6Addr::LOCALHOST,
    )));

    for name in ["localhost", tld] {
        match name.to_string().try_into() {
            Ok(ia5) => sans.push(SanType::DnsName(ia5)),
            Err(e) => warn!("invalid SAN {}: {}", name, e),
        }
    }

    params.subject_alt_names = sans;
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(CERT_VALIDITY_DAYS);

    let cert = params.signed_by(&key_pair, issuer)?;

    info!(
        "generated TLS cert for: {}",
        service_names
            .iter()
            .map(|n| format!("{}.{}", n, tld))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let cert_der = cert.der().clone();
    let ca_cert_der = ca_der.clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Ok((vec![cert_der, ca_cert_der], key_der))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn try_data_dir_advisory_permission_denied() {
        let err: crate::Error =
            Box::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        let path = PathBuf::from("/usr/local/var/numa");
        let msg = try_data_dir_advisory(&err, &path).expect("should advise");
        assert!(msg.contains("HTTPS proxy disabled"));
        assert!(msg.contains("/usr/local/var/numa"));
        assert!(msg.contains("numa install"));
        assert!(msg.contains("data_dir"));
    }

    #[test]
    fn try_data_dir_advisory_skips_other_io_kinds() {
        let err: crate::Error = Box::new(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(try_data_dir_advisory(&err, &PathBuf::from("/x")).is_none());
    }

    #[test]
    fn try_data_dir_advisory_skips_non_io_errors() {
        let err: crate::Error = "rcgen failure".into();
        assert!(try_data_dir_advisory(&err, &PathBuf::from("/x")).is_none());
    }

    #[test]
    fn service_cert_contains_expected_sans() {
        use x509_parser::prelude::GeneralName;

        let dir = std::env::temp_dir().join(format!("numa-test-san-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (ca_der, issuer) = ensure_ca(&dir).unwrap();

        let names = vec!["grafana".into(), "router".into()];
        let (chain, _) = generate_service_cert(&ca_der, &issuer, "numa", &names).unwrap();
        assert_eq!(chain.len(), 2, "chain should be [leaf, CA]");

        let (_, cert) = x509_parser::parse_x509_certificate(chain[0].as_ref()).unwrap();
        let san = cert
            .tbs_certificate
            .subject_alternative_name()
            .unwrap()
            .unwrap();

        let dns: Vec<&str> = san
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::DNSName(s) => Some(*s),
                _ => None,
            })
            .collect();

        let ips: Vec<std::net::IpAddr> = san
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::IPAddress(b) => match b.len() {
                    4 => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        b[0], b[1], b[2], b[3],
                    ))),
                    16 => {
                        let a: [u8; 16] = (*b).try_into().unwrap();
                        Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(a)))
                    }
                    _ => None,
                },
                _ => None,
            })
            .collect();

        // DNS SANs
        assert!(dns.contains(&"*.numa"), "missing wildcard SAN");
        assert!(dns.contains(&"grafana.numa"), "missing service SAN");
        assert!(dns.contains(&"router.numa"), "missing service SAN");
        assert!(dns.contains(&"localhost"), "missing localhost SAN");
        assert!(dns.contains(&"numa"), "missing bare TLD SAN");

        // IP SANs
        assert!(
            ips.contains(&std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            "missing 127.0.0.1 SAN"
        );
        assert!(
            ips.contains(&std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            "missing ::1 SAN"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn fresh_temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("numa-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_self_signed_pem_pair(dir: &Path, dns: &str) -> (PathBuf, PathBuf) {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .subject_alt_names
            .push(SanType::DnsName(dns.try_into().unwrap()));
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
        (cert_path, key_path)
    }

    #[test]
    fn load_pem_tls_config_round_trip() {
        let dir = fresh_temp_dir("pem");
        let (cert_path, key_path) = write_self_signed_pem_pair(&dir, "example.test");

        let config =
            load_pem_tls_config(&cert_path, &key_path, Vec::new()).expect("load self-signed pair");
        assert!(config.alpn_protocols.is_empty(), "proxy ALPN stays empty");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn regenerate_tls_is_noop_in_byo_mode() {
        let mut ctx = crate::testutil::test_ctx().await;
        let dir = fresh_temp_dir("byo");
        ctx.data_dir = dir.clone();

        let (cert_path, key_path) = write_self_signed_pem_pair(&dir, "byo.test");
        let user_cfg = load_pem_tls_config(&cert_path, &key_path, Vec::new()).unwrap();

        ctx.tls_config = Some(arc_swap::ArcSwap::from(Arc::clone(&user_cfg)));
        ctx.tls_byo = true;

        regenerate_tls(&ctx);

        let after = ctx.tls_config.as_ref().unwrap().load_full();
        assert!(
            Arc::ptr_eq(&user_cfg, &after),
            "BYO cert must not be replaced by regenerate_tls"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_pem_tls_config_rejects_empty_cert() {
        let dir = fresh_temp_dir("pem-empty");
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, b"").unwrap();
        std::fs::write(&key_path, b"").unwrap();

        let err = load_pem_tls_config(&cert_path, &key_path, Vec::new())
            .expect_err("empty PEM must fail");
        assert!(
            err.to_string().contains("no certificates found"),
            "unexpected error: {}",
            err
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
