use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use qrcode::render::unicode;
use qrcode::QrCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SETUP_PORT: u16 = 8765;
const RUST_OK_HEADERS: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/x-apple-aspen-config\r\nContent-Disposition: attachment; filename=\"numa.mobileconfig\"\r\nConnection: close\r\nContent-Length: ";
const RUST_NOT_FOUND: &str =
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Strip the PEM header/footer and newlines from a CA cert, leaving raw base64
/// for embedding in a plist `<data>` block.
fn pem_to_base64(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>()
}

/// Build a combined `.mobileconfig` containing:
/// 1. Root CA payload — installs and trusts the Numa local CA
/// 2. DNS payload — points the device at Numa over DoT
///
/// UUIDs and PayloadIdentifiers are intentionally fixed (not randomized) so
/// that re-running `numa setup-phone` after an IP change replaces the existing
/// profile rather than accumulating duplicates in iOS Settings.
fn build_mobileconfig(lan_ip: Ipv4Addr, ca_pem: &str) -> String {
    let ca_base64 = pem_to_base64(ca_pem);

    // Wrap base64 at 52 chars per line for plist readability (matches Apple convention)
    let ca_wrapped: String = ca_base64
        .chars()
        .collect::<Vec<_>>()
        .chunks(52)
        .map(|chunk| format!("\t\t\t{}", chunk.iter().collect::<String>()))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>numa-ca.pem</string>
			<key>PayloadContent</key>
			<data>
{ca}
			</data>
			<key>PayloadDescription</key>
			<string>Numa local Certificate Authority — required for DoT trust</string>
			<key>PayloadDisplayName</key>
			<string>Numa Local CA</string>
			<key>PayloadIdentifier</key>
			<string>com.numa.dns.ca</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>B2C3D4E5-F6A7-8901-BCDE-F12345678901</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
		<dict>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>TLS</string>
				<key>ServerAddresses</key>
				<array>
					<string>{ip}</string>
				</array>
				<key>ServerName</key>
				<string>numa.numa</string>
			</dict>
			<key>PayloadDescription</key>
			<string>Routes all DNS queries through Numa over DNS-over-TLS</string>
			<key>PayloadDisplayName</key>
			<string>Numa DNS-over-TLS</string>
			<key>PayloadIdentifier</key>
			<string>com.numa.dns.dot</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>A1B2C3D4-E5F6-7890-ABCD-EF1234567890</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Trusts the Numa local CA and routes DNS queries to Numa over DoT on your local network ({ip})</string>
	<key>PayloadDisplayName</key>
	<string>Numa DNS</string>
	<key>PayloadIdentifier</key>
	<string>com.numa.dns.profile</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>F1E2D3C4-B5A6-7890-1234-567890ABCDEF</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
"#,
        ca = ca_wrapped,
        ip = lan_ip
    )
}

fn render_qr(url: &str) -> Result<String, String> {
    let code = QrCode::new(url).map_err(|e| format!("failed to encode QR: {}", e))?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build())
}

async fn accept_loop(listener: TcpListener, profile: Arc<String>, count: Arc<AtomicUsize>) {
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => continue,
        };

        let profile = Arc::clone(&profile);
        let count = Arc::clone(&count);

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await
            {
                Ok(Ok(n)) => n,
                _ => return,
            };

            let request = String::from_utf8_lossy(&buf);
            if request.starts_with("GET /setup") || request.starts_with("GET / ") {
                let body = profile.as_bytes();
                let mut response =
                    format!("{}{}\r\n\r\n", RUST_OK_HEADERS, body.len()).into_bytes();
                response.extend_from_slice(body);
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
                let n = count.fetch_add(1, Ordering::Relaxed) + 1;
                eprintln!(
                    "  \x1b[32m✓\x1b[0m Profile downloaded by {} ({} total)",
                    peer.ip(),
                    n
                );
            } else {
                let _ = stream.write_all(RUST_NOT_FOUND.as_bytes()).await;
            }
        });
    }
}

/// Run the `numa setup-phone` flow.
pub async fn run() -> Result<(), String> {
    let lan_ip = crate::lan::detect_lan_ip()
        .ok_or("could not detect LAN IP — are you connected to a network?")?;

    let ca_path: PathBuf = crate::data_dir().join("ca.pem");
    let ca_pem = std::fs::read_to_string(&ca_path).map_err(|e| {
        format!(
            "could not read CA at {}: {} — is Numa installed and has the service started at least once?",
            ca_path.display(),
            e
        )
    })?;

    let profile = build_mobileconfig(lan_ip, &ca_pem);
    let url = format!("http://{}:{}/setup", lan_ip, SETUP_PORT);
    let qr = render_qr(&url)?;

    let bind_addr = SocketAddr::from(([0, 0, 0, 0], SETUP_PORT));
    let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
        format!(
            "could not bind setup server on port {}: {} — is another setup running?",
            SETUP_PORT, e
        )
    })?;

    eprintln!();
    eprintln!("  \x1b[1;38;2;192;98;58mNuma Phone Setup\x1b[0m\n");
    eprintln!("  Serving setup profile at: \x1b[36m{}\x1b[0m\n", url);
    for line in qr.lines() {
        eprintln!("  {}", line);
    }
    eprintln!();
    eprintln!("  \x1b[1mOn your iPhone:\x1b[0m");
    eprintln!("    1. Open Camera, point at the QR code, tap the yellow banner");
    eprintln!("    2. Allow the download when Safari asks");
    eprintln!("    3. Open Settings — tap \"Profile Downloaded\" near the top");
    eprintln!("       (or: Settings → General → VPN & Device Management → Numa DNS)");
    eprintln!("    4. Tap Install (top right), enter passcode, Install again");
    eprintln!("    5. \x1b[1mSettings → General → About → Certificate Trust Settings\x1b[0m");
    eprintln!("       Toggle ON \"Numa Local CA\" — required for DoT to work");
    eprintln!();
    eprintln!(
        "  \x1b[33mNote:\x1b[0m profile uses your laptop's current IP ({}). If your",
        lan_ip
    );
    eprintln!("  laptop changes networks, re-run this command — iOS will replace the");
    eprintln!("  existing profile automatically.");
    eprintln!();
    eprintln!("  Waiting for download (Ctrl+C to exit)...");
    eprintln!();

    let count = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(accept_loop(listener, Arc::new(profile), Arc::clone(&count)));

    let _ = tokio::signal::ctrl_c().await;
    server.abort();
    eprintln!();
    let total = count.load(Ordering::Relaxed);
    if total > 0 {
        eprintln!(
            "  Setup ended — {} download{} served",
            total,
            if total == 1 { "" } else { "s" }
        );
    } else {
        eprintln!("  Setup cancelled — no downloads served");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_to_base64_strips_headers() {
        let pem = "-----BEGIN CERTIFICATE-----\nABCDEF\nGHIJKL\n-----END CERTIFICATE-----\n";
        assert_eq!(pem_to_base64(pem), "ABCDEFGHIJKL");
    }

    #[test]
    fn mobileconfig_contains_ip_and_ca() {
        let pem =
            "-----BEGIN CERTIFICATE-----\nMIIBkDCCATagAwIBAgIUTEST\n-----END CERTIFICATE-----\n";
        let config = build_mobileconfig(Ipv4Addr::new(192, 168, 1, 100), pem);
        assert!(config.contains("192.168.1.100"));
        assert!(config.contains("MIIBkDCCATagAwIBAgIUTEST"));
        assert!(config.contains("com.apple.security.root"));
        assert!(config.contains("com.apple.dnsSettings.managed"));
        assert!(config.contains("DNSProtocol"));
    }

    #[test]
    fn render_qr_produces_unicode() {
        let qr = render_qr("http://192.168.1.9:8765/setup").unwrap();
        assert!(!qr.is_empty());
        // Dense1x2 uses these block characters
        assert!(qr.chars().any(|c| matches!(c, '█' | '▀' | '▄' | ' ')));
    }
}
