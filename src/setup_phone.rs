//! `numa setup-phone` CLI — thin QR wrapper over the persistent mobile API.
//!
//! Before the mobile API existed, this command spawned its own one-shot
//! HTTP server on port 8765 to serve a freshly-generated mobileconfig
//! for a single download. That role now belongs to
//! [`crate::mobile_api`], which runs persistently alongside the main
//! API and serves `/mobileconfig` at the same port whenever Numa is
//! running.
//!
//! This command is now a thin terminal-side wrapper:
//!
//!   1. Detect the current LAN IP
//!   2. Render a terminal QR code pointing at
//!      `http://<lan_ip>:8765/mobileconfig`
//!   3. Print install instructions and exit
//!
//! The user scans the QR, iOS fetches the profile from the mobile API
//! (which is always up as long as `numa` is running), installs, and the
//! user walks through Settings → Certificate Trust Settings to enable
//! trust.
//!
//! Numa must be running for the profile download to succeed; if the
//! mobile API is not listening on port 8765, the download will fail
//! and the user will see Safari's "Cannot Connect to Server" error.
//! The CLI prints a reminder about this at the bottom of the output.

use qrcode::render::unicode;
use qrcode::QrCode;

/// Default port where the persistent mobile API serves `/mobileconfig`.
/// Matches `MobileConfig::default().port` in `config.rs`. If the user
/// has overridden `[mobile] port = N` in `numa.toml`, they'll need to
/// adjust the URL manually — this CLI uses the default without parsing
/// `numa.toml`.
const SETUP_PORT: u16 = 8765;

fn render_qr(url: &str) -> Result<String, String> {
    let code = QrCode::new(url).map_err(|e| format!("failed to encode QR: {}", e))?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build())
}

/// Run the `numa setup-phone` flow.
pub async fn run() -> Result<(), String> {
    let lan_ip = crate::lan::detect_lan_ip()
        .ok_or("could not detect LAN IP — are you connected to a network?")?;

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], SETUP_PORT));
    let api_reachable = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);

    if !api_reachable {
        eprintln!();
        eprintln!(
            "  \x1b[1;38;5;166mNuma\x1b[0m — mobile API is not reachable on port {}.",
            SETUP_PORT
        );
        eprintln!();
        eprintln!("  The phone won't be able to download the profile until the mobile");
        eprintln!("  API is running. Add this to your numa.toml and restart Numa:");
        eprintln!();
        eprintln!("    [mobile]");
        eprintln!("    enabled = true");
        eprintln!();
        return Err("mobile API not running".into());
    }

    let url = format!("http://{}:{}/mobileconfig", lan_ip, SETUP_PORT);
    let qr = render_qr(&url)?;

    eprintln!();
    eprintln!("  \x1b[1;38;5;166mNuma Phone Setup\x1b[0m");
    eprintln!();
    eprintln!("  Profile URL: \x1b[36m{}\x1b[0m", url);
    eprintln!();
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
    eprintln!("  laptop changes networks, re-scan this QR — iOS will replace the");
    eprintln!("  existing profile automatically (fixed UUID).");
    eprintln!();
    eprintln!(
        "  \x1b[90mThe profile is served by Numa's persistent mobile API on port {}.\x1b[0m",
        SETUP_PORT
    );
    eprintln!("  \x1b[90mMake sure `numa` is running before scanning. If it's not,\x1b[0m");
    eprintln!("  \x1b[90mstart it with `sudo numa install` or run it interactively.\x1b[0m");
    eprintln!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_qr_produces_unicode() {
        let qr = render_qr("http://192.168.1.9:8765/mobileconfig").unwrap();
        assert!(!qr.is_empty());
        // Dense1x2 uses these block characters
        assert!(qr.chars().any(|c| matches!(c, '█' | '▀' | '▄' | ' ')));
    }
}
