//! Apple `.mobileconfig` profile generator.
//!
//! Builds iOS Configuration Profiles that Numa serves to phones for one-tap
//! CA trust and DNS-over-TLS setup. The plist structure is hand-rendered
//! via `format!` — no plist crate dependency, deterministic output, small
//! binary footprint.
//!
//! Two modes:
//!
//! - [`ProfileMode::Full`]: CA trust payload + DNS settings payload pointing
//!   at a specific LAN IP over DoT. This is what `numa setup-phone` has
//!   always produced — the user scans a QR, installs this profile, and the
//!   phone is configured for DoT through Numa in a single step (after the
//!   iOS Certificate Trust Settings toggle, which is a separate system
//!   gate we can't bypass).
//!
//! - [`ProfileMode::CaOnly`]: CA trust payload only, no DNS settings. Used
//!   by the future iOS companion app flow where `NEDNSSettingsManager`
//!   configures DNS programmatically and we only need the system trust
//!   store to accept Numa's DoT cert. Installing this profile does NOT
//!   change the user's DNS at all.
//!
//! Payload identifiers and UUIDs are fixed (not randomized) so iOS replaces
//! the existing profile on re-install rather than accumulating duplicates.
//! The `Full` and `CaOnly` profiles have distinct top-level UUIDs so they
//! can coexist as separate installed profiles, but they share the same CA
//! payload UUID since the CA itself is the same trust anchor in both.

use std::net::Ipv4Addr;

/// Top-level UUID and PayloadIdentifier for the full profile (CA + DNS).
/// Changing this breaks in-place replacement on existing iOS installs.
const FULL_PROFILE_UUID: &str = "F1E2D3C4-B5A6-7890-1234-567890ABCDEF";
const FULL_PROFILE_ID: &str = "com.numa.dns.profile";

/// Top-level UUID and PayloadIdentifier for the CA-only profile.
/// Distinct from `FULL_PROFILE_UUID` so a user can install one, the other,
/// or both without the latest install silently replacing a different mode.
const CA_ONLY_PROFILE_UUID: &str = "F2E3D4C5-B6A7-8901-2345-67890ABCDEF0";
const CA_ONLY_PROFILE_ID: &str = "com.numa.dns.ca.profile";

/// CA trust payload UUID. Same in both modes — iOS will see "the same CA
/// trust anchor" regardless of which wrapping profile contains it.
const CA_PAYLOAD_UUID: &str = "B2C3D4E5-F6A7-8901-BCDE-F12345678901";
const CA_PAYLOAD_ID: &str = "com.numa.dns.ca";

/// DNS settings payload UUID (Full mode only).
const DNS_PAYLOAD_UUID: &str = "A1B2C3D4-E5F6-7890-ABCD-EF1234567890";
const DNS_PAYLOAD_ID: &str = "com.numa.dns.dot";

/// Profile mode determines which payloads are included in the generated
/// `.mobileconfig`.
#[derive(Debug, Clone)]
pub enum ProfileMode {
    /// Full profile: CA trust anchor + managed DNS settings payload
    /// pointing at the given LAN IP over DoT. This is what the classic
    /// `numa setup-phone` QR flow serves.
    Full { lan_ip: Ipv4Addr },

    /// CA-only profile: just the trust anchor, no DNS settings. For use
    /// with the iOS companion app which manages DNS programmatically via
    /// `NEDNSSettingsManager` and only needs the system trust store to
    /// accept Numa's self-signed DoT cert.
    CaOnly,
}

/// Build a full `.mobileconfig` profile as an XML plist string.
pub fn build_mobileconfig(mode: ProfileMode, ca_pem: &str) -> String {
    let ca_payload = build_ca_payload(ca_pem);

    match mode {
        ProfileMode::Full { lan_ip } => {
            let dns_payload = build_dns_payload(lan_ip);
            let payloads = format!("{}\n{}", ca_payload, dns_payload);
            let description = format!(
                "Trusts the Numa local CA and routes DNS queries to Numa over DoT on your local network ({lan_ip})"
            );
            wrap_plist(
                &payloads,
                FULL_PROFILE_UUID,
                FULL_PROFILE_ID,
                &description,
                "Numa DNS",
            )
        }
        ProfileMode::CaOnly => wrap_plist(
            &ca_payload,
            CA_ONLY_PROFILE_UUID,
            CA_ONLY_PROFILE_ID,
            "Trusts the Numa local Certificate Authority. Does not change your DNS settings.",
            "Numa CA",
        ),
    }
}

/// Strip the PEM header/footer and newlines from a CA cert, leaving raw
/// base64 for embedding in a plist `<data>` block.
fn pem_to_base64(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>()
}

/// Wrap the base64 CA cert at 52 chars per line for plist readability
/// (matches Apple convention in hand-written profiles).
fn chunk_base64(base64: &str) -> String {
    base64
        .chars()
        .collect::<Vec<_>>()
        .chunks(52)
        .map(|chunk| format!("\t\t\t{}", chunk.iter().collect::<String>()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render the `com.apple.security.root` payload dict containing the CA cert.
fn build_ca_payload(ca_pem: &str) -> String {
    let ca_wrapped = chunk_base64(&pem_to_base64(ca_pem));
    format!(
        r#"		<dict>
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
			<string>{ca_id}</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>{ca_uuid}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>"#,
        ca = ca_wrapped,
        ca_id = CA_PAYLOAD_ID,
        ca_uuid = CA_PAYLOAD_UUID,
    )
}

/// Render the `com.apple.dnsSettings.managed` payload dict for Full mode.
fn build_dns_payload(lan_ip: Ipv4Addr) -> String {
    format!(
        r#"		<dict>
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
			<key>OnDemandRules</key>
			<array>
				<dict>
					<key>Action</key>
					<string>Connect</string>
					<key>InterfaceTypeMatch</key>
					<string>WiFi</string>
				</dict>
				<dict>
					<key>Action</key>
					<string>Disconnect</string>
				</dict>
			</array>
			<key>PayloadDescription</key>
			<string>Routes DNS queries through Numa over DoT when on Wi-Fi</string>
			<key>PayloadDisplayName</key>
			<string>Numa DNS-over-TLS</string>
			<key>PayloadIdentifier</key>
			<string>{dns_id}</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>{dns_uuid}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>"#,
        ip = lan_ip,
        dns_id = DNS_PAYLOAD_ID,
        dns_uuid = DNS_PAYLOAD_UUID,
    )
}

/// Wrap one or more payload dicts in the top-level plist structure
/// with Configuration type, PayloadContent array, and profile metadata.
fn wrap_plist(
    payloads: &str,
    top_uuid: &str,
    top_id: &str,
    description: &str,
    display_name: &str,
) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
{payloads}
	</array>
	<key>PayloadDescription</key>
	<string>{description}</string>
	<key>PayloadDisplayName</key>
	<string>{display_name}</string>
	<key>PayloadIdentifier</key>
	<string>{top_id}</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{top_uuid}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
"#,
        payloads = payloads,
        description = description,
        display_name = display_name,
        top_id = top_id,
        top_uuid = top_uuid,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PEM: &str =
        "-----BEGIN CERTIFICATE-----\nMIIBkDCCATagAwIBAgIUTEST\n-----END CERTIFICATE-----\n";

    #[test]
    fn pem_to_base64_strips_headers() {
        let pem = "-----BEGIN CERTIFICATE-----\nABCDEF\nGHIJKL\n-----END CERTIFICATE-----\n";
        assert_eq!(pem_to_base64(pem), "ABCDEFGHIJKL");
    }

    #[test]
    fn full_profile_contains_ip_and_ca() {
        let config = build_mobileconfig(
            ProfileMode::Full {
                lan_ip: Ipv4Addr::new(192, 168, 1, 100),
            },
            SAMPLE_PEM,
        );
        assert!(config.contains("192.168.1.100"));
        assert!(config.contains("MIIBkDCCATagAwIBAgIUTEST"));
        assert!(config.contains("com.apple.security.root"));
        assert!(config.contains("com.apple.dnsSettings.managed"));
        assert!(config.contains("DNSProtocol"));
        assert!(config.contains(FULL_PROFILE_UUID));
        assert!(config.contains(FULL_PROFILE_ID));
    }

    #[test]
    fn ca_only_profile_contains_ca_but_not_dns() {
        let config = build_mobileconfig(ProfileMode::CaOnly, SAMPLE_PEM);
        assert!(config.contains("MIIBkDCCATagAwIBAgIUTEST"));
        assert!(config.contains("com.apple.security.root"));
        assert!(!config.contains("com.apple.dnsSettings.managed"));
        assert!(!config.contains("DNSProtocol"));
        assert!(!config.contains("ServerAddresses"));
        assert!(config.contains(CA_ONLY_PROFILE_UUID));
        assert!(config.contains(CA_ONLY_PROFILE_ID));
    }

    #[test]
    fn full_and_ca_only_have_distinct_top_uuids() {
        let full = build_mobileconfig(
            ProfileMode::Full {
                lan_ip: Ipv4Addr::new(10, 0, 0, 1),
            },
            SAMPLE_PEM,
        );
        let ca_only = build_mobileconfig(ProfileMode::CaOnly, SAMPLE_PEM);
        assert!(full.contains(FULL_PROFILE_UUID));
        assert!(!full.contains(CA_ONLY_PROFILE_UUID));
        assert!(ca_only.contains(CA_ONLY_PROFILE_UUID));
        assert!(!ca_only.contains(FULL_PROFILE_UUID));
    }

    #[test]
    fn both_modes_share_ca_payload_uuid() {
        let full = build_mobileconfig(
            ProfileMode::Full {
                lan_ip: Ipv4Addr::new(10, 0, 0, 1),
            },
            SAMPLE_PEM,
        );
        let ca_only = build_mobileconfig(ProfileMode::CaOnly, SAMPLE_PEM);
        assert!(full.contains(CA_PAYLOAD_UUID));
        assert!(ca_only.contains(CA_PAYLOAD_UUID));
    }
}
