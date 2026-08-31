use numa::system_dns::{
    install_service, restart_service, service_status, start_service, stop_service,
    uninstall_service,
};

const NO_SYSTEM_DNS_FLAG: &str = "--no-system-dns";

fn main() -> numa::Result<()> {
    let palette = numa::palette::get();
    // Handle CLI subcommands
    let arg1 = std::env::args().nth(1).unwrap_or_default();

    #[cfg(windows)]
    if arg1 == "--service" {
        // Running under SCM — stderr goes nowhere. Redirect logs to a file.
        let log_path = numa::data_dir().join("numa.log");
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .expect("failed to open log file");
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .format_timestamp_millis()
            .target(env_logger::Target::Pipe(Box::new(log_file)))
            .init();
        numa::windows_service::run_as_service()
            .map_err(|e| format!("windows service dispatcher failed: {}", e))?;
        return Ok(());
    }

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let skip_system_dns = std::env::args().any(|a| a == NO_SYSTEM_DNS_FLAG);

    match arg1.as_str() {
        "install" => {
            eprintln!("{}Numa{} — installing\n", palette.brand_bold, palette.reset);
            return install_service(skip_system_dns).map_err(|e| e.into());
        }
        "uninstall" => {
            eprintln!(
                "{}Numa{} — uninstalling\n",
                palette.brand_bold, palette.reset
            );
            return uninstall_service().map_err(|e| e.into());
        }
        "service" => {
            let sub = std::env::args().nth(2).unwrap_or_default();
            eprintln!(
                "{}Numa{} — service management\n",
                palette.brand_bold, palette.reset
            );
            return match sub.as_str() {
                "start" => start_service(skip_system_dns).map_err(|e| e.into()),
                "stop" => stop_service().map_err(|e| e.into()),
                "restart" => restart_service().map_err(|e| e.into()),
                "status" => service_status().map_err(|e| e.into()),
                _ => {
                    eprintln!("Usage: numa service <start|stop|restart|status>");
                    Ok(())
                }
            };
        }
        "config" => {
            let sub = std::env::args().nth(2).unwrap_or_default();
            return match sub.as_str() {
                "path" => numa::config_cli::print_config_path().map_err(|e| e.into()),
                "edit" => numa::config_cli::edit_config().map_err(|e| e.into()),
                _ => {
                    eprintln!("Usage: numa config <path|edit>");
                    Ok(())
                }
            };
        }
        "setup-phone" => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            return runtime
                .block_on(numa::setup_phone::run())
                .map_err(|e| e.into());
        }
        "relay" => {
            let port: u16 = std::env::args()
                .nth(2)
                .as_deref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8443);
            let bind: std::net::IpAddr = std::env::args()
                .nth(3)
                .as_deref()
                .map(|s| {
                    s.parse().unwrap_or_else(|e| {
                        eprintln!("invalid bind address '{}': {}", s, e);
                        std::process::exit(1);
                    })
                })
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            let addr = std::net::SocketAddr::new(bind, port);
            eprintln!(
                "{}Numa{} — ODoH relay on {}\n",
                palette.brand_bold, palette.reset, addr
            );
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            return runtime.block_on(numa::relay::run(addr));
        }
        "lan" | "block" | "dnssec" => {
            let sub = std::env::args().nth(2).unwrap_or_default();
            let enabled = match sub.as_str() {
                "on" => true,
                "off" => false,
                _ => {
                    eprintln!("Usage: numa {} <on|off> [config-path]", arg1);
                    return Ok(());
                }
            };
            // The daemon knows which file it loaded; a cwd-relative guess
            // writes a config nothing reads under systemd or launchd (#371).
            let config_path = match std::env::args().nth(3) {
                Some(explicit) => explicit,
                None => numa::config_cli::config_write_target()?,
            };
            let (section, feature_name) = match arg1.as_str() {
                "lan" => ("lan", "LAN discovery"),
                "block" => ("blocking", "ad-blocking"),
                "dnssec" => ("dnssec", "DNSSEC validation"),
                _ => unreachable!(),
            };
            return set_config_bool(&config_path, section, "enabled", enabled, feature_name);
        }
        "version" | "--version" | "-V" => {
            eprintln!("numa {}", numa::version());
            return Ok(());
        }
        "help" | "--help" | "-h" => {
            eprintln!("Usage: numa [command] [config-path]");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  (none)          Start the DNS server (default)");
            eprintln!("  install         Set system DNS to 127.0.0.1 (requires sudo)");
            eprintln!(
                "                  {}  Install service only; leave system DNS alone",
                NO_SYSTEM_DNS_FLAG
            );
            eprintln!("  uninstall       Restore original system DNS settings");
            eprintln!("  service start   Install as system service (auto-start on boot)");
            eprintln!(
                "                  {}  Same as 'install {}'",
                NO_SYSTEM_DNS_FLAG, NO_SYSTEM_DNS_FLAG
            );
            eprintln!("  service stop    Uninstall the system service");
            eprintln!("  service restart Restart the service with updated binary");
            eprintln!("  service status  Check if the service is running");
            eprintln!("  config path     Show the effective config file");
            eprintln!("  config edit     Open the effective config file in an editor");
            eprintln!("  lan on|off      Enable/disable LAN service discovery (mDNS)");
            eprintln!("  block on|off    Enable/disable ad-blocking");
            eprintln!("  dnssec on|off   Enable/disable DNSSEC validation");
            eprintln!("  relay [PORT] [BIND]");
            eprintln!("                  Run as an ODoH relay (RFC 9230, default 127.0.0.1:8443)");
            eprintln!("  setup-phone     Generate a QR code to install Numa DoT on a phone");
            eprintln!("  help            Show this help");
            eprintln!();
            eprintln!("Config path defaults to numa.toml");
            return Ok(());
        }
        _ => {
            if !arg1.is_empty()
                && arg1 != "run"
                && !arg1.contains('/')
                && !arg1.contains('\\')
                && !arg1.ends_with(".toml")
            {
                eprintln!(
                    "{}Numa{} — unknown command: {}{}{}\n",
                    palette.brand_bold, palette.reset, palette.bold, arg1, palette.reset
                );
                eprintln!(
                    "Run {}numa help{} for a list of commands.",
                    palette.bold, palette.reset
                );
                std::process::exit(1);
            }
        }
    }

    let config_path = if arg1.is_empty() || arg1 == "run" {
        std::env::args()
            .nth(2)
            .unwrap_or_else(|| "numa.toml".to_string())
    } else {
        arg1 // treat as config path for backwards compatibility
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(numa::serve::run(config_path))
}

fn set_config_bool(
    path: &str,
    section: &str,
    key: &str,
    value: bool,
    feature_name: &str,
) -> numa::Result<()> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = std::path::Path::new(path)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, format!("[{}]\n{} = {}\n", section, key, value))?;
            print_toggle_status(feature_name, value, path);
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let result = update_config_content(&contents, section, key, value);
    std::fs::write(path, result)?;
    print_toggle_status(feature_name, value, path);
    Ok(())
}

fn update_config_content(contents: &str, section: &str, key: &str, value: bool) -> String {
    let section_header = format!("[{}]", section);
    let mut in_section = false;
    let mut found = false;
    let mut lines: Vec<String> = contents
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_section = trimmed == section_header;
            }
            if in_section && !found {
                if let Some((k, _)) = trimmed.split_once('=') {
                    if k.trim() == key {
                        found = true;
                        let indent = &line[..line.len() - trimmed.len()];
                        return format!("{}{} = {}", indent, key, value);
                    }
                }
            }
            line.to_string()
        })
        .collect();

    if !found {
        if let Some(i) = lines.iter().position(|l| l.trim() == section_header) {
            lines.insert(i + 1, format!("{} = {}", key, value));
        } else {
            if !lines.is_empty() && !lines.last().unwrap().is_empty() {
                lines.push(String::new());
            }
            lines.push(section_header);
            lines.push(format!("{} = {}", key, value));
        }
    }

    let mut result = lines.join("\n");
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result
}

fn print_toggle_status(feature: &str, enabled: bool, path: &str) {
    let label = if enabled { "enabled" } else { "disabled" };
    let palette = numa::palette::get();
    let color = if enabled {
        palette.green
    } else {
        palette.warning
    };
    eprintln!(
        "{}Numa{} — {} {}{}{}",
        palette.brand_bold, palette.reset, feature, color, label, palette.reset
    );
    eprintln!("  Wrote {}", path);
    if enabled {
        eprintln!("  Restart Numa for changes to take effect");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_config_content() {
        let input =
            "[dnssec]\nstrict = true\n\n[lan]\nenabled = false\n\n[blocking]\nrefresh_hours = 24\n";

        let output = update_config_content(input, "lan", "enabled", true);
        assert!(output.contains("[lan]\nenabled = true"));
        assert!(output.contains("[dnssec]"));
        assert!(output.contains("[blocking]"));

        let output = update_config_content(input, "blocking", "enabled", true);
        assert!(output.contains("[blocking]\nenabled = true"));
        assert!(output.contains("refresh_hours = 24"));

        let output = update_config_content(input, "mobile", "enabled", true);
        assert!(output.contains("[mobile]\nenabled = true"));
    }

    #[test]
    fn test_update_config_inserts_into_existing_later_section() {
        // New key must land inside [lan], not at EOF or inside [blocking].
        let input = "[blocking]\nenabled = false\n\n[lan]\nfoo = 1\n";
        let output = update_config_content(input, "lan", "enabled", true);
        assert!(output.contains("[lan]\nenabled = true\nfoo = 1"));
        assert!(output.contains("[blocking]\nenabled = false"));
    }
}
