use numa::system_dns::{
    install_service, restart_service, service_status, start_service, stop_service,
    uninstall_service,
};

const NO_SYSTEM_DNS_FLAG: &str = "--no-system-dns";

fn main() -> numa::Result<()> {
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
            eprintln!("\x1b[1;38;2;192;98;58mNuma\x1b[0m — installing\n");
            return install_service(skip_system_dns).map_err(|e| e.into());
        }
        "uninstall" => {
            eprintln!("\x1b[1;38;2;192;98;58mNuma\x1b[0m — uninstalling\n");
            return uninstall_service().map_err(|e| e.into());
        }
        "service" => {
            let sub = std::env::args().nth(2).unwrap_or_default();
            eprintln!("\x1b[1;38;2;192;98;58mNuma\x1b[0m — service management\n");
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
                "\x1b[1;38;2;192;98;58mNuma\x1b[0m — ODoH relay on {}\n",
                addr
            );
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            return runtime.block_on(numa::relay::run(addr));
        }
        "lan" => {
            let sub = std::env::args().nth(2).unwrap_or_default();
            let config_path = std::env::args()
                .nth(3)
                .unwrap_or_else(|| "numa.toml".to_string());
            return match sub.as_str() {
                "on" => set_lan_enabled(true, &config_path),
                "off" => set_lan_enabled(false, &config_path),
                _ => {
                    eprintln!("Usage: numa lan <on|off> [config-path]");
                    Ok(())
                }
            };
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
            eprintln!("  lan on          Enable LAN service discovery (mDNS)");
            eprintln!("  lan off         Disable LAN service discovery");
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
                    "\x1b[1;38;2;192;98;58mNuma\x1b[0m — unknown command: \x1b[1m{}\x1b[0m\n",
                    arg1
                );
                eprintln!("Run \x1b[1mnuma help\x1b[0m for a list of commands.");
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

fn set_lan_enabled(enabled: bool, path: &str) -> numa::Result<()> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::write(path, format!("[lan]\nenabled = {}\n", enabled))?;
            print_lan_status(enabled);
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    // Track current TOML section while scanning lines
    let mut in_lan = false;
    let mut found = false;
    let mut lines: Vec<String> = contents
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_lan = trimmed == "[lan]";
            }
            if in_lan && !found {
                if let Some((key, _)) = trimmed.split_once('=') {
                    if key.trim() == "enabled" {
                        found = true;
                        let indent = &line[..line.len() - trimmed.len()];
                        return format!("{}enabled = {}", indent, enabled);
                    }
                }
            }
            line.to_string()
        })
        .collect();

    if !found {
        if let Some(i) = lines.iter().position(|l| l.trim() == "[lan]") {
            lines.insert(i + 1, format!("enabled = {}", enabled));
        } else {
            lines.push(String::new());
            lines.push("[lan]".to_string());
            lines.push(format!("enabled = {}", enabled));
        }
    }

    let mut result = lines.join("\n");
    if !result.ends_with('\n') {
        result.push('\n');
    }
    std::fs::write(path, result)?;
    print_lan_status(enabled);
    Ok(())
}

fn print_lan_status(enabled: bool) {
    let label = if enabled { "enabled" } else { "disabled" };
    let color = if enabled { "32" } else { "33" };
    eprintln!(
        "\x1b[1;38;2;192;98;58mNuma\x1b[0m — LAN discovery \x1b[{}m{}\x1b[0m",
        color, label
    );
    if enabled {
        eprintln!("  Restart Numa to start mDNS discovery");
    }
}
