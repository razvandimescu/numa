use numa::system_dns::{
    install_service, restart_service, service_status, start_service, stop_service,
    uninstall_service,
};

const NO_SYSTEM_DNS_FLAG: &str = "--no-system-dns";

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// libmimalloc-sys does not export this option; index 4 in the v2 and v3 headers of the pinned 0.1.49.
#[cfg(target_env = "musl")]
const MI_OPTION_ARENA_EAGER_COMMIT: libmimalloc_sys::mi_option_t = 4;

fn main() -> std::process::ExitCode {
    // mimalloc eagerly commits arenas on overcommit OSes; that is 27 MB idle vs 11 MB without.
    #[cfg(target_env = "musl")]
    unsafe {
        libmimalloc_sys::mi_option_set(MI_OPTION_ARENA_EAGER_COMMIT, 0);
    }
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", numa::format_error_chain(&*e));
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> numa::Result<()> {
    let palette = numa::palette::get();
    let (config_flag, args) = take_config_flag(std::env::args().skip(1).collect())?;
    let arg = |i: usize| args.get(i).cloned();
    let arg1 = arg(0).unwrap_or_default();

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

    let skip_system_dns = args.iter().any(|a| a == NO_SYSTEM_DNS_FLAG);

    let reads_config = matches!(
        arg1.as_str(),
        "" | "run" | "config" | "token" | "lan" | "block" | "dnssec"
    ) || names_config_file(&arg1);
    if config_flag.is_some() && !reads_config {
        return Err(format!("-c/--config is not supported by `numa {arg1}`").into());
    }

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
            let sub = arg(1).unwrap_or_default();
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
            let sub = arg(1).unwrap_or_default();
            let explicit = config_flag.as_deref();
            return match sub.as_str() {
                "path" => numa::config_cli::print_config_path(explicit).map_err(|e| e.into()),
                "edit" => numa::config_cli::edit_config(explicit).map_err(|e| e.into()),
                _ => {
                    eprintln!("Usage: numa config <path|edit>");
                    Ok(())
                }
            };
        }
        "token" => {
            return numa::config_cli::print_token(config_flag.as_deref()).map_err(|e| e.into())
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
            let port: u16 = arg(1)
                .as_deref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8443);
            let bind: std::net::IpAddr = arg(2)
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
            let sub = arg(1).unwrap_or_default();
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
            let config_path = match one_config_path(config_flag, arg(2))? {
                Some(named) => numa::config::named_config_path(&named)?,
                None => numa::config_cli::config_write_target()?,
            };
            let (section, feature_name) = match arg1.as_str() {
                "lan" => ("lan", "LAN discovery"),
                "block" => ("blocking", "ad-blocking"),
                "dnssec" => ("dnssec", "DNSSEC validation"),
                _ => unreachable!(),
            };
            let config = set_config_bool(&config_path, section, "enabled", enabled)?;
            let dnssec_inactive_in = (section == "dnssec" && enabled)
                .then_some(config.upstream.mode)
                .filter(|mode| mode.validates_dnssec() == Some(false));
            print_toggle_status(feature_name, enabled, &config_path, dnssec_inactive_in);
            return Ok(());
        }
        "version" | "--version" | "-V" => {
            eprintln!("numa {}", numa::version());
            return Ok(());
        }
        "help" | "--help" | "-h" => {
            eprintln!("Usage: numa [-c CONFIG] [command]");
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
            eprintln!("  token           Print the dashboard/API token for other devices");
            eprintln!("  lan on|off      Enable/disable LAN service discovery (mDNS)");
            eprintln!("  block on|off    Enable/disable ad-blocking");
            eprintln!("  dnssec on|off   Enable/disable DNSSEC validation (recursive mode)");
            eprintln!("  relay [PORT] [BIND]");
            eprintln!("                  Run as an ODoH relay (RFC 9230, default 127.0.0.1:8443)");
            eprintln!("  setup-phone     Generate a QR code to install Numa DoT on a phone");
            eprintln!("  help            Show this help");
            eprintln!();
            eprintln!("Options:");
            eprintln!("  -c, --config FILE  Use FILE as the config, for the server and for the");
            eprintln!("                     config/token/on|off commands");
            return Ok(());
        }
        _ => {
            if !arg1.is_empty() && arg1 != "run" && !names_config_file(&arg1) {
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

    let positional = if arg1.is_empty() || arg1 == "run" {
        arg(1)
    } else {
        Some(arg1) // bare config path: `numa /etc/numa/numa.toml`
    };
    let load = match one_config_path(config_flag, positional)? {
        Some(named) => numa::config::load_config_file(&named)?,
        None => numa::config::load_config("numa.toml")?,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(numa::serve::run(load))
}

fn names_config_file(arg: &str) -> bool {
    arg.contains('/') || arg.contains('\\') || arg.ends_with(".toml")
}

/// Pulls `-c FILE`, `--config FILE` or `--config=FILE` out of argv so the
/// flag can sit before or after the subcommand.
fn take_config_flag(args: Vec<String>) -> Result<(Option<String>, Vec<String>), String> {
    let mut config = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let value = match arg.strip_prefix("--config=") {
            Some(value) => Some(value.to_string()),
            None if arg == "-c" || arg == "--config" => args.next(),
            None => {
                rest.push(arg);
                continue;
            }
        };
        let value = value
            .filter(|v| !v.is_empty() && !v.starts_with('-'))
            .ok_or("-c/--config needs a config file path")?;
        if config.replace(value).is_some() {
            return Err("-c/--config given more than once".to_string());
        }
    }
    Ok((config, rest))
}

fn one_config_path(
    flag: Option<String>,
    positional: Option<String>,
) -> Result<Option<String>, String> {
    match (flag, positional) {
        (Some(_), Some(_)) => Err("config file given both with -c and as an argument".to_string()),
        (flag, positional) => Ok(flag.or(positional)),
    }
}

fn set_config_bool(
    path: &str,
    section: &str,
    key: &str,
    value: bool,
) -> numa::Result<numa::config::Config> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = std::path::Path::new(path)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent)?;
            }
            String::new()
        }
        Err(e) => return Err(e.into()),
    };

    let updated = update_config_content(&contents, section, key, value);
    // A config the daemon can't parse stops it on the next restart.
    let config = toml::from_str(&updated).map_err(|e| {
        format!(
            "{path} left unchanged, the edit would not parse: {}",
            e.to_string().trim_end()
        )
    })?;
    std::fs::write(path, updated)?;
    Ok(config)
}

/// `[ name ]  # note` gives `name`; array tables give `None`.
fn table_name(header: &str) -> Option<&str> {
    let name = header.split('#').next()?.trim();
    let name = name.strip_prefix('[')?.strip_suffix(']')?.trim();
    (!name.starts_with('[')).then_some(name)
}

fn update_config_content(contents: &str, section: &str, key: &str, value: bool) -> String {
    let mut in_section = false;
    let mut found = false;
    let mut lines: Vec<String> = contents
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_section = table_name(trimmed) == Some(section);
            }
            if in_section && !found {
                if let Some((k, _)) = trimmed.split_once('=') {
                    if k.trim() == key {
                        found = true;
                        let indent = &line[..line.len() - line.trim_start().len()];
                        return format!("{}{} = {}", indent, key, value);
                    }
                }
            }
            line.to_string()
        })
        .collect();

    if !found {
        if let Some(i) = lines
            .iter()
            .position(|l| table_name(l.trim()) == Some(section))
        {
            lines.insert(i + 1, format!("{} = {}", key, value));
        } else {
            if !lines.is_empty() && !lines.last().unwrap().is_empty() {
                lines.push(String::new());
            }
            lines.push(format!("[{}]", section));
            lines.push(format!("{} = {}", key, value));
        }
    }

    let mut result = lines.join("\n");
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result
}

fn print_toggle_status(
    feature: &str,
    enabled: bool,
    path: &str,
    dnssec_inactive_in: Option<numa::config::UpstreamMode>,
) {
    let palette = numa::palette::get();
    let (label, color, hint) = match (enabled, dnssec_inactive_in) {
        (false, _) => ("disabled".to_string(), palette.warning, None),
        (true, None) => (
            "enabled".to_string(),
            palette.green,
            Some("Restart Numa for changes to take effect"),
        ),
        (true, Some(mode)) => (
            format!("enabled, no effect in {} mode", mode.as_str()),
            palette.warning,
            Some(numa::config::DNSSEC_NEEDS_RECURSIVE),
        ),
    };
    eprintln!(
        "{}Numa{} — {} {}{}{}",
        palette.brand_bold, palette.reset, feature, color, label, palette.reset
    );
    eprintln!("  Wrote {}", path);
    if let Some(hint) = hint {
        eprintln!("  {hint}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(args: &[&str]) -> Result<(Option<String>, Vec<String>), String> {
        take_config_flag(args.iter().map(|a| a.to_string()).collect())
    }

    #[test]
    fn config_flag_is_taken_from_any_position() {
        for args in [
            &["-c", "t1.toml", "config", "path"][..],
            &["config", "path", "--config", "t1.toml"],
            &["config", "--config=t1.toml", "path"],
        ] {
            let (config, rest) = split(args).unwrap();
            assert_eq!(config.as_deref(), Some("t1.toml"));
            assert_eq!(rest, ["config", "path"]);
        }
    }

    #[test]
    fn config_flag_leaves_other_args_alone() {
        let (config, rest) = split(&["install", "--no-system-dns"]).unwrap();
        assert_eq!(config, None);
        assert_eq!(rest, ["install", "--no-system-dns"]);
    }

    #[test]
    fn config_flag_rejects_missing_or_repeated_values() {
        assert!(split(&["run", "-c"]).is_err());
        assert!(split(&["--config", ""]).is_err());
        assert!(split(&["--config="]).is_err());
        assert!(split(&["-c", "--no-system-dns"]).is_err());
        assert!(split(&["-c", "a.toml", "-c", "b.toml"]).is_err());
    }

    #[test]
    fn config_path_comes_from_flag_or_argument_not_both() {
        let some = |s: &str| Some(s.to_string());
        assert_eq!(one_config_path(some("a.toml"), None), Ok(some("a.toml")));
        assert_eq!(one_config_path(None, some("b.toml")), Ok(some("b.toml")));
        assert_eq!(one_config_path(None, None), Ok(None));
        assert!(one_config_path(some("a.toml"), some("b.toml")).is_err());
    }

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
    fn update_config_finds_headers_with_a_comment_or_spaces() {
        for header in ["[dnssec]  # chain of trust", "[ dnssec ]"] {
            let input = format!("{header}\nenabled = false\n");
            let output = update_config_content(&input, "dnssec", "enabled", true);
            assert_eq!(output, format!("{header}\nenabled = true\n"));
        }
    }

    #[test]
    fn update_config_keeps_the_indent_without_trailing_space() {
        for (line, want) in [
            ("enabled = false ", "enabled = true"),
            ("  enabled = false  ", "  enabled = true"),
        ] {
            let output =
                update_config_content(&format!("[dnssec]\n{line}\n"), "dnssec", "enabled", true);
            assert_eq!(output, format!("[dnssec]\n{want}\n"));
        }
    }

    #[test]
    fn set_config_bool_leaves_a_config_it_cannot_edit_untouched() {
        let path = std::env::temp_dir().join(format!("numa-toggle-{}.toml", std::process::id()));
        let original = "dnssec = { enabled = false }\n";
        std::fs::write(&path, original).unwrap();
        let result = set_config_bool(path.to_str().unwrap(), "dnssec", "enabled", true);
        let after = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(result.is_err());
        assert_eq!(after, original);
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
