use std::env;
use std::ffi::OsStr;
use std::io;

use rbinghidra::{RbmServer, ServerConfig, discover_install_dir};

type MainResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() {
    if let Err(err) = try_main() {
        eprintln!("rbinghidra: {err}");
        std::process::exit(1);
    }
}

fn try_main() -> MainResult<()> {
    parse_cli()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_server())
}

async fn run_server() -> MainResult<()> {
    let mut config = ServerConfig::from_env()
        .map_err(|e| io::Error::other(format!("failed to build server config from env: {e}")))?;
    if config.ghidra_install_dir.is_none()
        && let Some(dir) = discover_install_dir()
    {
        config.ghidra_install_dir = Some(dir);
    }

    config
        .cache
        .ensure_all()
        .map_err(|e| io::Error::other(format!("failed to prepare cache directories: {e}")))?;
    if !config.ghidra_scripts_dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "repo-owned Ghidra scripts directory does not exist or is not a directory: {}",
                config.ghidra_scripts_dir.display()
            ),
        )
        .into());
    }

    let server = RbmServer::new(config);

    server.serve_stdio().await.map_err(io::Error::other)?;
    Ok(())
}

fn parse_cli() -> MainResult<()> {
    let Some(arg) = env::args_os().nth(1) else {
        return Ok(());
    };

    let arg_ref = arg.as_os_str();
    if arg_ref == OsStr::new("--help") || arg_ref == OsStr::new("-h") {
        print_help();
        std::process::exit(0);
    }
    if arg_ref == OsStr::new("--version") || arg_ref == OsStr::new("-V") {
        println!("rbinghidra {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    Err(invalid_input(format!(
        "unknown argument: {}",
        arg.to_string_lossy()
    )))
}

fn invalid_input(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    io::Error::new(io::ErrorKind::InvalidInput, message.into()).into()
}

fn print_help() {
    println!(
        "MCP server for Ghidra-based binary analysis\n\n\
Usage: rbinghidra [OPTIONS]\n\n\
Options:\n\
  -h, --help               Print help\n\
  -V, --version            Print version"
    );
}
