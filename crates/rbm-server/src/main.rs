use anyhow::{Context, Result};
use clap::Parser;
use rbm_core::ServerConfig;
use rbm_ghidra::discover_install_dir;
use rbm_server::RbmServer;

#[derive(Parser)]
#[command(
    name = "rbinghidra",
    version,
    about = "MCP server for Ghidra-based binary analysis"
)]
struct Cli {
    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level)),
        )
        .init();

    let mut config = ServerConfig::from_env().context("failed to build server config from env")?;

    if config.ghidra_install_dir.is_none()
        && let Some(dir) = discover_install_dir()
    {
        tracing::info!(ghidra_dir = %dir.display(), "auto-discovered Ghidra install directory");
        config.ghidra_install_dir = Some(dir);
    }

    config
        .cache
        .ensure_all()
        .context("failed to prepare cache directories")?;
    anyhow::ensure!(
        config.ghidra_scripts_dir.is_dir(),
        "repo-owned Ghidra scripts directory does not exist or is not a directory: {}",
        config.ghidra_scripts_dir.display()
    );

    let server = RbmServer::new(config);
    tracing::info!("rbinghidra MCP server starting on stdio");

    server
        .serve_stdio()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(())
}
