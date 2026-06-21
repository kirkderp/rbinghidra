use std::path::PathBuf;
use std::time::Duration;

use crate::env::{nonempty_var_os, parse_env_secs};
use crate::error::ToolResult;
use crate::paths::CachePaths;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub cache: CachePaths,
    pub ghidra_install_dir: Option<PathBuf>,
    pub ghidra_scripts_dir: PathBuf,
    pub ghidra_call_timeout: Duration,
    pub ghidra_import_timeout: Duration,
}

fn default_ghidra_scripts_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("ghidra_scripts")
}

impl ServerConfig {
    /// Build server configuration from process environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error if cache path discovery fails.
    pub fn from_env() -> ToolResult<Self> {
        let cache = CachePaths::from_env()?;
        let ghidra_install_dir = nonempty_var_os("GHIDRA_INSTALL_DIR").map(PathBuf::from);
        let ghidra_scripts_dir = nonempty_var_os("RBM_GHIDRA_SCRIPTS_DIR")
            .map_or_else(default_ghidra_scripts_dir, PathBuf::from);

        Ok(Self {
            cache,
            ghidra_install_dir,
            ghidra_scripts_dir,
            ghidra_call_timeout: Duration::from_secs(parse_env_secs("RBM_GHIDRA_TIMEOUT", 60)),
            ghidra_import_timeout: Duration::from_secs(parse_env_secs(
                "RBM_GHIDRA_IMPORT_TIMEOUT",
                900,
            )),
        })
    }
}
