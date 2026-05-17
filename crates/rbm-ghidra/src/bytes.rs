use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, PathValidationError, ProjectManager, READ_BYTES_SCRIPT, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const READ_BYTES_SCHEMA: &str = "rbm.ghidra.read_bytes.v0";
pub const DEFAULT_SIZE: u64 = 32;
pub const MAX_SIZE: u64 = 8192;
const OUTPUT_PREFIX: &str = "bytes";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadBytesResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub address: String,
    pub resolved_address: String,
    pub size: u64,
    pub hex: String,
    pub ascii_preview: String,
}

#[derive(Debug, Error)]
pub enum ReadBytesError {
    #[error("address must not be empty")]
    EmptyAddress,
    #[error("memory read failed: {0}")]
    ReadFailed(String),
    #[error(transparent)]
    Inspect(#[from] InspectError),
    #[error(
        "ghidra cache for sha256 {sha256} is locked by another in-flight call; retry once it completes"
    )]
    LockHeld { sha256: String },
    #[error(transparent)]
    PathValidation(#[from] PathValidationError),
    #[error("ghidra project directory has no .gpr file: {0}")]
    ProjectFileMissing(PathBuf),
    #[error("analyzeHeadless exited with status {exit_code:?}; stderr: {stderr}")]
    HeadlessFailed {
        exit_code: Option<i32>,
        stderr: String,
    },
    #[error(
        "analyzeHeadless exited successfully but the read_bytes postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
    )]
    OutputMissing { stdout: String, stderr: String },
    #[error(transparent)]
    Headless(#[from] HeadlessError),
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("read_bytes output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(ReadBytesError);


#[derive(Debug, Clone)]
pub struct ReadBytesContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct ReadBytesEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    resolved_address: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    hex: String,
    #[serde(default)]
    ascii_preview: String,
    #[serde(default)]
    read_error: String,
}

#[must_use]
pub fn resolve_size(size: Option<u64>) -> u64 {
    size.unwrap_or(DEFAULT_SIZE).min(MAX_SIZE)
}

/// Read bytes at an address from a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the address is empty, the binary cannot be resolved, the
/// Ghidra script cannot run, or the byte-read report cannot be read or decoded.
pub async fn read_bytes(
    ctx: &ReadBytesContext,
    binary_query: &str,
    address: &str,
    size: Option<u64>,
) -> Result<ReadBytesResult, ReadBytesError> {
    if address.trim().is_empty() {
        return Err(ReadBytesError::EmptyAddress);
    }

    let resolved_size = resolve_size(size);

    let WarmPathProduct {
        sha256,
        program_name,
        bytes,
        output_path,
    } = execute_warm_path(WarmPathRequest {
        manager: ctx.manager.as_ref(),
        analyze_headless: &ctx.analyze_headless,
        scripts_dir: &ctx.scripts_dir,
        timeout: ctx.timeout,
        binary_query,
        script_name: READ_BYTES_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: address,
        extra_script_args: vec![address.to_string(), resolved_size.to_string()],
    })
    .await?;

    let envelope: ReadBytesEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| ReadBytesError::Parse {
            path: output_path,
            source: err,
        })?;

    if !envelope.read_error.is_empty() {
        return Err(ReadBytesError::ReadFailed(envelope.read_error));
    }

    Ok(ReadBytesResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        address: envelope.address,
        resolved_address: envelope.resolved_address,
        size: envelope.size,
        hex: envelope.hex,
        ascii_preview: envelope.ascii_preview,
    })
}
