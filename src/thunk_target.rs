use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, PathValidationError, ProjectManager, THUNK_TARGET_SCRIPT, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const THUNK_TARGET_SCHEMA: &str = "rbm.ghidra.thunk_target.v0";
const OUTPUT_PREFIX: &str = "thunk";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThunkTargetResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub function_name: String,
    pub address: String,
    pub is_thunk: bool,
    pub target_name: String,
    pub target_address: String,
    pub resolution_error: String,
}

#[derive(Debug, Error)]
pub enum ThunkTargetError {
    #[error("name_or_address must not be empty")]
    EmptyQuery,
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
        "analyzeHeadless exited successfully but the thunk_target postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("thunk_target output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(ThunkTargetError);

#[derive(Debug, Clone)]
pub struct ThunkTargetContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct ThunkTargetEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    function_name: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    is_thunk: bool,
    #[serde(default)]
    target_name: String,
    #[serde(default)]
    target_address: String,
    #[serde(default)]
    resolution_error: String,
}

/// Resolve a thunk target for a function.
///
/// # Errors
///
/// Returns an error if the function query is empty, the binary cannot be
/// resolved, the Ghidra script cannot run, or the thunk report cannot be read or
/// decoded.
pub async fn get_thunk_target(
    ctx: &ThunkTargetContext,
    binary_query: &str,
    name_or_address: &str,
) -> Result<ThunkTargetResult, ThunkTargetError> {
    if name_or_address.trim().is_empty() {
        return Err(ThunkTargetError::EmptyQuery);
    }

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
        script_name: THUNK_TARGET_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![name_or_address.to_string()],
    })
    .await?;

    let envelope: ThunkTargetEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| ThunkTargetError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(ThunkTargetResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        function_name: envelope.function_name,
        address: envelope.address,
        is_thunk: envelope.is_thunk,
        target_name: envelope.target_name,
        target_address: envelope.target_address,
        resolution_error: envelope.resolution_error,
    })
}
