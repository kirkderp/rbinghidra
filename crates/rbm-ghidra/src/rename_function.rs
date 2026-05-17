use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, PathValidationError, ProjectManager, RENAME_FUNCTION_SCRIPT, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const RENAME_SCHEMA: &str = "rbm.ghidra.rename_function.v0";
const OUTPUT_PREFIX: &str = "rename";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenameResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub new_name: String,
    pub old_name: String,
    pub function_name: String,
    pub address: String,
    pub resolution_error: String,
    pub rename_error: String,
}

#[derive(Debug, Error)]
pub enum RenameError {
    #[error("name_or_address must not be empty")]
    EmptyQuery,
    #[error("new_name must not be empty")]
    EmptyNewName,
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
        "analyzeHeadless exited successfully but the rename_function postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("rename_function output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(RenameError);


#[derive(Debug, Clone)]
pub struct RenameContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct RenameEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    new_name: String,
    #[serde(default)]
    old_name: String,
    #[serde(default)]
    function_name: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    resolution_error: String,
    #[serde(default)]
    rename_error: String,
}

/// Rename a function in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the function query or new name is empty, the binary
/// cannot be resolved, the Ghidra script cannot run, or the mutation report
/// cannot be read or decoded.
pub async fn rename_function(
    ctx: &RenameContext,
    binary_query: &str,
    name_or_address: &str,
    new_name: &str,
) -> Result<RenameResult, RenameError> {
    if name_or_address.trim().is_empty() {
        return Err(RenameError::EmptyQuery);
    }
    if new_name.trim().is_empty() {
        return Err(RenameError::EmptyNewName);
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
        script_name: RENAME_FUNCTION_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![name_or_address.to_string(), new_name.to_string()],
    })
    .await?;

    let envelope: RenameEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| RenameError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(RenameResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        new_name: envelope.new_name,
        old_name: envelope.old_name,
        function_name: envelope.function_name,
        address: envelope.address,
        resolution_error: envelope.resolution_error,
        rename_error: envelope.rename_error,
    })
}
