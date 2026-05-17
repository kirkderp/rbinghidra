use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    CREATE_FUNCTION_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const CREATE_FUNCTION_SCHEMA: &str = "rbm.ghidra.create_function.v0";
const OUTPUT_PREFIX: &str = "function_create";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateFunctionResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub address: String,
    pub function_name: String,
    pub created_function: String,
    pub existing_function: String,
    pub address_error: String,
    pub function_error: String,
}

#[derive(Debug, Error)]
pub enum CreateFunctionError {
    #[error("address must not be empty")]
    EmptyAddress,
    #[error("function_name must not be empty")]
    EmptyFunctionName,
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
        "analyzeHeadless exited successfully but the create_function postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("create_function output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(CreateFunctionError);


#[derive(Debug, Clone)]
pub struct CreateFunctionContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct CreateFunctionEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    function_name: String,
    #[serde(default)]
    created_function: String,
    #[serde(default)]
    existing_function: String,
    #[serde(default)]
    address_error: String,
    #[serde(default)]
    function_error: String,
}

/// Create a function at an address in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the address or function name is empty, the binary cannot
/// be resolved, the Ghidra script cannot run, or the mutation report cannot be
/// read or decoded.
pub async fn create_function(
    ctx: &CreateFunctionContext,
    binary_query: &str,
    address: &str,
    function_name: &str,
) -> Result<CreateFunctionResult, CreateFunctionError> {
    if address.trim().is_empty() {
        return Err(CreateFunctionError::EmptyAddress);
    }
    if function_name.trim().is_empty() {
        return Err(CreateFunctionError::EmptyFunctionName);
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
        script_name: CREATE_FUNCTION_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: address,
        extra_script_args: vec![address.to_string(), function_name.to_string()],
    })
    .await?;

    let envelope: CreateFunctionEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| CreateFunctionError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(CreateFunctionResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        address: envelope.address,
        function_name: envelope.function_name,
        created_function: envelope.created_function,
        existing_function: envelope.existing_function,
        address_error: envelope.address_error,
        function_error: envelope.function_error,
    })
}
