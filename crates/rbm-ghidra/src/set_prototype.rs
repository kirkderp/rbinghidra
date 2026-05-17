use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, PathValidationError, ProjectManager, SET_PROTOTYPE_SCRIPT, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const SET_PROTOTYPE_SCHEMA: &str = "rbm.ghidra.set_function_prototype.v0";
const OUTPUT_PREFIX: &str = "setproto";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetPrototypeResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub prototype: String,
    pub function_name: String,
    pub address: String,
    pub applied_signature: String,
    pub resolution_error: String,
    pub prototype_error: String,
}

#[derive(Debug, Error)]
pub enum SetPrototypeError {
    #[error("name_or_address must not be empty")]
    EmptyQuery,
    #[error("prototype must not be empty")]
    EmptyPrototype,
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
        "analyzeHeadless exited successfully but the set_function_prototype postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("set_function_prototype output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(SetPrototypeError);


#[derive(Debug, Clone)]
pub struct SetPrototypeContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct SetPrototypeEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    prototype: String,
    #[serde(default)]
    function_name: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    applied_signature: String,
    #[serde(default)]
    resolution_error: String,
    #[serde(default)]
    prototype_error: String,
}

/// Set a function prototype in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the function query or prototype is empty, the binary
/// cannot be resolved, the Ghidra script cannot run, or the mutation report
/// cannot be read or decoded.
pub async fn set_function_prototype(
    ctx: &SetPrototypeContext,
    binary_query: &str,
    name_or_address: &str,
    prototype: &str,
) -> Result<SetPrototypeResult, SetPrototypeError> {
    if name_or_address.trim().is_empty() {
        return Err(SetPrototypeError::EmptyQuery);
    }
    if prototype.trim().is_empty() {
        return Err(SetPrototypeError::EmptyPrototype);
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
        script_name: SET_PROTOTYPE_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![name_or_address.to_string(), prototype.to_string()],
    })
    .await?;

    let envelope: SetPrototypeEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| SetPrototypeError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(SetPrototypeResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        prototype: envelope.prototype,
        function_name: envelope.function_name,
        address: envelope.address,
        applied_signature: envelope.applied_signature,
        resolution_error: envelope.resolution_error,
        prototype_error: envelope.prototype_error,
    })
}
