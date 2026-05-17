use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, PathValidationError, ProjectManager, VARIABLES_SCRIPT, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const VARIABLES_SCHEMA: &str = "rbm.ghidra.variables.v0";
const OUTPUT_PREFIX: &str = "vars";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct FunctionParam {
    pub name: String,
    pub ordinal: i32,
    pub data_type: String,
    pub size: i32,
    pub storage: String,
    #[serde(default)]
    pub storage_kind: String,
    #[serde(default)]
    pub pc_address: String,
    #[serde(default)]
    pub is_name_locked: bool,
    #[serde(default)]
    pub is_type_locked: bool,
    #[serde(default)]
    pub is_this_pointer: bool,
    #[serde(default)]
    pub is_hidden_return: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionVariable {
    pub name: String,
    pub data_type: String,
    pub size: i32,
    pub storage: String,
    pub first_use_offset: i32,
    #[serde(default)]
    pub storage_kind: String,
    #[serde(default)]
    pub pc_address: String,
    #[serde(default)]
    pub is_name_locked: bool,
    #[serde(default)]
    pub is_type_locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariablesResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub function_name: String,
    pub address: String,
    #[serde(default)]
    pub source: String,
    pub parameter_count: u32,
    pub parameters: Vec<FunctionParam>,
    pub local_var_count: u32,
    pub local_vars: Vec<FunctionVariable>,
    #[serde(default)]
    pub decompiler_error: String,
    pub resolution_error: String,
}

#[derive(Debug, Error)]
pub enum VariablesError {
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
        "analyzeHeadless exited successfully but the variables postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("variables output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(VariablesError);


#[derive(Debug, Clone)]
pub struct VariablesContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct VariablesEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    function_name: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    parameter_count: u32,
    #[serde(default)]
    parameters: Vec<FunctionParam>,
    #[serde(default)]
    local_var_count: u32,
    #[serde(default)]
    local_vars: Vec<FunctionVariable>,
    #[serde(default)]
    decompiler_error: String,
    #[serde(default)]
    resolution_error: String,
}

/// Return variables for a function in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the function query is empty, the binary cannot be
/// resolved, the Ghidra script cannot run, or the variable report cannot be read
/// or decoded.
pub async fn get_variables(
    ctx: &VariablesContext,
    binary_query: &str,
    name_or_address: &str,
) -> Result<VariablesResult, VariablesError> {
    if name_or_address.trim().is_empty() {
        return Err(VariablesError::EmptyQuery);
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
        script_name: VARIABLES_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![name_or_address.to_string()],
    })
    .await?;

    let envelope: VariablesEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| VariablesError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(VariablesResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        function_name: envelope.function_name,
        address: envelope.address,
        source: envelope.source,
        parameter_count: envelope.parameter_count,
        parameters: envelope.parameters,
        local_var_count: envelope.local_var_count,
        local_vars: envelope.local_vars,
        decompiler_error: envelope.decompiler_error,
        resolution_error: envelope.resolution_error,
    })
}
