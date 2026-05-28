use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    FUNCTION_STATS_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const FUNCTION_STATS_SCHEMA: &str = "rbm.ghidra.function_stats.v0";
const OUTPUT_PREFIX: &str = "fn_stats";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct FunctionStatsResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub resolved_address: String,
    pub resolved_symbol_name: String,
    pub function_name: String,
    pub address: String,
    pub signature: String,
    pub size_bytes: u64,
    pub instruction_count: u64,
    pub basic_block_count: u64,
    pub cyclomatic_complexity: u64,
    pub call_count: u64,
    pub external_call_count: u64,
    pub memory_reference_count: u64,
    #[serde(default)]
    pub imports_by_library: serde_json::Value,
    #[serde(default)]
    pub has_stack_frame: bool,
    #[serde(default)]
    pub resolution_error: String,
}

#[derive(Debug, Error)]
pub enum FunctionStatsError {
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
        "analyzeHeadless exited successfully but function_stats postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("function_stats output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(FunctionStatsError);

#[derive(Debug, Clone)]
pub struct FunctionStatsContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct FunctionStatsEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    resolved_address: String,
    #[serde(default)]
    resolved_symbol_name: String,
    #[serde(default)]
    function_name: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    size_bytes: u64,
    #[serde(default)]
    instruction_count: u64,
    #[serde(default)]
    basic_block_count: u64,
    #[serde(default)]
    cyclomatic_complexity: u64,
    #[serde(default)]
    call_count: u64,
    #[serde(default)]
    external_call_count: u64,
    #[serde(default)]
    memory_reference_count: u64,
    #[serde(default)]
    imports_by_library: serde_json::Value,
    #[serde(default)]
    has_stack_frame: bool,
    #[serde(default)]
    resolution_error: String,
}

/// Compute function statistics (cyclomatic complexity, instruction count, call count, etc.).
///
/// # Errors
///
/// Returns an error if the function query is empty, the binary cannot be
/// resolved, the Ghidra script cannot run, or the report cannot be read or decoded.
pub async fn get_function_stats(
    ctx: &FunctionStatsContext,
    binary_query: &str,
    name_or_address: &str,
) -> Result<FunctionStatsResult, FunctionStatsError> {
    if name_or_address.trim().is_empty() {
        return Err(FunctionStatsError::EmptyQuery);
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
        script_name: FUNCTION_STATS_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![name_or_address.to_string()],
    })
    .await?;

    let envelope: FunctionStatsEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| FunctionStatsError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(FunctionStatsResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        resolved_address: envelope.resolved_address,
        resolved_symbol_name: envelope.resolved_symbol_name,
        function_name: envelope.function_name,
        address: envelope.address,
        signature: envelope.signature,
        size_bytes: envelope.size_bytes,
        instruction_count: envelope.instruction_count,
        basic_block_count: envelope.basic_block_count,
        cyclomatic_complexity: envelope.cyclomatic_complexity,
        call_count: envelope.call_count,
        external_call_count: envelope.external_call_count,
        memory_reference_count: envelope.memory_reference_count,
        imports_by_library: envelope.imports_by_library,
        has_stack_frame: envelope.has_stack_frame,
        resolution_error: envelope.resolution_error,
    })
}
