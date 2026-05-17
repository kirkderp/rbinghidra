use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    DECOMPILE_FUNCTION_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const DECOMPILE_SCHEMA: &str = "rbm.ghidra.decompile_function.v0";
const OUTPUT_PREFIX: &str = "decompile";
const DEFAULT_SIMPLIFICATION_STYLE: &str = "decompile";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallReference {
    pub name: String,
    pub address: String,
    pub is_external: bool,
    pub is_thunk: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DecompileResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub simplification_style: String,
    pub function_name: String,
    pub address: String,
    pub signature: String,
    #[serde(default)]
    pub decompiler_signature: String,
    pub pseudocode: String,
    pub callers: Vec<String>,
    pub callees: Vec<String>,
    #[serde(default)]
    pub caller_details: Vec<CallReference>,
    #[serde(default)]
    pub callee_details: Vec<CallReference>,
    #[serde(default)]
    pub basic_block_count: u32,
    #[serde(default)]
    pub decompile_completed: bool,
    #[serde(default)]
    pub decompile_valid: bool,
    #[serde(default)]
    pub is_timed_out: bool,
    #[serde(default)]
    pub is_cancelled: bool,
    #[serde(default)]
    pub failed_to_start: bool,
    pub decompile_error: String,
    pub resolution_error: String,
}

#[derive(Debug, Error)]
pub enum DecompileError {
    #[error("function name_or_address must not be empty")]
    EmptyQuery,
    #[error(
        "invalid simplification_style '{style}'; expected one of: decompile, normalize, register, firstpass, paramid"
    )]
    InvalidSimplificationStyle { style: String },
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
        "analyzeHeadless exited successfully but the decompile postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("decompile output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(DecompileError);

#[derive(Debug, Clone)]
pub struct DecompileContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct DecompileEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    simplification_style: String,
    #[serde(default)]
    function_name: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    decompiler_signature: String,
    #[serde(default)]
    pseudocode: String,
    #[serde(default)]
    callers: Vec<String>,
    #[serde(default)]
    callees: Vec<String>,
    #[serde(default)]
    caller_details: Vec<CallReference>,
    #[serde(default)]
    callee_details: Vec<CallReference>,
    #[serde(default)]
    basic_block_count: u32,
    #[serde(default)]
    decompile_completed: bool,
    #[serde(default)]
    decompile_valid: bool,
    #[serde(default)]
    is_timed_out: bool,
    #[serde(default)]
    is_cancelled: bool,
    #[serde(default)]
    failed_to_start: bool,
    #[serde(default)]
    decompile_error: String,
    #[serde(default)]
    resolution_error: String,
}

/// Decompile a function in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the function query or simplification style is invalid,
/// the binary cannot be resolved, the Ghidra script cannot run, or the decompile
/// report cannot be read or decoded.
pub async fn decompile_function(
    ctx: &DecompileContext,
    binary_query: &str,
    name_or_address: &str,
    simplification_style: Option<&str>,
) -> Result<DecompileResult, DecompileError> {
    if name_or_address.trim().is_empty() {
        return Err(DecompileError::EmptyQuery);
    }
    let simplification_style =
        resolve_simplification_style(simplification_style).ok_or_else(|| {
            DecompileError::InvalidSimplificationStyle {
                style: simplification_style.unwrap_or_default().to_string(),
            }
        })?;

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
        script_name: DECOMPILE_FUNCTION_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![
            name_or_address.to_string(),
            simplification_style.to_string(),
        ],
    })
    .await?;

    let envelope: DecompileEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| DecompileError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(DecompileResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        simplification_style: envelope.simplification_style,
        function_name: envelope.function_name,
        address: envelope.address,
        signature: envelope.signature,
        decompiler_signature: envelope.decompiler_signature,
        pseudocode: envelope.pseudocode,
        callers: envelope.callers,
        callees: envelope.callees,
        caller_details: envelope.caller_details,
        callee_details: envelope.callee_details,
        basic_block_count: envelope.basic_block_count,
        decompile_completed: envelope.decompile_completed,
        decompile_valid: envelope.decompile_valid,
        is_timed_out: envelope.is_timed_out,
        is_cancelled: envelope.is_cancelled,
        failed_to_start: envelope.failed_to_start,
        decompile_error: envelope.decompile_error,
        resolution_error: envelope.resolution_error,
    })
}

fn resolve_simplification_style(style: Option<&str>) -> Option<&'static str> {
    match style.unwrap_or(DEFAULT_SIMPLIFICATION_STYLE).trim() {
        "" | DEFAULT_SIMPLIFICATION_STYLE => Some(DEFAULT_SIMPLIFICATION_STYLE),
        "normalize" => Some("normalize"),
        "register" => Some("register"),
        "firstpass" => Some("firstpass"),
        "paramid" => Some("paramid"),
        _ => None,
    }
}
