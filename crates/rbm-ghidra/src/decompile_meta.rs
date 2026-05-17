use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    DECOMPILE_META_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::variables::{FunctionParam, FunctionVariable};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const DECOMPILE_META_SCHEMA: &str = "rbm.ghidra.decompile_meta.v0";
const OUTPUT_PREFIX: &str = "decompile_meta";
const DEFAULT_SIMPLIFICATION_STYLE: &str = "decompile";
const DEFAULT_TOKEN_LIMIT: u32 = 200;
const MAX_TOKEN_LIMIT: u32 = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileToken {
    pub text: String,
    pub token_class: String,
    pub syntax_type: i32,
    pub line_number: u32,
    pub line_token_index: u32,
    pub column_start: u32,
    pub column_end: u32,
    #[serde(default)]
    pub min_address: String,
    #[serde(default)]
    pub max_address: String,
    #[serde(default)]
    pub is_variable_ref: bool,
    #[serde(default)]
    pub high_variable_name: String,
    #[serde(default)]
    pub high_variable_data_type: String,
    #[serde(default)]
    pub high_variable_storage: String,
    #[serde(default)]
    pub high_variable_storage_kind: String,
    #[serde(default)]
    pub high_variable_pc_address: String,
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DecompileMetaResult {
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
    #[serde(default)]
    pub source: String,
    pub parameter_count: u32,
    pub parameters: Vec<FunctionParam>,
    pub local_var_count: u32,
    pub local_vars: Vec<FunctionVariable>,
    #[serde(default)]
    pub line_count: u32,
    #[serde(default)]
    pub token_count: u32,
    #[serde(default)]
    pub token_limit: u32,
    #[serde(default)]
    pub tokens_truncated: bool,
    #[serde(default)]
    pub tokens_preview: Vec<DecompileToken>,
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
    #[serde(default)]
    pub decompile_error: String,
    #[serde(default)]
    pub resolution_error: String,
}

#[derive(Debug, Error)]
pub enum DecompileMetaError {
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
        "analyzeHeadless exited successfully but the decompile_meta postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("decompile meta output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(DecompileMetaError);


#[derive(Debug, Clone)]
pub struct DecompileMetaContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct DecompileMetaEnvelope {
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
    line_count: u32,
    #[serde(default)]
    token_count: u32,
    #[serde(default)]
    token_limit: u32,
    #[serde(default)]
    tokens_truncated: bool,
    #[serde(default)]
    tokens_preview: Vec<DecompileToken>,
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

/// Return compact decompiler metadata for a function.
///
/// # Errors
///
/// Returns an error if the function query or simplification style is invalid,
/// the binary cannot be resolved, the Ghidra script cannot run, or the metadata
/// report cannot be read or decoded.
pub async fn get_decompile_meta(
    ctx: &DecompileMetaContext,
    binary_query: &str,
    name_or_address: &str,
    simplification_style: Option<&str>,
    token_limit: u32,
) -> Result<DecompileMetaResult, DecompileMetaError> {
    if name_or_address.trim().is_empty() {
        return Err(DecompileMetaError::EmptyQuery);
    }
    let simplification_style =
        resolve_simplification_style(simplification_style).ok_or_else(|| {
            DecompileMetaError::InvalidSimplificationStyle {
                style: simplification_style.unwrap_or_default().to_string(),
            }
        })?;
    let token_limit = resolve_token_limit(token_limit);

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
        script_name: DECOMPILE_META_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![
            name_or_address.to_string(),
            simplification_style.to_string(),
            token_limit.to_string(),
        ],
    })
    .await?;

    let envelope: DecompileMetaEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| DecompileMetaError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(DecompileMetaResult {
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
        source: envelope.source,
        parameter_count: envelope.parameter_count,
        parameters: envelope.parameters,
        local_var_count: envelope.local_var_count,
        local_vars: envelope.local_vars,
        line_count: envelope.line_count,
        token_count: envelope.token_count,
        token_limit: envelope.token_limit,
        tokens_truncated: envelope.tokens_truncated,
        tokens_preview: envelope.tokens_preview,
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

fn resolve_token_limit(limit: u32) -> u32 {
    if limit == 0 {
        DEFAULT_TOKEN_LIMIT
    } else {
        limit.min(MAX_TOKEN_LIMIT)
    }
}
