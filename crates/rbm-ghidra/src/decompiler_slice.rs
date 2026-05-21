use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::pcode::{PcodeOp, PcodeVarnode};
use crate::project::{
    DECOMPILER_SLICE_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const DECOMPILER_SLICE_SCHEMA: &str = "rbm.ghidra.decompiler_slice.v0";
const OUTPUT_PREFIX: &str = "decompiler_slice";
const DEFAULT_DIRECTION: &str = "both";
const DEFAULT_MAX_OPS: u32 = 80;
const MAX_OPS_CAP: u32 = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompilerSliceSeed {
    pub match_kind: String,
    pub op_seq_num: String,
    pub op_mnemonic: String,
    pub varnode: PcodeVarnode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DecompilerSliceResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub direction: String,
    pub simplification_style: String,
    pub function_name: String,
    pub address: String,
    pub seed: Option<DecompilerSliceSeed>,
    pub forward_op_count: u32,
    pub backward_op_count: u32,
    pub ops_returned: u32,
    pub ops_truncated: bool,
    pub ops: Vec<PcodeOp>,
    pub basic_block_count: u32,
    pub decompile_completed: bool,
    pub decompile_valid: bool,
    pub is_timed_out: bool,
    pub is_cancelled: bool,
    pub failed_to_start: bool,
    pub decompile_error: String,
    pub resolution_error: String,
    pub slice_error: String,
}

#[derive(Debug, Error)]
pub enum DecompilerSliceError {
    #[error("name_or_address must not be empty")]
    EmptyFunctionQuery,
    #[error("query must not be empty")]
    EmptySliceQuery,
    #[error("invalid direction '{direction}'; expected one of: forward, backward, both")]
    InvalidDirection { direction: String },
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
        "analyzeHeadless exited successfully but the decompiler_slice postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("decompiler_slice output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(DecompilerSliceError);

#[derive(Debug, Clone)]
pub struct DecompilerSliceContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct DecompilerSliceEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    direction: String,
    #[serde(default)]
    simplification_style: String,
    #[serde(default)]
    function_name: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    seed: Option<DecompilerSliceSeed>,
    #[serde(default)]
    forward_op_count: u32,
    #[serde(default)]
    backward_op_count: u32,
    #[serde(default)]
    ops_returned: u32,
    #[serde(default)]
    ops_truncated: bool,
    #[serde(default)]
    ops: Vec<serde_json::Value>,
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
    #[serde(default)]
    slice_error: String,
}

/// Return a bounded decompiler p-code slice rooted at a queried varnode/op.
///
/// # Errors
///
/// Returns an error if query parameters are invalid, the binary cannot be
/// resolved, the Ghidra script cannot run, or the slice report cannot be read
/// or decoded.
pub async fn get_decompiler_slice(
    ctx: &DecompilerSliceContext,
    binary_query: &str,
    name_or_address: &str,
    query: &str,
    direction: Option<&str>,
    simplification_style: Option<&str>,
    max_ops: u32,
) -> Result<DecompilerSliceResult, DecompilerSliceError> {
    if name_or_address.trim().is_empty() {
        return Err(DecompilerSliceError::EmptyFunctionQuery);
    }
    if query.trim().is_empty() {
        return Err(DecompilerSliceError::EmptySliceQuery);
    }
    let direction =
        resolve_direction(direction).ok_or_else(|| DecompilerSliceError::InvalidDirection {
            direction: direction.unwrap_or_default().to_string(),
        })?;
    let simplification_style =
        crate::utils::resolve_simplification_style(simplification_style).ok_or_else(|| {
            DecompilerSliceError::InvalidSimplificationStyle {
                style: simplification_style.unwrap_or_default().to_string(),
            }
        })?;
    let max_ops = resolve_max_ops(max_ops);

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
        script_name: DECOMPILER_SLICE_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: &format!("{name_or_address}_{query}_{direction}"),
        extra_script_args: vec![
            name_or_address.to_string(),
            query.to_string(),
            direction.to_string(),
            simplification_style.to_string(),
            max_ops.to_string(),
        ],
    })
    .await?;

    let envelope: DecompilerSliceEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| DecompilerSliceError::Parse {
            path: output_path,
            source: err,
        })?;

    let ops: Vec<PcodeOp> = envelope
        .ops
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect();

    Ok(DecompilerSliceResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        direction: envelope.direction,
        simplification_style: envelope.simplification_style,
        function_name: envelope.function_name,
        address: envelope.address,
        seed: envelope.seed,
        forward_op_count: envelope.forward_op_count,
        backward_op_count: envelope.backward_op_count,
        ops_returned: envelope.ops_returned,
        ops_truncated: envelope.ops_truncated,
        ops,
        basic_block_count: envelope.basic_block_count,
        decompile_completed: envelope.decompile_completed,
        decompile_valid: envelope.decompile_valid,
        is_timed_out: envelope.is_timed_out,
        is_cancelled: envelope.is_cancelled,
        failed_to_start: envelope.failed_to_start,
        decompile_error: envelope.decompile_error,
        resolution_error: envelope.resolution_error,
        slice_error: envelope.slice_error,
    })
}

fn resolve_direction(direction: Option<&str>) -> Option<&'static str> {
    match direction.unwrap_or(DEFAULT_DIRECTION).trim() {
        "" | DEFAULT_DIRECTION => Some(DEFAULT_DIRECTION),
        "forward" => Some("forward"),
        "backward" => Some("backward"),
        _ => None,
    }
}



fn resolve_max_ops(max_ops: u32) -> u32 {
    if max_ops == 0 {
        DEFAULT_MAX_OPS
    } else {
        max_ops.min(MAX_OPS_CAP)
    }
}
