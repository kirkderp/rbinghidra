use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    FUNCTION_CHECKPOINTS_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const FUNCTION_CHECKPOINTS_SCHEMA: &str = "rbm.ghidra.function_checkpoints.v0";
const OUTPUT_PREFIX: &str = "function_checkpoints";
const DEFAULT_SIMPLIFICATION_STYLE: &str = "decompile";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCheckpointStackRef {
    pub address: String,
    pub disassembly: String,
    pub operand_index: u32,
    pub operand: String,
    pub base_register: String,
    pub displacement: i32,
    pub displacement_hex: String,
    pub canonical_stack_offset: Option<i32>,
    pub canonical_stack_offset_hex: String,
    pub access: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCheckpointInstructionPreview {
    pub address: String,
    pub disassembly: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCheckpointRange {
    pub name: String,
    pub start: String,
    pub end: String,
    pub instruction_count: u32,
    pub first_instruction: String,
    pub last_instruction: String,
    pub byte_sha256: String,
    pub mnemonic_counts: Vec<(String, u32)>,
    pub call_count: u32,
    pub jump_count: u32,
    pub terminal_count: u32,
    pub memory_write_count: u32,
    pub stack_ref_count: u32,
    pub stack_write_count: u32,
    pub stack_refs_preview: Vec<FunctionCheckpointStackRef>,
    pub stack_refs_truncated: bool,
    pub instruction_preview: Vec<FunctionCheckpointInstructionPreview>,
    pub instruction_preview_truncated: bool,
    pub pcode_op_count: u32,
    pub pcode_mnemonic_counts: Vec<(String, u32)>,
    pub pcode_seq_preview: Vec<String>,
    pub pcode_preview_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct FunctionCheckpointsResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub simplification_style: String,
    pub function_name: String,
    pub address: String,
    pub ranges_query: String,
    pub range_count: u32,
    pub ranges: Vec<FunctionCheckpointRange>,
    pub decompile_completed: bool,
    pub decompile_valid: bool,
    pub is_timed_out: bool,
    pub is_cancelled: bool,
    pub failed_to_start: bool,
    pub decompile_error: String,
    pub resolution_error: String,
}

#[derive(Debug, Error)]
pub enum FunctionCheckpointsError {
    #[error("name_or_address must not be empty")]
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
        "analyzeHeadless exited successfully but the function_checkpoints postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("function_checkpoints output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(FunctionCheckpointsError);

#[derive(Debug, Clone)]
pub struct FunctionCheckpointsContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct FunctionCheckpointsEnvelope {
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
    ranges_query: String,
    #[serde(default)]
    range_count: u32,
    #[serde(default)]
    ranges: Vec<serde_json::Value>,
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

/// Return decompiler checkpoint slices for a function.
///
/// # Errors
///
/// Returns an error if the function query, range filter, or simplification style
/// is invalid, the binary cannot be resolved, the Ghidra script cannot run, or
/// the checkpoint report cannot be read or decoded.
pub async fn get_function_checkpoints(
    ctx: &FunctionCheckpointsContext,
    binary_query: &str,
    name_or_address: &str,
    ranges: Option<&str>,
    simplification_style: Option<&str>,
) -> Result<FunctionCheckpointsResult, FunctionCheckpointsError> {
    if name_or_address.trim().is_empty() {
        return Err(FunctionCheckpointsError::EmptyQuery);
    }
    let simplification_style =
        resolve_simplification_style(simplification_style).ok_or_else(|| {
            FunctionCheckpointsError::InvalidSimplificationStyle {
                style: simplification_style.unwrap_or_default().to_string(),
            }
        })?;

    let ranges_arg = ranges.unwrap_or("").trim();
    let output_key = checkpoint_output_key(name_or_address, ranges_arg, simplification_style);
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
        script_name: FUNCTION_CHECKPOINTS_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: &output_key,
        extra_script_args: vec![
            name_or_address.to_string(),
            ranges_arg.to_string(),
            simplification_style.to_string(),
        ],
    })
    .await?;

    let envelope: FunctionCheckpointsEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| FunctionCheckpointsError::Parse {
            path: output_path,
            source: err,
        })?;

    let ranges = envelope
        .ranges
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect();

    Ok(FunctionCheckpointsResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        simplification_style: envelope.simplification_style,
        function_name: envelope.function_name,
        address: envelope.address,
        ranges_query: envelope.ranges_query,
        range_count: envelope.range_count,
        ranges,
        decompile_completed: envelope.decompile_completed,
        decompile_valid: envelope.decompile_valid,
        is_timed_out: envelope.is_timed_out,
        is_cancelled: envelope.is_cancelled,
        failed_to_start: envelope.failed_to_start,
        decompile_error: envelope.decompile_error,
        resolution_error: envelope.resolution_error,
    })
}

fn checkpoint_output_key(
    name_or_address: &str,
    ranges: &str,
    simplification_style: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(name_or_address.as_bytes());
    h.update(b"\0");
    h.update(ranges.as_bytes());
    h.update(b"\0");
    h.update(simplification_style.as_bytes());
    let digest = h.finalize();
    format!("{name_or_address}_{}", hex_prefix(&digest, 16))
}

fn hex_prefix(bytes: &[u8], len: usize) -> String {
    bytes
        .iter()
        .flat_map(|b| {
            let s = format!("{b:02x}");
            s.into_bytes()
        })
        .take(len)
        .map(char::from)
        .collect()
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
