use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    DECOMPILER_CFG_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const DECOMPILER_CFG_SCHEMA: &str = "rbm.ghidra.decompiler_cfg.v0";
const OUTPUT_PREFIX: &str = "decompiler_cfg";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompilerCfgOp {
    pub seq_num: String,
    pub mnemonic: String,
    pub output: String,
    pub inputs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DecompilerCfgCallsite {
    pub mnemonic: String,
    pub op_address: String,
    pub target_name: String,
    pub target_address: String,
    pub target_preview: String,
    #[serde(default)]
    pub call_context_preview: Vec<String>,
    #[serde(default)]
    pub call_context_truncated: bool,
    #[serde(default)]
    pub module_name: String,
    #[serde(default)]
    pub api_family: String,
    #[serde(default)]
    pub api_tag: String,
    pub is_external: bool,
    pub is_thunk: bool,
    pub is_indirect: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompilerCfgMemoryAccess {
    pub access_kind: String,
    pub op_address: String,
    pub address_preview: String,
    pub value_preview: String,
    pub space_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompilerCfgConstant {
    pub value_hex: String,
    pub size_bytes: u32,
    pub source_op_mnemonic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompilerCfgStringRef {
    pub value: String,
    pub address: String,
    pub source_op_mnemonic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompilerCfgExternalRef {
    pub name: String,
    pub module_name: String,
    #[serde(default)]
    pub api_family: String,
    #[serde(default)]
    pub api_tag: String,
    pub address: String,
    pub ref_kind: String,
    pub source_op_mnemonic: String,
    #[serde(default)]
    pub source_op_address: String,
    #[serde(default)]
    pub source_value_preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DecompilerCfgBlock {
    pub index: u32,
    pub start: String,
    pub stop: String,
    #[serde(default)]
    pub block_kind: String,
    #[serde(default)]
    pub structural_tags: Vec<String>,
    pub pcode_op_count: u32,
    pub first_op_mnemonic: String,
    pub last_op_mnemonic: String,
    pub pcode_mnemonics_preview: Vec<String>,
    pub pcode_preview_truncated: bool,
    pub defs_preview: Vec<String>,
    pub defs_preview_truncated: bool,
    pub uses_preview: Vec<String>,
    pub uses_preview_truncated: bool,
    pub instruction_addresses_preview: Vec<String>,
    pub instruction_addresses_truncated: bool,
    #[serde(default)]
    pub call_count: u32,
    #[serde(default)]
    pub callsites_preview: Vec<DecompilerCfgCallsite>,
    #[serde(default)]
    pub callsites_preview_truncated: bool,
    #[serde(default)]
    pub internal_call_count: u32,
    #[serde(default)]
    pub external_callsite_count: u32,
    #[serde(default)]
    pub indirect_call_count: u32,
    #[serde(default)]
    pub thunk_call_count: u32,
    #[serde(default)]
    pub call_target_count: u32,
    #[serde(default)]
    pub call_targets: Vec<String>,
    #[serde(default)]
    pub call_targets_truncated: bool,
    #[serde(default)]
    pub internal_call_target_count: u32,
    #[serde(default)]
    pub internal_call_targets: Vec<String>,
    #[serde(default)]
    pub internal_call_targets_truncated: bool,
    #[serde(default)]
    pub external_call_target_count: u32,
    #[serde(default)]
    pub external_call_targets: Vec<String>,
    #[serde(default)]
    pub external_call_targets_truncated: bool,
    #[serde(default)]
    pub memory_access_count: u32,
    #[serde(default)]
    pub memory_accesses_preview: Vec<DecompilerCfgMemoryAccess>,
    #[serde(default)]
    pub memory_accesses_preview_truncated: bool,
    #[serde(default)]
    pub memory_read_count: u32,
    #[serde(default)]
    pub memory_write_count: u32,
    #[serde(default)]
    pub constant_count: u32,
    #[serde(default)]
    pub constants_preview: Vec<DecompilerCfgConstant>,
    #[serde(default)]
    pub constants_preview_truncated: bool,
    #[serde(default)]
    pub string_ref_count: u32,
    #[serde(default)]
    pub string_refs_preview: Vec<DecompilerCfgStringRef>,
    #[serde(default)]
    pub string_refs_preview_truncated: bool,
    #[serde(default)]
    pub external_ref_count: u32,
    #[serde(default)]
    pub external_refs_preview: Vec<DecompilerCfgExternalRef>,
    #[serde(default)]
    pub external_refs_preview_truncated: bool,
    #[serde(default)]
    pub external_call_count: u32,
    #[serde(default)]
    pub external_address_ref_count: u32,
    #[serde(default)]
    pub external_symbol_count: u32,
    #[serde(default)]
    pub external_symbols: Vec<String>,
    #[serde(default)]
    pub external_symbols_truncated: bool,
    #[serde(default)]
    pub module_count: u32,
    #[serde(default)]
    pub modules: Vec<String>,
    #[serde(default)]
    pub api_family_count: u32,
    #[serde(default)]
    pub api_families: Vec<String>,
    #[serde(default)]
    pub api_tag_count: u32,
    #[serde(default)]
    pub api_tags: Vec<String>,
    pub predecessor_indices: Vec<u32>,
    pub successor_indices: Vec<u32>,
    #[serde(default)]
    pub ops: Vec<DecompilerCfgOp>,
    pub incoming_edges: u32,
    pub outgoing_edges: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompilerCfgEdge {
    pub from_index: u32,
    pub to_index: u32,
    pub from: String,
    pub to: String,
    pub edge_index: u32,
    pub label: String,
    pub branch_kind: String,
    pub source_op_mnemonic: String,
    pub source_op_address: String,
    #[serde(default)]
    pub branch_target_preview: String,
    #[serde(default)]
    pub condition_preview: String,
    #[serde(default)]
    pub predicate_mnemonic: String,
    #[serde(default)]
    pub predicate_inputs_preview: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DecompilerCfgResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub simplification_style: String,
    pub include_ops: bool,
    pub resolved_address: String,
    pub resolved_function_name: String,
    pub block_count: u32,
    pub edge_count: u32,
    pub blocks: Vec<DecompilerCfgBlock>,
    pub edges: Vec<DecompilerCfgEdge>,
    pub decompile_completed: bool,
    pub decompile_valid: bool,
    pub is_timed_out: bool,
    pub is_cancelled: bool,
    pub failed_to_start: bool,
    pub decompile_error: String,
    pub resolution_error: String,
    pub mermaid: String,
}

#[derive(Debug, Error)]
pub enum DecompilerCfgError {
    #[error("cfg query must not be empty")]
    EmptyQuery,
    #[error(
        "invalid simplification_style '{style}'; expected one of: decompile, normalize, register, firstpass, paramid"
    )]
    InvalidSimplificationStyle { style: String },
    #[error(
        "invalid function_slices mode '{mode}'; expected one of: all, callsites, fields, buffers, indirect, lineage, table_lineage"
    )]
    InvalidFunctionSlicesMode { mode: String },
    #[error("function resolution failed: {0}")]
    ResolutionFailed(String),
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
        "analyzeHeadless exited successfully but the decompiler_cfg postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("decompiler_cfg output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(DecompilerCfgError);

#[derive(Debug, Clone)]
pub struct DecompilerCfgContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct DecompilerCfgEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    simplification_style: String,
    #[serde(default)]
    include_ops: bool,
    #[serde(default)]
    resolved_address: String,
    #[serde(default)]
    resolved_function_name: String,
    #[serde(default)]
    resolution_error: String,
    #[serde(default)]
    block_count: u32,
    #[serde(default)]
    edge_count: u32,
    #[serde(default)]
    blocks: Vec<DecompilerCfgBlock>,
    #[serde(default)]
    edges: Vec<DecompilerCfgEdge>,
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
    mermaid: String,
}

/// Generate a decompiler-derived CFG for a function.
///
/// # Errors
///
/// Returns an error if the function query or simplification style is invalid,
/// the binary cannot be resolved, the Ghidra script cannot run, or the CFG report
/// cannot be read or decoded.
pub async fn gen_decompiler_cfg(
    ctx: &DecompilerCfgContext,
    binary_query: &str,
    name_or_address: &str,
    simplification_style: Option<&str>,
    include_ops: bool,
) -> Result<DecompilerCfgResult, DecompilerCfgError> {
    if name_or_address.trim().is_empty() {
        return Err(DecompilerCfgError::EmptyQuery);
    }
    let simplification_style = crate::utils::resolve_simplification_style(simplification_style)
        .ok_or_else(|| DecompilerCfgError::InvalidSimplificationStyle {
            style: simplification_style.unwrap_or_default().to_string(),
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
        script_name: DECOMPILER_CFG_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![
            name_or_address.to_string(),
            simplification_style.to_string(),
            if include_ops { "1" } else { "0" }.to_string(),
        ],
    })
    .await?;

    let envelope: DecompilerCfgEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| DecompilerCfgError::Parse {
            path: output_path,
            source: err,
        })?;

    if !envelope.resolution_error.is_empty() {
        return Err(DecompilerCfgError::ResolutionFailed(
            envelope.resolution_error,
        ));
    }

    Ok(DecompilerCfgResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        simplification_style: envelope.simplification_style,
        include_ops: envelope.include_ops,
        resolved_address: envelope.resolved_address,
        resolved_function_name: envelope.resolved_function_name,
        block_count: envelope.block_count,
        edge_count: envelope.edge_count,
        blocks: envelope.blocks,
        edges: envelope.edges,
        decompile_completed: envelope.decompile_completed,
        decompile_valid: envelope.decompile_valid,
        is_timed_out: envelope.is_timed_out,
        is_cancelled: envelope.is_cancelled,
        failed_to_start: envelope.failed_to_start,
        decompile_error: envelope.decompile_error,
        resolution_error: String::new(),
        mermaid: envelope.mermaid,
    })
}
