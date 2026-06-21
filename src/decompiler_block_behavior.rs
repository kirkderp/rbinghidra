use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::decompiler_cfg::{DecompilerCfgConstant, DecompilerCfgError, DecompilerCfgStringRef};
use crate::project::{DECOMPILER_BLOCK_BEHAVIOR_SCRIPT, ProjectManager, cache_key};
use crate::warm_path::{WarmPathError, WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const DECOMPILER_BLOCK_BEHAVIOR_SCHEMA: &str = "rbm.ghidra.decompiler_block_behavior.v0";
const OUTPUT_PREFIX: &str = "decompiler_block_behavior";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecompilerBlockBehaviorFilter {
    pub only_strings: bool,
    pub only_api_tag: Option<String>,
    pub only_external: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompilerBlockBehaviorBlock {
    pub index: u32,
    pub start: String,
    pub stop: String,
    pub block_kind: String,
    pub structural_tags: Vec<String>,
    pub predecessor_indices: Vec<u32>,
    pub successor_indices: Vec<u32>,
    pub incoming_edges: u32,
    pub outgoing_edges: u32,
    pub conditional_edge_count: u32,
    pub flow_edge_count: u32,
    pub back_edge_count: u32,
    pub module_count: u32,
    pub modules: Vec<String>,
    pub api_family_count: u32,
    pub api_families: Vec<String>,
    pub api_tag_count: u32,
    pub api_tags: Vec<String>,
    pub external_call_count: u32,
    pub external_address_ref_count: u32,
    pub external_symbol_count: u32,
    pub external_symbols: Vec<String>,
    pub external_symbols_truncated: bool,
    pub constant_count: u32,
    pub constants_preview: Vec<DecompilerCfgConstant>,
    pub constants_preview_truncated: bool,
    pub string_ref_count: u32,
    pub string_refs_preview: Vec<DecompilerCfgStringRef>,
    pub string_refs_preview_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DecompilerBlockBehaviorResult {
    pub schema: String,
    pub source_schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub simplification_style: String,
    pub resolved_address: String,
    pub resolved_function_name: String,
    pub block_count: u32,
    pub total_conditional_edge_count: u32,
    pub total_flow_edge_count: u32,
    pub total_back_edge_count: u32,
    pub blocks: Vec<DecompilerBlockBehaviorBlock>,
    pub decompile_completed: bool,
    pub decompile_valid: bool,
    pub is_timed_out: bool,
    pub is_cancelled: bool,
    pub failed_to_start: bool,
    pub decompile_error: String,
}

#[derive(Debug, Clone)]
pub struct DecompilerBlockBehaviorContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct DecompilerBlockBehaviorEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    source_schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    simplification_style: String,
    #[serde(default)]
    resolved_address: String,
    #[serde(default)]
    resolved_function_name: String,
    #[serde(default)]
    block_count: u32,
    #[serde(default)]
    total_conditional_edge_count: u32,
    #[serde(default)]
    total_flow_edge_count: u32,
    #[serde(default)]
    total_back_edge_count: u32,
    #[serde(default)]
    blocks: Vec<DecompilerBlockBehaviorBlock>,
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

fn sorted_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn normalize_block_behavior_result(result: &mut DecompilerBlockBehaviorResult) {
    result.blocks.sort_by_key(|block| block.index);
    for block in &mut result.blocks {
        block.modules = sorted_strings(std::mem::take(&mut block.modules));
        block.api_families = sorted_strings(std::mem::take(&mut block.api_families));
        block.api_tags = sorted_strings(std::mem::take(&mut block.api_tags));
        block.external_symbols = sorted_strings(std::mem::take(&mut block.external_symbols));
    }
}

/// Return block-level behavior facts from the decompiler CFG output.
///
/// # Errors
///
/// Returns an error if the function query or simplification style is invalid,
/// the binary cannot be resolved, the Ghidra script cannot run, or the report
/// cannot be read or decoded.
pub async fn get_decompiler_block_behavior(
    ctx: &DecompilerBlockBehaviorContext,
    binary_query: &str,
    name_or_address: &str,
    simplification_style: Option<&str>,
    filter: &DecompilerBlockBehaviorFilter,
) -> Result<DecompilerBlockBehaviorResult, DecompilerCfgError> {
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
        script_name: DECOMPILER_BLOCK_BEHAVIOR_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![
            name_or_address.to_string(),
            simplification_style.to_string(),
            if filter.only_strings { "1" } else { "0" }.to_string(),
            if filter.only_external { "1" } else { "0" }.to_string(),
            filter.only_api_tag.clone().unwrap_or_default(),
        ],
    })
    .await
    .map_err(|err| match err {
        WarmPathError::Inspect(e) => DecompilerCfgError::Inspect(e),
        WarmPathError::LockHeld { sha256 } => DecompilerCfgError::LockHeld { sha256 },
        WarmPathError::PathValidation(e) => DecompilerCfgError::PathValidation(e),
        WarmPathError::ProjectFileMissing(p) => DecompilerCfgError::ProjectFileMissing(p),
        WarmPathError::HeadlessFailed { exit_code, stderr } => {
            DecompilerCfgError::HeadlessFailed { exit_code, stderr }
        }
        WarmPathError::OutputMissing { stdout, stderr } => {
            DecompilerCfgError::OutputMissing { stdout, stderr }
        }
        WarmPathError::Headless(e) => DecompilerCfgError::Headless(e),
        WarmPathError::Io { path, source } => DecompilerCfgError::Io { path, source },
    })?;

    let envelope: DecompilerBlockBehaviorEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| DecompilerCfgError::Parse {
            path: output_path,
            source: err,
        })?;

    if !envelope.resolution_error.is_empty() {
        return Err(DecompilerCfgError::ResolutionFailed(
            envelope.resolution_error,
        ));
    }

    let mut result = DecompilerBlockBehaviorResult {
        schema: envelope.schema,
        source_schema: envelope.source_schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        simplification_style: envelope.simplification_style,
        resolved_address: envelope.resolved_address,
        resolved_function_name: envelope.resolved_function_name,
        block_count: envelope.block_count,
        total_conditional_edge_count: envelope.total_conditional_edge_count,
        total_flow_edge_count: envelope.total_flow_edge_count,
        total_back_edge_count: envelope.total_back_edge_count,
        blocks: envelope.blocks,
        decompile_completed: envelope.decompile_completed,
        decompile_valid: envelope.decompile_valid,
        is_timed_out: envelope.is_timed_out,
        is_cancelled: envelope.is_cancelled,
        failed_to_start: envelope.failed_to_start,
        decompile_error: envelope.decompile_error,
    };
    normalize_block_behavior_result(&mut result);
    Ok(result)
}
