use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::decompiler_cfg::{DecompilerCfgCallsite, DecompilerCfgError};
use crate::project::{DECOMPILER_CALLS_SCRIPT, ProjectManager, cache_key};
use crate::warm_path::{WarmPathError, WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const DECOMPILER_CALLS_SCHEMA: &str = "rbm.ghidra.decompiler_calls.v0";
const OUTPUT_PREFIX: &str = "decompiler_calls";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecompilerCallsFilter {
    pub only_external: bool,
    pub only_indirect: bool,
    pub only_api_tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DecompilerCallsBlock {
    pub index: u32,
    pub start: String,
    pub stop: String,
    pub block_kind: String,
    pub structural_tags: Vec<String>,
    pub instruction_addresses_preview: Vec<String>,
    pub instruction_addresses_truncated: bool,
    pub call_count: u32,
    pub callsites_preview: Vec<DecompilerCfgCallsite>,
    pub callsites_preview_truncated: bool,
    pub internal_call_count: u32,
    pub external_callsite_count: u32,
    pub indirect_call_count: u32,
    pub thunk_call_count: u32,
    pub call_target_count: u32,
    pub call_targets: Vec<String>,
    pub call_targets_truncated: bool,
    pub internal_call_target_count: u32,
    pub internal_call_targets: Vec<String>,
    pub internal_call_targets_truncated: bool,
    pub external_call_target_count: u32,
    pub external_call_targets: Vec<String>,
    pub external_call_targets_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct DecompilerCallsEnvelope {
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
    source_block_count: u32,
    #[serde(default)]
    matched_block_count: u32,
    #[serde(default)]
    total_call_count: u32,
    #[serde(default)]
    total_internal_call_count: u32,
    #[serde(default)]
    total_external_callsite_count: u32,
    #[serde(default)]
    total_indirect_call_count: u32,
    #[serde(default)]
    total_thunk_call_count: u32,
    #[serde(default)]
    blocks: Vec<DecompilerCallsBlock>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DecompilerCallsResult {
    pub schema: String,
    pub source_schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub simplification_style: String,
    pub resolved_address: String,
    pub resolved_function_name: String,
    pub source_block_count: u32,
    pub matched_block_count: u32,
    pub total_call_count: u32,
    pub total_internal_call_count: u32,
    pub total_external_callsite_count: u32,
    pub total_indirect_call_count: u32,
    pub total_thunk_call_count: u32,
    pub blocks: Vec<DecompilerCallsBlock>,
    pub decompile_completed: bool,
    pub decompile_valid: bool,
    pub is_timed_out: bool,
    pub is_cancelled: bool,
    pub failed_to_start: bool,
    pub decompile_error: String,
}

#[derive(Debug, Clone)]
pub struct DecompilerCallsContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

fn sorted_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn normalize_calls_result(result: &mut DecompilerCallsResult) {
    result.blocks.sort_by_key(|block| block.index);
    for block in &mut result.blocks {
        block.call_targets = sorted_strings(std::mem::take(&mut block.call_targets));
        block.internal_call_targets =
            sorted_strings(std::mem::take(&mut block.internal_call_targets));
        block.external_call_targets =
            sorted_strings(std::mem::take(&mut block.external_call_targets));
    }
}

/// Return callsite facts from the decompiler CFG output.
///
/// # Errors
///
/// Returns an error if the function query or simplification style is invalid,
/// the binary cannot be resolved, the Ghidra script cannot run, or the report
/// cannot be read or decoded.
pub async fn get_decompiler_calls(
    ctx: &DecompilerCallsContext,
    binary_query: &str,
    name_or_address: &str,
    simplification_style: Option<&str>,
    filter: &DecompilerCallsFilter,
) -> Result<DecompilerCallsResult, DecompilerCfgError> {
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
        script_name: DECOMPILER_CALLS_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![
            name_or_address.to_string(),
            simplification_style.to_string(),
            if filter.only_external { "1" } else { "0" }.to_string(),
            if filter.only_indirect { "1" } else { "0" }.to_string(),
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

    let envelope: DecompilerCallsEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| DecompilerCfgError::Parse {
            path: output_path,
            source: err,
        })?;

    if !envelope.resolution_error.is_empty() {
        return Err(DecompilerCfgError::ResolutionFailed(
            envelope.resolution_error,
        ));
    }

    let mut result = DecompilerCallsResult {
        schema: envelope.schema,
        source_schema: envelope.source_schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        simplification_style: envelope.simplification_style,
        resolved_address: envelope.resolved_address,
        resolved_function_name: envelope.resolved_function_name,
        source_block_count: envelope.source_block_count,
        matched_block_count: envelope.matched_block_count,
        total_call_count: envelope.total_call_count,
        total_internal_call_count: envelope.total_internal_call_count,
        total_external_callsite_count: envelope.total_external_callsite_count,
        total_indirect_call_count: envelope.total_indirect_call_count,
        total_thunk_call_count: envelope.total_thunk_call_count,
        blocks: envelope.blocks,
        decompile_completed: envelope.decompile_completed,
        decompile_valid: envelope.decompile_valid,
        is_timed_out: envelope.is_timed_out,
        is_cancelled: envelope.is_cancelled,
        failed_to_start: envelope.failed_to_start,
        decompile_error: envelope.decompile_error,
    };
    normalize_calls_result(&mut result);
    Ok(result)
}
