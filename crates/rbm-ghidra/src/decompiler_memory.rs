use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::decompiler_cfg::{
    DECOMPILER_CFG_SCHEMA, DecompilerCfgError, DecompilerCfgMemoryAccess, DecompilerCfgResult,
};
use crate::project::{DECOMPILER_MEMORY_SCRIPT, ProjectManager, cache_key};
use crate::warm_path::{WarmPathError, WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const DECOMPILER_MEMORY_SCHEMA: &str = "rbm.ghidra.decompiler_memory.v0";
const OUTPUT_PREFIX: &str = "decompiler_memory";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecompilerMemoryFilter {
    pub only_writes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompilerMemoryBlock {
    pub index: u32,
    pub start: String,
    pub stop: String,
    pub block_kind: String,
    pub structural_tags: Vec<String>,
    pub instruction_addresses_preview: Vec<String>,
    pub instruction_addresses_truncated: bool,
    pub memory_access_count: u32,
    pub memory_accesses_preview: Vec<DecompilerCfgMemoryAccess>,
    pub memory_accesses_preview_truncated: bool,
    pub memory_read_count: u32,
    pub memory_write_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct DecompilerMemoryEnvelope {
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
    total_memory_access_count: u32,
    #[serde(default)]
    total_memory_read_count: u32,
    #[serde(default)]
    total_memory_write_count: u32,
    #[serde(default)]
    blocks: Vec<DecompilerMemoryBlock>,
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
pub struct DecompilerMemoryResult {
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
    pub total_memory_access_count: u32,
    pub total_memory_read_count: u32,
    pub total_memory_write_count: u32,
    pub blocks: Vec<DecompilerMemoryBlock>,
    pub decompile_completed: bool,
    pub decompile_valid: bool,
    pub is_timed_out: bool,
    pub is_cancelled: bool,
    pub failed_to_start: bool,
    pub decompile_error: String,
}

#[derive(Debug, Clone)]
pub struct DecompilerMemoryContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[must_use]
pub fn project_decompiler_memory_filtered(
    cfg: DecompilerCfgResult,
    filter: &DecompilerMemoryFilter,
) -> DecompilerMemoryResult {
    let source_block_count = cfg.block_count;
    let mut total_memory_access_count = 0;
    let mut total_memory_read_count = 0;
    let mut total_memory_write_count = 0;

    let mut blocks: Vec<DecompilerMemoryBlock> = cfg
        .blocks
        .into_iter()
        .filter(|block| block.memory_access_count > 0)
        .filter(|block| !filter.only_writes || block.memory_write_count > 0)
        .map(|block| DecompilerMemoryBlock {
            index: block.index,
            start: block.start,
            stop: block.stop,
            block_kind: block.block_kind,
            structural_tags: block.structural_tags,
            instruction_addresses_preview: block.instruction_addresses_preview,
            instruction_addresses_truncated: block.instruction_addresses_truncated,
            memory_access_count: block.memory_access_count,
            memory_accesses_preview: block.memory_accesses_preview,
            memory_accesses_preview_truncated: block.memory_accesses_preview_truncated,
            memory_read_count: block.memory_read_count,
            memory_write_count: block.memory_write_count,
        })
        .collect();
    blocks.sort_by_key(|block| block.index);

    for block in &blocks {
        total_memory_access_count += block.memory_access_count;
        total_memory_read_count += block.memory_read_count;
        total_memory_write_count += block.memory_write_count;
    }

    DecompilerMemoryResult {
        schema: DECOMPILER_MEMORY_SCHEMA.to_string(),
        source_schema: DECOMPILER_CFG_SCHEMA.to_string(),
        cache_key: cfg.cache_key,
        sha256: cfg.sha256,
        program_name: cfg.program_name,
        query: cfg.query,
        simplification_style: cfg.simplification_style,
        resolved_address: cfg.resolved_address,
        resolved_function_name: cfg.resolved_function_name,
        source_block_count,
        matched_block_count: u32::try_from(blocks.len()).unwrap_or(u32::MAX),
        total_memory_access_count,
        total_memory_read_count,
        total_memory_write_count,
        blocks,
        decompile_completed: cfg.decompile_completed,
        decompile_valid: cfg.decompile_valid,
        is_timed_out: cfg.is_timed_out,
        is_cancelled: cfg.is_cancelled,
        failed_to_start: cfg.failed_to_start,
        decompile_error: cfg.decompile_error,
    }
}

#[must_use]
pub fn project_decompiler_memory(cfg: DecompilerCfgResult) -> DecompilerMemoryResult {
    project_decompiler_memory_filtered(cfg, &DecompilerMemoryFilter::default())
}

fn normalize_memory_result(result: &mut DecompilerMemoryResult) {
    result.blocks.sort_by_key(|block| block.index);
}



/// Return memory-access facts from the decompiler CFG output.
///
/// # Errors
///
/// Returns an error if the function query or simplification style is invalid,
/// the binary cannot be resolved, the Ghidra script cannot run, or the report
/// cannot be read or decoded.
pub async fn get_decompiler_memory(
    ctx: &DecompilerMemoryContext,
    binary_query: &str,
    name_or_address: &str,
    simplification_style: Option<&str>,
    filter: &DecompilerMemoryFilter,
) -> Result<DecompilerMemoryResult, DecompilerCfgError> {
    if name_or_address.trim().is_empty() {
        return Err(DecompilerCfgError::EmptyQuery);
    }
    let simplification_style =
        crate::utils::resolve_simplification_style(simplification_style).ok_or_else(|| {
            DecompilerCfgError::InvalidSimplificationStyle {
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
        script_name: DECOMPILER_MEMORY_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![
            name_or_address.to_string(),
            simplification_style.to_string(),
            if filter.only_writes { "1" } else { "0" }.to_string(),
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

    let envelope: DecompilerMemoryEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| DecompilerCfgError::Parse {
            path: output_path,
            source: err,
        })?;

    if !envelope.resolution_error.is_empty() {
        return Err(DecompilerCfgError::ResolutionFailed(
            envelope.resolution_error,
        ));
    }

    let mut result = DecompilerMemoryResult {
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
        total_memory_access_count: envelope.total_memory_access_count,
        total_memory_read_count: envelope.total_memory_read_count,
        total_memory_write_count: envelope.total_memory_write_count,
        blocks: envelope.blocks,
        decompile_completed: envelope.decompile_completed,
        decompile_valid: envelope.decompile_valid,
        is_timed_out: envelope.is_timed_out,
        is_cancelled: envelope.is_cancelled,
        failed_to_start: envelope.failed_to_start,
        decompile_error: envelope.decompile_error,
    };
    normalize_memory_result(&mut result);
    Ok(result)
}
