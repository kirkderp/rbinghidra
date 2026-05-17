use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, MEMORY_MAP_SCRIPT, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const MEMORY_MAP_SCHEMA: &str = "rbm.ghidra.memory_map.v0";
const OUTPUT_PREFIX: &str = "memmap";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct MemoryBlockEntry {
    pub name: String,
    pub start: String,
    pub end: String,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub initialized: bool,
    pub is_external: bool,
    pub comment: String,
    #[serde(rename = "type")]
    pub block_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMapResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub block_count: u32,
    pub blocks: Vec<MemoryBlockEntry>,
}

#[derive(Debug, Error)]
pub enum MemoryMapError {
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
        "analyzeHeadless exited successfully but the memory_map postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("memory_map output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(MemoryMapError);

#[derive(Debug, Clone)]
pub struct MemoryMapContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct MemoryMapEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    block_count: u32,
    #[serde(default)]
    blocks: Vec<MemoryBlockEntry>,
}

/// Return the memory map for a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the Ghidra script cannot
/// run, or the memory-map report cannot be read or decoded.
pub async fn get_memory_map(
    ctx: &MemoryMapContext,
    binary_query: &str,
) -> Result<MemoryMapResult, MemoryMapError> {
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
        script_name: MEMORY_MAP_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: "",
        extra_script_args: vec![],
    })
    .await?;

    let envelope: MemoryMapEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| MemoryMapError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(MemoryMapResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        block_count: envelope.block_count,
        blocks: envelope.blocks,
    })
}
