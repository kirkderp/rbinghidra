use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{CFG_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const CFG_SCHEMA: &str = "rbm.ghidra.cfg.v0";
const OUTPUT_PREFIX: &str = "cfg";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfgBlock {
    pub address: String,
    pub size: u64,
    pub instructions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: String,
    pub to: String,
    pub flow_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CfgResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub resolved_address: String,
    pub resolved_function_name: String,
    pub block_count: u64,
    pub edge_count: u64,
    pub blocks: Vec<CfgBlock>,
    pub edges: Vec<CfgEdge>,
    pub mermaid: String,
}

#[derive(Debug, Error)]
pub enum CfgError {
    #[error("cfg query must not be empty")]
    EmptyQuery,
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
        "analyzeHeadless exited successfully but the cfg postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("cfg output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(CfgError);


#[derive(Debug, Clone)]
pub struct CfgContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct CfgEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    resolved_address: String,
    #[serde(default)]
    resolved_function_name: String,
    #[serde(default)]
    resolution_error: String,
    #[serde(default)]
    block_count: u64,
    #[serde(default)]
    edge_count: u64,
    #[serde(default)]
    blocks: Vec<CfgBlock>,
    #[serde(default)]
    edges: Vec<CfgEdge>,
    #[serde(default)]
    mermaid: String,
}

/// Generate a listing-level CFG for a function in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, function input is invalid,
/// the Ghidra script cannot run, or the CFG report cannot be read or decoded.
pub async fn gen_cfg(
    ctx: &CfgContext,
    binary_query: &str,
    name_or_address: &str,
) -> Result<CfgResult, CfgError> {
    if name_or_address.trim().is_empty() {
        return Err(CfgError::EmptyQuery);
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
        script_name: CFG_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![name_or_address.to_string()],
    })
    .await?;

    let envelope: CfgEnvelope = serde_json::from_slice(&bytes).map_err(|err| CfgError::Parse {
        path: output_path,
        source: err,
    })?;

    if !envelope.resolution_error.is_empty() {
        return Err(CfgError::ResolutionFailed(envelope.resolution_error));
    }

    Ok(CfgResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        resolved_address: envelope.resolved_address,
        resolved_function_name: envelope.resolved_function_name,
        block_count: envelope.block_count,
        edge_count: envelope.edge_count,
        blocks: envelope.blocks,
        edges: envelope.edges,
        mermaid: envelope.mermaid,
    })
}
