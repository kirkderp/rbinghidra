use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    EQUATES_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const EQUATES_SCHEMA: &str = "rbm.ghidra.equates.v0";
const OUTPUT_PREFIX: &str = "equates";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquateReference {
    pub address: String,
    pub op_index: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquateEntry {
    pub name: String,
    pub value_hex: String,
    pub value_dec: i64,
    pub display_name: String,
    pub reference_count: u32,
    pub references: Vec<EquateReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquatesResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub offset: u64,
    pub limit: u64,
    pub total_matched: u32,
    pub truncated: bool,
    pub equates: Vec<EquateEntry>,
}

#[derive(Debug, Error)]
pub enum EquatesError {
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
        "analyzeHeadless exited successfully but the equates postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("equates output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(EquatesError);


#[derive(Debug, Clone)]
pub struct EquatesContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct EquatesEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    offset: u64,
    #[serde(default)]
    limit: u64,
    #[serde(default)]
    total_matched: u32,
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    equates: Vec<EquateEntry>,
}

/// Search equates in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the Ghidra script cannot
/// run, or the equate report cannot be read or decoded.
pub async fn get_equates(
    ctx: &EquatesContext,
    binary_query: &str,
    query: &str,
    offset: Option<u64>,
    limit: Option<u64>,
) -> Result<EquatesResult, EquatesError> {
    let resolved_offset = offset.unwrap_or(0);
    let resolved_limit = limit.unwrap_or(500).min(1000);
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
        script_name: EQUATES_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: query,
        extra_script_args: vec![
            query.to_string(),
            resolved_offset.to_string(),
            resolved_limit.to_string(),
        ],
    })
    .await?;

    let envelope: EquatesEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| EquatesError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(EquatesResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        offset: envelope.offset,
        limit: envelope.limit,
        total_matched: envelope.total_matched,
        truncated: envelope.truncated,
        equates: envelope.equates,
    })
}
