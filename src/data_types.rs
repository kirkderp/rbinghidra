use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    DATA_TYPES_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const DATA_TYPES_SCHEMA: &str = "rbm.ghidra.data_types.v0";
const OUTPUT_PREFIX: &str = "dtypes";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeEntry {
    pub name: String,
    pub path: String,
    pub category: String,
    pub kind: String,
    pub size: i32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypesResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub offset: u64,
    pub limit: u64,
    pub total_matched: u32,
    pub truncated: bool,
    pub data_types: Vec<DataTypeEntry>,
}

#[derive(Debug, Error)]
pub enum DataTypesError {
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
        "analyzeHeadless exited successfully but the data_types postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("data_types output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(DataTypesError);

#[derive(Debug, Clone)]
pub struct DataTypesContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct DataTypesEnvelope {
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
    data_types: Vec<DataTypeEntry>,
}

/// Search data types in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the Ghidra script cannot
/// run, or the data-type report cannot be read or decoded.
pub async fn get_data_types(
    ctx: &DataTypesContext,
    binary_query: &str,
    query: &str,
    offset: Option<u64>,
    limit: Option<u64>,
) -> Result<DataTypesResult, DataTypesError> {
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
        script_name: DATA_TYPES_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: query,
        extra_script_args: vec![
            query.to_string(),
            resolved_offset.to_string(),
            resolved_limit.to_string(),
        ],
    })
    .await?;

    let envelope: DataTypesEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| DataTypesError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(DataTypesResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        offset: envelope.offset,
        limit: envelope.limit,
        total_matched: envelope.total_matched,
        truncated: envelope.truncated,
        data_types: envelope.data_types,
    })
}
