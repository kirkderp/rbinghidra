use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    CONSTANTS_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const CONSTANTS_SCHEMA: &str = "rbm.ghidra.constants.v0";
pub const DEFAULT_LIMIT: u64 = 100;
pub const MAX_LIMIT: u64 = 1000;
const OUTPUT_PREFIX: &str = "constants";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstantLocation {
    pub address: String,
    pub function_name: String,
    pub mnemonic: String,
    pub operand_index: u64,
    pub disassembly: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstantEntry {
    pub value: String,
    pub hex_value: String,
    pub count: u64,
    pub sample_locations: Vec<ConstantLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConstantsResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub mode: String,
    pub value: String,
    pub min_value: String,
    pub max_value: String,
    pub include_small_values: bool,
    pub limit: u64,
    pub instructions_scanned: u64,
    pub total_matched: u64,
    pub truncated: bool,
    pub error_count: u64,
    pub constants: Vec<ConstantEntry>,
}

#[derive(Debug, Error)]
pub enum ConstantsError {
    #[error("constants mode must be 'uses', 'range', or 'common', got: {0}")]
    InvalidMode(String),
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
        "analyzeHeadless exited successfully but the constants postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("constants output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(ConstantsError);

#[derive(Debug, Clone)]
pub struct ConstantsContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct ConstantsEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    min_value: String,
    #[serde(default)]
    max_value: String,
    #[serde(default)]
    include_small_values: bool,
    #[serde(default)]
    limit: u64,
    #[serde(default)]
    instructions_scanned: u64,
    #[serde(default)]
    total_matched: u64,
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    error_count: u64,
    #[serde(default)]
    constants: Vec<ConstantEntry>,
}

pub async fn scan_constants(
    ctx: &ConstantsContext,
    binary_query: &str,
    mode: Option<&str>,
    value: Option<&str>,
    min_value: Option<&str>,
    max_value: Option<&str>,
    include_small_values: bool,
    limit: Option<u64>,
) -> Result<ConstantsResult, ConstantsError> {
    let resolved_mode = mode.unwrap_or("common").trim().to_ascii_lowercase();
    if !matches!(resolved_mode.as_str(), "uses" | "range" | "common") {
        return Err(ConstantsError::InvalidMode(resolved_mode));
    }
    let resolved_limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let value = value.unwrap_or("").trim();
    let min_value = min_value.unwrap_or("").trim();
    let max_value = max_value.unwrap_or("").trim();

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
        script_name: CONSTANTS_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: &format!("{resolved_mode}_{value}_{min_value}_{max_value}"),
        extra_script_args: vec![
            resolved_mode,
            value.to_string(),
            min_value.to_string(),
            max_value.to_string(),
            include_small_values.to_string(),
            resolved_limit.to_string(),
        ],
    })
    .await?;

    let envelope: ConstantsEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| ConstantsError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(ConstantsResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        mode: envelope.mode,
        value: envelope.value,
        min_value: envelope.min_value,
        max_value: envelope.max_value,
        include_small_values: envelope.include_small_values,
        limit: envelope.limit,
        instructions_scanned: envelope.instructions_scanned,
        total_matched: envelope.total_matched,
        truncated: envelope.truncated,
        error_count: envelope.error_count,
        constants: envelope.constants,
    })
}
