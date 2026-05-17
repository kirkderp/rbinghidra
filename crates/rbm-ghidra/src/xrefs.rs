use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, LIST_XREFS_SCRIPT, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const LIST_XREFS_SCHEMA: &str = "rbm.ghidra.list_xrefs.v0";
pub const DEFAULT_OFFSET: u64 = 0;
pub const DEFAULT_LIMIT: u64 = 25;
pub const MAX_LIMIT: u64 = 1000;
pub const DEFAULT_DIRECTION: &str = "to";
const OUTPUT_PREFIX: &str = "xrefs";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XrefEntry {
    pub from_address: String,
    pub to_address: String,
    pub ref_type: String,
    pub function_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct XrefsResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub direction: String,
    pub resolved_address: String,
    pub resolved_symbol_name: String,
    pub offset: u64,
    pub limit: u64,
    pub total_matched: u64,
    pub truncated: bool,
    pub error_count: u64,
    pub xrefs: Vec<XrefEntry>,
}

#[derive(Debug, Error)]
pub enum XrefsError {
    #[error("xrefs query must not be empty")]
    EmptyQuery,
    #[error("xrefs direction must be 'to' or 'from', got: {0}")]
    InvalidDirection(String),
    #[error("symbol resolution failed: {0}")]
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
        "analyzeHeadless exited successfully but the list_xrefs postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("xrefs output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(XrefsError);

#[derive(Debug, Clone)]
pub struct XrefsContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct XrefsEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    direction: String,
    #[serde(default)]
    resolved_address: String,
    #[serde(default)]
    resolved_symbol_name: String,
    #[serde(default)]
    resolution_error: String,
    #[serde(default)]
    offset: u64,
    #[serde(default)]
    limit: u64,
    #[serde(default)]
    total_matched: u64,
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    error_count: u64,
    #[serde(default)]
    xrefs: Vec<XrefEntry>,
}

#[must_use]
pub fn resolve_offset(offset: Option<u64>) -> u64 {
    offset.unwrap_or(DEFAULT_OFFSET)
}

#[must_use]
pub fn resolve_limit(limit: Option<u64>) -> u64 {
    limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT)
}

/// Resolve an optional xref direction string.
///
/// # Errors
///
/// Returns an error if the direction is not `to`, `from`, or empty.
pub fn resolve_direction(direction: Option<&str>) -> Result<&'static str, XrefsError> {
    match direction
        .unwrap_or(DEFAULT_DIRECTION)
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "to" => Ok("to"),
        "from" => Ok("from"),
        other => Err(XrefsError::InvalidDirection(other.to_string())),
    }
}

/// List xrefs to or from a function or address.
///
/// # Errors
///
/// Returns an error if the function query or direction is invalid, the binary
/// cannot be resolved, the Ghidra script cannot run, or the xref report cannot
/// be read or decoded.
pub async fn list_xrefs(
    ctx: &XrefsContext,
    binary_query: &str,
    name_or_address: &str,
    direction: Option<&str>,
    offset: Option<u64>,
    limit: Option<u64>,
) -> Result<XrefsResult, XrefsError> {
    if name_or_address.trim().is_empty() {
        return Err(XrefsError::EmptyQuery);
    }

    let resolved_offset = resolve_offset(offset);
    let resolved_limit = resolve_limit(limit);
    let resolved_direction = resolve_direction(direction)?;
    let output_key = format!("{name_or_address}_{resolved_direction}");

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
        script_name: LIST_XREFS_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: &output_key,
        extra_script_args: vec![
            name_or_address.to_string(),
            resolved_offset.to_string(),
            resolved_limit.to_string(),
            resolved_direction.to_string(),
        ],
    })
    .await?;

    let envelope: XrefsEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| XrefsError::Parse {
            path: output_path,
            source: err,
        })?;

    if !envelope.resolution_error.is_empty() {
        return Err(XrefsError::ResolutionFailed(envelope.resolution_error));
    }

    Ok(XrefsResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        direction: if envelope.direction.is_empty() {
            resolved_direction.to_string()
        } else {
            envelope.direction
        },
        resolved_address: envelope.resolved_address,
        resolved_symbol_name: envelope.resolved_symbol_name,
        offset: envelope.offset,
        limit: envelope.limit,
        total_matched: envelope.total_matched,
        truncated: envelope.truncated
            || envelope.total_matched > envelope.offset.saturating_add(envelope.limit),
        error_count: envelope.error_count,
        xrefs: envelope.xrefs,
    })
}
