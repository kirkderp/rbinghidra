use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, PathValidationError, ProjectManager, SEARCH_STRINGS_SCRIPT, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const SEARCH_STRINGS_SCHEMA: &str = "rbm.ghidra.search_strings.v0";
pub const DEFAULT_QUERY: &str = ".*";
pub const DEFAULT_OFFSET: u64 = 0;
pub const DEFAULT_LIMIT: u64 = 25;
pub const MAX_LIMIT: u64 = 1000;
const OUTPUT_PREFIX: &str = "strings";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringEntry {
    pub address: String,
    pub value: String,
    pub length: u64,
    pub data_type: String,
    #[serde(default)]
    pub xref_count: u64,
    #[serde(default)]
    pub containing_function: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchStringsResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub offset: u64,
    pub limit: u64,
    pub total_matched: u64,
    pub error_count: u64,
    pub strings: Vec<StringEntry>,
}

#[derive(Debug, Error)]
pub enum SearchStringsError {
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
        "analyzeHeadless exited successfully but the search_strings postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("search_strings output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(SearchStringsError);


#[derive(Debug, Clone)]
pub struct SearchStringsContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct SearchStringsEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    offset: u64,
    #[serde(default)]
    limit: u64,
    #[serde(default)]
    total_matched: u64,
    #[serde(default)]
    error_count: u64,
    #[serde(default)]
    strings: Vec<StringEntry>,
}

#[must_use]
pub fn resolve_query(query: Option<&str>) -> String {
    match query {
        Some(q) if !q.is_empty() => q.to_string(),
        _ => DEFAULT_QUERY.to_string(),
    }
}

#[must_use]
pub fn resolve_offset(offset: Option<u64>) -> u64 {
    offset.unwrap_or(DEFAULT_OFFSET)
}

#[must_use]
pub fn resolve_limit(limit: Option<u64>) -> u64 {
    limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT)
}

/// Search strings in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the Ghidra script cannot
/// run, or the string report cannot be read or decoded.
pub async fn search_strings(
    ctx: &SearchStringsContext,
    binary_query: &str,
    query: Option<&str>,
    offset: Option<u64>,
    limit: Option<u64>,
) -> Result<SearchStringsResult, SearchStringsError> {
    let resolved_query = resolve_query(query);
    let resolved_offset = resolve_offset(offset);
    let resolved_limit = resolve_limit(limit);

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
        script_name: SEARCH_STRINGS_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: &resolved_query,
        extra_script_args: vec![
            resolved_query.clone(),
            resolved_offset.to_string(),
            resolved_limit.to_string(),
        ],
    })
    .await?;

    let envelope: SearchStringsEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| SearchStringsError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(SearchStringsResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        offset: envelope.offset,
        limit: envelope.limit,
        total_matched: envelope.total_matched,
        error_count: envelope.error_count,
        strings: envelope.strings,
    })
}
