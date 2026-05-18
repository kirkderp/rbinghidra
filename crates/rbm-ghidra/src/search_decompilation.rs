use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, PathValidationError, ProjectManager, SEARCH_DECOMPILATION_SCRIPT, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const SEARCH_DECOMPILATION_SCHEMA: &str = "rbm.ghidra.search_decompilation.v0";
pub const DEFAULT_LIMIT: u64 = 25;
pub const MAX_LIMIT: u64 = 200;
pub const DEFAULT_CONTEXT_LINES: u64 = 2;
pub const MAX_CONTEXT_LINES: u64 = 10;
pub const DEFAULT_MAX_FUNCTIONS: u64 = 500;
pub const MAX_MAX_FUNCTIONS: u64 = 5000;
const OUTPUT_PREFIX: &str = "decomp_search";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompilationSearchHit {
    pub function_name: String,
    pub address: String,
    pub signature: String,
    pub match_count: u64,
    pub first_line: u64,
    pub snippet: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchDecompilationResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub offset: u64,
    pub limit: u64,
    pub context_lines: u64,
    pub max_functions: u64,
    pub total_matched: u64,
    pub functions_scanned: u64,
    pub truncated: bool,
    pub error_count: u64,
    pub hits: Vec<DecompilationSearchHit>,
}

#[derive(Debug, Error)]
pub enum SearchDecompilationError {
    #[error("decompilation search query must not be empty")]
    EmptyQuery,
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
        "analyzeHeadless exited successfully but the search_decompilation postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("search_decompilation output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(SearchDecompilationError);

#[derive(Debug, Clone)]
pub struct SearchDecompilationContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct SearchDecompilationEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    offset: u64,
    #[serde(default)]
    limit: u64,
    #[serde(default)]
    context_lines: u64,
    #[serde(default)]
    total_matched: u64,
    #[serde(default)]
    functions_scanned: u64,
    #[serde(default)]
    max_functions: u64,
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    error_count: u64,
    #[serde(default)]
    hits: Vec<DecompilationSearchHit>,
}

#[must_use]
pub fn resolve_limit(limit: Option<u64>) -> u64 {
    limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT)
}

#[must_use]
pub fn resolve_context_lines(context_lines: Option<u64>) -> u64 {
    context_lines
        .unwrap_or(DEFAULT_CONTEXT_LINES)
        .min(MAX_CONTEXT_LINES)
}

#[must_use]
pub fn resolve_max_functions(max_functions: Option<u64>) -> u64 {
    max_functions
        .unwrap_or(DEFAULT_MAX_FUNCTIONS)
        .min(MAX_MAX_FUNCTIONS)
}

pub async fn search_decompilation(
    ctx: &SearchDecompilationContext,
    binary_query: &str,
    query: &str,
    offset: Option<u64>,
    limit: Option<u64>,
    context_lines: Option<u64>,
    max_functions: Option<u64>,
) -> Result<SearchDecompilationResult, SearchDecompilationError> {
    let query = query.trim();
    if query.is_empty() {
        return Err(SearchDecompilationError::EmptyQuery);
    }
    let resolved_offset = offset.unwrap_or(0);
    let resolved_limit = resolve_limit(limit);
    let resolved_context_lines = resolve_context_lines(context_lines);
    let resolved_max_functions = resolve_max_functions(max_functions);

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
        script_name: SEARCH_DECOMPILATION_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: query,
        extra_script_args: vec![
            query.to_string(),
            resolved_offset.to_string(),
            resolved_limit.to_string(),
            resolved_context_lines.to_string(),
            resolved_max_functions.to_string(),
        ],
    })
    .await?;

    let envelope: SearchDecompilationEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| SearchDecompilationError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(SearchDecompilationResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        offset: envelope.offset,
        limit: envelope.limit,
        context_lines: envelope.context_lines,
        max_functions: envelope.max_functions,
        total_matched: envelope.total_matched,
        functions_scanned: envelope.functions_scanned,
        truncated: envelope.truncated
            || envelope.total_matched > envelope.offset.saturating_add(envelope.limit),
        error_count: envelope.error_count,
        hits: envelope.hits,
    })
}
