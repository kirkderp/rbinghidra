use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, PathValidationError, ProjectManager, SEARCH_SYMBOLS_SCRIPT, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const SEARCH_SYMBOLS_SCHEMA: &str = "rbm.ghidra.search_symbols.v0";
pub const DEFAULT_OFFSET: u64 = 0;
pub const DEFAULT_LIMIT: u64 = 25;
pub const MAX_LIMIT: u64 = 1000;
const OUTPUT_PREFIX: &str = "symbols";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolEntry {
    pub name: String,
    pub address: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub namespace: String,
    pub source: String,
    pub refcount: i64,
    pub external: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SymbolsResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub offset: u64,
    pub limit: u64,
    pub total_matched: u64,
    pub error_count: u64,
    pub symbols: Vec<SymbolEntry>,
}

#[derive(Debug, Error)]
pub enum SymbolsError {
    #[error("symbol query must not be empty")]
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
        "analyzeHeadless exited successfully but the search_symbols postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("symbols output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(SymbolsError);


#[derive(Debug, Clone)]
pub struct SymbolsContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct SymbolsEnvelope {
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
    symbols: Vec<SymbolEntry>,
}

/// Search symbols in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the query is empty, the binary cannot be resolved, the
/// Ghidra script cannot run, or the symbol report cannot be read or decoded.
pub async fn search_symbols(
    ctx: &SymbolsContext,
    binary_query: &str,
    query: &str,
    offset: Option<u64>,
    limit: Option<u64>,
) -> Result<SymbolsResult, SymbolsError> {
    if query.trim().is_empty() {
        return Err(SymbolsError::EmptyQuery);
    }

    let resolved_offset = offset.unwrap_or(DEFAULT_OFFSET);
    let resolved_limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);

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
        script_name: SEARCH_SYMBOLS_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: query,
        extra_script_args: vec![
            query.to_string(),
            resolved_offset.to_string(),
            resolved_limit.to_string(),
        ],
    })
    .await?;

    let envelope: SymbolsEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| SymbolsError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(SymbolsResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        offset: envelope.offset,
        limit: envelope.limit,
        total_matched: envelope.total_matched,
        error_count: envelope.error_count,
        symbols: envelope.symbols,
    })
}
