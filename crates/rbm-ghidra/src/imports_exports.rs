use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, LIST_EXPORTS_SCRIPT, LIST_IMPORTS_SCRIPT, PathValidationError, ProjectManager,
    cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const LIST_EXPORTS_SCHEMA: &str = "rbm.ghidra.list_exports.v0";
pub const LIST_IMPORTS_SCHEMA: &str = "rbm.ghidra.list_imports.v0";
pub const DEFAULT_QUERY: &str = ".*";
pub const DEFAULT_OFFSET: u64 = 0;
pub const DEFAULT_LIMIT: u64 = 25;
pub const MAX_LIMIT: u64 = 1000;

const EXPORTS_OUTPUT_PREFIX: &str = "exports";
const IMPORTS_OUTPUT_PREFIX: &str = "imports";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportEntry {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportEntry {
    pub name: String,
    pub address: String,
    pub library: String,
    #[serde(default)]
    pub xref_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportsResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub offset: u64,
    pub limit: u64,
    pub total_matched: u64,
    pub truncated: bool,
    pub error_count: u64,
    pub exports: Vec<ExportEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportsResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub offset: u64,
    pub limit: u64,
    pub total_matched: u64,
    pub truncated: bool,
    pub error_count: u64,
    pub imports: Vec<ImportEntry>,
}

#[derive(Debug, Error)]
pub enum ImportsExportsError {
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
        "analyzeHeadless exited successfully but the postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("postScript output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(ImportsExportsError);

#[derive(Debug, Clone)]
pub struct ImportsExportsContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct ExportsEnvelope {
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
    truncated: bool,
    #[serde(default)]
    error_count: u64,
    #[serde(default)]
    exports: Vec<ExportEntry>,
}

#[derive(Debug, Deserialize)]
struct ImportsEnvelope {
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
    truncated: bool,
    #[serde(default)]
    error_count: u64,
    #[serde(default)]
    imports: Vec<ImportEntry>,
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

/// List exports from a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the Ghidra script cannot
/// run, or the exports report cannot be read or decoded.
pub async fn list_exports(
    ctx: &ImportsExportsContext,
    binary_query: &str,
    query: Option<&str>,
    offset: Option<u64>,
    limit: Option<u64>,
) -> Result<ExportsResult, ImportsExportsError> {
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
        script_name: LIST_EXPORTS_SCRIPT,
        output_prefix: EXPORTS_OUTPUT_PREFIX,
        output_key: &resolved_query,
        extra_script_args: vec![
            resolved_query.clone(),
            resolved_offset.to_string(),
            resolved_limit.to_string(),
        ],
    })
    .await?;

    let envelope: ExportsEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| ImportsExportsError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(ExportsResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        offset: envelope.offset,
        limit: envelope.limit,
        total_matched: envelope.total_matched,
        truncated: envelope.truncated
            || envelope.total_matched > envelope.offset.saturating_add(envelope.limit),
        error_count: envelope.error_count,
        exports: envelope.exports,
    })
}

/// List imports from a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the Ghidra script cannot
/// run, or the imports report cannot be read or decoded.
pub async fn list_imports(
    ctx: &ImportsExportsContext,
    binary_query: &str,
    query: Option<&str>,
    offset: Option<u64>,
    limit: Option<u64>,
) -> Result<ImportsResult, ImportsExportsError> {
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
        script_name: LIST_IMPORTS_SCRIPT,
        output_prefix: IMPORTS_OUTPUT_PREFIX,
        output_key: &resolved_query,
        extra_script_args: vec![
            resolved_query.clone(),
            resolved_offset.to_string(),
            resolved_limit.to_string(),
        ],
    })
    .await?;

    let envelope: ImportsEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| ImportsExportsError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(ImportsResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        offset: envelope.offset,
        limit: envelope.limit,
        total_matched: envelope.total_matched,
        truncated: envelope.truncated
            || envelope.total_matched > envelope.offset.saturating_add(envelope.limit),
        error_count: envelope.error_count,
        imports: envelope.imports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_limit() {
        // None returns DEFAULT_LIMIT
        assert_eq!(resolve_limit(None), DEFAULT_LIMIT);

        // Some(value < MAX_LIMIT) returns value
        assert_eq!(resolve_limit(Some(50)), 50);

        // Some(MAX_LIMIT) returns MAX_LIMIT
        assert_eq!(resolve_limit(Some(MAX_LIMIT)), MAX_LIMIT);

        // Some(value > MAX_LIMIT) returns MAX_LIMIT
        assert_eq!(resolve_limit(Some(2000)), MAX_LIMIT);
    }
}
