use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, PathValidationError, ProjectManager, SEARCH_BYTES_SCRIPT, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const SEARCH_BYTES_SCHEMA: &str = "rbm.ghidra.search_bytes.v0";
pub const DEFAULT_MAX_HITS: u64 = 500;
pub const MAX_HITS_CAP: u64 = 500;
const OUTPUT_PREFIX: &str = "search_bytes";

#[derive(Debug, Clone, Serialize)]
pub struct SearchBytesResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub hex_pattern: String,
    pub total_hits: u64,
    pub truncated: bool,
    pub hits: Vec<serde_json::Value>,
}

#[derive(Debug, Error)]
pub enum SearchBytesError {
    #[error(
        "invalid hex pattern '{0}': must be non-empty hex bytes; ASCII whitespace between bytes is allowed"
    )]
    InvalidHexPattern(String),
    #[error("search failed: {0}")]
    SearchFailed(String),
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
        "analyzeHeadless exited successfully but the search_bytes postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("search_bytes output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(SearchBytesError);

#[derive(Debug, Clone)]
pub struct SearchBytesContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct SearchBytesEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    hex_pattern: String,
    #[serde(default)]
    total_hits: u64,
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    hits: Vec<serde_json::Value>,
    #[serde(default)]
    error: String,
}

#[must_use]
pub fn resolve_max_hits(max_hits: Option<u64>) -> u64 {
    max_hits.unwrap_or(DEFAULT_MAX_HITS).min(MAX_HITS_CAP)
}

fn normalize_hex_pattern(hex_pattern: &str) -> Option<String> {
    let normalized: String = hex_pattern
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if normalized.is_empty()
        || !normalized.len().is_multiple_of(2)
        || !normalized.as_bytes().iter().all(|&b| b.is_ascii_hexdigit())
    {
        return None;
    }
    Some(normalized.to_ascii_lowercase())
}

/// Search for a byte pattern in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the hex pattern is invalid, the binary cannot be
/// resolved, the Ghidra script cannot run, or the search report cannot be read
/// or decoded.
pub async fn search_bytes(
    ctx: &SearchBytesContext,
    binary_query: &str,
    hex_pattern: &str,
    max_hits: Option<u64>,
) -> Result<SearchBytesResult, SearchBytesError> {
    let normalized_pattern = normalize_hex_pattern(hex_pattern)
        .ok_or_else(|| SearchBytesError::InvalidHexPattern(hex_pattern.to_string()))?;

    let resolved_max_hits = resolve_max_hits(max_hits);

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
        script_name: SEARCH_BYTES_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: &normalized_pattern,
        extra_script_args: vec![normalized_pattern.clone(), resolved_max_hits.to_string()],
    })
    .await?;

    let envelope: SearchBytesEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| SearchBytesError::Parse {
            path: output_path,
            source: err,
        })?;

    if !envelope.error.is_empty() {
        return Err(SearchBytesError::SearchFailed(envelope.error));
    }

    Ok(SearchBytesResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        hex_pattern: envelope.hex_pattern,
        total_hits: envelope.total_hits,
        truncated: envelope.truncated,
        hits: envelope.hits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_spaced_hex_patterns() {
        assert_eq!(
            normalize_hex_pattern("cf fa ed fe").as_deref(),
            Some("cffaedfe")
        );
        assert_eq!(
            normalize_hex_pattern("CF\tFA\nED FE").as_deref(),
            Some("cffaedfe")
        );
    }

    #[test]
    fn rejects_empty_or_malformed_hex_patterns() {
        assert!(normalize_hex_pattern("").is_none());
        assert!(normalize_hex_pattern("   ").is_none());
        assert!(normalize_hex_pattern("c f a").is_none());
        assert!(normalize_hex_pattern("cf zz").is_none());
    }
}
