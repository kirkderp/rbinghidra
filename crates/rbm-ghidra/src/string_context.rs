use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, PathValidationError, ProjectManager, STRING_CONTEXT_SCRIPT, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const STRING_CONTEXT_SCHEMA: &str = "rbm.ghidra.string_context.v0";
pub const DEFAULT_STRING_LIMIT: u64 = 5;
pub const DEFAULT_XREF_LIMIT: u64 = 10;
pub const DEFAULT_SNIPPET_CHARS: u64 = 1200;
pub const MAX_STRING_LIMIT: u64 = 25;
pub const MAX_XREF_LIMIT: u64 = 50;
pub const MAX_SNIPPET_CHARS: u64 = 4000;
const OUTPUT_PREFIX: &str = "string_context";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringContextXref {
    pub from_address: String,
    pub ref_type: String,
    pub function_name: String,
    pub function_address: String,
    pub decompile_snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringContextEntry {
    pub address: String,
    pub value: String,
    pub length: u64,
    pub data_type: String,
    pub xref_count: u64,
    pub xrefs_returned: u64,
    pub xrefs: Vec<StringContextXref>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StringContextResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub string_limit: u64,
    pub xref_limit: u64,
    pub snippet_chars: u64,
    pub total_strings_matched: u64,
    pub truncated: bool,
    pub error_count: u64,
    pub strings: Vec<StringContextEntry>,
}

#[derive(Debug, Error)]
pub enum StringContextError {
    #[error("string context query must not be empty")]
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
        "analyzeHeadless exited successfully but the string_context postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("string_context output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(StringContextError);

#[derive(Debug, Clone)]
pub struct StringContextContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct StringContextEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    string_limit: u64,
    #[serde(default)]
    xref_limit: u64,
    #[serde(default)]
    snippet_chars: u64,
    #[serde(default)]
    total_strings_matched: u64,
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    error_count: u64,
    #[serde(default)]
    strings: Vec<StringContextEntry>,
}

pub async fn get_string_context(
    ctx: &StringContextContext,
    binary_query: &str,
    query: &str,
    string_limit: Option<u64>,
    xref_limit: Option<u64>,
    snippet_chars: Option<u64>,
) -> Result<StringContextResult, StringContextError> {
    let query = query.trim();
    if query.is_empty() {
        return Err(StringContextError::EmptyQuery);
    }
    let resolved_string_limit = string_limit
        .unwrap_or(DEFAULT_STRING_LIMIT)
        .min(MAX_STRING_LIMIT);
    let resolved_xref_limit = xref_limit.unwrap_or(DEFAULT_XREF_LIMIT).min(MAX_XREF_LIMIT);
    let resolved_snippet_chars = snippet_chars
        .unwrap_or(DEFAULT_SNIPPET_CHARS)
        .min(MAX_SNIPPET_CHARS);

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
        script_name: STRING_CONTEXT_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: query,
        extra_script_args: vec![
            query.to_string(),
            resolved_string_limit.to_string(),
            resolved_xref_limit.to_string(),
            resolved_snippet_chars.to_string(),
        ],
    })
    .await?;

    let envelope: StringContextEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| StringContextError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(StringContextResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        string_limit: envelope.string_limit,
        xref_limit: envelope.xref_limit,
        snippet_chars: envelope.snippet_chars,
        total_strings_matched: envelope.total_strings_matched,
        truncated: envelope.truncated,
        error_count: envelope.error_count,
        strings: envelope.strings,
    })
}
