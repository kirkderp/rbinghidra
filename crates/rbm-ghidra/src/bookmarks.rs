use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    BOOKMARKS_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const BOOKMARKS_SCHEMA: &str = "rbm.ghidra.bookmarks.v0";
const OUTPUT_PREFIX: &str = "bookmarks";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookmarkEntry {
    pub id: i64,
    pub address: String,
    #[serde(rename = "type")]
    pub bookmark_type: String,
    pub category: String,
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookmarksResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub type_filter: String,
    pub total_matched: u32,
    pub bookmarks: Vec<BookmarkEntry>,
}

#[derive(Debug, Error)]
pub enum BookmarksError {
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
        "analyzeHeadless exited successfully but the bookmarks postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("bookmarks output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(BookmarksError);


#[derive(Debug, Clone)]
pub struct BookmarksContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct BookmarksEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    type_filter: String,
    #[serde(default)]
    total_matched: u32,
    #[serde(default)]
    bookmarks: Vec<BookmarkEntry>,
}

/// Return bookmarks from a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the Ghidra script cannot
/// run, or the bookmark report cannot be read or decoded.
pub async fn get_bookmarks(
    ctx: &BookmarksContext,
    binary_query: &str,
    type_filter: &str,
) -> Result<BookmarksResult, BookmarksError> {
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
        script_name: BOOKMARKS_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: type_filter,
        extra_script_args: vec![type_filter.to_string()],
    })
    .await?;

    let envelope: BookmarksEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| BookmarksError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(BookmarksResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        type_filter: envelope.type_filter,
        total_matched: envelope.total_matched,
        bookmarks: envelope.bookmarks,
    })
}
