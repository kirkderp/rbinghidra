use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, PathValidationError, ProjectManager, SET_BOOKMARK_SCRIPT, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const SET_BOOKMARK_SCHEMA: &str = "rbm.ghidra.set_bookmark.v0";
const OUTPUT_PREFIX: &str = "setbookmark";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetBookmarkResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub address: String,
    pub bookmark_type: String,
    pub category: String,
    pub comment: String,
    pub created_id: i64,
    pub address_error: String,
    pub bookmark_error: String,
}

#[derive(Debug, Error)]
pub enum SetBookmarkError {
    #[error("address must not be empty")]
    EmptyAddress,
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
        "analyzeHeadless exited successfully but the set_bookmark postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("set_bookmark output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(SetBookmarkError);


#[derive(Debug, Clone)]
pub struct SetBookmarkContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct SetBookmarkEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    bookmark_type: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    comment: String,
    #[serde(default = "default_created_id")]
    created_id: i64,
    #[serde(default)]
    address_error: String,
    #[serde(default)]
    bookmark_error: String,
}

const fn default_created_id() -> i64 {
    -1
}

/// Set a bookmark at an address in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if required bookmark fields are empty, the binary cannot be
/// resolved, the Ghidra script cannot run, or the mutation report cannot be read
/// or decoded.
pub async fn set_bookmark(
    ctx: &SetBookmarkContext,
    binary_query: &str,
    address: &str,
    bookmark_type: &str,
    category: &str,
    comment: &str,
) -> Result<SetBookmarkResult, SetBookmarkError> {
    if address.trim().is_empty() {
        return Err(SetBookmarkError::EmptyAddress);
    }

    let normalized_type = if bookmark_type.trim().is_empty() {
        "Note".to_string()
    } else {
        bookmark_type.to_string()
    };

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
        script_name: SET_BOOKMARK_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: address,
        extra_script_args: vec![
            address.to_string(),
            normalized_type,
            category.to_string(),
            comment.to_string(),
        ],
    })
    .await?;

    let envelope: SetBookmarkEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| SetBookmarkError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(SetBookmarkResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        address: envelope.address,
        bookmark_type: envelope.bookmark_type,
        category: envelope.category,
        comment: envelope.comment,
        created_id: envelope.created_id,
        address_error: envelope.address_error,
        bookmark_error: envelope.bookmark_error,
    })
}
