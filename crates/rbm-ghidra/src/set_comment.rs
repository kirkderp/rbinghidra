use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    HeadlessError, PathValidationError, ProjectManager, SET_COMMENT_SCRIPT, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const SET_COMMENT_SCHEMA: &str = "rbm.ghidra.set_comment.v0";
const OUTPUT_PREFIX: &str = "comment";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetCommentResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub address: String,
    pub comment_type: String,
    pub comment: String,
    pub address_error: String,
    pub comment_error: String,
}

#[derive(Debug, Error)]
pub enum SetCommentError {
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
        "analyzeHeadless exited successfully but the set_comment postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("set_comment output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(SetCommentError);


#[derive(Debug, Clone)]
pub struct SetCommentContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct SetCommentEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    comment_type: String,
    #[serde(default)]
    comment: String,
    #[serde(default)]
    address_error: String,
    #[serde(default)]
    comment_error: String,
}

/// Set a comment at an address in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the address, comment, or comment type is invalid, the
/// binary cannot be resolved, the Ghidra script cannot run, or the mutation
/// report cannot be read or decoded.
pub async fn set_comment(
    ctx: &SetCommentContext,
    binary_query: &str,
    address: &str,
    comment: &str,
    comment_type: &str,
) -> Result<SetCommentResult, SetCommentError> {
    if address.trim().is_empty() {
        return Err(SetCommentError::EmptyAddress);
    }

    let normalized_type = if comment_type.trim().is_empty() {
        "PLATE".to_string()
    } else {
        comment_type.to_uppercase()
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
        script_name: SET_COMMENT_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: address,
        extra_script_args: vec![address.to_string(), comment.to_string(), normalized_type],
    })
    .await?;

    let envelope: SetCommentEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| SetCommentError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(SetCommentResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        address: envelope.address,
        comment_type: envelope.comment_type,
        comment: envelope.comment,
        address_error: envelope.address_error,
        comment_error: envelope.comment_error,
    })
}
