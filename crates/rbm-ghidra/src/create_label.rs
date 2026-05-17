use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    CREATE_LABEL_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const CREATE_LABEL_SCHEMA: &str = "rbm.ghidra.create_label.v0";
const OUTPUT_PREFIX: &str = "label";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateLabelResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub address: String,
    pub label_name: String,
    pub created_symbol: String,
    pub address_error: String,
    pub label_error: String,
}

#[derive(Debug, Error)]
pub enum CreateLabelError {
    #[error("address must not be empty")]
    EmptyAddress,
    #[error("label_name must not be empty")]
    EmptyLabelName,
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
        "analyzeHeadless exited successfully but the create_label postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("create_label output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(CreateLabelError);


#[derive(Debug, Clone)]
pub struct CreateLabelContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct CreateLabelEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    label_name: String,
    #[serde(default)]
    created_symbol: String,
    #[serde(default)]
    address_error: String,
    #[serde(default)]
    label_error: String,
}

/// Create a label at an address in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the address or label name is empty, the binary cannot be
/// resolved, the Ghidra script cannot run, or the mutation report cannot be read
/// or decoded.
pub async fn create_label(
    ctx: &CreateLabelContext,
    binary_query: &str,
    address: &str,
    label_name: &str,
) -> Result<CreateLabelResult, CreateLabelError> {
    if address.trim().is_empty() {
        return Err(CreateLabelError::EmptyAddress);
    }
    if label_name.trim().is_empty() {
        return Err(CreateLabelError::EmptyLabelName);
    }

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
        script_name: CREATE_LABEL_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: address,
        extra_script_args: vec![address.to_string(), label_name.to_string()],
    })
    .await?;

    let envelope: CreateLabelEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| CreateLabelError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(CreateLabelResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        address: envelope.address,
        label_name: envelope.label_name,
        created_symbol: envelope.created_symbol,
        address_error: envelope.address_error,
        label_error: envelope.label_error,
    })
}
