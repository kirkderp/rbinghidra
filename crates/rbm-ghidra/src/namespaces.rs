use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{HeadlessError, PathValidationError, ProjectManager, cache_key};

pub const LIST_NAMESPACES_SCRIPT: &str = "list_namespaces.java";
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const NAMESPACES_SCHEMA: &str = "rbm.ghidra.list_namespaces.v0";
const OUTPUT_PREFIX: &str = "namespaces";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceEntry {
    pub name: String,
    pub full_name: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub member_count: u64,
    pub parent: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NamespacesResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub total_namespaces: u64,
    pub namespaces: Vec<serde_json::Value>,
}

#[derive(Debug, Error)]
pub enum NamespacesError {
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
        "analyzeHeadless exited successfully but the list_namespaces postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("list_namespaces output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(NamespacesError);

#[derive(Debug, Clone)]
pub struct NamespacesContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct NamespacesEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    total_namespaces: u64,
    #[serde(default)]
    namespaces: Vec<serde_json::Value>,
}

/// List namespaces from a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the Ghidra script cannot
/// run, or the namespace report cannot be read or decoded.
pub async fn list_namespaces(
    ctx: &NamespacesContext,
    binary_query: &str,
) -> Result<NamespacesResult, NamespacesError> {
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
        script_name: LIST_NAMESPACES_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: "all",
        extra_script_args: vec![],
    })
    .await?;

    let envelope: NamespacesEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| NamespacesError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(NamespacesResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        total_namespaces: envelope.total_namespaces,
        namespaces: envelope.namespaces,
    })
}
