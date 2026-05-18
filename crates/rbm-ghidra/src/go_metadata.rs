use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    GO_METADATA_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const GO_METADATA_SCHEMA: &str = "rbm.ghidra.go_metadata.v0";
pub const DEFAULT_LIMIT: u64 = 100;
pub const MAX_LIMIT: u64 = 1000;
const OUTPUT_PREFIX: &str = "go_metadata";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoStringHit {
    pub address: String,
    pub value: String,
    pub xref_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoFunctionHit {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GoMetadataResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub likely_go: bool,
    pub limit: u64,
    pub go_versions: Vec<GoStringHit>,
    pub module_paths: Vec<GoStringHit>,
    pub package_strings: Vec<GoStringHit>,
    pub runtime_functions: Vec<GoFunctionHit>,
    pub main_candidates: Vec<GoFunctionHit>,
    pub total_strings_scanned: u64,
    pub total_functions_scanned: u64,
    pub error_count: u64,
}

#[derive(Debug, Error)]
pub enum GoMetadataError {
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
        "analyzeHeadless exited successfully but the go_metadata postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("go_metadata output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

from_warm_path!(GoMetadataError);

#[derive(Debug, Clone)]
pub struct GoMetadataContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct GoMetadataEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    likely_go: bool,
    #[serde(default)]
    limit: u64,
    #[serde(default)]
    go_versions: Vec<GoStringHit>,
    #[serde(default)]
    module_paths: Vec<GoStringHit>,
    #[serde(default)]
    package_strings: Vec<GoStringHit>,
    #[serde(default)]
    runtime_functions: Vec<GoFunctionHit>,
    #[serde(default)]
    main_candidates: Vec<GoFunctionHit>,
    #[serde(default)]
    total_strings_scanned: u64,
    #[serde(default)]
    total_functions_scanned: u64,
    #[serde(default)]
    error_count: u64,
}

/// Extract heuristic Go build, package, and runtime indicators from a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the Ghidra script cannot
/// run, or the Go metadata report cannot be read or decoded.
pub async fn get_go_metadata(
    ctx: &GoMetadataContext,
    binary_query: &str,
    limit: Option<u64>,
) -> Result<GoMetadataResult, GoMetadataError> {
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
        script_name: GO_METADATA_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: "go",
        extra_script_args: vec![resolved_limit.to_string()],
    })
    .await?;

    let envelope: GoMetadataEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| GoMetadataError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(GoMetadataResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        likely_go: envelope.likely_go,
        limit: envelope.limit,
        go_versions: envelope.go_versions,
        module_paths: envelope.module_paths,
        package_strings: envelope.package_strings,
        runtime_functions: envelope.runtime_functions,
        main_candidates: envelope.main_candidates,
        total_strings_scanned: envelope.total_strings_scanned,
        total_functions_scanned: envelope.total_functions_scanned,
        error_count: envelope.error_count,
    })
}
