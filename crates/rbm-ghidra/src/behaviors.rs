use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    BEHAVIORS_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const BEHAVIORS_SCHEMA: &str = "rbm.ghidra.behaviors.v0";
const OUTPUT_PREFIX: &str = "behaviors";

#[derive(Debug, Clone, Serialize)]
pub struct BehaviorsResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub total_detected: u64,
    pub severity_summary: HashMap<String, u64>,
    pub behaviors: Vec<serde_json::Value>,
}

#[derive(Debug, Error)]
pub enum BehaviorsError {
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
        "analyzeHeadless exited successfully but the behaviors postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("behaviors output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(BehaviorsError);


#[derive(Debug, Clone)]
pub struct BehaviorsContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct BehaviorsEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    total_detected: u64,
    #[serde(default)]
    severity_summary: HashMap<String, u64>,
    #[serde(default)]
    behaviors: Vec<serde_json::Value>,
}

/// Run the behavior scanner for a cached binary.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the Ghidra script cannot
/// run, or the emitted behavior report cannot be read or decoded.
pub async fn scan_behaviors(
    ctx: &BehaviorsContext,
    binary_query: &str,
) -> Result<BehaviorsResult, BehaviorsError> {
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
        script_name: BEHAVIORS_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: "all",
        extra_script_args: vec![],
    })
    .await?;

    let envelope: BehaviorsEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| BehaviorsError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(BehaviorsResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        total_detected: envelope.total_detected,
        severity_summary: envelope.severity_summary,
        behaviors: envelope.behaviors,
    })
}
