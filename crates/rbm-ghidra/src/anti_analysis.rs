use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    ANTI_ANALYSIS_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const ANTI_ANALYSIS_SCHEMA: &str = "rbm.ghidra.anti_analysis.v0";
const OUTPUT_PREFIX: &str = "anti_analysis";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiAnalysisFinding {
    pub category: String,
    pub technique: String,
    pub address: String,
    pub function: String,
    pub severity: String,
    #[serde(default)]
    pub instruction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiAnalysisSummary {
    pub by_category: HashMap<String, u64>,
    pub by_severity: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AntiAnalysisResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub total_findings: u64,
    pub summary: AntiAnalysisSummary,
    pub findings: Vec<serde_json::Value>,
}

#[derive(Debug, Error)]
pub enum AntiAnalysisError {
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
        "analyzeHeadless exited successfully but the anti_analysis postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("anti_analysis output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(AntiAnalysisError);


#[derive(Debug, Clone)]
pub struct AntiAnalysisContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct AntiAnalysisEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    total_findings: u64,
    #[serde(default)]
    summary: EnvelopeSummary,
    #[serde(default)]
    findings: Vec<serde_json::Value>,
}

#[derive(Debug, Default, Deserialize)]
struct EnvelopeSummary {
    #[serde(default)]
    by_category: HashMap<String, u64>,
    #[serde(default)]
    by_severity: HashMap<String, u64>,
}

/// Run the anti-analysis scanner for a cached binary.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the Ghidra script cannot
/// run, or the emitted report cannot be read or decoded.
pub async fn scan_anti_analysis(
    ctx: &AntiAnalysisContext,
    binary_query: &str,
) -> Result<AntiAnalysisResult, AntiAnalysisError> {
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
        script_name: ANTI_ANALYSIS_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: "all",
        extra_script_args: vec![],
    })
    .await?;

    let envelope: AntiAnalysisEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| AntiAnalysisError::Parse {
            path: output_path,
            source: err,
        })?;

    Ok(AntiAnalysisResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        total_findings: envelope.total_findings,
        summary: AntiAnalysisSummary {
            by_category: envelope.summary.by_category,
            by_severity: envelope.summary.by_severity,
        },
        findings: envelope.findings,
    })
}
