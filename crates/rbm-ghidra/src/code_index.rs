use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::{InspectError, get_cached_metadata};
use crate::project::{
    DECOMPILE_ALL_FUNCTIONS_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathError, WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const CODE_INDEX_SCHEMA: &str = "rbm.ghidra.code_index.v0";
const OUTPUT_PREFIX: &str = "code_index";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeIndexEntry {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub pseudocode: String,
    #[serde(default)]
    pub callers: Vec<String>,
    #[serde(default)]
    pub callees: Vec<String>,
    #[serde(default)]
    pub decompile_error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeIndexEnvelope {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub program_name: String,
    #[serde(default)]
    pub program_path: String,
    #[serde(default)]
    pub function_count: u64,
    #[serde(default)]
    pub error_count: u64,
    #[serde(default)]
    pub functions: Vec<CodeIndexEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildCodeIndexResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub index_path: String,
    pub function_count: u64,
    pub error_count: u64,
}

#[derive(Debug, Error)]
pub enum CodeIndexError {
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
    #[error("analyzeHeadless exited with status {exit_code:?}; output: {output}")]
    HeadlessFailed {
        exit_code: Option<i32>,
        output: String,
    },
    #[error(
        "analyzeHeadless exited successfully but the code-index postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error(
        "code index is missing for {binary_query}; build it first with ghidra_build_code_index"
    )]
    IndexMissing { binary_query: String, path: PathBuf },
    #[error("code index at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

impl From<WarmPathError> for CodeIndexError {
    fn from(err: WarmPathError) -> Self {
        match err {
            WarmPathError::Inspect(e) => Self::Inspect(e),
            WarmPathError::LockHeld { sha256 } => Self::LockHeld { sha256 },
            WarmPathError::PathValidation(e) => Self::PathValidation(e),
            WarmPathError::ProjectFileMissing(p) => Self::ProjectFileMissing(p),
            WarmPathError::HeadlessFailed { exit_code, stderr } => {
                Self::HeadlessFailed { exit_code, output: stderr }
            }
            WarmPathError::OutputMissing { stdout, stderr } => {
                Self::OutputMissing { stdout, stderr }
            }
            WarmPathError::Headless(e) => Self::Headless(e),
            WarmPathError::Io { path, source } => Self::Io { path, source },
        }
    }
}


#[derive(Debug, Clone)]
pub struct CodeIndexContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

/// Build and cache the code index for a binary.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the Ghidra script cannot
/// run, or the generated index cannot be read, decoded, or written to cache.
pub async fn build_code_index(
    ctx: &CodeIndexContext,
    binary_query: &str,
) -> Result<BuildCodeIndexResult, CodeIndexError> {
    let WarmPathProduct {
        sha256,
        program_name,
        bytes,
        output_path: _,
    } = execute_warm_path(WarmPathRequest {
        manager: ctx.manager.as_ref(),
        analyze_headless: &ctx.analyze_headless,
        scripts_dir: &ctx.scripts_dir,
        timeout: ctx.timeout,
        binary_query,
        script_name: DECOMPILE_ALL_FUNCTIONS_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: "all",
        extra_script_args: vec![],
    })
    .await
    .map_err(map_warm_path_error)?;

    let mut envelope: CodeIndexEnvelope =
        serde_json::from_slice(&bytes).map_err(|source| CodeIndexError::Parse {
            path: PathBuf::from("<code_index_output>"),
            source,
        })?;
    envelope.schema = CODE_INDEX_SCHEMA.to_string();

    let index_path = ctx.manager.code_index_path(&sha256);
    let json = serde_json::to_vec_pretty(&envelope).map_err(|source| CodeIndexError::Parse {
        path: index_path.clone(),
        source,
    })?;
    tokio::fs::write(&index_path, &json)
        .await
        .map_err(|source| CodeIndexError::Io {
            path: index_path.clone(),
            source,
        })?;

    Ok(BuildCodeIndexResult {
        schema: CODE_INDEX_SCHEMA.to_string(),
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        index_path: index_path.display().to_string(),
        function_count: envelope.function_count,
        error_count: envelope.error_count,
    })
}

/// Read a cached code index for a binary.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved or if the index file cannot
/// be read or decoded.
pub async fn read_code_index(
    manager: &ProjectManager,
    binary_query: &str,
) -> Result<(crate::inspect::CachedBinary, CodeIndexEnvelope), CodeIndexError> {
    let cached = get_cached_metadata(manager, binary_query).await?;
    let index_path = manager.code_index_path(&cached.sha256);
    if !tokio::fs::try_exists(&index_path)
        .await
        .map_err(|source| CodeIndexError::Io {
            path: index_path.clone(),
            source,
        })?
    {
        return Err(CodeIndexError::IndexMissing {
            binary_query: binary_query.to_string(),
            path: index_path,
        });
    }

    let bytes = tokio::fs::read(&index_path)
        .await
        .map_err(|source| CodeIndexError::Io {
            path: index_path.clone(),
            source,
        })?;
    let envelope = serde_json::from_slice(&bytes).map_err(|source| CodeIndexError::Parse {
        path: index_path,
        source,
    })?;
    Ok((cached, envelope))
}

fn map_warm_path_error(err: WarmPathError) -> CodeIndexError {
    match err {
        WarmPathError::HeadlessFailed { exit_code, stderr } => CodeIndexError::HeadlessFailed {
            exit_code,
            output: stderr,
        },
        other => other.into(),
    }
}

#[must_use]
pub fn index_path_for(manager: &ProjectManager, sha256_hex: &str) -> PathBuf {
    manager.code_index_path(sha256_hex)
}

#[must_use]
pub fn is_index_present(path: &Path) -> bool {
    path.is_file()
}
