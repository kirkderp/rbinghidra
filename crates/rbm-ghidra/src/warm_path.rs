use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::inspect::{InspectError, get_cached_metadata};
use crate::project::{
    HeadlessError, HeadlessRunner, PathValidationError, ProcessSpec, ProjectManager,
    stage_script_for_headless, validate_ghidra_environment,
};

#[derive(Debug, Error)]
pub enum ProjectDiscoveryError {
    #[error("ghidra project directory has no .gpr file: {0}")]
    ProjectFileMissing(PathBuf),
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Error)]
pub enum WarmPathError {
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
        "analyzeHeadless exited successfully but the postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
}

impl From<ProjectDiscoveryError> for WarmPathError {
    fn from(err: ProjectDiscoveryError) -> Self {
        match err {
            ProjectDiscoveryError::Io { path, source } => Self::Io { path, source },
            ProjectDiscoveryError::ProjectFileMissing(p) => Self::ProjectFileMissing(p),
        }
    }
}

/// Discover the Ghidra project name inside a cached project directory.
///
/// # Errors
///
/// Returns an error if the project directory cannot be read or no Ghidra project
/// file is present.
pub async fn discover_project_name(project_dir: &Path) -> Result<String, ProjectDiscoveryError> {
    let mut entries =
        tokio::fs::read_dir(project_dir)
            .await
            .map_err(|e| ProjectDiscoveryError::Io {
                path: project_dir.to_path_buf(),
                source: e,
            })?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| ProjectDiscoveryError::Io {
            path: project_dir.to_path_buf(),
            source: e,
        })?
    {
        if let Some(stem) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_suffix(".gpr"))
        {
            return Ok(stem.to_string());
        }
    }
    Err(ProjectDiscoveryError::ProjectFileMissing(
        project_dir.to_path_buf(),
    ))
}

pub async fn discover_program_name(project_dir: &Path, preferred: &str) -> String {
    let idata_index = project_dir
        .join(format!("{preferred}.rep"))
        .join("idata")
        .join("~index.dat");
    let Ok(bytes) = tokio::fs::read(&idata_index).await else {
        return preferred.to_string();
    };
    let text = String::from_utf8_lossy(&bytes);

    let mut first_match: Option<&str> = None;
    let mut prefix_match: Option<&str> = None;

    for name in text.lines().filter_map(index_line_program_name) {
        if name == preferred {
            // Early return for exact match
            return preferred.to_string();
        }
        if prefix_match.is_none() && name.starts_with(preferred) {
            prefix_match = Some(name);
        }
        if first_match.is_none() {
            first_match = Some(name);
        }
    }

    if let Some(name) = prefix_match {
        return name.to_string();
    }

    first_match.unwrap_or(preferred).to_string()
}

fn index_line_program_name(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let (id, rest) = trimmed.split_once(':')?;
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let (name, _) = rest.rsplit_once(':')?;
    if name.is_empty() { None } else { Some(name) }
}

#[must_use]
pub fn extract_gpr_stem(entries: &[String]) -> Option<String> {
    entries.iter().find_map(|name| {
        name.strip_suffix(".gpr")
            .map(std::string::ToString::to_string)
    })
}

#[must_use]
pub fn per_call_output_path(project_dir: &Path, prefix: &str, query: &str) -> PathBuf {
    let sanitized = sanitize_query_for_filename(query);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    project_dir.join(format!("{prefix}_{sanitized}_{stamp}.json"))
}

#[must_use]
pub fn sanitize_query_for_filename(query: &str) -> Cow<'_, str> {
    if query.is_empty() {
        return Cow::Borrowed("query");
    }

    // Fast-path performance optimization: check if we need to sanitize first.
    // This avoids unnecessary string allocation for already-safe queries.
    let bytes = query.as_bytes();
    let mut needs_sanitize = false;
    for &b in bytes {
        if !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.') {
            needs_sanitize = true;
            break;
        }
    }

    if !needs_sanitize {
        return Cow::Borrowed(query);
    }

    let mut cleaned = String::with_capacity(query.len());
    for c in query.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
            cleaned.push(c);
        } else {
            cleaned.push('_');
        }
    }
    Cow::Owned(cleaned)
}

pub async fn cleanup_output(path: &Path) {
    if let Err(err) = tokio::fs::remove_file(path).await
        && err.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            path = %path.display(),
            error = %err,
            "ghidra: best-effort cleanup of per-call output failed"
        );
    }
}

#[derive(Debug)]
pub struct WarmPathRequest<'a> {
    pub manager: &'a ProjectManager,
    pub analyze_headless: &'a Path,
    pub scripts_dir: &'a Path,
    pub timeout: Duration,
    pub binary_query: &'a str,
    pub script_name: &'a str,
    pub output_prefix: &'a str,
    pub output_key: &'a str,
    pub extra_script_args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WarmPathProduct {
    pub sha256: String,
    pub program_name: String,
    pub bytes: Vec<u8>,
    pub output_path: PathBuf,
}

/// Validate, run, and read a warm-path Ghidra script product.
///
/// # Errors
///
/// Returns an error if the Ghidra environment is invalid, the binary cannot be
/// resolved, the project lock cannot be acquired before timeout, headless
/// execution fails, or the expected output file cannot be found or read.
pub async fn execute_warm_path(req: WarmPathRequest<'_>) -> Result<WarmPathProduct, WarmPathError> {
    validate_ghidra_environment(req.scripts_dir, req.script_name, req.analyze_headless).await?;
    let runtime_scripts_dir = req.manager.runtime_scripts_dir();
    stage_script_for_headless(&runtime_scripts_dir, req.scripts_dir, req.script_name).await?;

    let cached = get_cached_metadata(req.manager, req.binary_query).await?;
    let sha256_hex = cached.sha256.clone();
    let project_dir = req.manager.project_dir(&sha256_hex);

    let lock = req.manager.lock_for(&sha256_hex);
    let _guard = tokio::time::timeout(req.timeout, lock.lock_owned())
        .await
        .map_err(|_| WarmPathError::LockHeld {
            sha256: sha256_hex.clone(),
        })?;
    // Check if the project directory still exists after acquiring the lock,
    // in case it was deleted while we were waiting.
    if !tokio::fs::try_exists(&project_dir).await.unwrap_or(false) {
        return Err(InspectError::NotFound(req.binary_query.to_string()).into());
    }

    let project_name = discover_project_name(&project_dir).await?;
    let program_name = discover_program_name(&project_dir, &project_name).await;
    let output_path = per_call_output_path(&project_dir, req.output_prefix, req.output_key);

    let mut script_args = Vec::with_capacity(1 + req.extra_script_args.len());
    script_args.push(output_path.display().to_string());
    script_args.extend(req.extra_script_args);

    let spec = ProcessSpec {
        project_dir: project_dir.clone(),
        project_name: project_name.clone(),
        program_name,
        script_dir: runtime_scripts_dir,
        script_name: req.script_name.to_string(),
        script_args,
    };
    let runner = HeadlessRunner {
        analyze_headless: req.analyze_headless.to_path_buf(),
        timeout: req.timeout,
    };

    let mut outcome = runner.run_process(&spec).await?;
    if !outcome.success && is_project_lock_failure(&outcome.stdout, &outcome.stderr) {
        for delay_ms in [250_u64, 500, 1000, 2000] {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            outcome = runner.run_process(&spec).await?;
            if outcome.success || !is_project_lock_failure(&outcome.stdout, &outcome.stderr) {
                break;
            }
        }
    }
    if !outcome.success {
        cleanup_output(&output_path).await;
        return Err(WarmPathError::HeadlessFailed {
            exit_code: outcome.exit_code,
            stderr: combine_headless_output(&outcome.stdout, &outcome.stderr),
        });
    }

    let bytes_result = tokio::fs::read(&output_path).await;
    cleanup_output(&output_path).await;
    let bytes = match bytes_result {
        Ok(b) => b,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(WarmPathError::OutputMissing {
                stdout: outcome.stdout,
                stderr: outcome.stderr,
            });
        }
        Err(err) => {
            return Err(WarmPathError::Io {
                path: output_path,
                source: err,
            });
        }
    };

    Ok(WarmPathProduct {
        sha256: sha256_hex,
        program_name: cached.program_name,
        bytes,
        output_path,
    })
}

fn combine_headless_output(stdout: &str, stderr: &str) -> String {
    let stdout = stdout.trim();
    let stderr = stderr.trim();
    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (true, false) => stderr.to_string(),
        (false, true) => stdout.to_string(),
        (false, false) => format!("stdout: {stdout}\nstderr: {stderr}"),
    }
}

fn is_project_lock_failure(stdout: &str, stderr: &str) -> bool {
    stdout.contains("LockException: Unable to lock project")
        || stderr.contains("LockException: Unable to lock project")
}
