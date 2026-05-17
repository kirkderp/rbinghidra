use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::OwnedMutexGuard;

use crate::project::{
    EXTRACT_FUNCTIONS_SCRIPT, HeadlessOutcome, HeadlessRunner, IMPORT_ERROR_FILE, ImportSpec,
    PathValidationError, ProjectError, ProjectManager, cache_key, estimate_eta_ms, hash_file,
    project_name_for, stage_script_for_headless, validate_ghidra_environment,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportReport {
    pub status: String,
    pub cache_key: String,
    pub binary_name: String,
    pub project_dir: String,
    pub output_path: String,
    pub eta_ms: u64,
    pub started: bool,
    pub next_action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExtractFunctionsEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    program_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ImportFailureEnvelope {
    schema: String,
    error: String,
    exit_code: Option<i32>,
    stderr: String,
    stdout: String,
}

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("binary path is empty")]
    EmptyPath,
    #[error("binary path does not exist or is not a regular file: {0}")]
    BinaryMissing(PathBuf),
    #[error(transparent)]
    PathValidation(#[from] PathValidationError),
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Project(#[from] ProjectError),
}

impl ImportError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImportContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportOptions {
    pub loader: Option<String>,
    pub processor: Option<String>,
    pub cspec: Option<String>,
    pub loader_base_addr: Option<String>,
}

impl ImportOptions {
    fn has_explicit_loader_options(&self) -> bool {
        self.loader.as_ref().is_some_and(|s| !s.trim().is_empty())
            || self
                .processor
                .as_ref()
                .is_some_and(|s| !s.trim().is_empty())
            || self.cspec.as_ref().is_some_and(|s| !s.trim().is_empty())
            || self
                .loader_base_addr
                .as_ref()
                .is_some_and(|s| !s.trim().is_empty())
    }
}

impl ImportReport {
    fn analyzing(
        key: String,
        binary_name: String,
        project_dir: &Path,
        output_path: &Path,
        eta_ms: u64,
        started: bool,
    ) -> Self {
        Self {
            status: "analyzing".to_string(),
            cache_key: key,
            binary_name,
            project_dir: project_dir.display().to_string(),
            output_path: output_path.display().to_string(),
            eta_ms,
            started,
            next_action: "Call ghidra_import again with the same binary_path until status is ready; then use cache_key or binary_name with RE tools.".to_string(),
            error: None,
        }
    }

    fn ready(key: String, binary_name: String, project_dir: &Path, output_path: &Path) -> Self {
        Self {
            status: "ready".to_string(),
            cache_key: key,
            binary_name,
            project_dir: project_dir.display().to_string(),
            output_path: output_path.display().to_string(),
            eta_ms: 0,
            started: false,
            next_action: "Use cache_key or binary_name with RE tools.".to_string(),
            error: None,
        }
    }

    fn failed(
        key: String,
        binary_name: String,
        project_dir: &Path,
        output_path: &Path,
        error: String,
    ) -> Self {
        Self {
            status: "failed".to_string(),
            cache_key: key,
            binary_name,
            project_dir: project_dir.display().to_string(),
            output_path: output_path.display().to_string(),
            eta_ms: 0,
            started: false,
            next_action: "Import failed. Use ghidra_import with explicit loader/processor options for raw data, or choose a recognized executable format.".to_string(),
            error: Some(error),
        }
    }
}

/// Import a binary into the Ghidra project cache with default options.
///
/// # Errors
///
/// Returns an error if the binary path or Ghidra environment is invalid, import
/// execution fails, or metadata cannot be written.
pub async fn import_binary(
    ctx: &ImportContext,
    binary_path: &Path,
) -> Result<ImportReport, ImportError> {
    import_binary_with_options(ctx, binary_path, &ImportOptions::default()).await
}

/// Import a binary into the Ghidra project cache with explicit loader options.
///
/// # Errors
///
/// Returns an error if the binary path, loader options, or Ghidra environment is
/// invalid, import execution fails, or metadata cannot be written.
pub async fn import_binary_with_options(
    ctx: &ImportContext,
    binary_path: &Path,
    options: &ImportOptions,
) -> Result<ImportReport, ImportError> {
    if binary_path.as_os_str().is_empty() {
        return Err(ImportError::EmptyPath);
    }

    validate_paths(ctx, binary_path).await?;

    let metadata = tokio::fs::metadata(binary_path)
        .await
        .map_err(|e| ImportError::io(binary_path, e))?;
    let file_size = metadata.len();

    let sha256_hex = hash_file(binary_path).await?;
    let project_dir = ctx.manager.project_dir(&sha256_hex);
    let output_path = ctx.manager.output_path(&sha256_hex);
    let error_path = project_dir.join(IMPORT_ERROR_FILE);
    let key = cache_key(&sha256_hex);
    let binary_name = binary_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
        .to_string();

    if cached_output_is_ready(&output_path).await? {
        let lock = ctx.manager.lock_for(&sha256_hex);
        if lock.try_lock_owned().is_err() {
            return Ok(ImportReport::analyzing(
                key,
                binary_name,
                &project_dir,
                &output_path,
                estimate_eta_ms(file_size),
                false,
            ));
        }
        return Ok(ImportReport::ready(
            key,
            binary_name,
            &project_dir,
            &output_path,
        ));
    }

    if !options.has_explicit_loader_options() {
        if let Some(failure) = read_import_failure(&error_path).await? {
            return Ok(ImportReport::failed(
                key,
                binary_name,
                &project_dir,
                &output_path,
                failure.error,
            ));
        }
    }
    remove_stale_output(&output_path).await?;
    remove_import_failure(&error_path).await?;

    tokio::fs::create_dir_all(&project_dir)
        .await
        .map_err(|e| ImportError::io(&project_dir, e))?;

    let estimate = estimate_eta_ms(file_size);
    let lock = ctx.manager.lock_for(&sha256_hex);

    match lock.try_lock_owned() {
        Err(_) => Ok(ImportReport::analyzing(
            key,
            binary_name,
            &project_dir,
            &output_path,
            estimate,
            false,
        )),
        Ok(guard) => {
            // Re-check after lock acquisition: a concurrent task may have just
            // released the lock between the existence check above and this
            // try_lock_owned() succeeding. Without this re-check we would
            // spawn a wasted analyzeHeadless run on the already-cached project.
            if cached_output_is_ready(&output_path).await? {
                drop(guard);
                return Ok(ImportReport::ready(
                    key,
                    binary_name,
                    &project_dir,
                    &output_path,
                ));
            }
            remove_stale_output(&output_path).await?;
            remove_import_failure(&error_path).await?;
            let runtime_scripts_dir = ctx.manager.runtime_scripts_dir();
            stage_script_for_headless(
                &runtime_scripts_dir,
                &ctx.scripts_dir,
                EXTRACT_FUNCTIONS_SCRIPT,
            )
            .await?;
            let spec = ImportSpec {
                project_dir: project_dir.clone(),
                project_name: project_name_for(binary_path),
                binary: binary_path.to_path_buf(),
                loader: options.loader.clone(),
                processor: options.processor.clone(),
                cspec: options.cspec.clone(),
                loader_base_addr: options.loader_base_addr.clone(),
                script_dir: runtime_scripts_dir,
                script_name: EXTRACT_FUNCTIONS_SCRIPT.to_string(),
                script_args: vec![output_path.display().to_string()],
            };
            let runner = HeadlessRunner {
                analyze_headless: ctx.analyze_headless.clone(),
                timeout: ctx.timeout,
            };
            spawn_import_task(guard, runner, spec, output_path.clone(), error_path);
            Ok(ImportReport::analyzing(
                key,
                binary_name,
                &project_dir,
                &output_path,
                estimate,
                true,
            ))
        }
    }
}

async fn cached_output_is_ready(output_path: &Path) -> Result<bool, ImportError> {
    match tokio::fs::read(output_path).await {
        Ok(bytes) => {
            let Ok(envelope) = serde_json::from_slice::<ExtractFunctionsEnvelope>(&bytes) else {
                return Ok(false);
            };
            Ok(envelope.schema == "rbm.ghidra.extract_functions.v0"
                && !envelope.program_name.is_empty())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(ImportError::io(output_path, err)),
    }
}

async fn remove_stale_output(output_path: &Path) -> Result<(), ImportError> {
    match tokio::fs::remove_file(output_path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(ImportError::io(output_path, err)),
    }
}

async fn read_import_failure(
    error_path: &Path,
) -> Result<Option<ImportFailureEnvelope>, ImportError> {
    match tokio::fs::read(error_path).await {
        Ok(bytes) => match serde_json::from_slice::<ImportFailureEnvelope>(&bytes) {
            Ok(envelope) if envelope.schema == "rbm.ghidra.import_failure.v0" => Ok(Some(envelope)),
            _ => Ok(None),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(ImportError::io(error_path, err)),
    }
}

async fn remove_import_failure(error_path: &Path) -> Result<(), ImportError> {
    match tokio::fs::remove_file(error_path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(ImportError::io(error_path, err)),
    }
}

async fn write_import_failure(
    error_path: &Path,
    error: String,
    outcome: Option<&HeadlessOutcome>,
) -> Result<(), ImportError> {
    let envelope = ImportFailureEnvelope {
        schema: "rbm.ghidra.import_failure.v0".to_string(),
        error,
        exit_code: outcome.and_then(|o| o.exit_code),
        stderr: outcome.map_or_else(String::new, |o| o.stderr.clone()),
        stdout: outcome.map_or_else(String::new, |o| o.stdout.clone()),
    };
    if let Some(parent) = error_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ImportError::io(parent, e))?;
    }
    let json = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| ImportError::io(error_path, std::io::Error::other(e)))?;
    tokio::fs::write(error_path, json)
        .await
        .map_err(|e| ImportError::io(error_path, e))
}

fn spawn_import_task(
    guard: OwnedMutexGuard<()>,
    runner: HeadlessRunner,
    spec: ImportSpec,
    output_path: PathBuf,
    error_path: PathBuf,
) {
    tokio::spawn(async move {
        let _guard = guard;
        let binary = spec.binary.display().to_string();
        match runner.run_import(&spec).await {
            Ok(outcome) if outcome.success => match cached_output_is_ready(&output_path).await {
                Ok(true) => {
                    let _ = remove_import_failure(&error_path).await;
                    tracing::info!(binary = %binary, "ghidra_import: analyzeHeadless completed");
                }
                Ok(false) => {
                    let _ = write_import_failure(
                            &error_path,
                            "analyzeHeadless completed but did not produce a valid functions.json envelope".to_string(),
                            Some(&outcome),
                        )
                        .await;
                    tracing::error!(binary = %binary, "ghidra_import: missing functions output");
                }
                Err(err) => {
                    let _ =
                        write_import_failure(&error_path, err.to_string(), Some(&outcome)).await;
                    tracing::error!(binary = %binary, error = %err, "ghidra_import: output check failed");
                }
            },
            Ok(outcome) => {
                let error = format!(
                    "analyzeHeadless exited non-zero{}",
                    outcome
                        .exit_code
                        .map(|code| format!(" with code {code}"))
                        .unwrap_or_default()
                );
                let _ = write_import_failure(&error_path, error, Some(&outcome)).await;
                tracing::error!(
                    binary = %binary,
                    exit_code = ?outcome.exit_code,
                    stderr = %outcome.stderr,
                    "ghidra_import: analyzeHeadless exited non-zero"
                );
            }
            Err(err) => {
                let _ = write_import_failure(&error_path, err.to_string(), None).await;
                tracing::error!(binary = %binary, error = %err, "ghidra_import: runner failed");
            }
        }
    });
}

async fn validate_paths(ctx: &ImportContext, binary_path: &Path) -> Result<(), ImportError> {
    let bin_meta = tokio::fs::metadata(binary_path).await.map_err(|e| {
        tracing::warn!(
            path = %binary_path.display(),
            error = %e,
            "ghidra_import: binary metadata read failed"
        );
        ImportError::BinaryMissing(binary_path.to_path_buf())
    })?;
    if !bin_meta.is_file() {
        return Err(ImportError::BinaryMissing(binary_path.to_path_buf()));
    }
    validate_ghidra_environment(
        &ctx.scripts_dir,
        EXTRACT_FUNCTIONS_SCRIPT,
        &ctx.analyze_headless,
    )
    .await?;
    Ok(())
}
