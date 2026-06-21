use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::OwnedMutexGuard;

use crate::inspect::{
    InspectError, cached_binary_metadata_is_ready, refresh_cached_binary_metadata,
};
use crate::project::{
    EXTRACT_FUNCTIONS_SCRIPT, HeadlessOutcome, HeadlessRunner, IMPORT_ERROR_FILE, ImportSpec,
    PathValidationError, ProjectError, ProjectManager, cache_key, hash_file, project_name_for,
    sanitize_project_name, stage_script_for_headless, validate_ghidra_environment,
};

static IMPORT_STAGE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportReport {
    pub status: String,
    pub cache_key: String,
    pub binary_name: String,
    pub project_dir: String,
    pub output_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_ms: Option<u64>,
    pub started: bool,
    pub next_action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ImportFailureEnvelope {
    schema: String,
    error: String,
    exit_code: Option<i32>,
    stderr: String,
    stdout: String,
}

#[derive(Debug)]
struct StagedImport {
    dir: PathBuf,
    binary: PathBuf,
}

struct ImportPaths {
    project_dir: PathBuf,
    output_path: PathBuf,
    metadata_path: PathBuf,
    error_path: PathBuf,
}

struct PendingImport {
    key: String,
    sha256_hex: String,
    binary_name: String,
    staged: StagedImport,
    paths: ImportPaths,
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
    fn running(
        key: String,
        binary_name: String,
        project_dir: &Path,
        output_path: &Path,
        started: bool,
    ) -> Self {
        let next_action = if started {
            "Import is running. Call ghidra_import again with the same binary_path until status is ready; duration depends on Ghidra analysis time."
        } else {
            "Import or analysis for this binary is already running. Retry ghidra_import later, or call ghidra_lock_status with the cache_key."
        };
        Self {
            status: "running".to_string(),
            cache_key: key,
            binary_name,
            project_dir: project_dir.display().to_string(),
            output_path: output_path.display().to_string(),
            eta_ms: None,
            started,
            next_action: next_action.to_string(),
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
            eta_ms: None,
            started: false,
            next_action: "Use cache_key or binary_name with Ghidra tools.".to_string(),
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
            eta_ms: None,
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

    let binary_name = original_binary_name(binary_path);
    let staged = stage_import_binary(ctx, binary_path, &binary_name).await?;
    let sha256_hex = hash_staged_import(&staged).await?;
    import_staged_binary(ctx, binary_path, options, binary_name, staged, sha256_hex).await
}

async fn hash_staged_import(staged: &StagedImport) -> Result<String, ImportError> {
    match hash_file(&staged.binary).await {
        Ok(sha256_hex) => Ok(sha256_hex),
        Err(err) => {
            cleanup_staged_import(&staged.dir).await;
            Err(err.into())
        }
    }
}

async fn import_staged_binary(
    ctx: &ImportContext,
    binary_path: &Path,
    options: &ImportOptions,
    binary_name: String,
    staged: StagedImport,
    sha256_hex: String,
) -> Result<ImportReport, ImportError> {
    let paths = ImportPaths::new(ctx.manager.as_ref(), &sha256_hex);
    let key = cache_key(&sha256_hex);

    if let Some(report) = cleanup_on_error(
        &staged.dir,
        cached_ready_report(ctx, &sha256_hex, &key, &binary_name, &paths).await,
    )
    .await?
    {
        cleanup_staged_import(&staged.dir).await;
        return Ok(report);
    }

    if let Some(report) = cleanup_on_error(
        &staged.dir,
        cached_failure_report(options, &key, &binary_name, &paths).await,
    )
    .await?
    {
        cleanup_staged_import(&staged.dir).await;
        return Ok(report);
    }

    cleanup_on_error(&staged.dir, prepare_project_for_import(&paths).await).await?;

    let lock = ctx.manager.lock_for(&sha256_hex);
    match lock.try_lock_owned() {
        Err(_) => {
            cleanup_staged_import(&staged.dir).await;
            Ok(ImportReport::running(
                key,
                binary_name,
                &paths.project_dir,
                &paths.output_path,
                false,
            ))
        }
        Ok(guard) => {
            start_import_task_after_lock(
                ctx,
                binary_path,
                options,
                PendingImport {
                    key,
                    sha256_hex,
                    binary_name,
                    staged,
                    paths,
                },
                guard,
            )
            .await
        }
    }
}

impl ImportPaths {
    fn new(manager: &ProjectManager, sha256_hex: &str) -> Self {
        let project_dir = manager.project_dir(sha256_hex);
        let output_path = manager.output_path(sha256_hex);
        let metadata_path = manager.metadata_path(sha256_hex);
        let error_path = project_dir.join(IMPORT_ERROR_FILE);
        Self {
            project_dir,
            output_path,
            metadata_path,
            error_path,
        }
    }
}

async fn cleanup_on_error<T>(
    stage_dir: &Path,
    result: Result<T, ImportError>,
) -> Result<T, ImportError> {
    match result {
        Ok(value) => Ok(value),
        Err(err) => {
            cleanup_staged_import(stage_dir).await;
            Err(err)
        }
    }
}

async fn cached_ready_report(
    ctx: &ImportContext,
    sha256_hex: &str,
    key: &str,
    binary_name: &str,
    paths: &ImportPaths,
) -> Result<Option<ImportReport>, ImportError> {
    if !cached_output_is_ready(ctx.manager.as_ref(), sha256_hex).await? {
        return Ok(None);
    }

    let lock = ctx.manager.lock_for(sha256_hex);
    let report = if lock.try_lock_owned().is_err() {
        ImportReport::running(
            key.to_string(),
            binary_name.to_string(),
            &paths.project_dir,
            &paths.output_path,
            false,
        )
    } else {
        ImportReport::ready(
            key.to_string(),
            binary_name.to_string(),
            &paths.project_dir,
            &paths.output_path,
        )
    };
    Ok(Some(report))
}

async fn cached_failure_report(
    options: &ImportOptions,
    key: &str,
    binary_name: &str,
    paths: &ImportPaths,
) -> Result<Option<ImportReport>, ImportError> {
    if options.has_explicit_loader_options() {
        return Ok(None);
    }

    let Some(failure) = read_import_failure(&paths.error_path).await? else {
        return Ok(None);
    };

    Ok(Some(ImportReport::failed(
        key.to_string(),
        binary_name.to_string(),
        &paths.project_dir,
        &paths.output_path,
        failure.error,
    )))
}

async fn prepare_project_for_import(paths: &ImportPaths) -> Result<(), ImportError> {
    remove_stale_output(&paths.output_path).await?;
    remove_cached_metadata(&paths.metadata_path).await?;
    remove_import_failure(&paths.error_path).await?;
    tokio::fs::create_dir_all(&paths.project_dir)
        .await
        .map_err(|err| ImportError::io(&paths.project_dir, err))
}

async fn start_import_task_after_lock(
    ctx: &ImportContext,
    binary_path: &Path,
    options: &ImportOptions,
    pending: PendingImport,
    guard: OwnedMutexGuard<()>,
) -> Result<ImportReport, ImportError> {
    let PendingImport {
        key,
        sha256_hex,
        binary_name,
        staged,
        paths,
    } = pending;

    if cleanup_on_error(
        &staged.dir,
        cached_output_is_ready(ctx.manager.as_ref(), &sha256_hex).await,
    )
    .await?
    {
        drop(guard);
        cleanup_staged_import(&staged.dir).await;
        return Ok(ImportReport::ready(
            key,
            binary_name,
            &paths.project_dir,
            &paths.output_path,
        ));
    }

    cleanup_on_error(&staged.dir, prepare_project_for_import(&paths).await).await?;
    let spec = cleanup_on_error(
        &staged.dir,
        build_import_spec(
            ctx,
            binary_path,
            &staged.binary,
            options,
            &paths.project_dir,
            &paths.output_path,
        )
        .await,
    )
    .await?;

    let runner = HeadlessRunner {
        analyze_headless: ctx.analyze_headless.clone(),
        timeout: ctx.timeout,
    };
    spawn_import_task(
        guard,
        runner,
        spec,
        ctx.manager.clone(),
        sha256_hex,
        paths.error_path,
        staged.dir,
    );
    Ok(ImportReport::running(
        key,
        binary_name,
        &paths.project_dir,
        &paths.output_path,
        true,
    ))
}

fn original_binary_name(binary_path: &Path) -> String {
    binary_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("binary")
        .to_string()
}

async fn stage_import_binary(
    ctx: &ImportContext,
    binary_path: &Path,
    binary_name: &str,
) -> Result<StagedImport, ImportError> {
    let stage_root = ctx.manager.ghidra_dir().join("import_staging");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let sequence = IMPORT_STAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let stage_dir = stage_root.join(format!("{}_{stamp}_{sequence}", std::process::id()));
    tokio::fs::create_dir_all(&stage_dir)
        .await
        .map_err(|err| ImportError::io(&stage_dir, err))?;

    let safe_name = sanitize_project_name(binary_name);
    let safe_name = if safe_name.is_empty() {
        "binary"
    } else {
        safe_name.as_ref()
    };
    let staged_binary = stage_dir.join(safe_name);
    tokio::fs::copy(binary_path, &staged_binary)
        .await
        .map_err(|err| ImportError::io(binary_path, err))?;

    Ok(StagedImport {
        dir: stage_dir,
        binary: staged_binary,
    })
}

async fn cleanup_staged_import(stage_dir: &Path) {
    let _ = tokio::fs::remove_dir_all(stage_dir).await;
}

async fn build_import_spec(
    ctx: &ImportContext,
    original_binary_path: &Path,
    staged_binary_path: &Path,
    options: &ImportOptions,
    project_dir: &Path,
    output_path: &Path,
) -> Result<ImportSpec, ImportError> {
    let runtime_scripts_dir = ctx.manager.runtime_scripts_dir();
    stage_script_for_headless(
        &runtime_scripts_dir,
        &ctx.scripts_dir,
        EXTRACT_FUNCTIONS_SCRIPT,
    )
    .await?;

    Ok(ImportSpec {
        project_dir: project_dir.to_path_buf(),
        project_name: project_name_for(original_binary_path),
        binary: staged_binary_path.to_path_buf(),
        loader: options.loader.clone(),
        processor: options.processor.clone(),
        cspec: options.cspec.clone(),
        loader_base_addr: options.loader_base_addr.clone(),
        script_dir: runtime_scripts_dir,
        script_name: EXTRACT_FUNCTIONS_SCRIPT.to_string(),
        script_args: vec![
            output_path.display().to_string(),
            original_binary_path.display().to_string(),
        ],
    })
}

async fn cached_output_is_ready(
    manager: &ProjectManager,
    sha256_hex: &str,
) -> Result<bool, ImportError> {
    match cached_binary_metadata_is_ready(manager, sha256_hex).await {
        Ok(true) => return Ok(true),
        Ok(false) => {}
        Err(err) => {
            if let Some(err) = inspect_io_as_import_error(err) {
                return Err(err);
            }
            return Ok(false);
        }
    }

    match refresh_cached_binary_metadata(manager, sha256_hex).await {
        Ok(ready) => Ok(ready),
        Err(InspectError::Parse { .. }) => Ok(false),
        Err(err) => inspect_io_as_import_error(err).map_or(Ok(false), Err),
    }
}

async fn remove_stale_output(output_path: &Path) -> Result<(), ImportError> {
    remove_file_if_exists(output_path).await
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
    remove_file_if_exists(error_path).await
}

async fn remove_cached_metadata(metadata_path: &Path) -> Result<(), ImportError> {
    remove_file_if_exists(metadata_path).await
}

async fn remove_file_if_exists(path: &Path) -> Result<(), ImportError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(ImportError::io(path, err)),
    }
}

async fn write_import_failure(
    error_path: &Path,
    error: String,
    outcome: Option<&HeadlessOutcome>,
) -> Result<(), ImportError> {
    let error = summarize_import_failure(&error, outcome);
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

fn summarize_import_failure(default_error: &str, outcome: Option<&HeadlessOutcome>) -> String {
    let Some(outcome) = outcome else {
        return default_error.to_string();
    };
    let combined = format!("{}\n{}", outcome.stderr, outcome.stdout);
    for line in combined.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains("No load spec found")
            || trimmed.contains("could not successfully load")
            || trimmed.contains("Import failed")
            || trimmed.contains("ERROR Abort due")
            || trimmed.contains("ERROR REPORT: Import failed")
        {
            return trimmed.to_string();
        }
    }
    default_error.to_string()
}

fn spawn_import_task(
    guard: OwnedMutexGuard<()>,
    runner: HeadlessRunner,
    spec: ImportSpec,
    manager: Arc<ProjectManager>,
    sha256_hex: String,
    error_path: PathBuf,
    staged_dir: PathBuf,
) {
    tokio::spawn(async move {
        let _guard = guard;
        match runner.run_import(&spec).await {
            Ok(outcome) if outcome.success => {
                match cached_output_is_ready(&manager, &sha256_hex).await {
                    Ok(true) => {
                        let _ = remove_import_failure(&error_path).await;
                    }
                    Ok(false) => {
                        let _ = write_import_failure(
                            &error_path,
                            "analyzeHeadless completed but did not produce a valid functions.json envelope".to_string(),
                            Some(&outcome),
                        )
                        .await;
                    }
                    Err(err) => {
                        let _ = write_import_failure(&error_path, err.to_string(), Some(&outcome))
                            .await;
                    }
                }
            }
            Ok(outcome) => {
                let error = format!(
                    "analyzeHeadless exited non-zero{}",
                    outcome
                        .exit_code
                        .map(|code| format!(" with code {code}"))
                        .unwrap_or_default()
                );
                let _ = write_import_failure(&error_path, error, Some(&outcome)).await;
            }
            Err(err) => {
                let _ = write_import_failure(&error_path, err.to_string(), None).await;
            }
        }
        cleanup_staged_import(&staged_dir).await;
    });
}

fn inspect_io_as_import_error(err: InspectError) -> Option<ImportError> {
    match err {
        InspectError::Io { path, source } => Some(ImportError::io(path, source)),
        InspectError::Parse { .. } | InspectError::NotFound(_) | InspectError::Ambiguous { .. } => {
            None
        }
    }
}

async fn validate_paths(ctx: &ImportContext, binary_path: &Path) -> Result<(), ImportError> {
    let bin_meta = tokio::fs::metadata(binary_path)
        .await
        .map_err(|_| ImportError::BinaryMissing(binary_path.to_path_buf()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_failure_summary_prefers_ghidra_abort_line() {
        let outcome = HeadlessOutcome {
            success: false,
            exit_code: Some(1),
            stdout: "INFO startup\nERROR Abort due to Headless analyzer error: Path element starting with '.' is not permitted\n".to_string(),
            stderr: "openjdk warning\n".to_string(),
        };

        assert_eq!(
            summarize_import_failure(
                "analyzeHeadless exited non-zero with code 1",
                Some(&outcome)
            ),
            "ERROR Abort due to Headless analyzer error: Path element starting with '.' is not permitted"
        );
    }
}
