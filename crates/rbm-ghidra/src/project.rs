use std::borrow::Cow;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use rbm_core::CachePaths;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::Mutex;

pub const FUNCTIONS_OUTPUT_FILE: &str = "functions.json";
pub const IMPORT_ERROR_FILE: &str = "import_error.json";
pub const EXTRACT_FUNCTIONS_SCRIPT: &str = "extract_functions.java";
pub const DECOMPILE_FUNCTION_SCRIPT: &str = "decompile_function.java";
pub const DECOMPILE_META_SCRIPT: &str = "decompile_meta.java";
pub const SEARCH_SYMBOLS_SCRIPT: &str = "search_symbols.java";
pub const LIST_EXPORTS_SCRIPT: &str = "list_exports.java";
pub const LIST_IMPORTS_SCRIPT: &str = "list_imports.java";
pub const LIST_XREFS_SCRIPT: &str = "list_xrefs.java";
pub const SEARCH_STRINGS_SCRIPT: &str = "search_strings.java";
pub const READ_BYTES_SCRIPT: &str = "read_bytes.java";
pub const CALLGRAPH_SCRIPT: &str = "callgraph.java";
pub const CFG_SCRIPT: &str = "cfg.java";
pub const DECOMPILER_CFG_SCRIPT: &str = "decompiler_cfg.java";
pub const DECOMPILER_CALLS_SCRIPT: &str = "decompiler_calls.java";
pub const DECOMPILER_BLOCK_BEHAVIOR_SCRIPT: &str = "decompiler_block_behavior.java";
pub const DECOMPILER_MEMORY_SCRIPT: &str = "decompiler_memory.java";
pub const DECOMPILER_SLICE_SCRIPT: &str = "decompiler_slice.java";
pub const ANTI_ANALYSIS_SCRIPT: &str = "anti_analysis.java";
pub const BEHAVIORS_SCRIPT: &str = "behaviors.java";
pub const SEARCH_BYTES_SCRIPT: &str = "search_bytes.java";
pub const DEFINED_DATA_SCRIPT: &str = "defined_data.java";
pub const THUNK_TARGET_SCRIPT: &str = "thunk_target.java";
pub const PCODE_SCRIPT: &str = "pcode.java";
pub const FUNCTION_CHECKPOINTS_SCRIPT: &str = "function_checkpoints.java";
pub const FUNCTION_STATS_SCRIPT: &str = "function_stats.java";
pub const VARIABLES_SCRIPT: &str = "variables.java";
pub const DISASSEMBLE_SCRIPT: &str = "disassemble.java";
pub const MEMORY_MAP_SCRIPT: &str = "memory_map.java";
pub const DATA_TYPES_SCRIPT: &str = "data_types.java";
pub const EQUATES_SCRIPT: &str = "equates.java";
pub const FUNCTION_SLICES_SCRIPT: &str = "function_slices.java";
pub const PATH_DIGEST_SCRIPT: &str = "path_digest.java";
pub const DYNAMIC_DISPATCH_TABLE_SCRIPT: &str = "dynamic_dispatch_table.java";
pub const CONTEXT_API_SLOTS_SCRIPT: &str = "context_api_slots.java";
pub const SEARCH_DECOMPILATION_SCRIPT: &str = "search_decompilation.java";
pub const STRING_CONTEXT_SCRIPT: &str = "stringcontext.java";
pub const CONSTANTS_SCRIPT: &str = "constants.java";
pub const GO_METADATA_SCRIPT: &str = "go_metadata.java";

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("path is not a regular file: {0}")]
    NotAFile(PathBuf),
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("join error: {0}")]
    Join(String),
}

impl ProjectError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

#[derive(Debug, Error)]
pub enum PathValidationError {
    #[error("ghidra scripts directory does not exist or is not a directory: {0}")]
    ScriptsDirMissing(PathBuf),
    #[error("ghidra scripts directory is missing {script}: {dir}")]
    ScriptMissing { dir: PathBuf, script: String },
    #[error("failed to create ghidra runtime scripts directory {dir}: {source}")]
    RuntimeScriptsDirCreate {
        dir: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to stage ghidra script {src} -> {dst}: {source}")]
    RuntimeScriptCopy {
        src: PathBuf,
        dst: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("analyzeHeadless launcher does not exist or is not a regular file: {0}")]
    AnalyzeHeadlessMissing(PathBuf),
}

/// Validate the scripts directory, requested script, and `analyzeHeadless` path.
///
/// # Errors
///
/// Returns an error if the scripts directory, requested script, or
/// `analyzeHeadless` launcher is missing or not a regular file where required.
pub async fn validate_ghidra_environment(
    scripts_dir: &Path,
    script_name: &str,
    analyze_headless: &Path,
) -> Result<(), PathValidationError> {
    let scripts_meta = tokio::fs::metadata(scripts_dir).await.map_err(|e| {
        tracing::warn!(
            path = %scripts_dir.display(),
            error = %e,
            "ghidra: scripts dir metadata read failed"
        );
        PathValidationError::ScriptsDirMissing(scripts_dir.to_path_buf())
    })?;
    if !scripts_meta.is_dir() {
        return Err(PathValidationError::ScriptsDirMissing(
            scripts_dir.to_path_buf(),
        ));
    }

    let script_path = scripts_dir.join(script_name);
    let postscript_meta = tokio::fs::metadata(&script_path).await.map_err(|e| {
        tracing::warn!(
            path = %script_path.display(),
            error = %e,
            "ghidra: postScript metadata read failed"
        );
        PathValidationError::ScriptMissing {
            dir: scripts_dir.to_path_buf(),
            script: script_name.to_string(),
        }
    })?;
    if !postscript_meta.is_file() {
        return Err(PathValidationError::ScriptMissing {
            dir: scripts_dir.to_path_buf(),
            script: script_name.to_string(),
        });
    }

    let analyze_meta = tokio::fs::metadata(analyze_headless).await.map_err(|e| {
        tracing::warn!(
            path = %analyze_headless.display(),
            error = %e,
            "ghidra: analyzeHeadless metadata read failed"
        );
        PathValidationError::AnalyzeHeadlessMissing(analyze_headless.to_path_buf())
    })?;
    if !analyze_meta.is_file() {
        return Err(PathValidationError::AnalyzeHeadlessMissing(
            analyze_headless.to_path_buf(),
        ));
    }
    Ok(())
}

/// Copy a Ghidra script into the runtime scripts directory.
///
/// # Errors
///
/// Returns an error if the runtime directory cannot be created, the source script
/// is missing, or the script cannot be copied.
pub async fn stage_script_for_headless(
    runtime_scripts_dir: &Path,
    source_scripts_dir: &Path,
    script_name: &str,
) -> Result<PathBuf, PathValidationError> {
    let source_path = source_scripts_dir.join(script_name);
    tokio::fs::create_dir_all(runtime_scripts_dir)
        .await
        .map_err(|e| PathValidationError::RuntimeScriptsDirCreate {
            dir: runtime_scripts_dir.to_path_buf(),
            source: e,
        })?;
    let staged_path = runtime_scripts_dir.join(script_name);
    tokio::fs::copy(&source_path, &staged_path)
        .await
        .map_err(|e| PathValidationError::RuntimeScriptCopy {
            src: source_path,
            dst: staged_path.clone(),
            source: e,
        })?;
    Ok(staged_path)
}

#[derive(Debug, Error)]
pub enum HeadlessError {
    #[error("failed to spawn analyzeHeadless at {path}: {source}")]
    Spawn {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("analyzeHeadless timed out after {seconds}s")]
    Timeout { seconds: u64 },
    #[error("analyzeHeadless wait failed: {0}")]
    Wait(String),
}

#[derive(Debug)]
pub struct ProjectManager {
    #[allow(dead_code)]
    cache: CachePaths,
    ghidra_dir: PathBuf,
    locks: DashMap<String, Arc<Mutex<()>>>,
}

impl ProjectManager {
    #[must_use]
    pub fn new(cache: &CachePaths) -> Self {
        let ghidra_dir = safe_ghidra_dir_for_headless(&cache.ghidra_dir());
        Self {
            cache: cache.clone(),
            ghidra_dir,
            locks: DashMap::new(),
        }
    }

    #[must_use]
    pub fn ghidra_dir(&self) -> PathBuf {
        self.ghidra_dir.clone()
    }

    #[must_use]
    pub fn project_dir(&self, sha256_hex: &str) -> PathBuf {
        self.ghidra_dir.join(sha256_hex)
    }

    #[must_use]
    pub fn output_path(&self, sha256_hex: &str) -> PathBuf {
        self.project_dir(sha256_hex).join(FUNCTIONS_OUTPUT_FILE)
    }

    #[must_use]
    pub fn runtime_scripts_dir(&self) -> PathBuf {
        self.ghidra_dir().join("runtime_scripts")
    }

    #[must_use]
    pub fn lock_for(&self, sha256_hex: &str) -> Arc<Mutex<()>> {
        self.locks
            .entry(sha256_hex.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Removes the per-sha256 entry from the lock map. Returns true if an
    /// entry was removed.
    ///
    /// Safe to call only when the caller is the sole holder of the
    /// `Arc<Mutex>` (apart from the map's reference). In rbinghidra this
    /// invariant is upheld by holding the `OwnedMutexGuard` at the call
    /// site, combined with the codebase rule that every `lock_for(sha)`
    /// caller immediately consumes the returned `Arc` into
    /// `try_lock_owned()` in a sync, non-`await`ing sequence: a failure
    /// drops the Arc immediately, and a success moves it inside the
    /// `OwnedMutexGuard`. So when `delete_cached_binary` holds its guard,
    /// no other task can be holding the Arc without also holding the
    /// guard (which is impossible since we have it). After eviction the
    /// next `lock_for(sha)` returns a fresh Arc, and the old Arc dies
    /// when the caller's guard drops.
    ///
    /// This is the only puncture in the otherwise monotonic lock map;
    /// `delete_cached_binary` is the lone use site.
    #[must_use]
    pub fn release_lock(&self, sha256_hex: &str) -> bool {
        self.locks.remove(sha256_hex).is_some()
    }

    #[must_use]
    pub fn lock_count(&self) -> usize {
        self.locks.len()
    }

    #[must_use]
    pub fn locked_shas(&self) -> Vec<String> {
        self.locks.iter().map(|e| e.key().clone()).collect()
    }

    #[must_use]
    pub fn is_lock_held(&self, sha256_hex: &str) -> bool {
        let Some(lock) = self.locks.get(sha256_hex) else {
            return false;
        };
        // avoid cloning the Arc
        lock.value().try_lock().is_err()
    }

    #[must_use]
    pub fn held_shas(&self) -> Vec<String> {
        self.locks
            .iter()
            .filter_map(|entry| {
                // avoid cloning the Arc on every entry
                if entry.value().try_lock().is_err() {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

#[must_use]
pub fn safe_ghidra_dir_for_headless(requested: &Path) -> PathBuf {
    if !has_hidden_component(requested) {
        return requested.to_path_buf();
    }
    // Newer Ghidra headless imports reject project directories under hidden
    // path components such as ".cache", so keep the project root visible.
    let base = non_hidden_parent(requested).join("rbinghidra-ghidra");
    let digest = short_path_digest(requested);
    base.join(digest).join("ghidra")
}

fn non_hidden_parent(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        use std::path::Component;
        match component {
            Component::Normal(name)
                if name
                    .to_str()
                    .is_some_and(|s| s.len() > 1 && s.starts_with('.')) =>
            {
                break;
            }
            Component::Normal(name) => out.push(name),
            Component::RootDir | Component::Prefix(_) => out.push(component.as_os_str()),
            Component::CurDir | Component::ParentDir => {}
        }
    }
    if out.as_os_str().is_empty() {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        out
    }
}

fn has_hidden_component(path: &Path) -> bool {
    use std::path::Component;
    path.components().any(|component| match component {
        Component::Normal(name) => name
            .to_str()
            .is_some_and(|s| s.len() > 1 && s.starts_with('.')),
        _ => false,
    })
}

fn short_path_digest(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(path.as_os_str().as_encoded_bytes());
    let hex = hex::encode(hasher.finalize());
    hex[..16].to_string()
}

#[derive(Debug, Clone)]
pub struct ImportSpec {
    pub project_dir: PathBuf,
    pub project_name: String,
    pub binary: PathBuf,
    pub loader: Option<String>,
    pub processor: Option<String>,
    pub cspec: Option<String>,
    pub loader_base_addr: Option<String>,
    pub script_dir: PathBuf,
    pub script_name: String,
    pub script_args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub project_dir: PathBuf,
    pub project_name: String,
    pub program_name: String,
    pub script_dir: PathBuf,
    pub script_name: String,
    pub script_args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct HeadlessRunner {
    pub analyze_headless: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct HeadlessOutcome {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl HeadlessRunner {
    /// Run `analyzeHeadless` in import mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be spawned, times out, or its
    /// output cannot be collected.
    pub async fn run_import(&self, spec: &ImportSpec) -> Result<HeadlessOutcome, HeadlessError> {
        self.spawn_and_wait(build_import_argv(spec)).await
    }

    /// Run `analyzeHeadless` in process mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be spawned, times out, or its
    /// output cannot be collected.
    pub async fn run_process(&self, spec: &ProcessSpec) -> Result<HeadlessOutcome, HeadlessError> {
        self.spawn_and_wait(build_process_argv(spec)).await
    }

    async fn spawn_and_wait(&self, argv: Vec<OsString>) -> Result<HeadlessOutcome, HeadlessError> {
        let mut cmd = tokio::process::Command::new(&self.analyze_headless);
        cmd.args(&argv);
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.kill_on_drop(true);

        let child = cmd.spawn().map_err(|e| HeadlessError::Spawn {
            path: self.analyze_headless.clone(),
            source: e,
        })?;

        match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Err(_) => Err(HeadlessError::Timeout {
                seconds: self.timeout.as_secs(),
            }),
            Ok(Err(e)) => Err(HeadlessError::Wait(e.to_string())),
            Ok(Ok(output)) => Ok(HeadlessOutcome {
                success: output.status.success(),
                exit_code: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }),
        }
    }
}

#[must_use]
pub fn build_import_argv(spec: &ImportSpec) -> Vec<OsString> {
    let mut argv: Vec<OsString> = Vec::with_capacity(17 + spec.script_args.len());
    argv.push(spec.project_dir.as_os_str().to_os_string());
    argv.push(OsString::from(&spec.project_name));
    argv.push(OsString::from("-import"));
    argv.push(spec.binary.as_os_str().to_os_string());
    argv.push(OsString::from("-overwrite"));
    if let Some(loader) = non_empty_opt(spec.loader.as_ref()) {
        argv.push(OsString::from("-loader"));
        argv.push(OsString::from(loader));
    }
    if let Some(processor) = non_empty_opt(spec.processor.as_ref()) {
        argv.push(OsString::from("-processor"));
        argv.push(OsString::from(processor));
    }
    if let Some(cspec) = non_empty_opt(spec.cspec.as_ref()) {
        argv.push(OsString::from("-cspec"));
        argv.push(OsString::from(cspec));
    }
    if let Some(base_addr) = non_empty_opt(spec.loader_base_addr.as_ref()) {
        argv.push(OsString::from("-loader-baseAddr"));
        argv.push(OsString::from(base_addr));
    }
    argv.push(OsString::from("-scriptPath"));
    argv.push(spec.script_dir.as_os_str().to_os_string());
    argv.push(OsString::from("-postScript"));
    argv.push(OsString::from(&spec.script_name));
    for arg in &spec.script_args {
        argv.push(OsString::from(arg));
    }
    argv
}

fn non_empty_opt(value: Option<&String>) -> Option<&str> {
    value
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

#[must_use]
pub fn build_process_argv(spec: &ProcessSpec) -> Vec<OsString> {
    let mut argv: Vec<OsString> = Vec::with_capacity(9 + spec.script_args.len());
    argv.push(spec.project_dir.as_os_str().to_os_string());
    argv.push(OsString::from(&spec.project_name));
    argv.push(OsString::from("-process"));
    argv.push(OsString::from(&spec.program_name));
    argv.push(OsString::from("-noanalysis"));
    argv.push(OsString::from("-scriptPath"));
    argv.push(spec.script_dir.as_os_str().to_os_string());
    argv.push(OsString::from("-postScript"));
    argv.push(OsString::from(&spec.script_name));
    for arg in &spec.script_args {
        argv.push(OsString::from(arg));
    }
    argv
}

#[must_use]
pub fn cache_key(sha256_hex: &str) -> String {
    format!("sha256:{sha256_hex}")
}

#[must_use]
pub fn project_name_for(binary: &Path) -> String {
    binary
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| sanitize_project_name(s).into_owned())
        .unwrap_or_default()
}

#[must_use]
pub fn sanitize_project_name(input: &str) -> Cow<'_, str> {
    // Fast-path performance optimization: check if we need to sanitize first.
    // This avoids unnecessary string allocation for already-safe project names.
    let bytes = input.as_bytes();
    let mut needs_sanitize = false;
    for &b in bytes {
        if !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.') {
            needs_sanitize = true;
            break;
        }
    }

    if !needs_sanitize {
        return Cow::Borrowed(input);
    }

    let mut cleaned = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
            cleaned.push(c);
        } else {
            cleaned.push('_');
        }
    }
    Cow::Owned(cleaned)
}

/// Compute a SHA-256 digest for a regular file.
///
/// # Errors
///
/// Returns an error if the path is not a regular file or if the file cannot be
/// read.
pub async fn hash_file(path: &Path) -> Result<String, ProjectError> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|e| ProjectError::io(path, e))?;
    if !metadata.is_file() {
        return Err(ProjectError::NotAFile(path.to_path_buf()));
    }
    let path = path.to_path_buf();
    let path_for_err = path.clone();
    let join = tokio::task::spawn_blocking(move || -> Result<String, std::io::Error> {
        use std::io::Read;
        let mut file = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    })
    .await;
    match join {
        Ok(Ok(hex)) => Ok(hex),
        Ok(Err(io)) => Err(ProjectError::io(path_for_err, io)),
        Err(join) => Err(ProjectError::Join(join.to_string())),
    }
}
