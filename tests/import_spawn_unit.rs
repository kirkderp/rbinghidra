#![cfg(unix)]

#[path = "support/tempfile.rs"]
mod tempfile;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rbinghidra::CachePaths;
use rbinghidra::import::{ImportContext, import_binary};
use rbinghidra::project::{
    EXTRACT_FUNCTIONS_SCRIPT, FUNCTIONS_OUTPUT_FILE, IMPORT_ERROR_FILE, ProjectManager, hash_file,
};
use tempfile::TempDir;

mod common;
use common::{make_runtime, write_executable};

const CACHED_METADATA_FILE: &str = "cached_metadata.json";

fn fake_analyze_headless(path: &Path, payload: &str) {
    let script = format!(
        "#!/bin/sh\nout=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"-postScript\" ]; then\n    shift\n    shift\n    out=\"$1\"\n    break\n  fi\n  shift\ndone\nif [ -z \"$out\" ]; then exit 64; fi\nprintf '%s' '{payload}' > \"$out\"\nexit 0\n"
    );
    write_executable(path, &script);
}

fn fake_capture_import_input(path: &Path, payload: &str) {
    let script = format!(
        "#!/bin/sh\ninput=\"$4\"\nout=\noriginal=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"-postScript\" ]; then\n    shift\n    shift\n    out=\"$1\"\n    shift\n    original=\"$1\"\n    break\n  fi\n  shift\ndone\nif [ -z \"$out\" ]; then exit 64; fi\nsleep 1\ncat \"$input\" > \"$out.imported\"\nprintf '%s' \"$original\" > \"$out.original_path\"\nprintf '%s' '{payload}' > \"$out\"\nexit 0\n"
    );
    write_executable(path, &script);
}

fn fake_failing_analyze_headless(path: &Path) {
    write_executable(path, "#!/bin/sh\necho 'oops' >&2\nexit 7\n");
}

fn fake_no_load_spec_analyze_headless(path: &Path) {
    write_executable(
        path,
        "#!/bin/sh\necho 'INFO No load spec found for import file: sample.potm'\necho 'ERROR REPORT: Import failed for file: sample.potm'\nexit 0\n",
    );
}

fn fake_slow_analyze_headless(path: &Path) {
    write_executable(path, "#!/bin/sh\nsleep 30\nexit 0\n");
}

const fn valid_extract_payload() -> &'static str {
    "{\"schema\":\"rbm.ghidra.extract_functions.v0\",\"program_name\":\"sample.bin\",\"functions\":[]}"
}

fn make_ctx(
    tmp: &TempDir,
    manager: Arc<ProjectManager>,
    analyze_headless: PathBuf,
    timeout: Duration,
) -> ImportContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(EXTRACT_FUNCTIONS_SCRIPT), b"# stub").unwrap();
    ImportContext {
        manager,
        analyze_headless,
        scripts_dir: scripts,
        timeout,
    }
}

async fn wait_for_file(path: &std::path::Path, deadline: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if tokio::fs::try_exists(path).await.unwrap_or(false) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

async fn wait_for_file_contents(
    path: &std::path::Path,
    expected: &[u8],
    deadline: Duration,
) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if matches!(tokio::fs::read(path).await, Ok(bytes) if bytes == expected) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[test]
fn import_binary_spawns_runner_and_writes_output_via_fake_analyze_headless() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        let bin = tmp.path().join("sample.bin");
        std::fs::write(&bin, b"hello world").unwrap();
        let sha256_hex = hash_file(&bin).await.unwrap();

        let analyze = tmp.path().join("fake_analyze_headless");
        fake_analyze_headless(&analyze, valid_extract_payload());
        let ctx = make_ctx(&tmp, mgr.clone(), analyze, Duration::from_secs(10));

        let report = import_binary(&ctx, &bin).await.unwrap();
        assert_eq!(report.status, "running");
        assert!(report.started, "first call should kick off the runner");

        let output = mgr.output_path(&sha256_hex);
        assert!(
            wait_for_file(&output, Duration::from_secs(5)).await,
            "fake analyzeHeadless never wrote {output:?}"
        );
        let metadata = mgr.project_dir(&sha256_hex).join(CACHED_METADATA_FILE);
        assert!(
            wait_for_file(&metadata, Duration::from_secs(5)).await,
            "import task never wrote {metadata:?}"
        );

        let bytes = std::fs::read(&output).unwrap();
        assert!(
            bytes.starts_with(b"{\"schema\":\"rbm.ghidra.extract_functions.v0\""),
            "unexpected output payload: {:?}",
            String::from_utf8_lossy(&bytes)
        );
    });
}

#[test]
fn import_binary_imports_the_staged_copy_not_a_mutated_source_path() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        let bin = tmp.path().join("sample.bin");
        std::fs::write(&bin, b"original content").unwrap();
        let sha256_hex = hash_file(&bin).await.unwrap();

        let analyze = tmp.path().join("fake_analyze_headless");
        fake_capture_import_input(&analyze, valid_extract_payload());
        let ctx = make_ctx(&tmp, mgr.clone(), analyze, Duration::from_secs(10));

        let report = import_binary(&ctx, &bin).await.unwrap();
        assert_eq!(report.status, "running");
        assert!(report.started);

        std::fs::write(&bin, b"mutated content").unwrap();

        let output = mgr.output_path(&sha256_hex);
        let imported = PathBuf::from(format!("{}.imported", output.display()));
        assert!(
            wait_for_file_contents(&imported, b"original content", Duration::from_secs(5)).await,
            "fake analyzeHeadless never captured staged bytes at {imported:?}"
        );
        let original_path = PathBuf::from(format!("{}.original_path", output.display()));
        assert!(
            wait_for_file_contents(
                &original_path,
                bin.to_string_lossy().as_bytes(),
                Duration::from_secs(5)
            )
            .await,
            "fake analyzeHeadless never captured original metadata path at {original_path:?}"
        );
    });
}

#[test]
fn import_binary_returns_ready_after_runner_writes_output_file() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        let bin = tmp.path().join("sample.bin");
        std::fs::write(&bin, b"hello world").unwrap();
        let sha256_hex = hash_file(&bin).await.unwrap();
        let analyze = tmp.path().join("fake_analyze_headless");
        fake_analyze_headless(&analyze, valid_extract_payload());
        let ctx = make_ctx(&tmp, mgr.clone(), analyze, Duration::from_secs(10));

        let _first = import_binary(&ctx, &bin).await.unwrap();
        let output = mgr.output_path(&sha256_hex);
        assert!(wait_for_file(&output, Duration::from_secs(5)).await);
        // Give the spawned task a moment to observe process exit and drop its lock guard.
        tokio::time::sleep(Duration::from_millis(250)).await;

        let second = import_binary(&ctx, &bin).await.unwrap();
        assert_eq!(second.status, "ready");
        assert_eq!(second.eta_ms, None);
        assert!(!second.started);
        assert!(second.output_path.ends_with(FUNCTIONS_OUTPUT_FILE));
    });
}

#[test]
fn import_binary_retries_when_stale_output_is_not_valid_extract_envelope() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        let bin = tmp.path().join("sample.bin");
        std::fs::write(&bin, b"hello world").unwrap();
        let sha256_hex = hash_file(&bin).await.unwrap();
        let output = mgr.output_path(&sha256_hex);
        std::fs::create_dir_all(output.parent().unwrap()).unwrap();
        std::fs::write(&output, b"{\"schema\":\"partial\"").unwrap();

        let analyze = tmp.path().join("fake_analyze_headless");
        fake_analyze_headless(&analyze, valid_extract_payload());
        let ctx = make_ctx(&tmp, mgr.clone(), analyze, Duration::from_secs(10));

        let report = import_binary(&ctx, &bin).await.unwrap();
        assert_eq!(report.status, "running");
        assert!(
            report.started,
            "stale output should not be treated as ready"
        );
        assert!(wait_for_file(&output, Duration::from_secs(5)).await);
        let bytes = std::fs::read(&output).unwrap();
        assert!(
            bytes.starts_with(b"{\"schema\":\"rbm.ghidra.extract_functions.v0\""),
            "stale output should be replaced with a valid extract envelope"
        );
    });
}

#[test]
fn import_binary_failing_runner_does_not_write_output_or_panic() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        let bin = tmp.path().join("sample.bin");
        std::fs::write(&bin, b"hello world").unwrap();
        let sha256_hex = hash_file(&bin).await.unwrap();
        let analyze = tmp.path().join("fake_analyze_headless");
        fake_failing_analyze_headless(&analyze);
        let ctx = make_ctx(&tmp, mgr.clone(), analyze, Duration::from_secs(10));

        let report = import_binary(&ctx, &bin).await.unwrap();
        assert_eq!(report.status, "running");
        assert!(report.started);

        let error_path = mgr.project_dir(&sha256_hex).join(IMPORT_ERROR_FILE);
        assert!(
            wait_for_file(&error_path, Duration::from_secs(5)).await,
            "failing runner should write {error_path:?}"
        );
        let output = mgr.output_path(&sha256_hex);
        assert!(!output.exists(), "failing runner should not write output");

        let failed = import_binary(&ctx, &bin).await.unwrap();
        assert_eq!(failed.status, "failed");
        assert!(!failed.started);
        assert!(failed.error.as_deref().unwrap_or("").contains("non-zero"));
    });
}

#[test]
fn import_binary_success_without_output_surfaces_headless_import_reason() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        let bin = tmp.path().join("sample.potm");
        std::fs::write(&bin, b"not a recognized program").unwrap();
        let sha256_hex = hash_file(&bin).await.unwrap();
        let analyze = tmp.path().join("fake_analyze_headless");
        fake_no_load_spec_analyze_headless(&analyze);
        let ctx = make_ctx(&tmp, mgr.clone(), analyze, Duration::from_secs(10));

        let report = import_binary(&ctx, &bin).await.unwrap();
        assert_eq!(report.status, "running");
        assert!(report.started);

        let error_path = mgr.project_dir(&sha256_hex).join(IMPORT_ERROR_FILE);
        assert!(
            wait_for_file(&error_path, Duration::from_secs(5)).await,
            "runner should write {error_path:?}"
        );

        let failed = import_binary(&ctx, &bin).await.unwrap();
        assert_eq!(failed.status, "failed");
        let error = failed.error.as_deref().unwrap_or("");
        assert!(
            error.contains("No load spec found"),
            "expected Ghidra diagnostic in import error, got {error:?}"
        );
    });
}

#[test]
fn import_binary_slow_runner_holds_lock_until_complete() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        let bin = tmp.path().join("sample.bin");
        std::fs::write(&bin, b"hello world").unwrap();
        let analyze = tmp.path().join("fake_analyze_headless");
        fake_slow_analyze_headless(&analyze);
        let ctx = make_ctx(&tmp, mgr.clone(), analyze, Duration::from_secs(60));

        let first = import_binary(&ctx, &bin).await.unwrap();
        assert_eq!(first.status, "running");
        assert!(first.started);

        // Second call should observe the held lock and return running+started=false.
        let second = import_binary(&ctx, &bin).await.unwrap();
        assert_eq!(second.status, "running");
        assert!(
            !second.started,
            "second call must not spawn a duplicate task"
        );
    });
}
