#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rbm_core::CachePaths;
use rbm_ghidra::import::{ImportContext, import_binary};
use rbm_ghidra::project::{
    EXTRACT_FUNCTIONS_SCRIPT, FUNCTIONS_OUTPUT_FILE, IMPORT_ERROR_FILE, ProjectManager, hash_file,
};
use tempfile::TempDir;

mod common;
use common::{make_runtime, write_executable};

fn fake_analyze_headless(path: &Path, payload: &str) {
    let script = format!(
        "#!/bin/sh\nfor arg in \"$@\"; do out=\"$arg\"; done\nprintf '%s' '{payload}' > \"$out\"\nexit 0\n"
    );
    write_executable(path, &script);
}

fn fake_failing_analyze_headless(path: &Path) {
    write_executable(path, "#!/bin/sh\necho 'oops' >&2\nexit 7\n");
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
        assert_eq!(report.status, "analyzing");
        assert!(report.started, "first call should kick off the runner");

        let output = mgr.output_path(&sha256_hex);
        assert!(
            wait_for_file(&output, Duration::from_secs(5)).await,
            "fake analyzeHeadless never wrote {output:?}"
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
        assert_eq!(second.eta_ms, 0);
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
        assert_eq!(report.status, "analyzing");
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
        assert_eq!(report.status, "analyzing");
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
        assert_eq!(first.status, "analyzing");
        assert!(first.started);

        // Second call should observe the held lock and return analyzing+started=false.
        let second = import_binary(&ctx, &bin).await.unwrap();
        assert_eq!(second.status, "analyzing");
        assert!(
            !second.started,
            "second call must not spawn a duplicate task"
        );
    });
}
