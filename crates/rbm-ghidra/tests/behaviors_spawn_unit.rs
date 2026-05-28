#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rbm_core::CachePaths;
use rbm_ghidra::behaviors::{BehaviorsContext, BehaviorsError, scan_behaviors};
use rbm_ghidra::project::{BEHAVIORS_SCRIPT, ProjectManager};
use tempfile::TempDir;

mod common;
use common::{make_runtime, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fake_behaviors_analyze_headless(path: &Path, payload: &str) {
    let script = format!(
        "#!/bin/sh\nout=\"\"\nfor arg in \"$@\"; do\n  case \"$arg\" in\n    *.json)\n      if [ -z \"$out\" ]; then\n        out=\"$arg\"\n      fi\n      ;;\n  esac\ndone\nprintf '%s' '{payload}' > \"$out\"\nexit 0\n"
    );
    write_executable(path, &script);
}

fn fake_failing_analyze_headless(path: &Path) {
    write_executable(
        path,
        "#!/bin/sh\necho 'simulated ghidra failure' >&2\nexit 9\n",
    );
}

fn fake_silent_analyze_headless(path: &Path) {
    write_executable(
        path,
        "#!/bin/sh\necho 'silent run, postScript wrote nothing'\nexit 0\n",
    );
}

fn make_ctx(
    tmp: &TempDir,
    manager: Arc<ProjectManager>,
    analyze_headless: PathBuf,
) -> BehaviorsContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(BEHAVIORS_SCRIPT), b"// stub").unwrap();
    BehaviorsContext {
        manager,
        analyze_headless,
        scripts_dir: scripts,
        timeout: Duration::from_secs(10),
    }
}

fn touch_gpr(manager: &ProjectManager, sha: &str, project_name: &str) {
    let dir = manager.project_dir(sha);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{project_name}.gpr")), b"").unwrap();
}

#[test]
fn behaviors_spawns_runner_parses_envelope_and_cleans_up() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_analyze_headless");
        let payload = r#"{"schema":"rbm.ghidra.behaviors.v0","total_detected":1,"severity_summary":{"high":1},"behaviors":[{"name":"example_behavior","severity":"high"}]}"#;
        fake_behaviors_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = scan_behaviors(&ctx, "ls").await.unwrap();

        assert_eq!(result.schema, "rbm.ghidra.behaviors.v0");
        assert_eq!(result.cache_key, format!("sha256:{SHA_LS}"));
        assert_eq!(result.sha256, SHA_LS);
        assert_eq!(result.program_name, "ls");
        assert_eq!(result.total_detected, 1);
        assert_eq!(result.severity_summary["high"], 1);
        assert_eq!(result.behaviors[0]["name"], "example_behavior");

        let mut entries = tokio::fs::read_dir(mgr.project_dir(SHA_LS)).await.unwrap();
        let mut leftover = 0;
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("behaviors_") && common::has_json_extension(name) {
                    leftover += 1;
                }
            }
        }
        assert_eq!(
            leftover, 0,
            "best-effort cleanup should remove the per-call output file"
        );
    });
}

#[test]
fn behaviors_failing_runner_returns_headless_failed() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_failing_analyze_headless");
        fake_failing_analyze_headless(&analyze);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let err = scan_behaviors(&ctx, "ls").await.unwrap_err();
        match err {
            BehaviorsError::HeadlessFailed { exit_code, stderr } => {
                assert_eq!(exit_code, Some(9));
                assert!(
                    stderr.contains("simulated ghidra failure"),
                    "stderr was: {stderr}"
                );
            }
            other => panic!("expected HeadlessFailed, got {other:?}"),
        }
    });
}

#[test]
fn behaviors_returns_output_missing_when_runner_writes_nothing() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_silent_analyze_headless");
        fake_silent_analyze_headless(&analyze);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let err = scan_behaviors(&ctx, "ls").await.unwrap_err();
        match err {
            BehaviorsError::OutputMissing { stdout, stderr: _ } => {
                assert!(
                    stdout.contains("silent run"),
                    "stdout should be captured: {stdout}"
                );
            }
            other => panic!("expected OutputMissing, got {other:?}"),
        }
    });
}

#[test]
fn behaviors_propagates_parse_error_for_garbage_envelope() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_garbage_analyze_headless");
        fake_behaviors_analyze_headless(&analyze, "this is not json");

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let err = scan_behaviors(&ctx, "ls").await.unwrap_err();
        assert!(matches!(err, BehaviorsError::Parse { .. }), "{err:?}");

        let mut entries = tokio::fs::read_dir(mgr.project_dir(SHA_LS)).await.unwrap();
        let mut leftover = 0;
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("behaviors_") && common::has_json_extension(name) {
                    leftover += 1;
                }
            }
        }
        assert_eq!(leftover, 0, "cleanup should run even when parsing fails");
    });
}
