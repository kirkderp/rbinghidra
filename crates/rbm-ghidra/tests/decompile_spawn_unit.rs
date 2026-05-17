#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rbm_core::CachePaths;
use rbm_ghidra::decompile::{DecompileContext, DecompileError, decompile_function};
use rbm_ghidra::project::{DECOMPILE_FUNCTION_SCRIPT, ProjectManager};
use tempfile::TempDir;

mod common;
use common::{make_runtime, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fake_decompile_analyze_headless(path: &Path, payload: &str) {
    let script = format!(
        "#!/bin/sh\nout=\"\"\nprev=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"decompile_function.java\" ]; then\n    out=\"$arg\"\n    break\n  fi\n  prev=\"$arg\"\ndone\nprintf '%s' '{payload}' > \"$out\"\nexit 0\n"
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
) -> DecompileContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(DECOMPILE_FUNCTION_SCRIPT), b"// stub").unwrap();
    DecompileContext {
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
fn decompile_function_spawns_runner_parses_envelope_and_cleans_up() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_analyze_headless");
        let payload = r#"{"schema":"rbm.ghidra.decompile_function.v0","query":"main","simplification_style":"normalize","function_name":"main","address":"0x100003a40","signature":"int main(int, char **)","decompiler_signature":"int main(int argc, char **argv)","pseudocode":"int main(int argc, char **argv) { return 0; }","callers":["_start"],"callees":["puts","exit"],"caller_details":[{"name":"_start","address":"0x100000000","is_external":false,"is_thunk":false}],"callee_details":[{"name":"puts","address":"EXTERNAL:00000000","is_external":true,"is_thunk":true},{"name":"exit","address":"EXTERNAL:00000010","is_external":true,"is_thunk":true}],"basic_block_count":3,"decompile_completed":true,"decompile_valid":true,"is_timed_out":false,"is_cancelled":false,"failed_to_start":false,"decompile_error":""}"#;
        fake_decompile_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = decompile_function(&ctx, "ls", "main", Some("normalize"))
            .await
            .unwrap();

        assert_eq!(result.schema, "rbm.ghidra.decompile_function.v0");
        assert_eq!(result.cache_key, format!("sha256:{SHA_LS}"));
        assert_eq!(result.sha256, SHA_LS);
        assert_eq!(result.program_name, "ls");
        assert_eq!(result.function_name, "main");
        assert_eq!(result.address, "0x100003a40");
        assert_eq!(result.query, "main");
        assert_eq!(result.simplification_style, "normalize");
        assert_eq!(result.signature, "int main(int, char **)");
        assert_eq!(result.decompiler_signature, "int main(int argc, char **argv)");
        assert!(result.pseudocode.contains("return 0"));
        assert_eq!(result.callers, vec!["_start".to_string()]);
        assert_eq!(result.callees, vec!["puts".to_string(), "exit".to_string()]);
        assert_eq!(result.caller_details.len(), 1);
        assert_eq!(result.caller_details[0].name, "_start");
        assert!(!result.caller_details[0].is_external);
        assert_eq!(result.callee_details.len(), 2);
        assert_eq!(result.callee_details[0].name, "puts");
        assert!(result.callee_details[0].is_external);
        assert!(result.callee_details[0].is_thunk);
        assert_eq!(result.basic_block_count, 3);
        assert!(result.decompile_completed);
        assert!(result.decompile_valid);
        assert!(!result.is_timed_out);
        assert!(!result.is_cancelled);
        assert!(!result.failed_to_start);
        assert_eq!(result.decompile_error, "");

        let mut entries = tokio::fs::read_dir(mgr.project_dir(SHA_LS)).await.unwrap();
        let mut leftover_decompile_files = 0;
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if let Some(name) = entry.file_name().to_str()
                && name.starts_with("decompile_")
                && common::has_json_extension(name)
            {
                leftover_decompile_files += 1;
            }
        }
        assert_eq!(
            leftover_decompile_files, 0,
            "best-effort cleanup should remove the per-call output file"
        );
    });
}

#[test]
fn decompile_function_failing_runner_returns_headless_failed() {
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
        let err = decompile_function(&ctx, "ls", "main", None)
            .await
            .unwrap_err();
        match err {
            DecompileError::HeadlessFailed { exit_code, stderr } => {
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
fn decompile_function_returns_output_missing_when_runner_writes_nothing() {
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
        let err = decompile_function(&ctx, "ls", "main", None)
            .await
            .unwrap_err();
        match err {
            DecompileError::OutputMissing { stdout, stderr: _ } => {
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
fn decompile_function_propagates_parse_error_for_garbage_envelope() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_garbage_analyze_headless");
        fake_decompile_analyze_headless(&analyze, "this is not json");

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let err = decompile_function(&ctx, "ls", "main", None)
            .await
            .unwrap_err();
        assert!(matches!(err, DecompileError::Parse { .. }), "{err:?}");

        let mut entries = tokio::fs::read_dir(mgr.project_dir(SHA_LS)).await.unwrap();
        let mut leftover = 0;
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if let Some(name) = entry.file_name().to_str()
                && name.starts_with("decompile_")
                && common::has_json_extension(name)
            {
                leftover += 1;
            }
        }
        assert_eq!(leftover, 0, "cleanup should run even when parsing fails");
    });
}
