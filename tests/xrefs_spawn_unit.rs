#![cfg(unix)]

#[path = "support/tempfile.rs"]
mod tempfile;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rbinghidra::CachePaths;
use rbinghidra::project::{LIST_XREFS_SCRIPT, ProjectManager};
use rbinghidra::xrefs::{XrefsContext, XrefsError, list_xrefs};
use tempfile::TempDir;

mod common;
use common::{make_runtime, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fake_xrefs_analyze_headless(path: &Path, payload: &str) {
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
) -> XrefsContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(LIST_XREFS_SCRIPT), b"// stub").unwrap();
    XrefsContext {
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
fn list_xrefs_spawns_runner_parses_envelope_and_cleans_up() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_analyze_headless");
        let payload = r#"{"schema":"rbm.ghidra.list_xrefs.v0","query":"main","direction":"to","resolved_address":"0x100003a40","resolved_symbol_name":"Global::main","resolution_error":"","offset":0,"limit":25,"total_matched":2,"error_count":0,"xrefs":[{"from_address":"0x1001","to_address":"0x100003a40","ref_type":"UNCONDITIONAL_CALL","function_name":"_start"},{"from_address":"0x1020","to_address":"0x100003a40","ref_type":"DATA","function_name":""}]}"#;
        fake_xrefs_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = list_xrefs(&ctx, "ls", "main", None, None, None).await.unwrap();

        assert_eq!(result.schema, "rbm.ghidra.list_xrefs.v0");
        assert_eq!(result.cache_key, format!("sha256:{SHA_LS}"));
        assert_eq!(result.sha256, SHA_LS);
        assert_eq!(result.program_name, "ls");
        assert_eq!(result.query, "main");
        assert_eq!(result.direction, "to");
        assert_eq!(result.resolved_address, "0x100003a40");
        assert_eq!(result.resolved_symbol_name, "Global::main");
        assert_eq!(result.offset, 0);
        assert_eq!(result.limit, 25);
        assert_eq!(result.total_matched, 2);
        assert_eq!(result.error_count, 0);
        assert_eq!(result.xrefs.len(), 2);
        assert_eq!(result.xrefs[0].from_address, "0x1001");
        assert_eq!(result.xrefs[0].to_address, "0x100003a40");
        assert_eq!(result.xrefs[0].ref_type, "UNCONDITIONAL_CALL");
        assert_eq!(result.xrefs[0].function_name, "_start");
        assert_eq!(result.xrefs[1].function_name, "");

        let mut entries = tokio::fs::read_dir(mgr.project_dir(SHA_LS)).await.unwrap();
        let mut leftover = 0;
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if let Some(name) = entry.file_name().to_str()
                && name.starts_with("xrefs_")
                && common::has_json_extension(name)
            {
                leftover += 1;
            }
        }
        assert_eq!(
            leftover, 0,
            "best-effort cleanup should remove the per-call output file"
        );
    });
}

#[test]
fn list_xrefs_returns_resolution_failed_when_envelope_carries_error() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_resolution_failure");
        let payload = r#"{"schema":"rbm.ghidra.list_xrefs.v0","query":"bogus","resolved_address":"","resolved_symbol_name":"","resolution_error":"Symbol bogus not found.","offset":0,"limit":25,"total_matched":0,"error_count":0,"xrefs":[]}"#;
        fake_xrefs_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let err = list_xrefs(&ctx, "ls", "bogus", None, None, None)
            .await
            .unwrap_err();
        match err {
            XrefsError::ResolutionFailed(msg) => {
                assert!(
                    msg.contains("Symbol bogus not found"),
                    "unexpected resolution error: {msg}"
                );
            }
            other => panic!("expected ResolutionFailed, got {other:?}"),
        }

        let mut entries = tokio::fs::read_dir(mgr.project_dir(SHA_LS)).await.unwrap();
        let mut leftover = 0;
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if let Some(name) = entry.file_name().to_str()
                && name.starts_with("xrefs_")
                && common::has_json_extension(name)
            {
                leftover += 1;
            }
        }
        assert_eq!(
            leftover, 0,
            "cleanup should run even when resolution fails"
        );
    });
}

#[test]
fn list_xrefs_failing_runner_returns_headless_failed() {
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
        let err = list_xrefs(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        match err {
            XrefsError::HeadlessFailed { exit_code, stderr } => {
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
fn list_xrefs_returns_output_missing_when_runner_writes_nothing() {
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
        let err = list_xrefs(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        match err {
            XrefsError::OutputMissing { stdout, stderr: _ } => {
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
fn list_xrefs_propagates_parse_error_for_garbage_envelope() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_garbage_analyze_headless");
        fake_xrefs_analyze_headless(&analyze, "this is not json");

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let err = list_xrefs(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, XrefsError::Parse { .. }), "{err:?}");

        let mut entries = tokio::fs::read_dir(mgr.project_dir(SHA_LS)).await.unwrap();
        let mut leftover = 0;
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if let Some(name) = entry.file_name().to_str()
                && name.starts_with("xrefs_")
                && common::has_json_extension(name)
            {
                leftover += 1;
            }
        }
        assert_eq!(leftover, 0, "cleanup should run even when parsing fails");
    });
}
