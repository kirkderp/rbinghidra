#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rbm_core::CachePaths;
use rbm_ghidra::cfg::{CfgContext, CfgError, gen_cfg};
use rbm_ghidra::project::{CFG_SCRIPT, ProjectManager};
use tempfile::TempDir;

mod common;
use common::{make_runtime, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fake_cfg_analyze_headless(path: &Path, payload: &str) {
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

fn make_ctx(tmp: &TempDir, manager: Arc<ProjectManager>, analyze_headless: PathBuf) -> CfgContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(CFG_SCRIPT), b"// stub").unwrap();
    CfgContext {
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

fn assert_no_leftover(manager: &ProjectManager, sha: &str) {
    let dir = manager.project_dir(sha);
    let mut leftover = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if let Some(name) = entry.file_name().to_str()
            && name.starts_with("cfg_")
            && common::has_json_extension(name)
        {
            leftover += 1;
        }
    }
    assert_eq!(
        leftover, 0,
        "best-effort cleanup should remove the per-call output file"
    );
}

#[test]
fn gen_cfg_spawns_runner_parses_envelope_and_cleans_up() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_analyze_headless");
        let payload = r#"{"schema":"rbm.ghidra.cfg.v0","query":"main","resolved_address":"100003a40","resolved_function_name":"Global::main","resolution_error":"","block_count":2,"edge_count":1,"blocks":[{"address":"100003a40","size":16,"instructions":4},{"address":"100003a50","size":8,"instructions":2}],"edges":[{"from":"100003a40","to":"100003a50","flow_type":"CONDITIONAL_JUMP"}],"mermaid":"graph TD\n  b0[\"100003a40\"]\n  b1[\"100003a50\"]\n  b0 --> b1\n"}"#;
        fake_cfg_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = gen_cfg(&ctx, "ls", "main").await.unwrap();

        assert_eq!(result.schema, "rbm.ghidra.cfg.v0");
        assert_eq!(result.cache_key, format!("sha256:{SHA_LS}"));
        assert_eq!(result.sha256, SHA_LS);
        assert_eq!(result.program_name, "ls");
        assert_eq!(result.query, "main");
        assert_eq!(result.resolved_address, "100003a40");
        assert_eq!(result.resolved_function_name, "Global::main");
        assert_eq!(result.block_count, 2);
        assert_eq!(result.edge_count, 1);
        assert_eq!(result.blocks.len(), 2);
        assert_eq!(result.blocks[0].address, "100003a40");
        assert_eq!(result.blocks[0].size, 16);
        assert_eq!(result.blocks[0].instructions, 4);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].from, "100003a40");
        assert_eq!(result.edges[0].to, "100003a50");
        assert_eq!(result.edges[0].flow_type, "CONDITIONAL_JUMP");
        assert!(result.mermaid.starts_with("graph TD"));

        assert_no_leftover(&mgr, SHA_LS);
    });
}

#[test]
fn gen_cfg_returns_resolution_failed_when_envelope_carries_error() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_resolution_failure");
        let payload = r#"{"schema":"rbm.ghidra.cfg.v0","query":"__bogus","resolved_address":"","resolved_function_name":"","resolution_error":"Function '__bogus' not found.","block_count":0,"edge_count":0,"blocks":[],"edges":[],"mermaid":"graph TD"}"#;
        fake_cfg_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let err = gen_cfg(&ctx, "ls", "__bogus").await.unwrap_err();
        match err {
            CfgError::ResolutionFailed(msg) => {
                assert!(msg.contains("not found"), "unexpected message: {msg}");
            }
            other => panic!("expected ResolutionFailed, got {other:?}"),
        }

        assert_no_leftover(&mgr, SHA_LS);
    });
}

#[test]
fn gen_cfg_round_trips_empty_cfg_envelope() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_empty_cfg");
        let payload = r#"{"schema":"rbm.ghidra.cfg.v0","query":"thunk","resolved_address":"100000000","resolved_function_name":"thunk","resolution_error":"","block_count":0,"edge_count":0,"blocks":[],"edges":[],"mermaid":"graph TD"}"#;
        fake_cfg_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = gen_cfg(&ctx, "ls", "thunk").await.unwrap();

        assert_eq!(result.block_count, 0);
        assert_eq!(result.edge_count, 0);
        assert!(result.blocks.is_empty());
        assert!(result.edges.is_empty());
        assert_eq!(result.mermaid, "graph TD");
    });
}

#[test]
fn gen_cfg_failing_runner_returns_headless_failed() {
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
        let err = gen_cfg(&ctx, "ls", "main").await.unwrap_err();
        match err {
            CfgError::HeadlessFailed { exit_code, stderr } => {
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
fn gen_cfg_returns_output_missing_when_runner_writes_nothing() {
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
        let err = gen_cfg(&ctx, "ls", "main").await.unwrap_err();
        match err {
            CfgError::OutputMissing { stdout, stderr: _ } => {
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
fn gen_cfg_propagates_parse_error_for_garbage_envelope() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_garbage_analyze_headless");
        fake_cfg_analyze_headless(&analyze, "this is not json");

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let err = gen_cfg(&ctx, "ls", "main").await.unwrap_err();
        assert!(matches!(err, CfgError::Parse { .. }), "{err:?}");

        assert_no_leftover(&mgr, SHA_LS);
    });
}
