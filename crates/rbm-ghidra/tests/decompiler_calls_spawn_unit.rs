#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rbm_core::CachePaths;
use rbm_ghidra::decompiler_calls::{
    DecompilerCallsContext, DecompilerCallsFilter, get_decompiler_calls,
};
use rbm_ghidra::decompiler_cfg::DecompilerCfgError;
use rbm_ghidra::project::{DECOMPILER_CALLS_SCRIPT, ProjectManager};
use tempfile::TempDir;

mod common;
use common::{make_runtime, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fake_analyze_headless(path: &Path, payload: &str) {
    let script = format!(
        "#!/bin/sh\nout=\"\"\nprev=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"decompiler_calls.java\" ]; then\n    out=\"$arg\"\n    break\n  fi\n  prev=\"$arg\"\ndone\nprintf '%s' '{payload}' > \"$out\"\nexit 0\n"
    );
    write_executable(path, &script);
}

fn fake_failing_analyze_headless(path: &Path) {
    write_executable(path, "#!/bin/sh\necho 'calls boom' >&2\nexit 8\n");
}

fn fake_silent_analyze_headless(path: &Path) {
    write_executable(path, "#!/bin/sh\nexit 0\n");
}

fn make_ctx(
    tmp: &TempDir,
    manager: Arc<ProjectManager>,
    analyze_headless: PathBuf,
) -> DecompilerCallsContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(DECOMPILER_CALLS_SCRIPT), b"// stub").unwrap();
    DecompilerCallsContext {
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
fn get_decompiler_calls_spawns_runner_parses_envelope_and_sorts_targets() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_analyze_headless");
        let payload = r#"{"schema":"rbm.ghidra.decompiler_calls.v0","source_schema":"rbm.ghidra.decompiler_cfg.v0","query":"main","simplification_style":"decompile","resolved_address":"100003a40","resolved_function_name":"Global::main","source_block_count":2,"matched_block_count":1,"total_call_count":1,"total_internal_call_count":0,"total_external_callsite_count":1,"total_indirect_call_count":0,"total_thunk_call_count":0,"blocks":[{"index":8,"start":"100003a40","stop":"100003a48","block_kind":"conditional","structural_tags":["branch","conditional"],"instruction_addresses_preview":["100003a40"],"instruction_addresses_truncated":false,"call_count":1,"callsites_preview":[{"mnemonic":"CALL","op_address":"100003a44","target_name":"kernel32.dll::CreateFileW","target_address":"180012340","target_preview":"ram:180012340","module_name":"kernel32.dll","api_family":"process","api_tag":"file","is_external":true,"is_thunk":false,"is_indirect":false}],"callsites_preview_truncated":false,"internal_call_count":0,"external_callsite_count":1,"indirect_call_count":0,"thunk_call_count":0,"call_target_count":2,"call_targets":["zeta","alpha"],"call_targets_truncated":false,"internal_call_target_count":0,"internal_call_targets":[],"internal_call_targets_truncated":false,"external_call_target_count":2,"external_call_targets":["zeta","alpha"],"external_call_targets_truncated":false}],"decompile_completed":true,"decompile_valid":true,"is_timed_out":false,"is_cancelled":false,"failed_to_start":false,"decompile_error":"","resolution_error":""}"#;
        fake_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = get_decompiler_calls(
            &ctx,
            "ls",
            "main",
            Some("decompile"),
            &DecompilerCallsFilter {
                only_external: true,
                only_indirect: false,
                only_api_tag: Some("file".to_string()),
            },
        )
        .await
        .unwrap();

        assert_eq!(result.query, "main");
        assert_eq!(result.source_block_count, 2);
        assert_eq!(result.matched_block_count, 1);
        assert_eq!(result.total_external_callsite_count, 1);
        assert_eq!(result.blocks[0].call_targets[0], "alpha");
        assert_eq!(result.blocks[0].call_targets[1], "zeta");
        assert_eq!(result.blocks[0].external_call_targets[0], "alpha");
        assert_eq!(result.blocks[0].external_call_targets[1], "zeta");
    });
}

#[test]
fn get_decompiler_calls_failing_runner_returns_headless_failed() {
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
        let err = get_decompiler_calls(&ctx, "ls", "main", None, &DecompilerCallsFilter::default())
            .await
            .unwrap_err();
        match err {
            DecompilerCfgError::HeadlessFailed { exit_code, stderr } => {
                assert_eq!(exit_code, Some(8));
                assert!(stderr.contains("calls boom"));
            }
            other => panic!("expected HeadlessFailed, got {other:?}"),
        }
    });
}

#[test]
fn get_decompiler_calls_returns_output_missing_when_runner_writes_nothing() {
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
        let err = get_decompiler_calls(&ctx, "ls", "main", None, &DecompilerCallsFilter::default())
            .await
            .unwrap_err();
        match err {
            DecompilerCfgError::OutputMissing { stdout, stderr: _ } => {
                assert!(stdout.is_empty());
            }
            other => panic!("expected OutputMissing, got {other:?}"),
        }
    });
}
