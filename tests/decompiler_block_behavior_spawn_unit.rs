#![cfg(unix)]

#[path = "support/tempfile.rs"]
mod tempfile;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rbinghidra::CachePaths;
use rbinghidra::decompiler_block_behavior::{
    DecompilerBlockBehaviorContext, DecompilerBlockBehaviorFilter, get_decompiler_block_behavior,
};
use rbinghidra::decompiler_cfg::DecompilerCfgError;
use rbinghidra::project::{DECOMPILER_BLOCK_BEHAVIOR_SCRIPT, ProjectManager};
use tempfile::TempDir;

mod common;
use common::{make_runtime, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fake_analyze_headless(path: &Path, payload: &str) {
    let script = format!(
        "#!/bin/sh\nout=\"\"\nprev=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"decompiler_block_behavior.java\" ]; then\n    out=\"$arg\"\n    break\n  fi\n  prev=\"$arg\"\ndone\nprintf '%s' '{payload}' > \"$out\"\nexit 0\n"
    );
    write_executable(path, &script);
}

fn fake_failing_analyze_headless(path: &Path) {
    write_executable(path, "#!/bin/sh\necho 'behavior boom' >&2\nexit 11\n");
}

fn fake_silent_analyze_headless(path: &Path) {
    write_executable(path, "#!/bin/sh\nexit 0\n");
}

fn make_ctx(
    tmp: &TempDir,
    manager: Arc<ProjectManager>,
    analyze_headless: PathBuf,
) -> DecompilerBlockBehaviorContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(DECOMPILER_BLOCK_BEHAVIOR_SCRIPT), b"// stub").unwrap();
    DecompilerBlockBehaviorContext {
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
fn get_decompiler_block_behavior_spawns_runner_parses_envelope_and_sorts_fields() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_analyze_headless");
        let payload = r#"{"schema":"rbm.ghidra.decompiler_block_behavior.v0","source_schema":"rbm.ghidra.decompiler_cfg.v0","query":"main","simplification_style":"decompile","resolved_address":"100003a40","resolved_function_name":"Global::main","block_count":1,"total_conditional_edge_count":1,"total_flow_edge_count":0,"total_back_edge_count":0,"blocks":[{"index":8,"start":"100003a40","stop":"100003a48","block_kind":"conditional","structural_tags":["branch","conditional"],"predecessor_indices":[1],"successor_indices":[2,3],"incoming_edges":1,"outgoing_edges":2,"conditional_edge_count":1,"flow_edge_count":0,"back_edge_count":0,"module_count":3,"modules":["user32.dll","kernel32.dll","kernel32.dll"],"api_family_count":2,"api_families":["ui","process"],"api_tag_count":2,"api_tags":["timing","file"],"external_call_count":1,"external_address_ref_count":0,"external_symbol_count":3,"external_symbols":["Zeta","Alpha","Alpha"],"external_symbols_truncated":false,"constant_count":1,"constants_preview":[{"value_hex":"0x1","size_bytes":1,"source_op_mnemonic":"INT_EQUAL"}],"constants_preview_truncated":false,"string_ref_count":1,"string_refs_preview":[{"value":"hello","address":"180030000","source_op_mnemonic":"CALL"}],"string_refs_preview_truncated":false}],"decompile_completed":true,"decompile_valid":true,"is_timed_out":false,"is_cancelled":false,"failed_to_start":false,"decompile_error":"","resolution_error":""}"#;
        fake_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = get_decompiler_block_behavior(
            &ctx,
            "ls",
            "main",
            Some("decompile"),
            &DecompilerBlockBehaviorFilter {
                only_strings: true,
                only_api_tag: Some("file".to_string()),
                only_external: true,
            },
        )
        .await
        .unwrap();

        assert_eq!(result.block_count, 1);
        assert_eq!(result.blocks[0].modules[0], "kernel32.dll");
        assert_eq!(result.blocks[0].modules[1], "user32.dll");
        assert_eq!(result.blocks[0].api_tags[0], "file");
        assert_eq!(result.blocks[0].api_tags[1], "timing");
        assert_eq!(result.blocks[0].external_symbols[0], "Alpha");
        assert_eq!(result.blocks[0].external_symbols[1], "Zeta");
    });
}

#[test]
fn get_decompiler_block_behavior_failing_runner_returns_headless_failed() {
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
        let err = get_decompiler_block_behavior(
            &ctx,
            "ls",
            "main",
            None,
            &DecompilerBlockBehaviorFilter::default(),
        )
        .await
        .unwrap_err();
        match err {
            DecompilerCfgError::HeadlessFailed { exit_code, stderr } => {
                assert_eq!(exit_code, Some(11));
                assert!(stderr.contains("behavior boom"));
            }
            other => panic!("expected HeadlessFailed, got {other:?}"),
        }
    });
}

#[test]
fn get_decompiler_block_behavior_returns_output_missing_when_runner_writes_nothing() {
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
        let err = get_decompiler_block_behavior(
            &ctx,
            "ls",
            "main",
            None,
            &DecompilerBlockBehaviorFilter::default(),
        )
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
