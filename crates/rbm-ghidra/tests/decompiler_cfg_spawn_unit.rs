#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rbm_core::CachePaths;
use rbm_ghidra::decompiler_cfg::{DecompilerCfgContext, DecompilerCfgError, gen_decompiler_cfg};
use rbm_ghidra::project::{DECOMPILER_CFG_SCRIPT, ProjectManager};
use tempfile::TempDir;

mod common;
use common::{make_runtime, sample_decompiler_cfg_payload, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fake_analyze_headless(path: &Path, payload: &str) {
    let script = format!(
        "#!/bin/sh\nout=\"\"\nprev=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"decompiler_cfg.java\" ]; then\n    out=\"$arg\"\n    break\n  fi\n  prev=\"$arg\"\ndone\nprintf '%s' '{payload}' > \"$out\"\nexit 0\n"
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
) -> DecompilerCfgContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(DECOMPILER_CFG_SCRIPT), b"// stub").unwrap();
    DecompilerCfgContext {
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
            && name.starts_with("decompiler_cfg_")
            && common::has_json_extension(name)
        {
            leftover += 1;
        }
    }
    assert_eq!(leftover, 0, "cleanup should remove per-call output");
}

#[test]
fn gen_decompiler_cfg_spawns_runner_parses_envelope_and_cleans_up() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_analyze_headless");
        let payload = sample_decompiler_cfg_payload();
        fake_analyze_headless(&analyze, &payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = gen_decompiler_cfg(&ctx, "ls", "main", Some("paramid"), true)
            .await
            .unwrap();

        assert!(result.include_ops);
        assert_eq!(result.simplification_style, "paramid");
        assert_eq!(result.block_count, 2);
        assert_eq!(result.blocks[0].index, 0);
        assert_eq!(result.blocks[0].block_kind, "entry");
        assert_eq!(result.blocks[0].structural_tags[0], "entry");
        assert_eq!(result.blocks[1].block_kind, "exit");
        assert_eq!(result.blocks[0].pcode_op_count, 5);
        assert_eq!(result.blocks[0].first_op_mnemonic, "COPY");
        assert_eq!(result.blocks[0].last_op_mnemonic, "CBRANCH");
        assert_eq!(result.blocks[0].call_count, 1);
        assert_eq!(
            result.blocks[0].callsites_preview[0].target_name,
            "kernel32.dll::CreateFileW"
        );
        assert_eq!(result.blocks[0].memory_access_count, 2);
        assert_eq!(
            result.blocks[0].memory_accesses_preview[0].space_kind,
            "stack"
        );
        assert_eq!(
            result.blocks[0].memory_accesses_preview[1].space_kind,
            "global"
        );
        assert_eq!(result.blocks[0].constant_count, 2);
        assert_eq!(result.blocks[0].constants_preview[0].value_hex, "0x1");
        assert_eq!(
            result.blocks[0].constants_preview[1].source_op_mnemonic,
            "LOAD"
        );
        assert_eq!(result.blocks[0].string_ref_count, 1);
        assert_eq!(
            result.blocks[0].string_refs_preview[0].value,
            "CreateFileW failed"
        );
        assert_eq!(result.blocks[0].pcode_mnemonics_preview[1], "INT_EQUAL");
        assert!(!result.blocks[0].pcode_preview_truncated);
        assert_eq!(result.blocks[0].defs_preview[0], "local_20<unique:0x20:4>");
        assert_eq!(result.blocks[0].uses_preview[0], "RAX<register:0x0:8>");
        assert!(!result.blocks[0].uses_preview_truncated);
        assert_eq!(
            result.blocks[0].instruction_addresses_preview[0],
            "100003a40"
        );
        assert!(!result.blocks[0].instruction_addresses_truncated);
        assert_eq!(result.blocks[0].successor_indices[0], 1);
        assert_eq!(result.blocks[1].predecessor_indices[0], 0);
        assert_eq!(result.blocks[0].ops[0].mnemonic, "COPY");
        assert_eq!(result.blocks[0].ops[1].mnemonic, "CBRANCH");
        assert_eq!(result.blocks[1].ops[0].mnemonic, "RETURN");
        assert_eq!(result.edges[0].label, "false");
        assert_eq!(result.edges[0].branch_kind, "conditional_false");
        assert_eq!(result.edges[0].source_op_mnemonic, "CBRANCH");
        assert_eq!(result.edges[0].source_op_address, "100003a40");
        assert_eq!(result.edges[0].branch_target_preview, "const<const:0x1:1>");
        assert_eq!(result.edges[0].condition_preview, "local_20<unique:0x20:4>");
        assert_eq!(result.edges[0].predicate_mnemonic, "INT_EQUAL");
        assert_eq!(
            result.edges[0].predicate_inputs_preview[0],
            "RAX<register:0x0:8>"
        );
        assert!(result.decompile_completed);
        assert!(result.decompile_valid);

        assert_no_leftover(&mgr, SHA_LS);
    });
}

#[test]
fn gen_decompiler_cfg_returns_resolution_failed_when_envelope_carries_error() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_resolution_failure");
        let payload = r#"{"schema":"rbm.ghidra.decompiler_cfg.v0","query":"__bogus","simplification_style":"decompile","resolved_address":"","resolved_function_name":"","resolution_error":"Function '__bogus' not found.","block_count":0,"edge_count":0,"blocks":[],"edges":[],"decompile_completed":false,"decompile_valid":false,"is_timed_out":false,"is_cancelled":false,"failed_to_start":false,"decompile_error":"","mermaid":"graph TD"}"#;
        fake_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let err = gen_decompiler_cfg(&ctx, "ls", "__bogus", None, false)
            .await
            .unwrap_err();
        match err {
            DecompilerCfgError::ResolutionFailed(msg) => assert!(msg.contains("not found")),
            other => panic!("expected ResolutionFailed, got {other:?}"),
        }
    });
}

#[test]
fn gen_decompiler_cfg_failing_runner_returns_headless_failed() {
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
        let err = gen_decompiler_cfg(&ctx, "ls", "main", None, false)
            .await
            .unwrap_err();
        match err {
            DecompilerCfgError::HeadlessFailed { exit_code, stderr } => {
                assert_eq!(exit_code, Some(9));
                assert!(stderr.contains("simulated ghidra failure"));
            }
            other => panic!("expected HeadlessFailed, got {other:?}"),
        }
    });
}

#[test]
fn gen_decompiler_cfg_returns_output_missing_when_runner_writes_nothing() {
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
        let err = gen_decompiler_cfg(&ctx, "ls", "main", None, false)
            .await
            .unwrap_err();
        match err {
            DecompilerCfgError::OutputMissing { stdout, stderr: _ } => {
                assert!(stdout.contains("silent run"));
            }
            other => panic!("expected OutputMissing, got {other:?}"),
        }
    });
}
