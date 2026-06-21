#![cfg(unix)]

#[path = "support/tempfile.rs"]
mod tempfile;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rbinghidra::CachePaths;
use rbinghidra::decompiler_cfg::DecompilerCfgError;
use rbinghidra::decompiler_memory::{
    DecompilerMemoryContext, DecompilerMemoryFilter, get_decompiler_memory,
};
use rbinghidra::project::{DECOMPILER_MEMORY_SCRIPT, ProjectManager};
use tempfile::TempDir;

mod common;
use common::{make_runtime, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fake_analyze_headless(path: &Path, payload: &str) {
    let script = format!(
        "#!/bin/sh\nout=\"\"\nprev=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"decompiler_memory.java\" ]; then\n    out=\"$arg\"\n    break\n  fi\n  prev=\"$arg\"\ndone\nprintf '%s' '{payload}' > \"$out\"\nexit 0\n"
    );
    write_executable(path, &script);
}

fn fake_failing_analyze_headless(path: &Path) {
    write_executable(path, "#!/bin/sh\necho 'memory boom' >&2\nexit 9\n");
}

fn fake_silent_analyze_headless(path: &Path) {
    write_executable(path, "#!/bin/sh\nexit 0\n");
}

fn make_ctx(
    tmp: &TempDir,
    manager: Arc<ProjectManager>,
    analyze_headless: PathBuf,
) -> DecompilerMemoryContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(DECOMPILER_MEMORY_SCRIPT), b"// stub").unwrap();
    DecompilerMemoryContext {
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
fn get_decompiler_memory_spawns_runner_parses_envelope() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_analyze_headless");
        let payload = r#"{"schema":"rbm.ghidra.decompiler_memory.v0","source_schema":"rbm.ghidra.decompiler_cfg.v0","query":"main","simplification_style":"decompile","resolved_address":"100003a40","resolved_function_name":"Global::main","source_block_count":3,"matched_block_count":1,"total_memory_access_count":2,"total_memory_read_count":1,"total_memory_write_count":1,"blocks":[{"index":4,"start":"100003a40","stop":"100003a48","block_kind":"read_write","structural_tags":["memory_read","memory_write"],"instruction_addresses_preview":["100003a40","100003a44"],"instruction_addresses_truncated":false,"memory_access_count":2,"memory_accesses_preview":[{"access_kind":"read","op_address":"100003a40","address_preview":"stack:0x20:8","value_preview":"rax","space_kind":"stack"},{"access_kind":"write","op_address":"100003a44","address_preview":"ram:0x180001000:8","value_preview":"rcx","space_kind":"ram"}],"memory_accesses_preview_truncated":false,"memory_read_count":1,"memory_write_count":1}],"decompile_completed":true,"decompile_valid":true,"is_timed_out":false,"is_cancelled":false,"failed_to_start":false,"decompile_error":"","resolution_error":""}"#;
        fake_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = get_decompiler_memory(
            &ctx,
            "ls",
            "main",
            Some("decompile"),
            &DecompilerMemoryFilter { only_writes: true },
        )
        .await
        .unwrap();

        assert_eq!(result.source_block_count, 3);
        assert_eq!(result.matched_block_count, 1);
        assert_eq!(result.total_memory_access_count, 2);
        assert_eq!(result.total_memory_write_count, 1);
        assert_eq!(result.blocks[0].block_kind, "read_write");
    });
}

#[test]
fn get_decompiler_memory_failing_runner_returns_headless_failed() {
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
        let err =
            get_decompiler_memory(&ctx, "ls", "main", None, &DecompilerMemoryFilter::default())
                .await
                .unwrap_err();
        match err {
            DecompilerCfgError::HeadlessFailed { exit_code, stderr } => {
                assert_eq!(exit_code, Some(9));
                assert!(stderr.contains("memory boom"));
            }
            other => panic!("expected HeadlessFailed, got {other:?}"),
        }
    });
}

#[test]
fn get_decompiler_memory_returns_output_missing_when_runner_writes_nothing() {
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
        let err =
            get_decompiler_memory(&ctx, "ls", "main", None, &DecompilerMemoryFilter::default())
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
