#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rbm_core::CachePaths;
use rbm_ghidra::imports_exports::{
    ImportsExportsContext, ImportsExportsError, list_exports, list_imports,
};
use rbm_ghidra::project::{LIST_EXPORTS_SCRIPT, LIST_IMPORTS_SCRIPT, ProjectManager};
use tempfile::TempDir;

mod common;
use common::{make_runtime, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fake_writing_analyze_headless(path: &Path, payload: &str) {
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
) -> ImportsExportsContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(LIST_EXPORTS_SCRIPT), b"// stub").unwrap();
    std::fs::write(scripts.join(LIST_IMPORTS_SCRIPT), b"// stub").unwrap();
    ImportsExportsContext {
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

async fn count_leftover(manager: &ProjectManager, sha: &str, prefix: &str) -> usize {
    let mut entries = tokio::fs::read_dir(manager.project_dir(sha)).await.unwrap();
    let mut count = 0;
    while let Some(entry) = entries.next_entry().await.unwrap() {
        if let Some(name) = entry.file_name().to_str()
            && name.starts_with(prefix)
            && common::has_json_extension(name)
        {
            count += 1;
        }
    }
    count
}

#[test]
fn list_exports_spawns_runner_parses_envelope_and_cleans_up() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_writing_analyze_headless");
        let payload = r#"{"schema":"rbm.ghidra.list_exports.v0","query":".*","offset":0,"limit":25,"total_matched":2,"error_count":0,"exports":[{"name":"main","address":"0x100003a40"},{"name":"_start","address":"0x100003800"}]}"#;
        fake_writing_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = list_exports(&ctx, "ls", None, None, None).await.unwrap();

        assert_eq!(result.schema, "rbm.ghidra.list_exports.v0");
        assert_eq!(result.cache_key, format!("sha256:{SHA_LS}"));
        assert_eq!(result.sha256, SHA_LS);
        assert_eq!(result.program_name, "ls");
        assert_eq!(result.query, ".*");
        assert_eq!(result.offset, 0);
        assert_eq!(result.limit, 25);
        assert_eq!(result.total_matched, 2);
        assert_eq!(result.error_count, 0);
        assert_eq!(result.exports.len(), 2);
        assert_eq!(result.exports[0].name, "main");
        assert_eq!(result.exports[0].address, "0x100003a40");
        assert_eq!(result.exports[1].name, "_start");
        assert_eq!(result.exports[1].address, "0x100003800");

        assert_eq!(
            count_leftover(&mgr, SHA_LS, "exports_").await,
            0,
            "best-effort cleanup should remove the per-call output file"
        );
    });
}

#[test]
fn list_imports_spawns_runner_parses_envelope_and_cleans_up() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_writing_analyze_headless");
        let payload = r#"{"schema":"rbm.ghidra.list_imports.v0","query":".*","offset":0,"limit":25,"total_matched":2,"error_count":0,"imports":[{"name":"printf","address":"0x1000","library":"libc.so.6","xref_count":3},{"name":"malloc","address":"0x1010","library":"libc.so.6","xref_count":1}]}"#;
        fake_writing_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = list_imports(&ctx, "ls", None, None, None).await.unwrap();

        assert_eq!(result.schema, "rbm.ghidra.list_imports.v0");
        assert_eq!(result.cache_key, format!("sha256:{SHA_LS}"));
        assert_eq!(result.sha256, SHA_LS);
        assert_eq!(result.program_name, "ls");
        assert_eq!(result.query, ".*");
        assert_eq!(result.offset, 0);
        assert_eq!(result.limit, 25);
        assert_eq!(result.total_matched, 2);
        assert_eq!(result.error_count, 0);
        assert_eq!(result.imports.len(), 2);
        assert_eq!(result.imports[0].name, "printf");
        assert_eq!(result.imports[0].library, "libc.so.6");
        assert_eq!(result.imports[1].name, "malloc");
        assert_eq!(result.imports[1].library, "libc.so.6");

        assert_eq!(
            count_leftover(&mgr, SHA_LS, "imports_").await,
            0,
            "best-effort cleanup should remove the per-call output file"
        );
    });
}

#[test]
fn list_exports_failing_runner_returns_headless_failed() {
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
        let err = list_exports(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        match err {
            ImportsExportsError::HeadlessFailed { exit_code, stderr } => {
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
fn list_imports_returns_output_missing_when_runner_writes_nothing() {
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
        let err = list_imports(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        match err {
            ImportsExportsError::OutputMissing { stdout, stderr: _ } => {
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
fn list_exports_propagates_parse_error_for_garbage_envelope() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_garbage_analyze_headless");
        fake_writing_analyze_headless(&analyze, "this is not json");

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let err = list_exports(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, ImportsExportsError::Parse { .. }), "{err:?}");

        assert_eq!(
            count_leftover(&mgr, SHA_LS, "exports_").await,
            0,
            "cleanup should run even when parsing fails"
        );
    });
}
