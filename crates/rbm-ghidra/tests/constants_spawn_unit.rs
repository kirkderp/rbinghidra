#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rbm_core::CachePaths;
use rbm_ghidra::constants::{ConstantsContext, ConstantsError, ConstantsOptions, scan_constants};
use rbm_ghidra::inspect::InspectError;
use rbm_ghidra::project::PathValidationError;
use rbm_ghidra::project::{CONSTANTS_SCRIPT, ProjectManager};
use tempfile::TempDir;

mod common;
use common::{make_runtime, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn fake_constants_analyze_headless(path: &Path, payload: &str) {
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
) -> ConstantsContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(CONSTANTS_SCRIPT), b"// stub").unwrap();
    ConstantsContext {
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
#[allow(clippy::collapsible_if)]
fn scan_constants_spawns_runner_parses_envelope_and_cleans_up() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_analyze_headless");
        let payload = r#"{"schema":"rbm.ghidra.constants.v0","mode":"common","value":"","min_value":"","max_value":"","include_small_values":false,"limit":100,"instructions_scanned":1000,"total_matched":1,"error_count":0,"constants":[{"value":"42","hex_value":"0x2a","count":1,"sample_locations":[{"address":"0x1000","function_name":"main","mnemonic":"MOV","operand_index":1,"disassembly":"MOV RAX, 0x2a"}]}]}"#;
        fake_constants_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = scan_constants(&ctx, "ls", ConstantsOptions::default())
            .await
            .unwrap();

        assert_eq!(result.schema, "rbm.ghidra.constants.v0");
        assert_eq!(result.cache_key, format!("sha256:{SHA_LS}"));
        assert_eq!(result.sha256, SHA_LS);
        assert_eq!(result.program_name, "ls");
        assert_eq!(result.mode, "common");
        assert_eq!(result.limit, 100);
        assert_eq!(result.total_matched, 1);
        assert_eq!(result.error_count, 0);
        assert_eq!(result.constants.len(), 1);
        assert_eq!(result.constants[0].value, "42");
        assert_eq!(result.constants[0].hex_value, "0x2a");

        let mut entries = tokio::fs::read_dir(mgr.project_dir(SHA_LS)).await.unwrap();
        let mut leftover = 0;
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("constants_") && common::has_json_extension(name) {
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
fn scan_constants_failing_runner_returns_headless_failed() {
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
        let err = scan_constants(&ctx, "ls", ConstantsOptions::default())
            .await
            .unwrap_err();
        match err {
            ConstantsError::HeadlessFailed { exit_code, stderr } => {
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
fn scan_constants_returns_output_missing_when_runner_writes_nothing() {
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
        let err = scan_constants(&ctx, "ls", ConstantsOptions::default())
            .await
            .unwrap_err();
        match err {
            ConstantsError::OutputMissing { stdout, stderr: _ } => {
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
#[allow(clippy::collapsible_if)]
fn scan_constants_propagates_parse_error_for_garbage_envelope() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_garbage_analyze_headless");
        fake_constants_analyze_headless(&analyze, "this is not json");

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let err = scan_constants(&ctx, "ls", ConstantsOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, ConstantsError::Parse { .. }), "{err:?}");

        let mut entries = tokio::fs::read_dir(mgr.project_dir(SHA_LS)).await.unwrap();
        let mut leftover = 0;
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("constants_") && common::has_json_extension(name) {
                    leftover += 1;
                }
            }
        }
        assert_eq!(leftover, 0, "cleanup should run even when parsing fails");
    });
}

#[test]
fn scan_constants_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));
        let mut ctx = make_ctx(&tmp, mgr.clone(), tmp.path().join("analyzeHeadless"));
        ctx.scripts_dir = tmp.path().join("does-not-exist");

        let err = scan_constants(&ctx, "ls", ConstantsOptions::default())
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ConstantsError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn scan_constants_rejects_missing_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));
        let mut ctx = make_ctx(&tmp, mgr.clone(), tmp.path().join("analyzeHeadless"));

        let scripts = tmp.path().join("scripts-empty");
        std::fs::create_dir_all(&scripts).unwrap();
        ctx.scripts_dir = scripts;

        let err = scan_constants(&ctx, "ls", ConstantsOptions::default())
            .await
            .unwrap_err();
        match err {
            ConstantsError::PathValidation(PathValidationError::ScriptMissing {
                script, ..
            }) => {
                assert_eq!(script, CONSTANTS_SCRIPT);
            }
            other => panic!("expected PathValidation::ScriptMissing, got {other:?}"),
        }
    });
}

#[test]
fn scan_constants_rejects_missing_analyze_headless() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));
        let ctx = make_ctx(&tmp, mgr.clone(), tmp.path().join("does-not-exist"));

        let err = scan_constants(&ctx, "ls", ConstantsOptions::default())
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ConstantsError::PathValidation(PathValidationError::AnalyzeHeadlessMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn scan_constants_returns_inspect_not_found_for_unknown_binary() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));
        let analyze = tmp.path().join("analyzeHeadless");
        std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
        let ctx = make_ctx(&tmp, mgr.clone(), analyze);

        let err = scan_constants(&ctx, "missing", ConstantsOptions::default())
            .await
            .unwrap_err();
        assert!(
            matches!(err, ConstantsError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn scan_constants_propagates_ambiguous_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));
        let analyze = tmp.path().join("analyzeHeadless");
        std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
        let ctx = make_ctx(&tmp, mgr.clone(), analyze);

        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "ls", 1);

        let err = scan_constants(&ctx, "ls", ConstantsOptions::default())
            .await
            .unwrap_err();
        match err {
            ConstantsError::Inspect(InspectError::Ambiguous { matches, .. }) => {
                assert_eq!(matches, 2);
            }
            other => panic!("expected Inspect(Ambiguous), got {other:?}"),
        }
    });
}

#[test]
fn scan_constants_returns_project_file_missing_when_gpr_absent() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));
        let analyze = tmp.path().join("analyzeHeadless");
        std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
        let ctx = make_ctx(&tmp, mgr.clone(), analyze);

        write_envelope(&mgr, SHA_LS, "ls", 1);

        let err = scan_constants(&ctx, "ls", ConstantsOptions::default())
            .await
            .unwrap_err();
        assert!(
            matches!(err, ConstantsError::ProjectFileMissing(_)),
            "{err:?}"
        );
    });
}

#[test]
fn scan_constants_returns_lock_held_when_lock_is_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));
        let analyze = tmp.path().join("analyzeHeadless");
        std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
        let ctx = make_ctx(&tmp, mgr.clone(), analyze);

        write_envelope(&mgr, SHA_LS, "ls", 1);

        let lock = mgr.lock_for(SHA_LS);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let err = scan_constants(&ctx, "ls", ConstantsOptions::default())
            .await
            .unwrap_err();
        match err {
            ConstantsError::LockHeld { sha256 } => assert_eq!(sha256, SHA_LS),
            other => panic!("expected LockHeld, got {other:?}"),
        }
    });
}
