#[path = "support/tempfile.rs"]
mod tempfile;

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rbinghidra::decompile::{
    CallReference, DECOMPILE_SCHEMA, DecompileContext, DecompileError, DecompileResult,
    decompile_function,
};
use rbinghidra::inspect::InspectError;
use rbinghidra::project::{
    DECOMPILE_FUNCTION_SCRIPT, PathValidationError, ProcessSpec, ProjectManager, build_process_argv,
};
use rbinghidra::warm_path::WarmPathError;
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime, write_envelope};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn osstr(s: &str) -> OsString {
    OsString::from(s)
}

fn make_process_spec<'a>(
    project_dir: &'a std::path::Path,
    script_dir: &'a std::path::Path,
    script_args: &'a [String],
) -> ProcessSpec<'a> {
    ProcessSpec {
        project_dir,
        project_name: "ls",
        program_name: "ls",
        script_dir,
        script_name: DECOMPILE_FUNCTION_SCRIPT,
        script_args,
    }
}

fn make_decompile_ctx(tmp: &TempDir, manager: Arc<ProjectManager>) -> DecompileContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(DECOMPILE_FUNCTION_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    DecompileContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_millis(100),
    }
}

#[test]
fn decompile_function_script_constant_is_java() {
    assert_eq!(DECOMPILE_FUNCTION_SCRIPT, "decompile_function.java");
}

#[test]
fn decompile_schema_constant_pinned() {
    assert_eq!(DECOMPILE_SCHEMA, "rbm.ghidra.decompile_function.v0");
}

#[test]
fn build_process_argv_emits_full_invocation_in_order() {
    let project_dir = PathBuf::from("/tmp/proj");
    let script_dir = PathBuf::from("/scripts");
    let script_args = vec![
        "/tmp/proj/decompile_main_42.json".to_string(),
        "main".to_string(),
        "decompile".to_string(),
    ];
    let spec = make_process_spec(&project_dir, &script_dir, &script_args);
    let argv = build_process_argv(&spec);
    assert_eq!(
        argv,
        vec![
            osstr("/tmp/proj"),
            osstr("ls"),
            osstr("-process"),
            osstr("ls"),
            osstr("-noanalysis"),
            osstr("-scriptPath"),
            osstr("/scripts"),
            osstr("-postScript"),
            osstr("decompile_function.java"),
            osstr("/tmp/proj/decompile_main_42.json"),
            osstr("main"),
            osstr("decompile"),
        ]
    );
}

#[test]
fn build_process_argv_omits_import_and_overwrite_flags() {
    let project_dir = PathBuf::from("/tmp/proj");
    let script_dir = PathBuf::from("/scripts");
    let script_args = vec![
        "/tmp/proj/decompile_main_42.json".to_string(),
        "main".to_string(),
        "decompile".to_string(),
    ];
    let spec = make_process_spec(&project_dir, &script_dir, &script_args);
    let argv = build_process_argv(&spec);
    assert!(!argv.iter().any(|a| a == &osstr("-import")));
    assert!(!argv.iter().any(|a| a == &osstr("-overwrite")));
    assert!(argv.iter().any(|a| a == &osstr("-noanalysis")));
}

#[test]
fn build_process_argv_appends_extra_script_args_in_order() {
    let project_dir = PathBuf::from("/tmp/proj");
    let script_dir = PathBuf::from("/scripts");
    let script_args = vec![
        "/tmp/out.json".to_string(),
        "0x100003a40".to_string(),
        "extra".to_string(),
    ];
    let spec = make_process_spec(&project_dir, &script_dir, &script_args);
    let argv = build_process_argv(&spec);
    let tail: Vec<&OsString> = argv.iter().rev().take(3).collect();
    assert_eq!(tail[0], &osstr("extra"));
    assert_eq!(tail[1], &osstr("0x100003a40"));
    assert_eq!(tail[2], &osstr("/tmp/out.json"));
}

#[test]
fn warm_path_error_flattens_into_decompile_error() {
    let e: DecompileError = WarmPathError::LockHeld {
        sha256: "abc".to_string(),
    }
    .into();
    match e {
        DecompileError::LockHeld { sha256 } => assert_eq!(sha256, "abc"),
        other => panic!("expected LockHeld, got {other:?}"),
    }

    let e: DecompileError = WarmPathError::ProjectFileMissing(PathBuf::from("/tmp/proj")).into();
    assert!(matches!(e, DecompileError::ProjectFileMissing(_)), "{e:?}");

    let e: DecompileError = WarmPathError::HeadlessFailed {
        exit_code: Some(7),
        stderr: "boom".to_string(),
    }
    .into();
    match e {
        DecompileError::HeadlessFailed { exit_code, stderr } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(stderr, "boom");
        }
        other => panic!("expected HeadlessFailed, got {other:?}"),
    }

    let e: DecompileError = WarmPathError::OutputMissing {
        stdout: "out".to_string(),
        stderr: "err".to_string(),
    }
    .into();
    match e {
        DecompileError::OutputMissing { stdout, stderr } => {
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "err");
        }
        other => panic!("expected OutputMissing, got {other:?}"),
    }

    let e: DecompileError = WarmPathError::Io {
        path: PathBuf::from("/tmp/proj"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    }
    .into();
    match e {
        DecompileError::Io { path, source } => {
            assert_eq!(path, PathBuf::from("/tmp/proj"));
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected DecompileError::Io, got {other:?}"),
    }
}

#[test]
fn decompile_function_returns_empty_query_for_blank_string() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_decompile_ctx(&tmp, mgr.clone());
        let err = decompile_function(&ctx, "ls", "   ", None)
            .await
            .unwrap_err();
        assert!(matches!(err, DecompileError::EmptyQuery), "{err:?}");
    });
}

#[test]
fn decompile_function_rejects_invalid_simplification_style() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_decompile_ctx(&tmp, mgr.clone());
        let err = decompile_function(&ctx, "ls", "main", Some("bogus"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, DecompileError::InvalidSimplificationStyle { .. }),
            "{err:?}"
        );
    });
}

#[test]
fn decompile_function_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_decompile_ctx(&tmp, mgr.clone());
        ctx.scripts_dir = tmp.path().join("does-not-exist");
        let err = decompile_function(&ctx, "ls", "main", None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                DecompileError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn decompile_function_rejects_missing_decompile_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_decompile_ctx(&tmp, mgr.clone());
        let scripts = tmp.path().join("scripts-empty");
        std::fs::create_dir_all(&scripts).unwrap();
        ctx.scripts_dir = scripts;
        let err = decompile_function(&ctx, "ls", "main", None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                DecompileError::PathValidation(PathValidationError::ScriptMissing { .. })
            ),
            "{err:?}"
        );
    });
}

#[test]
fn decompile_function_rejects_missing_analyze_headless() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_decompile_ctx(&tmp, mgr.clone());
        ctx.analyze_headless = tmp.path().join("does-not-exist");
        let err = decompile_function(&ctx, "ls", "main", None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                DecompileError::PathValidation(PathValidationError::AnalyzeHeadlessMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn decompile_function_returns_inspect_not_found_for_unknown_query() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_decompile_ctx(&tmp, mgr.clone());
        let err = decompile_function(&ctx, "missing", "main", None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DecompileError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn decompile_function_propagates_ambiguous_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_decompile_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "ls", 1);
        let err = decompile_function(&ctx, "ls", "main", None)
            .await
            .unwrap_err();
        match err {
            DecompileError::Inspect(InspectError::Ambiguous { matches, .. }) => {
                assert_eq!(matches, 2);
            }
            other => panic!("expected Inspect(Ambiguous), got {other:?}"),
        }
    });
}

#[test]
fn decompile_function_returns_project_file_missing_when_gpr_absent() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_decompile_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let err = decompile_function(&ctx, "ls", "main", None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DecompileError::ProjectFileMissing(_)),
            "{err:?}"
        );
    });
}

#[test]
fn decompile_function_returns_lock_held_when_lock_is_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_decompile_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);

        let lock = mgr.lock_for(SHA_LS);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let err = decompile_function(&ctx, "ls", "main", None)
            .await
            .unwrap_err();
        match err {
            DecompileError::LockHeld { sha256 } => assert_eq!(sha256, SHA_LS),
            other => panic!("expected LockHeld, got {other:?}"),
        }
    });
}

#[test]
fn decompile_result_serializes_to_stable_shape() {
    let result = DecompileResult {
        schema: DECOMPILE_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: "main".to_string(),
        simplification_style: "decompile".to_string(),
        function_name: "main".to_string(),
        address: "0x100003a40".to_string(),
        signature: "int main(int argc, char ** argv)".to_string(),
        decompiler_signature: "int main(int argc, char * * argv)".to_string(),
        pseudocode: "int main(...) { return 0; }".to_string(),
        callers: vec!["_start".to_string()],
        callees: vec!["puts".to_string(), "exit".to_string()],
        caller_details: vec![CallReference {
            name: "_start".to_string(),
            address: "0x100000000".to_string(),
            is_external: false,
            is_thunk: false,
        }],
        callee_details: vec![CallReference {
            name: "puts".to_string(),
            address: "EXTERNAL:00000000".to_string(),
            is_external: true,
            is_thunk: true,
        }],
        basic_block_count: 4,
        decompile_completed: true,
        decompile_valid: true,
        is_timed_out: false,
        is_cancelled: false,
        failed_to_start: false,
        decompile_error: String::new(),
        resolution_error: String::new(),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], DECOMPILE_SCHEMA);
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["query"], "main");
    assert_eq!(json["simplification_style"], "decompile");
    assert_eq!(json["function_name"], "main");
    assert_eq!(json["address"], "0x100003a40");
    assert_eq!(json["signature"], "int main(int argc, char ** argv)");
    assert_eq!(
        json["decompiler_signature"],
        "int main(int argc, char * * argv)"
    );
    assert_eq!(json["pseudocode"], "int main(...) { return 0; }");
    assert_eq!(json["callers"][0], "_start");
    assert_eq!(json["callees"][0], "puts");
    assert_eq!(json["callees"][1], "exit");
    assert_eq!(json["caller_details"][0]["name"], "_start");
    assert_eq!(json["callee_details"][0]["is_external"], true);
    assert_eq!(json["basic_block_count"], 4);
    assert_eq!(json["decompile_completed"], true);
    assert_eq!(json["decompile_valid"], true);
    assert_eq!(json["is_timed_out"], false);
    assert_eq!(json["is_cancelled"], false);
    assert_eq!(json["failed_to_start"], false);
    assert_eq!(json["decompile_error"], "");
}
