use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::inspect::InspectError;
use rbm_ghidra::project::{PathValidationError, ProjectManager, GO_METADATA_SCRIPT};
use rbm_ghidra::go_metadata::{
    DEFAULT_LIMIT, MAX_LIMIT, GO_METADATA_SCHEMA,
    GoMetadataContext, GoMetadataError, GoMetadataResult, GoStringHit, GoFunctionHit, get_go_metadata,
};
use rbm_ghidra::warm_path::WarmPathError;
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime, write_envelope};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn make_go_metadata_ctx(tmp: &TempDir, manager: Arc<ProjectManager>) -> GoMetadataContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(GO_METADATA_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    GoMetadataContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_millis(100),
    }
}

#[test]
fn go_metadata_script_constant_is_java() {
    assert_eq!(GO_METADATA_SCRIPT, "go_metadata.java");
}

#[test]
fn go_metadata_schema_constant_pinned() {
    assert_eq!(GO_METADATA_SCHEMA, "rbm.ghidra.go_metadata.v0");
}

#[test]
fn limits_constants_pinned() {
    assert_eq!(DEFAULT_LIMIT, 100);
    assert_eq!(MAX_LIMIT, 1000);
}

#[test]
fn warm_path_error_flattens_into_go_metadata_error() {
    let e: GoMetadataError = WarmPathError::LockHeld {
        sha256: "abc".to_string(),
    }
    .into();
    match e {
        GoMetadataError::LockHeld { sha256 } => assert_eq!(sha256, "abc"),
        other => panic!("expected LockHeld, got {other:?}"),
    }

    let e: GoMetadataError =
        WarmPathError::ProjectFileMissing(PathBuf::from("/tmp/proj")).into();
    assert!(
        matches!(e, GoMetadataError::ProjectFileMissing(_)),
        "{e:?}"
    );

    let e: GoMetadataError = WarmPathError::HeadlessFailed {
        exit_code: Some(7),
        stderr: "boom".to_string(),
    }
    .into();
    match e {
        GoMetadataError::HeadlessFailed { exit_code, stderr } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(stderr, "boom");
        }
        other => panic!("expected HeadlessFailed, got {other:?}"),
    }

    let e: GoMetadataError = WarmPathError::OutputMissing {
        stdout: "out".to_string(),
        stderr: "err".to_string(),
    }
    .into();
    match e {
        GoMetadataError::OutputMissing { stdout, stderr } => {
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "err");
        }
        other => panic!("expected OutputMissing, got {other:?}"),
    }

    let e: GoMetadataError = WarmPathError::Io {
        path: PathBuf::from("/tmp/proj"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    }
    .into();
    match e {
        GoMetadataError::Io { path, source } => {
            assert_eq!(path, PathBuf::from("/tmp/proj"));
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected GoMetadataError::Io, got {other:?}"),
    }
}

#[test]
fn go_metadata_result_serializes_to_stable_shape() {
    let result = GoMetadataResult {
        schema: GO_METADATA_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        likely_go: true,
        limit: 100,
        go_versions: vec![GoStringHit {
            address: "0x1000".to_string(),
            value: "go1.20".to_string(),
            xref_count: 2,
        }],
        module_paths: vec![],
        package_strings: vec![],
        runtime_functions: vec![GoFunctionHit {
            name: "runtime.main".to_string(),
            address: "0x2000".to_string(),
        }],
        main_candidates: vec![],
        total_strings_scanned: 1000,
        total_functions_scanned: 500,
        error_count: 0,
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], GO_METADATA_SCHEMA);
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["likely_go"], true);
    assert_eq!(json["limit"], 100);
    assert_eq!(json["go_versions"][0]["address"], "0x1000");
    assert_eq!(json["go_versions"][0]["value"], "go1.20");
    assert_eq!(json["go_versions"][0]["xref_count"], 2);
    assert_eq!(json["runtime_functions"][0]["name"], "runtime.main");
    assert_eq!(json["runtime_functions"][0]["address"], "0x2000");
    assert_eq!(json["total_strings_scanned"], 1000);
    assert_eq!(json["total_functions_scanned"], 500);
    assert_eq!(json["error_count"], 0);
}

#[test]
fn get_go_metadata_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_go_metadata_ctx(&tmp, mgr.clone());
        ctx.scripts_dir = tmp.path().join("does-not-exist");
        let err = get_go_metadata(&ctx, "ls", None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                GoMetadataError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn get_go_metadata_rejects_missing_go_metadata_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_go_metadata_ctx(&tmp, mgr.clone());
        let scripts = tmp.path().join("scripts-empty");
        std::fs::create_dir_all(&scripts).unwrap();
        ctx.scripts_dir = scripts;
        let err = get_go_metadata(&ctx, "ls", None)
            .await
            .unwrap_err();
        match err {
            GoMetadataError::PathValidation(PathValidationError::ScriptMissing {
                script,
                ..
            }) => {
                assert_eq!(script, GO_METADATA_SCRIPT);
            }
            other => panic!("expected PathValidation::ScriptMissing, got {other:?}"),
        }
    });
}

#[test]
fn get_go_metadata_rejects_missing_analyze_headless() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_go_metadata_ctx(&tmp, mgr.clone());
        ctx.analyze_headless = tmp.path().join("does-not-exist");
        let err = get_go_metadata(&ctx, "ls", None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                GoMetadataError::PathValidation(PathValidationError::AnalyzeHeadlessMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn get_go_metadata_returns_inspect_not_found_for_unknown_binary() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_go_metadata_ctx(&tmp, mgr.clone());
        let err = get_go_metadata(&ctx, "missing", None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, GoMetadataError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn get_go_metadata_propagates_ambiguous_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_go_metadata_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "ls", 1);
        let err = get_go_metadata(&ctx, "ls", None)
            .await
            .unwrap_err();
        match err {
            GoMetadataError::Inspect(InspectError::Ambiguous { matches, .. }) => {
                assert_eq!(matches, 2);
            }
            other => panic!("expected Inspect(Ambiguous), got {other:?}"),
        }
    });
}

#[test]
fn get_go_metadata_returns_project_file_missing_when_gpr_absent() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_go_metadata_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let err = get_go_metadata(&ctx, "ls", None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, GoMetadataError::ProjectFileMissing(_)),
            "{err:?}"
        );
    });
}

#[test]
fn get_go_metadata_returns_lock_held_when_lock_is_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_go_metadata_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);

        let lock = mgr.lock_for(SHA_LS);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let err = get_go_metadata(&ctx, "ls", None)
            .await
            .unwrap_err();
        match err {
            GoMetadataError::LockHeld { sha256 } => assert_eq!(sha256, SHA_LS),
            other => panic!("expected LockHeld, got {other:?}"),
        }
    });
}
