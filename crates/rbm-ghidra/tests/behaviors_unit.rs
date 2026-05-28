use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::behaviors::{
    BEHAVIORS_SCHEMA, BehaviorsContext, BehaviorsError, BehaviorsResult, scan_behaviors,
};
use rbm_ghidra::inspect::InspectError;
use rbm_ghidra::project::{BEHAVIORS_SCRIPT, PathValidationError, ProjectManager};
use rbm_ghidra::warm_path::WarmPathError;
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime, write_envelope};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn make_behaviors_ctx(tmp: &TempDir, manager: Arc<ProjectManager>) -> BehaviorsContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(BEHAVIORS_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    BehaviorsContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_millis(100),
    }
}

#[test]
fn behaviors_script_constant_is_java() {
    assert_eq!(BEHAVIORS_SCRIPT, "behaviors.java");
}

#[test]
fn behaviors_schema_constant_pinned() {
    assert_eq!(BEHAVIORS_SCHEMA, "rbm.ghidra.behaviors.v0");
}

#[test]
fn warm_path_error_flattens_into_behaviors_error() {
    let e: BehaviorsError = WarmPathError::LockHeld {
        sha256: "abc".to_string(),
    }
    .into();
    match e {
        BehaviorsError::LockHeld { sha256 } => assert_eq!(sha256, "abc"),
        other => panic!("expected LockHeld, got {other:?}"),
    }

    let e: BehaviorsError = WarmPathError::ProjectFileMissing(PathBuf::from("/tmp/proj")).into();
    assert!(matches!(e, BehaviorsError::ProjectFileMissing(_)), "{e:?}");

    let e: BehaviorsError = WarmPathError::HeadlessFailed {
        exit_code: Some(7),
        stderr: "boom".to_string(),
    }
    .into();
    match e {
        BehaviorsError::HeadlessFailed { exit_code, stderr } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(stderr, "boom");
        }
        other => panic!("expected HeadlessFailed, got {other:?}"),
    }

    let e: BehaviorsError = WarmPathError::OutputMissing {
        stdout: "out".to_string(),
        stderr: "err".to_string(),
    }
    .into();
    match e {
        BehaviorsError::OutputMissing { stdout, stderr } => {
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "err");
        }
        other => panic!("expected OutputMissing, got {other:?}"),
    }

    let e: BehaviorsError = WarmPathError::Io {
        path: PathBuf::from("/tmp/proj"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    }
    .into();
    match e {
        BehaviorsError::Io { path, source } => {
            assert_eq!(path, PathBuf::from("/tmp/proj"));
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected BehaviorsError::Io, got {other:?}"),
    }
}

#[test]
fn behaviors_result_serializes_to_stable_shape() {
    let mut severity_summary = HashMap::new();
    severity_summary.insert("high".to_string(), 1);

    let result = BehaviorsResult {
        schema: BEHAVIORS_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        total_detected: 1,
        severity_summary,
        behaviors: vec![serde_json::json!({
            "name": "example_behavior",
            "severity": "high",
        })],
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], BEHAVIORS_SCHEMA);
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["total_detected"], 1);
    assert_eq!(json["severity_summary"]["high"], 1);
    assert_eq!(json["behaviors"][0]["name"], "example_behavior");
    assert_eq!(json.as_object().unwrap().len(), 7);
}

#[test]
fn scan_behaviors_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_behaviors_ctx(&tmp, mgr.clone());
        ctx.scripts_dir = tmp.path().join("does-not-exist");
        let err = scan_behaviors(&ctx, "ls").await.unwrap_err();
        assert!(
            matches!(
                err,
                BehaviorsError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn scan_behaviors_rejects_missing_behaviors_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_behaviors_ctx(&tmp, mgr.clone());
        let scripts = tmp.path().join("scripts-empty");
        std::fs::create_dir_all(&scripts).unwrap();
        ctx.scripts_dir = scripts;
        let err = scan_behaviors(&ctx, "ls").await.unwrap_err();
        match err {
            BehaviorsError::PathValidation(PathValidationError::ScriptMissing {
                script, ..
            }) => {
                assert_eq!(script, BEHAVIORS_SCRIPT);
            }
            other => panic!("expected PathValidation::ScriptMissing, got {other:?}"),
        }
    });
}

#[test]
fn scan_behaviors_rejects_missing_analyze_headless() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_behaviors_ctx(&tmp, mgr.clone());
        ctx.analyze_headless = tmp.path().join("does-not-exist");
        let err = scan_behaviors(&ctx, "ls").await.unwrap_err();
        assert!(
            matches!(
                err,
                BehaviorsError::PathValidation(PathValidationError::AnalyzeHeadlessMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn scan_behaviors_returns_inspect_not_found_for_unknown_binary() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_behaviors_ctx(&tmp, mgr.clone());
        let err = scan_behaviors(&ctx, "missing").await.unwrap_err();
        assert!(
            matches!(err, BehaviorsError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn scan_behaviors_propagates_ambiguous_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_behaviors_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "ls", 1);
        let err = scan_behaviors(&ctx, "ls").await.unwrap_err();
        match err {
            BehaviorsError::Inspect(InspectError::Ambiguous { matches, .. }) => {
                assert_eq!(matches, 2);
            }
            other => panic!("expected Inspect(Ambiguous), got {other:?}"),
        }
    });
}

#[test]
fn scan_behaviors_returns_project_file_missing_when_gpr_absent() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_behaviors_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let err = scan_behaviors(&ctx, "ls").await.unwrap_err();
        assert!(
            matches!(err, BehaviorsError::ProjectFileMissing(_)),
            "{err:?}"
        );
    });
}

#[test]
fn scan_behaviors_returns_lock_held_when_lock_is_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_behaviors_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);

        let lock = mgr.lock_for(SHA_LS);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let err = scan_behaviors(&ctx, "ls").await.unwrap_err();
        match err {
            BehaviorsError::LockHeld { sha256 } => assert_eq!(sha256, SHA_LS),
            other => panic!("expected LockHeld, got {other:?}"),
        }
    });
}
