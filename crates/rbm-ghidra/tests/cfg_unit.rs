use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::cfg::{CFG_SCHEMA, CfgBlock, CfgContext, CfgEdge, CfgError, CfgResult, gen_cfg};
use rbm_ghidra::inspect::InspectError;
use rbm_ghidra::project::{CFG_SCRIPT, PathValidationError, ProjectManager};
use rbm_ghidra::warm_path::WarmPathError;
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime, write_envelope};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn make_cfg_ctx(tmp: &TempDir, manager: Arc<ProjectManager>) -> CfgContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(CFG_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    CfgContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn cfg_script_constant_is_java() {
    assert_eq!(CFG_SCRIPT, "cfg.java");
}

#[test]
fn cfg_schema_constant_pinned() {
    assert_eq!(CFG_SCHEMA, "rbm.ghidra.cfg.v0");
}

#[test]
fn gen_cfg_rejects_empty_query() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_cfg_ctx(&tmp, mgr.clone());
        let err = gen_cfg(&ctx, "ls", "").await.unwrap_err();
        assert!(matches!(err, CfgError::EmptyQuery), "{err:?}");

        let err = gen_cfg(&ctx, "ls", "   ").await.unwrap_err();
        assert!(matches!(err, CfgError::EmptyQuery), "{err:?}");
    });
}

#[test]
fn warm_path_error_flattens_into_cfg_error() {
    let e: CfgError = WarmPathError::LockHeld {
        sha256: "abc".to_string(),
    }
    .into();
    match e {
        CfgError::LockHeld { sha256 } => assert_eq!(sha256, "abc"),
        other => panic!("expected LockHeld, got {other:?}"),
    }

    let e: CfgError = WarmPathError::ProjectFileMissing(PathBuf::from("/tmp/proj")).into();
    assert!(matches!(e, CfgError::ProjectFileMissing(_)), "{e:?}");

    let e: CfgError = WarmPathError::HeadlessFailed {
        exit_code: Some(7),
        stderr: "boom".to_string(),
    }
    .into();
    match e {
        CfgError::HeadlessFailed { exit_code, stderr } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(stderr, "boom");
        }
        other => panic!("expected HeadlessFailed, got {other:?}"),
    }

    let e: CfgError = WarmPathError::OutputMissing {
        stdout: "out".to_string(),
        stderr: "err".to_string(),
    }
    .into();
    match e {
        CfgError::OutputMissing { stdout, stderr } => {
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "err");
        }
        other => panic!("expected OutputMissing, got {other:?}"),
    }

    let e: CfgError = WarmPathError::Io {
        path: PathBuf::from("/tmp/proj"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    }
    .into();
    match e {
        CfgError::Io { path, source } => {
            assert_eq!(path, PathBuf::from("/tmp/proj"));
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected CfgError::Io, got {other:?}"),
    }
}

#[test]
fn cfg_result_serializes_to_stable_shape() {
    let result = CfgResult {
        schema: CFG_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: "main".to_string(),
        resolved_address: "100003a40".to_string(),
        resolved_function_name: "Global::main".to_string(),
        block_count: 2,
        edge_count: 1,
        blocks: vec![
            CfgBlock {
                address: "100003a40".to_string(),
                size: 16,
                instructions: 4,
            },
            CfgBlock {
                address: "100003a50".to_string(),
                size: 8,
                instructions: 2,
            },
        ],
        edges: vec![CfgEdge {
            from: "100003a40".to_string(),
            to: "100003a50".to_string(),
            flow_type: "CONDITIONAL_JUMP".to_string(),
        }],
        mermaid: "graph TD\n  b0[\"100003a40\"]\n  b1[\"100003a50\"]\n  b0 --> b1\n".to_string(),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], CFG_SCHEMA);
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["query"], "main");
    assert_eq!(json["resolved_address"], "100003a40");
    assert_eq!(json["resolved_function_name"], "Global::main");
    assert_eq!(json["block_count"], 2);
    assert_eq!(json["edge_count"], 1);
    assert_eq!(json["blocks"].as_array().unwrap().len(), 2);
    assert_eq!(json["blocks"][0]["address"], "100003a40");
    assert_eq!(json["blocks"][0]["size"], 16);
    assert_eq!(json["blocks"][0]["instructions"], 4);
    assert_eq!(json["edges"].as_array().unwrap().len(), 1);
    assert_eq!(json["edges"][0]["from"], "100003a40");
    assert_eq!(json["edges"][0]["to"], "100003a50");
    assert_eq!(json["edges"][0]["flow_type"], "CONDITIONAL_JUMP");
    assert!(json["mermaid"].as_str().unwrap().starts_with("graph TD"));
    assert_eq!(json.as_object().unwrap().len(), 12);
}

#[test]
fn gen_cfg_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_cfg_ctx(&tmp, mgr.clone());
        ctx.scripts_dir = tmp.path().join("does-not-exist");
        let err = gen_cfg(&ctx, "ls", "main").await.unwrap_err();
        assert!(
            matches!(
                err,
                CfgError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn gen_cfg_rejects_missing_cfg_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_cfg_ctx(&tmp, mgr.clone());
        let scripts = tmp.path().join("scripts-empty");
        std::fs::create_dir_all(&scripts).unwrap();
        ctx.scripts_dir = scripts;
        let err = gen_cfg(&ctx, "ls", "main").await.unwrap_err();
        match err {
            CfgError::PathValidation(PathValidationError::ScriptMissing { script, .. }) => {
                assert_eq!(script, CFG_SCRIPT);
            }
            other => panic!("expected PathValidation::ScriptMissing, got {other:?}"),
        }
    });
}

#[test]
fn gen_cfg_rejects_missing_analyze_headless() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_cfg_ctx(&tmp, mgr.clone());
        ctx.analyze_headless = tmp.path().join("does-not-exist");
        let err = gen_cfg(&ctx, "ls", "main").await.unwrap_err();
        assert!(
            matches!(
                err,
                CfgError::PathValidation(PathValidationError::AnalyzeHeadlessMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn gen_cfg_returns_inspect_not_found_for_unknown_binary() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_cfg_ctx(&tmp, mgr.clone());
        let err = gen_cfg(&ctx, "missing", "main").await.unwrap_err();
        assert!(
            matches!(err, CfgError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn gen_cfg_propagates_ambiguous_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_cfg_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "ls", 1);
        let err = gen_cfg(&ctx, "ls", "main").await.unwrap_err();
        match err {
            CfgError::Inspect(InspectError::Ambiguous { matches, .. }) => {
                assert_eq!(matches, 2);
            }
            other => panic!("expected Inspect(Ambiguous), got {other:?}"),
        }
    });
}

#[test]
fn gen_cfg_returns_project_file_missing_when_gpr_absent() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_cfg_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let err = gen_cfg(&ctx, "ls", "main").await.unwrap_err();
        assert!(matches!(err, CfgError::ProjectFileMissing(_)), "{err:?}");
    });
}

#[test]
fn gen_cfg_returns_lock_held_when_lock_is_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_cfg_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);

        let lock = mgr.lock_for(SHA_LS);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let err = gen_cfg(&ctx, "ls", "main").await.unwrap_err();
        match err {
            CfgError::LockHeld { sha256 } => assert_eq!(sha256, SHA_LS),
            other => panic!("expected LockHeld, got {other:?}"),
        }
    });
}
