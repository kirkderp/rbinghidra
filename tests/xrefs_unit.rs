#[path = "support/tempfile.rs"]
mod tempfile;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rbinghidra::inspect::InspectError;
use rbinghidra::project::{LIST_XREFS_SCRIPT, PathValidationError, ProjectManager};
use rbinghidra::warm_path::WarmPathError;
use rbinghidra::xrefs::{
    DEFAULT_DIRECTION, DEFAULT_LIMIT, DEFAULT_OFFSET, LIST_XREFS_SCHEMA, MAX_LIMIT, XrefEntry,
    XrefsContext, XrefsError, XrefsResult, list_xrefs, resolve_direction, resolve_limit,
    resolve_offset,
};
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime, write_envelope};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn make_xrefs_ctx(tmp: &TempDir, manager: Arc<ProjectManager>) -> XrefsContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(LIST_XREFS_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    XrefsContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_millis(100),
    }
}

#[test]
fn list_xrefs_script_constant_is_java() {
    assert_eq!(LIST_XREFS_SCRIPT, "list_xrefs.java");
}

#[test]
fn list_xrefs_schema_constant_pinned() {
    assert_eq!(LIST_XREFS_SCHEMA, "rbm.ghidra.list_xrefs.v0");
}

#[test]
fn xrefs_pagination_constants_pinned() {
    assert_eq!(DEFAULT_OFFSET, 0);
    assert_eq!(DEFAULT_LIMIT, 25);
    assert_eq!(MAX_LIMIT, 1000);
    assert_eq!(DEFAULT_DIRECTION, "to");
}

#[test]
fn resolve_offset_uses_default_for_none() {
    assert_eq!(resolve_offset(None), 0);
    assert_eq!(resolve_offset(Some(7)), 7);
}

#[test]
fn resolve_limit_clamps_at_max() {
    assert_eq!(resolve_limit(None), 25);
    assert_eq!(resolve_limit(Some(50)), 50);
    assert_eq!(resolve_limit(Some(MAX_LIMIT)), MAX_LIMIT);
    assert_eq!(resolve_limit(Some(MAX_LIMIT + 1)), MAX_LIMIT);
    assert_eq!(resolve_limit(Some(u64::MAX)), MAX_LIMIT);
}

#[test]
fn resolve_direction_accepts_to_from_and_rejects_unknowns() {
    assert_eq!(resolve_direction(None).unwrap(), "to");
    assert_eq!(resolve_direction(Some("")).unwrap(), "to");
    assert_eq!(resolve_direction(Some("TO")).unwrap(), "to");
    assert_eq!(resolve_direction(Some(" from ")).unwrap(), "from");
    let err = resolve_direction(Some("sideways")).unwrap_err();
    assert!(matches!(err, XrefsError::InvalidDirection(_)), "{err:?}");
}

#[test]
fn warm_path_error_flattens_into_xrefs_error() {
    let e: XrefsError = WarmPathError::LockHeld {
        sha256: "abc".to_string(),
    }
    .into();
    match e {
        XrefsError::LockHeld { sha256 } => assert_eq!(sha256, "abc"),
        other => panic!("expected LockHeld, got {other:?}"),
    }

    let e: XrefsError = WarmPathError::ProjectFileMissing(PathBuf::from("/tmp/proj")).into();
    assert!(matches!(e, XrefsError::ProjectFileMissing(_)), "{e:?}");

    let e: XrefsError = WarmPathError::HeadlessFailed {
        exit_code: Some(7),
        stderr: "boom".to_string(),
    }
    .into();
    match e {
        XrefsError::HeadlessFailed { exit_code, stderr } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(stderr, "boom");
        }
        other => panic!("expected HeadlessFailed, got {other:?}"),
    }

    let e: XrefsError = WarmPathError::OutputMissing {
        stdout: "out".to_string(),
        stderr: "err".to_string(),
    }
    .into();
    match e {
        XrefsError::OutputMissing { stdout, stderr } => {
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "err");
        }
        other => panic!("expected OutputMissing, got {other:?}"),
    }

    let e: XrefsError = WarmPathError::Io {
        path: PathBuf::from("/tmp/proj"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    }
    .into();
    match e {
        XrefsError::Io { path, source } => {
            assert_eq!(path, PathBuf::from("/tmp/proj"));
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected XrefsError::Io, got {other:?}"),
    }
}

#[test]
fn xref_entry_serializes_to_stable_shape() {
    let entry = XrefEntry {
        from_address: "0x1001".to_string(),
        to_address: "0x100003a40".to_string(),
        ref_type: "UNCONDITIONAL_CALL".to_string(),
        function_name: "_start".to_string(),
    };
    let json = serde_json::to_value(&entry).unwrap();
    assert_eq!(json["from_address"], "0x1001");
    assert_eq!(json["to_address"], "0x100003a40");
    assert_eq!(json["ref_type"], "UNCONDITIONAL_CALL");
    assert_eq!(json["function_name"], "_start");
    assert_eq!(json.as_object().unwrap().len(), 4);
}

#[test]
fn xrefs_result_serializes_to_stable_shape() {
    let result = XrefsResult {
        schema: LIST_XREFS_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: "main".to_string(),
        direction: "to".to_string(),
        resolved_address: "0x100003a40".to_string(),
        resolved_symbol_name: "Global::main".to_string(),
        offset: 0,
        limit: 25,
        total_matched: 1,
        truncated: false,
        error_count: 0,
        xrefs: vec![XrefEntry {
            from_address: "0x1001".to_string(),
            to_address: "0x100003a40".to_string(),
            ref_type: "UNCONDITIONAL_CALL".to_string(),
            function_name: "_start".to_string(),
        }],
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], LIST_XREFS_SCHEMA);
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["query"], "main");
    assert_eq!(json["direction"], "to");
    assert_eq!(json["resolved_address"], "0x100003a40");
    assert_eq!(json["resolved_symbol_name"], "Global::main");
    assert_eq!(json["offset"], 0);
    assert_eq!(json["limit"], 25);
    assert_eq!(json["total_matched"], 1);
    assert_eq!(json["truncated"], false);
    assert_eq!(json["error_count"], 0);
    assert_eq!(json["xrefs"][0]["from_address"], "0x1001");
    assert_eq!(json["xrefs"][0]["ref_type"], "UNCONDITIONAL_CALL");
}

#[test]
fn list_xrefs_returns_empty_query_for_blank_string() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_xrefs_ctx(&tmp, mgr.clone());
        let err = list_xrefs(&ctx, "ls", "   ", None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, XrefsError::EmptyQuery), "{err:?}");
    });
}

#[test]
fn list_xrefs_rejects_invalid_direction_before_warm_path() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_xrefs_ctx(&tmp, mgr.clone());
        let err = list_xrefs(&ctx, "ls", "main", Some("sideways"), None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, XrefsError::InvalidDirection(_)), "{err:?}");
    });
}

#[test]
fn list_xrefs_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_xrefs_ctx(&tmp, mgr.clone());
        ctx.scripts_dir = tmp.path().join("does-not-exist");
        let err = list_xrefs(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                XrefsError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn list_xrefs_rejects_missing_list_xrefs_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_xrefs_ctx(&tmp, mgr.clone());
        let scripts = tmp.path().join("scripts-empty");
        std::fs::create_dir_all(&scripts).unwrap();
        ctx.scripts_dir = scripts;
        let err = list_xrefs(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        match err {
            XrefsError::PathValidation(PathValidationError::ScriptMissing { script, .. }) => {
                assert_eq!(script, LIST_XREFS_SCRIPT);
            }
            other => panic!("expected PathValidation::ScriptMissing, got {other:?}"),
        }
    });
}

#[test]
fn list_xrefs_rejects_missing_analyze_headless() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_xrefs_ctx(&tmp, mgr.clone());
        ctx.analyze_headless = tmp.path().join("does-not-exist");
        let err = list_xrefs(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                XrefsError::PathValidation(PathValidationError::AnalyzeHeadlessMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn list_xrefs_returns_inspect_not_found_for_unknown_binary() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_xrefs_ctx(&tmp, mgr.clone());
        let err = list_xrefs(&ctx, "missing", "main", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, XrefsError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn list_xrefs_propagates_ambiguous_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_xrefs_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "ls", 1);
        let err = list_xrefs(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        match err {
            XrefsError::Inspect(InspectError::Ambiguous { matches, .. }) => {
                assert_eq!(matches, 2);
            }
            other => panic!("expected Inspect(Ambiguous), got {other:?}"),
        }
    });
}

#[test]
fn list_xrefs_returns_project_file_missing_when_gpr_absent() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_xrefs_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let err = list_xrefs(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, XrefsError::ProjectFileMissing(_)), "{err:?}");
    });
}

#[test]
fn list_xrefs_returns_lock_held_when_lock_is_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_xrefs_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);

        let lock = mgr.lock_for(SHA_LS);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let err = list_xrefs(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        match err {
            XrefsError::LockHeld { sha256 } => assert_eq!(sha256, SHA_LS),
            other => panic!("expected LockHeld, got {other:?}"),
        }
    });
}
