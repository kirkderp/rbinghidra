use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::inspect::InspectError;
use rbm_ghidra::project::{PathValidationError, ProjectManager, SEARCH_SYMBOLS_SCRIPT};
use rbm_ghidra::symbols::{
    DEFAULT_LIMIT, DEFAULT_OFFSET, MAX_LIMIT, SEARCH_SYMBOLS_SCHEMA, SymbolEntry, SymbolsContext,
    SymbolsError, SymbolsResult, search_symbols,
};
use rbm_ghidra::warm_path::WarmPathError;
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime, write_envelope};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn make_symbols_ctx(tmp: &TempDir, manager: Arc<ProjectManager>) -> SymbolsContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(SEARCH_SYMBOLS_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    SymbolsContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_millis(100),
    }
}

#[test]
fn search_symbols_script_constant_is_java() {
    assert_eq!(SEARCH_SYMBOLS_SCRIPT, "search_symbols.java");
}

#[test]
fn symbols_schema_constant_pinned() {
    assert_eq!(SEARCH_SYMBOLS_SCHEMA, "rbm.ghidra.search_symbols.v0");
}

#[test]
fn symbols_default_pagination_constants_pinned() {
    assert_eq!(DEFAULT_OFFSET, 0);
    assert_eq!(DEFAULT_LIMIT, 25);
    assert_eq!(MAX_LIMIT, 1000);
}

#[test]
fn warm_path_error_flattens_into_symbols_error() {
    let e: SymbolsError = WarmPathError::LockHeld {
        sha256: "abc".to_string(),
    }
    .into();
    match e {
        SymbolsError::LockHeld { sha256 } => assert_eq!(sha256, "abc"),
        other => panic!("expected LockHeld, got {other:?}"),
    }

    let e: SymbolsError = WarmPathError::ProjectFileMissing(PathBuf::from("/tmp/proj")).into();
    assert!(matches!(e, SymbolsError::ProjectFileMissing(_)), "{e:?}");

    let e: SymbolsError = WarmPathError::HeadlessFailed {
        exit_code: Some(7),
        stderr: "boom".to_string(),
    }
    .into();
    match e {
        SymbolsError::HeadlessFailed { exit_code, stderr } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(stderr, "boom");
        }
        other => panic!("expected HeadlessFailed, got {other:?}"),
    }

    let e: SymbolsError = WarmPathError::OutputMissing {
        stdout: "out".to_string(),
        stderr: "err".to_string(),
    }
    .into();
    match e {
        SymbolsError::OutputMissing { stdout, stderr } => {
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "err");
        }
        other => panic!("expected OutputMissing, got {other:?}"),
    }

    let e: SymbolsError = WarmPathError::Io {
        path: PathBuf::from("/tmp/proj"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    }
    .into();
    match e {
        SymbolsError::Io { path, source } => {
            assert_eq!(path, PathBuf::from("/tmp/proj"));
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected SymbolsError::Io, got {other:?}"),
    }
}

#[test]
fn search_symbols_returns_empty_query_for_blank_string() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_symbols_ctx(&tmp, mgr.clone());
        let err = search_symbols(&ctx, "ls", "   ", None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, SymbolsError::EmptyQuery), "{err:?}");
    });
}

#[test]
fn search_symbols_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_symbols_ctx(&tmp, mgr.clone());
        ctx.scripts_dir = tmp.path().join("does-not-exist");
        let err = search_symbols(&ctx, "ls", "main", None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                SymbolsError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn search_symbols_rejects_missing_search_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_symbols_ctx(&tmp, mgr.clone());
        let scripts = tmp.path().join("scripts-empty");
        std::fs::create_dir_all(&scripts).unwrap();
        ctx.scripts_dir = scripts;
        let err = search_symbols(&ctx, "ls", "main", None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                SymbolsError::PathValidation(PathValidationError::ScriptMissing { .. })
            ),
            "{err:?}"
        );
    });
}

#[test]
fn search_symbols_rejects_missing_analyze_headless() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_symbols_ctx(&tmp, mgr.clone());
        ctx.analyze_headless = tmp.path().join("does-not-exist");
        let err = search_symbols(&ctx, "ls", "main", None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                SymbolsError::PathValidation(PathValidationError::AnalyzeHeadlessMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn search_symbols_returns_inspect_not_found_for_unknown_query() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_symbols_ctx(&tmp, mgr.clone());
        let err = search_symbols(&ctx, "missing", "main", None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SymbolsError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn search_symbols_propagates_ambiguous_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_symbols_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "ls", 1);
        let err = search_symbols(&ctx, "ls", "main", None, None)
            .await
            .unwrap_err();
        match err {
            SymbolsError::Inspect(InspectError::Ambiguous { matches, .. }) => {
                assert_eq!(matches, 2);
            }
            other => panic!("expected Inspect(Ambiguous), got {other:?}"),
        }
    });
}

#[test]
fn search_symbols_returns_project_file_missing_when_gpr_absent() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_symbols_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let err = search_symbols(&ctx, "ls", "main", None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SymbolsError::ProjectFileMissing(_)),
            "{err:?}"
        );
    });
}

#[test]
fn search_symbols_returns_lock_held_when_lock_is_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_symbols_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);

        let lock = mgr.lock_for(SHA_LS);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let err = search_symbols(&ctx, "ls", "main", None, None)
            .await
            .unwrap_err();
        match err {
            SymbolsError::LockHeld { sha256 } => assert_eq!(sha256, SHA_LS),
            other => panic!("expected LockHeld, got {other:?}"),
        }
    });
}

#[test]
fn symbols_result_serializes_to_stable_shape() {
    let result = SymbolsResult {
        schema: SEARCH_SYMBOLS_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: "main".to_string(),
        offset: 0,
        limit: 25,
        total_matched: 1,
        truncated: false,
        error_count: 0,
        symbols: vec![SymbolEntry {
            name: "main".to_string(),
            address: "0x100003a40".to_string(),
            kind: "Function".to_string(),
            namespace: "Global".to_string(),
            source: "USER_DEFINED".to_string(),
            refcount: 3,
            external: false,
        }],
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], SEARCH_SYMBOLS_SCHEMA);
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["query"], "main");
    assert_eq!(json["offset"], 0);
    assert_eq!(json["limit"], 25);
    assert_eq!(json["total_matched"], 1);
    assert_eq!(json["truncated"], false);
    assert_eq!(json["error_count"], 0);
    assert_eq!(json["symbols"][0]["name"], "main");
    assert_eq!(json["symbols"][0]["address"], "0x100003a40");
    assert_eq!(json["symbols"][0]["type"], "Function");
    assert_eq!(json["symbols"][0]["namespace"], "Global");
    assert_eq!(json["symbols"][0]["source"], "USER_DEFINED");
    assert_eq!(json["symbols"][0]["refcount"], 3);
    assert_eq!(json["symbols"][0]["external"], false);
    assert!(
        json["symbols"][0].get("kind").is_none(),
        "rust field 'kind' must serialize as 'type'"
    );
}
