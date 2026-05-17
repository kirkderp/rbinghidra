use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::inspect::InspectError;
use rbm_ghidra::project::{PathValidationError, ProjectManager, SEARCH_STRINGS_SCRIPT};
use rbm_ghidra::strings::{
    DEFAULT_LIMIT, DEFAULT_OFFSET, DEFAULT_QUERY, MAX_LIMIT, SEARCH_STRINGS_SCHEMA,
    SearchStringsContext, SearchStringsError, SearchStringsResult, StringEntry, resolve_limit,
    resolve_offset, resolve_query, search_strings,
};
use rbm_ghidra::warm_path::WarmPathError;
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime, write_envelope};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn make_strings_ctx(tmp: &TempDir, manager: Arc<ProjectManager>) -> SearchStringsContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(SEARCH_STRINGS_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    SearchStringsContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_millis(100),
    }
}

#[test]
fn search_strings_script_constant_is_java() {
    assert_eq!(SEARCH_STRINGS_SCRIPT, "search_strings.java");
}

#[test]
fn search_strings_schema_constant_pinned() {
    assert_eq!(SEARCH_STRINGS_SCHEMA, "rbm.ghidra.search_strings.v0");
}

#[test]
fn pagination_constants_pinned() {
    assert_eq!(DEFAULT_QUERY, ".*");
    assert_eq!(DEFAULT_OFFSET, 0);
    assert_eq!(DEFAULT_LIMIT, 25);
    assert_eq!(MAX_LIMIT, 1000);
}

#[test]
fn resolve_query_returns_default_for_none_and_empty() {
    assert_eq!(resolve_query(None), ".*");
    assert_eq!(resolve_query(Some("")), ".*");
    assert_eq!(resolve_query(Some("usage")), "usage");
    assert_eq!(resolve_query(Some(".*error.*")), ".*error.*");
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
fn warm_path_error_flattens_into_search_strings_error() {
    let e: SearchStringsError = WarmPathError::LockHeld {
        sha256: "abc".to_string(),
    }
    .into();
    match e {
        SearchStringsError::LockHeld { sha256 } => assert_eq!(sha256, "abc"),
        other => panic!("expected LockHeld, got {other:?}"),
    }

    let e: SearchStringsError =
        WarmPathError::ProjectFileMissing(PathBuf::from("/tmp/proj")).into();
    assert!(
        matches!(e, SearchStringsError::ProjectFileMissing(_)),
        "{e:?}"
    );

    let e: SearchStringsError = WarmPathError::HeadlessFailed {
        exit_code: Some(7),
        stderr: "boom".to_string(),
    }
    .into();
    match e {
        SearchStringsError::HeadlessFailed { exit_code, stderr } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(stderr, "boom");
        }
        other => panic!("expected HeadlessFailed, got {other:?}"),
    }

    let e: SearchStringsError = WarmPathError::OutputMissing {
        stdout: "out".to_string(),
        stderr: "err".to_string(),
    }
    .into();
    match e {
        SearchStringsError::OutputMissing { stdout, stderr } => {
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "err");
        }
        other => panic!("expected OutputMissing, got {other:?}"),
    }

    let e: SearchStringsError = WarmPathError::Io {
        path: PathBuf::from("/tmp/proj"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    }
    .into();
    match e {
        SearchStringsError::Io { path, source } => {
            assert_eq!(path, PathBuf::from("/tmp/proj"));
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected SearchStringsError::Io, got {other:?}"),
    }
}

#[test]
fn string_entry_serializes_to_stable_shape() {
    let entry = StringEntry {
        address: "0x100004000".to_string(),
        value: "Usage: %s [OPTION]...".to_string(),
        length: 21,
        data_type: "string".to_string(),
        xref_count: 2,
        containing_function: "main".to_string(),
    };
    let json = serde_json::to_value(&entry).unwrap();
    assert_eq!(json["address"], "0x100004000");
    assert_eq!(json["value"], "Usage: %s [OPTION]...");
    assert_eq!(json["length"], 21);
    assert_eq!(json["data_type"], "string");
    assert_eq!(json["xref_count"], 2);
    assert_eq!(json["containing_function"], "main");
    assert_eq!(json.as_object().unwrap().len(), 6);
}

#[test]
fn search_strings_result_serializes_to_stable_shape() {
    let result = SearchStringsResult {
        schema: SEARCH_STRINGS_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: ".*".to_string(),
        offset: 0,
        limit: 25,
        total_matched: 1,
        truncated: false,
        error_count: 0,
        strings: vec![StringEntry {
            address: "0x100004000".to_string(),
            value: "Usage: %s".to_string(),
            length: 9,
            data_type: "string".to_string(),
            xref_count: 0,
            containing_function: String::new(),
        }],
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], SEARCH_STRINGS_SCHEMA);
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["query"], ".*");
    assert_eq!(json["offset"], 0);
    assert_eq!(json["limit"], 25);
    assert_eq!(json["total_matched"], 1);
    assert_eq!(json["truncated"], false);
    assert_eq!(json["error_count"], 0);
    assert_eq!(json["strings"][0]["address"], "0x100004000");
    assert_eq!(json["strings"][0]["value"], "Usage: %s");
    assert_eq!(json["strings"][0]["length"], 9);
    assert_eq!(json["strings"][0]["data_type"], "string");
}

#[test]
fn search_strings_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_strings_ctx(&tmp, mgr.clone());
        ctx.scripts_dir = tmp.path().join("does-not-exist");
        let err = search_strings(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                SearchStringsError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn search_strings_rejects_missing_search_strings_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_strings_ctx(&tmp, mgr.clone());
        let scripts = tmp.path().join("scripts-empty");
        std::fs::create_dir_all(&scripts).unwrap();
        ctx.scripts_dir = scripts;
        let err = search_strings(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        match err {
            SearchStringsError::PathValidation(PathValidationError::ScriptMissing {
                script,
                ..
            }) => {
                assert_eq!(script, SEARCH_STRINGS_SCRIPT);
            }
            other => panic!("expected PathValidation::ScriptMissing, got {other:?}"),
        }
    });
}

#[test]
fn search_strings_rejects_missing_analyze_headless() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_strings_ctx(&tmp, mgr.clone());
        ctx.analyze_headless = tmp.path().join("does-not-exist");
        let err = search_strings(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                SearchStringsError::PathValidation(PathValidationError::AnalyzeHeadlessMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn search_strings_returns_inspect_not_found_for_unknown_binary() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_strings_ctx(&tmp, mgr.clone());
        let err = search_strings(&ctx, "missing", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SearchStringsError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn search_strings_propagates_ambiguous_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_strings_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "ls", 1);
        let err = search_strings(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        match err {
            SearchStringsError::Inspect(InspectError::Ambiguous { matches, .. }) => {
                assert_eq!(matches, 2);
            }
            other => panic!("expected Inspect(Ambiguous), got {other:?}"),
        }
    });
}

#[test]
fn search_strings_returns_project_file_missing_when_gpr_absent() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_strings_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let err = search_strings(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SearchStringsError::ProjectFileMissing(_)),
            "{err:?}"
        );
    });
}

#[test]
fn search_strings_returns_lock_held_when_lock_is_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_strings_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);

        let lock = mgr.lock_for(SHA_LS);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let err = search_strings(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        match err {
            SearchStringsError::LockHeld { sha256 } => assert_eq!(sha256, SHA_LS),
            other => panic!("expected LockHeld, got {other:?}"),
        }
    });
}
