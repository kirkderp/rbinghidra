use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::imports_exports::{
    DEFAULT_LIMIT, DEFAULT_OFFSET, DEFAULT_QUERY, ExportEntry, ExportsResult, ImportEntry,
    ImportsExportsContext, ImportsExportsError, ImportsResult, LIST_EXPORTS_SCHEMA,
    LIST_IMPORTS_SCHEMA, MAX_LIMIT, list_exports, list_imports, resolve_limit, resolve_offset,
    resolve_query,
};
use rbm_ghidra::inspect::InspectError;
use rbm_ghidra::project::{
    LIST_EXPORTS_SCRIPT, LIST_IMPORTS_SCRIPT, PathValidationError, ProjectManager,
};
use rbm_ghidra::warm_path::WarmPathError;
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime, write_envelope};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn make_ctx(tmp: &TempDir, manager: Arc<ProjectManager>) -> ImportsExportsContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(LIST_EXPORTS_SCRIPT), b"// stub").unwrap();
    std::fs::write(scripts.join(LIST_IMPORTS_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    ImportsExportsContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn list_exports_script_constant_is_java() {
    assert_eq!(LIST_EXPORTS_SCRIPT, "list_exports.java");
}

#[test]
fn list_imports_script_constant_is_java() {
    assert_eq!(LIST_IMPORTS_SCRIPT, "list_imports.java");
}

#[test]
fn list_exports_schema_constant_pinned() {
    assert_eq!(LIST_EXPORTS_SCHEMA, "rbm.ghidra.list_exports.v0");
}

#[test]
fn list_imports_schema_constant_pinned() {
    assert_eq!(LIST_IMPORTS_SCHEMA, "rbm.ghidra.list_imports.v0");
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
    assert_eq!(resolve_query(Some("printf")), "printf");
    assert_eq!(resolve_query(Some(".*main.*")), ".*main.*");
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
fn warm_path_error_flattens_into_imports_exports_error() {
    let e: ImportsExportsError = WarmPathError::LockHeld {
        sha256: "abc".to_string(),
    }
    .into();
    match e {
        ImportsExportsError::LockHeld { sha256 } => assert_eq!(sha256, "abc"),
        other => panic!("expected LockHeld, got {other:?}"),
    }

    let e: ImportsExportsError =
        WarmPathError::ProjectFileMissing(PathBuf::from("/tmp/proj")).into();
    assert!(
        matches!(e, ImportsExportsError::ProjectFileMissing(_)),
        "{e:?}"
    );

    let e: ImportsExportsError = WarmPathError::HeadlessFailed {
        exit_code: Some(7),
        stderr: "boom".to_string(),
    }
    .into();
    match e {
        ImportsExportsError::HeadlessFailed { exit_code, stderr } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(stderr, "boom");
        }
        other => panic!("expected HeadlessFailed, got {other:?}"),
    }

    let e: ImportsExportsError = WarmPathError::OutputMissing {
        stdout: "out".to_string(),
        stderr: "err".to_string(),
    }
    .into();
    match e {
        ImportsExportsError::OutputMissing { stdout, stderr } => {
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "err");
        }
        other => panic!("expected OutputMissing, got {other:?}"),
    }

    let e: ImportsExportsError = WarmPathError::Io {
        path: PathBuf::from("/tmp/proj"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    }
    .into();
    match e {
        ImportsExportsError::Io { path, source } => {
            assert_eq!(path, PathBuf::from("/tmp/proj"));
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected ImportsExportsError::Io, got {other:?}"),
    }
}

#[test]
fn export_entry_serializes_to_name_and_address() {
    let entry = ExportEntry {
        name: "main".to_string(),
        address: "0x100003a40".to_string(),
    };
    let json = serde_json::to_value(&entry).unwrap();
    assert_eq!(json["name"], "main");
    assert_eq!(json["address"], "0x100003a40");
    assert_eq!(json.as_object().unwrap().len(), 2);
}

#[test]
fn import_entry_serializes_to_name_and_library() {
    let entry = ImportEntry {
        name: "printf".to_string(),
        address: "0x1000".to_string(),
        library: "libc.so.6".to_string(),
        xref_count: 3,
    };
    let json = serde_json::to_value(&entry).unwrap();
    assert_eq!(json["name"], "printf");
    assert_eq!(json["address"], "0x1000");
    assert_eq!(json["library"], "libc.so.6");
    assert_eq!(json["xref_count"], 3);
    assert_eq!(json.as_object().unwrap().len(), 4);
}

#[test]
fn exports_result_serializes_to_stable_shape() {
    let result = ExportsResult {
        schema: LIST_EXPORTS_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: ".*".to_string(),
        offset: 0,
        limit: 25,
        total_matched: 1,
        error_count: 0,
        exports: vec![ExportEntry {
            name: "main".to_string(),
            address: "0x100003a40".to_string(),
        }],
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], LIST_EXPORTS_SCHEMA);
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["query"], ".*");
    assert_eq!(json["offset"], 0);
    assert_eq!(json["limit"], 25);
    assert_eq!(json["total_matched"], 1);
    assert_eq!(json["error_count"], 0);
    assert_eq!(json["exports"][0]["name"], "main");
    assert_eq!(json["exports"][0]["address"], "0x100003a40");
}

#[test]
fn imports_result_serializes_to_stable_shape() {
    let result = ImportsResult {
        schema: LIST_IMPORTS_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: ".*".to_string(),
        offset: 0,
        limit: 25,
        total_matched: 1,
        error_count: 0,
        imports: vec![ImportEntry {
            name: "printf".to_string(),
            address: "0x1000".to_string(),
            library: "libc.so.6".to_string(),
            xref_count: 0,
        }],
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], LIST_IMPORTS_SCHEMA);
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["query"], ".*");
    assert_eq!(json["offset"], 0);
    assert_eq!(json["limit"], 25);
    assert_eq!(json["total_matched"], 1);
    assert_eq!(json["error_count"], 0);
    assert_eq!(json["imports"][0]["name"], "printf");
    assert_eq!(json["imports"][0]["library"], "libc.so.6");
}

#[test]
fn list_exports_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_ctx(&tmp, mgr.clone());
        ctx.scripts_dir = tmp.path().join("does-not-exist");
        let err = list_exports(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ImportsExportsError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn list_exports_rejects_missing_list_exports_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_ctx(&tmp, mgr.clone());
        let scripts = tmp.path().join("scripts-without-exports");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join(LIST_IMPORTS_SCRIPT), b"// stub").unwrap();
        ctx.scripts_dir = scripts;
        let err = list_exports(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        match err {
            ImportsExportsError::PathValidation(PathValidationError::ScriptMissing {
                script,
                ..
            }) => {
                assert_eq!(script, LIST_EXPORTS_SCRIPT);
            }
            other => {
                panic!("expected PathValidation::ScriptMissing(list_exports.java), got {other:?}")
            }
        }
    });
}

#[test]
fn list_imports_rejects_missing_list_imports_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_ctx(&tmp, mgr.clone());
        let scripts = tmp.path().join("scripts-without-imports");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join(LIST_EXPORTS_SCRIPT), b"// stub").unwrap();
        ctx.scripts_dir = scripts;
        let err = list_imports(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        match err {
            ImportsExportsError::PathValidation(PathValidationError::ScriptMissing {
                script,
                ..
            }) => {
                assert_eq!(script, LIST_IMPORTS_SCRIPT);
            }
            other => {
                panic!("expected PathValidation::ScriptMissing(list_imports.java), got {other:?}")
            }
        }
    });
}

#[test]
fn list_exports_rejects_missing_analyze_headless() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_ctx(&tmp, mgr.clone());
        ctx.analyze_headless = tmp.path().join("does-not-exist");
        let err = list_exports(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ImportsExportsError::PathValidation(PathValidationError::AnalyzeHeadlessMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn list_exports_returns_inspect_not_found_for_unknown_query() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_ctx(&tmp, mgr.clone());
        let err = list_exports(&ctx, "missing", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ImportsExportsError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn list_imports_returns_inspect_not_found_for_unknown_query() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_ctx(&tmp, mgr.clone());
        let err = list_imports(&ctx, "missing", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ImportsExportsError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn list_exports_propagates_ambiguous_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "ls", 1);
        let err = list_exports(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        match err {
            ImportsExportsError::Inspect(InspectError::Ambiguous { matches, .. }) => {
                assert_eq!(matches, 2);
            }
            other => panic!("expected Inspect(Ambiguous), got {other:?}"),
        }
    });
}

#[test]
fn list_exports_returns_project_file_missing_when_gpr_absent() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let err = list_exports(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ImportsExportsError::ProjectFileMissing(_)),
            "{err:?}"
        );
    });
}

#[test]
fn list_imports_returns_project_file_missing_when_gpr_absent() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let err = list_imports(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ImportsExportsError::ProjectFileMissing(_)),
            "{err:?}"
        );
    });
}

#[test]
fn list_exports_returns_lock_held_when_lock_is_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);

        let lock = mgr.lock_for(SHA_LS);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let err = list_exports(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        match err {
            ImportsExportsError::LockHeld { sha256 } => assert_eq!(sha256, SHA_LS),
            other => panic!("expected LockHeld, got {other:?}"),
        }
    });
}

#[test]
fn list_imports_returns_lock_held_when_lock_is_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);

        let lock = mgr.lock_for(SHA_LS);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let err = list_imports(&ctx, "ls", None, None, None)
            .await
            .unwrap_err();
        match err {
            ImportsExportsError::LockHeld { sha256 } => assert_eq!(sha256, SHA_LS),
            other => panic!("expected LockHeld, got {other:?}"),
        }
    });
}
