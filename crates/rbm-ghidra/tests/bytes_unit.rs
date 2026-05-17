use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::bytes::{
    DEFAULT_SIZE, MAX_SIZE, READ_BYTES_SCHEMA, ReadBytesContext, ReadBytesError, ReadBytesResult,
    read_bytes, resolve_size,
};
use rbm_ghidra::inspect::InspectError;
use rbm_ghidra::project::{PathValidationError, ProjectManager, READ_BYTES_SCRIPT};
use rbm_ghidra::warm_path::WarmPathError;
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime, write_envelope};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn make_bytes_ctx(tmp: &TempDir, manager: Arc<ProjectManager>) -> ReadBytesContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(READ_BYTES_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    ReadBytesContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn read_bytes_script_constant_is_java() {
    assert_eq!(READ_BYTES_SCRIPT, "read_bytes.java");
}

#[test]
fn read_bytes_schema_constant_pinned() {
    assert_eq!(READ_BYTES_SCHEMA, "rbm.ghidra.read_bytes.v0");
}

#[test]
fn size_constants_pinned() {
    assert_eq!(DEFAULT_SIZE, 32);
    assert_eq!(MAX_SIZE, 8192);
}

#[test]
fn resolve_size_defaults_none_to_thirty_two() {
    assert_eq!(resolve_size(None), 32);
}

#[test]
fn resolve_size_passes_through_valid() {
    assert_eq!(resolve_size(Some(1)), 1);
    assert_eq!(resolve_size(Some(32)), 32);
    assert_eq!(resolve_size(Some(1024)), 1024);
    assert_eq!(resolve_size(Some(MAX_SIZE)), MAX_SIZE);
}

#[test]
fn resolve_size_clamps_above_max() {
    assert_eq!(resolve_size(Some(MAX_SIZE + 1)), MAX_SIZE);
    assert_eq!(resolve_size(Some(100_000)), MAX_SIZE);
    assert_eq!(resolve_size(Some(u64::MAX)), MAX_SIZE);
}

#[test]
fn resolve_size_zero_is_passed_through() {
    assert_eq!(resolve_size(Some(0)), 0);
}

#[test]
fn read_bytes_rejects_empty_address() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_bytes_ctx(&tmp, mgr.clone());
        let err = read_bytes(&ctx, "ls", "", None).await.unwrap_err();
        assert!(matches!(err, ReadBytesError::EmptyAddress), "{err:?}");

        let err = read_bytes(&ctx, "ls", "   ", None).await.unwrap_err();
        assert!(matches!(err, ReadBytesError::EmptyAddress), "{err:?}");
    });
}

#[test]
fn warm_path_error_flattens_into_read_bytes_error() {
    let e: ReadBytesError = WarmPathError::LockHeld {
        sha256: "abc".to_string(),
    }
    .into();
    match e {
        ReadBytesError::LockHeld { sha256 } => assert_eq!(sha256, "abc"),
        other => panic!("expected LockHeld, got {other:?}"),
    }

    let e: ReadBytesError = WarmPathError::ProjectFileMissing(PathBuf::from("/tmp/proj")).into();
    assert!(matches!(e, ReadBytesError::ProjectFileMissing(_)), "{e:?}");

    let e: ReadBytesError = WarmPathError::HeadlessFailed {
        exit_code: Some(7),
        stderr: "boom".to_string(),
    }
    .into();
    match e {
        ReadBytesError::HeadlessFailed { exit_code, stderr } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(stderr, "boom");
        }
        other => panic!("expected HeadlessFailed, got {other:?}"),
    }

    let e: ReadBytesError = WarmPathError::OutputMissing {
        stdout: "out".to_string(),
        stderr: "err".to_string(),
    }
    .into();
    match e {
        ReadBytesError::OutputMissing { stdout, stderr } => {
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "err");
        }
        other => panic!("expected OutputMissing, got {other:?}"),
    }

    let e: ReadBytesError = WarmPathError::Io {
        path: PathBuf::from("/tmp/proj"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    }
    .into();
    match e {
        ReadBytesError::Io { path, source } => {
            assert_eq!(path, PathBuf::from("/tmp/proj"));
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected ReadBytesError::Io, got {other:?}"),
    }
}

#[test]
fn read_bytes_result_serializes_to_stable_shape() {
    let result = ReadBytesResult {
        schema: READ_BYTES_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        address: "0x100003a40".to_string(),
        resolved_address: "100003a40".to_string(),
        size: 4,
        hex: "4d5a9000".to_string(),
        ascii_preview: "MZ..".to_string(),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], READ_BYTES_SCHEMA);
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["address"], "0x100003a40");
    assert_eq!(json["resolved_address"], "100003a40");
    assert_eq!(json["size"], 4);
    assert_eq!(json["hex"], "4d5a9000");
    assert_eq!(json["ascii_preview"], "MZ..");
    assert_eq!(json.as_object().unwrap().len(), 9);
}

#[test]
fn read_bytes_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_bytes_ctx(&tmp, mgr.clone());
        ctx.scripts_dir = tmp.path().join("does-not-exist");
        let err = read_bytes(&ctx, "ls", "0x1000", None).await.unwrap_err();
        assert!(
            matches!(
                err,
                ReadBytesError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn read_bytes_rejects_missing_read_bytes_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_bytes_ctx(&tmp, mgr.clone());
        let scripts = tmp.path().join("scripts-empty");
        std::fs::create_dir_all(&scripts).unwrap();
        ctx.scripts_dir = scripts;
        let err = read_bytes(&ctx, "ls", "0x1000", None).await.unwrap_err();
        match err {
            ReadBytesError::PathValidation(PathValidationError::ScriptMissing {
                script, ..
            }) => {
                assert_eq!(script, READ_BYTES_SCRIPT);
            }
            other => panic!("expected PathValidation::ScriptMissing, got {other:?}"),
        }
    });
}

#[test]
fn read_bytes_rejects_missing_analyze_headless() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_bytes_ctx(&tmp, mgr.clone());
        ctx.analyze_headless = tmp.path().join("does-not-exist");
        let err = read_bytes(&ctx, "ls", "0x1000", None).await.unwrap_err();
        assert!(
            matches!(
                err,
                ReadBytesError::PathValidation(PathValidationError::AnalyzeHeadlessMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn read_bytes_returns_inspect_not_found_for_unknown_binary() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_bytes_ctx(&tmp, mgr.clone());
        let err = read_bytes(&ctx, "missing", "0x1000", None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ReadBytesError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn read_bytes_propagates_ambiguous_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_bytes_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "ls", 1);
        let err = read_bytes(&ctx, "ls", "0x1000", None).await.unwrap_err();
        match err {
            ReadBytesError::Inspect(InspectError::Ambiguous { matches, .. }) => {
                assert_eq!(matches, 2);
            }
            other => panic!("expected Inspect(Ambiguous), got {other:?}"),
        }
    });
}

#[test]
fn read_bytes_returns_project_file_missing_when_gpr_absent() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_bytes_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let err = read_bytes(&ctx, "ls", "0x1000", None).await.unwrap_err();
        assert!(
            matches!(err, ReadBytesError::ProjectFileMissing(_)),
            "{err:?}"
        );
    });
}

#[test]
fn read_bytes_returns_lock_held_when_lock_is_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_bytes_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);

        let lock = mgr.lock_for(SHA_LS);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let err = read_bytes(&ctx, "ls", "0x1000", None).await.unwrap_err();
        match err {
            ReadBytesError::LockHeld { sha256 } => assert_eq!(sha256, SHA_LS),
            other => panic!("expected LockHeld, got {other:?}"),
        }
    });
}
