use std::time::Duration;

use rbm_ghidra::project::THUNK_TARGET_SCRIPT;
use rbm_ghidra::thunk_target::{
    THUNK_TARGET_SCHEMA, ThunkTargetContext, ThunkTargetError, ThunkTargetResult, get_thunk_target,
};

mod common;
use common::{make_manager, make_runtime};

#[test]
fn thunk_target_result_deserializes_is_thunk_true() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.thunk_target.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "query": "printf",
        "function_name": "printf",
        "address": "100001234",
        "is_thunk": true,
        "target_name": "libc.printf",
        "target_address": "200005678",
        "resolution_error": ""
    });
    let result: ThunkTargetResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.thunk_target.v0");
    assert_eq!(result.query, "printf");
    assert_eq!(result.function_name, "printf");
    assert_eq!(result.address, "100001234");
    assert!(result.is_thunk);
    assert_eq!(result.target_name, "libc.printf");
    assert_eq!(result.target_address, "200005678");
    assert_eq!(result.resolution_error, "");
}

#[test]
fn thunk_target_result_deserializes_is_thunk_false() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.thunk_target.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "query": "main",
        "function_name": "main",
        "address": "100003a40",
        "is_thunk": false,
        "target_name": "",
        "target_address": "",
        "resolution_error": ""
    });
    let result: ThunkTargetResult = serde_json::from_value(json).unwrap();
    assert!(!result.is_thunk);
    assert_eq!(result.target_name, "");
    assert_eq!(result.target_address, "");
    assert_eq!(result.query, "main");
}

#[test]
fn get_thunk_target_returns_empty_query_for_blank_address() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let scripts = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join(THUNK_TARGET_SCRIPT), b"// stub").unwrap();
        let analyze = tmp.path().join("analyzeHeadless");
        std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
        let ctx = ThunkTargetContext {
            manager: mgr,
            analyze_headless: analyze,
            scripts_dir: scripts,
            timeout: Duration::from_secs(5),
        };
        let err = get_thunk_target(&ctx, "ls", "   ").await.unwrap_err();
        assert!(
            matches!(err, ThunkTargetError::EmptyQuery),
            "expected EmptyQuery, got {err:?}"
        );
    });
}

#[test]
fn thunk_target_schema_constant_has_expected_value() {
    assert_eq!(THUNK_TARGET_SCHEMA, "rbm.ghidra.thunk_target.v0");
}
