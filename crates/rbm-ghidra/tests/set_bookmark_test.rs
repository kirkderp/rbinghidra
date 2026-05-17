use std::time::Duration;

use rbm_ghidra::project::SET_BOOKMARK_SCRIPT;
use rbm_ghidra::set_bookmark::{
    SET_BOOKMARK_SCHEMA, SetBookmarkContext, SetBookmarkError, SetBookmarkResult, set_bookmark,
};

mod common;
use common::{make_manager, make_runtime};

#[test]
fn set_bookmark_result_deserializes_from_mock_envelope() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.set_bookmark.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "address": "100003a40",
        "bookmark_type": "Note",
        "category": "suspicious",
        "comment": "investigate this",
        "created_id": 7,
        "address_error": "",
        "bookmark_error": ""
    });
    let result: SetBookmarkResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.set_bookmark.v0");
    assert_eq!(result.address, "100003a40");
    assert_eq!(result.bookmark_type, "Note");
    assert_eq!(result.category, "suspicious");
    assert_eq!(result.comment, "investigate this");
    assert_eq!(result.created_id, 7);
    assert_eq!(result.address_error, "");
    assert_eq!(result.bookmark_error, "");
}

#[test]
fn set_bookmark_returns_empty_address_for_blank_address() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let scripts = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join(SET_BOOKMARK_SCRIPT), b"// stub").unwrap();
        let analyze = tmp.path().join("analyzeHeadless");
        std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
        let ctx = SetBookmarkContext {
            manager: mgr,
            analyze_headless: analyze,
            scripts_dir: scripts,
            timeout: Duration::from_secs(5),
        };
        let err = set_bookmark(&ctx, "ls", "   ", "Note", "", "")
            .await
            .unwrap_err();
        assert!(
            matches!(err, SetBookmarkError::EmptyAddress),
            "expected EmptyAddress, got {err:?}"
        );
    });
}

#[test]
fn set_bookmark_schema_constant_has_expected_value() {
    assert_eq!(SET_BOOKMARK_SCHEMA, "rbm.ghidra.set_bookmark.v0");
}

#[test]
fn set_bookmark_result_serializes_to_stable_shape() {
    let result = SetBookmarkResult {
        schema: "rbm.ghidra.set_bookmark.v0".to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        address: "100003a40".to_string(),
        bookmark_type: "Analysis".to_string(),
        category: "Found Code".to_string(),
        comment: "entry point".to_string(),
        created_id: 3,
        address_error: String::new(),
        bookmark_error: String::new(),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], "rbm.ghidra.set_bookmark.v0");
    assert_eq!(json["address"], "100003a40");
    assert_eq!(json["bookmark_type"], "Analysis");
    assert_eq!(json["category"], "Found Code");
    assert_eq!(json["comment"], "entry point");
    assert_eq!(json["created_id"], 3);
    assert_eq!(json["address_error"], "");
    assert_eq!(json["bookmark_error"], "");
}
