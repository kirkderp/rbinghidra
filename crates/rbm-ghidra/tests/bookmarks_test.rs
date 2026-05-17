use std::time::Duration;

use rbm_ghidra::bookmarks::{
    BOOKMARKS_SCHEMA, BookmarkEntry, BookmarksContext, BookmarksError, BookmarksResult,
    get_bookmarks,
};
use rbm_ghidra::project::BOOKMARKS_SCRIPT;

mod common;
use common::{make_manager, make_runtime};

#[test]
fn bookmarks_result_deserializes_from_mock_envelope() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.bookmarks.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "type_filter": "",
        "total_matched": 2,
        "bookmarks": [
            {
                "id": 1,
                "address": "100003a40",
                "type": "Analysis",
                "category": "Found Code",
                "comment": "auto-discovered"
            },
            {
                "id": 2,
                "address": "100003b00",
                "type": "Note",
                "category": "",
                "comment": "interesting branch"
            }
        ]
    });
    let result: BookmarksResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.bookmarks.v0");
    assert_eq!(result.type_filter, "");
    assert_eq!(result.total_matched, 2);
    assert_eq!(result.bookmarks.len(), 2);
    assert_eq!(result.bookmarks[0].id, 1);
    assert_eq!(result.bookmarks[0].address, "100003a40");
    assert_eq!(result.bookmarks[0].bookmark_type, "Analysis");
    assert_eq!(result.bookmarks[0].category, "Found Code");
    assert_eq!(result.bookmarks[0].comment, "auto-discovered");
    assert_eq!(result.bookmarks[1].id, 2);
    assert_eq!(result.bookmarks[1].bookmark_type, "Note");
}

#[test]
fn bookmarks_schema_constant_has_expected_value() {
    assert_eq!(BOOKMARKS_SCHEMA, "rbm.ghidra.bookmarks.v0");
}

#[test]
fn bookmark_entry_serializes_type_field_as_type() {
    let entry = BookmarkEntry {
        id: 42,
        address: "100003a40".to_string(),
        bookmark_type: "Note".to_string(),
        category: "manual".to_string(),
        comment: "test".to_string(),
    };
    let json = serde_json::to_value(&entry).unwrap();
    assert_eq!(json["type"], "Note");
    assert!(json.get("bookmark_type").is_none());
    assert_eq!(json["id"], 42);
    assert_eq!(json["address"], "100003a40");
    assert_eq!(json["category"], "manual");
    assert_eq!(json["comment"], "test");
}

#[test]
fn bookmarks_result_with_empty_type_filter_deserializes() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.bookmarks.v0",
        "cache_key": "sha256:deadbeef",
        "sha256": "deadbeef",
        "program_name": "sample.exe",
        "type_filter": "",
        "total_matched": 0,
        "bookmarks": []
    });
    let result: BookmarksResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.type_filter, "");
    assert_eq!(result.total_matched, 0);
    assert!(result.bookmarks.is_empty());
}

#[test]
fn get_bookmarks_returns_error_when_cache_missing() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let scripts = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join(BOOKMARKS_SCRIPT), b"// stub").unwrap();
        let analyze = tmp.path().join("analyzeHeadless");
        std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
        let ctx = BookmarksContext {
            manager: mgr,
            analyze_headless: analyze,
            scripts_dir: scripts,
            timeout: Duration::from_secs(5),
        };
        let err = get_bookmarks(&ctx, "nonexistent_binary", "")
            .await
            .unwrap_err();
        assert!(
            matches!(err, BookmarksError::Inspect(_)),
            "expected Inspect error, got {err:?}"
        );
    });
}
