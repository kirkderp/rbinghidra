#[path = "support/tempfile.rs"]
mod tempfile;

use std::sync::Arc;
use std::time::Duration;

use rbinghidra::CachePaths;
use rbinghidra::project::ProjectManager;
use rbinghidra::search_bytes::{
    DEFAULT_MAX_HITS, MAX_HITS_CAP, SearchBytesContext, SearchBytesError, SearchBytesResult,
    resolve_max_hits, search_bytes,
};
use tempfile::TempDir;

fn make_ctx(tmp: &TempDir) -> SearchBytesContext {
    let cache = CachePaths::new(tmp.path().join("cache"));
    let manager = Arc::new(ProjectManager::new(&cache));
    let analyze_headless = tmp.path().join("fake_analyze_headless");
    let scripts_dir = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    SearchBytesContext {
        manager,
        analyze_headless,
        scripts_dir,
        timeout: Duration::from_secs(60),
    }
}

fn make_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn resolve_max_hits_defaults_to_500() {
    assert_eq!(resolve_max_hits(None), DEFAULT_MAX_HITS);
    assert_eq!(resolve_max_hits(None), 500);
}

#[test]
fn resolve_max_hits_clamps_to_cap() {
    assert_eq!(resolve_max_hits(Some(9999)), MAX_HITS_CAP);
    assert_eq!(resolve_max_hits(Some(9999)), 500);
}

#[test]
fn invalid_hex_pattern_odd_length_rejected() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let ctx = make_ctx(&tmp);
        let err = search_bytes(&ctx, "/bin/ls", "4a5", None)
            .await
            .unwrap_err();
        match err {
            SearchBytesError::InvalidHexPattern(pat) => {
                assert_eq!(pat, "4a5");
            }
            other => panic!("expected InvalidHexPattern, got {other:?}"),
        }
    });
}

#[test]
fn invalid_hex_pattern_non_hex_chars_rejected() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let ctx = make_ctx(&tmp);
        let err = search_bytes(&ctx, "/bin/ls", "4xzz", None)
            .await
            .unwrap_err();
        match err {
            SearchBytesError::InvalidHexPattern(pat) => {
                assert_eq!(pat, "4xzz");
            }
            other => panic!("expected InvalidHexPattern, got {other:?}"),
        }
    });
}

#[test]
fn search_bytes_result_serializes_to_stable_shape() {
    let result = SearchBytesResult {
        schema: "rbm.ghidra.search_bytes.v0".to_string(),
        cache_key: "sha256:aabbcc".to_string(),
        sha256: "aabbcc".to_string(),
        program_name: "ls".to_string(),
        hex_pattern: "4889e5".to_string(),
        total_hits: 2,
        truncated: false,
        hits: vec![
            serde_json::json!({"address": "0x100001234", "containing_function": "main"}),
            serde_json::json!({"address": "0x100005678", "containing_function": ""}),
        ],
    };

    let value = serde_json::to_value(&result).unwrap();

    assert_eq!(value["schema"], "rbm.ghidra.search_bytes.v0");
    assert_eq!(value["cache_key"], "sha256:aabbcc");
    assert_eq!(value["sha256"], "aabbcc");
    assert_eq!(value["program_name"], "ls");
    assert_eq!(value["hex_pattern"], "4889e5");
    assert_eq!(value["total_hits"], 2);
    assert_eq!(value["truncated"], false);
    assert_eq!(value["hits"].as_array().unwrap().len(), 2);
    assert_eq!(value["hits"][0]["address"], "0x100001234");
    assert_eq!(value["hits"][0]["containing_function"], "main");
    assert_eq!(value["hits"][1]["containing_function"], "");
}

#[test]
fn invalid_hex_pattern_empty_rejected() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let ctx = make_ctx(&tmp);
        let err = search_bytes(&ctx, "/bin/ls", "", None).await.unwrap_err();
        assert!(
            matches!(err, SearchBytesError::InvalidHexPattern(_)),
            "expected InvalidHexPattern, got {err:?}"
        );
    });
}
