use rbinghidra::search_decompilation::{
    DEFAULT_CONTEXT_LINES, DEFAULT_LIMIT, DEFAULT_MAX_FUNCTIONS, MAX_CONTEXT_LINES, MAX_LIMIT,
    MAX_MAX_FUNCTIONS, resolve_context_lines, resolve_limit, resolve_max_functions,
};

#[test]
fn test_resolve_limit_none() {
    assert_eq!(resolve_limit(None), DEFAULT_LIMIT);
}

#[test]
fn test_resolve_limit_some() {
    assert_eq!(resolve_limit(Some(100)), 100);
}

#[test]
fn test_resolve_limit_some_above_max() {
    assert_eq!(resolve_limit(Some(MAX_LIMIT + 100)), MAX_LIMIT);
}

#[test]
fn test_resolve_limit_some_max() {
    assert_eq!(resolve_limit(Some(MAX_LIMIT)), MAX_LIMIT);
}

#[test]
fn test_resolve_context_lines_none() {
    assert_eq!(resolve_context_lines(None), DEFAULT_CONTEXT_LINES);
}

#[test]
fn test_resolve_context_lines_some() {
    assert_eq!(resolve_context_lines(Some(5)), 5);
}

#[test]
fn test_resolve_context_lines_some_above_max() {
    assert_eq!(
        resolve_context_lines(Some(MAX_CONTEXT_LINES + 5)),
        MAX_CONTEXT_LINES
    );
}

#[test]
fn test_resolve_context_lines_some_max() {
    assert_eq!(
        resolve_context_lines(Some(MAX_CONTEXT_LINES)),
        MAX_CONTEXT_LINES
    );
}

#[test]
fn test_resolve_max_functions_none() {
    assert_eq!(resolve_max_functions(None), DEFAULT_MAX_FUNCTIONS);
}

#[test]
fn test_resolve_max_functions_some() {
    assert_eq!(resolve_max_functions(Some(100)), 100);
}

#[test]
fn test_resolve_max_functions_some_above_max() {
    assert_eq!(
        resolve_max_functions(Some(MAX_MAX_FUNCTIONS + 100)),
        MAX_MAX_FUNCTIONS
    );
}

#[test]
fn test_resolve_max_functions_some_max() {
    assert_eq!(
        resolve_max_functions(Some(MAX_MAX_FUNCTIONS)),
        MAX_MAX_FUNCTIONS
    );
}

#[test]
fn search_decompilation_result_serializes_to_stable_shape() {
    let result = rbinghidra::search_decompilation::SearchDecompilationResult {
        schema: "rbm.ghidra.search_decompilation.v0".to_string(),
        cache_key: "sha256:aabbcc".to_string(),
        sha256: "aabbcc".to_string(),
        program_name: "ls".to_string(),
        query: "printf".to_string(),
        offset: 0,
        limit: 25,
        context_lines: 2,
        max_functions: 500,
        total_matched: 1,
        functions_scanned: 10,
        truncated: false,
        error_count: 0,
        hits: vec![rbinghidra::search_decompilation::DecompilationSearchHit {
            function_name: "main".to_string(),
            address: "0x100001234".to_string(),
            signature: "int main(int argc, char **argv)".to_string(),
            match_count: 1,
            first_line: 10,
            snippet: vec!["  printf(\"hello world\");".to_string()],
        }],
    };

    let value = serde_json::to_value(&result).unwrap();

    assert_eq!(value["schema"], "rbm.ghidra.search_decompilation.v0");
    assert_eq!(value["cache_key"], "sha256:aabbcc");
    assert_eq!(value["sha256"], "aabbcc");
    assert_eq!(value["program_name"], "ls");
    assert_eq!(value["query"], "printf");
    assert_eq!(value["offset"], 0);
    assert_eq!(value["limit"], 25);
    assert_eq!(value["context_lines"], 2);
    assert_eq!(value["max_functions"], 500);
    assert_eq!(value["total_matched"], 1);
    assert_eq!(value["functions_scanned"], 10);
    assert_eq!(value["truncated"], false);
    assert_eq!(value["error_count"], 0);
    assert_eq!(value["hits"].as_array().unwrap().len(), 1);
    assert_eq!(value["hits"][0]["function_name"], "main");
    assert_eq!(value["hits"][0]["address"], "0x100001234");
    assert_eq!(
        value["hits"][0]["signature"],
        "int main(int argc, char **argv)"
    );
    assert_eq!(value["hits"][0]["match_count"], 1);
    assert_eq!(value["hits"][0]["first_line"], 10);
    assert_eq!(value["hits"][0]["snippet"][0], "  printf(\"hello world\");");
}

#[path = "support/tempfile.rs"]
mod tempfile;

use std::sync::Arc;
use std::time::Duration;

use rbinghidra::CachePaths;
use rbinghidra::project::ProjectManager;
use rbinghidra::search_decompilation::{
    SearchDecompilationContext, SearchDecompilationError, search_decompilation,
};
use tempfile::TempDir;

fn make_ctx(tmp: &TempDir) -> SearchDecompilationContext {
    let cache = CachePaths::new(tmp.path().join("cache"));
    let manager = Arc::new(ProjectManager::new(&cache));
    let analyze_headless = tmp.path().join("fake_analyze_headless");
    let scripts_dir = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    SearchDecompilationContext {
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
fn invalid_query_empty_rejected() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let ctx = make_ctx(&tmp);
        let err = search_decompilation(&ctx, "/bin/ls", "", None, None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SearchDecompilationError::EmptyQuery),
            "expected EmptyQuery, got {err:?}"
        );
    });
}
