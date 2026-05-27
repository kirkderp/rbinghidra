use std::sync::Arc;
use std::time::Duration;

use rbm_core::CachePaths;
use rbm_ghidra::project::ProjectManager;
use rbm_ghidra::search_decompilation::{
    DEFAULT_CONTEXT_LINES, DEFAULT_LIMIT, DEFAULT_MAX_FUNCTIONS, MAX_CONTEXT_LINES, MAX_LIMIT,
    MAX_MAX_FUNCTIONS, SearchDecompilationContext, SearchDecompilationError,
    SearchDecompilationResult, resolve_context_lines, resolve_limit, resolve_max_functions,
    search_decompilation,
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
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn resolve_limit_defaults_to_25() {
    assert_eq!(resolve_limit(None), DEFAULT_LIMIT);
    assert_eq!(resolve_limit(None), 25);
}

#[test]
fn resolve_limit_clamps_to_cap() {
    assert_eq!(resolve_limit(Some(9999)), MAX_LIMIT);
    assert_eq!(resolve_limit(Some(9999)), 200);
}

#[test]
fn resolve_context_lines_defaults_to_2() {
    assert_eq!(resolve_context_lines(None), DEFAULT_CONTEXT_LINES);
    assert_eq!(resolve_context_lines(None), 2);
}

#[test]
fn resolve_context_lines_clamps_to_cap() {
    assert_eq!(resolve_context_lines(Some(9999)), MAX_CONTEXT_LINES);
    assert_eq!(resolve_context_lines(Some(9999)), 10);
}

#[test]
fn resolve_max_functions_defaults_to_500() {
    assert_eq!(resolve_max_functions(None), DEFAULT_MAX_FUNCTIONS);
    assert_eq!(resolve_max_functions(None), 500);
}

#[test]
fn resolve_max_functions_clamps_to_cap() {
    assert_eq!(resolve_max_functions(Some(99999)), MAX_MAX_FUNCTIONS);
    assert_eq!(resolve_max_functions(Some(99999)), 5000);
}

#[test]
fn empty_query_rejected() {
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

        let err_whitespace =
            search_decompilation(&ctx, "/bin/ls", "   \n\t ", None, None, None, None)
                .await
                .unwrap_err();
        assert!(
            matches!(err_whitespace, SearchDecompilationError::EmptyQuery),
            "expected EmptyQuery for whitespace string, got {err_whitespace:?}"
        );
    });
}

#[test]
fn search_decompilation_result_serializes_to_stable_shape() {
    let result = SearchDecompilationResult {
        schema: "rbm.ghidra.search_decompilation.v0".to_string(),
        cache_key: "sha256:aabbcc".to_string(),
        sha256: "aabbcc".to_string(),
        program_name: "ls".to_string(),
        query: "malloc".to_string(),
        offset: 0,
        limit: 25,
        context_lines: 2,
        max_functions: 500,
        total_matched: 1,
        functions_scanned: 10,
        truncated: false,
        error_count: 0,
        hits: vec![rbm_ghidra::search_decompilation::DecompilationSearchHit {
            function_name: "main".to_string(),
            address: "0x100000".to_string(),
            signature: "int main()".to_string(),
            match_count: 1,
            first_line: 10,
            snippet: vec!["  void* p = malloc(10);".to_string()],
        }],
    };

    let value = serde_json::to_value(&result).unwrap();

    assert_eq!(value["schema"], "rbm.ghidra.search_decompilation.v0");
    assert_eq!(value["cache_key"], "sha256:aabbcc");
    assert_eq!(value["sha256"], "aabbcc");
    assert_eq!(value["program_name"], "ls");
    assert_eq!(value["query"], "malloc");
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
    assert_eq!(value["hits"][0]["address"], "0x100000");
}
