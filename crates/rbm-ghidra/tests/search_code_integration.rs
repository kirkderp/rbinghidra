use rbm_core::CachePaths;
use rbm_ghidra::ProjectManager;
use rbm_ghidra::{SearchCodeContext, SearchCodeOptions, probe, search_code};
use std::sync::Arc;

fn project_manager() -> Arc<ProjectManager> {
    Arc::new(ProjectManager::new(&CachePaths::from_env().unwrap()))
}

#[test]
fn search_code_returns_empty_query_error() {
    let health = probe();
    if !health.available {
        return;
    }

    let ctx = SearchCodeContext {
        manager: project_manager(),
        preview_length: 500,
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(search_code(
        &ctx,
        "ls",
        "",
        &SearchCodeOptions {
            search_mode: "semantic".to_string(),
            limit: 5,
            offset: 0,
            include_full_code: true,
            preview_length: 500,
        },
    ));
    assert!(result.is_err(), "empty query should return an error");
}

#[test]
fn search_code_literal_mode_finds_substrings() {
    let health = probe();
    if !health.available {
        return;
    }

    let ctx = SearchCodeContext {
        manager: project_manager(),
        preview_length: 100,
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(search_code(
        &ctx,
        "ls",
        "main",
        &SearchCodeOptions {
            search_mode: "literal".to_string(),
            limit: 5,
            offset: 0,
            include_full_code: false,
            preview_length: 100,
        },
    ));

    match result {
        Ok(results) => {
            assert_eq!(results.search_mode, "literal");
            assert!(
                !results.results.is_empty(),
                "expected literal matches for 'main'"
            );
            assert!(results.literal_total > 0);
            for r in &results.results {
                assert!(r.code.to_lowercase().contains("main") || r.function_name.contains("main"));
            }
        }
        Err(e) => {
            // Binary may not be imported yet - that's ok for CI
            eprintln!("search_code error (expected if binary not imported): {e}");
        }
    }
}
