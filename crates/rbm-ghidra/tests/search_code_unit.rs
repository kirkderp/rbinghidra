use std::sync::Arc;

use rbm_core::CachePaths;
use rbm_ghidra::{
    CODE_INDEX_OUTPUT_FILE, CODE_INDEX_SCHEMA, CodeIndexEntry, CodeIndexEnvelope, ProjectManager,
    SearchCodeContext, SearchCodeError, SearchCodeOptions, search_code,
};
use tempfile::TempDir;

fn make_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn make_manager() -> (TempDir, Arc<ProjectManager>) {
    let tmp = TempDir::new().unwrap();
    let cache = CachePaths::new(tmp.path().join("cache"));
    (tmp, Arc::new(ProjectManager::new(&cache)))
}

fn write_functions_output(project_dir: &std::path::Path) {
    let functions_json = serde_json::json!({
        "schema": "rbm.ghidra.functions.v0",
        "program_name": "sample.exe",
        "program_path": "/tmp/sample.exe",
        "function_count": 2,
        "error_count": 0,
        "functions": []
    });
    std::fs::create_dir_all(project_dir).unwrap();
    std::fs::write(
        project_dir.join("functions.json"),
        serde_json::to_vec_pretty(&functions_json).unwrap(),
    )
    .unwrap();
}

fn sample_code_index() -> CodeIndexEnvelope {
    CodeIndexEnvelope {
        schema: CODE_INDEX_SCHEMA.to_string(),
        program_name: "sample.exe".to_string(),
        program_path: "/tmp/sample.exe".to_string(),
        function_count: 2,
        error_count: 0,
        functions: vec![
            CodeIndexEntry {
                name: "FUN_401000".to_string(),
                address: "00401000".to_string(),
                signature: "void FUN_401000()".to_string(),
                pseudocode: "puts(\"Failed to generate subnet IPs\");".to_string(),
                callers: vec!["entry".to_string()],
                callees: vec!["puts".to_string()],
                decompile_error: String::new(),
            },
            CodeIndexEntry {
                name: "FUN_402000".to_string(),
                address: "00402000".to_string(),
                signature: "void FUN_402000()".to_string(),
                pseudocode: "return 0;".to_string(),
                callers: vec![],
                callees: vec![],
                decompile_error: String::new(),
            },
        ],
    }
}

#[test]
fn search_code_uses_persisted_literal_index() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, manager) = make_manager();
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let project_dir = manager.project_dir(sha);
        write_functions_output(&project_dir);
        std::fs::write(
            project_dir.join(CODE_INDEX_OUTPUT_FILE),
            serde_json::to_vec_pretty(&sample_code_index()).unwrap(),
        )
        .unwrap();

        let ctx = SearchCodeContext {
            manager,
            preview_length: 64,
        };
        let result = search_code(
            &ctx,
            &format!("sha256:{sha}"),
            "Failed to generate subnet IPs",
            &SearchCodeOptions {
                search_mode: "literal".to_string(),
                limit: 5,
                offset: 0,
                include_full_code: false,
                preview_length: 64,
            },
        )
        .await
        .unwrap();

        assert_eq!(result.schema, "rbm.ghidra.search_code.v0");
        assert_eq!(result.literal_total, 1);
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].function_name, "FUN_401000");
    });
}

#[test]
fn search_code_requires_built_index() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, manager) = make_manager();
        let sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let project_dir = manager.project_dir(sha);
        write_functions_output(&project_dir);

        let ctx = SearchCodeContext {
            manager,
            preview_length: 64,
        };
        let err = search_code(
            &ctx,
            &format!("sha256:{sha}"),
            "needle",
            &SearchCodeOptions {
                search_mode: "literal".to_string(),
                limit: 5,
                offset: 0,
                include_full_code: false,
                preview_length: 64,
            },
        )
        .await
        .unwrap_err();

        match err {
            SearchCodeError::IndexMissing { binary_query, path } => {
                assert_eq!(binary_query, format!("sha256:{sha}"));
                assert_eq!(path, project_dir.join(CODE_INDEX_OUTPUT_FILE));
            }
            other => panic!("expected IndexMissing, got {other:?}"),
        }
    });
}
