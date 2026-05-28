use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::function_stats::{
    FUNCTION_STATS_SCHEMA, FunctionStatsContext, FunctionStatsError, FunctionStatsResult,
    get_function_stats,
};
use rbm_ghidra::project::FUNCTION_STATS_SCRIPT;

mod common;
use common::{make_manager, make_runtime};

fn make_function_stats_ctx(
    tmp: &tempfile::TempDir,
    manager: Arc<rbm_ghidra::ProjectManager>,
) -> FunctionStatsContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(FUNCTION_STATS_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    FunctionStatsContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn function_stats_schema_constant_has_expected_value() {
    assert_eq!(FUNCTION_STATS_SCHEMA, "rbm.ghidra.function_stats.v0");
}

#[test]
fn function_stats_result_deserializes_from_mock_envelope() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.function_stats.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "query": "main",
        "resolved_address": "0x100003a40",
        "resolved_symbol_name": "main",
        "function_name": "main",
        "address": "0x100003a40",
        "signature": "int main(int argc, char **argv)",
        "size_bytes": 100,
        "instruction_count": 25,
        "basic_block_count": 5,
        "cyclomatic_complexity": 3,
        "call_count": 2,
        "external_call_count": 1,
        "memory_reference_count": 10,
        "imports_by_library": {},
        "has_stack_frame": true,
        "resolution_error": ""
    });
    let result: FunctionStatsResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.function_stats.v0");
    assert_eq!(result.query, "main");
    assert_eq!(result.function_name, "main");
    assert_eq!(result.address, "0x100003a40");
    assert_eq!(result.size_bytes, 100);
    assert_eq!(result.instruction_count, 25);
    assert_eq!(result.basic_block_count, 5);
    assert_eq!(result.cyclomatic_complexity, 3);
    assert_eq!(result.call_count, 2);
    assert_eq!(result.external_call_count, 1);
    assert_eq!(result.memory_reference_count, 10);
    assert!(result.has_stack_frame);
    assert_eq!(result.resolution_error, "");
}

#[test]
fn function_stats_result_serializes_to_stable_shape() {
    let result = FunctionStatsResult {
        schema: "rbm.ghidra.function_stats.v0".to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: "main".to_string(),
        resolved_address: "0x100003a40".to_string(),
        resolved_symbol_name: "main".to_string(),
        function_name: "main".to_string(),
        address: "0x100003a40".to_string(),
        signature: "int main(int argc, char **argv)".to_string(),
        size_bytes: 100,
        instruction_count: 25,
        basic_block_count: 5,
        cyclomatic_complexity: 3,
        call_count: 2,
        external_call_count: 1,
        memory_reference_count: 10,
        imports_by_library: serde_json::json!({}),
        has_stack_frame: true,
        resolution_error: String::new(),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], "rbm.ghidra.function_stats.v0");
    assert_eq!(json["query"], "main");
    assert_eq!(json["size_bytes"], 100);
    assert_eq!(json["cyclomatic_complexity"], 3);
    assert_eq!(json["has_stack_frame"], true);
}

#[test]
fn get_function_stats_returns_empty_query_for_blank_address() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_function_stats_ctx(&tmp, mgr);
        let err = get_function_stats(&ctx, "ls", "   ").await.unwrap_err();
        assert!(matches!(err, FunctionStatsError::EmptyQuery), "{err:?}");
    });
}
