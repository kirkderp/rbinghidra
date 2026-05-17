use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::project::VARIABLES_SCRIPT;
use rbm_ghidra::variables::{
    FunctionParam, FunctionVariable, VARIABLES_SCHEMA, VariablesContext, VariablesError,
    VariablesResult, get_variables,
};

mod common;
use common::{make_manager, make_runtime};

fn make_variables_ctx(
    tmp: &tempfile::TempDir,
    manager: Arc<rbm_ghidra::ProjectManager>,
) -> VariablesContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(VARIABLES_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    VariablesContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn variables_schema_constant_has_expected_value() {
    assert_eq!(VARIABLES_SCHEMA, "rbm.ghidra.variables.v0");
}

#[test]
fn variables_result_deserializes_from_mock_envelope() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.variables.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "query": "main",
        "function_name": "main",
        "address": "0x100003a40",
        "source": "decompiler",
        "parameter_count": 0,
        "parameters": [],
        "local_var_count": 0,
        "local_vars": [],
        "decompiler_error": "",
        "resolution_error": ""
    });
    let result: VariablesResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.variables.v0");
    assert_eq!(result.query, "main");
    assert_eq!(result.function_name, "main");
    assert_eq!(result.address, "0x100003a40");
    assert_eq!(result.source, "decompiler");
    assert_eq!(result.parameter_count, 0);
    assert!(result.parameters.is_empty());
    assert_eq!(result.local_var_count, 0);
    assert!(result.local_vars.is_empty());
    assert_eq!(result.decompiler_error, "");
    assert_eq!(result.resolution_error, "");
}

#[test]
fn variables_result_backfills_new_metadata_fields_when_absent() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.variables.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "query": "main",
        "function_name": "main",
        "address": "0x100003a40",
        "parameter_count": 1,
        "parameters": [{
            "name": "argc",
            "ordinal": 0,
            "data_type": "int",
            "size": 4,
            "storage": "EDI"
        }],
        "local_var_count": 1,
        "local_vars": [{
            "name": "local_8",
            "data_type": "undefined8",
            "size": 8,
            "storage": "Stack[-0x8]",
            "first_use_offset": 0
        }],
        "resolution_error": ""
    });
    let result: VariablesResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.source, "");
    assert_eq!(result.decompiler_error, "");
    assert_eq!(result.parameters[0].storage_kind, "");
    assert_eq!(result.parameters[0].pc_address, "");
    assert!(!result.parameters[0].is_name_locked);
    assert_eq!(result.local_vars[0].storage_kind, "");
    assert_eq!(result.local_vars[0].pc_address, "");
    assert!(!result.local_vars[0].is_type_locked);
}

#[test]
fn variables_result_serializes_to_stable_shape() {
    let result = VariablesResult {
        schema: "rbm.ghidra.variables.v0".to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: "main".to_string(),
        function_name: "main".to_string(),
        address: "0x100003a40".to_string(),
        source: "decompiler".to_string(),
        parameter_count: 1,
        parameters: vec![FunctionParam {
            name: "argc".to_string(),
            ordinal: 0,
            data_type: "int".to_string(),
            size: 4,
            storage: "EDI".to_string(),
            storage_kind: "register".to_string(),
            pc_address: String::new(),
            is_name_locked: true,
            is_type_locked: true,
            is_this_pointer: false,
            is_hidden_return: false,
        }],
        local_var_count: 1,
        local_vars: vec![FunctionVariable {
            name: "local_8".to_string(),
            data_type: "undefined8".to_string(),
            size: 8,
            storage: "Stack[-0x8]".to_string(),
            first_use_offset: 0,
            storage_kind: "stack".to_string(),
            pc_address: "0x100003a40".to_string(),
            is_name_locked: true,
            is_type_locked: false,
        }],
        decompiler_error: String::new(),
        resolution_error: String::new(),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], "rbm.ghidra.variables.v0");
    assert_eq!(json["source"], "decompiler");
    assert_eq!(json["parameter_count"], 1);
    assert_eq!(json["parameters"][0]["name"], "argc");
    assert_eq!(json["parameters"][0]["ordinal"], 0);
    assert_eq!(json["parameters"][0]["storage_kind"], "register");
    assert_eq!(json["parameters"][0]["is_name_locked"], true);
    assert_eq!(json["local_var_count"], 1);
    assert_eq!(json["local_vars"][0]["name"], "local_8");
    assert_eq!(json["local_vars"][0]["storage_kind"], "stack");
    assert_eq!(json["local_vars"][0]["pc_address"], "0x100003a40");
    assert_eq!(json["decompiler_error"], "");
    assert_eq!(json["resolution_error"], "");
}

#[test]
fn get_variables_returns_empty_query_for_blank_address() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_variables_ctx(&tmp, mgr);
        let err = get_variables(&ctx, "ls", "   ").await.unwrap_err();
        assert!(matches!(err, VariablesError::EmptyQuery), "{err:?}");
    });
}
