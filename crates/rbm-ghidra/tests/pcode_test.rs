use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::pcode::{
    PCODE_SCHEMA, PcodeContext, PcodeError, PcodeOp, PcodeResult, PcodeVarnode, get_pcode,
};
use rbm_ghidra::project::PCODE_SCRIPT;

mod common;
use common::{make_manager, make_runtime};

fn make_pcode_ctx(
    tmp: &tempfile::TempDir,
    manager: Arc<rbm_ghidra::ProjectManager>,
) -> PcodeContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(PCODE_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    PcodeContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn pcode_schema_constant_has_expected_value() {
    assert_eq!(PCODE_SCHEMA, "rbm.ghidra.pcode.v0");
}

#[test]
fn pcode_result_deserializes_from_mock_envelope() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.pcode.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "query": "main",
        "simplification_style": "register",
        "function_name": "main",
        "address": "0x100003a40",
        "op_count": 0,
        "ops": [],
        "basic_block_count": 2,
        "decompile_completed": true,
        "decompile_valid": true,
        "is_timed_out": false,
        "is_cancelled": false,
        "failed_to_start": false,
        "decompile_error": "",
        "resolution_error": ""
    });
    let result: PcodeResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.pcode.v0");
    assert_eq!(result.query, "main");
    assert_eq!(result.simplification_style, "register");
    assert_eq!(result.function_name, "main");
    assert_eq!(result.address, "0x100003a40");
    assert_eq!(result.op_count, 0);
    assert!(result.ops.is_empty());
    assert_eq!(result.basic_block_count, 2);
    assert!(result.decompile_completed);
    assert!(result.decompile_valid);
    assert!(!result.is_timed_out);
    assert!(!result.is_cancelled);
    assert!(!result.failed_to_start);
    assert_eq!(result.decompile_error, "");
    assert_eq!(result.resolution_error, "");
}

#[test]
fn pcode_result_serializes_to_stable_shape() {
    let result = PcodeResult {
        schema: "rbm.ghidra.pcode.v0".to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: "main".to_string(),
        simplification_style: "normalize".to_string(),
        function_name: "main".to_string(),
        address: "0x100003a40".to_string(),
        op_count: 1,
        ops: vec![PcodeOp {
            seq_num: "0x100003a40@0".to_string(),
            mnemonic: "COPY".to_string(),
            output: Some(PcodeVarnode {
                space: "register".to_string(),
                offset: "0x0".to_string(),
                size: 8,
                is_register: true,
                name: "RAX".to_string(),
            }),
            inputs: vec![],
        }],
        basic_block_count: 3,
        decompile_completed: true,
        decompile_valid: true,
        is_timed_out: false,
        is_cancelled: false,
        failed_to_start: false,
        decompile_error: String::new(),
        resolution_error: String::new(),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], "rbm.ghidra.pcode.v0");
    assert_eq!(json["simplification_style"], "normalize");
    assert_eq!(json["op_count"], 1);
    assert_eq!(json["ops"][0]["mnemonic"], "COPY");
    assert_eq!(json["ops"][0]["output"]["name"], "RAX");
    assert_eq!(json["basic_block_count"], 3);
    assert_eq!(json["decompile_completed"], true);
    assert_eq!(json["decompile_error"], "");
    assert_eq!(json["resolution_error"], "");
}

#[test]
fn get_pcode_returns_empty_query_for_blank_address() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_pcode_ctx(&tmp, mgr);
        let err = get_pcode(&ctx, "ls", "   ", None).await.unwrap_err();
        assert!(matches!(err, PcodeError::EmptyQuery), "{err:?}");
    });
}

#[test]
fn get_pcode_rejects_invalid_simplification_style() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_pcode_ctx(&tmp, mgr);
        let err = get_pcode(&ctx, "ls", "main", Some("bogus"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, PcodeError::InvalidSimplificationStyle { .. }),
            "{err:?}"
        );
    });
}
