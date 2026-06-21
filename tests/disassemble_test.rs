#[path = "support/tempfile.rs"]
mod tempfile;

use std::sync::Arc;
use std::time::Duration;

use rbinghidra::disassemble::{
    DEFAULT_MAX_INSTRUCTIONS, DISASSEMBLE_SCHEMA, DisassembleContext, DisassembleError,
    DisassembleResult, HARD_MAX_INSTRUCTIONS, Instruction, StackRef, disassemble_function,
};
use rbinghidra::project::DISASSEMBLE_SCRIPT;

mod common;
use common::{make_manager, make_runtime};

fn make_disassemble_ctx(
    tmp: &tempfile::TempDir,
    manager: Arc<rbinghidra::ProjectManager>,
) -> DisassembleContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(DISASSEMBLE_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    DisassembleContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn disassemble_schema_constant_has_expected_value() {
    assert_eq!(DISASSEMBLE_SCHEMA, "rbm.ghidra.disassemble.v0");
}

#[test]
fn disassemble_instruction_caps_are_pinned() {
    assert_eq!(DEFAULT_MAX_INSTRUCTIONS, 32);
    assert_eq!(HARD_MAX_INSTRUCTIONS, 512);
}

#[test]
fn disassemble_result_deserializes_from_mock_envelope() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.disassemble.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "query": "main",
        "function_name": "main",
        "address": "0x100003a40",
        "instruction_count": 0,
        "instructions_returned": 0,
        "truncated": false,
        "instructions": [],
        "resolution_error": ""
    });
    let result: DisassembleResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.disassemble.v0");
    assert_eq!(result.query, "main");
    assert_eq!(result.function_name, "main");
    assert_eq!(result.address, "0x100003a40");
    assert_eq!(result.instruction_count, 0);
    assert_eq!(result.instructions_returned, 0);
    assert!(!result.truncated);
    assert!(result.instructions.is_empty());
    assert_eq!(result.resolution_error, "");
}

#[test]
fn disassemble_result_defaults_new_cap_metadata_for_old_envelopes() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.disassemble.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "query": "main",
        "function_name": "main",
        "address": "0x100003a40",
        "instruction_count": 0,
        "instructions": [],
        "resolution_error": ""
    });
    let result: DisassembleResult = serde_json::from_value(json).unwrap();

    assert_eq!(result.instructions_returned, 0);
    assert!(!result.truncated);
}

#[test]
fn disassemble_result_serializes_to_stable_shape() {
    let result = DisassembleResult {
        schema: "rbm.ghidra.disassemble.v0".to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: "main".to_string(),
        function_name: "main".to_string(),
        address: "0x100003a40".to_string(),
        instruction_count: 1,
        instructions_returned: 1,
        truncated: false,
        instructions: vec![Instruction {
            address: "100003a40".to_string(),
            bytes: "55".to_string(),
            mnemonic: "PUSH".to_string(),
            operands: vec!["RBP".to_string()],
            disassembly: "PUSH RBP".to_string(),
            esp_delta_before: Some(0),
            esp_delta_after: Some(-8),
            esp_delta_known: true,
            stack_refs: vec![],
            flow_type: "FALL_THROUGH".to_string(),
            fall_through: "100003a41".to_string(),
            flows: vec![],
            default_flows: vec![],
            has_fallthrough: true,
            is_call: false,
            is_jump: false,
            is_terminal: false,
        }],
        resolution_error: String::new(),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], "rbm.ghidra.disassemble.v0");
    assert_eq!(json["instruction_count"], 1);
    assert_eq!(json["instructions_returned"], 1);
    assert_eq!(json["truncated"], false);
    assert_eq!(json["instructions"][0]["mnemonic"], "PUSH");
    assert_eq!(json["instructions"][0]["bytes"], "55");
    assert_eq!(json["instructions"][0]["disassembly"], "PUSH RBP");
    assert_eq!(json["instructions"][0]["esp_delta_before"], 0);
    assert_eq!(json["instructions"][0]["esp_delta_after"], -8);
    assert_eq!(json["instructions"][0]["esp_delta_known"], true);
    assert!(json["instructions"][0].get("stack_refs").is_none());
    assert_eq!(json["instructions"][0]["flow_type"], "FALL_THROUGH");
    assert_eq!(json["instructions"][0]["fall_through"], "100003a41");
    assert_eq!(json["instructions"][0]["has_fallthrough"], true);
    assert_eq!(json["resolution_error"], "");
}

#[test]
fn disassemble_instruction_supports_stack_ref_annotations() {
    let json = serde_json::json!({
        "address": "00417fa5",
        "bytes": "8b4c2464",
        "mnemonic": "MOV",
        "operands": ["ECX", "dword ptr [ESP + 0x64]"],
        "disassembly": "MOV ECX,dword ptr [ESP + 0x64]",
        "esp_delta_before": -8,
        "esp_delta_after": -8,
        "esp_delta_known": true,
        "stack_refs": [{
            "operand_index": 1,
            "operand": "dword ptr [ESP + 0x64]",
            "base_register": "ESP",
            "displacement": 100,
            "displacement_hex": "0x64",
            "canonical_stack_offset": 92,
            "canonical_stack_offset_hex": "0x5c",
            "access": "read"
        }],
        "flow_type": "FALL_THROUGH",
        "fall_through": "00417fa9",
        "flows": [],
        "default_flows": [],
        "has_fallthrough": true,
        "is_call": false,
        "is_jump": false,
        "is_terminal": false
    });
    let instr: Instruction = serde_json::from_value(json).unwrap();
    assert_eq!(instr.esp_delta_before, Some(-8));
    assert_eq!(instr.esp_delta_after, Some(-8));
    assert!(instr.esp_delta_known);
    assert_eq!(instr.stack_refs.len(), 1);
    let stack_ref: &StackRef = &instr.stack_refs[0];
    assert_eq!(stack_ref.canonical_stack_offset, Some(92));
    assert_eq!(stack_ref.canonical_stack_offset_hex, "0x5c");
}

#[test]
fn disassemble_function_returns_empty_query_for_blank_address() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_disassemble_ctx(&tmp, mgr);
        let err = disassemble_function(&ctx, "ls", "   ", 0, false)
            .await
            .unwrap_err();
        assert!(matches!(err, DisassembleError::EmptyQuery), "{err:?}");
    });
}
