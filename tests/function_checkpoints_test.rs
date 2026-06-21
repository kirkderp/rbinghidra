#[path = "support/tempfile.rs"]
mod tempfile;

use std::sync::Arc;
use std::time::Duration;

use rbinghidra::function_checkpoints::{
    FUNCTION_CHECKPOINTS_SCHEMA, FunctionCheckpointsContext, FunctionCheckpointsError,
    FunctionCheckpointsResult, get_function_checkpoints,
};
use rbinghidra::project::FUNCTION_CHECKPOINTS_SCRIPT;

mod common;
use common::{make_manager, make_runtime};

fn make_ctx(
    tmp: &tempfile::TempDir,
    manager: Arc<rbinghidra::ProjectManager>,
) -> FunctionCheckpointsContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(FUNCTION_CHECKPOINTS_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    FunctionCheckpointsContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn function_checkpoints_schema_constant_has_expected_value() {
    assert_eq!(
        FUNCTION_CHECKPOINTS_SCHEMA,
        "rbm.ghidra.function_checkpoints.v0"
    );
}

#[test]
fn function_checkpoints_result_deserializes_from_mock_envelope() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.function_checkpoints.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "sample.exe",
        "query": "0x401000",
        "simplification_style": "decompile",
        "function_name": "FUN_00401000",
        "address": "00401000",
        "ranges_query": "setup:0x401000-0x401020",
        "range_count": 1,
        "ranges": [{
            "name": "setup",
            "start": "00401000",
            "end": "00401020",
            "instruction_count": 2,
            "first_instruction": "PUSH EBP",
            "last_instruction": "RET",
            "byte_sha256": "abc",
            "mnemonic_counts": [["PUSH", 1], ["RET", 1]],
            "call_count": 0,
            "jump_count": 0,
            "terminal_count": 1,
            "memory_write_count": 1,
            "stack_ref_count": 1,
            "stack_write_count": 1,
            "stack_refs_preview": [{
                "address": "00401001",
                "disassembly": "MOV dword ptr [ESP + 0x4],EAX",
                "operand_index": 0,
                "operand": "dword ptr [ESP + 0x4]",
                "base_register": "ESP",
                "displacement": 4,
                "displacement_hex": "0x4",
                "canonical_stack_offset": -84,
                "canonical_stack_offset_hex": "-0x54",
                "access": "write"
            }],
            "stack_refs_truncated": false,
            "instruction_preview": [{"address":"00401000","disassembly":"PUSH EBP"}],
            "instruction_preview_truncated": false,
            "pcode_op_count": 1,
            "pcode_mnemonic_counts": [["COPY", 1]],
            "pcode_seq_preview": ["00401000@0:COPY"],
            "pcode_preview_truncated": false
        }],
        "decompile_completed": true,
        "decompile_valid": true,
        "is_timed_out": false,
        "is_cancelled": false,
        "failed_to_start": false,
        "decompile_error": "",
        "resolution_error": ""
    });
    let result: FunctionCheckpointsResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, FUNCTION_CHECKPOINTS_SCHEMA);
    assert_eq!(result.ranges.len(), 1);
    assert_eq!(result.ranges[0].name, "setup");
    assert_eq!(result.ranges[0].mnemonic_counts[0], ("PUSH".to_string(), 1));
    assert_eq!(
        result.ranges[0].stack_refs_preview[0].canonical_stack_offset_hex,
        "-0x54"
    );
    assert_eq!(
        result.ranges[0].pcode_mnemonic_counts[0],
        ("COPY".to_string(), 1)
    );
}

#[test]
fn get_function_checkpoints_returns_empty_query_for_blank_address() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_ctx(&tmp, mgr);
        let err = get_function_checkpoints(&ctx, "ls", "   ", None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, FunctionCheckpointsError::EmptyQuery),
            "{err:?}"
        );
    });
}

#[test]
fn get_function_checkpoints_rejects_invalid_simplification_style() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_ctx(&tmp, mgr);
        let err = get_function_checkpoints(&ctx, "ls", "main", None, Some("bogus"))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                FunctionCheckpointsError::InvalidSimplificationStyle { .. }
            ),
            "{err:?}"
        );
    });
}
