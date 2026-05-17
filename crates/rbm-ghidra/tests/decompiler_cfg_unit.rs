use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::decompiler_cfg::{
    DECOMPILER_CFG_SCHEMA, DecompilerCfgContext, DecompilerCfgError, gen_decompiler_cfg,
};
use rbm_ghidra::inspect::InspectError;
use rbm_ghidra::project::{DECOMPILER_CFG_SCRIPT, PathValidationError, ProjectManager};
use rbm_ghidra::warm_path::WarmPathError;
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime, sample_decompiler_cfg_result, write_envelope};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn make_cfg_ctx(tmp: &TempDir, manager: Arc<ProjectManager>) -> DecompilerCfgContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(DECOMPILER_CFG_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    DecompilerCfgContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn decompiler_cfg_script_constant_is_java() {
    assert_eq!(DECOMPILER_CFG_SCRIPT, "decompiler_cfg.java");
}

#[test]
fn decompiler_cfg_schema_constant_pinned() {
    assert_eq!(DECOMPILER_CFG_SCHEMA, "rbm.ghidra.decompiler_cfg.v0");
}

#[test]
fn gen_decompiler_cfg_rejects_empty_query() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_cfg_ctx(&tmp, mgr.clone());
        let err = gen_decompiler_cfg(&ctx, "ls", "", None, false)
            .await
            .unwrap_err();
        assert!(matches!(err, DecompilerCfgError::EmptyQuery), "{err:?}");
    });
}

#[test]
fn gen_decompiler_cfg_rejects_invalid_simplification_style() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_cfg_ctx(&tmp, mgr.clone());
        let err = gen_decompiler_cfg(&ctx, "ls", "main", Some("bogus"), false)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DecompilerCfgError::InvalidSimplificationStyle { .. }),
            "{err:?}"
        );
    });
}

#[test]
fn warm_path_error_flattens_into_decompiler_cfg_error() {
    let e: DecompilerCfgError = WarmPathError::LockHeld {
        sha256: "abc".to_string(),
    }
    .into();
    match e {
        DecompilerCfgError::LockHeld { sha256 } => assert_eq!(sha256, "abc"),
        other => panic!("expected LockHeld, got {other:?}"),
    }
}

#[test]
fn decompiler_cfg_result_serializes_to_stable_shape() {
    let result = sample_decompiler_cfg_result();
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], DECOMPILER_CFG_SCHEMA);
    assert_eq!(json["simplification_style"], "normalize");
    assert_eq!(json["include_ops"], true);
    assert_eq!(json["block_count"], 2);
    assert_eq!(json["edge_count"], 1);
    assert_eq!(json["resolved_function_name"], "Global::main");
    assert_eq!(json["decompile_completed"], true);
}

#[test]
fn decompiler_cfg_serializes_edge_metadata() {
    let result = sample_decompiler_cfg_result();
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["edges"][0]["label"], "false");
    assert_eq!(json["edges"][0]["branch_kind"], "conditional_false");
    assert_eq!(json["edges"][0]["source_op_mnemonic"], "CBRANCH");
    assert_eq!(json["edges"][0]["source_op_address"], "100003a40");
    assert_eq!(
        json["edges"][0]["branch_target_preview"],
        "const<const:0x1:1>"
    );
    assert_eq!(
        json["edges"][0]["condition_preview"],
        "local_20<unique:0x20:4>"
    );
    assert_eq!(json["edges"][0]["predicate_mnemonic"], "INT_EQUAL");
    assert_eq!(
        json["edges"][0]["predicate_inputs_preview"][0],
        "RAX<register:0x0:8>"
    );
}

#[test]
fn decompiler_cfg_serializes_block_shape_and_ops() {
    let result = sample_decompiler_cfg_result();
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["blocks"][0]["block_kind"], "entry");
    assert_eq!(json["blocks"][0]["structural_tags"][0], "entry");
    assert_eq!(json["blocks"][0]["structural_tags"][1], "conditional");
    assert_eq!(json["blocks"][1]["block_kind"], "exit");
    assert_eq!(json["blocks"][0]["pcode_op_count"], 5);
    assert_eq!(json["blocks"][0]["first_op_mnemonic"], "COPY");
    assert_eq!(json["blocks"][0]["last_op_mnemonic"], "CBRANCH");
    assert_eq!(json["blocks"][0]["pcode_mnemonics_preview"][1], "INT_EQUAL");
    assert_eq!(json["blocks"][0]["pcode_preview_truncated"], false);
    assert_eq!(
        json["blocks"][0]["defs_preview"][0],
        "local_20<unique:0x20:4>"
    );
    assert_eq!(json["blocks"][0]["uses_preview"][0], "RAX<register:0x0:8>");
    assert_eq!(json["blocks"][0]["uses_preview_truncated"], false);
    assert_eq!(
        json["blocks"][0]["instruction_addresses_preview"][0],
        "100003a40"
    );
    assert_eq!(json["blocks"][0]["instruction_addresses_truncated"], false);
    assert_eq!(json["blocks"][0]["successor_indices"][0], 1);
    assert_eq!(json["blocks"][1]["predecessor_indices"][0], 0);
    assert_eq!(json["blocks"][0]["ops"][0]["mnemonic"], "COPY");
}

#[test]
fn decompiler_cfg_serializes_call_metadata() {
    let result = sample_decompiler_cfg_result();
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["blocks"][0]["call_count"], 1);
    assert_eq!(
        json["blocks"][0]["callsites_preview"][0]["target_name"],
        "kernel32.dll::CreateFileW"
    );
    assert_eq!(json["blocks"][0]["call_target_count"], 1);
    assert_eq!(
        json["blocks"][0]["call_targets"][0],
        "kernel32.dll::CreateFileW"
    );
    assert_eq!(json["blocks"][0]["internal_call_target_count"], 0);
    assert_eq!(json["blocks"][0]["external_call_target_count"], 1);
    assert_eq!(
        json["blocks"][0]["external_call_targets"][0],
        "kernel32.dll::CreateFileW"
    );
    assert_eq!(json["blocks"][0]["internal_call_count"], 0);
    assert_eq!(json["blocks"][0]["external_callsite_count"], 1);
    assert_eq!(json["blocks"][0]["indirect_call_count"], 0);
    assert_eq!(json["blocks"][0]["thunk_call_count"], 0);
    assert_eq!(
        json["blocks"][0]["callsites_preview"][0]["module_name"],
        "kernel32.dll"
    );
    assert_eq!(
        json["blocks"][0]["callsites_preview"][0]["api_family"],
        "process"
    );
    assert_eq!(json["blocks"][0]["callsites_preview"][0]["api_tag"], "file");
    assert_eq!(
        json["blocks"][0]["callsites_preview"][0]["is_external"],
        true
    );
}

#[test]
fn decompiler_cfg_serializes_memory_and_constant_metadata() {
    let result = sample_decompiler_cfg_result();
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["blocks"][0]["memory_access_count"], 2);
    assert_eq!(json["blocks"][0]["memory_read_count"], 1);
    assert_eq!(json["blocks"][0]["memory_write_count"], 1);
    assert_eq!(
        json["blocks"][0]["memory_accesses_preview"][0]["space_kind"],
        "stack"
    );
    assert_eq!(
        json["blocks"][0]["memory_accesses_preview"][1]["space_kind"],
        "global"
    );
    assert_eq!(json["blocks"][0]["constant_count"], 2);
    assert_eq!(
        json["blocks"][0]["constants_preview"][0]["value_hex"],
        "0x1"
    );
    assert_eq!(
        json["blocks"][0]["constants_preview"][1]["source_op_mnemonic"],
        "LOAD"
    );
    assert_eq!(json["blocks"][0]["string_ref_count"], 1);
    assert_eq!(
        json["blocks"][0]["string_refs_preview"][0]["value"],
        "CreateFileW failed"
    );
}

#[test]
fn decompiler_cfg_serializes_external_reference_metadata() {
    let result = sample_decompiler_cfg_result();
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["blocks"][0]["external_ref_count"], 2);
    assert_eq!(
        json["blocks"][0]["external_refs_preview"][0]["name"],
        "kernel32.dll::CreateFileW"
    );
    assert_eq!(
        json["blocks"][0]["external_refs_preview"][0]["module_name"],
        "kernel32.dll"
    );
    assert_eq!(
        json["blocks"][0]["external_refs_preview"][0]["api_family"],
        "process"
    );
    assert_eq!(
        json["blocks"][0]["external_refs_preview"][0]["api_tag"],
        "file"
    );
    assert_eq!(
        json["blocks"][0]["external_refs_preview"][0]["source_op_address"],
        "100003a44"
    );
    assert_eq!(
        json["blocks"][0]["external_refs_preview"][0]["source_value_preview"],
        "ram:180012340"
    );
    assert_eq!(
        json["blocks"][0]["external_refs_preview"][1]["ref_kind"],
        "address_ref"
    );
    assert_eq!(
        json["blocks"][0]["external_refs_preview"][1]["api_family"],
        "process"
    );
    assert_eq!(
        json["blocks"][0]["external_refs_preview"][1]["source_op_address"],
        "100003a43"
    );
    assert_eq!(
        json["blocks"][0]["external_refs_preview"][1]["source_value_preview"],
        "ram:180020000"
    );
}

#[test]
fn decompiler_cfg_serializes_external_summary_metadata() {
    let result = sample_decompiler_cfg_result();
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["blocks"][0]["external_call_count"], 1);
    assert_eq!(json["blocks"][0]["external_address_ref_count"], 1);
    assert_eq!(json["blocks"][0]["external_symbol_count"], 2);
    assert_eq!(
        json["blocks"][0]["external_symbols"][0],
        "kernel32.dll::CreateFileW"
    );
    assert_eq!(json["blocks"][0]["external_symbols"][1], "KERNEL32.DLL");
    assert_eq!(json["blocks"][0]["module_count"], 1);
    assert_eq!(json["blocks"][0]["modules"][0], "kernel32.dll");
    assert_eq!(json["blocks"][0]["api_family_count"], 1);
    assert_eq!(json["blocks"][0]["api_families"][0], "process");
    assert_eq!(json["blocks"][0]["api_tag_count"], 1);
    assert_eq!(json["blocks"][0]["api_tags"][0], "file");
}

#[test]
fn gen_decompiler_cfg_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_cfg_ctx(&tmp, mgr.clone());
        ctx.scripts_dir = tmp.path().join("does-not-exist");
        let err = gen_decompiler_cfg(&ctx, "ls", "main", None, false)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                DecompilerCfgError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn gen_decompiler_cfg_rejects_missing_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_cfg_ctx(&tmp, mgr.clone());
        let scripts = tmp.path().join("scripts-empty");
        std::fs::create_dir_all(&scripts).unwrap();
        ctx.scripts_dir = scripts;
        let err = gen_decompiler_cfg(&ctx, "ls", "main", None, false)
            .await
            .unwrap_err();
        match err {
            DecompilerCfgError::PathValidation(PathValidationError::ScriptMissing {
                script,
                ..
            }) => assert_eq!(script, DECOMPILER_CFG_SCRIPT),
            other => panic!("expected missing script, got {other:?}"),
        }
    });
}

#[test]
fn gen_decompiler_cfg_returns_inspect_not_found_for_unknown_binary() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_cfg_ctx(&tmp, mgr.clone());
        let err = gen_decompiler_cfg(&ctx, "missing", "main", None, false)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DecompilerCfgError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn gen_decompiler_cfg_propagates_ambiguous_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_cfg_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "ls", 1);
        let err = gen_decompiler_cfg(&ctx, "ls", "main", None, false)
            .await
            .unwrap_err();
        match err {
            DecompilerCfgError::Inspect(InspectError::Ambiguous { matches, .. }) => {
                assert_eq!(matches, 2);
            }
            other => panic!("expected Inspect(Ambiguous), got {other:?}"),
        }
    });
}
