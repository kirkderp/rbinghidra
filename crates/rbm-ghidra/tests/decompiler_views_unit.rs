use rbm_ghidra::decompiler_block_behavior::{
    DECOMPILER_BLOCK_BEHAVIOR_SCHEMA, DecompilerBlockBehaviorFilter,
    project_decompiler_block_behavior, project_decompiler_block_behavior_filtered,
};
use rbm_ghidra::decompiler_calls::{
    DECOMPILER_CALLS_SCHEMA, DecompilerCallsFilter, project_decompiler_calls,
    project_decompiler_calls_filtered,
};
use rbm_ghidra::decompiler_cfg::DECOMPILER_CFG_SCHEMA;
use rbm_ghidra::decompiler_memory::{
    DECOMPILER_MEMORY_SCHEMA, DecompilerMemoryFilter, project_decompiler_memory,
    project_decompiler_memory_filtered,
};

mod common;
use common::sample_decompiler_cfg_result;

#[test]
fn decompiler_calls_projection_filters_and_summarizes_calls() {
    let result = project_decompiler_calls(sample_decompiler_cfg_result());
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], DECOMPILER_CALLS_SCHEMA);
    assert_eq!(json["source_schema"], DECOMPILER_CFG_SCHEMA);
    assert_eq!(json["source_block_count"], 2);
    assert_eq!(json["matched_block_count"], 1);
    assert_eq!(json["total_call_count"], 1);
    assert_eq!(json["total_external_callsite_count"], 1);
    assert_eq!(
        json["blocks"][0]["external_call_targets"][0],
        "kernel32.dll::CreateFileW"
    );
    assert_eq!(
        json["blocks"][0]["callsites_preview"][0]["call_context_preview"][0],
        "100003a40 PUSH 0x1"
    );
}

#[test]
fn decompiler_memory_projection_filters_and_summarizes_memory() {
    let result = project_decompiler_memory(sample_decompiler_cfg_result());
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], DECOMPILER_MEMORY_SCHEMA);
    assert_eq!(json["matched_block_count"], 1);
    assert_eq!(json["total_memory_access_count"], 2);
    assert_eq!(json["total_memory_read_count"], 1);
    assert_eq!(json["total_memory_write_count"], 1);
    assert_eq!(
        json["blocks"][0]["memory_accesses_preview"][0]["space_kind"],
        "stack"
    );
}

#[test]
fn decompiler_block_behavior_projection_keeps_all_blocks_and_edge_summaries() {
    let result = project_decompiler_block_behavior(sample_decompiler_cfg_result());
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], DECOMPILER_BLOCK_BEHAVIOR_SCHEMA);
    assert_eq!(json["block_count"], 2);
    assert_eq!(json["total_conditional_edge_count"], 1);
    assert_eq!(json["total_back_edge_count"], 0);
    assert_eq!(json["blocks"][0]["api_families"][0], "process");
    assert_eq!(json["blocks"][0]["conditional_edge_count"], 1);
    assert_eq!(
        json["blocks"][0]["constants_preview"][0]["value_hex"],
        "0x1"
    );
}

#[test]
fn decompiler_calls_projection_applies_filters_and_sorts_targets() {
    let mut cfg = sample_decompiler_cfg_result();
    cfg.blocks[0].call_targets = vec!["zeta".to_string(), "alpha".to_string(), "alpha".to_string()];
    cfg.blocks[0].external_call_targets =
        vec!["zeta".to_string(), "alpha".to_string(), "alpha".to_string()];
    let result = project_decompiler_calls_filtered(
        cfg,
        &DecompilerCallsFilter {
            only_external: true,
            only_indirect: false,
            only_api_tag: Some("file".to_string()),
        },
    );
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["matched_block_count"], 1);
    assert_eq!(json["blocks"][0]["call_targets"][0], "alpha");
    assert_eq!(json["blocks"][0]["call_targets"][1], "zeta");
}

#[test]
fn decompiler_memory_projection_only_writes_filter_keeps_write_blocks() {
    let result = project_decompiler_memory_filtered(
        sample_decompiler_cfg_result(),
        &DecompilerMemoryFilter { only_writes: true },
    );
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["matched_block_count"], 1);
    assert_eq!(json["total_memory_write_count"], 1);
}

#[test]
fn decompiler_block_behavior_projection_filters_and_sorts_summaries() {
    let mut cfg = sample_decompiler_cfg_result();
    cfg.blocks[0].modules = vec![
        "user32.dll".to_string(),
        "kernel32.dll".to_string(),
        "kernel32.dll".to_string(),
    ];
    cfg.blocks[0].api_tags = vec!["timing".to_string(), "file".to_string(), "file".to_string()];
    cfg.blocks[0].external_symbols =
        vec!["Zeta".to_string(), "Alpha".to_string(), "Alpha".to_string()];
    let result = project_decompiler_block_behavior_filtered(
        cfg,
        &DecompilerBlockBehaviorFilter {
            only_strings: true,
            only_api_tag: Some("file".to_string()),
            only_external: true,
        },
    );
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["block_count"], 1);
    assert_eq!(json["blocks"][0]["modules"][0], "kernel32.dll");
    assert_eq!(json["blocks"][0]["modules"][1], "user32.dll");
    assert_eq!(json["blocks"][0]["api_tags"][0], "file");
    assert_eq!(json["blocks"][0]["api_tags"][1], "timing");
    assert_eq!(json["blocks"][0]["external_symbols"][0], "Alpha");
    assert_eq!(json["blocks"][0]["external_symbols"][1], "Zeta");
}
