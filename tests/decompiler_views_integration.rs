#![cfg(feature = "integration-ghidra")]

#[path = "support/tempfile.rs"]
mod tempfile;

use std::path::PathBuf;
use std::time::Duration;

use rbinghidra::decompiler_block_behavior::{
    DECOMPILER_BLOCK_BEHAVIOR_SCHEMA, DecompilerBlockBehaviorContext,
    DecompilerBlockBehaviorFilter, get_decompiler_block_behavior,
};
use rbinghidra::decompiler_calls::{
    DECOMPILER_CALLS_SCHEMA, DecompilerCallsContext, DecompilerCallsFilter, get_decompiler_calls,
};
use rbinghidra::decompiler_memory::{
    DECOMPILER_MEMORY_SCHEMA, DecompilerMemoryContext, DecompilerMemoryFilter,
    get_decompiler_memory,
};

mod common;
use common::{first_real_function_name, import_real_binary};

fn sorted_u32(values: &[u32]) -> bool {
    values.windows(2).all(|pair| pair[0] <= pair[1])
}

#[test]
#[ignore = "requires real Ghidra/analyzeHeadless; run explicitly with --ignored"]
fn decompiler_split_views_run_against_real_binary() {
    common::make_runtime().block_on(decompiler_split_views_run_against_real_binary_impl());
}

async fn decompiler_split_views_run_against_real_binary_impl() {
    let fixture = import_real_binary(PathBuf::from("/bin/ls").as_path()).await;
    let target_name = first_real_function_name(&fixture.functions);

    let calls_ctx = DecompilerCallsContext {
        manager: fixture.manager.clone(),
        analyze_headless: fixture.analyze_headless.clone(),
        scripts_dir: fixture.scripts_dir.clone(),
        timeout: Duration::from_secs(240),
    };
    let calls = get_decompiler_calls(
        &calls_ctx,
        &fixture.program_name,
        &target_name,
        Some("decompile"),
        &DecompilerCallsFilter::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("ghidra_decompiler_calls({target_name}): {e:?}"));
    assert_eq!(calls.schema, DECOMPILER_CALLS_SCHEMA);
    assert_eq!(calls.cache_key, format!("sha256:{}", fixture.sha));
    assert!(!calls.resolved_address.is_empty());
    assert!(!calls.resolved_function_name.is_empty());
    assert!(calls.source_block_count >= calls.matched_block_count);
    assert!(calls.decompile_completed);
    assert!(calls.decompile_valid);
    let call_indices: Vec<u32> = calls.blocks.iter().map(|block| block.index).collect();
    assert!(sorted_u32(&call_indices));

    let behavior_ctx = DecompilerBlockBehaviorContext {
        manager: fixture.manager.clone(),
        analyze_headless: fixture.analyze_headless.clone(),
        scripts_dir: fixture.scripts_dir.clone(),
        timeout: Duration::from_secs(240),
    };
    let behavior = get_decompiler_block_behavior(
        &behavior_ctx,
        &fixture.program_name,
        &target_name,
        Some("decompile"),
        &DecompilerBlockBehaviorFilter::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("ghidra_decompiler_block_behavior({target_name}): {e:?}"));
    assert_eq!(behavior.schema, DECOMPILER_BLOCK_BEHAVIOR_SCHEMA);
    assert_eq!(behavior.cache_key, format!("sha256:{}", fixture.sha));
    assert!(!behavior.resolved_address.is_empty());
    assert!(!behavior.resolved_function_name.is_empty());
    assert!(behavior.decompile_completed);
    assert!(behavior.decompile_valid);
    let behavior_indices: Vec<u32> = behavior.blocks.iter().map(|block| block.index).collect();
    assert!(sorted_u32(&behavior_indices));

    let memory_ctx = DecompilerMemoryContext {
        manager: fixture.manager.clone(),
        analyze_headless: fixture.analyze_headless.clone(),
        scripts_dir: fixture.scripts_dir.clone(),
        timeout: Duration::from_secs(240),
    };
    let memory = get_decompiler_memory(
        &memory_ctx,
        &fixture.program_name,
        &target_name,
        Some("decompile"),
        &DecompilerMemoryFilter::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("ghidra_decompiler_memory({target_name}): {e:?}"));
    assert_eq!(memory.schema, DECOMPILER_MEMORY_SCHEMA);
    assert_eq!(memory.cache_key, format!("sha256:{}", fixture.sha));
    assert!(!memory.resolved_address.is_empty());
    assert!(!memory.resolved_function_name.is_empty());
    assert!(memory.source_block_count >= memory.matched_block_count);
    assert!(memory.decompile_completed);
    assert!(memory.decompile_valid);
    let memory_indices: Vec<u32> = memory.blocks.iter().map(|block| block.index).collect();
    assert!(sorted_u32(&memory_indices));
}

#[test]
#[ignore = "requires real Ghidra/analyzeHeadless; run explicitly with --ignored"]
fn decompiler_split_views_support_env_driven_regression_targets() {
    common::make_runtime()
        .block_on(decompiler_split_views_support_env_driven_regression_targets_impl());
}

async fn decompiler_split_views_support_env_driven_regression_targets_impl() {
    let large_binary = match std::env::var("RBM_GHIDRA_LARGE_BINARY") {
        Ok(value) if !value.is_empty() => value,
        _ => return,
    };
    let large_function = match std::env::var("RBM_GHIDRA_LARGE_FUNCTION") {
        Ok(value) if !value.is_empty() => value,
        _ => return,
    };

    let large_fixture = import_real_binary(PathBuf::from(&large_binary).as_path()).await;

    let calls_ctx = DecompilerCallsContext {
        manager: large_fixture.manager.clone(),
        analyze_headless: large_fixture.analyze_headless.clone(),
        scripts_dir: large_fixture.scripts_dir.clone(),
        timeout: Duration::from_secs(240),
    };
    let calls = get_decompiler_calls(
        &calls_ctx,
        &large_fixture.program_name,
        &large_function,
        Some("decompile"),
        &DecompilerCallsFilter {
            only_external: true,
            only_indirect: false,
            only_api_tag: None,
        },
    )
    .await
    .unwrap_or_else(|e| panic!("large ghidra_decompiler_calls({large_function}): {e:?}"));
    assert!(calls.decompile_completed);
    assert!(calls.decompile_valid);

    let behavior_ctx = DecompilerBlockBehaviorContext {
        manager: large_fixture.manager.clone(),
        analyze_headless: large_fixture.analyze_headless.clone(),
        scripts_dir: large_fixture.scripts_dir.clone(),
        timeout: Duration::from_secs(240),
    };
    let behavior = get_decompiler_block_behavior(
        &behavior_ctx,
        &large_fixture.program_name,
        &large_function,
        Some("decompile"),
        &DecompilerBlockBehaviorFilter {
            only_strings: false,
            only_api_tag: None,
            only_external: true,
        },
    )
    .await
    .unwrap_or_else(|e| panic!("large ghidra_decompiler_block_behavior({large_function}): {e:?}"));
    assert!(behavior.decompile_completed);
    assert!(behavior.decompile_valid);

    let memory_ctx = DecompilerMemoryContext {
        manager: large_fixture.manager.clone(),
        analyze_headless: large_fixture.analyze_headless.clone(),
        scripts_dir: large_fixture.scripts_dir.clone(),
        timeout: Duration::from_secs(240),
    };
    let memory = get_decompiler_memory(
        &memory_ctx,
        &large_fixture.program_name,
        &large_function,
        Some("decompile"),
        &DecompilerMemoryFilter { only_writes: true },
    )
    .await
    .unwrap_or_else(|e| panic!("large ghidra_decompiler_memory({large_function}): {e:?}"));
    assert!(memory.decompile_completed);
    assert!(memory.decompile_valid);

    let narrow_binary = match std::env::var("RBM_GHIDRA_NARROW_BINARY") {
        Ok(value) if !value.is_empty() => value,
        _ => return,
    };
    let narrow_function = match std::env::var("RBM_GHIDRA_NARROW_FUNCTION") {
        Ok(value) if !value.is_empty() => value,
        _ => return,
    };
    let narrow_fixture = import_real_binary(PathBuf::from(&narrow_binary).as_path()).await;

    let narrow_calls_ctx = DecompilerCallsContext {
        manager: narrow_fixture.manager.clone(),
        analyze_headless: narrow_fixture.analyze_headless.clone(),
        scripts_dir: narrow_fixture.scripts_dir.clone(),
        timeout: Duration::from_secs(240),
    };
    let narrow_calls = get_decompiler_calls(
        &narrow_calls_ctx,
        &narrow_fixture.program_name,
        &narrow_function,
        Some("decompile"),
        &DecompilerCallsFilter {
            only_external: true,
            only_indirect: false,
            only_api_tag: None,
        },
    )
    .await
    .unwrap_or_else(|e| panic!("narrow ghidra_decompiler_calls({narrow_function}): {e:?}"));
    assert!(narrow_calls.decompile_completed);
    assert!(narrow_calls.decompile_valid);

    let narrow_behavior_ctx = DecompilerBlockBehaviorContext {
        manager: narrow_fixture.manager.clone(),
        analyze_headless: narrow_fixture.analyze_headless.clone(),
        scripts_dir: narrow_fixture.scripts_dir.clone(),
        timeout: Duration::from_secs(240),
    };
    let narrow_behavior = get_decompiler_block_behavior(
        &narrow_behavior_ctx,
        &narrow_fixture.program_name,
        &narrow_function,
        Some("decompile"),
        &DecompilerBlockBehaviorFilter {
            only_strings: false,
            only_api_tag: None,
            only_external: true,
        },
    )
    .await
    .unwrap_or_else(|e| {
        panic!("narrow ghidra_decompiler_block_behavior({narrow_function}): {e:?}")
    });
    assert!(narrow_behavior.decompile_completed);
    assert!(narrow_behavior.decompile_valid);

    let narrow_memory_ctx = DecompilerMemoryContext {
        manager: narrow_fixture.manager.clone(),
        analyze_headless: narrow_fixture.analyze_headless.clone(),
        scripts_dir: narrow_fixture.scripts_dir.clone(),
        timeout: Duration::from_secs(240),
    };
    let narrow_memory = get_decompiler_memory(
        &narrow_memory_ctx,
        &narrow_fixture.program_name,
        &narrow_function,
        Some("decompile"),
        &DecompilerMemoryFilter { only_writes: true },
    )
    .await
    .unwrap_or_else(|e| panic!("narrow ghidra_decompiler_memory({narrow_function}): {e:?}"));
    assert!(narrow_memory.decompile_completed);
    assert!(narrow_memory.decompile_valid);
}
