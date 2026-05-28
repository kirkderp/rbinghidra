use std::time::Duration;

use rbm_ghidra::dynamic_dispatch_table::{
    DYNAMIC_DISPATCH_TABLE_SCHEMA, DynamicDispatchTableContext, DynamicDispatchTableOptions,
    recover_dynamic_dispatch_table,
};
use rbm_ghidra::project::DYNAMIC_DISPATCH_TABLE_SCRIPT;

mod common;
use common::{make_manager, make_runtime};

fn default_options() -> DynamicDispatchTableOptions<'static> {
    DynamicDispatchTableOptions {
        table_count_global: "count",
        table_ptr_global: "ptr",
        builder_start: "start",
        builder_end: "end",
        hash_function: "hash",
        call_gate_global: "gate",
        lookup_hashes: "1,2,3",
        adapter_function: "adapter",
        hash_seed: "seed",
        hash_multiplier: "mult",
        candidate_names: "name1,name2",
        max_instructions: 0,
        limit: 0,
    }
}

#[test]
fn dynamic_dispatch_table_script_constant() {
    assert_eq!(DYNAMIC_DISPATCH_TABLE_SCRIPT, "dynamic_dispatch_table.java");
}

#[test]
fn dynamic_dispatch_table_schema_constant_pinned() {
    assert_eq!(
        DYNAMIC_DISPATCH_TABLE_SCHEMA,
        "rbm.ghidra.dynamic_dispatch_table.v0"
    );
}

#[test]
fn recover_dynamic_dispatch_table_missing_binary() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();

        let scripts = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join(DYNAMIC_DISPATCH_TABLE_SCRIPT), b"// stub").unwrap();

        let analyze = tmp.path().join("analyzeHeadless");
        std::fs::write(&analyze, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        common::write_executable(&analyze, "#!/bin/sh\n");

        let ctx = DynamicDispatchTableContext {
            manager: mgr.clone(),
            analyze_headless: analyze,
            scripts_dir: scripts,
            timeout: Duration::from_millis(100),
        };

        let res = recover_dynamic_dispatch_table(&ctx, "nonexistent", default_options()).await;
        assert!(res.is_err());
    });
}
