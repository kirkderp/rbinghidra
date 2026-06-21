#![cfg(feature = "integration-ghidra")]

#[path = "support/tempfile.rs"]
mod tempfile;

mod common;

use std::path::Path;
use std::time::Duration;

use rbinghidra::path_digest::{PathDigestContext, PathDigestOptions, get_path_digest};

#[test]
#[ignore = "requires real Ghidra/analyzeHeadless; run explicitly with --ignored"]
fn ghidra_path_digest_round_trip_against_real_binary() {
    common::make_runtime().block_on(ghidra_path_digest_round_trip_against_real_binary_impl());
}

async fn ghidra_path_digest_round_trip_against_real_binary_impl() {
    let fixture = common::import_real_binary(Path::new("/bin/ls")).await;
    assert!(
        fixture.scripts_dir.join("path_digest.java").exists(),
        "path_digest.java must exist at {:?}",
        fixture.scripts_dir
    );
    let target = fixture
        .functions
        .iter()
        .find(|f| {
            f["is_thunk"].as_bool() == Some(false)
                && f["is_external"].as_bool() == Some(false)
                && f["size"].as_u64().unwrap_or(0) > 0
                && f["entry"].as_str().map(|e| !e.is_empty()).unwrap_or(false)
        })
        .expect("at least one real function in /bin/ls");
    let entry = target["entry"].as_str().unwrap();

    let ctx = PathDigestContext {
        manager: fixture.manager.clone(),
        analyze_headless: fixture.analyze_headless,
        scripts_dir: fixture.scripts_dir,
        timeout: Duration::from_secs(240),
    };

    let digest = get_path_digest(
        &ctx,
        "ls",
        entry,
        PathDigestOptions {
            range_start: "",
            range_end: "",
            stop_addresses: "",
            state_register: "rsp",
            max_instructions: 200,
            max_events: 50,
        },
    )
    .await
    .unwrap_or_else(|e| panic!("ghidra_path_digest({entry}): {e:?}"));

    assert_eq!(digest["schema"], "rbm.ghidra.path_digest.v0");
    assert_eq!(digest["cache_key"], format!("sha256:{}", fixture.sha));
    assert_eq!(digest["program_name"], fixture.program_name);
    assert!(digest["instruction_count"].as_u64().unwrap_or(0) > 0);
    assert!(digest["block_count"].as_u64().unwrap_or(0) > 0);
    assert!(digest["events"].as_array().is_some());
}
