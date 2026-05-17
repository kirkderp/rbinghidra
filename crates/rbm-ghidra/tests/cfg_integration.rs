#![cfg(feature = "integration-ghidra")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rbm_core::CachePaths;
use rbm_ghidra::cfg::{CfgContext, CfgError, gen_cfg};
use rbm_ghidra::import::{ImportContext, import_binary};
use rbm_ghidra::probe;
use rbm_ghidra::project::{ProjectManager, hash_file};
use serde_json::Value;
use tempfile::TempDir;

fn repo_scripts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("ghidra_scripts")
}

#[tokio::test]
#[ignore = "requires real Ghidra/analyzeHeadless; run explicitly with --ignored"]
async fn ghidra_cfg_round_trip_against_real_binary() {
    let health = probe();
    assert!(
        health.available,
        "GHIDRA_INSTALL_DIR must point at a real Ghidra install. health={health:?}"
    );
    let analyze_headless = PathBuf::from(
        health
            .analyze_headless_path
            .expect("analyze_headless_path populated"),
    );
    let scripts_dir = repo_scripts_dir();
    assert!(
        scripts_dir.join("extract_functions.java").exists(),
        "extract_functions.java must exist at {scripts_dir:?}"
    );
    assert!(
        scripts_dir.join("cfg.java").exists(),
        "cfg.java must exist at {scripts_dir:?}"
    );

    let tmp = TempDir::new().unwrap();
    let cache = CachePaths::new(tmp.path().join("rbinghidra-cache"));
    let manager = Arc::new(ProjectManager::new(&cache));

    let binary = PathBuf::from("/bin/ls");
    assert!(binary.exists(), "/bin/ls must exist on this host");
    let sha = hash_file(&binary).await.unwrap();
    let output = manager.output_path(&sha);

    let import_ctx = ImportContext {
        manager: manager.clone(),
        analyze_headless: analyze_headless.clone(),
        scripts_dir: scripts_dir.clone(),
        timeout: Duration::from_secs(600),
    };
    let report = import_binary(&import_ctx, &binary).await.unwrap();
    assert_eq!(report.cache_key, format!("sha256:{sha}"));

    let deadline = Instant::now() + Duration::from_secs(600);
    while !output.exists() {
        if Instant::now() >= deadline {
            panic!("ghidra_import never produced {output:?}");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let lock = manager.lock_for(&sha);
    let _wait = lock.clone().lock_owned().await;
    drop(_wait);

    let envelope_bytes = std::fs::read(&output).expect("read functions.json");
    let envelope: Value = serde_json::from_slice(&envelope_bytes).expect("parse functions.json");
    let functions = envelope["functions"]
        .as_array()
        .expect("functions array present");
    let target = functions
        .iter()
        .find(|f| {
            f["is_thunk"].as_bool() == Some(false)
                && f["is_external"].as_bool() == Some(false)
                && f["size"].as_u64().unwrap_or(0) > 0
                && f["name"].as_str().map(|n| !n.is_empty()).unwrap_or(false)
                && f["entry"].as_str().map(|e| !e.is_empty()).unwrap_or(false)
        })
        .expect("at least one real (non-thunk, non-external) function in /bin/ls");
    let target_name = target["name"].as_str().unwrap().to_string();
    let target_entry = target["entry"].as_str().unwrap().to_string();

    let ctx = CfgContext {
        manager: manager.clone(),
        analyze_headless,
        scripts_dir,
        timeout: Duration::from_secs(240),
    };

    let by_address = gen_cfg(&ctx, "ls", &target_entry)
        .await
        .unwrap_or_else(|e| panic!("gen_cfg({target_entry}): {e:?}"));

    assert_eq!(by_address.schema, "rbm.ghidra.cfg.v0");
    assert_eq!(by_address.cache_key, format!("sha256:{sha}"));
    assert_eq!(by_address.sha256, sha);
    assert_eq!(by_address.program_name, "ls");
    assert_eq!(by_address.query, target_entry);
    assert!(
        !by_address.resolved_address.is_empty(),
        "address lookup must resolve to a non-empty address"
    );
    assert!(
        !by_address.resolved_function_name.is_empty(),
        "resolved_function_name should be populated"
    );
    assert!(
        by_address.block_count >= 1,
        "cfg must contain at least one block, got block_count={}",
        by_address.block_count
    );
    assert_eq!(by_address.blocks.len() as u64, by_address.block_count);
    assert_eq!(by_address.edges.len() as u64, by_address.edge_count);
    assert!(
        by_address.mermaid.starts_with("graph TD"),
        "mermaid must start with 'graph TD', got {:?}",
        by_address.mermaid
    );
    for block in &by_address.blocks {
        assert!(
            !block.address.is_empty(),
            "block.address must not be empty: {block:?}"
        );
    }
    for edge in &by_address.edges {
        assert!(
            !edge.from.is_empty(),
            "edge.from must not be empty: {edge:?}"
        );
        assert!(!edge.to.is_empty(), "edge.to must not be empty: {edge:?}");
        assert!(
            !edge.flow_type.is_empty(),
            "edge.flow_type must not be empty: {edge:?}"
        );
    }

    let by_name = gen_cfg(&ctx, "ls", &target_name)
        .await
        .unwrap_or_else(|e| panic!("gen_cfg({target_name}): {e:?}"));
    assert!(
        !by_name.resolved_address.is_empty(),
        "name-based lookup must resolve to an address"
    );
    assert!(
        by_name.block_count >= 1,
        "name-based cfg must contain at least one block"
    );

    let err = gen_cfg(&ctx, "ls", "__bogus_function_never_exists_xyz")
        .await
        .expect_err("bogus function name must fail to resolve");
    match err {
        CfgError::ResolutionFailed(msg) => {
            assert!(
                msg.contains("not found") || msg.contains("Ambiguous"),
                "unexpected resolution message: {msg}"
            );
        }
        other => panic!("expected ResolutionFailed, got {other:?}"),
    }
}
