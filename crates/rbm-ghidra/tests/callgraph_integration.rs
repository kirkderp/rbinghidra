#![cfg(feature = "integration-ghidra")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rbm_core::CachePaths;
use rbm_ghidra::callgraph::{CallGraphContext, CallGraphError, gen_callgraph};
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
async fn ghidra_callgraph_round_trip_against_real_binary() {
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
        scripts_dir.join("callgraph.java").exists(),
        "callgraph.java must exist at {scripts_dir:?}"
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

    let ctx = CallGraphContext {
        manager: manager.clone(),
        analyze_headless,
        scripts_dir,
        timeout: Duration::from_secs(240),
    };

    let calling = gen_callgraph(&ctx, "ls", &target_entry, Some("calling"), None, None)
        .await
        .unwrap_or_else(|e| panic!("gen_callgraph({target_entry}, calling): {e:?}"));

    assert_eq!(calling.schema, "rbm.ghidra.callgraph.v0");
    assert_eq!(calling.cache_key, format!("sha256:{sha}"));
    assert_eq!(calling.sha256, sha);
    assert_eq!(calling.program_name, "ls");
    assert_eq!(calling.query, target_entry);
    assert_eq!(calling.direction, "calling");
    assert!(
        !calling.resolved_address.is_empty(),
        "address lookup must resolve to a non-empty address"
    );
    assert!(
        !calling.resolved_function_name.is_empty(),
        "resolved_function_name should be populated"
    );
    assert!(
        calling.node_count >= 1,
        "calling graph must contain at least the root node, got node_count={}",
        calling.node_count
    );
    assert_eq!(calling.nodes.len() as u64, calling.node_count);
    assert_eq!(calling.edges.len() as u64, calling.edge_count);
    assert!(
        calling.mermaid.starts_with("graph LR"),
        "mermaid must start with 'graph LR', got {:?}",
        calling.mermaid
    );
    let root_addr = calling.resolved_address.clone();
    assert!(
        calling.nodes.iter().any(|n| n.address == root_addr),
        "calling graph nodes must contain the root address {root_addr}"
    );
    for edge in &calling.edges {
        assert!(
            !edge.from.is_empty(),
            "edge.from must not be empty: {edge:?}"
        );
        assert!(!edge.to.is_empty(), "edge.to must not be empty: {edge:?}");
    }
    for node in &calling.nodes {
        assert!(
            !node.address.is_empty(),
            "node.address must not be empty: {node:?}"
        );
    }

    let by_name = gen_callgraph(&ctx, "ls", &target_name, Some("calling"), Some(1), None)
        .await
        .unwrap_or_else(|e| panic!("gen_callgraph({target_name}, calling, depth=1): {e:?}"));
    assert_eq!(by_name.direction, "calling");
    assert_eq!(by_name.depth, 1);
    assert!(
        !by_name.resolved_address.is_empty(),
        "name-based lookup must resolve to an address"
    );

    let called = gen_callgraph(&ctx, "ls", &target_entry, Some("called"), Some(2), None)
        .await
        .unwrap_or_else(|e| panic!("gen_callgraph({target_entry}, called): {e:?}"));
    assert_eq!(called.direction, "called");
    assert_eq!(called.depth, 2);
    assert!(
        called.node_count >= 1,
        "called graph must contain at least the root"
    );
    assert!(
        called.nodes.iter().any(|n| n.address == root_addr),
        "called graph must include the root function"
    );

    let err = gen_callgraph(
        &ctx,
        "ls",
        "__bogus_function_never_exists_xyz",
        None,
        None,
        None,
    )
    .await
    .expect_err("bogus function name must fail to resolve");
    match err {
        CallGraphError::ResolutionFailed(msg) => {
            assert!(
                msg.contains("not found") || msg.contains("Ambiguous"),
                "unexpected resolution message: {msg}"
            );
        }
        other => panic!("expected ResolutionFailed, got {other:?}"),
    }
}
