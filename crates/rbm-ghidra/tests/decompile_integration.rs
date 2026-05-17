#![cfg(feature = "integration-ghidra")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rbm_core::CachePaths;
use rbm_ghidra::decompile::{DecompileContext, decompile_function};
use rbm_ghidra::import::{ImportContext, import_binary};
use rbm_ghidra::probe;
use rbm_ghidra::project::{ProjectManager, hash_file};
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
async fn ghidra_decompile_runs_decompile_function_against_real_binary() {
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
        scripts_dir.join("decompile_function.java").exists(),
        "decompile_function.java must exist at {scripts_dir:?}"
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
    tokio::time::sleep(Duration::from_millis(200)).await;

    let envelope_bytes = std::fs::read(&output).expect("read functions.json");
    let envelope: serde_json::Value =
        serde_json::from_slice(&envelope_bytes).expect("parse functions.json");
    let functions = envelope["functions"]
        .as_array()
        .expect("functions array present");
    let target = functions
        .iter()
        .find(|f| {
            f["is_thunk"].as_bool() == Some(false)
                && f["is_external"].as_bool() == Some(false)
                && f["size"].as_u64().unwrap_or(0) > 0
                && f["name"].as_str().is_some()
        })
        .expect("at least one real (non-thunk, non-external) function in /bin/ls");
    let target_name = target["name"].as_str().unwrap().to_string();

    let decompile_ctx = DecompileContext {
        manager: manager.clone(),
        analyze_headless,
        scripts_dir,
        timeout: Duration::from_secs(180),
    };

    let result = decompile_function(&decompile_ctx, "ls", &target_name, None)
        .await
        .unwrap_or_else(|e| panic!("decompile {target_name}: {e:?}"));
    assert_eq!(result.schema, "rbm.ghidra.decompile_function.v0");
    assert_eq!(result.cache_key, format!("sha256:{sha}"));
    assert_eq!(result.sha256, sha);
    assert_eq!(result.program_name, "ls");
    assert_eq!(
        result.function_name, target_name,
        "function_name should match the resolved target"
    );
    assert!(
        !result.address.is_empty(),
        "address should be populated, got {:?}",
        result.address
    );
    assert!(
        !result.pseudocode.is_empty(),
        "pseudocode should be populated for {target_name}"
    );
}
