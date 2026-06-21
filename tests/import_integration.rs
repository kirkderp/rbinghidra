#![cfg(feature = "integration-ghidra")]

#[path = "support/tempfile.rs"]
mod tempfile;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rbinghidra::CachePaths;
use rbinghidra::import::{ImportContext, import_binary};
use rbinghidra::probe;
use rbinghidra::project::{ProjectManager, hash_file};
use tempfile::TempDir;

fn repo_scripts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ghidra_scripts")
}

fn make_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
#[ignore = "requires real Ghidra/analyzeHeadless; run explicitly with --ignored"]
fn ghidra_import_runs_extract_functions_against_real_binary() {
    make_runtime().block_on(ghidra_import_runs_extract_functions_against_real_binary_impl());
}

async fn ghidra_import_runs_extract_functions_against_real_binary_impl() {
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
        "ghidra_scripts/extract_functions.java must exist at {scripts_dir:?}"
    );

    let tmp = TempDir::new().unwrap();
    let cache = CachePaths::new(tmp.path().join("rbinghidra-cache"));
    let manager = Arc::new(ProjectManager::new(&cache));

    let binary = PathBuf::from("/bin/ls");
    assert!(binary.exists(), "/bin/ls must exist on this host");
    let sha = hash_file(&binary).await.unwrap();
    let output = manager.output_path(&sha);

    let ctx = ImportContext {
        manager: manager.clone(),
        analyze_headless,
        scripts_dir,
        timeout: Duration::from_secs(600),
    };

    let report = import_binary(&ctx, &binary).await.unwrap();
    assert_eq!(report.status, "running");
    assert!(report.started, "first call should start the runner");
    assert_eq!(report.cache_key, format!("sha256:{sha}"));

    let deadline = Instant::now() + Duration::from_secs(600);
    while !output.exists() {
        if Instant::now() >= deadline {
            panic!("ghidra_import: extract_functions.java never produced {output:?}");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let bytes = std::fs::read(&output).expect("read functions.json");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("functions.json parses");
    assert_eq!(value["schema"], "rbm.ghidra.extract_functions.v0");
    assert_eq!(value["program_path"], binary.to_string_lossy().as_ref());
    assert!(
        value["function_count"].as_i64().unwrap_or(-1) >= 0,
        "function_count should be a non-negative integer"
    );
}
