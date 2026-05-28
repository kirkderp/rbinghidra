#![cfg(feature = "integration-ghidra")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rbm_core::CachePaths;
use rbm_ghidra::constants::{ConstantsContext, ConstantsOptions, scan_constants};
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
async fn ghidra_scan_constants_runs_against_real_binary() {
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
        scripts_dir.join("constants.java").exists(),
        "constants.java must exist at {scripts_dir:?}"
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

    let ctx = ConstantsContext {
        manager: manager.clone(),
        analyze_headless,
        scripts_dir,
        timeout: Duration::from_secs(180),
    };

    let options = ConstantsOptions {
        mode: Some("common"),
        limit: Some(10),
        ..Default::default()
    };

    let result = scan_constants(&ctx, "ls", options)
        .await
        .unwrap_or_else(|e| panic!("scan_constants failed: {e:?}"));

    assert_eq!(result.schema, "rbm.ghidra.constants.v0");
    assert_eq!(result.cache_key, format!("sha256:{sha}"));
    assert_eq!(result.sha256, sha);
    assert_eq!(result.program_name, "ls");
    assert_eq!(result.mode, "common");
    assert_eq!(result.limit, 10);
    assert!(
        result.total_matched > 0,
        "expected at least one defined constant in /bin/ls, got total_matched={}",
        result.total_matched
    );
    assert!(
        !result.constants.is_empty(),
        "expected at least one constant entry returned"
    );
    assert!(
        (result.constants.len() as u64) <= 10,
        "page size should respect the limit, got {}",
        result.constants.len()
    );
}
