#![cfg(feature = "integration-ghidra")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rbm_core::CachePaths;
use rbm_ghidra::import::{ImportContext, import_binary};
use rbm_ghidra::imports_exports::{ImportsExportsContext, list_exports, list_imports};
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
async fn ghidra_imports_exports_round_trip_against_real_binary() {
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
        scripts_dir.join("list_exports.java").exists(),
        "list_exports.java must exist at {scripts_dir:?}"
    );
    assert!(
        scripts_dir.join("list_imports.java").exists(),
        "list_imports.java must exist at {scripts_dir:?}"
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

    let ctx = ImportsExportsContext {
        manager: manager.clone(),
        analyze_headless,
        scripts_dir,
        timeout: Duration::from_secs(180),
    };

    let exports = list_exports(&ctx, "ls", None, None, None)
        .await
        .unwrap_or_else(|e| panic!("list_exports: {e:?}"));
    assert_eq!(exports.schema, "rbm.ghidra.list_exports.v0");
    assert_eq!(exports.cache_key, format!("sha256:{sha}"));
    assert_eq!(exports.sha256, sha);
    assert_eq!(exports.program_name, "ls");
    assert_eq!(exports.query, ".*");
    assert!(
        exports.total_matched > 0,
        "/bin/ls should have at least one export, got {}",
        exports.total_matched
    );
    assert!(
        !exports.exports.is_empty(),
        "exports page must not be empty when total_matched > 0"
    );
    for entry in &exports.exports {
        assert!(!entry.name.is_empty(), "every export must have a name");
        assert!(
            !entry.address.is_empty(),
            "every export must have an address, got entry {:?}",
            entry
        );
    }

    let imports = list_imports(&ctx, "ls", None, None, None)
        .await
        .unwrap_or_else(|e| panic!("list_imports: {e:?}"));
    assert_eq!(imports.schema, "rbm.ghidra.list_imports.v0");
    assert_eq!(imports.cache_key, format!("sha256:{sha}"));
    assert_eq!(imports.sha256, sha);
    assert_eq!(imports.program_name, "ls");
    assert_eq!(imports.query, ".*");
    assert!(
        imports.total_matched > 0,
        "/bin/ls should have at least one import, got {}",
        imports.total_matched
    );
    assert!(
        !imports.imports.is_empty(),
        "imports page must not be empty when total_matched > 0"
    );
    for entry in &imports.imports {
        assert!(!entry.name.is_empty(), "every import must have a name");
        assert!(
            !entry.library.is_empty(),
            "every import must have a library, got entry {:?}",
            entry
        );
    }

    let small_page = list_imports(&ctx, "ls", None, None, Some(2))
        .await
        .unwrap_or_else(|e| panic!("list_imports limit=2: {e:?}"));
    assert_eq!(small_page.limit, 2);
    assert!(
        small_page.imports.len() <= 2,
        "page must respect the limit, got {} imports",
        small_page.imports.len()
    );
    if small_page.total_matched > 2 {
        assert_eq!(
            small_page.imports.len(),
            2,
            "when total_matched > limit, the page should be exactly limit entries"
        );
    }
}
