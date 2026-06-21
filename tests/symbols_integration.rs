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
use rbinghidra::symbols::{SymbolsContext, search_symbols};
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
fn ghidra_symbols_runs_search_symbols_against_real_binary() {
    make_runtime().block_on(ghidra_symbols_runs_search_symbols_against_real_binary_impl());
}

async fn ghidra_symbols_runs_search_symbols_against_real_binary_impl() {
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
        scripts_dir.join("search_symbols.java").exists(),
        "search_symbols.java must exist at {scripts_dir:?}"
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

    let symbols_ctx = SymbolsContext {
        manager: manager.clone(),
        analyze_headless,
        scripts_dir,
        timeout: Duration::from_secs(180),
    };

    let result = search_symbols(&symbols_ctx, "ls", "_", Some(0), Some(50))
        .await
        .unwrap_or_else(|e| panic!("search_symbols failed: {e:?}"));

    assert_eq!(result.schema, "rbm.ghidra.search_symbols.v0");
    assert_eq!(result.cache_key, format!("sha256:{sha}"));
    assert_eq!(result.sha256, sha);
    assert_eq!(result.program_name, "ls");
    assert_eq!(result.query, "_");
    assert_eq!(result.offset, 0);
    assert_eq!(result.limit, 50);
    assert!(
        result.total_matched > 0,
        "expected at least one symbol matching '_' in /bin/ls, got total_matched={}",
        result.total_matched
    );
    assert!(
        !result.symbols.is_empty(),
        "expected at least one symbol entry returned"
    );
    assert!(
        (result.symbols.len() as u64) <= 50,
        "page size should respect the limit, got {}",
        result.symbols.len()
    );
    for sym in &result.symbols {
        assert!(!sym.name.is_empty(), "symbol name should be populated");
        assert!(
            sym.name.to_lowercase().contains('_'),
            "symbol '{}' should contain the query substring",
            sym.name
        );
    }
}
