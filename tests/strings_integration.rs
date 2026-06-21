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
use rbinghidra::strings::{SearchStringsContext, search_strings};
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
fn ghidra_search_strings_runs_against_real_binary() {
    make_runtime().block_on(ghidra_search_strings_runs_against_real_binary_impl());
}

async fn ghidra_search_strings_runs_against_real_binary_impl() {
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
        scripts_dir.join("search_strings.java").exists(),
        "search_strings.java must exist at {scripts_dir:?}"
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

    let ctx = SearchStringsContext {
        manager: manager.clone(),
        analyze_headless,
        scripts_dir,
        timeout: Duration::from_secs(180),
    };

    let result = search_strings(&ctx, "ls", None, Some(0), Some(100))
        .await
        .unwrap_or_else(|e| panic!("search_strings failed: {e:?}"));

    assert_eq!(result.schema, "rbm.ghidra.search_strings.v0");
    assert_eq!(result.cache_key, format!("sha256:{sha}"));
    assert_eq!(result.sha256, sha);
    assert_eq!(result.program_name, "ls");
    assert_eq!(result.query, ".*");
    assert_eq!(result.offset, 0);
    assert_eq!(result.limit, 100);
    assert!(
        result.total_matched > 0,
        "expected at least one defined string in /bin/ls, got total_matched={}",
        result.total_matched
    );
    assert!(
        !result.strings.is_empty(),
        "expected at least one string entry returned"
    );
    assert!(
        (result.strings.len() as u64) <= 100,
        "page size should respect the limit, got {}",
        result.strings.len()
    );
    let mut non_empty = 0;
    for s in &result.strings {
        assert!(!s.address.is_empty(), "every string must have an address");
        assert!(
            !s.data_type.is_empty(),
            "every string must have a data_type"
        );
        assert_eq!(
            s.length as usize,
            s.value.chars().count(),
            "length should match value.chars().count() for {s:?}"
        );
        if !s.value.is_empty() {
            non_empty += 1;
        }
    }
    assert!(
        non_empty > 0,
        "expected at least one non-empty string in /bin/ls"
    );
}
