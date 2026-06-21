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
use rbinghidra::xrefs::{XrefsContext, XrefsError, list_xrefs};
use serde_json::Value;
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
fn ghidra_xrefs_round_trip_against_real_binary() {
    make_runtime().block_on(ghidra_xrefs_round_trip_against_real_binary_impl());
}

async fn ghidra_xrefs_round_trip_against_real_binary_impl() {
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
        scripts_dir.join("list_xrefs.java").exists(),
        "list_xrefs.java must exist at {scripts_dir:?}"
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

    let envelope_bytes = tokio::fs::read(&output).await.unwrap();
    let envelope: Value = serde_json::from_slice(&envelope_bytes).unwrap();
    let first_entry = envelope["functions"][0]["entry"]
        .as_str()
        .expect("at least one function with an entry field in functions.json")
        .to_string();

    let ctx = XrefsContext {
        manager: manager.clone(),
        analyze_headless,
        scripts_dir,
        timeout: Duration::from_secs(180),
    };

    let xrefs = list_xrefs(&ctx, "ls", &first_entry, None, None, None)
        .await
        .unwrap_or_else(|e| panic!("list_xrefs({first_entry}): {e:?}"));
    assert_eq!(xrefs.schema, "rbm.ghidra.list_xrefs.v0");
    assert_eq!(xrefs.cache_key, format!("sha256:{sha}"));
    assert_eq!(xrefs.sha256, sha);
    assert_eq!(xrefs.program_name, "ls");
    assert_eq!(xrefs.query, first_entry);
    assert!(
        !xrefs.resolved_address.is_empty(),
        "address lookup must resolve to a non-empty address"
    );
    for entry in &xrefs.xrefs {
        assert!(
            !entry.from_address.is_empty(),
            "every xref must have a from_address, got {entry:?}"
        );
        assert!(
            !entry.to_address.is_empty(),
            "every xref must have a to_address, got {entry:?}"
        );
        assert!(
            !entry.ref_type.is_empty(),
            "every xref must have a ref_type, got {entry:?}"
        );
    }

    let err = list_xrefs(
        &ctx,
        "ls",
        "__bogus_symbol_never_exists_xyz",
        None,
        None,
        None,
    )
    .await
    .expect_err("bogus symbol must fail to resolve");
    match err {
        XrefsError::ResolutionFailed(msg) => {
            assert!(
                msg.contains("not found") || msg.contains("Ambiguous"),
                "unexpected resolution message: {msg}"
            );
        }
        other => panic!("expected ResolutionFailed, got {other:?}"),
    }
}
