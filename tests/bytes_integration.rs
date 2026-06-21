#![cfg(feature = "integration-ghidra")]

#[path = "support/tempfile.rs"]
mod tempfile;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rbinghidra::CachePaths;
use rbinghidra::bytes::{DEFAULT_SIZE, ReadBytesContext, ReadBytesError, read_bytes};
use rbinghidra::import::{ImportContext, import_binary};
use rbinghidra::probe;
use rbinghidra::project::{ProjectManager, hash_file};
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
fn ghidra_read_bytes_round_trip_against_real_binary() {
    make_runtime().block_on(ghidra_read_bytes_round_trip_against_real_binary_impl());
}

async fn ghidra_read_bytes_round_trip_against_real_binary_impl() {
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
        scripts_dir.join("read_bytes.java").exists(),
        "read_bytes.java must exist at {scripts_dir:?}"
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
    let entry_addr = envelope["functions"][0]["entry"]
        .as_str()
        .expect("at least one function with an entry field in functions.json")
        .to_string();

    let ctx = ReadBytesContext {
        manager: manager.clone(),
        analyze_headless,
        scripts_dir,
        timeout: Duration::from_secs(180),
    };

    let result = read_bytes(&ctx, "ls", &entry_addr, None)
        .await
        .unwrap_or_else(|e| panic!("read_bytes({entry_addr}): {e:?}"));

    assert_eq!(result.schema, "rbm.ghidra.read_bytes.v0");
    assert_eq!(result.cache_key, format!("sha256:{sha}"));
    assert_eq!(result.sha256, sha);
    assert_eq!(result.program_name, "ls");
    assert_eq!(result.address, entry_addr);
    assert!(
        !result.resolved_address.is_empty(),
        "address lookup must resolve to a non-empty address"
    );
    assert_eq!(result.size, DEFAULT_SIZE);
    assert_eq!(
        result.hex.len() as u64,
        DEFAULT_SIZE * 2,
        "hex must be exactly size*2 characters, got {}",
        result.hex.len()
    );
    assert!(
        result.hex.chars().all(|c| c.is_ascii_hexdigit()),
        "hex must be lowercase ascii hex, got {}",
        result.hex
    );
    assert_eq!(
        result.ascii_preview.chars().count() as u64,
        DEFAULT_SIZE,
        "ascii_preview must be exactly size characters (1:1 with bytes), got {}",
        result.ascii_preview.chars().count()
    );

    let custom = read_bytes(&ctx, "ls", &entry_addr, Some(8))
        .await
        .unwrap_or_else(|e| panic!("read_bytes({entry_addr}, size=8): {e:?}"));
    assert_eq!(custom.size, 8);
    assert_eq!(custom.hex.len(), 16);
    assert_eq!(custom.ascii_preview.chars().count(), 8);

    let err = read_bytes(&ctx, "ls", "0xffffffffffffffff", None)
        .await
        .expect_err("bogus out-of-range address must fail");
    match err {
        ReadBytesError::ReadFailed(msg) => {
            assert!(!msg.is_empty(), "ReadFailed must carry a non-empty message");
        }
        other => panic!("expected ReadFailed, got {other:?}"),
    }
}
