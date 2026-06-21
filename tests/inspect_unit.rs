#[path = "support/tempfile.rs"]
mod tempfile;

use rbinghidra::inspect::{
    CachedBinary, InspectError, get_cached_metadata, is_sha256_hex, list_cached_binaries,
    parse_sha256_lookup, read_cached_binary,
};
use rbinghidra::project::{FUNCTIONS_OUTPUT_FILE, ProjectManager};

mod common;
use common::{make_manager, make_runtime, write_envelope};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const SHA_DUP: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const SHA_INCOMPLETE: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const CACHED_METADATA_FILE: &str = "cached_metadata.json";

fn touch_dir(manager: &ProjectManager, sha256: &str) {
    std::fs::create_dir_all(manager.project_dir(sha256)).unwrap();
}

fn write_garbage(manager: &ProjectManager, sha256: &str, payload: &[u8]) {
    let dir = manager.project_dir(sha256);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(FUNCTIONS_OUTPUT_FILE), payload).unwrap();
}

fn create_unrelated_dir(manager: &ProjectManager, name: &str) {
    let path = manager.ghidra_dir();
    std::fs::create_dir_all(path.join(name)).unwrap();
}

fn metadata_path(manager: &ProjectManager, sha256: &str) -> std::path::PathBuf {
    manager.project_dir(sha256).join(CACHED_METADATA_FILE)
}

#[test]
fn is_sha256_hex_accepts_64_lowercase() {
    assert!(is_sha256_hex(SHA_LS));
    assert!(is_sha256_hex(
        "ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789"
    ));
}

#[test]
fn is_sha256_hex_rejects_wrong_length_or_chars() {
    assert!(!is_sha256_hex(""));
    assert!(!is_sha256_hex("abc"));
    assert!(!is_sha256_hex(&"a".repeat(63)));
    assert!(!is_sha256_hex(&"a".repeat(65)));
    assert!(!is_sha256_hex(&"g".repeat(64)));
}

#[test]
fn parse_sha256_lookup_strips_prefix_and_lowercases() {
    assert_eq!(parse_sha256_lookup(SHA_LS), Some(SHA_LS.to_string()));
    let mixed = "ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789";
    let lower = mixed.to_ascii_lowercase();
    assert_eq!(parse_sha256_lookup(mixed), Some(lower.clone()));
    assert_eq!(parse_sha256_lookup(&format!("sha256:{mixed}")), Some(lower));
    assert_eq!(parse_sha256_lookup("ls"), None);
    assert_eq!(parse_sha256_lookup("sha256:notvalid"), None);
}

#[test]
fn list_cached_binaries_returns_empty_when_cache_missing() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        let result = list_cached_binaries(&mgr, None).await.unwrap();
        assert!(result.is_empty());
    });
}

#[test]
fn list_cached_binaries_returns_only_completed_projects() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 12);
        write_envelope(&mgr, SHA_CAT, "cat", 7);
        touch_dir(&mgr, SHA_INCOMPLETE);
        create_unrelated_dir(&mgr, "not-a-sha");

        let result = list_cached_binaries(&mgr, None).await.unwrap();
        assert_eq!(result.len(), 2);
        let names: Vec<&str> = result.iter().map(|c| c.program_name.as_str()).collect();
        assert_eq!(names, vec!["cat", "ls"]);
        assert!(result.iter().all(|c| c.cache_key.starts_with("sha256:")));
        assert!(result.iter().all(|c| c.last_modified_unix.is_some()));
    });
}

#[test]
fn list_cached_binaries_filters_by_program_name_substring() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "lsblk", 1);
        write_envelope(&mgr, SHA_CAT, "cat", 1);

        let result = list_cached_binaries(&mgr, Some("ls")).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].program_name, "lsblk");

        let none = list_cached_binaries(&mgr, Some("zzz")).await.unwrap();
        assert!(none.is_empty());
    });
}

#[test]
fn list_cached_binaries_skips_dirs_with_unparseable_envelope() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_garbage(&mgr, SHA_CAT, b"not json at all");

        let result = list_cached_binaries(&mgr, None).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].program_name, "ls");
    });
}

#[test]
fn read_cached_binary_returns_none_when_output_missing() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        touch_dir(&mgr, SHA_INCOMPLETE);
        let result = read_cached_binary(&mgr, SHA_INCOMPLETE).await.unwrap();
        assert!(result.is_none());
    });
}

#[test]
fn read_cached_binary_parses_envelope_and_populates_paths() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 42);
        let cached = read_cached_binary(&mgr, SHA_LS).await.unwrap().unwrap();
        assert_eq!(cached.sha256, SHA_LS);
        assert_eq!(cached.cache_key, format!("sha256:{SHA_LS}"));
        assert_eq!(cached.program_name, "ls");
        assert_eq!(cached.program_path, "/bin/ls");
        assert_eq!(cached.function_count, 42);
        assert_eq!(cached.error_count, 0);
        assert_eq!(cached.schema, "rbm.ghidra.extract_functions.v0");
        assert!(cached.output_path.ends_with(FUNCTIONS_OUTPUT_FILE));
        assert!(cached.project_dir.ends_with(SHA_LS));
    });
}

#[test]
fn read_cached_binary_writes_small_metadata_sidecar() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 42);
        let output_len = std::fs::metadata(mgr.output_path(SHA_LS)).unwrap().len();

        let cached = read_cached_binary(&mgr, SHA_LS).await.unwrap().unwrap();

        let metadata_bytes = std::fs::read(metadata_path(&mgr, SHA_LS)).unwrap();
        let metadata: serde_json::Value = serde_json::from_slice(&metadata_bytes).unwrap();
        assert_eq!(cached.program_name, "ls");
        assert_eq!(metadata["schema"], "rbm.ghidra.cached_binary.v0");
        assert_eq!(
            metadata["functions_schema"],
            "rbm.ghidra.extract_functions.v0"
        );
        assert_eq!(metadata["program_name"], "ls");
        assert_eq!(metadata["output_len"], output_len);
    });
}

#[test]
fn read_cached_binary_refreshes_stale_metadata_sidecar() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let first = read_cached_binary(&mgr, SHA_LS).await.unwrap().unwrap();
        assert_eq!(first.program_name, "ls");

        write_envelope(&mgr, SHA_LS, "busybox", 12_345);
        let second = read_cached_binary(&mgr, SHA_LS).await.unwrap().unwrap();

        let metadata_bytes = std::fs::read(metadata_path(&mgr, SHA_LS)).unwrap();
        let metadata: serde_json::Value = serde_json::from_slice(&metadata_bytes).unwrap();
        assert_eq!(second.program_name, "busybox");
        assert_eq!(second.function_count, 12_345);
        assert_eq!(metadata["program_name"], "busybox");
        assert_eq!(metadata["function_count"], 12_345);
    });
}

#[test]
fn read_cached_binary_errors_on_malformed_json() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_garbage(&mgr, SHA_LS, b"{not json");
        let err = read_cached_binary(&mgr, SHA_LS).await.unwrap_err();
        assert!(matches!(err, InspectError::Parse { .. }), "{err:?}");
    });
}

#[test]
fn get_cached_metadata_lookup_by_cache_key_prefix() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let cached = get_cached_metadata(&mgr, &format!("sha256:{SHA_LS}"))
            .await
            .unwrap();
        assert_eq!(cached.program_name, "ls");
    });
}

#[test]
fn get_cached_metadata_lookup_by_raw_sha256() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let cached = get_cached_metadata(&mgr, SHA_LS).await.unwrap();
        assert_eq!(cached.cache_key, format!("sha256:{SHA_LS}"));
    });
}

#[test]
fn get_cached_metadata_lookup_by_program_name_exact() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "cat", 1);
        let cached = get_cached_metadata(&mgr, "cat").await.unwrap();
        assert_eq!(cached.sha256, SHA_CAT);
    });
}

#[test]
fn get_cached_metadata_returns_not_found_for_unknown_query() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let err = get_cached_metadata(&mgr, "missing").await.unwrap_err();
        assert!(matches!(err, InspectError::NotFound(_)), "{err:?}");
        let err = get_cached_metadata(&mgr, "").await.unwrap_err();
        assert!(matches!(err, InspectError::NotFound(_)), "{err:?}");
    });
}

#[test]
fn get_cached_metadata_returns_ambiguous_when_multiple_match() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_DUP, "ls", 1);
        let err = get_cached_metadata(&mgr, "ls").await.unwrap_err();
        match err {
            InspectError::Ambiguous { matches, .. } => assert_eq!(matches, 2),
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    });
}

#[test]
fn cached_binary_serializes_to_stable_shape() {
    let cb = CachedBinary {
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        schema: "rbm.ghidra.extract_functions.v0".to_string(),
        program_name: "ls".to_string(),
        program_path: "/bin/ls".to_string(),
        function_count: 7,
        error_count: 0,
        project_dir: "/tmp/abc".to_string(),
        output_path: "/tmp/abc/functions.json".to_string(),
        last_modified_unix: Some(1_700_000_000),
    };
    let json = serde_json::to_value(&cb).unwrap();
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["schema"], "rbm.ghidra.extract_functions.v0");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["program_path"], "/bin/ls");
    assert_eq!(json["function_count"], 7);
    assert_eq!(json["error_count"], 0);
    assert_eq!(json["project_dir"], "/tmp/abc");
    assert_eq!(json["output_path"], "/tmp/abc/functions.json");
    assert_eq!(json["last_modified_unix"], 1_700_000_000);
}
