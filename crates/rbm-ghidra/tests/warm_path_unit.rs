use std::path::PathBuf;

use rbm_ghidra::warm_path::{
    ProjectDiscoveryError, WarmPathError, discover_project_name, extract_gpr_stem,
    per_call_output_path, sanitize_query_for_filename,
};
use tempfile::TempDir;

mod common;
use common::make_runtime;

#[test]
fn extract_gpr_stem_returns_first_match() {
    let entries = vec![
        "ls.rep".to_string(),
        "ls.gpr".to_string(),
        "decompile_main_1.json".to_string(),
    ];
    assert_eq!(extract_gpr_stem(&entries), Some("ls".to_string()));
}

#[test]
fn extract_gpr_stem_returns_none_when_absent() {
    let entries = vec!["ls.rep".to_string(), "functions.json".to_string()];
    assert_eq!(extract_gpr_stem(&entries), None);
}

#[test]
fn sanitize_query_for_filename_strips_punctuation_keeps_safe_chars() {
    assert_eq!(sanitize_query_for_filename("main"), "main");
    assert_eq!(sanitize_query_for_filename("0x100003a40"), "0x100003a40");
    assert_eq!(
        sanitize_query_for_filename("main; rm -rf /"),
        "main__rm_-rf__"
    );
    assert_eq!(
        sanitize_query_for_filename("foo.bar_baz-1"),
        "foo.bar_baz-1"
    );
    assert_eq!(sanitize_query_for_filename(""), "query");
}

#[test]
fn per_call_output_path_uses_project_dir_and_includes_prefix_query_and_stamp() {
    let project_dir = PathBuf::from("/tmp/proj");
    let path = per_call_output_path(&project_dir, "decompile", "main");
    assert!(path.starts_with(&project_dir));
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with("decompile_main_"), "{name}");
    assert!(common::has_json_extension(&name), "{name}");
}

#[test]
fn per_call_output_path_honors_alternate_prefix() {
    let project_dir = PathBuf::from("/tmp/proj");
    let path = per_call_output_path(&project_dir, "symbols", "main");
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with("symbols_main_"), "{name}");
    assert!(common::has_json_extension(&name), "{name}");
}

#[test]
fn per_call_output_path_sanitizes_query_segment() {
    let project_dir = PathBuf::from("/tmp/proj");
    let path = per_call_output_path(&project_dir, "decompile", "weird/name with spaces");
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    assert!(!name.contains('/'));
    assert!(!name.contains(' '));
    assert!(
        name.starts_with("decompile_weird_name_with_spaces_"),
        "{name}"
    );
}

#[test]
fn discover_project_name_returns_gpr_stem_from_real_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("ls.gpr"), b"").unwrap();
        std::fs::create_dir_all(tmp.path().join("ls.rep")).unwrap();
        let name = discover_project_name(tmp.path()).await.unwrap();
        assert_eq!(name, "ls");
    });
}

#[test]
fn discover_project_name_returns_project_file_missing_when_absent() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("functions.json"), b"{}").unwrap();
        let err = discover_project_name(tmp.path()).await.unwrap_err();
        assert!(
            matches!(err, ProjectDiscoveryError::ProjectFileMissing(_)),
            "{err:?}"
        );
    });
}

#[test]
fn project_discovery_error_flattens_into_warm_path_error() {
    let missing = ProjectDiscoveryError::ProjectFileMissing(PathBuf::from("/tmp/proj"));
    let outer: WarmPathError = missing.into();
    assert!(
        matches!(outer, WarmPathError::ProjectFileMissing(_)),
        "{outer:?}"
    );

    let io = ProjectDiscoveryError::Io {
        path: PathBuf::from("/tmp/proj"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    };
    let outer: WarmPathError = io.into();
    match outer {
        WarmPathError::Io { path, source } => {
            assert_eq!(path, PathBuf::from("/tmp/proj"));
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected WarmPathError::Io, got {other:?}"),
    }
}
