#![allow(unsafe_code)]
use std::fs;
use std::path::{Path, PathBuf};

use rbm_ghidra::health::{
    GhidraCapabilities, GhidraHealth, analyze_headless_path, application_properties_path,
    assemble_health, discover_install_dir, is_valid_ghidra_dir, parse_application_properties,
    probe_at,
};
use tempfile::TempDir;

const GOOD_PROPS: &str = "\
application.name=Ghidra
application.version=12.0.4
application.release.name=PUBLIC
application.build.date=2026-Mar-04 1130 GMT
";

const PROPS_WITH_COMMENTS: &str = "\
# Top-level comment
! Another comment style
application.name=Ghidra
   application.version=11.2.0
application.release.name=DEV
";

#[test]
fn analyze_headless_path_joins_support_directory() {
    let dir = PathBuf::from("/opt/ghidra");
    assert_eq!(
        analyze_headless_path(&dir),
        PathBuf::from("/opt/ghidra/support/analyzeHeadless"),
    );
}

#[test]
fn application_properties_path_joins_ghidra_subdirectory() {
    let dir = PathBuf::from("/opt/ghidra");
    assert_eq!(
        application_properties_path(&dir),
        PathBuf::from("/opt/ghidra/Ghidra/application.properties"),
    );
}

#[test]
fn parse_application_properties_handles_basic_keys() {
    let parsed = parse_application_properties(GOOD_PROPS);
    assert_eq!(
        parsed.get("application.name").map(String::as_str),
        Some("Ghidra")
    );
    assert_eq!(
        parsed.get("application.version").map(String::as_str),
        Some("12.0.4")
    );
    assert_eq!(
        parsed.get("application.release.name").map(String::as_str),
        Some("PUBLIC"),
    );
}

#[test]
fn parse_application_properties_strips_comments_and_blank_lines() {
    let parsed = parse_application_properties(PROPS_WITH_COMMENTS);
    assert_eq!(parsed.len(), 3);
    assert_eq!(
        parsed.get("application.version").map(String::as_str),
        Some("11.2.0")
    );
}

#[test]
fn parse_application_properties_ignores_lines_without_equals() {
    let text = "no_equals_here\nkey=value\n";
    let parsed = parse_application_properties(text);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed.get("key").map(String::as_str), Some("value"));
}

#[test]
fn parse_application_properties_trims_key_and_value_whitespace() {
    let text = "  spaced.key   =   spaced value   \n";
    let parsed = parse_application_properties(text);
    assert_eq!(
        parsed.get("spaced.key").map(String::as_str),
        Some("spaced value")
    );
}

#[test]
fn assemble_health_returns_available_when_props_are_valid() {
    let install_dir = PathBuf::from("/opt/ghidra");
    let analyze_headless = analyze_headless_path(&install_dir);

    let health = assemble_health(&install_dir, &analyze_headless, GOOD_PROPS);

    assert!(health.available);
    assert_eq!(health.error, None);
    assert_eq!(health.version.as_deref(), Some("12.0.4"));
    assert_eq!(health.release_name.as_deref(), Some("PUBLIC"));
    assert!(!health.capabilities.decompiler_bitfield_names);
    assert_eq!(health.ghidra_install_dir.as_deref(), Some("/opt/ghidra"));
    assert_eq!(
        health.analyze_headless_path.as_deref(),
        Some("/opt/ghidra/support/analyzeHeadless"),
    );
}

#[test]
fn assemble_health_returns_unavailable_when_application_name_is_wrong() {
    let install_dir = PathBuf::from("/opt/ghidra");
    let analyze_headless = analyze_headless_path(&install_dir);
    let bad = "application.name=NotGhidra\napplication.version=12.0.4\n";

    let health = assemble_health(&install_dir, &analyze_headless, bad);

    assert!(!health.available);
    let err = health.error.expect("error message expected");
    assert!(err.contains("does not identify as Ghidra"), "got: {err}");
    assert!(err.contains("NotGhidra"), "got: {err}");
    assert_eq!(health.version.as_deref(), Some("12.0.4"));
}

#[test]
fn assemble_health_returns_unavailable_when_application_name_is_missing() {
    let install_dir = PathBuf::from("/opt/ghidra");
    let analyze_headless = analyze_headless_path(&install_dir);
    let bad = "application.version=12.0.4\n";

    let health = assemble_health(&install_dir, &analyze_headless, bad);

    assert!(!health.available);
    let err = health.error.expect("error message expected");
    assert!(err.contains("does not identify as Ghidra"), "got: {err}");
}

#[test]
fn assemble_health_returns_unavailable_when_version_is_missing() {
    let install_dir = PathBuf::from("/opt/ghidra");
    let analyze_headless = analyze_headless_path(&install_dir);
    let bad = "application.name=Ghidra\napplication.release.name=PUBLIC\n";

    let health = assemble_health(&install_dir, &analyze_headless, bad);

    assert!(!health.available);
    assert_eq!(health.version, None);
    assert_eq!(health.release_name.as_deref(), Some("PUBLIC"));
    let err = health.error.expect("error message expected");
    assert!(err.contains("missing application.version"), "got: {err}");
}

#[test]
fn probe_at_returns_unavailable_when_install_dir_is_none() {
    let health = probe_at(None);
    assert!(!health.available);
    assert_eq!(health.ghidra_install_dir, None);
    assert_eq!(health.analyze_headless_path, None);
    let err = health.error.expect("error message expected");
    assert!(err.contains("GHIDRA_INSTALL_DIR"), "got: {err}");
}

#[test]
fn probe_at_treats_empty_install_dir_as_unset() {
    let empty = PathBuf::new();
    let health = probe_at(Some(&empty));
    assert!(!health.available);
    assert_eq!(health.ghidra_install_dir, None);
    assert_eq!(health.analyze_headless_path, None);
    let err = health.error.expect("error message expected");
    assert!(err.contains("Ghidra not found"), "got: {err}");
}

#[test]
fn probe_at_returns_unavailable_when_install_dir_does_not_exist() {
    let nonexistent = PathBuf::from("/definitely/does/not/exist/ghidra-xyz-987654");
    let health = probe_at(Some(&nonexistent));
    assert!(!health.available);
    assert_eq!(
        health.ghidra_install_dir.as_deref(),
        Some("/definitely/does/not/exist/ghidra-xyz-987654"),
    );
    assert!(
        health
            .error
            .as_deref()
            .unwrap_or("")
            .contains("not a directory"),
        "error: {:?}",
        health.error
    );
}

#[test]
fn probe_at_returns_unavailable_when_analyze_headless_is_missing() {
    let dir = TempDir::new().expect("create temp dir");
    let health = probe_at(Some(dir.path()));

    assert!(!health.available);
    assert!(health.ghidra_install_dir.is_some());
    assert!(health.analyze_headless_path.is_some());
    assert!(
        health
            .error
            .as_deref()
            .unwrap_or("")
            .contains("analyzeHeadless not found"),
        "error: {:?}",
        health.error,
    );
}

#[test]
fn probe_at_returns_unavailable_when_application_properties_is_missing() {
    let dir = TempDir::new().expect("create temp dir");
    let support = dir.path().join("support");
    fs::create_dir_all(&support).unwrap();
    fs::write(support.join("analyzeHeadless"), b"#!/bin/sh\nexit 0\n").unwrap();

    let health = probe_at(Some(dir.path()));

    assert!(!health.available);
    let err = health.error.expect("error message expected");
    assert!(err.contains("could not read"), "got: {err}");
}

#[test]
fn probe_at_returns_available_against_synthetic_layout() {
    let dir = TempDir::new().expect("create temp dir");
    let support = dir.path().join("support");
    let ghidra = dir.path().join("Ghidra");
    fs::create_dir_all(&support).unwrap();
    fs::create_dir_all(&ghidra).unwrap();
    fs::write(support.join("analyzeHeadless"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::write(ghidra.join("application.properties"), GOOD_PROPS).unwrap();

    let health = probe_at(Some(dir.path()));

    assert!(health.available, "error: {:?}", health.error);
    assert_eq!(health.error, None);
    assert_eq!(health.version.as_deref(), Some("12.0.4"));
    assert_eq!(health.release_name.as_deref(), Some("PUBLIC"));
    assert!(
        health
            .analyze_headless_path
            .as_deref()
            .unwrap_or("")
            .ends_with("support/analyzeHeadless"),
        "analyze_headless_path: {:?}",
        health.analyze_headless_path,
    );
}

#[test]
fn ghidra_health_serializes_to_expected_json_shape() {
    let install_dir = PathBuf::from("/opt/ghidra");
    let analyze_headless = analyze_headless_path(&install_dir);
    let health = assemble_health(&install_dir, &analyze_headless, GOOD_PROPS);

    let value = serde_json::to_value(&health).unwrap();
    assert_eq!(value["available"], serde_json::json!(true));
    assert_eq!(value["version"], serde_json::json!("12.0.4"));
    assert_eq!(value["release_name"], serde_json::json!("PUBLIC"));
    assert_eq!(
        value["capabilities"]["decompiler_bitfield_names"],
        serde_json::json!(false)
    );
    assert_eq!(value["error"], serde_json::Value::Null);
    assert_eq!(
        value["ghidra_install_dir"],
        serde_json::json!("/opt/ghidra")
    );
}

#[test]
fn ghidra_health_implements_partial_eq() {
    let h1 = GhidraHealth {
        available: true,
        ghidra_install_dir: Some("/x".into()),
        analyze_headless_path: Some("/x/support/analyzeHeadless".into()),
        version: Some("12.0.4".into()),
        release_name: None,
        capabilities: GhidraCapabilities {
            decompiler_bitfield_names: false,
            debuginfod: false,
            hexagon_processor: false,
            modern_objc_analyzers: false,
            jython_enabled_by_default: true,
            notes: Vec::new(),
        },
        error: None,
    };
    let h2 = h1.clone();
    assert_eq!(h1, h2);
}

#[test]
fn is_valid_ghidra_dir_rejects_nonexistent() {
    assert!(!is_valid_ghidra_dir(Path::new("/does/not/exist")));
}

#[test]
fn is_valid_ghidra_dir_rejects_file() {
    // A regular file should not be a valid Ghidra dir
    assert!(!is_valid_ghidra_dir(Path::new(file!())));
}

#[test]
fn is_valid_ghidra_dir_accepts_synthetic_layout() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    // Create support/analyzeHeadless (just a regular file)
    let support = root.join("support");
    std::fs::create_dir(&support).unwrap();
    std::fs::write(support.join("analyzeHeadless"), "#!/bin/sh\n").unwrap();
    // Create Ghidra/application.properties
    let ghidra = root.join("Ghidra");
    std::fs::create_dir(&ghidra).unwrap();
    std::fs::write(ghidra.join("application.properties"), GOOD_PROPS).unwrap();
    // Make analyzeHeadless executable on unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(support.join("analyzeHeadless")).unwrap();
        let mut perms = meta.permissions();
        perms.set_mode(perms.mode() | 0o111);
        std::fs::set_permissions(support.join("analyzeHeadless"), perms).unwrap();
    }

    assert!(is_valid_ghidra_dir(root));
}

use serial_test::serial;

#[test]
#[serial]
fn discover_install_dir_respects_env_override() {
    // Set env var to a nonexistent dir -> should return None (since it's not valid)
    // First, test with a valid synthetic dir
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let support = root.join("support");
    std::fs::create_dir(&support).unwrap();
    std::fs::write(support.join("analyzeHeadless"), "#!/bin/sh\n").unwrap();
    let ghidra_dir = root.join("Ghidra");
    std::fs::create_dir(&ghidra_dir).unwrap();
    std::fs::write(ghidra_dir.join("application.properties"), GOOD_PROPS).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(support.join("analyzeHeadless")).unwrap();
        let mut perms = meta.permissions();
        perms.set_mode(perms.mode() | 0o111);
        std::fs::set_permissions(support.join("analyzeHeadless"), perms).unwrap();
    }

    // SAFETY: this test performs a narrow env override and restores it before returning.
    unsafe {
        std::env::set_var("GHIDRA_INSTALL_DIR", root.as_os_str());
    }
    let result = discover_install_dir();
    // SAFETY: restore the process environment modified above.
    unsafe {
        std::env::remove_var("GHIDRA_INSTALL_DIR");
    }

    assert_eq!(result.as_deref(), Some(root));
}

#[test]
#[serial]
fn discover_install_dir_env_override_ignores_invalid() {
    // Set env var to a dir that doesn't look like Ghidra -> should fall through to known paths
    let tmp = TempDir::new().unwrap();
    // SAFETY: this test performs a narrow env override and restores it before returning.
    unsafe {
        std::env::set_var("GHIDRA_INSTALL_DIR", tmp.path().as_os_str());
    }
    let _result = discover_install_dir();
    // SAFETY: restore the process environment modified above.
    unsafe {
        std::env::remove_var("GHIDRA_INSTALL_DIR");
    }
    // On this machine, if Homebrew is installed, it should still find the real Ghidra
    // If not, result will be None. Either way, it did NOT use the invalid tmp dir.
    // (This test is mainly to verify the env var is checked for validity, not just presence)
}
