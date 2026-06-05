use std::path::PathBuf;

use rbm_ghidra::warm_path::{
    ProjectDiscoveryError, WarmPathError, WarmPathRequest, discover_program_name,
    discover_project_name, execute_warm_path, per_call_output_path,
    sanitize_query_for_filename,
};
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime, write_envelope, write_executable};

const SHA_SAMPLE: &str = "1111111111111111111111111111111111111111111111111111111111111111";

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
fn discover_program_name_uses_ghidra_idata_entry_when_import_suffixes_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let idata = tmp.path().join("sample.rep").join("idata");
        std::fs::create_dir_all(&idata).unwrap();
        std::fs::write(
            idata.join("~index.dat"),
            "VERSION=1\n  00000001:sample.bin.0:c0a823e5601235220094043875\n",
        )
        .unwrap();

        let name = discover_program_name(tmp.path(), "sample").await;
        assert_eq!(name, "sample.bin.0");
    });
}

#[test]
fn discover_program_name_falls_back_to_project_name_without_idata_index() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let name = discover_program_name(tmp.path(), "sample").await;
        assert_eq!(name, "sample");
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

#[test]
fn execute_warm_path_processes_discovered_project_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, manager) = make_manager();
        write_envelope(
            manager.as_ref(),
            SHA_SAMPLE,
            "sample.bin",
            1,
        );
        let project_dir = manager.project_dir(SHA_SAMPLE);
        std::fs::write(project_dir.join("sample.gpr"), b"gpr").unwrap();
        let idata = project_dir.join("sample.rep").join("idata");
        std::fs::create_dir_all(&idata).unwrap();
        std::fs::write(
            idata.join("~index.dat"),
            "VERSION=1\n  00000001:sample.bin.0:c0a823e5601235220094043875\n",
        )
        .unwrap();

        let scripts = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join("probe.java"), b"// probe").unwrap();

        let args_path = tmp.path().join("args.txt");
        let analyze = tmp.path().join("analyzeHeadless");
        write_executable(
            &analyze,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nlast=\nfor arg in \"$@\"; do last=\"$arg\"; done\nprintf '{{\"ok\":true}}' > \"$last\"\n",
                args_path.display()
            ),
        );

        let product = execute_warm_path(WarmPathRequest {
            manager: manager.as_ref(),
            analyze_headless: &analyze,
            scripts_dir: &scripts,
            timeout: std::time::Duration::from_secs(5),
            binary_query: "sample.bin",
            script_name: "probe.java",
            output_prefix: "probe",
            output_key: "all",
            extra_script_args: vec![],
        })
        .await
        .unwrap();

        assert_eq!(product.program_name, "sample.bin");
        assert_eq!(product.bytes, br#"{"ok":true}"#);

        let args = std::fs::read_to_string(args_path).unwrap();
        assert!(args.contains("\n-process\nsample.bin.0\n-noanalysis\n"), "{args}");
    });
}
