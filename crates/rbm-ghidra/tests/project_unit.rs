use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::import::{ImportContext, ImportError, ImportReport, import_binary};
use rbm_ghidra::project::{
    EXTRACT_FUNCTIONS_SCRIPT, FUNCTIONS_OUTPUT_FILE, HeadlessRunner, ImportSpec,
    PathValidationError, ProjectManager, build_import_argv, cache_key, hash_file, project_name_for,
    safe_ghidra_dir_for_headless, sanitize_project_name, stage_script_for_headless,
};
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime};

fn osstr(s: &str) -> OsString {
    OsString::from(s)
}

fn make_spec() -> ImportSpec {
    ImportSpec {
        project_dir: PathBuf::from("/tmp/proj"),
        project_name: "sample".to_string(),
        binary: PathBuf::from("/bin/ls"),
        loader: None,
        processor: None,
        cspec: None,
        loader_base_addr: None,
        script_dir: PathBuf::from("/scripts"),
        script_name: EXTRACT_FUNCTIONS_SCRIPT.to_string(),
        script_args: vec!["/tmp/proj/functions.json".to_string()],
    }
}

#[test]
fn extract_functions_script_constant_is_java() {
    assert_eq!(EXTRACT_FUNCTIONS_SCRIPT, "extract_functions.java");
}

fn touch(path: &std::path::Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

fn make_fake_ctx(tmp: &TempDir, manager: Arc<ProjectManager>) -> ImportContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(EXTRACT_FUNCTIONS_SCRIPT), b"").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    ImportContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn build_import_argv_emits_full_invocation_in_order() {
    let spec = make_spec();
    let argv = build_import_argv(&spec);
    assert_eq!(
        argv,
        vec![
            osstr("/tmp/proj"),
            osstr("sample"),
            osstr("-import"),
            osstr("/bin/ls"),
            osstr("-overwrite"),
            osstr("-scriptPath"),
            osstr("/scripts"),
            osstr("-postScript"),
            osstr("extract_functions.java"),
            osstr("/tmp/proj/functions.json"),
        ]
    );
}

#[test]
fn build_import_argv_appends_extra_script_args_in_order() {
    let mut spec = make_spec();
    spec.script_args = vec![
        "/tmp/out.json".to_string(),
        "extra1".to_string(),
        "extra2".to_string(),
    ];
    let argv = build_import_argv(&spec);
    let tail: Vec<&OsString> = argv.iter().rev().take(3).collect();
    assert_eq!(tail[0], &osstr("extra2"));
    assert_eq!(tail[1], &osstr("extra1"));
    assert_eq!(tail[2], &osstr("/tmp/out.json"));
}

#[test]
fn build_import_argv_includes_raw_loader_options_before_script_args() {
    let mut spec = make_spec();
    spec.loader = Some("BinaryLoader".to_string());
    spec.processor = Some("x86:LE:32:default".to_string());
    spec.cspec = Some("windows".to_string());
    spec.loader_base_addr = Some("0x0".to_string());

    let argv = build_import_argv(&spec);
    assert_eq!(
        argv,
        vec![
            osstr("/tmp/proj"),
            osstr("sample"),
            osstr("-import"),
            osstr("/bin/ls"),
            osstr("-overwrite"),
            osstr("-loader"),
            osstr("BinaryLoader"),
            osstr("-processor"),
            osstr("x86:LE:32:default"),
            osstr("-cspec"),
            osstr("windows"),
            osstr("-loader-baseAddr"),
            osstr("0x0"),
            osstr("-scriptPath"),
            osstr("/scripts"),
            osstr("-postScript"),
            osstr("extract_functions.java"),
            osstr("/tmp/proj/functions.json"),
        ]
    );
}

#[test]
fn stage_script_for_headless_copies_requested_script_to_runtime_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let source_scripts = tmp.path().join("source_scripts");
        let runtime_scripts = tmp.path().join("runtime_scripts");
        std::fs::create_dir_all(&source_scripts).unwrap();
        let source_path = source_scripts.join(EXTRACT_FUNCTIONS_SCRIPT);
        std::fs::write(&source_path, b"public class extract_functions {}").unwrap();

        let staged =
            stage_script_for_headless(&runtime_scripts, &source_scripts, EXTRACT_FUNCTIONS_SCRIPT)
                .await
                .unwrap();

        assert_eq!(staged, runtime_scripts.join(EXTRACT_FUNCTIONS_SCRIPT));
        assert_eq!(
            std::fs::read_to_string(&staged).unwrap(),
            "public class extract_functions {}"
        );
    });
}

#[test]
fn stage_script_for_headless_overwrites_existing_runtime_copy() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let source_scripts = tmp.path().join("source_scripts");
        let runtime_scripts = tmp.path().join("runtime_scripts");
        std::fs::create_dir_all(&source_scripts).unwrap();
        std::fs::create_dir_all(&runtime_scripts).unwrap();
        std::fs::write(
            source_scripts.join(EXTRACT_FUNCTIONS_SCRIPT),
            b"new payload",
        )
        .unwrap();
        std::fs::write(
            runtime_scripts.join(EXTRACT_FUNCTIONS_SCRIPT),
            b"old payload",
        )
        .unwrap();

        let staged =
            stage_script_for_headless(&runtime_scripts, &source_scripts, EXTRACT_FUNCTIONS_SCRIPT)
                .await
                .unwrap();

        assert_eq!(std::fs::read_to_string(staged).unwrap(), "new payload");
    });
}

#[test]
fn cache_key_prefixes_sha256() {
    assert_eq!(
        cache_key("deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe"),
        "sha256:deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe"
    );
}

#[test]
fn project_name_for_uses_file_stem() {
    assert_eq!(project_name_for(&PathBuf::from("/bin/ls")), "ls");
    assert_eq!(
        project_name_for(&PathBuf::from("/tmp/sample.exe")),
        "sample"
    );
}

#[test]
fn project_name_for_returns_empty_when_stem_missing() {
    assert_eq!(project_name_for(&PathBuf::from("/")), "");
}

#[test]
fn sanitize_project_name_strips_punctuation_keeps_safe_chars() {
    assert_eq!(
        sanitize_project_name("hello-world.bin_42"),
        "hello-world.bin_42"
    );
    assert_eq!(sanitize_project_name("evil; rm -rf"), "evil__rm_-rf");
    assert_eq!(sanitize_project_name(""), "");
    assert_eq!(sanitize_project_name(" "), "_");
}

#[test]
fn project_manager_paths_use_cache_layout() {
    let (tmp, mgr) = make_manager();
    let dir = mgr.project_dir("abc123");
    if tmp.path().components().any(|component| {
        matches!(component, std::path::Component::Normal(name) if name.to_str().is_some_and(|s| s.len() > 1 && s.starts_with('.')))
    }) {
        assert!(dir.to_string_lossy().contains("rbinghidra-ghidra"));
        assert!(
            !dir.components().any(|component| {
                matches!(component, std::path::Component::Normal(name) if name.to_str().is_some_and(|s| s.len() > 1 && s.starts_with('.')))
            }),
            "safe Ghidra path must not contain hidden components: {dir:?}"
        );
    } else {
        assert!(dir.starts_with(tmp.path().join("ghidra")));
    }
    assert!(dir.ends_with("abc123"));
    assert_eq!(mgr.output_path("abc123"), dir.join(FUNCTIONS_OUTPUT_FILE));
}

#[test]
fn safe_ghidra_dir_keeps_non_hidden_cache_paths() {
    let requested = PathBuf::from("/tmp/rbinghidra-cache/ghidra");
    assert_eq!(safe_ghidra_dir_for_headless(&requested), requested);
}

#[test]
fn safe_ghidra_dir_moves_hidden_cache_paths_to_non_hidden_base() {
    let requested = PathBuf::from("visible")
        .join(".cache")
        .join("rbinghidra")
        .join("ghidra");
    let safe = safe_ghidra_dir_for_headless(&requested);
    assert!(safe.starts_with(PathBuf::from("visible").join("rbinghidra-ghidra")));
    assert!(safe.ends_with("ghidra"));
    assert!(
        !safe.components().any(|component| {
            matches!(component, std::path::Component::Normal(name) if name.to_str().is_some_and(|s| s.len() > 1 && s.starts_with('.')))
        }),
        "safe Ghidra project path must not contain hidden components: {safe:?}"
    );
}

#[test]
fn project_manager_lock_for_returns_same_arc_per_key() {
    let (_tmp, mgr) = make_manager();
    let a = mgr.lock_for("abc");
    let b = mgr.lock_for("abc");
    let c = mgr.lock_for("def");
    assert!(Arc::ptr_eq(&a, &b));
    assert!(!Arc::ptr_eq(&a, &c));
    assert_eq!(mgr.lock_count(), 2);
}

#[test]
fn project_manager_lock_for_blocks_second_try_lock() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        let lock = mgr.lock_for("abc");
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("first lock should win");
        assert!(
            lock.try_lock_owned().is_err(),
            "second try_lock_owned must fail while held"
        );
    });
}

#[test]
fn hash_file_matches_known_sha256_for_inline_payload() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("payload.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let hex = hash_file(&path).await.unwrap();
        assert_eq!(
            hex,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    });
}

#[test]
fn hash_file_rejects_directory_paths() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let result = hash_file(tmp.path()).await;
        assert!(matches!(
            result,
            Err(rbm_ghidra::project::ProjectError::NotAFile(_))
        ));
    });
}

#[test]
fn import_report_serializes_to_stable_shape() {
    let report = ImportReport {
        status: "analyzing".to_string(),
        cache_key: "sha256:abc".to_string(),
        binary_name: "sample.bin".to_string(),
        project_dir: "/tmp/proj".to_string(),
        output_path: "/tmp/proj/functions.json".to_string(),
        eta_ms: None,
        started: true,
        next_action: "poll".to_string(),
        error: None,
    };
    let json: serde_json::Value = serde_json::to_value(&report).unwrap();
    assert_eq!(json["status"], "analyzing");
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["binary_name"], "sample.bin");
    assert_eq!(json["project_dir"], "/tmp/proj");
    assert_eq!(json["output_path"], "/tmp/proj/functions.json");
    assert!(json.get("eta_ms").is_none());
    assert_eq!(json["started"], true);
    assert_eq!(json["next_action"], "poll");
}

#[test]
fn import_binary_returns_ready_when_output_already_exists() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_fake_ctx(&tmp, mgr.clone());
        let bin = tmp.path().join("sample.bin");
        std::fs::write(&bin, b"hello world").unwrap();
        let sha256_hex =
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string();
        let output = mgr.output_path(&sha256_hex);
        touch(
            &output,
            "{\"schema\":\"rbm.ghidra.extract_functions.v0\",\"program_name\":\"sample.bin\",\"functions\":[]}",
        );

        let report = import_binary(&ctx, &bin).await.unwrap();
        assert_eq!(report.status, "ready");
        assert_eq!(report.cache_key, format!("sha256:{sha256_hex}"));
        assert_eq!(report.binary_name, "sample.bin");
        assert_eq!(report.eta_ms, None);
        assert!(!report.started);
        assert!(report.next_action.contains("Ghidra tools"));
        assert!(report.output_path.ends_with(FUNCTIONS_OUTPUT_FILE));
    });
}

#[test]
fn import_binary_returns_analyzing_without_starting_when_lock_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_fake_ctx(&tmp, mgr.clone());
        let bin = tmp.path().join("sample.bin");
        std::fs::write(&bin, b"hello world").unwrap();
        let sha256_hex =
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string();
        let lock = mgr.lock_for(&sha256_hex);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let report = import_binary(&ctx, &bin).await.unwrap();
        assert_eq!(report.status, "analyzing");
        assert!(!report.started, "lock was held, no new task should start");
        assert_eq!(report.eta_ms, None);
        assert!(report.next_action.contains("already running"));
    });
}

#[test]
fn import_binary_rejects_missing_binary() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_fake_ctx(&tmp, mgr.clone());
        let bogus = tmp.path().join("does-not-exist.bin");
        let err = import_binary(&ctx, &bogus).await.unwrap_err();
        assert!(matches!(err, ImportError::BinaryMissing(_)), "{err:?}");
    });
}

#[test]
fn import_binary_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_fake_ctx(&tmp, mgr.clone());
        ctx.scripts_dir = tmp.path().join("does-not-exist");
        let bin = tmp.path().join("sample.bin");
        std::fs::write(&bin, b"hello world").unwrap();
        let err = import_binary(&ctx, &bin).await.unwrap_err();
        assert!(
            matches!(
                err,
                ImportError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn import_binary_rejects_missing_extract_functions_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_fake_ctx(&tmp, mgr.clone());
        let scripts = tmp.path().join("scripts-empty");
        std::fs::create_dir_all(&scripts).unwrap();
        ctx.scripts_dir = scripts;
        let bin = tmp.path().join("sample.bin");
        std::fs::write(&bin, b"hello world").unwrap();
        let err = import_binary(&ctx, &bin).await.unwrap_err();
        assert!(
            matches!(
                err,
                ImportError::PathValidation(PathValidationError::ScriptMissing { .. })
            ),
            "{err:?}"
        );
    });
}

#[test]
fn import_binary_rejects_missing_analyze_headless() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_fake_ctx(&tmp, mgr.clone());
        ctx.analyze_headless = tmp.path().join("does-not-exist");
        let bin = tmp.path().join("sample.bin");
        std::fs::write(&bin, b"hello world").unwrap();
        let err = import_binary(&ctx, &bin).await.unwrap_err();
        assert!(
            matches!(
                err,
                ImportError::PathValidation(PathValidationError::AnalyzeHeadlessMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn import_binary_rejects_empty_path() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_fake_ctx(&tmp, mgr.clone());
        let err = import_binary(&ctx, &PathBuf::from("")).await.unwrap_err();
        assert!(matches!(err, ImportError::EmptyPath), "{err:?}");
    });
}

#[test]
fn headless_runner_struct_holds_clonable_config() {
    let runner = HeadlessRunner {
        analyze_headless: PathBuf::from("/opt/ghidra/support/analyzeHeadless"),
        timeout: Duration::from_secs(60),
    };
    let cloned = runner.clone();
    assert_eq!(cloned.analyze_headless, runner.analyze_headless);
    assert_eq!(cloned.timeout, runner.timeout);
}
