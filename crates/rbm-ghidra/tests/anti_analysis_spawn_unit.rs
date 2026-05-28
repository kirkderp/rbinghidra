#![cfg(unix)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rbm_core::CachePaths;
use rbm_ghidra::anti_analysis::{AntiAnalysisContext, AntiAnalysisError, scan_anti_analysis};
use rbm_ghidra::project::ProjectManager;
use tempfile::TempDir;

mod common;
use common::{make_runtime, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fake_anti_analysis_analyze_headless(path: &Path, payload: &str) {
    let script = format!(
        "#!/bin/sh\nout=\"\"\nfor arg in \"$@\"; do\n  case \"$arg\" in\n    *.json)\n      if [ -z \"$out\" ]; then\n        out=\"$arg\"\n      fi\n      ;;\n  esac\ndone\nprintf '%s' '{payload}' > \"$out\"\nexit 0\n"
    );
    write_executable(path, &script);
}

fn fake_failing_analyze_headless(path: &Path) {
    write_executable(
        path,
        "#!/bin/sh\necho 'simulated ghidra failure' >&2\nexit 9\n",
    );
}

#[test]
fn scan_anti_analysis_failing_runner_returns_headless_failed() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        let analyze_headless = tmp.path().join("analyzeHeadless");
        fake_failing_analyze_headless(&analyze_headless);

        let scripts_dir = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts_dir).unwrap();
        std::fs::write(
            scripts_dir.join(rbm_ghidra::project::ANTI_ANALYSIS_SCRIPT),
            b"",
        )
        .unwrap();

        let ctx = AntiAnalysisContext {
            manager: mgr.clone(),
            analyze_headless,
            scripts_dir,
            timeout: Duration::from_secs(5),
        };

        write_envelope(&mgr, SHA_LS, "ls", 1);
        std::fs::write(mgr.project_dir(SHA_LS).join("project.gpr"), "").unwrap();
        let err = scan_anti_analysis(&ctx, "ls").await.unwrap_err();

        match err {
            AntiAnalysisError::HeadlessFailed { exit_code, stderr } => {
                assert_eq!(exit_code, Some(9));
                assert!(stderr.contains("simulated ghidra failure"));
            }
            other => panic!("expected HeadlessFailed, got {other:?}"),
        }
    });
}

#[test]
fn scan_anti_analysis_returns_output_missing_when_runner_writes_nothing() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        let analyze_headless = tmp.path().join("analyzeHeadless");
        // write an executable that just exits 0 without writing any output to the path
        write_executable(&analyze_headless, "#!/bin/sh\nexit 0\n");

        let scripts_dir = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts_dir).unwrap();
        std::fs::write(
            scripts_dir.join(rbm_ghidra::project::ANTI_ANALYSIS_SCRIPT),
            b"",
        )
        .unwrap();

        let ctx = AntiAnalysisContext {
            manager: mgr.clone(),
            analyze_headless,
            scripts_dir,
            timeout: Duration::from_secs(5),
        };

        write_envelope(&mgr, SHA_LS, "ls", 1);
        std::fs::write(mgr.project_dir(SHA_LS).join("project.gpr"), "").unwrap();
        let err = scan_anti_analysis(&ctx, "ls").await.unwrap_err();

        match err {
            AntiAnalysisError::OutputMissing { .. } => {}
            other => panic!("expected OutputMissing, got {other:?}"),
        }
    });
}

#[test]
fn scan_anti_analysis_spawns_runner_parses_envelope_and_cleans_up() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        let analyze_headless = tmp.path().join("analyzeHeadless");
        let payload = r#"{
            "schema": "rbm.ghidra.anti_analysis.v0",
            "total_findings": 1,
            "summary": {
                "by_category": {"Anti-Debugging": 1},
                "by_severity": {"High": 1}
            },
            "findings": [{
                "category": "Anti-Debugging",
                "technique": "ptrace",
                "address": "0x1234",
                "function": "main",
                "severity": "High",
                "instruction": "CALL ptrace"
            }]
        }"#;
        fake_anti_analysis_analyze_headless(&analyze_headless, payload);

        let scripts_dir = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts_dir).unwrap();
        std::fs::write(
            scripts_dir.join(rbm_ghidra::project::ANTI_ANALYSIS_SCRIPT),
            b"",
        )
        .unwrap();

        let ctx = AntiAnalysisContext {
            manager: mgr.clone(),
            analyze_headless,
            scripts_dir,
            timeout: Duration::from_secs(5),
        };

        write_envelope(&mgr, SHA_LS, "ls", 1);
        std::fs::write(mgr.project_dir(SHA_LS).join("project.gpr"), "").unwrap();
        let out_dir = mgr.project_dir(SHA_LS).join("anti_analysis-all");
        assert!(!out_dir.exists(), "directory should not exist initially");

        let res = scan_anti_analysis(&ctx, "ls").await.unwrap();
        assert_eq!(res.total_findings, 1);
        assert_eq!(res.findings.len(), 1);

        assert!(
            !out_dir.exists(),
            "temporary output directory should have been cleaned up"
        );
    });
}

#[test]
fn scan_anti_analysis_propagates_parse_error_for_garbage_envelope() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        let analyze_headless = tmp.path().join("analyzeHeadless");
        fake_anti_analysis_analyze_headless(&analyze_headless, "{ garbage json");

        let scripts_dir = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts_dir).unwrap();
        std::fs::write(
            scripts_dir.join(rbm_ghidra::project::ANTI_ANALYSIS_SCRIPT),
            b"",
        )
        .unwrap();

        let ctx = AntiAnalysisContext {
            manager: mgr.clone(),
            analyze_headless,
            scripts_dir,
            timeout: Duration::from_secs(5),
        };

        write_envelope(&mgr, SHA_LS, "ls", 1);
        std::fs::write(mgr.project_dir(SHA_LS).join("project.gpr"), "").unwrap();

        let err = scan_anti_analysis(&ctx, "ls").await.unwrap_err();
        match err {
            AntiAnalysisError::Parse { .. } => {}
            other => panic!("expected Parse error, got {other:?}"),
        }
    });
}
