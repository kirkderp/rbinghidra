#![cfg(unix)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::anti_analysis::{
    ANTI_ANALYSIS_SCHEMA, AntiAnalysisContext, AntiAnalysisError, AntiAnalysisFinding,
    AntiAnalysisResult, AntiAnalysisSummary, scan_anti_analysis,
};
use rbm_ghidra::project::{ANTI_ANALYSIS_SCRIPT, PathValidationError, ProjectManager};
use rbm_ghidra::warm_path::WarmPathError;
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime};

fn make_anti_analysis_ctx(tmp: &TempDir, manager: Arc<ProjectManager>) -> AntiAnalysisContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(ANTI_ANALYSIS_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    AntiAnalysisContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_millis(100),
    }
}

#[test]
fn anti_analysis_schema_constant_pinned() {
    assert_eq!(ANTI_ANALYSIS_SCHEMA, "rbm.ghidra.anti_analysis.v0");
}

#[test]
fn anti_analysis_result_serializes_to_stable_shape() {
    let result = AntiAnalysisResult {
        schema: ANTI_ANALYSIS_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "test".to_string(),
        total_findings: 1,
        summary: AntiAnalysisSummary {
            by_category: HashMap::from([("Anti-Debugging".to_string(), 1)]),
            by_severity: HashMap::from([("High".to_string(), 1)]),
        },
        findings: vec![
            serde_json::to_value(AntiAnalysisFinding {
                category: "Anti-Debugging".to_string(),
                technique: "ptrace".to_string(),
                address: "0x1234".to_string(),
                function: "main".to_string(),
                severity: "High".to_string(),
                instruction: "CALL ptrace".to_string(),
            })
            .unwrap(),
        ],
    };

    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], "rbm.ghidra.anti_analysis.v0");
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "test");
    assert_eq!(json["total_findings"], 1);
    assert_eq!(json["summary"]["by_category"]["Anti-Debugging"], 1);
    assert_eq!(json["summary"]["by_severity"]["High"], 1);
    assert_eq!(json["findings"][0]["category"], "Anti-Debugging");
    assert_eq!(json["findings"][0]["technique"], "ptrace");
    assert_eq!(json["findings"][0]["address"], "0x1234");
    assert_eq!(json["findings"][0]["function"], "main");
    assert_eq!(json["findings"][0]["severity"], "High");
    assert_eq!(json["findings"][0]["instruction"], "CALL ptrace");
}

#[test]
fn warm_path_error_flattens_into_anti_analysis_error() {
    let e: AntiAnalysisError = WarmPathError::LockHeld {
        sha256: "abc".to_string(),
    }
    .into();
    match e {
        AntiAnalysisError::LockHeld { sha256 } => assert_eq!(sha256, "abc"),
        other => panic!("expected LockHeld, got {other:?}"),
    }

    let e: AntiAnalysisError = WarmPathError::ProjectFileMissing(PathBuf::from("/tmp/proj")).into();
    assert!(
        matches!(e, AntiAnalysisError::ProjectFileMissing(_)),
        "{e:?}"
    );

    let e: AntiAnalysisError = WarmPathError::HeadlessFailed {
        exit_code: Some(7),
        stderr: "boom".to_string(),
    }
    .into();
    match e {
        AntiAnalysisError::HeadlessFailed { exit_code, stderr } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(stderr, "boom");
        }
        other => panic!("expected HeadlessFailed, got {other:?}"),
    }

    let e: AntiAnalysisError = WarmPathError::OutputMissing {
        stdout: "out".to_string(),
        stderr: "err".to_string(),
    }
    .into();
    match e {
        AntiAnalysisError::OutputMissing { stdout, stderr } => {
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "err");
        }
        other => panic!("expected OutputMissing, got {other:?}"),
    }

    let e: AntiAnalysisError = WarmPathError::Io {
        path: PathBuf::from("/tmp/proj"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    }
    .into();
    match e {
        AntiAnalysisError::Io { path, source } => {
            assert_eq!(path, PathBuf::from("/tmp/proj"));
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected AntiAnalysisError::Io, got {other:?}"),
    }
}

#[test]
fn scan_anti_analysis_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_anti_analysis_ctx(&tmp, mgr.clone());
        ctx.scripts_dir = tmp.path().join("does-not-exist");
        let err = scan_anti_analysis(&ctx, "ls").await.unwrap_err();
        assert!(
            matches!(
                err,
                AntiAnalysisError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn scan_anti_analysis_rejects_missing_anti_analysis_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_anti_analysis_ctx(&tmp, mgr.clone());
        let scripts = tmp.path().join("scripts-empty");
        std::fs::create_dir_all(&scripts).unwrap();
        ctx.scripts_dir = scripts;
        let err = scan_anti_analysis(&ctx, "ls").await.unwrap_err();
        match err {
            AntiAnalysisError::PathValidation(PathValidationError::ScriptMissing {
                script,
                ..
            }) => {
                assert_eq!(script, ANTI_ANALYSIS_SCRIPT);
            }
            other => panic!("expected PathValidation::ScriptMissing, got {other:?}"),
        }
    });
}

#[test]
fn scan_anti_analysis_rejects_missing_analyze_headless() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_anti_analysis_ctx(&tmp, mgr.clone());
        ctx.analyze_headless = tmp.path().join("does-not-exist");
        let err = scan_anti_analysis(&ctx, "ls").await.unwrap_err();
        assert!(
            matches!(
                err,
                AntiAnalysisError::PathValidation(PathValidationError::AnalyzeHeadlessMissing(_))
            ),
            "{err:?}"
        );
    });
}
