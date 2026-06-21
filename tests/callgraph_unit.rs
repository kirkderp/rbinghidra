#[path = "support/tempfile.rs"]
mod tempfile;

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use rbinghidra::callgraph::{
    CALLGRAPH_SCHEMA, CallGraphContext, CallGraphDirection, CallGraphEdge, CallGraphError,
    CallGraphNode, CallGraphResult, DEFAULT_DEPTH, DEFAULT_DIRECTION, DEFAULT_MAX_NODES, MAX_DEPTH,
    MAX_NODES_CAP, gen_callgraph, resolve_depth, resolve_direction, resolve_max_nodes,
};
use rbinghidra::inspect::InspectError;
use rbinghidra::project::{CALLGRAPH_SCRIPT, PathValidationError, ProjectManager};
use rbinghidra::warm_path::WarmPathError;
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime, write_envelope};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn make_callgraph_ctx(tmp: &TempDir, manager: Arc<ProjectManager>) -> CallGraphContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(CALLGRAPH_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    CallGraphContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_millis(100),
    }
}

#[test]
fn callgraph_script_constant_is_java() {
    assert_eq!(CALLGRAPH_SCRIPT, "callgraph.java");
}

#[test]
fn callgraph_schema_constant_pinned() {
    assert_eq!(CALLGRAPH_SCHEMA, "rbm.ghidra.callgraph.v0");
}

#[test]
fn callgraph_constants_pinned() {
    assert_eq!(DEFAULT_DEPTH, 0);
    assert_eq!(MAX_DEPTH, 10);
    assert_eq!(DEFAULT_MAX_NODES, 1000);
    assert_eq!(MAX_NODES_CAP, 1000);
    assert_eq!(DEFAULT_DIRECTION, CallGraphDirection::Calling);
}

#[test]
fn direction_display_matches_wire_form() {
    assert_eq!(CallGraphDirection::Calling.to_string(), "calling");
    assert_eq!(CallGraphDirection::Called.to_string(), "called");
    assert_eq!(CallGraphDirection::Calling.as_wire_str(), "calling");
    assert_eq!(CallGraphDirection::Called.as_wire_str(), "called");
}

#[test]
fn direction_from_str_accepts_both_and_ignores_case() {
    assert_eq!(
        CallGraphDirection::from_str("calling").unwrap(),
        CallGraphDirection::Calling
    );
    assert_eq!(
        CallGraphDirection::from_str("CALLED").unwrap(),
        CallGraphDirection::Called
    );
    assert_eq!(
        CallGraphDirection::from_str("  Calling  ").unwrap(),
        CallGraphDirection::Calling
    );
}

#[test]
fn direction_from_str_rejects_unknown_values() {
    let err = CallGraphDirection::from_str("outgoing").unwrap_err();
    match err {
        CallGraphError::InvalidDirection(raw) => assert_eq!(raw, "outgoing"),
        other => panic!("expected InvalidDirection, got {other:?}"),
    }
}

#[test]
fn resolve_direction_defaults_to_calling() {
    assert_eq!(
        resolve_direction(None).unwrap(),
        CallGraphDirection::Calling
    );
    assert_eq!(
        resolve_direction(Some("")).unwrap(),
        CallGraphDirection::Calling
    );
    assert_eq!(
        resolve_direction(Some("   ")).unwrap(),
        CallGraphDirection::Calling
    );
}

#[test]
fn resolve_direction_parses_valid_values() {
    assert_eq!(
        resolve_direction(Some("calling")).unwrap(),
        CallGraphDirection::Calling
    );
    assert_eq!(
        resolve_direction(Some("called")).unwrap(),
        CallGraphDirection::Called
    );
}

#[test]
fn resolve_direction_rejects_unknown() {
    let err = resolve_direction(Some("incoming")).unwrap_err();
    assert!(
        matches!(err, CallGraphError::InvalidDirection(_)),
        "{err:?}"
    );
}

#[test]
fn resolve_depth_defaults_and_clamps() {
    assert_eq!(resolve_depth(None), 0);
    assert_eq!(resolve_depth(Some(0)), 0);
    assert_eq!(resolve_depth(Some(3)), 3);
    assert_eq!(resolve_depth(Some(MAX_DEPTH)), MAX_DEPTH);
    assert_eq!(resolve_depth(Some(MAX_DEPTH + 1)), MAX_DEPTH);
    assert_eq!(resolve_depth(Some(u64::MAX)), MAX_DEPTH);
}

#[test]
fn resolve_max_nodes_defaults_and_clamps() {
    assert_eq!(resolve_max_nodes(None), DEFAULT_MAX_NODES);
    assert_eq!(resolve_max_nodes(Some(1)), 1);
    assert_eq!(resolve_max_nodes(Some(500)), 500);
    assert_eq!(resolve_max_nodes(Some(MAX_NODES_CAP)), MAX_NODES_CAP);
    assert_eq!(resolve_max_nodes(Some(MAX_NODES_CAP + 1)), MAX_NODES_CAP);
    assert_eq!(resolve_max_nodes(Some(u64::MAX)), MAX_NODES_CAP);
}

#[test]
fn resolve_max_nodes_zero_bumps_to_one() {
    assert_eq!(resolve_max_nodes(Some(0)), 1);
}

#[test]
fn gen_callgraph_rejects_empty_query() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_callgraph_ctx(&tmp, mgr.clone());
        let err = gen_callgraph(&ctx, "ls", "", None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, CallGraphError::EmptyQuery), "{err:?}");

        let err = gen_callgraph(&ctx, "ls", "   ", None, None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, CallGraphError::EmptyQuery), "{err:?}");
    });
}

#[test]
fn gen_callgraph_rejects_invalid_direction() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_callgraph_ctx(&tmp, mgr.clone());
        let err = gen_callgraph(&ctx, "ls", "main", Some("outgoing"), None, None)
            .await
            .unwrap_err();
        match err {
            CallGraphError::InvalidDirection(raw) => assert_eq!(raw, "outgoing"),
            other => panic!("expected InvalidDirection, got {other:?}"),
        }
    });
}

#[test]
fn warm_path_error_flattens_into_callgraph_error() {
    let e: CallGraphError = WarmPathError::LockHeld {
        sha256: "abc".to_string(),
    }
    .into();
    match e {
        CallGraphError::LockHeld { sha256 } => assert_eq!(sha256, "abc"),
        other => panic!("expected LockHeld, got {other:?}"),
    }

    let e: CallGraphError = WarmPathError::ProjectFileMissing(PathBuf::from("/tmp/proj")).into();
    assert!(matches!(e, CallGraphError::ProjectFileMissing(_)), "{e:?}");

    let e: CallGraphError = WarmPathError::HeadlessFailed {
        exit_code: Some(7),
        stderr: "boom".to_string(),
    }
    .into();
    match e {
        CallGraphError::HeadlessFailed { exit_code, stderr } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(stderr, "boom");
        }
        other => panic!("expected HeadlessFailed, got {other:?}"),
    }

    let e: CallGraphError = WarmPathError::OutputMissing {
        stdout: "out".to_string(),
        stderr: "err".to_string(),
    }
    .into();
    match e {
        CallGraphError::OutputMissing { stdout, stderr } => {
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "err");
        }
        other => panic!("expected OutputMissing, got {other:?}"),
    }

    let e: CallGraphError = WarmPathError::Io {
        path: PathBuf::from("/tmp/proj"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    }
    .into();
    match e {
        CallGraphError::Io { path, source } => {
            assert_eq!(path, PathBuf::from("/tmp/proj"));
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected CallGraphError::Io, got {other:?}"),
    }
}

#[test]
fn callgraph_result_serializes_to_stable_shape() {
    let result = CallGraphResult {
        schema: CALLGRAPH_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: "main".to_string(),
        direction: "calling".to_string(),
        depth: 0,
        resolved_address: "100003a40".to_string(),
        resolved_function_name: "Global::main".to_string(),
        truncated: false,
        node_count: 2,
        edge_count: 1,
        nodes: vec![
            CallGraphNode {
                address: "100003a40".to_string(),
                name: "main".to_string(),
            },
            CallGraphNode {
                address: "100003b20".to_string(),
                name: "helper".to_string(),
            },
        ],
        edges: vec![CallGraphEdge {
            from: "100003a40".to_string(),
            to: "100003b20".to_string(),
        }],
        mermaid: "graph LR\n  n0[\"main\"]\n  n1[\"helper\"]\n  n0 --> n1\n".to_string(),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], CALLGRAPH_SCHEMA);
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["query"], "main");
    assert_eq!(json["direction"], "calling");
    assert_eq!(json["depth"], 0);
    assert_eq!(json["resolved_address"], "100003a40");
    assert_eq!(json["resolved_function_name"], "Global::main");
    assert_eq!(json["truncated"], false);
    assert_eq!(json["node_count"], 2);
    assert_eq!(json["edge_count"], 1);
    assert_eq!(json["nodes"].as_array().unwrap().len(), 2);
    assert_eq!(json["nodes"][0]["address"], "100003a40");
    assert_eq!(json["nodes"][0]["name"], "main");
    assert_eq!(json["edges"].as_array().unwrap().len(), 1);
    assert_eq!(json["edges"][0]["from"], "100003a40");
    assert_eq!(json["edges"][0]["to"], "100003b20");
    assert!(json["mermaid"].as_str().unwrap().starts_with("graph LR"));
    assert_eq!(json.as_object().unwrap().len(), 15);
}

#[test]
fn gen_callgraph_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_callgraph_ctx(&tmp, mgr.clone());
        ctx.scripts_dir = tmp.path().join("does-not-exist");
        let err = gen_callgraph(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                CallGraphError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn gen_callgraph_rejects_missing_callgraph_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_callgraph_ctx(&tmp, mgr.clone());
        let scripts = tmp.path().join("scripts-empty");
        std::fs::create_dir_all(&scripts).unwrap();
        ctx.scripts_dir = scripts;
        let err = gen_callgraph(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        match err {
            CallGraphError::PathValidation(PathValidationError::ScriptMissing {
                script, ..
            }) => {
                assert_eq!(script, CALLGRAPH_SCRIPT);
            }
            other => panic!("expected PathValidation::ScriptMissing, got {other:?}"),
        }
    });
}

#[test]
fn gen_callgraph_rejects_missing_analyze_headless() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_callgraph_ctx(&tmp, mgr.clone());
        ctx.analyze_headless = tmp.path().join("does-not-exist");
        let err = gen_callgraph(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                CallGraphError::PathValidation(PathValidationError::AnalyzeHeadlessMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn gen_callgraph_returns_inspect_not_found_for_unknown_binary() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_callgraph_ctx(&tmp, mgr.clone());
        let err = gen_callgraph(&ctx, "missing", "main", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, CallGraphError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn gen_callgraph_propagates_ambiguous_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_callgraph_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "ls", 1);
        let err = gen_callgraph(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        match err {
            CallGraphError::Inspect(InspectError::Ambiguous { matches, .. }) => {
                assert_eq!(matches, 2);
            }
            other => panic!("expected Inspect(Ambiguous), got {other:?}"),
        }
    });
}

#[test]
fn gen_callgraph_returns_project_file_missing_when_gpr_absent() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_callgraph_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);
        let err = gen_callgraph(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, CallGraphError::ProjectFileMissing(_)),
            "{err:?}"
        );
    });
}

#[test]
fn gen_callgraph_returns_lock_held_when_lock_is_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_callgraph_ctx(&tmp, mgr.clone());
        write_envelope(&mgr, SHA_LS, "ls", 1);

        let lock = mgr.lock_for(SHA_LS);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let err = gen_callgraph(&ctx, "ls", "main", None, None, None)
            .await
            .unwrap_err();
        match err {
            CallGraphError::LockHeld { sha256 } => assert_eq!(sha256, SHA_LS),
            other => panic!("expected LockHeld, got {other:?}"),
        }
    });
}
