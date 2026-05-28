use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::context_api_slots::{
    CONTEXT_API_SLOTS_SCHEMA, ContextApiSlotsContext, ContextApiSlotsOptions, get_context_api_slots,
};
use rbm_ghidra::decompiler_cfg::DecompilerCfgError;
use rbm_ghidra::inspect::InspectError;
use rbm_ghidra::project::{CONTEXT_API_SLOTS_SCRIPT, PathValidationError, ProjectManager};
use tempfile::TempDir;

mod common;
use common::{make_manager, make_runtime, write_envelope};
use serde_json::json;

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn make_context_api_slots_ctx(
    tmp: &TempDir,
    manager: Arc<ProjectManager>,
    mock_output: Option<&serde_json::Value>,
) -> ContextApiSlotsContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(CONTEXT_API_SLOTS_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");

    // Create a mock script that writes a predefined JSON output or a valid JSON object
    let json_output = mock_output.map_or_else(|| "{}".to_string(), |val| serde_json::to_string(val).unwrap());

    let mock_script = format!(
        r#"#!/bin/bash
# Mock analyzeHeadless to write JSON to the expected output path
for i in "$@"; do
    if [[ $i == *".json" ]]; then
        echo '{json_output}' > "$i"
    fi
done
"#
    );
    std::fs::write(&analyze, mock_script).unwrap();

    #[cfg(unix)]
    std::fs::set_permissions(
        &analyze,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();

    ContextApiSlotsContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_millis(100),
    }
}

fn touch_gpr(manager: &ProjectManager, sha: &str, project_name: &str) {
    let dir = manager.project_dir(sha);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{project_name}.gpr")), b"").unwrap();
}

const fn default_options() -> ContextApiSlotsOptions<'static> {
    ContextApiSlotsOptions {
        target_function: "target",
        init_function: "init",
        export_resolver: "export",
        module_resolver: "module",
        context_stack_offset: "offset",
        limit: 0,
    }
}

#[test]
fn context_api_slots_script_constant_is_java() {
    assert_eq!(CONTEXT_API_SLOTS_SCRIPT, "context_api_slots.java");
}

#[test]
fn context_api_slots_schema_constant_pinned() {
    assert_eq!(CONTEXT_API_SLOTS_SCHEMA, "rbm.ghidra.context_api_slots.v0");
}

#[test]
fn get_context_api_slots_rejects_missing_scripts_dir() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_context_api_slots_ctx(&tmp, mgr.clone(), None);
        ctx.scripts_dir = tmp.path().join("does-not-exist");
        let err = get_context_api_slots(&ctx, "ls", default_options())
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                DecompilerCfgError::PathValidation(PathValidationError::ScriptsDirMissing(_))
            ),
            "{err:?}"
        );
    });
}

#[test]
fn get_context_api_slots_rejects_missing_script() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mut ctx = make_context_api_slots_ctx(&tmp, mgr.clone(), None);
        let scripts = tmp.path().join("scripts-empty");
        std::fs::create_dir_all(&scripts).unwrap();
        ctx.scripts_dir = scripts;
        let err = get_context_api_slots(&ctx, "ls", default_options())
            .await
            .unwrap_err();
        match err {
            DecompilerCfgError::PathValidation(PathValidationError::ScriptMissing {
                script,
                ..
            }) => {
                assert_eq!(script, CONTEXT_API_SLOTS_SCRIPT);
            }
            other => panic!("expected PathValidation::ScriptMissing, got {other:?}"),
        }
    });
}

#[test]
fn get_context_api_slots_returns_inspect_not_found_for_unknown_binary() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_context_api_slots_ctx(&tmp, mgr.clone(), None);
        let err = get_context_api_slots(&ctx, "missing", default_options())
            .await
            .unwrap_err();
        assert!(
            matches!(err, DecompilerCfgError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn get_context_api_slots_propagates_ambiguous_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_context_api_slots_ctx(&tmp, mgr.clone(), None);
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "ls", 1);
        let err = get_context_api_slots(&ctx, "ls", default_options())
            .await
            .unwrap_err();
        match err {
            DecompilerCfgError::Inspect(InspectError::Ambiguous { matches, .. }) => {
                assert_eq!(matches, 2);
            }
            other => panic!("expected Inspect(Ambiguous), got {other:?}"),
        }
    });
}

#[test]
fn get_context_api_slots_returns_lock_held_when_lock_is_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_context_api_slots_ctx(&tmp, mgr.clone(), None);
        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let lock = mgr.lock_for(SHA_LS);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let err = get_context_api_slots(&ctx, "ls", default_options())
            .await
            .unwrap_err();
        match err {
            DecompilerCfgError::LockHeld { sha256 } => assert_eq!(sha256, SHA_LS),
            other => panic!("expected LockHeld, got {other:?}"),
        }
    });
}

#[test]
fn get_context_api_slots_adds_metadata_to_response() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mock_val = json!({"dummy": "value"});
        let ctx = make_context_api_slots_ctx(&tmp, mgr.clone(), Some(&mock_val));
        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let res = get_context_api_slots(&ctx, "ls", default_options())
            .await
            .unwrap();

        assert_eq!(res["dummy"], "value");
        assert_eq!(res["sha256"], SHA_LS);
        assert_eq!(res["program_name"], "ls");
        assert!(res["cache_key"].as_str().unwrap().starts_with("sha256:"));
    });
}

#[test]
fn get_context_api_slots_handles_resolution_error() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let mock_val = json!({"resolution_error": "failed to resolve function target"});
        let ctx = make_context_api_slots_ctx(&tmp, mgr.clone(), Some(&mock_val));
        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let err = get_context_api_slots(&ctx, "ls", default_options())
            .await
            .unwrap_err();
        match err {
            DecompilerCfgError::ResolutionFailed(msg) => {
                assert_eq!(msg, "failed to resolve function target");
            }
            other => panic!("expected ResolutionFailed, got {other:?}"),
        }
    });
}

#[test]
fn get_context_api_slots_handles_limit_options() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();

        let scripts = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join(CONTEXT_API_SLOTS_SCRIPT), b"// stub").unwrap();
        let analyze = tmp.path().join("analyzeHeadless");

        let mock_script = r#"#!/bin/bash
# Mock analyzeHeadless to write JSON to the expected output path containing the script args
for i in "$@"; do
    if [[ $i == *".json" ]]; then
        # $16 is the limit arg in the argument list we passed to execute_warm_path
        echo '{"limit_passed": "'"${16}"'"}' > "$i"
    fi
done
"#;
        std::fs::write(&analyze, mock_script).unwrap();

        #[cfg(unix)]
        std::fs::set_permissions(
            &analyze,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();

        let ctx = ContextApiSlotsContext {
            manager: mgr.clone(),
            analyze_headless: analyze,
            scripts_dir: scripts,
            timeout: Duration::from_millis(100),
        };

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        // Option with limit = 0
        let mut opts = default_options();
        opts.limit = 0;
        let res = get_context_api_slots(&ctx, "ls", opts).await.unwrap();
        assert_eq!(res["limit_passed"], "200");

        // Option with limit < 1000
        opts.limit = 500;
        let res2 = get_context_api_slots(&ctx, "ls", opts).await.unwrap();
        assert_eq!(res2["limit_passed"], "500");

        // Option with limit > 1000
        opts.limit = 2000;
        let res3 = get_context_api_slots(&ctx, "ls", opts).await.unwrap();
        assert_eq!(res3["limit_passed"], "1000");
    });
}
