#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rbm_core::CachePaths;
use rbm_ghidra::decompiler_cfg::DecompilerCfgError;
use rbm_ghidra::function_slices::{
    FunctionSlicesContext, FunctionSlicesOptions, get_function_slices,
};
use rbm_ghidra::project::{FUNCTION_SLICES_SCRIPT, ProjectManager};
use tempfile::TempDir;

mod common;
use common::{make_runtime, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fake_analyze_headless(path: &Path, payload: &str) {
    let script = format!(
        "#!/bin/sh\nout=\"\"\nprev=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"function_slices.java\" ]; then\n    out=\"$arg\"\n    break\n  fi\n  prev=\"$arg\"\ndone\nprintf '%s' '{payload}' > \"$out\"\nexit 0\n"
    );
    write_executable(path, &script);
}

fn make_ctx(
    tmp: &TempDir,
    manager: Arc<ProjectManager>,
    analyze_headless: PathBuf,
) -> FunctionSlicesContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(FUNCTION_SLICES_SCRIPT), b"// stub").unwrap();
    FunctionSlicesContext {
        manager,
        analyze_headless,
        scripts_dir: scripts,
        timeout: Duration::from_secs(10),
    }
}

fn touch_gpr(manager: &ProjectManager, sha: &str, project_name: &str) {
    let dir = manager.project_dir(sha);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{project_name}.gpr")), b"").unwrap();
}

#[test]
fn get_function_slices_spawns_runner_and_injects_cache_metadata() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_analyze_headless");
        let payload = r#"{"schema":"rbm.ghidra.function_slices.v0","mode":"callsites","query":"Crypt","function_query":"main","range_start":"","range_end":"","limit":50,"resolved_address":"100003a40","resolved_function_name":"Global::main","instruction_count":12,"callsite_count":1,"field_reference_count":0,"local_buffer_count":0,"indirect_jump_count":0,"callsites":[{"address":"100003a50","disassembly":"CALL CryptDecrypt","target_name":"CryptDecrypt","target_address":"180012340","stack_args":[{"index":0,"address":"100003a4c","disassembly":"PUSH EAX","value":"EAX"}],"return_consumers":["100003a55: TEST EAX,EAX"],"context_before":["100003a4c: PUSH EAX"],"context_after":["100003a55: TEST EAX,EAX"]}],"field_references":[],"local_buffers":[],"indirect_jumps":[],"resolution_error":""}"#;
        fake_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = get_function_slices(
            &ctx,
            "ls",
            "main",
            FunctionSlicesOptions {
                mode: "callsites",
                query: "Crypt",
                range_start: "",
                range_end: "",
                limit: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(result["schema"], "rbm.ghidra.function_slices.v0");
        assert_eq!(result["mode"], "callsites");
        assert_eq!(result["cache_key"], format!("sha256:{SHA_LS}"));
        assert_eq!(result["program_name"], "ls");
        assert_eq!(result["callsite_count"], 1);
        assert_eq!(result["callsites"][0]["target_name"], "CryptDecrypt");
    });
}

#[test]
fn get_function_slices_rejects_invalid_mode() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));
        let analyze = tmp.path().join("fake_analyze_headless");
        fake_analyze_headless(&analyze, "{}");

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let err = get_function_slices(
            &ctx,
            "ls",
            "main",
            FunctionSlicesOptions {
                mode: "nope",
                query: "",
                range_start: "",
                range_end: "",
                limit: 50,
            },
        )
        .await
        .unwrap_err();

        match err {
            DecompilerCfgError::InvalidFunctionSlicesMode { mode } => assert_eq!(mode, "nope"),
            other => panic!("expected InvalidFunctionSlicesMode, got {other:?}"),
        }
    });
}
