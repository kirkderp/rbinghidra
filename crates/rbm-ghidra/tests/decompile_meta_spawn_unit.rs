#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rbm_core::CachePaths;
use rbm_ghidra::decompile_meta::{
    DECOMPILE_META_SCHEMA, DecompileMetaContext, DecompileMetaError, get_decompile_meta,
};
use rbm_ghidra::project::{DECOMPILE_META_SCRIPT, ProjectManager};
use tempfile::TempDir;

mod common;
use common::{make_runtime, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fake_decompile_meta_analyze_headless(path: &Path, payload: &str) {
    let script = format!(
        "#!/bin/sh\nout=\"\"\nprev=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"decompile_meta.java\" ]; then\n    out=\"$arg\"\n    break\n  fi\n  prev=\"$arg\"\ndone\nprintf '%s' '{payload}' > \"$out\"\nexit 0\n"
    );
    write_executable(path, &script);
}

fn make_ctx(
    tmp: &TempDir,
    manager: Arc<ProjectManager>,
    analyze_headless: PathBuf,
) -> DecompileMetaContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(DECOMPILE_META_SCRIPT), b"// stub").unwrap();
    DecompileMetaContext {
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
fn decompile_meta_schema_constant_has_expected_value() {
    assert_eq!(DECOMPILE_META_SCHEMA, "rbm.ghidra.decompile_meta.v0");
}

#[test]
fn decompile_meta_spawns_runner_parses_envelope_and_cleans_up() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));

        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_analyze_headless");
        let payload = r#"{"schema":"rbm.ghidra.decompile_meta.v0","query":"main","simplification_style":"decompile","token_limit":3,"function_name":"main","address":"0x100003a40","signature":"int main(int, char **)","decompiler_signature":"int main(int argc, char **argv)","source":"decompiler","parameter_count":1,"parameters":[{"name":"argc","ordinal":0,"data_type":"int","size":4,"storage":"EDI","storage_kind":"register","pc_address":"","is_name_locked":true,"is_type_locked":true,"is_this_pointer":false,"is_hidden_return":false}],"local_var_count":1,"local_vars":[{"name":"local_8","data_type":"undefined8","size":8,"storage":"Stack[-0x8]","first_use_offset":0,"storage_kind":"stack","pc_address":"0x100003a40","is_name_locked":true,"is_type_locked":false}],"line_count":2,"token_count":5,"tokens_truncated":true,"tokens_preview":[{"text":"int","token_class":"ClangTypeToken","syntax_type":4,"line_number":1,"line_token_index":0,"column_start":0,"column_end":3,"min_address":"","max_address":"","is_variable_ref":false,"high_variable_name":"","high_variable_data_type":"","high_variable_storage":"","high_variable_storage_kind":"","high_variable_pc_address":""},{"text":"argc","token_class":"ClangVariableToken","syntax_type":5,"line_number":1,"line_token_index":1,"column_start":4,"column_end":8,"min_address":"0x100003a40","max_address":"0x100003a40","is_variable_ref":true,"high_variable_name":"argc","high_variable_data_type":"int","high_variable_storage":"EDI","high_variable_storage_kind":"register","high_variable_pc_address":""}],"decompile_completed":true,"decompile_valid":true,"is_timed_out":false,"is_cancelled":false,"failed_to_start":false,"decompile_error":"","resolution_error":""}"#;
        fake_decompile_meta_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = get_decompile_meta(&ctx, "ls", "main", None, 3).await.unwrap();

        assert_eq!(result.schema, "rbm.ghidra.decompile_meta.v0");
        assert_eq!(result.cache_key, format!("sha256:{SHA_LS}"));
        assert_eq!(result.sha256, SHA_LS);
        assert_eq!(result.program_name, "ls");
        assert_eq!(result.function_name, "main");
        assert_eq!(result.address, "0x100003a40");
        assert_eq!(result.parameter_count, 1);
        assert_eq!(result.parameters[0].name, "argc");
        assert_eq!(result.local_var_count, 1);
        assert_eq!(result.local_vars[0].name, "local_8");
        assert_eq!(result.line_count, 2);
        assert_eq!(result.token_count, 5);
        assert_eq!(result.token_limit, 3);
        assert!(result.tokens_truncated);
        assert_eq!(result.tokens_preview.len(), 2);
        assert_eq!(result.tokens_preview[1].text, "argc");
        assert_eq!(result.tokens_preview[1].high_variable_storage_kind, "register");
        assert!(result.decompile_completed);
        assert!(result.decompile_valid);
        assert_eq!(result.decompile_error, "");

        let mut entries = tokio::fs::read_dir(mgr.project_dir(SHA_LS)).await.unwrap();
        let mut leftover = 0;
        while let Some(entry) = entries.next_entry().await.unwrap() {
            if let Some(name) = entry.file_name().to_str()
                && name.starts_with("decompile_meta_")
                && common::has_json_extension(name)
            {
                leftover += 1;
            }
        }
        assert_eq!(leftover, 0, "cleanup should remove per-call output");
    });
}

#[test]
fn decompile_meta_rejects_empty_query() {
    let rt = make_runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let cache = CachePaths::new(tmp.path().join("cache"));
        let mgr = Arc::new(ProjectManager::new(&cache));
        let analyze = tmp.path().join("fake_analyze_headless");
        fake_decompile_meta_analyze_headless(&analyze, "{}");
        let ctx = make_ctx(&tmp, mgr, analyze);
        let err = get_decompile_meta(&ctx, "ls", "   ", None, 0)
            .await
            .unwrap_err();
        assert!(matches!(err, DecompileMetaError::EmptyQuery), "{err:?}");
    });
}
