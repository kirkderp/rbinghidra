use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::decompiler_slice::{
    DECOMPILER_SLICE_SCHEMA, DecompilerSliceContext, DecompilerSliceError, DecompilerSliceResult,
    DecompilerSliceSeed, get_decompiler_slice,
};
use rbm_ghidra::pcode::{PcodeOp, PcodeVarnode};
use rbm_ghidra::project::{DECOMPILER_SLICE_SCRIPT, ProjectManager};

mod common;
use common::{make_manager, make_runtime, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn make_ctx(
    tmp: &tempfile::TempDir,
    manager: Arc<ProjectManager>,
    analyze_headless: PathBuf,
) -> DecompilerSliceContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(DECOMPILER_SLICE_SCRIPT), b"// stub").unwrap();
    DecompilerSliceContext {
        manager,
        analyze_headless,
        scripts_dir: scripts,
        timeout: Duration::from_secs(5),
    }
}

fn touch_gpr(manager: &ProjectManager, sha256: &str, program_name: &str) {
    let dir = manager.project_dir(sha256);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{program_name}.gpr")), b"gpr").unwrap();
}

fn fake_decompiler_slice_analyze_headless(path: &Path, payload: &str) {
    let script = format!(
        "#!/bin/sh\nout=\"\"\nprev=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"decompiler_slice.java\" ]; then\n    out=\"$arg\"\n    break\n  fi\n  prev=\"$arg\"\ndone\nprintf '%s' '{payload}' > \"$out\"\nexit 0\n"
    );
    write_executable(path, &script);
}

#[test]
fn decompiler_slice_schema_constant_is_stable() {
    assert_eq!(DECOMPILER_SLICE_SCHEMA, "rbm.ghidra.decompiler_slice.v0");
    assert_eq!(DECOMPILER_SLICE_SCRIPT, "decompiler_slice.java");
}

#[test]
fn decompiler_slice_result_serializes_to_stable_shape() {
    let result = DecompilerSliceResult {
        schema: DECOMPILER_SLICE_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: "rax".to_string(),
        direction: "both".to_string(),
        simplification_style: "decompile".to_string(),
        function_name: "main".to_string(),
        address: "0x1000".to_string(),
        seed: Some(DecompilerSliceSeed {
            match_kind: "output".to_string(),
            op_seq_num: "0x1000@0".to_string(),
            op_mnemonic: "COPY".to_string(),
            varnode: PcodeVarnode {
                space: "register".to_string(),
                offset: "0x0".to_string(),
                size: 8,
                is_register: true,
                name: "RAX".to_string(),
            },
        }),
        forward_op_count: 1,
        backward_op_count: 1,
        ops_returned: 1,
        ops_truncated: false,
        ops: vec![PcodeOp {
            seq_num: "0x1000@0".to_string(),
            mnemonic: "COPY".to_string(),
            output: None,
            inputs: vec![],
        }],
        basic_block_count: 1,
        decompile_completed: true,
        decompile_valid: true,
        is_timed_out: false,
        is_cancelled: false,
        failed_to_start: false,
        decompile_error: String::new(),
        resolution_error: String::new(),
        slice_error: String::new(),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], DECOMPILER_SLICE_SCHEMA);
    assert_eq!(json["seed"]["varnode"]["name"], "RAX");
    assert_eq!(json["ops"][0]["mnemonic"], "COPY");
    assert_eq!(json["ops_returned"], 1);
}

#[test]
fn get_decompiler_slice_validates_queries() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let analyze = tmp.path().join("fake_analyze_headless");
        write_executable(&analyze, "#!/bin/sh\nexit 0\n");
        let ctx = make_ctx(&tmp, mgr, analyze);

        let err = get_decompiler_slice(&ctx, "ls", "", "rax", None, None, 0)
            .await
            .unwrap_err();
        assert!(matches!(err, DecompilerSliceError::EmptyFunctionQuery));

        let err = get_decompiler_slice(&ctx, "ls", "main", "  ", None, None, 0)
            .await
            .unwrap_err();
        assert!(matches!(err, DecompilerSliceError::EmptySliceQuery));

        let err = get_decompiler_slice(&ctx, "ls", "main", "rax", Some("sideways"), None, 0)
            .await
            .unwrap_err();
        assert!(matches!(err, DecompilerSliceError::InvalidDirection { .. }));
    });
}

#[test]
fn get_decompiler_slice_spawns_runner_and_parses_envelope() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_analyze_headless");
        let payload = r#"{"schema":"rbm.ghidra.decompiler_slice.v0","query":"rax","direction":"forward","simplification_style":"normalize","function_name":"main","address":"0x1000","seed":{"match_kind":"output","op_seq_num":"0x1000@0","op_mnemonic":"COPY","varnode":{"space":"register","offset":"0x0","size":8,"is_register":true,"name":"RAX"}},"forward_op_count":1,"backward_op_count":0,"ops_returned":1,"ops_truncated":false,"ops":[{"seq_num":"0x1000@0","mnemonic":"COPY","output":null,"inputs":[]}],"basic_block_count":1,"decompile_completed":true,"decompile_valid":true,"is_timed_out":false,"is_cancelled":false,"failed_to_start":false,"decompile_error":"","resolution_error":"","slice_error":""}"#;
        fake_decompiler_slice_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result =
            get_decompiler_slice(&ctx, "ls", "main", "rax", Some("forward"), Some("normalize"), 7)
                .await
                .unwrap();

        assert_eq!(result.query, "rax");
        assert_eq!(result.direction, "forward");
        assert_eq!(result.simplification_style, "normalize");
        assert_eq!(result.function_name, "main");
        assert_eq!(result.forward_op_count, 1);
        assert_eq!(result.ops_returned, 1);
        assert_eq!(result.ops[0].mnemonic, "COPY");
        assert_eq!(result.seed.unwrap().varnode.name, "RAX");
    });
}
