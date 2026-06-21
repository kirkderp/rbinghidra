#[path = "support/tempfile.rs"]
mod tempfile;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rbinghidra::ProjectManager;
use rbinghidra::pcode::{PcodeContext, PcodeError, get_pcode};

mod common;
use common::{make_manager, make_runtime, write_envelope, write_executable};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fake_pcode_analyze_headless(path: &Path, payload: &str) {
    let script = format!(
        "#!/bin/sh\nout=\"\"\nprev=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"pcode.java\" ]; then\n    out=\"$arg\"\n    break\n  fi\n  prev=\"$arg\"\ndone\nprintf '%s' '{payload}' > \"$out\"\nexit 0\n"
    );
    write_executable(path, &script);
}

fn fake_failing_analyze_headless(path: &Path) {
    write_executable(path, "#!/bin/sh\necho 'boom' >&2\nexit 7\n");
}

fn fake_silent_analyze_headless(path: &Path) {
    write_executable(path, "#!/bin/sh\nexit 0\n");
}

fn make_ctx(
    tmp: &tempfile::TempDir,
    manager: Arc<ProjectManager>,
    analyze_headless: PathBuf,
) -> PcodeContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join("pcode.java"), b"// stub").unwrap();
    PcodeContext {
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

#[test]
fn get_pcode_spawns_runner_parses_envelope_and_cleans_up() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_analyze_headless");
        let payload = r#"{"schema":"rbm.ghidra.pcode.v0","query":"main","simplification_style":"paramid","function_name":"main","address":"0x100003a40","op_count":1,"ops":[{"seq_num":"0x100003a40@0","mnemonic":"COPY","output":{"space":"register","offset":"0x0","size":8,"is_register":true,"name":"RAX"},"inputs":[]}],"basic_block_count":4,"decompile_completed":true,"decompile_valid":true,"is_timed_out":false,"is_cancelled":false,"failed_to_start":false,"decompile_error":"","resolution_error":""}"#;
        fake_pcode_analyze_headless(&analyze, payload);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let result = get_pcode(&ctx, "ls", "main", Some("paramid"))
            .await
            .unwrap();

        assert_eq!(result.query, "main");
        assert_eq!(result.simplification_style, "paramid");
        assert_eq!(result.function_name, "main");
        assert_eq!(result.address, "0x100003a40");
        assert_eq!(result.op_count, 1);
        assert_eq!(result.basic_block_count, 4);
        assert!(result.decompile_completed);
        assert!(result.decompile_valid);
        assert_eq!(result.ops.len(), 1);
        assert_eq!(result.ops[0].mnemonic, "COPY");
    });
}

#[test]
fn get_pcode_failing_runner_returns_headless_failed() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_failing_analyze_headless");
        fake_failing_analyze_headless(&analyze);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let err = get_pcode(&ctx, "ls", "main", None).await.unwrap_err();
        match err {
            PcodeError::HeadlessFailed { exit_code, stderr } => {
                assert_eq!(exit_code, Some(7));
                assert!(stderr.contains("boom"));
            }
            other => panic!("expected HeadlessFailed, got {other:?}"),
        }
    });
}

#[test]
fn get_pcode_returns_output_missing_when_runner_writes_nothing() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 1);
        touch_gpr(&mgr, SHA_LS, "ls");

        let analyze = tmp.path().join("fake_silent_analyze_headless");
        fake_silent_analyze_headless(&analyze);

        let ctx = make_ctx(&tmp, mgr.clone(), analyze);
        let err = get_pcode(&ctx, "ls", "main", None).await.unwrap_err();
        match err {
            PcodeError::OutputMissing { stdout, stderr: _ } => {
                assert!(stdout.is_empty());
            }
            other => panic!("expected OutputMissing, got {other:?}"),
        }
    });
}
