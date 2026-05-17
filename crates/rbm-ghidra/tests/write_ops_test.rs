use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rbm_ghidra::create_function::{
    CreateFunctionContext, CreateFunctionError, CreateFunctionResult,
    create_function as run_create_function,
};
use rbm_ghidra::create_label::{CreateLabelError, CreateLabelResult, create_label};
use rbm_ghidra::project::{
    CREATE_FUNCTION_SCRIPT, CREATE_LABEL_SCRIPT, RENAME_FUNCTION_SCRIPT, SET_COMMENT_SCRIPT,
    SET_PROTOTYPE_SCRIPT,
};
use rbm_ghidra::rename_function::{RenameContext, RenameError, RenameResult, rename_function};
use rbm_ghidra::set_comment::{SetCommentContext, SetCommentError, SetCommentResult, set_comment};
use rbm_ghidra::set_prototype::{SetPrototypeError, SetPrototypeResult, set_function_prototype};

mod common;
use common::{make_manager, make_runtime};

fn make_rename_ctx(
    tmp: &tempfile::TempDir,
    manager: Arc<rbm_ghidra::ProjectManager>,
) -> RenameContext {
    let scripts = tmp.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join(RENAME_FUNCTION_SCRIPT), b"// stub").unwrap();
    let analyze = tmp.path().join("analyzeHeadless");
    std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
    RenameContext {
        manager,
        analyze_headless: analyze,
        scripts_dir: scripts,
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn rename_result_deserializes_from_mock_envelope() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.rename_function.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "query": "main",
        "new_name": "entry_point",
        "old_name": "main",
        "function_name": "entry_point",
        "address": "0x100003a40",
        "resolution_error": "",
        "rename_error": ""
    });
    let result: RenameResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.rename_function.v0");
    assert_eq!(result.query, "main");
    assert_eq!(result.new_name, "entry_point");
    assert_eq!(result.old_name, "main");
    assert_eq!(result.function_name, "entry_point");
    assert_eq!(result.address, "0x100003a40");
    assert_eq!(result.resolution_error, "");
    assert_eq!(result.rename_error, "");
}

#[test]
fn set_prototype_result_deserializes_from_mock_envelope() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.set_function_prototype.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "query": "main",
        "prototype": "int main(int argc, char **argv)",
        "function_name": "main",
        "address": "0x100003a40",
        "applied_signature": "int main(int argc, char **argv)",
        "resolution_error": "",
        "prototype_error": ""
    });
    let result: SetPrototypeResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.set_function_prototype.v0");
    assert_eq!(result.prototype, "int main(int argc, char **argv)");
    assert_eq!(result.applied_signature, "int main(int argc, char **argv)");
    assert_eq!(result.resolution_error, "");
    assert_eq!(result.prototype_error, "");
}

#[test]
fn create_label_result_deserializes_from_mock_envelope() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.create_label.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "address": "0x100003a40",
        "label_name": "my_func_entry",
        "created_symbol": "my_func_entry",
        "address_error": "",
        "label_error": ""
    });
    let result: CreateLabelResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.create_label.v0");
    assert_eq!(result.address, "0x100003a40");
    assert_eq!(result.label_name, "my_func_entry");
    assert_eq!(result.created_symbol, "my_func_entry");
    assert_eq!(result.address_error, "");
    assert_eq!(result.label_error, "");
}

#[test]
fn create_function_result_deserializes_from_mock_envelope() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.create_function.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "loader.bin",
        "address": "0x45f000",
        "function_name": "dat_entry",
        "created_function": "dat_entry",
        "existing_function": "",
        "address_error": "",
        "function_error": ""
    });
    let result: CreateFunctionResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.create_function.v0");
    assert_eq!(result.address, "0x45f000");
    assert_eq!(result.function_name, "dat_entry");
    assert_eq!(result.created_function, "dat_entry");
    assert_eq!(result.existing_function, "");
    assert_eq!(result.address_error, "");
    assert_eq!(result.function_error, "");
}

#[test]
fn set_comment_result_deserializes_from_mock_envelope() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.set_comment.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "address": "0x100003a40",
        "comment_type": "PLATE",
        "comment": "This is the main entry point.",
        "address_error": "",
        "comment_error": ""
    });
    let result: SetCommentResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.set_comment.v0");
    assert_eq!(result.address, "0x100003a40");
    assert_eq!(result.comment_type, "PLATE");
    assert_eq!(result.comment, "This is the main entry point.");
    assert_eq!(result.address_error, "");
    assert_eq!(result.comment_error, "");
}

#[test]
fn rename_function_returns_empty_query_for_blank_address() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_rename_ctx(&tmp, mgr);
        let err = rename_function(&ctx, "ls", "   ", "new_name")
            .await
            .unwrap_err();
        assert!(matches!(err, RenameError::EmptyQuery), "{err:?}");
    });
}

#[test]
fn rename_function_returns_empty_new_name_for_blank_new_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let ctx = make_rename_ctx(&tmp, mgr);
        let err = rename_function(&ctx, "ls", "main", "   ")
            .await
            .unwrap_err();
        assert!(matches!(err, RenameError::EmptyNewName), "{err:?}");
    });
}

#[test]
fn script_constants_have_expected_filenames() {
    assert_eq!(RENAME_FUNCTION_SCRIPT, "rename_function.java");
    assert_eq!(SET_PROTOTYPE_SCRIPT, "set_function_prototype.java");
    assert_eq!(CREATE_LABEL_SCRIPT, "create_label.java");
    assert_eq!(CREATE_FUNCTION_SCRIPT, "create_function.java");
    assert_eq!(SET_COMMENT_SCRIPT, "set_comment.java");
}

#[test]
fn set_prototype_returns_empty_query_for_blank_address() {
    use rbm_ghidra::set_prototype::SetPrototypeContext;
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let scripts = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join(SET_PROTOTYPE_SCRIPT), b"// stub").unwrap();
        let analyze = tmp.path().join("analyzeHeadless");
        std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
        let ctx = SetPrototypeContext {
            manager: mgr,
            analyze_headless: analyze,
            scripts_dir: scripts,
            timeout: Duration::from_secs(5),
        };
        let err = set_function_prototype(&ctx, "ls", "   ", "int foo(void)")
            .await
            .unwrap_err();
        assert!(matches!(err, SetPrototypeError::EmptyQuery), "{err:?}");
    });
}

#[test]
fn set_prototype_returns_empty_prototype_for_blank_prototype() {
    use rbm_ghidra::set_prototype::SetPrototypeContext;
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let scripts = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join(SET_PROTOTYPE_SCRIPT), b"// stub").unwrap();
        let analyze = tmp.path().join("analyzeHeadless");
        std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
        let ctx = SetPrototypeContext {
            manager: mgr,
            analyze_headless: analyze,
            scripts_dir: scripts,
            timeout: Duration::from_secs(5),
        };
        let err = set_function_prototype(&ctx, "ls", "main", "   ")
            .await
            .unwrap_err();
        assert!(matches!(err, SetPrototypeError::EmptyPrototype), "{err:?}");
    });
}

#[test]
fn create_label_returns_empty_address_for_blank_address() {
    use rbm_ghidra::create_label::CreateLabelContext;
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let scripts = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join(CREATE_LABEL_SCRIPT), b"// stub").unwrap();
        let analyze = tmp.path().join("analyzeHeadless");
        std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
        let ctx = CreateLabelContext {
            manager: mgr,
            analyze_headless: analyze,
            scripts_dir: scripts,
            timeout: Duration::from_secs(5),
        };
        let err = create_label(&ctx, "ls", "   ", "my_label")
            .await
            .unwrap_err();
        assert!(matches!(err, CreateLabelError::EmptyAddress), "{err:?}");
    });
}

#[test]
fn create_function_returns_empty_address_for_blank_address() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let scripts = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join(CREATE_FUNCTION_SCRIPT), b"// stub").unwrap();
        let analyze = tmp.path().join("analyzeHeadless");
        std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
        let ctx = CreateFunctionContext {
            manager: mgr,
            analyze_headless: analyze,
            scripts_dir: scripts,
            timeout: Duration::from_secs(5),
        };
        let err = run_create_function(&ctx, "ls", "   ", "my_function")
            .await
            .unwrap_err();
        assert!(matches!(err, CreateFunctionError::EmptyAddress), "{err:?}");
    });
}

#[test]
fn create_function_returns_empty_name_for_blank_function_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let scripts = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join(CREATE_FUNCTION_SCRIPT), b"// stub").unwrap();
        let analyze = tmp.path().join("analyzeHeadless");
        std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
        let ctx = CreateFunctionContext {
            manager: mgr,
            analyze_headless: analyze,
            scripts_dir: scripts,
            timeout: Duration::from_secs(5),
        };
        let err = run_create_function(&ctx, "ls", "0x45f000", "   ")
            .await
            .unwrap_err();
        assert!(
            matches!(err, CreateFunctionError::EmptyFunctionName),
            "{err:?}"
        );
    });
}

#[test]
fn set_comment_returns_empty_address_for_blank_address() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let scripts = tmp.path().join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join(SET_COMMENT_SCRIPT), b"// stub").unwrap();
        let analyze = tmp.path().join("analyzeHeadless");
        std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
        let ctx = SetCommentContext {
            manager: mgr,
            analyze_headless: analyze,
            scripts_dir: scripts,
            timeout: Duration::from_secs(5),
        };
        let err = set_comment(&ctx, "ls", "   ", "some comment", "PLATE")
            .await
            .unwrap_err();
        assert!(matches!(err, SetCommentError::EmptyAddress), "{err:?}");
    });
}

#[test]
fn rename_result_serializes_to_stable_shape() {
    let result = RenameResult {
        schema: "rbm.ghidra.rename_function.v0".to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: "main".to_string(),
        new_name: "entry_point".to_string(),
        old_name: "main".to_string(),
        function_name: "entry_point".to_string(),
        address: "0x100003a40".to_string(),
        resolution_error: String::new(),
        rename_error: String::new(),
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], "rbm.ghidra.rename_function.v0");
    assert_eq!(json["new_name"], "entry_point");
    assert_eq!(json["old_name"], "main");
    assert_eq!(json["function_name"], "entry_point");
    assert_eq!(json["address"], "0x100003a40");
    assert_eq!(json["rename_error"], "");
}

#[test]
fn set_comment_normalizes_empty_type_to_plate() {
    let rt = make_runtime();
    rt.block_on(async {
        let (tmp, mgr) = make_manager();
        let scripts = tmp.path().join("scripts-sc");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join(SET_COMMENT_SCRIPT), b"// stub").unwrap();
        let analyze = tmp.path().join("analyzeHeadless-sc");
        std::fs::write(&analyze, b"#!/bin/sh\nexit 0\n").unwrap();
        let ctx = SetCommentContext {
            manager: mgr,
            analyze_headless: analyze,
            scripts_dir: scripts,
            timeout: Duration::from_secs(5),
        };
        let err = set_comment(&ctx, "ls", "   ", "text", "")
            .await
            .unwrap_err();
        assert!(matches!(err, SetCommentError::EmptyAddress), "{err:?}");
    });
}

#[test]
fn warm_path_error_flattens_into_rename_error() {
    use rbm_ghidra::warm_path::WarmPathError;
    let e: RenameError = WarmPathError::LockHeld {
        sha256: "abc".to_string(),
    }
    .into();
    match e {
        RenameError::LockHeld { sha256 } => assert_eq!(sha256, "abc"),
        other => panic!("expected LockHeld, got {other:?}"),
    }

    let e: RenameError = WarmPathError::ProjectFileMissing(PathBuf::from("/tmp/proj")).into();
    assert!(matches!(e, RenameError::ProjectFileMissing(_)), "{e:?}");

    let e: RenameError = WarmPathError::HeadlessFailed {
        exit_code: Some(7),
        stderr: "boom".to_string(),
    }
    .into();
    match e {
        RenameError::HeadlessFailed { exit_code, stderr } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(stderr, "boom");
        }
        other => panic!("expected HeadlessFailed, got {other:?}"),
    }
}
