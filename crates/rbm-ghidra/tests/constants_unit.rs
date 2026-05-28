use rbm_ghidra::constants::{
    CONSTANTS_SCHEMA, ConstantEntry, ConstantLocation, ConstantsError, ConstantsResult,
    DEFAULT_LIMIT, MAX_LIMIT,
};
use rbm_ghidra::project::CONSTANTS_SCRIPT;
use std::path::PathBuf;

#[test]
fn constants_script_constant_is_java() {
    assert_eq!(CONSTANTS_SCRIPT, "constants.java");
}

#[test]
fn constants_schema_constant_pinned() {
    assert_eq!(CONSTANTS_SCHEMA, "rbm.ghidra.constants.v0");
}

#[test]
fn pagination_constants_pinned() {
    assert_eq!(DEFAULT_LIMIT, 100);
    assert_eq!(MAX_LIMIT, 1000);
}

#[test]
fn constant_entry_serializes_to_stable_shape() {
    let entry = ConstantEntry {
        value: "42".to_string(),
        hex_value: "0x2a".to_string(),
        count: 1,
        sample_locations: vec![ConstantLocation {
            address: "0x1000".to_string(),
            function_name: "main".to_string(),
            mnemonic: "MOV".to_string(),
            operand_index: 1,
            disassembly: "MOV RAX, 0x2a".to_string(),
        }],
    };
    let json = serde_json::to_value(&entry).unwrap();
    assert_eq!(json["value"], "42");
    assert_eq!(json["hex_value"], "0x2a");
    assert_eq!(json["count"], 1);
    assert_eq!(json["sample_locations"][0]["address"], "0x1000");
    assert_eq!(json["sample_locations"][0]["function_name"], "main");
    assert_eq!(json["sample_locations"][0]["mnemonic"], "MOV");
    assert_eq!(json["sample_locations"][0]["operand_index"], 1);
    assert_eq!(json["sample_locations"][0]["disassembly"], "MOV RAX, 0x2a");
}

#[test]
fn constants_result_serializes_to_stable_shape() {
    let result = ConstantsResult {
        schema: CONSTANTS_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        mode: "common".to_string(),
        value: String::new(),
        min_value: String::new(),
        max_value: String::new(),
        include_small_values: false,
        limit: 100,
        instructions_scanned: 1000,
        total_matched: 1,
        truncated: false,
        error_count: 0,
        constants: vec![ConstantEntry {
            value: "42".to_string(),
            hex_value: "0x2a".to_string(),
            count: 1,
            sample_locations: vec![],
        }],
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], CONSTANTS_SCHEMA);
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["mode"], "common");
    assert_eq!(json["value"], "");
    assert_eq!(json["min_value"], "");
    assert_eq!(json["max_value"], "");
    assert_eq!(json["include_small_values"], false);
    assert_eq!(json["limit"], 100);
    assert_eq!(json["instructions_scanned"], 1000);
    assert_eq!(json["total_matched"], 1);
    assert_eq!(json["truncated"], false);
    assert_eq!(json["error_count"], 0);
    assert_eq!(json["constants"][0]["value"], "42");
    assert_eq!(json["constants"][0]["hex_value"], "0x2a");
}

#[test]
fn warm_path_error_flattens_into_constants_error() {
    use rbm_ghidra::warm_path::WarmPathError;

    let e: ConstantsError = WarmPathError::LockHeld {
        sha256: "abc".to_string(),
    }
    .into();
    match e {
        ConstantsError::LockHeld { sha256 } => assert_eq!(sha256, "abc"),
        other => panic!("expected LockHeld, got {other:?}"),
    }

    let e: ConstantsError = WarmPathError::ProjectFileMissing(PathBuf::from("/tmp/proj")).into();
    assert!(matches!(e, ConstantsError::ProjectFileMissing(_)), "{e:?}");

    let e: ConstantsError = WarmPathError::HeadlessFailed {
        exit_code: Some(7),
        stderr: "boom".to_string(),
    }
    .into();
    match e {
        ConstantsError::HeadlessFailed { exit_code, stderr } => {
            assert_eq!(exit_code, Some(7));
            assert_eq!(stderr, "boom");
        }
        other => panic!("expected HeadlessFailed, got {other:?}"),
    }

    let e: ConstantsError = WarmPathError::OutputMissing {
        stdout: "out".to_string(),
        stderr: "err".to_string(),
    }
    .into();
    match e {
        ConstantsError::OutputMissing { stdout, stderr } => {
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "err");
        }
        other => panic!("expected OutputMissing, got {other:?}"),
    }

    let e: ConstantsError = WarmPathError::Io {
        path: PathBuf::from("/tmp/proj"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    }
    .into();
    match e {
        ConstantsError::Io { path, source } => {
            assert_eq!(path, PathBuf::from("/tmp/proj"));
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("expected ConstantsError::Io, got {other:?}"),
    }
}

#[test]
fn constants_error_invalid_mode_message() {
    let err = ConstantsError::InvalidMode("test".to_string());
    let msg = err.to_string();
    assert!(
        msg.contains("test"),
        "expected 'test' in error message, got: {msg}"
    );
}

#[test]
fn constants_error_lock_held_message() {
    let err = ConstantsError::LockHeld {
        sha256: "abc".to_string(),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("abc"),
        "expected 'abc' in error message, got: {msg}"
    );
}
