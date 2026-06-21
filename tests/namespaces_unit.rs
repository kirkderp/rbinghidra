use rbinghidra::namespaces::{
    LIST_NAMESPACES_SCRIPT, NAMESPACES_SCHEMA, NamespacesError, NamespacesResult,
};

#[test]
fn namespaces_result_serializes_to_stable_shape() {
    let result = NamespacesResult {
        schema: NAMESPACES_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "test.exe".to_string(),
        total_namespaces: 2,
        namespaces: vec![
            serde_json::json!({
                "name": "std",
                "full_name": "std",
                "type": "namespace",
                "member_count": 45u64,
                "parent": ""
            }),
            serde_json::json!({
                "name": "MyClass",
                "full_name": "MyClass",
                "type": "class",
                "member_count": 8u64,
                "parent": ""
            }),
        ],
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], NAMESPACES_SCHEMA);
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "test.exe");
    assert_eq!(json["total_namespaces"], 2u64);
    assert_eq!(json["namespaces"].as_array().unwrap().len(), 2);
}

#[test]
fn namespaces_error_lock_held_message() {
    let err = NamespacesError::LockHeld {
        sha256: "abc".to_string(),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("abc"),
        "expected 'abc' in error message, got: {msg}"
    );
}

#[test]
fn list_namespaces_script_constant_pinned() {
    assert_eq!(LIST_NAMESPACES_SCRIPT, "list_namespaces.java");
}

#[test]
fn namespaces_schema_constant_pinned() {
    assert_eq!(NAMESPACES_SCHEMA, "rbm.ghidra.list_namespaces.v0");
}
