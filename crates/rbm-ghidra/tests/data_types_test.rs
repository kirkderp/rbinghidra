use rbm_ghidra::data_types::{DATA_TYPES_SCHEMA, DataTypeEntry, DataTypesResult};

#[test]
fn schema_constant_value() {
    assert_eq!(DATA_TYPES_SCHEMA, "rbm.ghidra.data_types.v0");
}

#[test]
fn result_deserializes_from_mock_json() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.data_types.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "query": "DWORD",
        "offset": 0,
        "limit": 100,
        "total_matched": 3,
        "truncated": false,
        "data_types": [
            {
                "name": "DWORD",
                "path": "/DWORD",
                "category": "/",
                "kind": "TypeDef",
                "size": 4,
                "description": "unsigned 32-bit integer"
            },
            {
                "name": "DWORD_PTR",
                "path": "/DWORD_PTR",
                "category": "/",
                "kind": "TypeDef",
                "size": 8,
                "description": ""
            },
            {
                "name": "DWORD64",
                "path": "/DWORD64",
                "category": "/",
                "kind": "TypeDef",
                "size": 8,
                "description": ""
            }
        ]
    });
    let result: DataTypesResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.data_types.v0");
    assert_eq!(result.query, "DWORD");
    assert_eq!(result.total_matched, 3);
    assert!(!result.truncated);
    assert_eq!(result.data_types.len(), 3);

    let first = &result.data_types[0];
    assert_eq!(first.name, "DWORD");
    assert_eq!(first.kind, "TypeDef");
    assert_eq!(first.size, 4);
    assert_eq!(first.description, "unsigned 32-bit integer");
}

#[test]
fn truncated_flag_true_when_results_exceeded() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.data_types.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "query": "",
        "offset": 0,
        "limit": 100,
        "total_matched": 1200,
        "truncated": true,
        "data_types": []
    });
    let result: DataTypesResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.total_matched, 1200);
    assert!(result.truncated);
    assert!(result.data_types.is_empty());
}

#[test]
fn entry_serializes_to_stable_shape() {
    let entry = DataTypeEntry {
        name: "HANDLE".to_string(),
        path: "/HANDLE".to_string(),
        category: "/".to_string(),
        kind: "TypeDef".to_string(),
        size: 8,
        description: "generic handle".to_string(),
    };
    let value = serde_json::to_value(&entry).unwrap();
    assert_eq!(value["name"], "HANDLE");
    assert_eq!(value["kind"], "TypeDef");
    assert_eq!(value["size"], 8);
    assert_eq!(value["description"], "generic handle");
}

#[test]
fn empty_query_deserializes_correctly() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.data_types.v0",
        "cache_key": "sha256:000000",
        "sha256": "000000",
        "program_name": "test",
        "query": "",
        "offset": 0,
        "limit": 100,
        "total_matched": 0,
        "truncated": false,
        "data_types": []
    });
    let result: DataTypesResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.query, "");
    assert_eq!(result.total_matched, 0);
    assert!(!result.truncated);
}
