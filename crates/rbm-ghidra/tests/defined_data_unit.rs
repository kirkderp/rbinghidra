use rbm_ghidra::defined_data::{
    DEFAULT_QUERY, DEFINED_DATA_SCHEMA, DefinedDataEntry, DefinedDataResult, MAX_LIMIT,
    resolve_limit, resolve_query,
};

#[test]
fn resolve_query_returns_default_for_empty() {
    assert_eq!(resolve_query(None), DEFAULT_QUERY);
    assert_eq!(resolve_query(Some("")), DEFAULT_QUERY);
}

#[test]
fn resolve_query_returns_custom_when_non_empty() {
    assert_eq!(resolve_query(Some("ConfigStruct")), "ConfigStruct");
}

#[test]
fn resolve_limit_clamps_to_max() {
    assert_eq!(resolve_limit(Some(99_999)), MAX_LIMIT);
    assert_eq!(resolve_limit(Some(1_000)), MAX_LIMIT);
    assert_eq!(resolve_limit(Some(500)), 500);
}

#[test]
fn defined_data_entry_serializes_to_stable_shape() {
    let entry = DefinedDataEntry {
        address: "0x100004000".to_string(),
        label: "g_config".to_string(),
        data_type_name: "ConfigStruct".to_string(),
        size: 64,
        value: "ConfigStruct@100004000".to_string(),
        xref_count: 3,
        containing_function: String::new(),
    };
    let v = serde_json::to_value(&entry).unwrap();
    assert_eq!(v["address"], "0x100004000");
    assert_eq!(v["label"], "g_config");
    assert_eq!(v["data_type_name"], "ConfigStruct");
    assert_eq!(v["size"], 64u64);
    assert_eq!(v["value"], "ConfigStruct@100004000");
    assert_eq!(v["xref_count"], 3u64);
    assert_eq!(v["containing_function"], "");
}

#[test]
fn defined_data_result_serializes_to_stable_shape() {
    let entry = DefinedDataEntry {
        address: "0x100004000".to_string(),
        label: "g_config".to_string(),
        data_type_name: "ConfigStruct".to_string(),
        size: 64,
        value: "ConfigStruct@100004000".to_string(),
        xref_count: 3,
        containing_function: String::new(),
    };
    let result = DefinedDataResult {
        schema: DEFINED_DATA_SCHEMA.to_string(),
        cache_key: "sha256:abc123".to_string(),
        sha256: "abc123".to_string(),
        program_name: "sample.exe".to_string(),
        query: ".*".to_string(),
        offset: 0,
        limit: 25,
        total_matched: 1,
        truncated: false,
        error_count: 0,
        data: vec![entry],
    };
    let v = serde_json::to_value(&result).unwrap();
    assert_eq!(v["schema"], DEFINED_DATA_SCHEMA);
    assert_eq!(v["query"], ".*");
    assert_eq!(v["offset"], 0u64);
    assert_eq!(v["limit"], 25u64);
    assert_eq!(v["total_matched"], 1u64);
    assert_eq!(v["truncated"], false);
    assert_eq!(v["error_count"], 0u64);
    assert_eq!(v["data"].as_array().unwrap().len(), 1);
    assert_eq!(v["data"][0]["label"], "g_config");
}
