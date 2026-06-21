use rbinghidra::equates::{EQUATES_SCHEMA, EquateEntry, EquateReference, EquatesResult};

#[test]
fn schema_constant_value() {
    assert_eq!(EQUATES_SCHEMA, "rbm.ghidra.equates.v0");
}

#[test]
fn result_deserializes_from_mock_json() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.equates.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "query": "ERROR",
        "offset": 0,
        "limit": 100,
        "total_matched": 2,
        "truncated": false,
        "equates": [
            {
                "name": "ERROR_SUCCESS",
                "value_hex": "0x0",
                "value_dec": 0,
                "display_name": "ERROR_SUCCESS",
                "reference_count": 5,
                "references": [
                    { "address": "100003a40", "op_index": 0 },
                    { "address": "100003b20", "op_index": 1 }
                ]
            },
            {
                "name": "ERROR_FILE_NOT_FOUND",
                "value_hex": "0x2",
                "value_dec": 2,
                "display_name": "ERROR_FILE_NOT_FOUND",
                "reference_count": 1,
                "references": [
                    { "address": "100003c10", "op_index": 0 }
                ]
            }
        ]
    });
    let result: EquatesResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.equates.v0");
    assert_eq!(result.query, "ERROR");
    assert_eq!(result.total_matched, 2);
    assert_eq!(result.equates.len(), 2);

    let first = &result.equates[0];
    assert_eq!(first.name, "ERROR_SUCCESS");
    assert_eq!(first.value_hex, "0x0");
    assert_eq!(first.value_dec, 0);
    assert_eq!(first.reference_count, 5);
    assert_eq!(first.references.len(), 2);
    assert_eq!(first.references[0].address, "100003a40");
    assert_eq!(first.references[0].op_index, 0);
}

#[test]
fn entry_with_no_references_deserializes_correctly() {
    let json = serde_json::json!({
        "name": "STATUS_OK",
        "value_hex": "0x0",
        "value_dec": 0,
        "display_name": "STATUS_OK",
        "reference_count": 0,
        "references": []
    });
    let entry: EquateEntry = serde_json::from_value(json).unwrap();
    assert_eq!(entry.name, "STATUS_OK");
    assert_eq!(entry.value_dec, 0);
    assert!(entry.references.is_empty());
    assert_eq!(entry.reference_count, 0);
}

#[test]
fn reference_serializes_to_stable_shape() {
    let r = EquateReference {
        address: "100003a40".to_string(),
        op_index: 2,
    };
    let value = serde_json::to_value(&r).unwrap();
    assert_eq!(value["address"], "100003a40");
    assert_eq!(value["op_index"], 2);
}

#[test]
fn negative_value_dec_roundtrips() {
    let json = serde_json::json!({
        "name": "MINUS_ONE",
        "value_hex": "0xffffffffffffffff",
        "value_dec": -1_i64,
        "display_name": "MINUS_ONE",
        "reference_count": 0,
        "references": []
    });
    let entry: EquateEntry = serde_json::from_value(json).unwrap();
    assert_eq!(entry.value_dec, -1);
    let re = serde_json::to_value(&entry).unwrap();
    assert_eq!(re["value_dec"], -1);
}

#[test]
fn empty_equates_array_deserializes_correctly() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.equates.v0",
        "cache_key": "sha256:000000",
        "sha256": "000000",
        "program_name": "test",
        "query": "",
        "offset": 0,
        "limit": 100,
        "total_matched": 0,
        "truncated": false,
        "equates": []
    });
    let result: EquatesResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.total_matched, 0);
    assert!(result.equates.is_empty());
}
