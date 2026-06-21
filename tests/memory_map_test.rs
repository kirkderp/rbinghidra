use rbinghidra::memory_map::{MEMORY_MAP_SCHEMA, MemoryBlockEntry, MemoryMapResult};

#[test]
fn schema_constant_value() {
    assert_eq!(MEMORY_MAP_SCHEMA, "rbm.ghidra.memory_map.v0");
}

#[test]
fn result_deserializes_from_mock_json() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.memory_map.v0",
        "cache_key": "sha256:aabbcc",
        "sha256": "aabbcc",
        "program_name": "ls",
        "block_count": 2,
        "blocks": [
            {
                "name": ".text",
                "start": "100001000",
                "end": "100008fff",
                "size": 32768,
                "readable": true,
                "writable": false,
                "executable": true,
                "initialized": true,
                "is_external": false,
                "comment": "",
                "type": "DEFAULT"
            },
            {
                "name": ".data",
                "start": "100009000",
                "end": "10000afff",
                "size": 8192,
                "readable": true,
                "writable": true,
                "executable": false,
                "initialized": true,
                "is_external": false,
                "comment": "data segment",
                "type": "DEFAULT"
            }
        ]
    });
    let result: MemoryMapResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.schema, "rbm.ghidra.memory_map.v0");
    assert_eq!(result.cache_key, "sha256:aabbcc");
    assert_eq!(result.sha256, "aabbcc");
    assert_eq!(result.program_name, "ls");
    assert_eq!(result.block_count, 2);
    assert_eq!(result.blocks.len(), 2);

    let text = &result.blocks[0];
    assert_eq!(text.name, ".text");
    assert_eq!(text.start, "100001000");
    assert!(text.executable);
    assert!(!text.writable);
    assert_eq!(text.block_type, "DEFAULT");

    let data = &result.blocks[1];
    assert_eq!(data.name, ".data");
    assert!(data.writable);
    assert_eq!(data.comment, "data segment");
}

#[test]
fn block_type_field_serializes_as_type() {
    let block = MemoryBlockEntry {
        name: ".text".to_string(),
        start: "100001000".to_string(),
        end: "100008fff".to_string(),
        size: 32768,
        readable: true,
        writable: false,
        executable: true,
        initialized: true,
        is_external: false,
        comment: String::new(),
        block_type: "DEFAULT".to_string(),
    };
    let value = serde_json::to_value(&block).unwrap();
    assert_eq!(value["type"], "DEFAULT");
    assert!(
        value.get("block_type").is_none(),
        "block_type key must not appear in JSON"
    );
}

#[test]
fn block_type_field_deserializes_from_type_key() {
    let json = serde_json::json!({
        "name": "EXTERNAL",
        "start": "0",
        "end": "fff",
        "size": 4096,
        "readable": false,
        "writable": false,
        "executable": false,
        "initialized": false,
        "is_external": true,
        "comment": "",
        "type": "BIT_MAPPED"
    });
    let entry: MemoryBlockEntry = serde_json::from_value(json).unwrap();
    assert_eq!(entry.block_type, "BIT_MAPPED");
    assert!(entry.is_external);
}

#[test]
fn empty_blocks_array_deserializes_correctly() {
    let json = serde_json::json!({
        "schema": "rbm.ghidra.memory_map.v0",
        "cache_key": "sha256:000000",
        "sha256": "000000",
        "program_name": "empty",
        "block_count": 0,
        "blocks": []
    });
    let result: MemoryMapResult = serde_json::from_value(json).unwrap();
    assert_eq!(result.block_count, 0);
    assert!(result.blocks.is_empty());
}
