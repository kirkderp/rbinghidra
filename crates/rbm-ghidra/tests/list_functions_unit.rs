use rbm_ghidra::inspect::InspectError;
use rbm_ghidra::list_functions::{
    DEFAULT_LIMIT, FunctionEntry, LIST_FUNCTIONS_SCHEMA, ListFunctionsResult, list_functions,
    resolve_limit, resolve_offset, resolve_query,
};
use rbm_ghidra::project::FUNCTIONS_OUTPUT_FILE;

mod common;
use common::{make_manager, make_runtime};

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn make_entry(name: &str, entry: &str, is_thunk: bool) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "entry": entry,
        "size": 64,
        "is_thunk": is_thunk,
        "is_external": false,
        "calling_convention": "__cdecl",
        "signature": format!("void {}(void)", name),
    })
}

fn write_functions_json(
    manager: &rbm_ghidra::project::ProjectManager,
    sha256: &str,
    program_name: &str,
    functions: &[serde_json::Value],
) {
    let dir = manager.project_dir(sha256);
    std::fs::create_dir_all(&dir).unwrap();
    let payload = serde_json::json!({
        "schema": "rbm.ghidra.extract_functions.v0",
        "program_name": program_name,
        "program_path": format!("/bin/{}", program_name),
        "function_count": functions.len(),
        "error_count": 0,
        "functions": functions,
    });
    std::fs::write(
        dir.join(FUNCTIONS_OUTPUT_FILE),
        serde_json::to_vec_pretty(&payload).unwrap(),
    )
    .unwrap();
}

#[test]
fn returns_all_functions_when_query_is_none() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        let fns = vec![
            make_entry("main", "0x100000000", false),
            make_entry("helper", "0x100000100", false),
            make_entry("__thunk_exit", "0x100000200", true),
        ];
        write_functions_json(&mgr, SHA_A, "testbin", &fns);

        let result = list_functions(&mgr, SHA_A, None, None, None).await.unwrap();

        assert_eq!(result.total_matched, 3);
        assert_eq!(result.functions.len(), 3);
        assert_eq!(result.query, ".*");
        assert_eq!(result.schema, LIST_FUNCTIONS_SCHEMA);
        assert_eq!(result.program_name, "testbin");
    });
}

#[test]
fn filters_by_name_substring_case_insensitive() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        let fns = vec![
            make_entry("MainDispatch", "0x100000000", false),
            make_entry("helper", "0x100000100", false),
            make_entry("GetMainHandle", "0x100000200", false),
        ];
        write_functions_json(&mgr, SHA_A, "testbin", &fns);

        let result = list_functions(&mgr, SHA_A, Some("main"), None, None)
            .await
            .unwrap();

        assert_eq!(result.total_matched, 2);
        assert_eq!(result.query, "main");
        let names: Vec<&str> = result.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"MainDispatch"));
        assert!(names.contains(&"GetMainHandle"));
        assert!(!names.contains(&"helper"));
    });
}

#[test]
fn pagination_offset_and_limit() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        let fns: Vec<serde_json::Value> = (0..10)
            .map(|i| {
                make_entry(
                    &format!("fn_{i:02}"),
                    &format!("0x{:08x}", i * 0x100),
                    false,
                )
            })
            .collect();
        write_functions_json(&mgr, SHA_A, "testbin", &fns);

        let result = list_functions(&mgr, SHA_A, None, Some(3), Some(4))
            .await
            .unwrap();

        assert_eq!(result.total_matched, 10);
        assert_eq!(result.offset, 3);
        assert_eq!(result.limit, 4);
        assert_eq!(result.functions.len(), 4);
        assert_eq!(result.functions[0].name, "fn_03");
        assert_eq!(result.functions[3].name, "fn_06");
    });
}

#[test]
fn result_serializes_to_stable_json_shape() {
    let result = ListFunctionsResult {
        schema: LIST_FUNCTIONS_SCHEMA.to_string(),
        cache_key: "sha256:aabb".to_string(),
        sha256: "aabb".to_string(),
        program_name: "ls".to_string(),
        query: ".*".to_string(),
        offset: 0,
        limit: DEFAULT_LIMIT,
        total_matched: 1,
        functions: vec![FunctionEntry {
            name: "main".to_string(),
            entry: "0x100003a40".to_string(),
            size: 124,
            is_thunk: false,
            is_external: false,
            calling_convention: "__cdecl".to_string(),
            signature: "int main(int argc, char ** argv)".to_string(),
        }],
    };

    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], LIST_FUNCTIONS_SCHEMA);
    assert_eq!(json["cache_key"], "sha256:aabb");
    assert_eq!(json["sha256"], "aabb");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["query"], ".*");
    assert_eq!(json["offset"], 0);
    assert_eq!(json["limit"], DEFAULT_LIMIT);
    assert_eq!(json["total_matched"], 1);
    assert_eq!(json["functions"][0]["name"], "main");
    assert_eq!(json["functions"][0]["entry"], "0x100003a40");
    assert_eq!(json["functions"][0]["size"], 124);
    assert_eq!(json["functions"][0]["is_thunk"], false);
    assert_eq!(json["functions"][0]["is_external"], false);
    assert_eq!(json["functions"][0]["calling_convention"], "__cdecl");
    assert_eq!(
        json["functions"][0]["signature"],
        "int main(int argc, char ** argv)"
    );
}

#[test]
fn returns_not_found_for_unknown_binary_query() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_functions_json(&mgr, SHA_A, "knownbin", &[]);

        let err = list_functions(&mgr, "unknownbin", None, None, None)
            .await
            .unwrap_err();

        assert!(
            matches!(
                err,
                rbm_ghidra::list_functions::ListFunctionsError::Inspect(InspectError::NotFound(_))
            ),
            "expected NotFound, got {err:?}"
        );
    });
}

#[test]
fn resolve_query_none_gives_wildcard() {
    assert_eq!(resolve_query(None), ".*");
}

#[test]
fn resolve_query_empty_gives_wildcard() {
    assert_eq!(resolve_query(Some("")), ".*");
}

#[test]
fn resolve_query_nonempty_passthrough() {
    assert_eq!(resolve_query(Some("main")), "main");
}

#[test]
fn resolve_offset_none_gives_default() {
    assert_eq!(resolve_offset(None), 0);
}

#[test]
fn resolve_limit_none_gives_default() {
    assert_eq!(resolve_limit(None), DEFAULT_LIMIT);
}

#[test]
fn resolve_limit_clamps_to_max() {
    assert_eq!(
        resolve_limit(Some(99999)),
        rbm_ghidra::list_functions::MAX_LIMIT
    );
}

#[test]
fn empty_query_string_returns_all_functions() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        let fns = vec![
            make_entry("alpha", "0x100000000", false),
            make_entry("beta", "0x100000100", false),
        ];
        write_functions_json(&mgr, SHA_B, "mybin", &fns);

        let result = list_functions(&mgr, SHA_B, Some(""), None, None)
            .await
            .unwrap();

        assert_eq!(result.total_matched, 2);
        assert_eq!(result.query, ".*");
    });
}

#[test]
fn offset_beyond_end_returns_empty_page() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        let fns = vec![make_entry("only_fn", "0x100000000", false)];
        write_functions_json(&mgr, SHA_A, "smallbin", &fns);

        let result = list_functions(&mgr, SHA_A, None, Some(100), Some(10))
            .await
            .unwrap();

        assert_eq!(result.total_matched, 1);
        assert_eq!(result.functions.len(), 0);
    });
}
