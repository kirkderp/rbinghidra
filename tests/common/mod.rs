#![allow(unreachable_pub)]
// Shared integration-test helpers are compiled once per test target, so each
// target only uses a subset of this module.
#![allow(dead_code)]

use std::path::Path;
#[cfg(feature = "integration-ghidra")]
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "integration-ghidra")]
use std::time::{Duration, Instant};

use crate::tempfile::TempDir;
use rbinghidra::CachePaths;
use rbinghidra::decompiler_cfg::{
    DECOMPILER_CFG_SCHEMA, DecompilerCfgBlock, DecompilerCfgCallsite, DecompilerCfgConstant,
    DecompilerCfgEdge, DecompilerCfgExternalRef, DecompilerCfgMemoryAccess, DecompilerCfgOp,
    DecompilerCfgResult, DecompilerCfgStringRef,
};
#[cfg(feature = "integration-ghidra")]
use rbinghidra::import::{ImportContext, import_binary};
#[cfg(feature = "integration-ghidra")]
use rbinghidra::probe;
#[cfg(feature = "integration-ghidra")]
use rbinghidra::project::hash_file;
use rbinghidra::project::{FUNCTIONS_OUTPUT_FILE, ProjectManager};

#[cfg(unix)]
pub fn write_executable(path: &Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, contents).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

pub fn make_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

pub fn make_manager() -> (TempDir, Arc<ProjectManager>) {
    let tmp = TempDir::new().unwrap();
    let cache = CachePaths::new(tmp.path().to_path_buf());
    (tmp, Arc::new(ProjectManager::new(&cache)))
}

pub fn has_json_extension(name: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
}

pub fn write_envelope(
    manager: &ProjectManager,
    sha256: &str,
    program_name: &str,
    function_count: u64,
) {
    let dir = manager.project_dir(sha256);
    std::fs::create_dir_all(&dir).unwrap();
    let payload = serde_json::json!({
        "schema": "rbm.ghidra.extract_functions.v0",
        "program_name": program_name,
        "program_path": format!("/bin/{program_name}"),
        "function_count": function_count,
        "error_count": 0,
        "functions": [],
    });
    std::fs::write(
        dir.join(FUNCTIONS_OUTPUT_FILE),
        serde_json::to_vec_pretty(&payload).unwrap(),
    )
    .unwrap();
}

pub fn sample_decompiler_cfg_result() -> DecompilerCfgResult {
    DecompilerCfgResult {
        schema: DECOMPILER_CFG_SCHEMA.to_string(),
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        query: "main".to_string(),
        simplification_style: "normalize".to_string(),
        include_ops: true,
        resolved_address: "100003a40".to_string(),
        resolved_function_name: "Global::main".to_string(),
        block_count: 2,
        edge_count: 1,
        blocks: vec![sample_cfg_entry_block(), sample_cfg_exit_block()],
        edges: vec![sample_cfg_edge()],
        decompile_completed: true,
        decompile_valid: true,
        is_timed_out: false,
        is_cancelled: false,
        failed_to_start: false,
        decompile_error: String::new(),
        resolution_error: String::new(),
        mermaid: "graph TD\n  b0[\"0: 100003a40\"]\n  b1[\"1: 100003a50\"]\n  b0 -->|false| b1\n"
            .to_string(),
    }
}

fn sample_cfg_entry_block() -> DecompilerCfgBlock {
    DecompilerCfgBlock {
        index: 0,
        start: "100003a40".to_string(),
        stop: "100003a48".to_string(),
        block_kind: "entry".to_string(),
        structural_tags: vec!["entry".to_string(), "conditional".to_string()],
        pcode_op_count: 5,
        first_op_mnemonic: "COPY".to_string(),
        last_op_mnemonic: "CBRANCH".to_string(),
        pcode_mnemonics_preview: vec![
            "COPY".to_string(),
            "INT_EQUAL".to_string(),
            "CBRANCH".to_string(),
        ],
        pcode_preview_truncated: false,
        defs_preview: vec!["local_20<unique:0x20:4>".to_string()],
        defs_preview_truncated: false,
        uses_preview: vec![
            "RAX<register:0x0:8>".to_string(),
            "const<const:0x1:1>".to_string(),
        ],
        uses_preview_truncated: false,
        instruction_addresses_preview: vec!["100003a40".to_string()],
        instruction_addresses_truncated: false,
        call_count: 1,
        callsites_preview: sample_cfg_callsites(),
        callsites_preview_truncated: false,
        internal_call_count: 0,
        external_callsite_count: 1,
        indirect_call_count: 0,
        thunk_call_count: 0,
        call_target_count: 1,
        call_targets: vec!["kernel32.dll::CreateFileW".to_string()],
        call_targets_truncated: false,
        internal_call_target_count: 0,
        internal_call_targets: vec![],
        internal_call_targets_truncated: false,
        external_call_target_count: 1,
        external_call_targets: vec!["kernel32.dll::CreateFileW".to_string()],
        external_call_targets_truncated: false,
        memory_access_count: 2,
        memory_accesses_preview: sample_cfg_memory_accesses(),
        memory_accesses_preview_truncated: false,
        memory_read_count: 1,
        memory_write_count: 1,
        constant_count: 2,
        constants_preview: sample_cfg_constants(),
        constants_preview_truncated: false,
        string_ref_count: 1,
        string_refs_preview: sample_cfg_string_refs(),
        string_refs_preview_truncated: false,
        external_ref_count: 2,
        external_refs_preview: sample_cfg_external_refs(),
        external_refs_preview_truncated: false,
        external_call_count: 1,
        external_address_ref_count: 1,
        external_symbol_count: 2,
        external_symbols: vec![
            "kernel32.dll::CreateFileW".to_string(),
            "KERNEL32.DLL".to_string(),
        ],
        external_symbols_truncated: false,
        module_count: 1,
        modules: vec!["kernel32.dll".to_string()],
        api_family_count: 1,
        api_families: vec!["process".to_string()],
        api_tag_count: 1,
        api_tags: vec!["file".to_string()],
        predecessor_indices: vec![],
        successor_indices: vec![1],
        ops: sample_cfg_entry_ops(),
        incoming_edges: 0,
        outgoing_edges: 1,
    }
}

fn sample_cfg_exit_block() -> DecompilerCfgBlock {
    DecompilerCfgBlock {
        index: 1,
        start: "100003a50".to_string(),
        stop: "100003a58".to_string(),
        block_kind: "exit".to_string(),
        structural_tags: vec!["exit".to_string()],
        pcode_op_count: 3,
        first_op_mnemonic: "RETURN".to_string(),
        last_op_mnemonic: "RETURN".to_string(),
        pcode_mnemonics_preview: vec!["RETURN".to_string()],
        pcode_preview_truncated: false,
        defs_preview: vec![],
        defs_preview_truncated: false,
        uses_preview: vec!["RAX<register:0x0:8>".to_string()],
        uses_preview_truncated: false,
        instruction_addresses_preview: vec!["100003a50".to_string()],
        instruction_addresses_truncated: false,
        call_count: 0,
        callsites_preview: vec![],
        callsites_preview_truncated: false,
        internal_call_count: 0,
        external_callsite_count: 0,
        indirect_call_count: 0,
        thunk_call_count: 0,
        call_target_count: 0,
        call_targets: vec![],
        call_targets_truncated: false,
        internal_call_target_count: 0,
        internal_call_targets: vec![],
        internal_call_targets_truncated: false,
        external_call_target_count: 0,
        external_call_targets: vec![],
        external_call_targets_truncated: false,
        memory_access_count: 0,
        memory_accesses_preview: vec![],
        memory_accesses_preview_truncated: false,
        memory_read_count: 0,
        memory_write_count: 0,
        constant_count: 0,
        constants_preview: vec![],
        constants_preview_truncated: false,
        string_ref_count: 0,
        string_refs_preview: vec![],
        string_refs_preview_truncated: false,
        external_ref_count: 0,
        external_refs_preview: vec![],
        external_refs_preview_truncated: false,
        external_call_count: 0,
        external_address_ref_count: 0,
        external_symbol_count: 0,
        external_symbols: vec![],
        external_symbols_truncated: false,
        module_count: 0,
        modules: vec![],
        api_family_count: 0,
        api_families: vec![],
        api_tag_count: 0,
        api_tags: vec![],
        predecessor_indices: vec![0],
        successor_indices: vec![],
        ops: sample_cfg_exit_ops(),
        incoming_edges: 1,
        outgoing_edges: 0,
    }
}

fn sample_cfg_callsites() -> Vec<DecompilerCfgCallsite> {
    vec![DecompilerCfgCallsite {
        mnemonic: "CALL".to_string(),
        op_address: "100003a44".to_string(),
        target_name: "kernel32.dll::CreateFileW".to_string(),
        target_address: "180012340".to_string(),
        target_preview: "ram:180012340".to_string(),
        call_context_preview: vec![
            "100003a40 PUSH 0x1".to_string(),
            "100003a44 CALL 0x180012340".to_string(),
        ],
        call_context_truncated: false,
        module_name: "kernel32.dll".to_string(),
        api_family: "process".to_string(),
        api_tag: "file".to_string(),
        is_external: true,
        is_thunk: false,
        is_indirect: false,
    }]
}

fn sample_cfg_memory_accesses() -> Vec<DecompilerCfgMemoryAccess> {
    vec![
        DecompilerCfgMemoryAccess {
            access_kind: "read".to_string(),
            op_address: "100003a42".to_string(),
            address_preview: "local_20<unique:0x20:4>".to_string(),
            value_preview: "RAX<register:0x0:8>".to_string(),
            space_kind: "stack".to_string(),
        },
        DecompilerCfgMemoryAccess {
            access_kind: "write".to_string(),
            op_address: "100003a43".to_string(),
            address_preview: "ram:180020000".to_string(),
            value_preview: "local_24<unique:0x24:4>".to_string(),
            space_kind: "global".to_string(),
        },
    ]
}

fn sample_cfg_constants() -> Vec<DecompilerCfgConstant> {
    vec![
        DecompilerCfgConstant {
            value_hex: "0x1".to_string(),
            size_bytes: 1,
            source_op_mnemonic: "INT_EQUAL".to_string(),
        },
        DecompilerCfgConstant {
            value_hex: "0x20".to_string(),
            size_bytes: 4,
            source_op_mnemonic: "LOAD".to_string(),
        },
    ]
}

fn sample_cfg_string_refs() -> Vec<DecompilerCfgStringRef> {
    vec![DecompilerCfgStringRef {
        value: "CreateFileW failed".to_string(),
        address: "180030000".to_string(),
        source_op_mnemonic: "CALL".to_string(),
    }]
}

fn sample_cfg_external_refs() -> Vec<DecompilerCfgExternalRef> {
    vec![
        DecompilerCfgExternalRef {
            name: "kernel32.dll::CreateFileW".to_string(),
            module_name: "kernel32.dll".to_string(),
            api_family: "process".to_string(),
            api_tag: "file".to_string(),
            address: "180012340".to_string(),
            ref_kind: "call_target".to_string(),
            source_op_mnemonic: "CALL".to_string(),
            source_op_address: "100003a44".to_string(),
            source_value_preview: "ram:180012340".to_string(),
        },
        DecompilerCfgExternalRef {
            name: "KERNEL32.DLL".to_string(),
            module_name: "kernel32.dll".to_string(),
            api_family: "process".to_string(),
            api_tag: String::new(),
            address: "180020000".to_string(),
            ref_kind: "address_ref".to_string(),
            source_op_mnemonic: "LOAD".to_string(),
            source_op_address: "100003a43".to_string(),
            source_value_preview: "ram:180020000".to_string(),
        },
    ]
}

fn sample_cfg_entry_ops() -> Vec<DecompilerCfgOp> {
    vec![
        DecompilerCfgOp {
            seq_num: "100003a40@0".to_string(),
            mnemonic: "COPY".to_string(),
            output: "local_20<unique:0x20:4>".to_string(),
            inputs: vec!["RAX<register:0x0:8>".to_string()],
        },
        DecompilerCfgOp {
            seq_num: "100003a40@1".to_string(),
            mnemonic: "CBRANCH".to_string(),
            output: String::new(),
            inputs: vec!["const<const:0x1:1>".to_string()],
        },
    ]
}

fn sample_cfg_exit_ops() -> Vec<DecompilerCfgOp> {
    vec![DecompilerCfgOp {
        seq_num: "100003a50@0".to_string(),
        mnemonic: "RETURN".to_string(),
        output: String::new(),
        inputs: vec!["RAX<register:0x0:8>".to_string()],
    }]
}

fn sample_cfg_edge() -> DecompilerCfgEdge {
    DecompilerCfgEdge {
        from_index: 0,
        to_index: 1,
        from: "100003a40".to_string(),
        to: "100003a50".to_string(),
        edge_index: 0,
        label: "false".to_string(),
        branch_kind: "conditional_false".to_string(),
        source_op_mnemonic: "CBRANCH".to_string(),
        source_op_address: "100003a40".to_string(),
        branch_target_preview: "const<const:0x1:1>".to_string(),
        condition_preview: "local_20<unique:0x20:4>".to_string(),
        predicate_mnemonic: "INT_EQUAL".to_string(),
        predicate_inputs_preview: vec![
            "RAX<register:0x0:8>".to_string(),
            "const<const:0x1:1>".to_string(),
        ],
    }
}

pub fn sample_decompiler_cfg_payload() -> String {
    let result = sample_decompiler_cfg_result();
    serde_json::to_string(&serde_json::json!({
        "schema": result.schema,
        "query": result.query,
        "simplification_style": "paramid",
        "include_ops": result.include_ops,
        "resolved_address": result.resolved_address,
        "resolved_function_name": result.resolved_function_name,
        "resolution_error": result.resolution_error,
        "block_count": result.block_count,
        "edge_count": result.edge_count,
        "blocks": result.blocks,
        "edges": result.edges,
        "decompile_completed": result.decompile_completed,
        "decompile_valid": result.decompile_valid,
        "is_timed_out": result.is_timed_out,
        "is_cancelled": result.is_cancelled,
        "failed_to_start": result.failed_to_start,
        "decompile_error": result.decompile_error,
        "mermaid": result.mermaid,
    }))
    .unwrap()
}

#[cfg(feature = "integration-ghidra")]
pub struct ImportedBinaryFixture {
    pub _tmp: TempDir,
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub sha: String,
    pub program_name: String,
    pub functions: Vec<serde_json::Value>,
}

#[cfg(feature = "integration-ghidra")]
pub fn repo_scripts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ghidra_scripts")
}

#[cfg(feature = "integration-ghidra")]
pub async fn import_real_binary(binary: &Path) -> ImportedBinaryFixture {
    let health = probe();
    assert!(
        health.available,
        "GHIDRA_INSTALL_DIR must point at a real Ghidra install. health={health:?}"
    );
    let analyze_headless = PathBuf::from(
        health
            .analyze_headless_path
            .expect("analyze_headless_path populated"),
    );
    let scripts_dir = repo_scripts_dir();
    assert!(
        scripts_dir.join("extract_functions.java").exists(),
        "extract_functions.java must exist at {scripts_dir:?}"
    );

    let tmp = TempDir::new().unwrap();
    let cache = CachePaths::new(tmp.path().join("rbinghidra-cache"));
    let manager = Arc::new(ProjectManager::new(&cache));

    assert!(binary.exists(), "{binary:?} must exist on this host");
    let sha = hash_file(binary).await.unwrap();
    let output = manager.output_path(&sha);

    let import_ctx = ImportContext {
        manager: manager.clone(),
        analyze_headless: analyze_headless.clone(),
        scripts_dir: scripts_dir.clone(),
        timeout: Duration::from_secs(600),
    };
    let report = import_binary(&import_ctx, binary).await.unwrap();
    assert_eq!(report.cache_key, format!("sha256:{sha}"));

    let deadline = Instant::now() + Duration::from_secs(600);
    while !output.exists() {
        if Instant::now() >= deadline {
            panic!("ghidra_import never produced {output:?}");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let lock = manager.lock_for(&sha);
    let wait = lock.clone().lock_owned().await;
    drop(wait);

    let envelope_bytes = std::fs::read(&output).expect("read functions.json");
    let envelope: serde_json::Value =
        serde_json::from_slice(&envelope_bytes).expect("parse functions.json");
    let functions = envelope["functions"]
        .as_array()
        .expect("functions array present")
        .clone();

    ImportedBinaryFixture {
        _tmp: tmp,
        manager,
        analyze_headless,
        scripts_dir,
        sha,
        program_name: binary
            .file_name()
            .expect("binary file name")
            .to_string_lossy()
            .into_owned(),
        functions,
    }
}

#[cfg(feature = "integration-ghidra")]
pub fn first_real_function_name(functions: &[serde_json::Value]) -> String {
    functions
        .iter()
        .find(|f| {
            f["is_thunk"].as_bool() == Some(false)
                && f["is_external"].as_bool() == Some(false)
                && f["size"].as_u64().unwrap_or(0) > 0
                && f["name"].as_str().map(|n| !n.is_empty()).unwrap_or(false)
        })
        .and_then(|f| f["name"].as_str())
        .expect("at least one real function")
        .to_string()
}
