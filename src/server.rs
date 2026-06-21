// Manual MCP server for Ghidra-based binary analysis.
use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::anti_analysis::{AntiAnalysisContext, scan_anti_analysis};
use crate::behaviors::{BehaviorsContext, scan_behaviors};
use crate::bytes::{ReadBytesContext, read_bytes};
use crate::callgraph::{CallGraphContext, gen_callgraph};
use crate::cfg::{CfgContext, gen_cfg};
use crate::config::ServerConfig;
use crate::constants::{ConstantsContext, ConstantsOptions, scan_constants};
use crate::context_api_slots::{
    ContextApiSlotsContext, ContextApiSlotsOptions, get_context_api_slots,
};
use crate::data_types::{DataTypesContext, get_data_types};
use crate::decompile::{DecompileContext, decompile_function};
use crate::decompile_meta::{DecompileMetaContext, get_decompile_meta};
use crate::decompiler_block_behavior::{
    DecompilerBlockBehaviorContext, DecompilerBlockBehaviorFilter, get_decompiler_block_behavior,
};
use crate::decompiler_calls::{
    DecompilerCallsContext, DecompilerCallsFilter, get_decompiler_calls,
};
use crate::decompiler_cfg::{DecompilerCfgContext, gen_decompiler_cfg};
use crate::decompiler_memory::{
    DecompilerMemoryContext, DecompilerMemoryFilter, get_decompiler_memory,
};
use crate::decompiler_slice::{DecompilerSliceContext, get_decompiler_slice};
use crate::defined_data::{DefinedDataContext, list_defined_data};
use crate::delete::delete_cached_binary;
use crate::disassemble::{DisassembleContext, disassemble_function};
use crate::dynamic_dispatch_table::{
    DynamicDispatchTableContext, DynamicDispatchTableOptions, recover_dynamic_dispatch_table,
};
use crate::equates::{EquatesContext, get_equates};
use crate::function_checkpoints::{FunctionCheckpointsContext, get_function_checkpoints};
use crate::function_slices::{FunctionSlicesContext, FunctionSlicesOptions, get_function_slices};
use crate::function_stats::{FunctionStatsContext, get_function_stats};
use crate::go_metadata::{GoMetadataContext, get_go_metadata};
use crate::health::probe_at;
use crate::import::{ImportContext, ImportOptions, import_binary_with_options};
use crate::imports_exports::{ImportsExportsContext, list_exports, list_imports};
use crate::inspect::{get_cached_metadata, list_cached_binaries, parse_sha256_lookup};
use crate::list_functions::list_functions;
use crate::memory_map::{MemoryMapContext, get_memory_map};
use crate::namespaces::{NamespacesContext, list_namespaces};
use crate::path_digest::{PathDigestContext, PathDigestOptions, get_path_digest};
use crate::pcode::{PcodeContext, get_pcode};
use crate::project::ProjectManager;
use crate::search_bytes::{SearchBytesContext, search_bytes};
use crate::search_decompilation::{SearchDecompilationContext, search_decompilation};
use crate::string_context::{StringContextContext, get_string_context};
use crate::strings::{SearchStringsContext, search_strings};
use crate::symbols::{SymbolsContext, search_symbols};
use crate::thunk_target::{ThunkTargetContext, get_thunk_target};
use crate::variables::{VariablesContext, get_variables};
use crate::xrefs::{XrefsContext, list_xrefs};
use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Clone)]
pub struct RbmServer {
    config: Arc<ServerConfig>,
    ghidra_projects: Arc<ProjectManager>,
    tools: Vec<Tool>,
}

impl RbmServer {
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        let projects = Arc::new(ProjectManager::new(&config.cache));
        Self {
            config: Arc::new(config),
            ghidra_projects: projects,
            tools: Self::build_tools(),
        }
    }

    #[must_use]
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    #[must_use]
    pub const fn ghidra_projects(&self) -> &Arc<ProjectManager> {
        &self.ghidra_projects
    }

    /// Serve the MCP server over stdio. Runs until stdin closes.
    ///
    /// # Errors
    ///
    /// Returns an error when stdin reads, stdout writes, or response serialization fails.
    pub async fn serve_stdio(self) -> Result<(), String> {
        let stdin = tokio::io::stdin();
        let mut lines = BufReader::new(stdin).lines();
        let mut stdout = tokio::io::stdout();

        while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
            let line = line.trim_start_matches('\u{feff}');
            if line.is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<Value>(line) {
                Ok(message) => self.handle_rpc_message(message).await,
                Err(_) => Some(rpc_error_response(
                    None,
                    &RpcError::parse_error("Parse error"),
                )),
            };
            if let Some(response) = response {
                let bytes = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
                stdout.write_all(&bytes).await.map_err(|e| e.to_string())?;
                stdout.write_all(b"\n").await.map_err(|e| e.to_string())?;
                stdout.flush().await.map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    fn build_tools() -> Vec<Tool> {
        all_tools()
    }

    fn ghidra_runtime(&self, timeout: Duration) -> Result<GhidraRuntime, RpcError> {
        let install_dir = self.config.ghidra_install_dir.as_deref();
        let health = probe_at(install_dir);
        if !health.available {
            return Err(err(health
                .error
                .unwrap_or_else(|| "Ghidra not available".to_string())));
        }
        let analyze_headless = health
            .analyze_headless_path
            .map(PathBuf::from)
            .ok_or_else(|| err("no analyzeHeadless path"))?;
        Ok(GhidraRuntime {
            manager: self.ghidra_projects.clone(),
            analyze_headless,
            scripts_dir: self.config.ghidra_scripts_dir.clone(),
            timeout,
        })
    }

    fn ghidra_call_context<C>(&self) -> Result<C, RpcError>
    where
        C: From<GhidraRuntime>,
    {
        Ok(self.ghidra_runtime(self.config.ghidra_call_timeout)?.into())
    }

    fn ghidra_import_context(&self) -> Result<ImportContext, RpcError> {
        Ok(self
            .ghidra_runtime(self.config.ghidra_import_timeout)?
            .into())
    }
}

type SchemaProps = Vec<(&'static str, Value)>;
type RpcParams = Map<String, Value>;

fn all_tools() -> Vec<Tool> {
    [
        project_cache_tools(),
        discovery_tools(),
        metadata_tools(),
        graph_tools(),
        decompiler_tools(),
        analysis_tools(),
        recovery_tools(),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn project_cache_tools() -> Vec<Tool> {
    vec![
        tool("ghidra_health", "Check Ghidra availability", empty_schema()),
        tool(
            "ghidra_inventory",
            "List cached binaries",
            inventory_schema(),
        ),
        tool(
            "ghidra_lock_status",
            "View in-flight lock status for a cached binary. Held locks mean an import or query is still running; retry once released.",
            binary_schema(),
        ),
        tool(
            "ghidra_cached_metadata",
            "Get cached metadata",
            binary_schema(),
        ),
        tool(
            "ghidra_delete",
            "Delete cached Ghidra project data for a binary",
            delete_schema(),
        ),
        tool("ghidra_import", "Import binary", import_schema()),
    ]
}

fn discovery_tools() -> Vec<Tool> {
    vec![
        tool(
            "ghidra_list_functions",
            "List functions with filtering",
            binary_paging_schema(),
        ),
        tool("ghidra_imports", "List imports", binary_paging_schema()),
        tool("ghidra_exports", "List exports", binary_paging_schema()),
        tool(
            "ghidra_search_strings",
            "Search strings",
            binary_paging_schema(),
        ),
        tool(
            "ghidra_string_context",
            "Find strings and return xrefs with short decompiler snippets from referrer functions",
            string_context_schema(),
        ),
        tool(
            "ghidra_search_decompilation",
            "Search decompiled pseudocode across functions",
            search_decompilation_schema(),
        ),
        tool("ghidra_symbols", "Search symbols", symbols_schema()),
    ]
}

fn metadata_tools() -> Vec<Tool> {
    vec![
        tool(
            "ghidra_constants",
            "Scan instruction constants and immediates",
            constants_schema(),
        ),
        tool(
            "ghidra_go_metadata",
            "Heuristically extract Go build/package/module indicators",
            go_metadata_schema(),
        ),
        tool("ghidra_namespaces", "List namespaces", binary_schema()),
        tool("ghidra_data_types", "List data types", data_types_schema()),
        tool(
            "ghidra_defined_data",
            "List defined data",
            binary_paging_schema(),
        ),
        tool("ghidra_memory_map", "Get memory map", binary_schema()),
        tool(
            "ghidra_function_stats",
            "Get function stats",
            function_schema(),
        ),
        tool("ghidra_equates", "List equates", equates_schema()),
    ]
}

fn graph_tools() -> Vec<Tool> {
    vec![
        tool("ghidra_xrefs", "Get cross-references", xrefs_schema()),
        tool("ghidra_callgraph", "Traverse callgraph", callgraph_schema()),
        tool("ghidra_cfg", "Get basic-block CFG", function_schema()),
    ]
}

fn decompiler_tools() -> Vec<Tool> {
    vec![
        tool(
            "ghidra_decompile",
            "Decompile a function",
            decompile_schema(),
        ),
        tool(
            "ghidra_decompile_meta",
            "Decompile with context",
            decompile_meta_schema(),
        ),
        tool(
            "ghidra_decompiler_cfg",
            "Get decompiler CFG",
            decompiler_cfg_schema(),
        ),
        tool(
            "ghidra_decompiler_calls",
            "Analyze function calls",
            decompiler_calls_schema(),
        ),
        tool(
            "ghidra_decompiler_memory",
            "Analyze memory access",
            decompiler_memory_schema(),
        ),
        tool(
            "ghidra_decompiler_block_behavior",
            "Classify block behavior",
            decompiler_block_behavior_schema(),
        ),
        tool(
            "ghidra_decompiler_slice",
            "Extract decompiler slice",
            decompiler_slice_schema(),
        ),
    ]
}

fn analysis_tools() -> Vec<Tool> {
    vec![
        tool(
            "ghidra_variables",
            "Get function variables",
            function_schema(),
        ),
        tool("ghidra_pcode", "Get P-code", pcode_schema()),
        tool(
            "ghidra_search_bytes",
            "Search hex pattern",
            search_bytes_schema(),
        ),
        tool("ghidra_behaviors", "Scan threat patterns", binary_schema()),
        tool(
            "ghidra_anti_analysis",
            "Scan anti-analysis techniques",
            binary_schema(),
        ),
        tool(
            "ghidra_function_checkpoints",
            "Get P-code checkpoints",
            function_checkpoints_schema(),
        ),
        tool(
            "ghidra_function_slices",
            "Get high-level function slices",
            function_slices_schema(),
        ),
        tool(
            "ghidra_path_digest",
            "Get compact path digest",
            path_digest_schema(),
        ),
    ]
}

fn recovery_tools() -> Vec<Tool> {
    vec![
        tool(
            "ghidra_context_api_slots",
            "Recover context API slot assignments",
            context_api_slots_schema(),
        ),
        tool("ghidra_thunk_target", "Resolve thunk", function_schema()),
        tool(
            "ghidra_disassemble",
            "Disassemble at address",
            disassemble_schema(),
        ),
        tool(
            "ghidra_dynamic_dispatch_table",
            "Recover dynamic dispatch table",
            dynamic_dispatch_table_schema(),
        ),
        tool(
            "ghidra_read_bytes",
            "Read bytes from binary",
            read_bytes_schema(),
        ),
    ]
}

fn tool(name: &'static str, desc: &'static str, schema: Value) -> Tool {
    let input_schema = match schema {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    Tool::new(name, desc, input_schema)
}

fn req(desc: &str) -> Value {
    json!({"type": "string", "description": desc})
}

fn binary_ref() -> Value {
    req("binary name, raw SHA-256, or sha256: cache key")
}

fn function_ref() -> Value {
    req("function name or address")
}

fn string_schema(desc: &str) -> Value {
    json!({"type": "string", "description": desc})
}

fn bool_schema(desc: &str, default: bool) -> Value {
    json!({"type": "boolean", "description": desc, "default": default})
}

fn uint_schema(desc: &str, default: u32) -> Value {
    json!({"type": "integer", "format": "uint32", "description": desc, "default": default})
}

fn capped_uint_schema(desc: &str, default: u32, maximum: u32) -> Value {
    json!({
        "type": "integer",
        "format": "uint32",
        "description": desc,
        "default": default,
        "maximum": maximum
    })
}

fn simplification_style() -> Value {
    json!({
        "type": "string",
        "description": "Decompiler simplification style",
        "enum": ["decompile", "normalize", "register", "firstpass", "paramid"],
        "default": "decompile"
    })
}

fn paging_props() -> SchemaProps {
    vec![
        ("query", string_schema("substring/filter")),
        ("offset", uint_schema("result offset", 0)),
        ("limit", uint_schema("max results", 25)),
    ]
}

fn with_paging(mut props: SchemaProps) -> SchemaProps {
    props.extend(paging_props());
    props
}

fn schema(props: SchemaProps, required: &[&str]) -> Value {
    let mut properties = Map::new();
    for (key, value) in props {
        properties.insert(key.to_string(), value);
    }
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    })
}

fn schema_any_of(props: SchemaProps, required: &[&str], any_of: Vec<Vec<&str>>) -> Value {
    let mut value = schema(props, required);
    value["anyOf"] = Value::Array(
        any_of
            .into_iter()
            .map(|required| json!({"required": required}))
            .collect(),
    );
    value
}

fn empty_schema() -> Value {
    schema(vec![], &[])
}

fn inventory_schema() -> Value {
    schema(vec![("name_filter", string_schema("filter by name"))], &[])
}

fn binary_schema() -> Value {
    schema(vec![("binary_name", binary_ref())], &["binary_name"])
}

fn binary_paging_schema() -> Value {
    schema(
        with_paging(vec![("binary_name", binary_ref())]),
        &["binary_name"],
    )
}

fn function_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("function_address", function_ref()),
        ],
        &["binary_name", "function_address"],
    )
}

fn decompile_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("function_address", function_ref()),
            ("style", simplification_style()),
        ],
        &["binary_name", "function_address"],
    )
}

fn decompile_meta_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("function_address", function_ref()),
            ("style", simplification_style()),
            (
                "token_limit",
                capped_uint_schema("max decompiler tokens", 200, 2000),
            ),
        ],
        &["binary_name", "function_address"],
    )
}

fn string_context_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("query", req("string substring/regex literal or address")),
            (
                "string_limit",
                capped_uint_schema("max matching strings", 5, 25),
            ),
            (
                "xref_limit",
                capped_uint_schema("max xrefs per string", 10, 50),
            ),
            (
                "snippet_chars",
                capped_uint_schema("max decompiler snippet characters", 1200, 4000),
            ),
        ],
        &["binary_name", "query"],
    )
}

fn search_decompilation_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("query", req("case-insensitive regex to find in pseudocode")),
            ("offset", uint_schema("result offset", 0)),
            (
                "limit",
                capped_uint_schema("max matching functions", 25, 200),
            ),
            (
                "context_lines",
                capped_uint_schema("source lines around first match", 2, 10),
            ),
            (
                "max_functions",
                capped_uint_schema("max functions to decompile before stopping", 500, 5000),
            ),
        ],
        &["binary_name", "query"],
    )
}

fn constants_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            (
                "mode",
                json!({"type": "string", "description": "constant scan mode", "enum": ["common", "uses", "range"], "default": "common"}),
            ),
            (
                "value",
                string_schema("constant for mode=uses; decimal or 0x hex"),
            ),
            (
                "min_value",
                string_schema("minimum constant for mode=range; decimal or 0x hex"),
            ),
            (
                "max_value",
                string_schema("maximum constant for mode=range; decimal or 0x hex"),
            ),
            (
                "include_small_values",
                bool_schema("include 0..255 constants", false),
            ),
            ("limit", capped_uint_schema("max constants", 100, 1000)),
        ],
        &["binary_name"],
    )
}

fn go_metadata_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            (
                "limit",
                capped_uint_schema("max entries per category", 100, 1000),
            ),
        ],
        &["binary_name"],
    )
}

fn symbols_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("query", req("symbol name substring")),
            ("offset", uint_schema("result offset", 0)),
            ("limit", capped_uint_schema("max results", 25, 1000)),
        ],
        &["binary_name", "query"],
    )
}

fn data_types_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("query", string_schema("substring/filter")),
            ("offset", uint_schema("result offset", 0)),
            ("limit", capped_uint_schema("max results", 500, 1000)),
        ],
        &["binary_name"],
    )
}

fn xrefs_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("function_address", function_ref()),
            (
                "direction",
                json!({"type": "string", "description": "xref direction", "enum": ["to", "from"], "default": "to"}),
            ),
            ("offset", uint_schema("result offset", 0)),
            ("limit", capped_uint_schema("max results", 25, 1000)),
        ],
        &["binary_name", "function_address"],
    )
}

fn callgraph_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("function_address", req("starting function name or address")),
            (
                "depth",
                capped_uint_schema(
                    "callgraph depth; 0 uses the built-in max depth of 10",
                    0,
                    10,
                ),
            ),
            (
                "direction",
                json!({"type": "string", "description": "callgraph direction", "enum": ["calling", "called"], "default": "calling"}),
            ),
            ("max_nodes", capped_uint_schema("max nodes", 1000, 1000)),
        ],
        &["binary_name", "function_address"],
    )
}

fn decompiler_cfg_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("function_address", function_ref()),
            ("style", simplification_style()),
            (
                "include_ops",
                bool_schema("include per-block p-code ops", false),
            ),
        ],
        &["binary_name", "function_address"],
    )
}

fn decompiler_calls_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("function_address", function_ref()),
            ("style", simplification_style()),
            ("only_external", json!({"type": "boolean", "default": true})),
            (
                "only_indirect",
                json!({"type": "boolean", "default": false}),
            ),
            ("only_api_tag", string_schema("API tag substring filter")),
        ],
        &["binary_name", "function_address"],
    )
}

fn decompiler_memory_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("function_address", function_ref()),
            ("style", simplification_style()),
            (
                "only_writes",
                bool_schema("only blocks with memory writes", false),
            ),
        ],
        &["binary_name", "function_address"],
    )
}

fn decompiler_block_behavior_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("function_address", function_ref()),
            ("style", simplification_style()),
            (
                "only_strings",
                bool_schema("only blocks with string references", false),
            ),
            ("only_api_tag", string_schema("API tag substring filter")),
            (
                "only_external",
                bool_schema("only blocks with external calls", false),
            ),
        ],
        &["binary_name", "function_address"],
    )
}

fn decompiler_slice_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("function_address", function_ref()),
            ("seed_address", req("seed address")),
            (
                "direction",
                json!({"type": "string", "description": "slice direction", "enum": ["forward", "backward", "both"], "default": "both"}),
            ),
            ("style", simplification_style()),
            (
                "max_ops",
                capped_uint_schema("max p-code ops to return", 80, 500),
            ),
        ],
        &["binary_name", "function_address", "seed_address"],
    )
}

fn pcode_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("function_address", function_ref()),
            ("style", simplification_style()),
        ],
        &["binary_name", "function_address"],
    )
}

fn search_bytes_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            (
                "hex_pattern",
                req("hex byte pattern; ASCII whitespace is allowed"),
            ),
            ("max_hits", capped_uint_schema("max results", 500, 500)),
        ],
        &["binary_name", "hex_pattern"],
    )
}

fn function_checkpoints_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("function_address", function_ref()),
            (
                "ranges",
                string_schema(
                    "semicolon- or comma-separated address ranges with optional name: prefix, e.g. body:401000-401080,401080-401100",
                ),
            ),
            ("style", simplification_style()),
        ],
        &["binary_name", "function_address"],
    )
}

fn function_slices_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("function_address", function_ref()),
            (
                "mode",
                json!({"type": "string", "description": "slice mode", "enum": ["all", "callsites", "fields", "buffers", "indirect", "lineage", "table_lineage"], "default": "all"}),
            ),
            ("query", string_schema("mode-specific substring/filter")),
            ("range_start", string_schema("optional address range start")),
            ("range_end", string_schema("optional address range end")),
            ("limit", capped_uint_schema("max slice entries", 50, 500)),
        ],
        &["binary_name", "function_address"],
    )
}

fn path_digest_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("function_address", function_ref()),
            ("range_start", string_schema("optional address range start")),
            ("range_end", string_schema("optional address range end")),
            (
                "stop_addresses",
                string_schema("comma-separated stop addresses"),
            ),
            ("state_register", string_schema("state register name")),
            (
                "max_instructions",
                capped_uint_schema("max instructions to inspect", 800, 5000),
            ),
            ("max_events", capped_uint_schema("max events", 200, 1000)),
        ],
        &["binary_name", "function_address"],
    )
}

fn context_api_slots_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            (
                "target_function",
                req("function/address that consumes resolved API slots"),
            ),
            (
                "init_function",
                req("function/address that initializes the context"),
            ),
            (
                "export_resolver",
                string_schema("function/address that resolves export names"),
            ),
            (
                "module_resolver",
                string_schema("function/address that resolves module names"),
            ),
            (
                "context_stack_offset",
                string_schema("stack offset for context pointer"),
            ),
            ("limit", uint_schema("max slots", 200)),
        ],
        &["binary_name", "target_function", "init_function"],
    )
}

fn disassemble_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("target_address", req("address")),
            (
                "max_instructions",
                capped_uint_schema("max instructions", 32, 512),
            ),
            (
                "include_analysis",
                bool_schema("include stack/flow analysis", false),
            ),
        ],
        &["binary_name", "target_address"],
    )
}

fn equates_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("query", string_schema("substring/filter")),
            ("offset", uint_schema("result offset", 0)),
            ("limit", capped_uint_schema("max results", 500, 1000)),
        ],
        &["binary_name"],
    )
}

fn dynamic_dispatch_table_schema() -> Value {
    schema_any_of(
        vec![
            ("binary_name", binary_ref()),
            (
                "table_count_global",
                string_schema("global/address containing table count"),
            ),
            (
                "table_ptr_global",
                string_schema("global/address containing table pointer"),
            ),
            (
                "builder_start",
                string_schema("builder function/address or range start"),
            ),
            ("builder_end", string_schema("builder range end")),
            ("hash_function", string_schema("hash function/address")),
            (
                "call_gate_global",
                string_schema("global/address used as call gate"),
            ),
            (
                "lookup_hashes",
                string_schema("comma-separated lookup hashes"),
            ),
            (
                "adapter_function",
                string_schema("adapter function/address"),
            ),
            ("hash_seed", string_schema("hash seed as decimal or hex")),
            (
                "hash_multiplier",
                string_schema("hash multiplier as decimal or hex"),
            ),
            (
                "candidate_names",
                string_schema("comma-separated candidate API names"),
            ),
            (
                "max_instructions",
                uint_schema("max instructions to inspect", 15000),
            ),
            ("limit", uint_schema("max recovered entries", 100)),
        ],
        &["binary_name"],
        vec![
            vec!["table_count_global"],
            vec!["table_ptr_global"],
            vec!["builder_start"],
            vec!["hash_function"],
            vec!["call_gate_global"],
        ],
    )
}

fn read_bytes_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            ("address", req("address")),
            ("size", capped_uint_schema("bytes to read", 32, 8192)),
        ],
        &["binary_name", "address"],
    )
}

fn delete_schema() -> Value {
    schema(
        vec![
            ("binary_name", binary_ref()),
            (
                "cache_key",
                req("explicit sha256: cache key or raw SHA-256"),
            ),
        ],
        &[],
    )
}

fn import_schema() -> Value {
    schema(
        vec![
            ("binary_path", req("path to binary")),
            ("loader", string_schema("loader name")),
            ("processor", string_schema("processor")),
            ("cspec", string_schema("cspec")),
            ("loader_base_addr", string_schema("base address")),
        ],
        &["binary_path"],
    )
}

fn param_s(v: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn opt_s<'a>(v: &'a serde_json::Map<String, serde_json::Value>, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|s| {
        let s = s.as_str()?;
        if s.is_empty() { None } else { Some(s) }
    })
}

fn opt_u64(v: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}

fn opt_u32(
    v: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    default: u32,
) -> Result<u32, RpcError> {
    let Some(value) = opt_u64(v, key) else {
        return Ok(default);
    };
    u32::try_from(value).map_err(|_| RpcError::invalid_params(format!("{key} must fit uint32")))
}

fn opt_bool(v: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<bool> {
    v.get(key).and_then(Value::as_bool)
}

fn ok_json(value: impl serde::Serialize) -> Result<ToolResult, RpcError> {
    let text = serde_json::to_string(&value).map_err(|e| RpcError::internal(e.to_string()))?;
    Ok(ToolResult::success_text(text))
}

impl RbmServer {
    async fn handle_rpc_message(&self, message: Value) -> Option<Value> {
        let Some(object) = message.as_object() else {
            return Some(rpc_error_response(
                None,
                &RpcError::invalid_request("Invalid request"),
            ));
        };
        let id = object.get("id").cloned();
        let method = object.get("method").and_then(Value::as_str);
        let Some(method) = method else {
            return id.map(|id| {
                rpc_error_response(Some(&id), &RpcError::invalid_request("Invalid request"))
            });
        };

        let id = id?;
        let result = match method {
            "initialize" => Ok(self.initialize_result()),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": self.tools })),
            "tools/call" => self.handle_tools_call(object.get("params")).await,
            _ => Err(RpcError::method_not_found(format!(
                "method not found: {method}"
            ))),
        };

        Some(match result {
            Ok(result) => rpc_success_response(&id, &result),
            Err(error) => rpc_error_response(Some(&id), &error),
        })
    }

    fn initialize_result(&self) -> Value {
        json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "rbinghidra",
                "version": env!("CARGO_PKG_VERSION")
            },
            "instructions": format!(
                "rbinghidra Ghidra MCP server. {} tools available.",
                self.tools.len()
            )
        })
    }

    async fn handle_tools_call(&self, params: Option<&Value>) -> Result<Value, RpcError> {
        let params = params
            .and_then(Value::as_object)
            .ok_or_else(|| RpcError::invalid_params("tools/call params must be an object"))?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("tools/call params.name is required"))?;
        let arguments = params
            .get("arguments")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let result = self.call_tool(name, arguments).await?;
        serde_json::to_value(result).map_err(|e| RpcError::internal(e.to_string()))
    }
}

#[derive(Clone)]
struct GhidraRuntime {
    manager: Arc<ProjectManager>,
    analyze_headless: PathBuf,
    scripts_dir: PathBuf,
    timeout: Duration,
}

macro_rules! impl_from_ghidra_runtime {
    ($($context:ty),+ $(,)?) => {
        $(
            impl From<GhidraRuntime> for $context {
                fn from(runtime: GhidraRuntime) -> Self {
                    Self {
                        manager: runtime.manager,
                        analyze_headless: runtime.analyze_headless,
                        scripts_dir: runtime.scripts_dir,
                        timeout: runtime.timeout,
                    }
                }
            }
        )+
    };
}

impl_from_ghidra_runtime!(
    AntiAnalysisContext,
    BehaviorsContext,
    CallGraphContext,
    CfgContext,
    ConstantsContext,
    ContextApiSlotsContext,
    DataTypesContext,
    DecompileContext,
    DecompileMetaContext,
    DecompilerBlockBehaviorContext,
    DecompilerCallsContext,
    DecompilerCfgContext,
    DecompilerMemoryContext,
    DecompilerSliceContext,
    DefinedDataContext,
    DisassembleContext,
    DynamicDispatchTableContext,
    EquatesContext,
    FunctionCheckpointsContext,
    FunctionSlicesContext,
    FunctionStatsContext,
    GoMetadataContext,
    ImportContext,
    ImportsExportsContext,
    MemoryMapContext,
    NamespacesContext,
    PathDigestContext,
    PcodeContext,
    ReadBytesContext,
    SearchBytesContext,
    SearchDecompilationContext,
    SearchStringsContext,
    StringContextContext,
    SymbolsContext,
    ThunkTargetContext,
    VariablesContext,
    XrefsContext,
);

const MCP_PROTOCOL_VERSION: &str = "2025-11-25";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Tool {
    name: Cow<'static, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<Cow<'static, str>>,
    input_schema: Map<String, Value>,
}

impl Tool {
    const fn new(
        name: &'static str,
        description: &'static str,
        input_schema: Map<String, Value>,
    ) -> Self {
        Self {
            name: Cow::Borrowed(name),
            description: Some(Cow::Borrowed(description)),
            input_schema,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolResult {
    content: Vec<TextContent>,
    is_error: bool,
}

impl ToolResult {
    fn success_text(text: String) -> Self {
        Self {
            content: vec![TextContent::new(text)],
            is_error: false,
        }
    }
}

#[derive(Debug, Serialize)]
struct TextContent {
    #[serde(rename = "type")]
    kind: &'static str,
    text: String,
}

impl TextContent {
    const fn new(text: String) -> Self {
        Self { kind: "text", text }
    }
}

#[derive(Debug, Clone)]
struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    fn parse_error(message: impl Into<String>) -> Self {
        Self {
            code: -32700,
            message: message.into(),
        }
    }

    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            code: -32600,
            message: message.into(),
        }
    }

    fn method_not_found(message: impl Into<String>) -> Self {
        Self {
            code: -32601,
            message: message.into(),
        }
    }

    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: -32603,
            message: message.into(),
        }
    }
}

fn err(msg: impl Into<String>) -> RpcError {
    RpcError::internal(msg)
}

fn rpc_success_response(id: &Value, result: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn rpc_error_response(id: Option<&Value>, error: &RpcError) -> Value {
    let id = id.cloned().unwrap_or(Value::Null);
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": error.code,
            "message": error.message
        }
    })
}

impl RbmServer {
    async fn call_tool(&self, name: &str, params: RpcParams) -> Result<ToolResult, RpcError> {
        match name {
            "ghidra_health"
            | "ghidra_inventory"
            | "ghidra_delete"
            | "ghidra_lock_status"
            | "ghidra_cached_metadata" => self.call_cache_tool(name, params).await,
            "ghidra_import" => self.call_import_tool(name, params).await,
            "ghidra_list_functions"
            | "ghidra_imports"
            | "ghidra_exports"
            | "ghidra_search_strings" => self.call_listing_tool(name, params).await,
            "ghidra_string_context"
            | "ghidra_search_decompilation"
            | "ghidra_constants"
            | "ghidra_go_metadata" => self.call_search_tool(name, params).await,
            "ghidra_symbols"
            | "ghidra_namespaces"
            | "ghidra_data_types"
            | "ghidra_defined_data"
            | "ghidra_memory_map" => self.call_metadata_tool(name, params).await,
            "ghidra_function_stats" | "ghidra_equates" => {
                self.call_function_metadata_tool(name, params).await
            }
            "ghidra_xrefs" | "ghidra_callgraph" | "ghidra_cfg" => {
                self.call_graph_tool(name, params).await
            }
            "ghidra_decompile" | "ghidra_decompile_meta" | "ghidra_decompiler_cfg" => {
                self.call_decompile_tool(name, params).await
            }
            "ghidra_decompiler_calls"
            | "ghidra_decompiler_memory"
            | "ghidra_decompiler_block_behavior"
            | "ghidra_decompiler_slice" => self.call_decompiler_projection_tool(name, params).await,
            "ghidra_variables"
            | "ghidra_pcode"
            | "ghidra_search_bytes"
            | "ghidra_behaviors"
            | "ghidra_anti_analysis" => self.call_analysis_tool(name, params).await,
            "ghidra_function_checkpoints" | "ghidra_function_slices" | "ghidra_path_digest" => {
                self.call_function_analysis_tool(name, params).await
            }
            "ghidra_context_api_slots" | "ghidra_thunk_target" | "ghidra_disassemble" => {
                self.call_context_recovery_tool(name, params).await
            }
            "ghidra_dynamic_dispatch_table" | "ghidra_read_bytes" => {
                self.call_dynamic_bytes_tool(name, params).await
            }
            _ => Err(RpcError::invalid_params(format!("unknown tool: {name}"))),
        }
    }

    async fn call_cache_tool(&self, name: &str, params: RpcParams) -> Result<ToolResult, RpcError> {
        match name {
            "ghidra_health" => {
                let health = probe_at(self.config.ghidra_install_dir.as_deref());
                ok_json(health)
            }

            "ghidra_inventory" => {
                let bins =
                    list_cached_binaries(&self.ghidra_projects, opt_s(&params, "name_filter"))
                        .await
                        .map_err(|e| err(e.to_string()))?;
                ok_json(bins)
            }

            "ghidra_delete" => {
                let query = opt_s(&params, "cache_key")
                    .or_else(|| opt_s(&params, "binary_name"))
                    .unwrap_or("");
                if query.is_empty() {
                    return Err(err("either binary_name or cache_key is required"));
                }
                let result = delete_cached_binary(&self.ghidra_projects, query)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_lock_status" => {
                let binary_name = param_s(&params, "binary_name");
                if binary_name.is_empty() {
                    return Err(err("binary_name is required"));
                }
                let held_shas = self.ghidra_projects.held_shas();
                let status = if let Some(sha256) = parse_sha256_lookup(&binary_name) {
                    match get_cached_metadata(&self.ghidra_projects, &sha256).await {
                        Ok(metadata) => serde_json::json!({
                            "schema": "rbm.ghidra.lock_status.v0",
                            "cache_key": metadata.cache_key,
                            "sha256": metadata.sha256,
                            "program_name": metadata.program_name,
                            "locked": self.ghidra_projects.is_lock_held(&metadata.sha256),
                            "held_lock_count": held_shas.len(),
                            "held_shas": held_shas,
                        }),
                        Err(_) => serde_json::json!({
                            "schema": "rbm.ghidra.lock_status.v0",
                            "cache_key": format!("sha256:{sha256}"),
                            "sha256": sha256,
                            "program_name": null,
                            "locked": self.ghidra_projects.is_lock_held(&sha256),
                            "held_lock_count": held_shas.len(),
                            "held_shas": held_shas,
                        }),
                    }
                } else {
                    let metadata = get_cached_metadata(&self.ghidra_projects, &binary_name)
                        .await
                        .map_err(|e| err(e.to_string()))?;
                    serde_json::json!({
                        "schema": "rbm.ghidra.lock_status.v0",
                        "cache_key": metadata.cache_key,
                        "sha256": metadata.sha256,
                        "program_name": metadata.program_name,
                        "locked": self.ghidra_projects.is_lock_held(&metadata.sha256),
                        "held_lock_count": held_shas.len(),
                        "held_shas": held_shas,
                    })
                };
                ok_json(status)
            }

            "ghidra_cached_metadata" => {
                let result =
                    get_cached_metadata(&self.ghidra_projects, &param_s(&params, "binary_name"))
                        .await
                        .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            _ => Err(RpcError::invalid_params(format!("unknown tool: {name}"))),
        }
    }

    async fn call_import_tool(
        &self,
        name: &str,
        params: RpcParams,
    ) -> Result<ToolResult, RpcError> {
        match name {
            "ghidra_import" => {
                let ctx = self.ghidra_import_context()?;
                let binary = PathBuf::from(param_s(&params, "binary_path"));
                let options = ImportOptions {
                    loader: opt_s(&params, "loader").map(String::from),
                    processor: opt_s(&params, "processor").map(String::from),
                    cspec: opt_s(&params, "cspec").map(String::from),
                    loader_base_addr: opt_s(&params, "loader_base_addr").map(String::from),
                };
                let report = import_binary_with_options(&ctx, &binary, &options)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                ok_json(report)
            }

            _ => Err(RpcError::invalid_params(format!("unknown tool: {name}"))),
        }
    }

    async fn call_listing_tool(
        &self,
        name: &str,
        params: RpcParams,
    ) -> Result<ToolResult, RpcError> {
        match name {
            "ghidra_list_functions" => {
                let result = list_functions(
                    &self.ghidra_projects,
                    &param_s(&params, "binary_name"),
                    opt_s(&params, "query"),
                    opt_u64(&params, "offset"),
                    opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_imports" => {
                let ctx = self.ghidra_call_context::<ImportsExportsContext>()?;
                let result = list_imports(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    opt_s(&params, "query"),
                    opt_u64(&params, "offset"),
                    opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_exports" => {
                let ctx = self.ghidra_call_context::<ImportsExportsContext>()?;
                let result = list_exports(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    opt_s(&params, "query"),
                    opt_u64(&params, "offset"),
                    opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_search_strings" => {
                let ctx = self.ghidra_call_context::<SearchStringsContext>()?;
                let result = search_strings(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    opt_s(&params, "query"),
                    opt_u64(&params, "offset"),
                    opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            _ => Err(RpcError::invalid_params(format!("unknown tool: {name}"))),
        }
    }

    async fn call_search_tool(
        &self,
        name: &str,
        params: RpcParams,
    ) -> Result<ToolResult, RpcError> {
        match name {
            "ghidra_string_context" => {
                let ctx = self.ghidra_call_context::<StringContextContext>()?;
                let result = get_string_context(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "query"),
                    opt_u64(&params, "string_limit"),
                    opt_u64(&params, "xref_limit"),
                    opt_u64(&params, "snippet_chars"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_search_decompilation" => {
                let ctx = self.ghidra_call_context::<SearchDecompilationContext>()?;
                let result = search_decompilation(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "query"),
                    opt_u64(&params, "offset"),
                    opt_u64(&params, "limit"),
                    opt_u64(&params, "context_lines"),
                    opt_u64(&params, "max_functions"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_constants" => {
                let ctx = self.ghidra_call_context::<ConstantsContext>()?;
                let result = scan_constants(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    ConstantsOptions {
                        mode: opt_s(&params, "mode"),
                        value: opt_s(&params, "value"),
                        min_value: opt_s(&params, "min_value"),
                        max_value: opt_s(&params, "max_value"),
                        include_small_values: opt_bool(&params, "include_small_values")
                            .unwrap_or(false),
                        limit: opt_u64(&params, "limit"),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_go_metadata" => {
                let ctx = self.ghidra_call_context::<GoMetadataContext>()?;
                let result = get_go_metadata(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            _ => Err(RpcError::invalid_params(format!("unknown tool: {name}"))),
        }
    }

    async fn call_metadata_tool(
        &self,
        name: &str,
        params: RpcParams,
    ) -> Result<ToolResult, RpcError> {
        match name {
            "ghidra_symbols" => {
                let ctx = self.ghidra_call_context::<SymbolsContext>()?;
                let result = search_symbols(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "query"),
                    opt_u64(&params, "offset"),
                    opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_namespaces" => {
                let ctx = self.ghidra_call_context::<NamespacesContext>()?;
                let result = list_namespaces(&ctx, &param_s(&params, "binary_name"))
                    .await
                    .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_data_types" => {
                let ctx = self.ghidra_call_context::<DataTypesContext>()?;
                let result = get_data_types(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    opt_s(&params, "query").unwrap_or(""),
                    opt_u64(&params, "offset"),
                    opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_defined_data" => {
                let ctx = self.ghidra_call_context::<DefinedDataContext>()?;
                let result = list_defined_data(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    opt_s(&params, "query"),
                    opt_u64(&params, "offset"),
                    opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_memory_map" => {
                let ctx = self.ghidra_call_context::<MemoryMapContext>()?;
                let result = get_memory_map(&ctx, &param_s(&params, "binary_name"))
                    .await
                    .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            _ => Err(RpcError::invalid_params(format!("unknown tool: {name}"))),
        }
    }

    async fn call_function_metadata_tool(
        &self,
        name: &str,
        params: RpcParams,
    ) -> Result<ToolResult, RpcError> {
        match name {
            "ghidra_function_stats" => {
                let ctx = self.ghidra_call_context::<FunctionStatsContext>()?;
                let result = get_function_stats(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_equates" => {
                let ctx = self.ghidra_call_context::<EquatesContext>()?;
                let result = get_equates(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    opt_s(&params, "query").unwrap_or(""),
                    opt_u64(&params, "offset"),
                    opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            _ => Err(RpcError::invalid_params(format!("unknown tool: {name}"))),
        }
    }

    async fn call_graph_tool(&self, name: &str, params: RpcParams) -> Result<ToolResult, RpcError> {
        match name {
            "ghidra_xrefs" => {
                let ctx = self.ghidra_call_context::<XrefsContext>()?;
                let result = list_xrefs(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                    opt_s(&params, "direction"),
                    opt_u64(&params, "offset"),
                    opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_callgraph" => {
                let ctx = self.ghidra_call_context::<CallGraphContext>()?;
                let result = gen_callgraph(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                    opt_s(&params, "direction"),
                    opt_u64(&params, "depth"),
                    opt_u64(&params, "max_nodes"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_cfg" => {
                let ctx = self.ghidra_call_context::<CfgContext>()?;
                let result = gen_cfg(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            _ => Err(RpcError::invalid_params(format!("unknown tool: {name}"))),
        }
    }

    async fn call_decompile_tool(
        &self,
        name: &str,
        params: RpcParams,
    ) -> Result<ToolResult, RpcError> {
        match name {
            "ghidra_decompile" => {
                let ctx = self.ghidra_call_context::<DecompileContext>()?;
                let result = decompile_function(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                    opt_s(&params, "style"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_decompile_meta" => {
                let ctx = self.ghidra_call_context::<DecompileMetaContext>()?;
                let result = get_decompile_meta(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                    opt_s(&params, "style"),
                    opt_u32(&params, "token_limit", 200)?,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_decompiler_cfg" => {
                let ctx = self.ghidra_call_context::<DecompilerCfgContext>()?;
                let result = gen_decompiler_cfg(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                    opt_s(&params, "style"),
                    opt_bool(&params, "include_ops").unwrap_or(false),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            _ => Err(RpcError::invalid_params(format!("unknown tool: {name}"))),
        }
    }

    async fn call_decompiler_projection_tool(
        &self,
        name: &str,
        params: RpcParams,
    ) -> Result<ToolResult, RpcError> {
        match name {
            "ghidra_decompiler_calls" => {
                let ctx = self.ghidra_call_context::<DecompilerCallsContext>()?;
                let filter = DecompilerCallsFilter {
                    only_external: opt_bool(&params, "only_external").unwrap_or(true),
                    only_indirect: opt_bool(&params, "only_indirect").unwrap_or(false),
                    only_api_tag: opt_s(&params, "only_api_tag").map(String::from),
                };
                let result = get_decompiler_calls(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                    opt_s(&params, "style"),
                    &filter,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_decompiler_memory" => {
                let ctx = self.ghidra_call_context::<DecompilerMemoryContext>()?;
                let result = get_decompiler_memory(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                    opt_s(&params, "style"),
                    &DecompilerMemoryFilter {
                        only_writes: opt_bool(&params, "only_writes").unwrap_or(false),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_decompiler_block_behavior" => {
                let ctx = self.ghidra_call_context::<DecompilerBlockBehaviorContext>()?;
                let result = get_decompiler_block_behavior(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                    opt_s(&params, "style"),
                    &DecompilerBlockBehaviorFilter {
                        only_strings: opt_bool(&params, "only_strings").unwrap_or(false),
                        only_api_tag: opt_s(&params, "only_api_tag").map(String::from),
                        only_external: opt_bool(&params, "only_external").unwrap_or(false),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_decompiler_slice" => {
                let ctx = self.ghidra_call_context::<DecompilerSliceContext>()?;
                let result = get_decompiler_slice(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                    &param_s(&params, "seed_address"),
                    opt_s(&params, "direction"),
                    opt_s(&params, "style"),
                    opt_u32(&params, "max_ops", 80)?,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            _ => Err(RpcError::invalid_params(format!("unknown tool: {name}"))),
        }
    }

    async fn call_analysis_tool(
        &self,
        name: &str,
        params: RpcParams,
    ) -> Result<ToolResult, RpcError> {
        match name {
            "ghidra_variables" => {
                let ctx = self.ghidra_call_context::<VariablesContext>()?;
                let result = get_variables(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_pcode" => {
                let ctx = self.ghidra_call_context::<PcodeContext>()?;
                let result = get_pcode(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                    opt_s(&params, "style"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_search_bytes" => {
                let ctx = self.ghidra_call_context::<SearchBytesContext>()?;
                let result = search_bytes(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "hex_pattern"),
                    opt_u64(&params, "max_hits"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_behaviors" => {
                let ctx = self.ghidra_call_context::<BehaviorsContext>()?;
                let result = scan_behaviors(&ctx, &param_s(&params, "binary_name"))
                    .await
                    .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_anti_analysis" => {
                let ctx = self.ghidra_call_context::<AntiAnalysisContext>()?;
                let result = scan_anti_analysis(&ctx, &param_s(&params, "binary_name"))
                    .await
                    .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            _ => Err(RpcError::invalid_params(format!("unknown tool: {name}"))),
        }
    }

    async fn call_function_analysis_tool(
        &self,
        name: &str,
        params: RpcParams,
    ) -> Result<ToolResult, RpcError> {
        match name {
            "ghidra_function_checkpoints" => {
                let ctx = self.ghidra_call_context::<FunctionCheckpointsContext>()?;
                let result = get_function_checkpoints(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                    opt_s(&params, "ranges"),
                    opt_s(&params, "style"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_function_slices" => {
                let ctx = self.ghidra_call_context::<FunctionSlicesContext>()?;
                let result = get_function_slices(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                    FunctionSlicesOptions {
                        mode: opt_s(&params, "mode").unwrap_or(""),
                        query: opt_s(&params, "query").unwrap_or(""),
                        range_start: opt_s(&params, "range_start").unwrap_or(""),
                        range_end: opt_s(&params, "range_end").unwrap_or(""),
                        limit: opt_u32(&params, "limit", 50)?,
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_path_digest" => {
                let ctx = self.ghidra_call_context::<PathDigestContext>()?;
                let result = get_path_digest(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                    PathDigestOptions {
                        range_start: opt_s(&params, "range_start").unwrap_or(""),
                        range_end: opt_s(&params, "range_end").unwrap_or(""),
                        stop_addresses: opt_s(&params, "stop_addresses").unwrap_or(""),
                        state_register: opt_s(&params, "state_register").unwrap_or(""),
                        max_instructions: opt_u32(&params, "max_instructions", 800)?,
                        max_events: opt_u32(&params, "max_events", 200)?,
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            _ => Err(RpcError::invalid_params(format!("unknown tool: {name}"))),
        }
    }

    async fn call_context_recovery_tool(
        &self,
        name: &str,
        params: RpcParams,
    ) -> Result<ToolResult, RpcError> {
        match name {
            "ghidra_context_api_slots" => {
                if opt_s(&params, "target_function").is_none()
                    || opt_s(&params, "init_function").is_none()
                {
                    return Err(err(
                        "ghidra_context_api_slots requires both target_function and init_function. Use ghidra_list_functions first to choose resolvable function names or addresses.",
                    ));
                }
                let ctx = self.ghidra_call_context::<ContextApiSlotsContext>()?;
                let result = get_context_api_slots(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    ContextApiSlotsOptions {
                        target_function: opt_s(&params, "target_function").unwrap_or(""),
                        init_function: opt_s(&params, "init_function").unwrap_or(""),
                        export_resolver: opt_s(&params, "export_resolver").unwrap_or(""),
                        module_resolver: opt_s(&params, "module_resolver").unwrap_or(""),
                        context_stack_offset: opt_s(&params, "context_stack_offset").unwrap_or(""),
                        limit: opt_u32(&params, "limit", 200)?,
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_thunk_target" => {
                let ctx = self.ghidra_call_context::<ThunkTargetContext>()?;
                let result = get_thunk_target(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "function_address"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_disassemble" => {
                let ctx = self.ghidra_call_context::<DisassembleContext>()?;
                let result = disassemble_function(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "target_address"),
                    opt_u32(&params, "max_instructions", 32)?,
                    opt_bool(&params, "include_analysis").unwrap_or(false),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            _ => Err(RpcError::invalid_params(format!("unknown tool: {name}"))),
        }
    }

    async fn call_dynamic_bytes_tool(
        &self,
        name: &str,
        params: RpcParams,
    ) -> Result<ToolResult, RpcError> {
        match name {
            "ghidra_dynamic_dispatch_table" => {
                if opt_s(&params, "table_count_global").is_none()
                    && opt_s(&params, "table_ptr_global").is_none()
                    && opt_s(&params, "builder_start").is_none()
                    && opt_s(&params, "hash_function").is_none()
                    && opt_s(&params, "call_gate_global").is_none()
                {
                    return Err(err(
                        "ghidra_dynamic_dispatch_table requires at least one anchor: table_count_global, table_ptr_global, builder_start, hash_function, or call_gate_global. Use ghidra_symbols, ghidra_defined_data, and ghidra_list_functions first to identify candidate anchors.",
                    ));
                }
                let ctx = self.ghidra_call_context::<DynamicDispatchTableContext>()?;
                let result = recover_dynamic_dispatch_table(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    DynamicDispatchTableOptions {
                        table_count_global: opt_s(&params, "table_count_global").unwrap_or(""),
                        table_ptr_global: opt_s(&params, "table_ptr_global").unwrap_or(""),
                        builder_start: opt_s(&params, "builder_start").unwrap_or(""),
                        builder_end: opt_s(&params, "builder_end").unwrap_or(""),
                        hash_function: opt_s(&params, "hash_function").unwrap_or(""),
                        call_gate_global: opt_s(&params, "call_gate_global").unwrap_or(""),
                        lookup_hashes: opt_s(&params, "lookup_hashes").unwrap_or(""),
                        adapter_function: opt_s(&params, "adapter_function").unwrap_or(""),
                        hash_seed: opt_s(&params, "hash_seed").unwrap_or(""),
                        hash_multiplier: opt_s(&params, "hash_multiplier").unwrap_or(""),
                        candidate_names: opt_s(&params, "candidate_names").unwrap_or(""),
                        max_instructions: opt_u32(&params, "max_instructions", 15_000)?,
                        limit: opt_u32(&params, "limit", 100)?,
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            "ghidra_read_bytes" => {
                let ctx = self.ghidra_call_context::<ReadBytesContext>()?;
                let result = read_bytes(
                    &ctx,
                    &param_s(&params, "binary_name"),
                    &param_s(&params, "address"),
                    opt_u64(&params, "size"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                ok_json(result)
            }

            _ => Err(RpcError::invalid_params(format!("unknown tool: {name}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::CachePaths;
    use std::future::Future;
    use std::time::Duration;

    fn test_config() -> ServerConfig {
        ServerConfig {
            cache: CachePaths::new("/tmp/rbm-cache"),
            ghidra_install_dir: Some(PathBuf::from("/opt/ghidra")),
            ghidra_scripts_dir: PathBuf::from("/opt/ghidra/scripts"),
            ghidra_call_timeout: Duration::from_secs(60),
            ghidra_import_timeout: Duration::from_secs(300),
        }
    }

    fn test_server() -> RbmServer {
        RbmServer::new(test_config())
    }

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    #[test]
    fn test_server_creation_and_accessors() {
        let server = test_server();

        let retrieved_config = server.config();
        assert_eq!(
            retrieved_config.ghidra_install_dir.as_deref(),
            Some(PathBuf::from("/opt/ghidra").as_path())
        );
        assert_eq!(
            retrieved_config.ghidra_call_timeout,
            Duration::from_secs(60)
        );

        let projects = server.ghidra_projects();
        assert_eq!(projects.held_shas().len(), 0);
    }

    #[test]
    fn initialize_response_uses_mcp_shape() {
        let server = test_server();
        let response = block_on(server.handle_rpc_message(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        })))
        .unwrap();

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert!(response["result"]["capabilities"]["tools"].is_object());
        assert_eq!(response["result"]["serverInfo"]["name"], "rbinghidra");
        assert!(
            response["result"]["instructions"]
                .as_str()
                .unwrap()
                .contains(&server.tools.len().to_string())
        );
    }

    #[test]
    fn tools_list_exposes_camel_case_input_schema() {
        let server = test_server();
        let response = block_on(server.handle_rpc_message(json!({
            "jsonrpc": "2.0",
            "id": "tools",
            "method": "tools/list"
        })))
        .unwrap();

        assert_eq!(response["id"], "tools");
        let tools = response["result"]["tools"].as_array().unwrap();
        assert!(!tools.is_empty());

        let health = tools
            .iter()
            .find(|tool| tool["name"] == "ghidra_health")
            .unwrap();
        assert!(health.get("inputSchema").is_some());
        assert!(health.get("input_schema").is_none());
        assert_eq!(health["inputSchema"]["type"], "object");
    }

    #[test]
    fn notifications_do_not_emit_responses() {
        let server = test_server();
        let response = block_on(server.handle_rpc_message(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })));

        assert!(response.is_none());
    }

    #[test]
    fn rpc_errors_use_json_rpc_codes() {
        let server = test_server();
        let missing = block_on(server.handle_rpc_message(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "missing"
        })))
        .unwrap();

        assert_eq!(missing["error"]["code"], -32601);
        assert_eq!(missing["id"], 2);

        let invalid_params = block_on(server.handle_rpc_message(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {}
        })))
        .unwrap();

        assert_eq!(invalid_params["error"]["code"], -32602);
        assert_eq!(invalid_params["id"], 3);
    }

    #[test]
    fn tools_call_formats_success_result() {
        let server = test_server();
        let response = block_on(server.handle_rpc_message(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "ghidra_health",
                "arguments": {}
            }
        })))
        .unwrap();

        assert_eq!(response["id"], 4);
        assert_eq!(response["result"]["isError"], false);

        let content = response["result"]["content"].as_array().unwrap();
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], "text");

        let text = content[0]["text"].as_str().unwrap();
        let health: Value = serde_json::from_str(text).unwrap();
        assert!(health["available"].is_boolean());
    }

    fn schema_for(name: &str) -> serde_json::Value {
        let tool = RbmServer::build_tools()
            .into_iter()
            .find(|tool| tool.name == name)
            .expect("tool must exist");
        serde_json::to_value(tool.input_schema).unwrap()
    }

    #[test]
    fn high_volume_tools_expose_paging_schema() {
        for name in [
            "ghidra_list_functions",
            "ghidra_imports",
            "ghidra_exports",
            "ghidra_search_strings",
            "ghidra_data_types",
            "ghidra_defined_data",
            "ghidra_equates",
        ] {
            let schema = schema_for(name);
            let props = &schema["properties"];
            assert_eq!(props["query"]["type"], "string", "{name}");
            assert_eq!(props["offset"]["type"], "integer", "{name}");
            assert_eq!(props["limit"]["type"], "integer", "{name}");
        }
    }

    #[test]
    fn data_types_schema_matches_handler_default() {
        let schema = schema_for("ghidra_data_types");
        assert_eq!(schema["properties"]["limit"]["default"], 500);
        assert_eq!(schema["properties"]["limit"]["maximum"], 1000);
    }

    #[test]
    fn schema_paging_defaults_match_handlers() {
        let symbols = schema_for("ghidra_symbols");
        assert_eq!(symbols["properties"]["limit"]["default"], 25);
        assert_eq!(symbols["properties"]["limit"]["maximum"], 1000);

        let xrefs = schema_for("ghidra_xrefs");
        assert_eq!(xrefs["properties"]["limit"]["default"], 25);
        assert_eq!(xrefs["properties"]["limit"]["maximum"], 1000);

        let equates = schema_for("ghidra_equates");
        assert_eq!(equates["properties"]["limit"]["default"], 500);
        assert_eq!(equates["properties"]["limit"]["maximum"], 1000);
    }

    #[test]
    fn decompile_meta_exposes_token_limit_schema() {
        let schema = schema_for("ghidra_decompile_meta");
        assert_eq!(schema["properties"]["token_limit"]["type"], "integer");
        assert_eq!(schema["properties"]["token_limit"]["default"], 200);
        assert_eq!(schema["properties"]["token_limit"]["maximum"], 2000);
    }

    #[test]
    fn agent_facing_params_are_discoverable() {
        let read_bytes = schema_for("ghidra_read_bytes");
        assert_eq!(read_bytes["properties"]["size"]["default"], 32);
        assert_eq!(read_bytes["properties"]["size"]["maximum"], 8192);

        let search_bytes = schema_for("ghidra_search_bytes");
        assert_eq!(search_bytes["properties"]["max_hits"]["default"], 500);
        assert_eq!(search_bytes["properties"]["max_hits"]["maximum"], 500);

        let slice = schema_for("ghidra_decompiler_slice");
        assert_eq!(slice["properties"]["max_ops"]["default"], 80);
        assert_eq!(slice["properties"]["max_ops"]["maximum"], 500);
        assert_eq!(slice["properties"]["direction"]["default"], "both");
        assert_eq!(
            slice["properties"]["direction"]["enum"],
            serde_json::json!(["forward", "backward", "both"])
        );

        let callgraph = schema_for("ghidra_callgraph");
        assert_eq!(callgraph["properties"]["depth"]["default"], 0);
        assert_eq!(callgraph["properties"]["max_nodes"]["default"], 1000);
        assert_eq!(callgraph["properties"]["max_nodes"]["maximum"], 1000);
        assert_eq!(callgraph["properties"]["direction"]["default"], "calling");
        assert_eq!(
            callgraph["properties"]["direction"]["enum"],
            serde_json::json!(["calling", "called"])
        );
        assert_eq!(
            callgraph["required"],
            serde_json::json!(["binary_name", "function_address"])
        );

        let decompiler_cfg = schema_for("ghidra_decompiler_cfg");
        assert_eq!(
            decompiler_cfg["properties"]["include_ops"]["type"],
            "boolean"
        );

        let decompiler_calls = schema_for("ghidra_decompiler_calls");
        assert_eq!(
            decompiler_calls["properties"]["only_indirect"]["type"],
            "boolean"
        );
        assert_eq!(
            decompiler_calls["properties"]["only_api_tag"]["type"],
            "string"
        );

        let decompiler_memory = schema_for("ghidra_decompiler_memory");
        assert_eq!(
            decompiler_memory["properties"]["only_writes"]["type"],
            "boolean"
        );

        let block_behavior = schema_for("ghidra_decompiler_block_behavior");
        assert_eq!(
            block_behavior["properties"]["only_strings"]["type"],
            "boolean"
        );
        assert_eq!(
            block_behavior["properties"]["only_api_tag"]["type"],
            "string"
        );
        assert_eq!(
            block_behavior["properties"]["only_external"]["type"],
            "boolean"
        );

        let decompile = schema_for("ghidra_decompile");
        assert_eq!(
            decompile["properties"]["function_address"]["description"],
            "function name or address"
        );
        assert_eq!(
            decompile["properties"]["style"]["enum"],
            serde_json::json!(["decompile", "normalize", "register", "firstpass", "paramid"])
        );

        let cfg = schema_for("ghidra_cfg");
        assert_eq!(
            cfg["properties"]["function_address"]["description"],
            "function name or address"
        );
    }

    #[test]
    fn cleanup_tool_is_exposed() {
        let schema = schema_for("ghidra_delete");
        assert_eq!(schema["properties"]["binary_name"]["type"], "string");
        assert_eq!(
            schema["properties"]["binary_name"]["description"],
            "binary name, raw SHA-256, or sha256: cache key"
        );
        assert_eq!(
            schema["properties"]["cache_key"]["description"],
            "explicit sha256: cache key or raw SHA-256"
        );
        assert_eq!(schema["required"], serde_json::json!([]));
        assert!(
            schema.get("anyOf").is_none(),
            "OpenAI tool schemas reject top-level anyOf; ghidra_delete validates either field at runtime"
        );
    }

    #[test]
    fn specialized_recovery_tools_expose_anchor_requirements() {
        let context_slots = schema_for("ghidra_context_api_slots");
        assert_eq!(
            context_slots["required"],
            serde_json::json!(["binary_name", "target_function", "init_function"])
        );

        let dispatch = schema_for("ghidra_dynamic_dispatch_table");
        assert_eq!(
            dispatch["anyOf"],
            serde_json::json!([
                {"required": ["table_count_global"]},
                {"required": ["table_ptr_global"]},
                {"required": ["builder_start"]},
                {"required": ["hash_function"]},
                {"required": ["call_gate_global"]}
            ])
        );
    }
}
