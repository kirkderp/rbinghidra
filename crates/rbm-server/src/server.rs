/// Manual MCP server for Ghidra-based binary analysis.
use std::path::PathBuf;
use std::sync::Arc;

use rbm_core::ServerConfig;
use rbm_ghidra::inspect::parse_sha256_lookup;
use rbm_ghidra::{
    AntiAnalysisContext, BehaviorsContext, CallGraphContext, CfgContext, ConstantsContext,
    ContextApiSlotsContext, DataTypesContext, DecompileContext, DecompileMetaContext,
    DecompilerBlockBehaviorContext, DecompilerBlockBehaviorFilter, DecompilerCallsContext,
    DecompilerCallsFilter, DecompilerCfgContext, DecompilerMemoryContext, DecompilerMemoryFilter,
    DecompilerSliceContext, DefinedDataContext, DisassembleContext, DynamicDispatchTableContext,
    DynamicDispatchTableOptions, EquatesContext, FunctionCheckpointsContext, FunctionSlicesContext,
    FunctionSlicesOptions, FunctionStatsContext, GoMetadataContext, ImportContext, ImportOptions,
    ImportsExportsContext, MemoryMapContext, NamespacesContext, PathDigestContext,
    PathDigestOptions, PcodeContext, ProjectManager, ReadBytesContext, SearchBytesContext,
    SearchDecompilationContext, SearchStringsContext, StringContextContext, SymbolsContext,
    ThunkTargetContext, VariablesContext, XrefsContext, decompile_function, delete_cached_binary,
    disassemble_function, gen_callgraph, gen_cfg, gen_decompiler_cfg, get_cached_metadata,
    get_context_api_slots, get_data_types, get_decompile_meta, get_decompiler_block_behavior,
    get_decompiler_calls, get_decompiler_memory, get_decompiler_slice, get_equates,
    get_function_checkpoints, get_function_slices, get_function_stats, get_go_metadata,
    get_memory_map, get_path_digest, get_pcode, get_string_context, get_thunk_target,
    get_variables, import_binary_with_options, list_cached_binaries, list_defined_data,
    list_exports, list_functions, list_imports, list_namespaces, list_xrefs, probe_at, read_bytes,
    recover_dynamic_dispatch_table, scan_anti_analysis, scan_behaviors, scan_constants,
    search_bytes, search_decompilation, search_strings, search_symbols,
};
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, ErrorData, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use serde_json::json;

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
    pub async fn serve_stdio(self) -> Result<(), String> {
        use rmcp::service::serve_server;
        use rmcp::transport::stdio;
        let service = serve_server(self, stdio())
            .await
            .map_err(|e| format!("{e:?}"))?;
        service.waiting().await.map_err(|e| format!("{e:?}"))?;
        Ok(())
    }

    fn build_tools() -> Vec<Tool> {
        fn t(name: &'static str, desc: &'static str, schema: serde_json::Value) -> Tool {
            let input_schema = schema.as_object().cloned().unwrap_or_default();
            Tool::new(name, desc, input_schema)
        }
        fn req(name: &str) -> serde_json::Value {
            json!({"type": "string", "description": name})
        }
        fn binary_ref() -> serde_json::Value {
            req("binary name, raw SHA-256, or sha256: cache key")
        }
        fn function_ref() -> serde_json::Value {
            req("function name or address")
        }
        fn opt_s(desc: &str) -> serde_json::Value {
            json!({"type": "string", "description": desc})
        }
        fn opt_u32(desc: &str, def: u32) -> serde_json::Value {
            json!({"type": "integer", "format": "uint32", "description": desc, "default": def})
        }
        fn opt_u32_capped(desc: &str, def: u32, max: u32) -> serde_json::Value {
            json!({"type": "integer", "format": "uint32", "description": desc, "default": def, "maximum": max})
        }
        fn simplification_style() -> serde_json::Value {
            json!({
                "type": "string",
                "description": "Decompiler simplification style",
                "enum": ["decompile", "normalize", "register", "firstpass", "paramid"],
                "default": "decompile"
            })
        }
        fn paging_props() -> Vec<(&'static str, serde_json::Value)> {
            vec![
                ("query", opt_s("substring/filter")),
                ("offset", opt_u32("result offset", 0)),
                ("limit", opt_u32("max results", 25)),
            ]
        }
        fn with_paging(
            mut props: Vec<(&'static str, serde_json::Value)>,
        ) -> Vec<(&'static str, serde_json::Value)> {
            props.extend(paging_props());
            props
        }
        fn schema(props: Vec<(&str, serde_json::Value)>, required: Vec<&str>) -> serde_json::Value {
            let mut p = serde_json::Map::new();
            for (k, v) in props {
                p.insert(k.to_string(), v);
            }
            json!({"type": "object", "properties": p, "required": required, "additionalProperties": false})
        }
        fn schema_any_of(
            props: Vec<(&str, serde_json::Value)>,
            required: Vec<&str>,
            any_of: Vec<Vec<&str>>,
        ) -> serde_json::Value {
            let mut value = schema(props, required);
            value["anyOf"] = serde_json::Value::Array(
                any_of
                    .into_iter()
                    .map(|required| json!({"required": required}))
                    .collect(),
            );
            value
        }

        vec![
            t(
                "ghidra_health",
                "Check Ghidra availability",
                schema(vec![], vec![]),
            ),
            t(
                "ghidra_inventory",
                "List cached binaries",
                schema(vec![("name_filter", opt_s("filter by name"))], vec![]),
            ),
            t(
                "ghidra_lock_status",
                "View in-flight lock status for a cached binary. Held locks mean an import or query is still running; retry once released.",
                schema(
                    vec![(
                        "binary_name",
                        req("binary name, raw SHA-256, or sha256: cache key"),
                    )],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_cached_metadata",
                "Get cached metadata",
                schema(vec![("binary_name", binary_ref())], vec!["binary_name"]),
            ),
            t(
                "ghidra_list_functions",
                "List functions with filtering",
                schema(
                    with_paging(vec![("binary_name", binary_ref())]),
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_decompile",
                "Decompile a function",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", function_ref()),
                        ("style", simplification_style()),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_decompile_meta",
                "Decompile with context",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", function_ref()),
                        ("style", simplification_style()),
                        (
                            "token_limit",
                            opt_u32_capped("max decompiler tokens", 200, 2000),
                        ),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_imports",
                "List imports",
                schema(
                    with_paging(vec![("binary_name", binary_ref())]),
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_exports",
                "List exports",
                schema(
                    with_paging(vec![("binary_name", binary_ref())]),
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_search_strings",
                "Search strings",
                schema(
                    with_paging(vec![("binary_name", binary_ref())]),
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_string_context",
                "Find strings and return xrefs with short decompiler snippets from referrer functions",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("query", req("string substring/regex literal or address")),
                        (
                            "string_limit",
                            opt_u32_capped("max matching strings", 5, 25),
                        ),
                        ("xref_limit", opt_u32_capped("max xrefs per string", 10, 50)),
                        (
                            "snippet_chars",
                            opt_u32_capped("max decompiler snippet characters", 1200, 4000),
                        ),
                    ],
                    vec!["binary_name", "query"],
                ),
            ),
            t(
                "ghidra_search_decompilation",
                "Search decompiled pseudocode across functions",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("query", req("case-insensitive regex to find in pseudocode")),
                        ("offset", opt_u32("result offset", 0)),
                        ("limit", opt_u32_capped("max matching functions", 25, 200)),
                        (
                            "context_lines",
                            opt_u32_capped("source lines around first match", 2, 10),
                        ),
                        (
                            "max_functions",
                            opt_u32_capped("max functions to decompile before stopping", 500, 5000),
                        ),
                    ],
                    vec!["binary_name", "query"],
                ),
            ),
            t(
                "ghidra_constants",
                "Scan instruction constants and immediates",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        (
                            "mode",
                            json!({"type": "string", "description": "constant scan mode", "enum": ["common", "uses", "range"], "default": "common"}),
                        ),
                        ("value", opt_s("constant for mode=uses; decimal or 0x hex")),
                        (
                            "min_value",
                            opt_s("minimum constant for mode=range; decimal or 0x hex"),
                        ),
                        (
                            "max_value",
                            opt_s("maximum constant for mode=range; decimal or 0x hex"),
                        ),
                        (
                            "include_small_values",
                            json!({"type": "boolean", "description": "include 0..255 constants", "default": false}),
                        ),
                        ("limit", opt_u32_capped("max constants", 100, 1000)),
                    ],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_go_metadata",
                "Heuristically extract Go build/package/module indicators",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        (
                            "limit",
                            opt_u32_capped("max entries per category", 100, 1000),
                        ),
                    ],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_symbols",
                "Search symbols",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("query", req("symbol name substring")),
                        ("offset", opt_u32("result offset", 0)),
                        ("limit", opt_u32_capped("max results", 25, 1000)),
                    ],
                    vec!["binary_name", "query"],
                ),
            ),
            t(
                "ghidra_namespaces",
                "List namespaces",
                schema(vec![("binary_name", binary_ref())], vec!["binary_name"]),
            ),
            t(
                "ghidra_data_types",
                "List data types",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("query", opt_s("substring/filter")),
                        ("offset", opt_u32("result offset", 0)),
                        ("limit", opt_u32_capped("max results", 500, 1000)),
                    ],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_defined_data",
                "List defined data",
                schema(
                    with_paging(vec![("binary_name", binary_ref())]),
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_memory_map",
                "Get memory map",
                schema(vec![("binary_name", binary_ref())], vec!["binary_name"]),
            ),
            t(
                "ghidra_function_stats",
                "Get function stats",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", function_ref()),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_xrefs",
                "Get cross-references",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", function_ref()),
                        (
                            "direction",
                            json!({"type": "string", "description": "xref direction", "enum": ["to", "from"], "default": "to"}),
                        ),
                        ("offset", opt_u32("result offset", 0)),
                        ("limit", opt_u32_capped("max results", 25, 1000)),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_callgraph",
                "Traverse callgraph",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", req("starting function name or address")),
                        (
                            "depth",
                            opt_u32_capped(
                                "callgraph depth; 0 uses the built-in max depth of 10",
                                0,
                                10,
                            ),
                        ),
                        (
                            "direction",
                            json!({"type": "string", "description": "callgraph direction", "enum": ["calling", "called"], "default": "calling"}),
                        ),
                        ("max_nodes", opt_u32_capped("max nodes", 1000, 1000)),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_cfg",
                "Get basic-block CFG",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", function_ref()),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_decompiler_cfg",
                "Get decompiler CFG",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", function_ref()),
                        ("style", simplification_style()),
                        (
                            "include_ops",
                            json!({"type": "boolean", "description": "include per-block p-code ops", "default": false}),
                        ),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_decompiler_calls",
                "Analyze function calls",
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
                        ("only_api_tag", opt_s("API tag substring filter")),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_decompiler_memory",
                "Analyze memory access",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", function_ref()),
                        ("style", simplification_style()),
                        (
                            "only_writes",
                            json!({"type": "boolean", "description": "only blocks with memory writes", "default": false}),
                        ),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_decompiler_block_behavior",
                "Classify block behavior",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", function_ref()),
                        ("style", simplification_style()),
                        (
                            "only_strings",
                            json!({"type": "boolean", "description": "only blocks with string references", "default": false}),
                        ),
                        ("only_api_tag", opt_s("API tag substring filter")),
                        (
                            "only_external",
                            json!({"type": "boolean", "description": "only blocks with external calls", "default": false}),
                        ),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_decompiler_slice",
                "Extract decompiler slice",
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
                            opt_u32_capped("max p-code ops to return", 80, 500),
                        ),
                    ],
                    vec!["binary_name", "function_address", "seed_address"],
                ),
            ),
            t(
                "ghidra_variables",
                "Get function variables",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", function_ref()),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_pcode",
                "Get P-code",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", function_ref()),
                        ("style", simplification_style()),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_search_bytes",
                "Search hex pattern",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        (
                            "hex_pattern",
                            req("hex byte pattern; ASCII whitespace is allowed"),
                        ),
                        ("max_hits", opt_u32_capped("max results", 500, 500)),
                    ],
                    vec!["binary_name", "hex_pattern"],
                ),
            ),
            t(
                "ghidra_behaviors",
                "Scan threat patterns",
                schema(vec![("binary_name", binary_ref())], vec!["binary_name"]),
            ),
            t(
                "ghidra_anti_analysis",
                "Scan anti-analysis techniques",
                schema(vec![("binary_name", binary_ref())], vec!["binary_name"]),
            ),
            t(
                "ghidra_function_checkpoints",
                "Get P-code checkpoints",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", function_ref()),
                        (
                            "ranges",
                            opt_s(
                                "semicolon- or comma-separated address ranges with optional name: prefix, e.g. body:401000-401080,401080-401100",
                            ),
                        ),
                        ("style", simplification_style()),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_function_slices",
                "Get high-level function slices",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", function_ref()),
                        (
                            "mode",
                            json!({"type": "string", "description": "slice mode", "enum": ["all", "callsites", "fields", "buffers", "indirect", "lineage", "table_lineage"], "default": "all"}),
                        ),
                        ("query", opt_s("mode-specific substring/filter")),
                        ("range_start", opt_s("optional address range start")),
                        ("range_end", opt_s("optional address range end")),
                        ("limit", opt_u32_capped("max slice entries", 50, 500)),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_path_digest",
                "Get compact path digest",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", function_ref()),
                        ("range_start", opt_s("optional address range start")),
                        ("range_end", opt_s("optional address range end")),
                        ("stop_addresses", opt_s("comma-separated stop addresses")),
                        ("state_register", opt_s("state register name")),
                        (
                            "max_instructions",
                            opt_u32_capped("max instructions to inspect", 800, 5000),
                        ),
                        ("max_events", opt_u32_capped("max events", 200, 1000)),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_context_api_slots",
                "Recover context API slot assignments",
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
                            opt_s("function/address that resolves export names"),
                        ),
                        (
                            "module_resolver",
                            opt_s("function/address that resolves module names"),
                        ),
                        (
                            "context_stack_offset",
                            opt_s("stack offset for context pointer"),
                        ),
                        ("limit", opt_u32("max slots", 200)),
                    ],
                    vec!["binary_name", "target_function", "init_function"],
                ),
            ),
            t(
                "ghidra_thunk_target",
                "Resolve thunk",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("function_address", function_ref()),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_disassemble",
                "Disassemble at address",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("target_address", req("address")),
                        (
                            "max_instructions",
                            opt_u32_capped("max instructions", 32, 512),
                        ),
                        (
                            "include_analysis",
                            json!({"type": "boolean", "description": "include stack/flow analysis", "default": false}),
                        ),
                    ],
                    vec!["binary_name", "target_address"],
                ),
            ),
            t(
                "ghidra_equates",
                "List equates",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("query", opt_s("substring/filter")),
                        ("offset", opt_u32("result offset", 0)),
                        ("limit", opt_u32_capped("max results", 500, 1000)),
                    ],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_dynamic_dispatch_table",
                "Recover dynamic dispatch table",
                schema_any_of(
                    vec![
                        ("binary_name", binary_ref()),
                        (
                            "table_count_global",
                            opt_s("global/address containing table count"),
                        ),
                        (
                            "table_ptr_global",
                            opt_s("global/address containing table pointer"),
                        ),
                        (
                            "builder_start",
                            opt_s("builder function/address or range start"),
                        ),
                        ("builder_end", opt_s("builder range end")),
                        ("hash_function", opt_s("hash function/address")),
                        (
                            "call_gate_global",
                            opt_s("global/address used as call gate"),
                        ),
                        ("lookup_hashes", opt_s("comma-separated lookup hashes")),
                        ("adapter_function", opt_s("adapter function/address")),
                        ("hash_seed", opt_s("hash seed as decimal or hex")),
                        (
                            "hash_multiplier",
                            opt_s("hash multiplier as decimal or hex"),
                        ),
                        (
                            "candidate_names",
                            opt_s("comma-separated candidate API names"),
                        ),
                        (
                            "max_instructions",
                            opt_u32("max instructions to inspect", 15000),
                        ),
                        ("limit", opt_u32("max recovered entries", 100)),
                    ],
                    vec!["binary_name"],
                    vec![
                        vec!["table_count_global"],
                        vec!["table_ptr_global"],
                        vec!["builder_start"],
                        vec!["hash_function"],
                        vec!["call_gate_global"],
                    ],
                ),
            ),
            t(
                "ghidra_read_bytes",
                "Read bytes from binary",
                schema(
                    vec![
                        ("binary_name", binary_ref()),
                        ("address", req("address")),
                        ("size", opt_u32_capped("bytes to read", 32, 8192)),
                    ],
                    vec!["binary_name", "address"],
                ),
            ),
            t(
                "ghidra_delete",
                "Delete cached Ghidra project data for a binary",
                schema_any_of(
                    vec![
                        (
                            "binary_name",
                            req("binary name, raw SHA-256, or sha256: cache key"),
                        ),
                        (
                            "cache_key",
                            req("explicit sha256: cache key or raw SHA-256"),
                        ),
                    ],
                    vec![],
                    vec![vec!["binary_name"], vec!["cache_key"]],
                ),
            ),
            t(
                "ghidra_import",
                "Import binary",
                schema(
                    vec![
                        ("binary_path", req("path to binary")),
                        ("loader", opt_s("loader name")),
                        ("processor", opt_s("processor")),
                        ("cspec", opt_s("cspec")),
                        ("loader_base_addr", opt_s("base address")),
                    ],
                    vec!["binary_path"],
                ),
            ),
        ]
    }

    fn ghidra_runtime(&self) -> Result<GhidraRuntime, String> {
        let install_dir = self.config.ghidra_install_dir.as_deref();
        let health = probe_at(install_dir);
        if !health.available {
            return Err(health
                .error
                .unwrap_or_else(|| "Ghidra not available".to_string()));
        }
        let analyze_headless = health
            .analyze_headless_path
            .map(PathBuf::from)
            .ok_or_else(|| "no analyzeHeadless path".to_string())?;
        Ok(GhidraRuntime {
            analyze_headless,
            scripts_dir: self.config.ghidra_scripts_dir.clone(),
        })
    }

    fn s(&self, v: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
        v.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    fn opt_s<'a>(
        &self,
        v: &'a serde_json::Map<String, serde_json::Value>,
        key: &str,
    ) -> Option<&'a str> {
        v.get(key).and_then(|s| {
            let s = s.as_str()?;
            if s.is_empty() { None } else { Some(s) }
        })
    }

    fn opt_u64(&self, v: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u64> {
        v.get(key).and_then(|v| v.as_u64())
    }

    fn opt_bool(&self, v: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<bool> {
        v.get(key).and_then(|v| v.as_bool())
    }

    fn ok_json(&self, value: impl serde::Serialize) -> Result<CallToolResult, ErrorData> {
        let text = serde_json::to_string(&value).map_err(|e| err(e.to_string()))?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }
}

#[derive(Clone)]
struct GhidraRuntime {
    analyze_headless: PathBuf,
    scripts_dir: PathBuf,
}

fn err(msg: impl Into<String>) -> ErrorData {
    ErrorData::new(rmcp::model::ErrorCode::INTERNAL_ERROR, msg.into(), None)
}

impl ServerHandler for RbmServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("rbinghidra", env!("CARGO_PKG_VERSION")))
            .with_instructions(format!(
                "rbinghidra Ghidra MCP server. {} tools available.",
                self.tools.len()
            ))
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: self.tools.clone(),
            meta: None,
            next_cursor: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let name = request.name.as_ref();
        let params = request.arguments.unwrap_or_default();

        match name {
            "ghidra_health" => {
                let health = probe_at(self.config.ghidra_install_dir.as_deref());
                self.ok_json(health)
            }

            "ghidra_import" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = ImportContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_import_timeout,
                };
                let binary = PathBuf::from(self.s(&params, "binary_path"));
                let options = ImportOptions {
                    loader: self.opt_s(&params, "loader").map(String::from),
                    processor: self.opt_s(&params, "processor").map(String::from),
                    cspec: self.opt_s(&params, "cspec").map(String::from),
                    loader_base_addr: self.opt_s(&params, "loader_base_addr").map(String::from),
                };
                let report = import_binary_with_options(&ctx, &binary, &options)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                self.ok_json(report)
            }

            "ghidra_inventory" => {
                let bins =
                    list_cached_binaries(&self.ghidra_projects, self.opt_s(&params, "name_filter"))
                        .await
                        .map_err(|e| err(e.to_string()))?;
                self.ok_json(bins)
            }

            "ghidra_delete" => {
                let query = self
                    .opt_s(&params, "cache_key")
                    .or_else(|| self.opt_s(&params, "binary_name"))
                    .unwrap_or("");
                if query.is_empty() {
                    return Err(err("either binary_name or cache_key is required"));
                }
                let result = delete_cached_binary(&self.ghidra_projects, query)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_lock_status" => {
                let binary_name = self.s(&params, "binary_name");
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
                self.ok_json(status)
            }

            "ghidra_cached_metadata" => {
                let result =
                    get_cached_metadata(&self.ghidra_projects, &self.s(&params, "binary_name"))
                        .await
                        .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_list_functions" => {
                let result = list_functions(
                    &self.ghidra_projects,
                    &self.s(&params, "binary_name"),
                    self.opt_s(&params, "query"),
                    self.opt_u64(&params, "offset"),
                    self.opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_decompile" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = DecompileContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = decompile_function(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    self.opt_s(&params, "style"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_decompile_meta" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = DecompileMetaContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_decompile_meta(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    self.opt_s(&params, "style"),
                    self.opt_u64(&params, "token_limit").unwrap_or(200) as u32,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_imports" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = ImportsExportsContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = list_imports(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    self.opt_s(&params, "query"),
                    self.opt_u64(&params, "offset"),
                    self.opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_exports" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = ImportsExportsContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = list_exports(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    self.opt_s(&params, "query"),
                    self.opt_u64(&params, "offset"),
                    self.opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_search_strings" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = SearchStringsContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = search_strings(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    self.opt_s(&params, "query"),
                    self.opt_u64(&params, "offset"),
                    self.opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_string_context" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = StringContextContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_string_context(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "query"),
                    self.opt_u64(&params, "string_limit"),
                    self.opt_u64(&params, "xref_limit"),
                    self.opt_u64(&params, "snippet_chars"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_search_decompilation" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = SearchDecompilationContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = search_decompilation(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "query"),
                    self.opt_u64(&params, "offset"),
                    self.opt_u64(&params, "limit"),
                    self.opt_u64(&params, "context_lines"),
                    self.opt_u64(&params, "max_functions"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_constants" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = ConstantsContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = scan_constants(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    self.opt_s(&params, "mode"),
                    self.opt_s(&params, "value"),
                    self.opt_s(&params, "min_value"),
                    self.opt_s(&params, "max_value"),
                    self.opt_bool(&params, "include_small_values")
                        .unwrap_or(false),
                    self.opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_go_metadata" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = GoMetadataContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_go_metadata(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    self.opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_symbols" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = SymbolsContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = search_symbols(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "query"),
                    self.opt_u64(&params, "offset"),
                    self.opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_namespaces" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = NamespacesContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = list_namespaces(&ctx, &self.s(&params, "binary_name"))
                    .await
                    .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_data_types" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = DataTypesContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_data_types(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    self.opt_s(&params, "query").unwrap_or(""),
                    self.opt_u64(&params, "offset"),
                    self.opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_defined_data" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = DefinedDataContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = list_defined_data(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    self.opt_s(&params, "query"),
                    self.opt_u64(&params, "offset"),
                    self.opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_memory_map" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = MemoryMapContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_memory_map(&ctx, &self.s(&params, "binary_name"))
                    .await
                    .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_function_stats" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = FunctionStatsContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_function_stats(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_xrefs" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = XrefsContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = list_xrefs(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    self.opt_s(&params, "direction"),
                    self.opt_u64(&params, "offset"),
                    self.opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_callgraph" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = CallGraphContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = gen_callgraph(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    self.opt_s(&params, "direction"),
                    self.opt_u64(&params, "depth"),
                    self.opt_u64(&params, "max_nodes"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_cfg" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = CfgContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = gen_cfg(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_decompiler_cfg" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = DecompilerCfgContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = gen_decompiler_cfg(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    self.opt_s(&params, "style"),
                    self.opt_bool(&params, "include_ops").unwrap_or(false),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_decompiler_calls" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = DecompilerCallsContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let filter = DecompilerCallsFilter {
                    only_external: self.opt_bool(&params, "only_external").unwrap_or(true),
                    only_indirect: self.opt_bool(&params, "only_indirect").unwrap_or(false),
                    only_api_tag: self.opt_s(&params, "only_api_tag").map(String::from),
                };
                let result = get_decompiler_calls(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    self.opt_s(&params, "style"),
                    &filter,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_decompiler_memory" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = DecompilerMemoryContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_decompiler_memory(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    self.opt_s(&params, "style"),
                    &DecompilerMemoryFilter {
                        only_writes: self.opt_bool(&params, "only_writes").unwrap_or(false),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_decompiler_block_behavior" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = DecompilerBlockBehaviorContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_decompiler_block_behavior(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    self.opt_s(&params, "style"),
                    &DecompilerBlockBehaviorFilter {
                        only_strings: self.opt_bool(&params, "only_strings").unwrap_or(false),
                        only_api_tag: self.opt_s(&params, "only_api_tag").map(String::from),
                        only_external: self.opt_bool(&params, "only_external").unwrap_or(false),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_decompiler_slice" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = DecompilerSliceContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_decompiler_slice(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    &self.s(&params, "seed_address"),
                    self.opt_s(&params, "direction"),
                    self.opt_s(&params, "style"),
                    self.opt_u64(&params, "max_ops").unwrap_or(80) as u32,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_variables" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = VariablesContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_variables(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_pcode" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = PcodeContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_pcode(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    self.opt_s(&params, "style"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_search_bytes" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = SearchBytesContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = search_bytes(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "hex_pattern"),
                    self.opt_u64(&params, "max_hits"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_behaviors" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = BehaviorsContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = scan_behaviors(&ctx, &self.s(&params, "binary_name"))
                    .await
                    .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_anti_analysis" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = AntiAnalysisContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = scan_anti_analysis(&ctx, &self.s(&params, "binary_name"))
                    .await
                    .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_function_checkpoints" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = FunctionCheckpointsContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_function_checkpoints(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    self.opt_s(&params, "ranges"),
                    self.opt_s(&params, "style"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_function_slices" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = FunctionSlicesContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_function_slices(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    FunctionSlicesOptions {
                        mode: self.opt_s(&params, "mode").unwrap_or(""),
                        query: self.opt_s(&params, "query").unwrap_or(""),
                        range_start: self.opt_s(&params, "range_start").unwrap_or(""),
                        range_end: self.opt_s(&params, "range_end").unwrap_or(""),
                        limit: self.opt_u64(&params, "limit").unwrap_or(50) as u32,
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_path_digest" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = PathDigestContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_path_digest(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    PathDigestOptions {
                        range_start: self.opt_s(&params, "range_start").unwrap_or(""),
                        range_end: self.opt_s(&params, "range_end").unwrap_or(""),
                        stop_addresses: self.opt_s(&params, "stop_addresses").unwrap_or(""),
                        state_register: self.opt_s(&params, "state_register").unwrap_or(""),
                        max_instructions: self.opt_u64(&params, "max_instructions").unwrap_or(800)
                            as u32,
                        max_events: self.opt_u64(&params, "max_events").unwrap_or(200) as u32,
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_context_api_slots" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                if self.opt_s(&params, "target_function").is_none()
                    || self.opt_s(&params, "init_function").is_none()
                {
                    return Err(err(
                        "ghidra_context_api_slots requires both target_function and init_function. Use ghidra_list_functions first to choose resolvable function names or addresses.",
                    ));
                }
                let ctx = ContextApiSlotsContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_context_api_slots(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    rbm_ghidra::ContextApiSlotsOptions {
                        target_function: self.opt_s(&params, "target_function").unwrap_or(""),
                        init_function: self.opt_s(&params, "init_function").unwrap_or(""),
                        export_resolver: self.opt_s(&params, "export_resolver").unwrap_or(""),
                        module_resolver: self.opt_s(&params, "module_resolver").unwrap_or(""),
                        context_stack_offset: self
                            .opt_s(&params, "context_stack_offset")
                            .unwrap_or(""),
                        limit: self.opt_u64(&params, "limit").unwrap_or(200) as u32,
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_thunk_target" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = ThunkTargetContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_thunk_target(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_disassemble" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = DisassembleContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = disassemble_function(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "target_address"),
                    self.opt_u64(&params, "max_instructions").unwrap_or(32) as u32,
                    self.opt_bool(&params, "include_analysis").unwrap_or(false),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_equates" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = EquatesContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_equates(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    self.opt_s(&params, "query").unwrap_or(""),
                    self.opt_u64(&params, "offset"),
                    self.opt_u64(&params, "limit"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_dynamic_dispatch_table" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                if self.opt_s(&params, "table_count_global").is_none()
                    && self.opt_s(&params, "table_ptr_global").is_none()
                    && self.opt_s(&params, "builder_start").is_none()
                    && self.opt_s(&params, "hash_function").is_none()
                    && self.opt_s(&params, "call_gate_global").is_none()
                {
                    return Err(err(
                        "ghidra_dynamic_dispatch_table requires at least one anchor: table_count_global, table_ptr_global, builder_start, hash_function, or call_gate_global. Use ghidra_symbols, ghidra_defined_data, and ghidra_list_functions first to identify candidate anchors.",
                    ));
                }
                let ctx = DynamicDispatchTableContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = recover_dynamic_dispatch_table(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    DynamicDispatchTableOptions {
                        table_count_global: self.opt_s(&params, "table_count_global").unwrap_or(""),
                        table_ptr_global: self.opt_s(&params, "table_ptr_global").unwrap_or(""),
                        builder_start: self.opt_s(&params, "builder_start").unwrap_or(""),
                        builder_end: self.opt_s(&params, "builder_end").unwrap_or(""),
                        hash_function: self.opt_s(&params, "hash_function").unwrap_or(""),
                        call_gate_global: self.opt_s(&params, "call_gate_global").unwrap_or(""),
                        lookup_hashes: self.opt_s(&params, "lookup_hashes").unwrap_or(""),
                        adapter_function: self.opt_s(&params, "adapter_function").unwrap_or(""),
                        hash_seed: self.opt_s(&params, "hash_seed").unwrap_or(""),
                        hash_multiplier: self.opt_s(&params, "hash_multiplier").unwrap_or(""),
                        candidate_names: self.opt_s(&params, "candidate_names").unwrap_or(""),
                        max_instructions: self.opt_u64(&params, "max_instructions").unwrap_or(15000)
                            as u32,
                        limit: self.opt_u64(&params, "limit").unwrap_or(100) as u32,
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_read_bytes" => {
                let rt = self.ghidra_runtime().map_err(err)?;
                let ctx = ReadBytesContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = read_bytes(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "address"),
                    self.opt_u64(&params, "size"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            _ => Err(rmcp::model::ErrorData::new(
                rmcp::model::ErrorCode::INVALID_PARAMS,
                format!("unknown tool: {name}"),
                None,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            schema["anyOf"],
            serde_json::json!([{"required": ["binary_name"]}, {"required": ["cache_key"]}])
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
