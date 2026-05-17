/// Manual MCP server for Ghidra-based binary analysis.
use std::path::PathBuf;
use std::sync::Arc;

use rbm_core::ServerConfig;
use rbm_ghidra::{
    AntiAnalysisContext, BehaviorsContext, CallGraphContext, CfgContext, ContextApiSlotsContext,
    CreateFunctionContext, CreateLabelContext, DataTypesContext, DecompileContext,
    DecompileMetaContext, DecompilerBlockBehaviorContext, DecompilerBlockBehaviorFilter,
    DecompilerCallsContext, DecompilerCallsFilter, DecompilerCfgContext, DecompilerMemoryContext,
    DecompilerMemoryFilter, DecompilerSliceContext, DefinedDataContext, DisassembleContext,
    DynamicDispatchTableContext, DynamicDispatchTableOptions, EquatesContext,
    FunctionCheckpointsContext, FunctionStatsContext, ImportContext, ImportOptions,
    ImportsExportsContext, MemoryMapContext, NamespacesContext, PcodeContext, ProjectManager,
    ReadBytesContext, RenameContext, SearchBytesContext, SearchStringsContext, SetPrototypeContext,
    SymbolsContext, ThunkTargetContext, VariablesContext, XrefsContext, create_function,
    create_label, decompile_function, disassemble_function, gen_callgraph, gen_cfg,
    gen_decompiler_cfg, get_cached_metadata, get_context_api_slots, get_data_types,
    get_decompile_meta, get_decompiler_block_behavior, get_decompiler_calls, get_decompiler_memory,
    get_decompiler_slice, get_equates, get_function_checkpoints, get_function_stats,
    get_memory_map, get_pcode, get_thunk_target, get_variables, import_binary_with_options,
    list_cached_binaries, list_defined_data, list_exports, list_functions, list_imports,
    list_namespaces, list_xrefs, probe_at, read_bytes, recover_dynamic_dispatch_table,
    rename_function, scan_anti_analysis, scan_behaviors, search_bytes, search_strings,
    search_symbols, set_function_prototype,
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
        fn opt_s(desc: &str) -> serde_json::Value {
            json!({"type": "string", "description": desc})
        }
        fn opt_u32(desc: &str, def: u32) -> serde_json::Value {
            json!({"type": "integer", "description": desc, "default": def})
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
                "View lock status",
                schema(
                    vec![("binary_name", req("binary name"))],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_cached_metadata",
                "Get cached metadata",
                schema(
                    vec![("binary_name", req("binary name"))],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_list_functions",
                "List functions with filtering",
                schema(
                    with_paging(vec![("binary_name", req("binary name"))]),
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_decompile",
                "Decompile a function",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                        ("style", opt_s("style")),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_decompile_meta",
                "Decompile with context",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                        ("style", opt_s("style")),
                        ("token_limit", opt_u32("max decompiler tokens", 1000)),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_imports",
                "List imports",
                schema(
                    with_paging(vec![("binary_name", req("binary name"))]),
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_exports",
                "List exports",
                schema(
                    with_paging(vec![("binary_name", req("binary name"))]),
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_search_strings",
                "Search strings",
                schema(
                    with_paging(vec![("binary_name", req("binary name"))]),
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_symbols",
                "Search symbols",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("query", req("symbol name substring")),
                    ],
                    vec!["binary_name", "query"],
                ),
            ),
            t(
                "ghidra_namespaces",
                "List namespaces",
                schema(
                    vec![("binary_name", req("binary name"))],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_data_types",
                "List data types",
                schema(
                    vec![("binary_name", req("binary name"))],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_defined_data",
                "List defined data",
                schema(
                    vec![("binary_name", req("binary name"))],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_memory_map",
                "Get memory map",
                schema(
                    vec![("binary_name", req("binary name"))],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_function_stats",
                "Get function stats",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_xrefs",
                "Get cross-references",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                        (
                            "direction",
                            json!({"type": "string", "description": "xref direction", "enum": ["to", "from"], "default": "to"}),
                        ),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_callgraph",
                "Traverse callgraph",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", opt_s("starting address")),
                        ("depth", opt_u32("depth", 3)),
                        ("max_nodes", opt_u32("max nodes", 500)),
                    ],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_cfg",
                "Get basic-block CFG",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_decompiler_cfg",
                "Get decompiler CFG",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                        ("style", opt_s("style")),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_decompiler_calls",
                "Analyze function calls",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                        ("style", opt_s("style")),
                        ("only_external", json!({"type": "boolean", "default": true})),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_decompiler_memory",
                "Analyze memory access",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                        ("style", opt_s("style")),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_decompiler_block_behavior",
                "Classify block behavior",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                        ("style", opt_s("style")),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_decompiler_slice",
                "Extract decompiler slice",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                        ("seed_address", req("seed address")),
                        ("direction", opt_s("forward/backward")),
                        ("style", opt_s("style")),
                    ],
                    vec!["binary_name", "function_address", "seed_address"],
                ),
            ),
            t(
                "ghidra_variables",
                "Get function variables",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_pcode",
                "Get P-code",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                        ("style", opt_s("style")),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_search_bytes",
                "Search hex pattern",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("hex_pattern", req("hex pattern")),
                        ("max_hits", opt_u32("max results", 100)),
                    ],
                    vec!["binary_name", "hex_pattern"],
                ),
            ),
            t(
                "ghidra_behaviors",
                "Scan threat patterns",
                schema(
                    vec![("binary_name", req("binary name"))],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_anti_analysis",
                "Scan anti-analysis techniques",
                schema(
                    vec![("binary_name", req("binary name"))],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_function_checkpoints",
                "Get P-code checkpoints",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                        ("ranges", opt_s("address ranges")),
                        ("style", opt_s("style")),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_context_api_slots",
                "Recover context API slot assignments",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        (
                            "target_function",
                            opt_s("function that consumes resolved API slots"),
                        ),
                        (
                            "init_function",
                            opt_s("function that initializes the context"),
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
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_thunk_target",
                "Resolve thunk",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                    ],
                    vec!["binary_name", "function_address"],
                ),
            ),
            t(
                "ghidra_rename_function",
                "Rename function",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                        ("new_name", req("new name")),
                    ],
                    vec!["binary_name", "function_address", "new_name"],
                ),
            ),
            t(
                "ghidra_set_prototype",
                "Set function prototype",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("function_address", req("address")),
                        ("prototype", req("prototype string")),
                    ],
                    vec!["binary_name", "function_address", "prototype"],
                ),
            ),
            t(
                "ghidra_create_label",
                "Create label",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("target_address", req("address")),
                        ("label_name", req("label name")),
                    ],
                    vec!["binary_name", "target_address", "label_name"],
                ),
            ),
            t(
                "ghidra_create_function",
                "Create function",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("target_address", req("address")),
                        ("function_name", req("function name")),
                    ],
                    vec!["binary_name", "target_address", "function_name"],
                ),
            ),
            t(
                "ghidra_disassemble",
                "Disassemble at address",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("target_address", req("address")),
                        ("max_instructions", opt_u32("max instructions", 100)),
                    ],
                    vec!["binary_name", "target_address"],
                ),
            ),
            t(
                "ghidra_equates",
                "List equates",
                schema(
                    vec![("binary_name", req("binary name"))],
                    vec!["binary_name"],
                ),
            ),
            t(
                "ghidra_dynamic_dispatch_table",
                "Recover dynamic dispatch table",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
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
                        ("hash_seed", opt_s("hash seed")),
                        ("hash_multiplier", opt_s("hash multiplier")),
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
                ),
            ),
            t(
                "ghidra_read_bytes",
                "Read bytes from binary",
                schema(
                    vec![
                        ("binary_name", req("binary name")),
                        ("address", req("address")),
                    ],
                    vec!["binary_name", "address"],
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
        ] {
            let schema = schema_for(name);
            let props = &schema["properties"];
            assert_eq!(props["query"]["type"], "string", "{name}");
            assert_eq!(props["offset"]["type"], "integer", "{name}");
            assert_eq!(props["limit"]["type"], "integer", "{name}");
        }
    }

    #[test]
    fn decompile_meta_exposes_token_limit_schema() {
        let schema = schema_for("ghidra_decompile_meta");
        assert_eq!(schema["properties"]["token_limit"]["type"], "integer");
    }
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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

            "ghidra_lock_status" => {
                let status = serde_json::json!({"count": self.ghidra_projects.lock_count(), "shas": self.ghidra_projects.locked_shas()});
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                    self.opt_u64(&params, "token_limit").unwrap_or(1000) as u32,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_imports" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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

            "ghidra_symbols" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                    None,
                    None,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_namespaces" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
                let ctx = DataTypesContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_data_types(&ctx, &self.s(&params, "binary_name"), "", None, None)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_defined_data" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                    None,
                    None,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_memory_map" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                    None,
                    None,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_callgraph" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
                let ctx = CallGraphContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = gen_callgraph(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    self.opt_s(&params, "function_address").unwrap_or(""),
                    None,
                    self.opt_u64(&params, "depth"),
                    self.opt_u64(&params, "max_nodes"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_cfg" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                    false,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_decompiler_calls" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
                let ctx = DecompilerCallsContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let filter = DecompilerCallsFilter {
                    only_external: self.opt_bool(&params, "only_external").unwrap_or(true),
                    only_indirect: false,
                    only_api_tag: None,
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                    &DecompilerMemoryFilter { only_writes: false },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_decompiler_block_behavior" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                        only_strings: false,
                        only_api_tag: None,
                        only_external: false,
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_decompiler_slice" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                    1000,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_variables" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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

            "ghidra_context_api_slots" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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

            "ghidra_rename_function" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
                let ctx = RenameContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = rename_function(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    &self.s(&params, "new_name"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_set_prototype" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
                let ctx = SetPrototypeContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = set_function_prototype(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "function_address"),
                    &self.s(&params, "prototype"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_create_label" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
                let ctx = CreateLabelContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = create_label(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "target_address"),
                    &self.s(&params, "label_name"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_create_function" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
                let ctx = CreateFunctionContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = create_function(
                    &ctx,
                    &self.s(&params, "binary_name"),
                    &self.s(&params, "target_address"),
                    &self.s(&params, "function_name"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_disassemble" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                    self.opt_u64(&params, "max_instructions").unwrap_or(100) as u32,
                    false,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_equates" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
                let ctx = EquatesContext {
                    manager: self.ghidra_projects.clone(),
                    analyze_headless: rt.analyze_headless,
                    scripts_dir: rt.scripts_dir,
                    timeout: self.config.ghidra_call_timeout,
                };
                let result = get_equates(&ctx, &self.s(&params, "binary_name"), "", None, None)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "ghidra_dynamic_dispatch_table" => {
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                let rt = self.ghidra_runtime().map_err(|e| err(e))?;
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
                    None,
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
