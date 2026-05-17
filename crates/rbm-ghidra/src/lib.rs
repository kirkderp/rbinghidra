#![doc = "Ghidra backend for rbinghidra: headless subprocess driver and ghidra_* tool implementations."]
#![cfg_attr(test, allow(unsafe_code))]

#[macro_export]
macro_rules! from_warm_path {
    ($err:ty) => {
        impl From<$crate::warm_path::WarmPathError> for $err {
            fn from(err: $crate::warm_path::WarmPathError) -> Self {
                match err {
                    $crate::warm_path::WarmPathError::Inspect(e) => Self::Inspect(e),
                    $crate::warm_path::WarmPathError::LockHeld { sha256 } => {
                        Self::LockHeld { sha256 }
                    }
                    $crate::warm_path::WarmPathError::PathValidation(e) => Self::PathValidation(e),
                    $crate::warm_path::WarmPathError::ProjectFileMissing(p) => {
                        Self::ProjectFileMissing(p)
                    }
                    $crate::warm_path::WarmPathError::HeadlessFailed { exit_code, stderr } => {
                        Self::HeadlessFailed { exit_code, stderr }
                    }
                    $crate::warm_path::WarmPathError::OutputMissing { stdout, stderr } => {
                        Self::OutputMissing { stdout, stderr }
                    }
                    $crate::warm_path::WarmPathError::Headless(e) => Self::Headless(e),
                    $crate::warm_path::WarmPathError::Io { path, source } => {
                        Self::Io { path, source }
                    }
                }
            }
        }
    };
}

pub mod anti_analysis;
pub mod behaviors;
pub mod bytes;
pub mod callgraph;
pub mod cfg;
pub mod context_api_slots;
pub mod data_types;
pub mod decompile;
pub mod decompile_meta;
pub mod decompiler_block_behavior;
pub mod decompiler_calls;
pub mod decompiler_cfg;
pub mod decompiler_memory;
pub mod decompiler_slice;
pub mod defined_data;
pub mod delete;
pub mod disassemble;
pub mod dynamic_dispatch_table;
pub mod equates;
pub mod function_checkpoints;
pub mod function_slices;
pub mod function_stats;
pub mod health;
pub mod import;
pub mod imports_exports;
pub mod inspect;
pub mod list_functions;
pub mod memory_map;
pub mod namespaces;
pub mod path_digest;
pub mod pcode;
pub mod project;
pub mod search_bytes;
pub mod strings;
pub mod symbols;
pub mod thunk_target;
pub mod variables;
pub mod warm_path;
pub mod xrefs;

pub use anti_analysis::{
    AntiAnalysisContext, AntiAnalysisError, AntiAnalysisFinding, AntiAnalysisResult,
    AntiAnalysisSummary, scan_anti_analysis,
};
pub use behaviors::{BehaviorsContext, BehaviorsError, BehaviorsResult, scan_behaviors};
pub use bytes::{ReadBytesContext, ReadBytesError, ReadBytesResult, read_bytes};
pub use callgraph::{
    CallGraphContext, CallGraphDirection, CallGraphEdge, CallGraphError, CallGraphNode,
    CallGraphResult, gen_callgraph,
};
pub use cfg::{CFG_SCHEMA, CfgBlock, CfgContext, CfgEdge, CfgError, CfgResult, gen_cfg};
pub use context_api_slots::{
    CONTEXT_API_SLOTS_SCHEMA, ContextApiSlotsContext, ContextApiSlotsOptions, get_context_api_slots,
};
pub use data_types::{
    DATA_TYPES_SCHEMA, DataTypeEntry, DataTypesContext, DataTypesError, DataTypesResult,
    get_data_types,
};
pub use decompile::{
    CallReference, DecompileContext, DecompileError, DecompileResult, decompile_function,
};
pub use decompile_meta::{
    DECOMPILE_META_SCHEMA, DecompileMetaContext, DecompileMetaError, DecompileMetaResult,
    DecompileToken, get_decompile_meta,
};
pub use decompiler_block_behavior::{
    DECOMPILER_BLOCK_BEHAVIOR_SCHEMA, DecompilerBlockBehaviorBlock, DecompilerBlockBehaviorContext,
    DecompilerBlockBehaviorFilter, DecompilerBlockBehaviorResult, get_decompiler_block_behavior,
    project_decompiler_block_behavior, project_decompiler_block_behavior_filtered,
};
pub use decompiler_calls::{
    DECOMPILER_CALLS_SCHEMA, DecompilerCallsBlock, DecompilerCallsContext, DecompilerCallsFilter,
    DecompilerCallsResult, get_decompiler_calls, project_decompiler_calls,
    project_decompiler_calls_filtered,
};
pub use decompiler_cfg::{
    DECOMPILER_CFG_SCHEMA, DecompilerCfgBlock, DecompilerCfgContext, DecompilerCfgEdge,
    DecompilerCfgError, DecompilerCfgResult, gen_decompiler_cfg,
};
pub use decompiler_memory::{
    DECOMPILER_MEMORY_SCHEMA, DecompilerMemoryBlock, DecompilerMemoryContext,
    DecompilerMemoryFilter, DecompilerMemoryResult, get_decompiler_memory,
    project_decompiler_memory, project_decompiler_memory_filtered,
};
pub use decompiler_slice::{
    DECOMPILER_SLICE_SCHEMA, DecompilerSliceContext, DecompilerSliceError, DecompilerSliceResult,
    DecompilerSliceSeed, get_decompiler_slice,
};
pub use defined_data::{
    DEFAULT_QUERY, DEFINED_DATA_SCHEMA, DefinedDataContext, DefinedDataEntry, DefinedDataError,
    DefinedDataResult, list_defined_data,
};
pub use delete::{DeleteError, DeleteReport, delete_cached_binary};
pub use disassemble::{
    DISASSEMBLE_SCHEMA, DisassembleContext, DisassembleError, DisassembleResult, Instruction,
    disassemble_function,
};
pub use dynamic_dispatch_table::{
    DYNAMIC_DISPATCH_TABLE_SCHEMA, DynamicDispatchTableContext, DynamicDispatchTableOptions,
    recover_dynamic_dispatch_table,
};
pub use equates::{
    EQUATES_SCHEMA, EquateEntry, EquateReference, EquatesContext, EquatesError, EquatesResult,
    get_equates,
};
pub use function_checkpoints::{
    FUNCTION_CHECKPOINTS_SCHEMA, FunctionCheckpointInstructionPreview, FunctionCheckpointRange,
    FunctionCheckpointStackRef, FunctionCheckpointsContext, FunctionCheckpointsError,
    FunctionCheckpointsResult, get_function_checkpoints,
};
pub use function_slices::{
    FUNCTION_SLICES_SCHEMA, FunctionSlicesContext, FunctionSlicesOptions, get_function_slices,
};
pub use function_stats::{
    FunctionStatsContext, FunctionStatsError, FunctionStatsResult, get_function_stats,
};
pub use health::{
    GhidraCapabilities, GhidraHealth, discover_install_dir, is_valid_ghidra_dir, probe, probe_at,
};
pub use import::{
    ImportContext, ImportError, ImportOptions, ImportReport, import_binary,
    import_binary_with_options,
};
pub use imports_exports::{
    ExportEntry, ExportsResult, ImportEntry, ImportsExportsContext, ImportsExportsError,
    ImportsResult, list_exports, list_imports,
};
pub use inspect::{CachedBinary, InspectError, get_cached_metadata, list_cached_binaries};
pub use list_functions::{
    DEFAULT_LIMIT, DEFAULT_OFFSET, FunctionEntry, LIST_FUNCTIONS_SCHEMA, ListFunctionsError,
    ListFunctionsResult, MAX_LIMIT, list_functions, resolve_limit, resolve_offset, resolve_query,
};
pub use memory_map::{
    MEMORY_MAP_SCHEMA, MemoryBlockEntry, MemoryMapContext, MemoryMapError, MemoryMapResult,
    get_memory_map,
};
pub use namespaces::{
    LIST_NAMESPACES_SCRIPT, NAMESPACES_SCHEMA, NamespacesContext, NamespacesError,
    NamespacesResult, list_namespaces,
};
pub use path_digest::{PATH_DIGEST_SCHEMA, PathDigestContext, PathDigestOptions, get_path_digest};
pub use pcode::{
    PCODE_SCHEMA, PcodeContext, PcodeError, PcodeOp, PcodeResult, PcodeVarnode, get_pcode,
};
pub use project::{
    ANTI_ANALYSIS_SCRIPT, BEHAVIORS_SCRIPT, CALLGRAPH_SCRIPT, CFG_SCRIPT, CONTEXT_API_SLOTS_SCRIPT,
    DATA_TYPES_SCRIPT, DECOMPILE_FUNCTION_SCRIPT, DECOMPILE_META_SCRIPT,
    DECOMPILER_BLOCK_BEHAVIOR_SCRIPT, DECOMPILER_CALLS_SCRIPT, DECOMPILER_CFG_SCRIPT,
    DECOMPILER_MEMORY_SCRIPT, DECOMPILER_SLICE_SCRIPT, DEFINED_DATA_SCRIPT, DISASSEMBLE_SCRIPT,
    DYNAMIC_DISPATCH_TABLE_SCRIPT, EQUATES_SCRIPT, EXTRACT_FUNCTIONS_SCRIPT,
    FUNCTION_CHECKPOINTS_SCRIPT, FUNCTION_SLICES_SCRIPT, FUNCTIONS_OUTPUT_FILE, HeadlessError,
    HeadlessOutcome, HeadlessRunner, ImportSpec, LIST_EXPORTS_SCRIPT, LIST_IMPORTS_SCRIPT,
    LIST_XREFS_SCRIPT, MEMORY_MAP_SCRIPT, PATH_DIGEST_SCRIPT, PCODE_SCRIPT, PathValidationError,
    ProcessSpec, ProjectError, ProjectManager, READ_BYTES_SCRIPT, SEARCH_BYTES_SCRIPT,
    SEARCH_STRINGS_SCRIPT, SEARCH_SYMBOLS_SCRIPT, THUNK_TARGET_SCRIPT, VARIABLES_SCRIPT,
    build_import_argv, build_process_argv, cache_key, hash_file, project_name_for,
    sanitize_project_name, stage_script_for_headless, validate_ghidra_environment,
};
pub use search_bytes::{
    DEFAULT_MAX_HITS, MAX_HITS_CAP, SEARCH_BYTES_SCHEMA, SearchBytesContext, SearchBytesError,
    SearchBytesResult, resolve_max_hits, search_bytes,
};
pub use strings::{
    SearchStringsContext, SearchStringsError, SearchStringsResult, StringEntry, search_strings,
};
pub use symbols::{SymbolEntry, SymbolsContext, SymbolsError, SymbolsResult, search_symbols};
pub use thunk_target::{
    THUNK_TARGET_SCHEMA, ThunkTargetContext, ThunkTargetError, ThunkTargetResult, get_thunk_target,
};
pub use variables::{
    FunctionParam, FunctionVariable, VARIABLES_SCHEMA, VariablesContext, VariablesError,
    VariablesResult, get_variables,
};
pub use warm_path::{
    ProjectDiscoveryError, WarmPathError, WarmPathProduct, WarmPathRequest, cleanup_output,
    discover_program_name, discover_project_name, execute_warm_path, extract_gpr_stem,
    per_call_output_path, sanitize_query_for_filename,
};
pub use xrefs::{XrefEntry, XrefsContext, XrefsError, XrefsResult, list_xrefs};
