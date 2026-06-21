use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::decompiler_cfg::DecompilerCfgError;
use crate::project::{DYNAMIC_DISPATCH_TABLE_SCRIPT, ProjectManager, cache_key};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const DYNAMIC_DISPATCH_TABLE_SCHEMA: &str = "rbm.ghidra.dynamic_dispatch_table.v0";
const OUTPUT_PREFIX: &str = "dynamic_dispatch_table";

#[derive(Debug, Clone)]
pub struct DynamicDispatchTableContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct DynamicDispatchTableOptions<'a> {
    pub table_count_global: &'a str,
    pub table_ptr_global: &'a str,
    pub builder_start: &'a str,
    pub builder_end: &'a str,
    pub hash_function: &'a str,
    pub call_gate_global: &'a str,
    pub lookup_hashes: &'a str,
    pub adapter_function: &'a str,
    pub hash_seed: &'a str,
    pub hash_multiplier: &'a str,
    pub candidate_names: &'a str,
    pub max_instructions: u32,
    pub limit: u32,
}

/// Recover a dynamic dispatch table from decompiler output.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the Ghidra script cannot
/// run, or the dispatch-table report cannot be read or decoded.
pub async fn recover_dynamic_dispatch_table(
    ctx: &DynamicDispatchTableContext,
    binary_query: &str,
    options: DynamicDispatchTableOptions<'_>,
) -> Result<Value, DecompilerCfgError> {
    let max_instructions = if options.max_instructions == 0 {
        15000
    } else {
        options.max_instructions.min(50000)
    };
    let limit = if options.limit == 0 {
        100
    } else {
        options.limit.min(1000)
    };

    let output_key = format!(
        "{}_{}_{}",
        options.table_count_global, options.table_ptr_global, options.builder_start
    );

    let WarmPathProduct {
        sha256,
        program_name,
        bytes,
        output_path,
    } = execute_warm_path(WarmPathRequest {
        manager: ctx.manager.as_ref(),
        analyze_headless: &ctx.analyze_headless,
        scripts_dir: &ctx.scripts_dir,
        timeout: ctx.timeout,
        binary_query,
        script_name: DYNAMIC_DISPATCH_TABLE_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: &output_key,
        extra_script_args: vec![
            options.table_count_global.to_string(),
            options.table_ptr_global.to_string(),
            options.builder_start.to_string(),
            options.builder_end.to_string(),
            options.hash_function.to_string(),
            options.call_gate_global.to_string(),
            options.lookup_hashes.to_string(),
            max_instructions.to_string(),
            limit.to_string(),
            options.adapter_function.to_string(),
            options.hash_seed.to_string(),
            options.hash_multiplier.to_string(),
            options.candidate_names.to_string(),
        ],
    })
    .await?;

    let mut value: Value =
        serde_json::from_slice(&bytes).map_err(|err| DecompilerCfgError::Parse {
            path: output_path,
            source: err,
        })?;

    if let Some(obj) = value.as_object_mut() {
        obj.insert("cache_key".to_string(), Value::String(cache_key(&sha256)));
        obj.insert("sha256".to_string(), Value::String(sha256));
        obj.insert("program_name".to_string(), Value::String(program_name));
        if obj
            .get("resolution_error")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
        {
            let msg = obj
                .get("resolution_error")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            return Err(DecompilerCfgError::ResolutionFailed(msg));
        }
    }

    Ok(value)
}
