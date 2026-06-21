use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::decompiler_cfg::DecompilerCfgError;
use crate::project::{CONTEXT_API_SLOTS_SCRIPT, ProjectManager, cache_key};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const CONTEXT_API_SLOTS_SCHEMA: &str = "rbm.ghidra.context_api_slots.v0";
const OUTPUT_PREFIX: &str = "context_api_slots";

#[derive(Debug, Clone)]
pub struct ContextApiSlotsContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct ContextApiSlotsOptions<'a> {
    pub target_function: &'a str,
    pub init_function: &'a str,
    pub export_resolver: &'a str,
    pub module_resolver: &'a str,
    pub context_stack_offset: &'a str,
    pub limit: u32,
}

/// Recover context API slot assignments from a cached binary.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the Ghidra script cannot
/// run, or the emitted report cannot be read or decoded.
pub async fn get_context_api_slots(
    ctx: &ContextApiSlotsContext,
    binary_query: &str,
    options: ContextApiSlotsOptions<'_>,
) -> Result<Value, DecompilerCfgError> {
    let limit = if options.limit == 0 {
        200
    } else {
        options.limit.min(1000)
    };
    let output_key = format!(
        "{}_{}_{}",
        options.target_function, options.init_function, options.export_resolver
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
        script_name: CONTEXT_API_SLOTS_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: &output_key,
        extra_script_args: vec![
            options.target_function.to_string(),
            options.init_function.to_string(),
            options.export_resolver.to_string(),
            options.module_resolver.to_string(),
            options.context_stack_offset.to_string(),
            limit.to_string(),
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
