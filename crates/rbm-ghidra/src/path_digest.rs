use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::decompiler_cfg::DecompilerCfgError;
use crate::project::{PATH_DIGEST_SCRIPT, ProjectManager, cache_key};
use crate::warm_path::{WarmPathError, WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const PATH_DIGEST_SCHEMA: &str = "rbm.ghidra.path_digest.v0";
const OUTPUT_PREFIX: &str = "path_digest";

#[derive(Debug, Clone)]
pub struct PathDigestContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct PathDigestOptions<'a> {
    pub range_start: &'a str,
    pub range_end: &'a str,
    pub stop_addresses: &'a str,
    pub state_register: &'a str,
    pub max_instructions: u32,
    pub max_events: u32,
}

fn map_warm_error(err: WarmPathError) -> DecompilerCfgError {
    match err {
        WarmPathError::Inspect(e) => DecompilerCfgError::Inspect(e),
        WarmPathError::LockHeld { sha256 } => DecompilerCfgError::LockHeld { sha256 },
        WarmPathError::PathValidation(e) => DecompilerCfgError::PathValidation(e),
        WarmPathError::ProjectFileMissing(p) => DecompilerCfgError::ProjectFileMissing(p),
        WarmPathError::HeadlessFailed { exit_code, stderr } => {
            DecompilerCfgError::HeadlessFailed { exit_code, stderr }
        }
        WarmPathError::OutputMissing { stdout, stderr } => {
            DecompilerCfgError::OutputMissing { stdout, stderr }
        }
        WarmPathError::Headless(e) => DecompilerCfgError::Headless(e),
        WarmPathError::Io { path, source } => DecompilerCfgError::Io { path, source },
    }
}

/// Return a compact path digest for a function.
///
/// # Errors
///
/// Returns an error if the function query or mode options are invalid, the
/// binary cannot be resolved, the Ghidra script cannot run, or the digest report
/// cannot be read or decoded.
pub async fn get_path_digest(
    ctx: &PathDigestContext,
    binary_query: &str,
    name_or_address: &str,
    options: PathDigestOptions<'_>,
) -> Result<Value, DecompilerCfgError> {
    if name_or_address.trim().is_empty() {
        return Err(DecompilerCfgError::EmptyQuery);
    }
    let max_instructions = if options.max_instructions == 0 {
        800
    } else {
        options.max_instructions.min(5000)
    };
    let max_events = if options.max_events == 0 {
        200
    } else {
        options.max_events.min(1000)
    };

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
        script_name: PATH_DIGEST_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![
            name_or_address.to_string(),
            options.range_start.to_string(),
            options.range_end.to_string(),
            options.stop_addresses.to_string(),
            options.state_register.to_string(),
            max_instructions.to_string(),
            max_events.to_string(),
        ],
    })
    .await
    .map_err(map_warm_error)?;

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
