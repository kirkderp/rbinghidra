use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    DISASSEMBLE_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const DISASSEMBLE_SCHEMA: &str = "rbm.ghidra.disassemble.v0";
const OUTPUT_PREFIX: &str = "disasm";
pub const DEFAULT_MAX_INSTRUCTIONS: u32 = 32;
pub const HARD_MAX_INSTRUCTIONS: u32 = 512;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct Instruction {
    pub address: String,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub disassembly: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_delta_before: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esp_delta_after: Option<i32>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub esp_delta_known: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stack_refs: Vec<StackRef>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flow_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fall_through: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flows: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_flows: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_fallthrough: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_call: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_jump: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_terminal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackRef {
    pub operand_index: u32,
    pub operand: String,
    pub base_register: String,
    pub displacement: i32,
    pub displacement_hex: String,
    pub canonical_stack_offset: Option<i32>,
    pub canonical_stack_offset_hex: String,
    pub access: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassembleResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub function_name: String,
    pub address: String,
    pub instruction_count: u32,
    #[serde(default)]
    pub instructions_returned: u32,
    #[serde(default)]
    pub truncated: bool,
    pub instructions: Vec<Instruction>,
    pub resolution_error: String,
}

#[derive(Debug, Error)]
pub enum DisassembleError {
    #[error("name_or_address must not be empty")]
    EmptyQuery,
    #[error(transparent)]
    Inspect(#[from] InspectError),
    #[error(
        "ghidra cache for sha256 {sha256} is locked by another in-flight call; retry once it completes"
    )]
    LockHeld { sha256: String },
    #[error(transparent)]
    PathValidation(#[from] PathValidationError),
    #[error("ghidra project directory has no .gpr file: {0}")]
    ProjectFileMissing(PathBuf),
    #[error("analyzeHeadless exited with status {exit_code:?}; stderr: {stderr}")]
    HeadlessFailed {
        exit_code: Option<i32>,
        stderr: String,
    },
    #[error(
        "analyzeHeadless exited successfully but the disassemble postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
    )]
    OutputMissing { stdout: String, stderr: String },
    #[error(transparent)]
    Headless(#[from] HeadlessError),
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("disassemble output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(DisassembleError);


#[derive(Debug, Clone)]
pub struct DisassembleContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct DisassembleEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    function_name: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    instruction_count: u32,
    #[serde(default)]
    instructions_returned: u32,
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    instructions: Vec<serde_json::Value>,
    #[serde(default)]
    resolution_error: String,
}

/// Disassemble a function in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the function query is empty, the binary cannot be
/// resolved, the Ghidra script cannot run, or the disassembly report cannot be
/// read or decoded.
pub async fn disassemble_function(
    ctx: &DisassembleContext,
    binary_query: &str,
    name_or_address: &str,
    max_instructions: u32,
    include_analysis: bool,
) -> Result<DisassembleResult, DisassembleError> {
    if name_or_address.trim().is_empty() {
        return Err(DisassembleError::EmptyQuery);
    }

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
        script_name: DISASSEMBLE_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![
            name_or_address.to_string(),
            resolve_max_instructions(max_instructions).to_string(),
            include_analysis.to_string(),
        ],
    })
    .await?;

    let envelope: DisassembleEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| DisassembleError::Parse {
            path: output_path,
            source: err,
        })?;

    let instructions: Vec<Instruction> = envelope
        .instructions
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect();

    Ok(DisassembleResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        function_name: envelope.function_name,
        address: envelope.address,
        instruction_count: envelope.instruction_count,
        instructions_returned: envelope.instructions_returned,
        truncated: envelope.truncated,
        instructions,
        resolution_error: envelope.resolution_error,
    })
}

#[allow(clippy::missing_const_for_fn, clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}

fn resolve_max_instructions(max_instructions: u32) -> u32 {
    if max_instructions == 0 {
        DEFAULT_MAX_INSTRUCTIONS
    } else {
        max_instructions.min(HARD_MAX_INSTRUCTIONS)
    }
}
