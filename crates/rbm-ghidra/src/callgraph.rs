use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::InspectError;
use crate::project::{
    CALLGRAPH_SCRIPT, HeadlessError, PathValidationError, ProjectManager, cache_key,
};
use crate::warm_path::{WarmPathProduct, WarmPathRequest, execute_warm_path};

pub const CALLGRAPH_SCHEMA: &str = "rbm.ghidra.callgraph.v0";
pub const DEFAULT_DIRECTION: CallGraphDirection = CallGraphDirection::Calling;
pub const DEFAULT_DEPTH: u64 = 0;
pub const MAX_DEPTH: u64 = 10;
pub const DEFAULT_MAX_NODES: u64 = 1000;
pub const MAX_NODES_CAP: u64 = 1000;
const OUTPUT_PREFIX: &str = "callgraph";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallGraphDirection {
    Calling,
    Called,
}

impl CallGraphDirection {
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::Calling => "calling",
            Self::Called => "called",
        }
    }
}

impl fmt::Display for CallGraphDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire_str())
    }
}

impl FromStr for CallGraphDirection {
    type Err = CallGraphError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "calling" => Ok(Self::Calling),
            "called" => Ok(Self::Called),
            other => Err(CallGraphError::InvalidDirection(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallGraphNode {
    pub address: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallGraphEdge {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallGraphResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub direction: String,
    pub depth: u64,
    pub resolved_address: String,
    pub resolved_function_name: String,
    pub truncated: bool,
    pub node_count: u64,
    pub edge_count: u64,
    pub nodes: Vec<CallGraphNode>,
    pub edges: Vec<CallGraphEdge>,
    pub mermaid: String,
}

#[derive(Debug, Error)]
pub enum CallGraphError {
    #[error("callgraph query must not be empty")]
    EmptyQuery,
    #[error("function resolution failed: {0}")]
    ResolutionFailed(String),
    #[error("unknown callgraph direction '{0}'; expected 'calling' or 'called'")]
    InvalidDirection(String),
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
        "analyzeHeadless exited successfully but the callgraph postScript produced no output file; stdout: {stdout}; stderr: {stderr}"
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
    #[error("callgraph output at {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

}

from_warm_path!(CallGraphError);


#[derive(Debug, Clone)]
pub struct CallGraphContext {
    pub manager: Arc<ProjectManager>,
    pub analyze_headless: PathBuf,
    pub scripts_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct CallGraphEnvelope {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    direction: String,
    #[serde(default)]
    depth: u64,
    #[serde(default)]
    resolved_address: String,
    #[serde(default)]
    resolved_function_name: String,
    #[serde(default)]
    resolution_error: String,
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    node_count: u64,
    #[serde(default)]
    edge_count: u64,
    #[serde(default)]
    nodes: Vec<CallGraphNode>,
    #[serde(default)]
    edges: Vec<CallGraphEdge>,
    #[serde(default)]
    mermaid: String,
}

/// Resolve an optional call-graph direction string.
///
/// # Errors
///
/// Returns an error if the direction is not one of the supported call-graph
/// directions.
pub fn resolve_direction(raw: Option<&str>) -> Result<CallGraphDirection, CallGraphError> {
    match raw {
        None => Ok(DEFAULT_DIRECTION),
        Some(s) if s.trim().is_empty() => Ok(DEFAULT_DIRECTION),
        Some(s) => CallGraphDirection::from_str(s),
    }
}

#[must_use]
pub fn resolve_depth(depth: Option<u64>) -> u64 {
    depth.unwrap_or(DEFAULT_DEPTH).min(MAX_DEPTH)
}

#[must_use]
pub fn resolve_max_nodes(max_nodes: Option<u64>) -> u64 {
    let raw = max_nodes.unwrap_or(DEFAULT_MAX_NODES);
    if raw == 0 { 1 } else { raw.min(MAX_NODES_CAP) }
}

/// Generate a call graph for a function in a cached Ghidra project.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, function input is invalid,
/// the Ghidra script cannot run, or the call-graph report cannot be read or
/// decoded.
pub async fn gen_callgraph(
    ctx: &CallGraphContext,
    binary_query: &str,
    name_or_address: &str,
    direction: Option<&str>,
    depth: Option<u64>,
    max_nodes: Option<u64>,
) -> Result<CallGraphResult, CallGraphError> {
    if name_or_address.trim().is_empty() {
        return Err(CallGraphError::EmptyQuery);
    }

    let resolved_direction = resolve_direction(direction)?;
    let resolved_depth = resolve_depth(depth);
    let resolved_max_nodes = resolve_max_nodes(max_nodes);

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
        script_name: CALLGRAPH_SCRIPT,
        output_prefix: OUTPUT_PREFIX,
        output_key: name_or_address,
        extra_script_args: vec![
            name_or_address.to_string(),
            resolved_direction.as_wire_str().to_string(),
            resolved_depth.to_string(),
            resolved_max_nodes.to_string(),
        ],
    })
    .await?;

    let envelope: CallGraphEnvelope =
        serde_json::from_slice(&bytes).map_err(|err| CallGraphError::Parse {
            path: output_path,
            source: err,
        })?;

    if !envelope.resolution_error.is_empty() {
        return Err(CallGraphError::ResolutionFailed(envelope.resolution_error));
    }

    Ok(CallGraphResult {
        schema: envelope.schema,
        cache_key: cache_key(&sha256),
        sha256,
        program_name,
        query: envelope.query,
        direction: envelope.direction,
        depth: envelope.depth,
        resolved_address: envelope.resolved_address,
        resolved_function_name: envelope.resolved_function_name,
        truncated: envelope.truncated,
        node_count: envelope.node_count,
        edge_count: envelope.edge_count,
        nodes: envelope.nodes,
        edges: envelope.edges,
        mermaid: envelope.mermaid,
    })
}
