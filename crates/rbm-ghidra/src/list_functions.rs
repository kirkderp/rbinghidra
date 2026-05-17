use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inspect::{InspectError, get_cached_metadata};
use crate::project::ProjectManager;

pub const LIST_FUNCTIONS_SCHEMA: &str = "rbm.ghidra.list_functions.v0";
pub const DEFAULT_OFFSET: u64 = 0;
pub const DEFAULT_LIMIT: u64 = 25;
pub const MAX_LIMIT: u64 = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionEntry {
    pub name: String,
    pub entry: String,
    pub size: u64,
    pub is_thunk: bool,
    pub is_external: bool,
    pub calling_convention: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListFunctionsResult {
    pub schema: String,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub query: String,
    pub offset: u64,
    pub limit: u64,
    pub total_matched: u64,
    pub functions: Vec<FunctionEntry>,
}

#[derive(Debug, Error)]
pub enum ListFunctionsError {
    #[error(transparent)]
    Inspect(#[from] InspectError),
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse error at {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Deserialize)]
struct FunctionsFileEnvelope {
    #[serde(default)]
    functions: Vec<FunctionEntry>,
}

#[must_use]
pub fn resolve_query(query: Option<&str>) -> String {
    match query.unwrap_or("") {
        "" => ".*".to_string(),
        q => q.to_string(),
    }
}

#[must_use]
pub fn resolve_offset(offset: Option<u64>) -> u64 {
    offset.unwrap_or(DEFAULT_OFFSET)
}

#[must_use]
pub fn resolve_limit(limit: Option<u64>) -> u64 {
    limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT)
}

/// List functions from cached import metadata.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved or cached metadata cannot
/// be read or decoded.
pub async fn list_functions(
    manager: &ProjectManager,
    binary_query: &str,
    query: Option<&str>,
    offset: Option<u64>,
    limit: Option<u64>,
) -> Result<ListFunctionsResult, ListFunctionsError> {
    let cached = get_cached_metadata(manager, binary_query).await?;
    let output_path = manager.output_path(&cached.sha256);

    let bytes = tokio::fs::read(&output_path)
        .await
        .map_err(|e| ListFunctionsError::Io {
            path: output_path.clone(),
            source: e,
        })?;

    let envelope: FunctionsFileEnvelope =
        serde_json::from_slice(&bytes).map_err(|e| ListFunctionsError::Parse {
            path: output_path,
            source: e,
        })?;

    let resolved_query = resolve_query(query);
    let resolved_offset = resolve_offset(offset);
    let resolved_limit = resolve_limit(limit);

    let filter_active = resolved_query != ".*";
    let lower_query = resolved_query.to_ascii_lowercase();

    let matched: Vec<FunctionEntry> = envelope
        .functions
        .into_iter()
        .filter(|f| {
            if filter_active {
                f.name.to_ascii_lowercase().contains(&lower_query)
            } else {
                true
            }
        })
        .collect();

    let total_matched = matched.len() as u64;
    let page_offset = usize::try_from(resolved_offset).unwrap_or(usize::MAX);
    let page_limit = usize::try_from(resolved_limit).unwrap_or(usize::MAX);

    let page: Vec<FunctionEntry> = matched
        .into_iter()
        .skip(page_offset)
        .take(page_limit)
        .collect();

    Ok(ListFunctionsResult {
        schema: LIST_FUNCTIONS_SCHEMA.to_string(),
        cache_key: cached.cache_key,
        sha256: cached.sha256,
        program_name: cached.program_name,
        query: resolved_query,
        offset: resolved_offset,
        limit: resolved_limit,
        total_matched,
        functions: page,
    })
}
