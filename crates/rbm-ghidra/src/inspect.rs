use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::project::{CODE_INDEX_OUTPUT_FILE, ProjectManager, cache_key};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CachedBinary {
    pub cache_key: String,
    pub sha256: String,
    pub schema: String,
    pub program_name: String,
    pub program_path: String,
    pub function_count: u64,
    pub error_count: u64,
    pub project_dir: String,
    pub output_path: String,
    pub code_index_path: String,
    pub code_index_present: bool,
    pub last_modified_unix: Option<i64>,
}

#[derive(Debug, Error)]
pub enum InspectError {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid functions.json envelope at {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("no cached binary found for lookup '{0}'")]
    NotFound(String),
    #[error(
        "ambiguous lookup '{query}' matched {matches} cached binaries; use cache_key (sha256:HEX) for an exact lookup"
    )]
    Ambiguous { query: String, matches: usize },
}

impl InspectError {
    fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    fn parse(path: impl Into<PathBuf>, source: serde_json::Error) -> Self {
        Self::Parse {
            path: path.into(),
            source,
        }
    }
}

#[derive(Debug, Deserialize)]
struct EnvelopeHeader {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    program_name: String,
    #[serde(default)]
    program_path: String,
    #[serde(default)]
    function_count: u64,
    #[serde(default)]
    error_count: u64,
}

/// List cached Ghidra binaries.
///
/// # Errors
///
/// Returns an error if the cache directory cannot be inspected or cached
/// metadata cannot be read.
pub async fn list_cached_binaries(
    manager: &ProjectManager,
    name_filter: Option<&str>,
) -> Result<Vec<CachedBinary>, InspectError> {
    let ghidra_dir = manager.ghidra_dir();
    if !tokio::fs::try_exists(&ghidra_dir)
        .await
        .map_err(|e| InspectError::io(&ghidra_dir, e))?
    {
        return Ok(Vec::new());
    }
    let mut entries = tokio::fs::read_dir(&ghidra_dir)
        .await
        .map_err(|e| InspectError::io(&ghidra_dir, e))?;

    let mut results = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| InspectError::io(&ghidra_dir, e))?
    {
        let path = entry.path();
        let file_type = match entry.file_type().await {
            Ok(ft) => ft,
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "ghidra cache: skipping entry whose file type could not be read"
                );
                continue;
            }
        };
        if !file_type.is_dir() {
            continue;
        }
        let Some(name) = entry
            .file_name()
            .to_str()
            .map(std::string::ToString::to_string)
        else {
            continue;
        };
        if !is_sha256_hex(&name) {
            continue;
        }
        match read_cached_binary(manager, &name).await {
            Ok(Some(cached)) => {
                if let Some(filter) = name_filter
                    && !cached.program_name.contains(filter)
                {
                    continue;
                }
                results.push(cached);
            }
            Ok(None) => {
                tracing::debug!(
                    sha256 = %name,
                    "ghidra cache: skipping incomplete project (functions.json missing)"
                );
            }
            Err(err) => {
                tracing::warn!(
                    sha256 = %name,
                    error = %err,
                    "ghidra cache: skipping unreadable project"
                );
            }
        }
    }
    results.sort_by(|a, b| {
        a.program_name
            .cmp(&b.program_name)
            .then_with(|| a.sha256.cmp(&b.sha256))
    });
    Ok(results)
}

/// Resolve cached metadata by SHA-256 or exact program name.
///
/// # Errors
///
/// Returns an error if the query is empty, missing, ambiguous, or if cache
/// metadata cannot be read.
pub async fn get_cached_metadata(
    manager: &ProjectManager,
    query: &str,
) -> Result<CachedBinary, InspectError> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err(InspectError::NotFound(query.to_string()));
    }
    if let Some(hex) = parse_sha256_lookup(trimmed) {
        return read_cached_binary(manager, &hex)
            .await?
            .ok_or_else(|| InspectError::NotFound(query.to_string()));
    }
    let all = list_cached_binaries(manager, None).await?;
    let matches: Vec<CachedBinary> = all
        .into_iter()
        .filter(|c| c.program_name == trimmed)
        .collect();
    match matches.len() {
        0 => Err(InspectError::NotFound(query.to_string())),
        1 => {
            let Some(cached) = matches.into_iter().next() else {
                return Err(InspectError::NotFound(query.to_string()));
            };
            Ok(cached)
        }
        n => Err(InspectError::Ambiguous {
            query: query.to_string(),
            matches: n,
        }),
    }
}

/// Read one cached binary metadata record by SHA-256.
///
/// # Errors
///
/// Returns an error if the cached metadata file cannot be inspected, read, or
/// decoded.
pub async fn read_cached_binary(
    manager: &ProjectManager,
    sha256_hex: &str,
) -> Result<Option<CachedBinary>, InspectError> {
    let project_dir = manager.project_dir(sha256_hex);
    let output_path = manager.output_path(sha256_hex);
    if !tokio::fs::try_exists(&output_path)
        .await
        .map_err(|e| InspectError::io(&output_path, e))?
    {
        return Ok(None);
    }
    let bytes = tokio::fs::read(&output_path)
        .await
        .map_err(|e| InspectError::io(&output_path, e))?;
    let header: EnvelopeHeader =
        serde_json::from_slice(&bytes).map_err(|e| InspectError::parse(&output_path, e))?;
    let last_modified_unix = file_mtime_unix(&output_path).await;
    let code_index_path = project_dir.join(CODE_INDEX_OUTPUT_FILE);
    let code_index_present = tokio::fs::try_exists(&code_index_path)
        .await
        .map_err(|e| InspectError::io(&code_index_path, e))?;
    Ok(Some(CachedBinary {
        cache_key: cache_key(sha256_hex),
        sha256: sha256_hex.to_string(),
        schema: header.schema,
        program_name: header.program_name,
        program_path: header.program_path,
        function_count: header.function_count,
        error_count: header.error_count,
        project_dir: project_dir.display().to_string(),
        output_path: output_path.display().to_string(),
        code_index_path: code_index_path.display().to_string(),
        code_index_present,
        last_modified_unix,
    }))
}

async fn file_mtime_unix(path: &Path) -> Option<i64> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    let mtime = meta.modified().ok()?;
    let dur = mtime.duration_since(std::time::UNIX_EPOCH).ok()?;
    i64::try_from(dur.as_secs()).ok()
}

#[must_use]
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[must_use]
pub fn parse_sha256_lookup(s: &str) -> Option<String> {
    if let Some(stripped) = s.strip_prefix("sha256:")
        && is_sha256_hex(stripped)
    {
        return Some(stripped.to_ascii_lowercase());
    }
    if is_sha256_hex(s) {
        return Some(s.to_ascii_lowercase());
    }
    None
}
