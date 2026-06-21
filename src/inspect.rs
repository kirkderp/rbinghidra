use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::project::{ProjectManager, cache_key};

const EXTRACT_FUNCTIONS_SCHEMA: &str = "rbm.ghidra.extract_functions.v0";
const CACHED_METADATA_SCHEMA: &str = "rbm.ghidra.cached_binary.v0";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OutputStamp {
    len: u64,
    modified_unix_nanos: Option<u128>,
}

impl OutputStamp {
    fn last_modified_unix(self) -> Option<i64> {
        let seconds = self.modified_unix_nanos? / 1_000_000_000;
        i64::try_from(seconds).ok()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CachedBinaryMetadata {
    schema: String,
    cache_key: String,
    sha256: String,
    functions_schema: String,
    program_name: String,
    program_path: String,
    function_count: u64,
    error_count: u64,
    output_len: u64,
    output_modified_unix_nanos: Option<u128>,
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
    if !tokio::fs::try_exists(ghidra_dir)
        .await
        .map_err(|e| InspectError::io(ghidra_dir, e))?
    {
        return Ok(Vec::new());
    }
    let mut entries = tokio::fs::read_dir(ghidra_dir)
        .await
        .map_err(|e| InspectError::io(ghidra_dir, e))?;

    let mut results = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| InspectError::io(ghidra_dir, e))?
    {
        let Ok(file_type) = entry.file_type().await else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if !is_sha256_hex(name) {
            continue;
        }
        if let Ok(Some(cached)) = read_cached_binary(manager, name).await {
            if let Some(filter) = name_filter
                && !cached.program_name.contains(filter)
            {
                continue;
            }
            results.push(cached);
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
    let output_path = manager.output_path(sha256_hex);
    let Some(stamp) = output_stamp(&output_path).await? else {
        return Ok(None);
    };
    if let Some(cached) = read_fresh_metadata(manager, sha256_hex, stamp).await {
        return Ok(Some(cached));
    }

    let Some(cached) = read_functions_metadata(manager, sha256_hex, &output_path, stamp).await?
    else {
        return Ok(None);
    };
    write_cached_metadata(manager, &cached, stamp).await;
    Ok(Some(cached))
}

pub(crate) async fn cached_binary_metadata_is_ready(
    manager: &ProjectManager,
    sha256_hex: &str,
) -> Result<bool, InspectError> {
    let output_path = manager.output_path(sha256_hex);
    let Some(stamp) = output_stamp(&output_path).await? else {
        return Ok(false);
    };
    Ok(read_fresh_metadata(manager, sha256_hex, stamp)
        .await
        .is_some())
}

pub(crate) async fn refresh_cached_binary_metadata(
    manager: &ProjectManager,
    sha256_hex: &str,
) -> Result<bool, InspectError> {
    let output_path = manager.output_path(sha256_hex);
    let Some(stamp) = output_stamp(&output_path).await? else {
        return Ok(false);
    };
    if read_fresh_metadata(manager, sha256_hex, stamp)
        .await
        .is_some()
    {
        return Ok(true);
    }

    let Some(cached) = read_functions_metadata(manager, sha256_hex, &output_path, stamp).await?
    else {
        return Ok(false);
    };
    let ready = is_ready_extract_metadata(&cached);
    if ready {
        write_cached_metadata(manager, &cached, stamp).await;
    }
    Ok(ready)
}

async fn read_functions_metadata(
    manager: &ProjectManager,
    sha256_hex: &str,
    output_path: &Path,
    stamp: OutputStamp,
) -> Result<Option<CachedBinary>, InspectError> {
    let project_dir = manager.project_dir(sha256_hex);
    let bytes = match tokio::fs::read(output_path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(InspectError::io(output_path, err)),
    };
    let header: EnvelopeHeader =
        serde_json::from_slice(&bytes).map_err(|e| InspectError::parse(output_path, e))?;
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
        last_modified_unix: stamp.last_modified_unix(),
    }))
}

async fn read_fresh_metadata(
    manager: &ProjectManager,
    sha256_hex: &str,
    stamp: OutputStamp,
) -> Option<CachedBinary> {
    let metadata_path = manager.metadata_path(sha256_hex);
    let bytes = tokio::fs::read(&metadata_path).await.ok()?;
    let metadata: CachedBinaryMetadata = serde_json::from_slice(&bytes).ok()?;
    if !metadata_matches(&metadata, sha256_hex, stamp) {
        return None;
    }
    Some(cached_binary_from_metadata(
        manager, sha256_hex, metadata, stamp,
    ))
}

async fn write_cached_metadata(
    manager: &ProjectManager,
    cached: &CachedBinary,
    stamp: OutputStamp,
) {
    if !is_ready_extract_metadata(cached) {
        return;
    }
    let metadata_path = manager.metadata_path(&cached.sha256);
    let metadata = CachedBinaryMetadata {
        schema: CACHED_METADATA_SCHEMA.to_string(),
        cache_key: cached.cache_key.clone(),
        sha256: cached.sha256.clone(),
        functions_schema: cached.schema.clone(),
        program_name: cached.program_name.clone(),
        program_path: cached.program_path.clone(),
        function_count: cached.function_count,
        error_count: cached.error_count,
        output_len: stamp.len,
        output_modified_unix_nanos: stamp.modified_unix_nanos,
    };
    let Ok(json) = serde_json::to_vec_pretty(&metadata) else {
        return;
    };
    if let Some(parent) = metadata_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let _ = tokio::fs::write(metadata_path, json).await;
}

fn metadata_matches(metadata: &CachedBinaryMetadata, sha256_hex: &str, stamp: OutputStamp) -> bool {
    metadata.schema == CACHED_METADATA_SCHEMA
        && metadata.sha256.eq_ignore_ascii_case(sha256_hex)
        && metadata.cache_key == cache_key(sha256_hex)
        && metadata.functions_schema == EXTRACT_FUNCTIONS_SCHEMA
        && !metadata.program_name.is_empty()
        && metadata.output_len == stamp.len
        && metadata.output_modified_unix_nanos == stamp.modified_unix_nanos
}

fn cached_binary_from_metadata(
    manager: &ProjectManager,
    sha256_hex: &str,
    metadata: CachedBinaryMetadata,
    stamp: OutputStamp,
) -> CachedBinary {
    let project_dir = manager.project_dir(sha256_hex);
    let output_path = manager.output_path(sha256_hex);
    CachedBinary {
        cache_key: cache_key(sha256_hex),
        sha256: sha256_hex.to_string(),
        schema: metadata.functions_schema,
        program_name: metadata.program_name,
        program_path: metadata.program_path,
        function_count: metadata.function_count,
        error_count: metadata.error_count,
        project_dir: project_dir.display().to_string(),
        output_path: output_path.display().to_string(),
        last_modified_unix: stamp.last_modified_unix(),
    }
}

fn is_ready_extract_metadata(cached: &CachedBinary) -> bool {
    cached.schema == EXTRACT_FUNCTIONS_SCHEMA && !cached.program_name.is_empty()
}

async fn output_stamp(path: &Path) -> Result<Option<OutputStamp>, InspectError> {
    let metadata = match tokio::fs::metadata(path).await {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(InspectError::io(path, err)),
    };
    if !metadata.is_file() {
        return Ok(None);
    }
    Ok(Some(OutputStamp {
        len: metadata.len(),
        modified_unix_nanos: metadata
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos()),
    }))
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
