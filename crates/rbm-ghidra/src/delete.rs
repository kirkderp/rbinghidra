use std::path::PathBuf;

use serde::Serialize;
use thiserror::Error;

use crate::inspect::{InspectError, get_cached_metadata, parse_sha256_lookup};
use crate::project::{ProjectManager, cache_key};

pub const DELETE_SCHEMA: &str = "rbm.ghidra.delete.v0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeleteReport {
    pub schema: &'static str,
    pub cache_key: String,
    pub sha256: String,
    pub program_name: String,
    pub project_dir: String,
    pub deleted: bool,
}

#[derive(Debug, Error)]
pub enum DeleteError {
    #[error(transparent)]
    Inspect(#[from] InspectError),
    #[error(
        "ghidra cache for sha256 {sha256} is locked by an in-flight import; refuse to delete (retry once the import completes)"
    )]
    LockHeld { sha256: String },
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl DeleteError {
    fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Delete cached metadata and project files for a binary.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the cache lock is already
/// held, or any cached path cannot be removed.
pub async fn delete_cached_binary(
    manager: &ProjectManager,
    query: &str,
) -> Result<DeleteReport, DeleteError> {
    let cached = match get_cached_metadata(manager, query).await {
        Ok(cached) => Some(cached),
        Err(InspectError::NotFound(_)) => None,
        Err(err) => return Err(err.into()),
    };
    let sha256_hex = cached
        .as_ref()
        .map(|cached| cached.sha256.clone())
        .or_else(|| parse_sha256_lookup(query))
        .ok_or_else(|| InspectError::NotFound(query.to_string()))?;
    let project_dir = manager.project_dir(&sha256_hex);

    let lock = manager.lock_for(&sha256_hex);
    let _guard = lock.try_lock_owned().map_err(|_| DeleteError::LockHeld {
        sha256: sha256_hex.clone(),
    })?;

    let remove_result = tokio::fs::remove_dir_all(&project_dir).await;
    let _ = manager.release_lock(&sha256_hex);
    let deleted = match remove_result {
        Ok(()) => true,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => return Err(DeleteError::io(&project_dir, err)),
    };

    Ok(DeleteReport {
        schema: DELETE_SCHEMA,
        cache_key: cached
            .as_ref()
            .map_or_else(|| cache_key(&sha256_hex), |cached| cached.cache_key.clone()),
        sha256: sha256_hex,
        program_name: cached.map_or_else(String::new, |cached| cached.program_name),
        project_dir: project_dir.display().to_string(),
        deleted,
    })
}
