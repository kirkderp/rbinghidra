use std::path::PathBuf;

use serde::Serialize;
use thiserror::Error;

use crate::inspect::{InspectError, get_cached_metadata};
use crate::project::ProjectManager;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeleteReport {
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

/// Delete cached metadata, project files, and derived indexes for a binary.
///
/// # Errors
///
/// Returns an error if the binary cannot be resolved, the cache lock is already
/// held, or any cached path cannot be removed.
pub async fn delete_cached_binary(
    manager: &ProjectManager,
    query: &str,
) -> Result<DeleteReport, DeleteError> {
    let cached = get_cached_metadata(manager, query).await?;
    let sha256_hex = cached.sha256.clone();
    let project_dir = manager.project_dir(&sha256_hex);

    let lock = manager.lock_for(&sha256_hex);
    let _guard = lock.try_lock_owned().map_err(|_| DeleteError::LockHeld {
        sha256: sha256_hex.clone(),
    })?;

    let deleted = match tokio::fs::remove_dir_all(&project_dir).await {
        Ok(()) => true,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => return Err(DeleteError::io(&project_dir, err)),
    };

    let _ = manager.release_lock(&sha256_hex);

    Ok(DeleteReport {
        cache_key: cached.cache_key,
        sha256: cached.sha256,
        program_name: cached.program_name,
        project_dir: project_dir.display().to_string(),
        deleted,
    })
}
