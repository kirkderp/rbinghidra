use std::path::PathBuf;

use thiserror::Error;

pub type ToolResult<T> = Result<T, ToolError>;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("i/o error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{0}")]
    Other(String),
}

impl ToolError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
