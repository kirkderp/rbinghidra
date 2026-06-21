use std::path::{Component, Path, PathBuf};

use crate::error::{ToolError, ToolResult};

#[derive(Debug, Clone)]
pub struct CachePaths {
    root: PathBuf,
}

impl CachePaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Build cache paths from `RBM_CACHE_DIR` or default to `./rbinghidra-cache/`.
    ///
    /// # Errors
    ///
    /// Returns an error only if `RBM_CACHE_DIR` is set to an empty string.
    pub fn from_env() -> ToolResult<Self> {
        if let Ok(val) = std::env::var("RBM_CACHE_DIR") {
            if val.is_empty() {
                return Err(ToolError::Other("RBM_CACHE_DIR must not be empty".into()));
            }
            return Ok(Self::new(absolute_cache_root(PathBuf::from(val))?));
        }
        Ok(Self::new(absolute_cache_root(PathBuf::from(
            "./rbinghidra-cache",
        ))?))
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn ghidra_dir(&self) -> PathBuf {
        self.root.join("ghidra")
    }

    /// Create cache subdirectories used by the server.
    ///
    /// # Errors
    ///
    /// Returns an error if any directory cannot be created.
    pub fn ensure_all(&self) -> ToolResult<()> {
        let dir = self.ghidra_dir();
        std::fs::create_dir_all(&dir).map_err(|e| ToolError::io(&dir, e))?;
        Ok(())
    }
}

fn absolute_cache_root(path: PathBuf) -> ToolResult<PathBuf> {
    let path = if path.is_absolute() {
        path
    } else {
        let cwd = std::env::current_dir().map_err(|e| ToolError::io(".", e))?;
        cwd.join(path)
    };
    Ok(normalize_lexically(&path))
}

fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(_) | Component::RootDir | Component::Prefix(_) => {
                out.push(component.as_os_str());
            }
        }
    }
    out
}
