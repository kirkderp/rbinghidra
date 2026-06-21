use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub(crate) struct TempDir {
    path: PathBuf,
    keep: bool,
}

impl TempDir {
    /// Creates a unique temporary directory under the process temp directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub(crate) fn new() -> io::Result<Self> {
        let base = std::env::temp_dir();
        let process_id = std::process::id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());

        for _ in 0..100 {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("rbinghidra-test-{process_id}-{timestamp}-{id}"));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path, keep: false }),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create unique temporary directory",
        ))
    }

    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
