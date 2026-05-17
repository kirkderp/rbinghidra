use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use tempfile::Builder as TempBuilder;

use crate::error::{ToolError, ToolResult};

pub const MAX_INLINE_CHARS: usize = 200_000;
pub const OVERFLOW_TTL: Duration = Duration::from_secs(3600);
pub const OVERFLOW_PREFIX: &str = "mcp_";
pub const OVERFLOW_PREVIEW_CHARS: usize = 2000;

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum GuardedOutput {
    Inline(String),
    Overflow(OverflowSummary),
}

#[derive(Debug, Clone, Serialize)]
pub struct OverflowSummary {
    pub overflow: bool,
    pub message: String,
    pub file_path: PathBuf,
    pub preview: String,
    pub total_chars: usize,
}

#[derive(Debug, Clone)]
pub struct OutputGuard {
    overflow_dir: PathBuf,
    max_inline_chars: usize,
    ttl: Duration,
}

impl OutputGuard {
    pub fn new(overflow_dir: impl Into<PathBuf>) -> Self {
        Self {
            overflow_dir: overflow_dir.into(),
            max_inline_chars: MAX_INLINE_CHARS,
            ttl: OVERFLOW_TTL,
        }
    }

    #[must_use]
    pub const fn with_max_inline_chars(mut self, limit: usize) -> Self {
        self.max_inline_chars = limit;
        self
    }

    #[must_use]
    pub const fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    #[must_use]
    pub fn overflow_dir(&self) -> &Path {
        &self.overflow_dir
    }

    #[must_use]
    pub const fn max_inline_chars(&self) -> usize {
        self.max_inline_chars
    }

    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Return text inline or spill it to the overflow directory when it is too large.
    ///
    /// # Errors
    ///
    /// Returns an error if the overflow directory cannot be created or written.
    pub fn guard_str(&self, label: &str, text: impl Into<String>) -> ToolResult<GuardedOutput> {
        let text = text.into();
        if text.chars().count() <= self.max_inline_chars {
            return Ok(GuardedOutput::Inline(text));
        }
        self.sweep();
        let summary = self.write_overflow(label, &text)?;
        Ok(GuardedOutput::Overflow(summary))
    }

    /// Serialize JSON and pass it through the same output guard.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or overflow output cannot be written.
    pub fn guard_json<T: Serialize>(&self, label: &str, value: &T) -> ToolResult<GuardedOutput> {
        let text = serde_json::to_string(value)?;
        self.guard_str(label, text)
    }

    pub fn sweep(&self) {
        let Ok(entries) = fs::read_dir(&self.overflow_dir) else {
            return;
        };
        let now = SystemTime::now();
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with(OVERFLOW_PREFIX) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            let Ok(modified) = meta.modified() else {
                continue;
            };
            if now.duration_since(modified).unwrap_or_default() > self.ttl {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    fn write_overflow(&self, label: &str, text: &str) -> ToolResult<OverflowSummary> {
        fs::create_dir_all(&self.overflow_dir).map_err(|e| ToolError::io(&self.overflow_dir, e))?;
        let prefix = format!("{OVERFLOW_PREFIX}{label}_");
        let mut temp = TempBuilder::new()
            .prefix(&prefix)
            .suffix(".txt")
            .tempfile_in(&self.overflow_dir)
            .map_err(|e| ToolError::io(&self.overflow_dir, e))?;
        temp.write_all(text.as_bytes())
            .map_err(|e| ToolError::io(temp.path(), e))?;
        let (_file, path) = temp
            .keep()
            .map_err(|e| ToolError::io(&self.overflow_dir, e.error))?;

        let preview: String = text.chars().take(OVERFLOW_PREVIEW_CHARS).collect();
        let total_chars = text.chars().count();
        let ttl_min = self.ttl.as_secs() / 60;
        let message = format!(
            "Output too large ({} chars). Full result saved to: {}\n\
             NOTE: This file is temporary and will be auto-deleted after {ttl_min} minutes. \
             Copy or move it if you need to keep it.",
            format_with_commas(total_chars),
            path.display()
        );
        Ok(OverflowSummary {
            overflow: true,
            message,
            file_path: path,
            preview,
            total_chars,
        })
    }
}

fn format_with_commas(n: usize) -> String {
    let digits: Vec<char> = n.to_string().chars().collect();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.iter().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*c);
    }
    out
}
