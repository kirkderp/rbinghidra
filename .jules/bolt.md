## 2025-01-20 - Streaming directory iteration
**Learning:** In Rust using tokio, `tokio::fs::read_dir` returns a stream. Using `.next_entry()` rather than collecting all entries into a vector limits memory overhead and unnecessary processing when the file system interaction seeks a single known extension (like `.gpr`).
**Action:** When searching directories for specific files, avoid `let entries: Vec<String> = ...` and use streaming iteration with early returns where possible.
