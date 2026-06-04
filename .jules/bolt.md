## 2025-02-27 - Stream File Discovery over Vector Allocation
**Learning:** In the rbinghidra Rust codebase, avoid collecting directory entries into a `Vec` using `tokio::fs::read_dir` when searching for a specific file. Collecting directory entries into a `Vec` forces unnecessary memory allocations.
**Action:** Use streaming iteration with `while let Some(entry) = entries.next_entry().await` and early returns to find specific files to prevent these unnecessary memory allocations.
