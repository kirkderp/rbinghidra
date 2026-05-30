## 2024-05-18 - Streaming Directory Reads for Targeted Files
**Learning:** In the `rbinghidra` Rust codebase, using `tokio::fs::read_dir` to collect directory entries into a `Vec` just to find a single target file (e.g., the `.gpr` file for project discovery) incurs unnecessary memory allocations and blocks early returns.
**Action:** Always process directory entries using a streaming approach (`while let Some(entry) = entries.next_entry().await`) when searching for specific files to minimize memory footprint and exit immediately upon success.
