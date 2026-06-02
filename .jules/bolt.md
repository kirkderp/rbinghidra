## 2024-05-24 - Avoid Vec Allocation During Directory Traversal
**Learning:** In the `rbinghidra` Rust codebase, when searching for a specific file (like `.gpr`) in a project directory using `tokio::fs::read_dir`, avoid collecting all directory entries into a `Vec`. This causes unnecessary memory allocations, especially in directories with many files.
**Action:** Instead of collecting entries into a `Vec`, use streaming iteration with `next_entry()` and return early as soon as the target file is found. This prevents unnecessary memory allocations and improves performance.
