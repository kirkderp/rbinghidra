## 2025-05-18 - Avoid collecting directory entries into Vec

**Learning:** When searching for a specific file in a directory using `tokio::fs::read_dir`, collecting all entries into a `Vec` before processing them is inefficient and causes unnecessary memory allocations. Streaming the entries using `.next_entry()` and returning early upon finding the target avoids this overhead.

**Action:** Prefer streaming iteration (`while let Some(entry) = entries.next_entry().await`) and early returns over collecting directory entries into a `Vec` (e.g., `let mut names = Vec::new()`) when searching for specific files or resolving names.
