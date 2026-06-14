## 2024-06-14 - Byte-level string sanitization
**Learning:** To optimize string sanitization in hot code paths (e.g., substituting non-alphanumeric characters with `_`), operate directly on byte slices (`&[u8]`) instead of iterating over `String::chars()` to avoid UTF-8 boundary check overhead, then convert back using `String::from_utf8`.
**Action:** When sanitizing ASCII-safe strings for filenames or IDs, prefer iterating over `as_bytes()` and constructing a `Vec<u8>` to avoid UTF-8 boundary checks, rather than iterating via `.chars()`.
