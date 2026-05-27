## 2024-05-27 - Premature micro-optimizations rejected
**Learning:** Re-formatting filename logic and introducing new dependencies (`itoa`) for string manipulations in path generation was rejected during code review as "premature micro-optimization of cold paths." String manipulation for paths is fine using standard formatting methods like `format!`, and introducing new workspace-level dependencies for minor optimizations is strongly discouraged.
**Action:** Focus on algorithm complexities or actual data processing loops. Do not micro-optimize `PathBuf` construction. Avoid adding dependencies like `itoa` unless absolutely necessary and approved.

## 2024-05-27 - Fast string sanitization
**Learning:** For string sanitization that iterates byte-by-byte checking properties (like `sanitize_query_for_filename`), using a fast prefix-skip algorithm by finding the index of the first invalid character via `push_str` on string slices (`&query[..i]`) is noticeably faster than iterating over characters. It's safe since the ASCII check guarantees we cut on UTF-8 boundaries.
**Action:** Employ the fast-prefix-skip algorithm when cleaning strings to reduce looping overhead.
