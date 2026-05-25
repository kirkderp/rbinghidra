## 2024-05-15 - Fast-path sanitization optimization

**Learning:** Returning `String` from `sanitize_project_name` and `sanitize_query_for_filename` was allocating memory even when strings didn't contain characters that needed sanitizing (the "fast-path"), causing unnecessary memory allocations. Replacing the `String` return type with `Cow<'_, str>` prevents this overhead and yields ~40-50% speedup on safe strings. The performance gain was measurable in microbenchmarks.
**Action:** When writing fast-path string mutation functions that often don't need to mutate anything, prefer returning `std::borrow::Cow<'_, str>` rather than `String` to avoid allocations on the fast path.
