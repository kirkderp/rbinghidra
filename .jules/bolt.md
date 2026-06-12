## 2024-05-24 - Avoid UTF-8 decoding for static ASCII sanitization
**Learning:** In hot code paths, avoiding `String::chars()` iteration for simple input sanitization (like substituting non-alphanumeric characters with `_`) saves significant overhead by skipping UTF-8 boundary checks.
**Action:** When mapping unknown input strings to guaranteed-ASCII constants, convert the string to a byte slice `&[u8]` and process it directly, then use `String::from_utf8` on the resulting buffer to skip decoding/encoding costs.
