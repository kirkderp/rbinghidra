## 2024-05-18 - Faster ASCII validation

**Learning:** When validating string patterns known to be ASCII (e.g., verifying hex strings), using `.chars().all(|c| c.is_ascii_hexdigit())` is sub-optimal. The `chars()` iterator checks for UTF-8 boundaries. By operating on bytes via `.as_bytes().iter().all(u8::is_ascii_hexdigit)` we avoid these overheads and the `is_ascii_hexdigit` checks can sometimes be better vectorized or faster without decoding overheads, which provides a noticeable micro-optimization.

**Action:** Whenever iterating over characters in strings strictly to check ASCII-based properties, use `.as_bytes().iter().all(u8::is_ascii_X)` instead.
