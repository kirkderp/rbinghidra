## 2024-05-19 - Single-pass search streaming

**Learning:** When evaluating search queries where the result is immediately known from an iterator, avoid using `collect()` into a memory-intensive collection like `Vec` as it introduces overhead, particularly if the evaluation list is large. Instead, stream the iterator elements and employ short-circuit evaluation logic.

**Action:** Whenever parsing data strictly for lookup purposes (like scanning multiple strings to find a preferred match), prioritize using `for element in iterator { ... }` loops containing early returns directly instead of evaluating the whole text before searching for the match.
