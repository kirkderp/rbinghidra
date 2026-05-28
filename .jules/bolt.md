## 2024-05-28
**Title**: Iterator Optimization in Ghidra Cache Inspector
**Learning**: Allocating an entire collection into a `Vec` just to check `.len()` or `.next()` is expensive and unnecessary, especially when filtering a large number of directories or cache entries. Using lazy iterators with `.next()` and `.count()` provides the same logic (checking for exactly one match, or counting ambiguous matches) without heap allocations for the intermediate collection.
**Action**: Replaced `.collect::<Vec<_>>()` with a direct lazy iterator check in `rbm-ghidra::inspect::get_cached_metadata`. Microbenchmarks confirmed a minor latency reduction and the elimination of unnecessary memory allocations for normal queries.
