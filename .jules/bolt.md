# Performance Learnings

## 2025-05-18: OutputGuard Sweep Stalls

*   **Learning:** Synchronous file system sweeps on the main execution thread can introduce measurable delays (several milliseconds) and stall async context event loops when dealing with many files. Moving such cleanups to an asynchronous background thread significantly improves the latency of the hot path, effectively removing it as a bottleneck.
*   **Action:** Wrapping the blocking file operations in `std::thread::spawn` mitigates the issue while preserving the correctness and cleanup guarantees.
