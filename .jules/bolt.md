## 2025-02-18 - Arc cloning on Mutex guards
**Learning:** Checking lock status without taking ownership was cloning `Arc<Mutex<()>>` unnecessarily by using `.try_lock_owned().is_err()`. It is faster to directly call `.try_lock().is_err()` on a reference since it avoids atomic operations.
**Action:** Prefer `try_lock()` on `Mutex` references over `try_lock_owned()` unless you explicitly need an `OwnedMutexGuard`. When filtering `DashMap` iterations, perform checks using `.value()` rather than `.clone()` to avoid allocating memory for skipped entries.
