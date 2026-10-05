//! Allocation/deallocation pair tracking.
//!
//! This module will provide `AllocatorTracker`, which detects
//! `malloc`/`calloc`/`realloc` → `free` pairs within a function and
//! suggests `Box<T>` or stack allocation for short-lived allocations.
