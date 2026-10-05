//! Reference counting detection.
//!
//! This module will detect reference count increments and decrements —
//! `ref_count++`/`ref_count--` field arithmetic and the COM
//! `AddRef`/`Release` pair — reading where the count lives and who
//! bumps it so the prompt can suggest `Rc<T>` for single-threaded
//! ownership and `Arc<T>` when the count crosses threads.
