//! Callback pattern detection.
//!
//! This module will provide `CallbackPatternDb`, which matches function
//! signatures and usage against callback shapes — qsort compare, bsearch
//! compare, hash table comparator — recognizing the functions that serve
//! as callbacks, with caller name pattern matching through the call
//! graph.
