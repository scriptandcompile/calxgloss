//! Control flow signature matching.
//!
//! This module will provide `CfgPatternMatcher`, which scans decompiled
//! function bodies against control flow signatures — comparison sort,
//! binary search, linear search, hash table lookup, state machine,
//! recursion, and linked list traversal. Each signature is an
//! `AlgorithmPattern`: a named bundle of regexes (configurable match and
//! exclude patterns) with a minimum line-count floor that keeps tiny
//! functions from accidentally fitting a broad shape.
