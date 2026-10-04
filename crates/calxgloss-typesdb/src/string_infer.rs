//! String-guided struct inference.
//!
//! This module will provide `StringInferenceEngine` with `infer_structures()`,
//! running the full collect → cluster → infer → score pipeline: strings come
//! from the bridge's `list_strings` (regex filter + quality filtering),
//! cross-reference clustering groups them into candidate structs, and
//! confidence scoring filters candidates against a configurable threshold.
