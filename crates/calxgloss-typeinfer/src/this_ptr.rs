//! C++ this-pointer detection.
//!
//! This module will provide `ThisPointerDetector`, which parses decompiled
//! output for `vtable[index]` call patterns and first-parameter usage to
//! recognize member functions, extracts the class name from vtable function
//! names, filters namespace false positives (`std::`, `operator::`), and
//! detects IUnknown-derived COM interfaces.
