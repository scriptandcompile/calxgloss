//! Parameter size detection.
//!
//! This module will provide `ParameterSizeDetector`, which scans decompiled
//! text for dereference and pointer-arithmetic patterns, string-function
//! calls (`strlen`, `strcpy`, `strcmp`, ...), and integer bit-pattern usage
//! (shifts, bitwise AND) to narrow each parameter to a pointer, string, or
//! integer width. When several readings compete for one parameter, the
//! highest-confidence one wins.
