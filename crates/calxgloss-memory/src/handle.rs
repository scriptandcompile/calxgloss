//! Handle lifecycle detection.
//!
//! This module will detect Windows and POSIX handle creation and
//! closure — `CreateFileW`/`CloseHandle`, `fopen`/`fclose` — pairing
//! each opener with its closer inside a function so the prompt can
//! suggest an RAII guard struct with a `Drop` impl standing in for the
//! manual close.
