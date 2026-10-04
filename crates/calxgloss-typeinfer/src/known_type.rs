//! Known type propagation.
//!
//! This module will provide `KnownTypePropagationEngine`, which extracts
//! calls from decompiled text and propagates parameter types through a
//! signature database of well-known library functions — `malloc`, `free`,
//! `realloc`, `strlen`, `strcmp`, `strcpy`, `memcpy`, `memset`,
//! `CloseHandle`, `CreateFileW` — matching names with A/W-suffix support
//! and applying per-signature confidence scores.
