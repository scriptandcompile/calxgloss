//! The seam's error vocabulary — the failure facts every engine's reads fold into.
//!
//! Kuna is the only analysis engine (issue #214, ADR-0041), and its named
//! failures are folded into this vocabulary at the seam (ADR-0039's fold): a
//! missing function, type, or byte range is [`EngineError::NotFound`] and a
//! kind mismatch [`EngineError::Malformed`] — the same facts the old Ghidra
//! bridge reported, so layout probes and retry logic branch on one vocabulary
//! whichever engine answers. Every other engine failure arrives as
//! [`EngineError::Reported`] carrying the engine's own self-explaining message.

use thiserror::Error;

/// Errors from the scan seam, whichever engine answers the reads.
#[derive(Debug, Error)]
pub enum EngineError {
    /// The engine answered, and its answer was an explanation rather than a
    /// result.
    ///
    /// The message is the engine's own — Kuna's failures are named and
    /// self-explaining, so this variant usually carries the whole diagnosis.
    #[error("the engine reported an error: {message}")]
    Reported { message: String },

    /// Nothing in the loaded program matched the request.
    #[error("the engine has no {kind} matching '{query}'")]
    NotFound { kind: &'static str, query: String },

    /// An answer was a result but did not have the shape the read promises.
    #[error("could not read {kind} from the engine's answer: {detail}")]
    Malformed { kind: &'static str, detail: String },
}

/// The result type every seam read answers with.
pub type Result<T> = std::result::Result<T, EngineError>;

/// Fold a Kuna engine failure into the seam's error vocabulary (ADR-0039).
///
/// A missing function or type is the same fact in the same shape — consumers
/// already branch on [`NotFound`](Self::NotFound) for a bad name, and the
/// typesdb scanner's layout probes read a kind mismatch as
/// [`Malformed`](Self::Malformed). Every other Kuna failure is already a
/// named, self-explaining message, so it rides the seam as a
/// [`Reported`](Self::Reported) explanation.
impl From<calxgloss_kuna::error::KunaError> for EngineError {
    fn from(error: calxgloss_kuna::error::KunaError) -> Self {
        match error {
            calxgloss_kuna::error::KunaError::FunctionNotFound { name } => EngineError::NotFound {
                kind: "function",
                query: name,
            },
            calxgloss_kuna::error::KunaError::TypeNotFound { name } => EngineError::NotFound {
                kind: "type",
                query: name,
            },
            calxgloss_kuna::error::KunaError::NotAStruct { name } => EngineError::Malformed {
                kind: "structure layout",
                detail: format!("the Kuna engine's type manager has no structure named '{name}'"),
            },
            calxgloss_kuna::error::KunaError::NotAnEnum { name } => EngineError::Malformed {
                kind: "enumeration",
                detail: format!("the Kuna engine's type manager has no enumeration named '{name}'"),
            },
            calxgloss_kuna::error::KunaError::MemoryUnmapped { address, length } => {
                EngineError::NotFound {
                    kind: "memory",
                    query: format!("{address:#x} ({length} bytes)"),
                }
            }
            other => EngineError::Reported {
                message: other.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_kuna::error::KunaError;

    #[test]
    fn a_kuna_miss_folds_into_a_named_not_found() {
        let err = EngineError::from(KunaError::FunctionNotFound {
            name: "FUN_18003e750".into(),
        });
        assert!(matches!(
            err,
            EngineError::NotFound {
                kind: "function",
                ..
            }
        ));
        assert!(
            err.to_string().contains("FUN_18003e750"),
            "the miss names what was asked for: {err}"
        );
    }

    #[test]
    fn a_kuna_kind_mismatch_folds_into_malformed() {
        let err = EngineError::from(KunaError::NotAStruct {
            name: "COLOR".into(),
        });
        assert!(matches!(err, EngineError::Malformed { .. }));
    }

    #[test]
    fn any_other_kuna_failure_rides_as_reported() {
        let err = EngineError::from(KunaError::EngineFault {
            call: "decompile".into(),
            panic: "boom".into(),
        });
        match err {
            EngineError::Reported { message } => assert!(message.contains("boom")),
            other => panic!("expected Reported, got {other:?}"),
        }
    }
}
