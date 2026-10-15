//! Caller-supplied callable signatures that deepen the scan's suggestions.
//!
//! A registration or chain finding names the callback it binds, but the
//! closure it suggests stays open — `Box<dyn Fn(...)>` — because no
//! single body spells the callback's contract. The type-inference scan
//! reads that contract piecemeal across the binary: parameter records
//! from the bodies that use them, a return record from the callers that
//! consume the value. A caller of this crate (the CLI `callback`
//! command, the batch pre-analysis) composes those records into a
//! [`SignatureMap`] and injects it through
//! [`with_signatures`](crate::engine::CallbackEngine::with_signatures);
//! this module owns the map's shape and the rendering that fills the
//! placeholder in.
//!
//! The callback crate never reads the type-inference document itself —
//! the integration is injection only, so no dependency on the
//! type-inference crate lands here (ADR-0036). An empty map, or a name
//! the map does not carry, leaves every suggestion exactly as the
//! detectors wrote it.

use std::collections::HashMap;

/// The known callable contract of one named function, as C text.
///
/// The record shape the injecting caller composes from the type-
/// inference scan's per-function readings: the parameter types in
/// parameter order, and the return type when one was read. Types are
/// carried as the narrowed C text the inference produced (`i32`,
/// `char *`) — this crate renders them into the Rust closure contract
/// verbatim, so the caller never pre-translates anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallableSignature {
    /// Parameter types in parameter order. A signature with no known
    /// parameters carries no entry at all rather than an empty list:
    /// the inference records cannot tell a zero-parameter callback
    /// from one whose parameters were never read, and `Fn()` would
    /// assert an arity nobody read (ADR-0036).
    pub param_types: Vec<String>,
    /// The return type as C text, `None` when no return reading
    /// stands. A `void` return rides as `Some("void")` and drops its
    /// clause at render time — the decision is the renderer's, so a
    /// hand-built map gets the same contract as a composed one.
    pub return_type: Option<String>,
}

impl CallableSignature {
    /// The Rust closure contract this signature renders: `Fn(i32) ->
    /// bool`, with the parameter types joined in order and a `void`
    /// return dropping its clause — Rust's implicit unit needs no
    /// arrow, and `-> void` is not valid Rust.
    pub fn contract(&self) -> String {
        let params = self.param_types.join(", ");
        match self.return_type.as_deref() {
            Some(return_type) if return_type != "void" => {
                format!("Fn({params}) -> {return_type}")
            }
            _ => format!("Fn({params})"),
        }
    }
}

/// A map of function name to its known callable contract.
///
/// Keyed by the callback's spelled name — the same spelling the
/// registration detector bound — so the engine's lookup needs no
/// normalization beyond what the decompiler itself printed.
pub type SignatureMap = HashMap<String, CallableSignature>;

/// Deepen `suggestion`'s `Fn(...)` placeholder with `signature`'s
/// real contract, replacing the first placeholder only.
///
/// The registration and chain suggestions share the `Fn(...)`
/// placeholder in their templates, so one substitution point keeps
/// the templates the source of truth for everything around the
/// contract; a suggestion carrying no placeholder (a `match` for a
/// jump table, a `Vec` for an fp array) passes through untouched.
pub fn enrich_suggestion(suggestion: &str, signature: &CallableSignature) -> String {
    suggestion.replacen("Fn(...)", &signature.contract(), 1)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn signature(params: &[&str], return_type: Option<&str>) -> CallableSignature {
        CallableSignature {
            param_types: params.iter().map(|param| (*param).to_string()).collect(),
            return_type: return_type.map(|return_type| return_type.to_string()),
        }
    }

    #[test]
    fn a_contract_renders_its_parameters_and_return() {
        assert_eq!(
            signature(&["i32"], Some("bool")).contract(),
            "Fn(i32) -> bool"
        );
        assert_eq!(
            signature(&["char *", "u32"], Some("void *")).contract(),
            "Fn(char *, u32) -> void *"
        );
    }

    #[test]
    fn a_void_return_drops_its_clause() {
        // Rust's implicit unit needs no arrow: `-> void` would be a
        // syntax error in the contract the suggestion recommends.
        assert_eq!(signature(&["i32"], Some("void")).contract(), "Fn(i32)");
    }

    #[test]
    fn an_unknown_return_renders_without_a_clause() {
        // No return reading stands: the contract carries what was
        // read and nothing more.
        assert_eq!(signature(&["i32"], None).contract(), "Fn(i32)");
    }

    #[test]
    fn enrichment_fills_the_registration_placeholder() {
        assert_eq!(
            enrich_suggestion("Box<dyn Fn(...)>", &signature(&["i32"], Some("bool"))),
            "Box<dyn Fn(i32) -> bool>"
        );
    }

    #[test]
    fn enrichment_fills_the_placeholder_inside_longer_prose() {
        // The chain template wraps the same placeholder in its own
        // sentence; only the placeholder moves.
        assert_eq!(
            enrich_suggestion(
                "Box<dyn Fn(...)> shared between the registering and calling functions",
                &signature(&["i32"], Some("bool")),
            ),
            "Box<dyn Fn(i32) -> bool> shared between the registering and calling functions"
        );
    }

    #[test]
    fn a_suggestion_without_a_placeholder_passes_through() {
        assert_eq!(
            enrich_suggestion(
                "match over the table index",
                &signature(&["i32"], Some("bool"))
            ),
            "match over the table index"
        );
    }
}
