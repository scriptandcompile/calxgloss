//! Cross-function known-library propagation over the kept bodies.
//!
//! The per-function matcher reads one body at a time: it can only name
//! a function whose own body carries a signature's shape. This module
//! fills that gap using the kept bodies one scan already holds, like
//! the memory crate's cross-function pass (ADR-0027), the sync crate's
//! (ADR-0033), and the callback crate's (ADR-0035). Its readings come
//! from the fetched bodies, using the same normalization the matcher
//! already performs, so it makes no new
//! [`ScanSource`](crate::engine::ScanSource) reads. The
//! exactly-once-decompile guarantee still holds, and the skip-rate
//! breaker still works: a scan whose decompiles fail for more than
//! half of the function listing still aborts rather than persisting a
//! record that looks clean but is not.
//!
//! [`propagate`] runs the readings. A kept body whose normalized shape
//! is identical to a matched body's is the same routine: the linker
//! folds template instantiations into one body (COMDAT folding / ICF),
//! so every copy but the first reads identical to the first. The
//! duplicate inherits the claim whole, at the matched body's evidence
//! confidence. When more than one matched body carries the shape, the
//! duplicate inherits from the one listed first; each matched body
//! already carries its function's single strongest claim, decided by
//! [`resolve_matches`](crate::confidence::resolve_matches). The
//! duplicate's evidence is a line from its own decompile, taken from
//! the place where the matched body's evidence line stands, so a
//! reviewer reads the duplicate's decompile, not the parent's.
//!
//! A kept body whose only statement is a call to a claimed function is
//! that function's thunk, and inherits its match at an evidence-
//! confidence penalty. The reading repeats until no new claim appears,
//! so a whole chain of thunks inherits from the matched end, and the
//! penalty is paid once per chain, not per hop. Cross-function
//! findings — identical-body duplicates first, then thunks — are
//! appended after every per-function finding, each group in listing
//! order.
//!
//! The pass's internals — the shape keys and the call readings — are
//! never tested directly: scan findings are the test surface, as with
//! the [normalize](crate::normalize) module.

use std::collections::HashMap;
use std::sync::LazyLock;

use calxgloss_decomp::DecompiledFunction;
use regex::Regex;

use crate::confidence::TAIL_CALL_CONFIDENCE_PENALTY;
use crate::normalize::normalize_lines;
use crate::types::{Confidence, LibmatchFinding, LibmatchMatch};

/// Propagate matches across the scan's kept bodies.
///
/// `matched` is the resolved per-function findings — at most one claim
/// per function — and `bodies` is the decompiles the scan kept, in
/// listing order. A body that already carries a claim is never
/// re-claimed: propagation only names the bodies the per-function
/// pass left without a finding. The returned findings come in two
/// groups — identical-body duplicates first, then thunks — each in
/// listing order, and they are appended after every per-function
/// finding in the persisted result.
pub(crate) fn propagate(
    bodies: &[DecompiledFunction],
    matched: &[LibmatchFinding],
) -> Vec<LibmatchFinding> {
    let pairings: Vec<Vec<(String, String)>> = bodies
        .iter()
        .map(|body| normalize_lines(&body.body))
        .collect();
    let keys: Vec<String> = pairings
        .iter()
        .zip(bodies)
        .map(|(pairing, body)| body_key(&body.name, pairing))
        .collect();

    let mut claims: HashMap<String, LibmatchFinding> = matched
        .iter()
        .map(|finding| (finding.function().to_string(), finding.clone()))
        .collect();

    // For each normalized shape, the claimed body that has it earliest
    // in the listing, by listing index. The map is built whole before
    // any inherited finding is added, so a duplicate standing before
    // its matched twin in the listing still inherits.
    let mut shape_owner: HashMap<&str, usize> = HashMap::new();
    for (index, body) in bodies.iter().enumerate() {
        if claims.contains_key(body.name.as_str()) {
            shape_owner.entry(keys[index].as_str()).or_insert(index);
        }
    }

    let mut propagated = Vec::new();
    for (index, body) in bodies.iter().enumerate() {
        if claims.contains_key(body.name.as_str()) {
            continue;
        }
        let Some(&owner) = shape_owner.get(keys[index].as_str()) else {
            continue;
        };
        let evidence = inherited_evidence(
            &pairings[owner],
            &pairings[index],
            claims[bodies[owner].name.as_str()].evidence(),
        );
        let parent = &claims[bodies[owner].name.as_str()];
        let finding = LibmatchFinding::IdenticalBody(inherited_match(
            parent,
            &body.name,
            parent.confidence(),
            evidence,
        ));
        claims.insert(body.name.clone(), finding.clone());
        propagated.push(finding);
    }

    // A body whose only statement is a call to a claimed function is
    // that function's thunk, and inherits its match at the penalty.
    // The reading repeats until no new claim appears, so a chain of
    // thunks — each body only a tail call to the next — all inherits
    // from the matched end, and the penalty is paid once per chain,
    // not per hop: a thunk calling an inherited thunk copies that
    // finding's already-penalized score, so the whole chain stands at
    // one evidence confidence and collapses into the same downstream
    // decision. Claims are added while the loop repeats; the findings
    // are emitted in one listing-order pass afterwards.
    loop {
        let mut inherited = false;
        for (index, body) in bodies.iter().enumerate() {
            if claims.contains_key(body.name.as_str()) {
                continue;
            }
            let Some((callee, evidence)) = sole_tail_call(&pairings[index]) else {
                continue;
            };
            let Some(parent) = claims.get(&callee) else {
                continue;
            };
            let confidence = if matches!(parent, LibmatchFinding::TailCallThunk(_)) {
                parent.confidence()
            } else {
                Confidence::new(
                    parent
                        .confidence()
                        .value()
                        .saturating_sub(TAIL_CALL_CONFIDENCE_PENALTY),
                )
            };
            let finding = LibmatchFinding::TailCallThunk(inherited_match(
                parent, &body.name, confidence, evidence,
            ));
            claims.insert(body.name.clone(), finding);
            inherited = true;
        }
        if !inherited {
            break;
        }
    }

    for body in bodies {
        if let Some(finding @ LibmatchFinding::TailCallThunk(_)) = claims.get(body.name.as_str()) {
            propagated.push(finding.clone());
        }
    }
    propagated
}

/// The shape two bodies must share to be the same routine: the
/// normalized lines inside the decompile's braces, with the function's
/// own name replaced by a placeholder. The prototype line sits outside
/// the span because Ghidra renders folded copies' prototypes
/// differently — a second copy often arrives named `thunk_…` — and the
/// function's own name sits inside the span, so it gets replaced,
/// because a folded copy's self-calls mention that copy's own name.
fn body_key(name: &str, pairing: &[(String, String)]) -> String {
    let (start, end) = brace_span(pairing);
    let own_name = regex::Regex::new(&format!(r"\b{}\b", regex::escape(name)))
        .expect("an escaped function name is a valid regex");
    pairing[start..end]
        .iter()
        .map(|(_, line)| own_name.replace_all(line, "{self}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The span of the decompile's brace-enclosed statements: the lines
/// between the opening and closing brace lines, or the whole body when
/// the decompile has no braces.
fn brace_span(pairing: &[(String, String)]) -> (usize, usize) {
    match (
        pairing.iter().position(|(_, line)| line == "{"),
        pairing.iter().rposition(|(_, line)| line == "}"),
    ) {
        (Some(open), Some(close)) if close > open => (open + 1, close),
        _ => (0, pairing.len()),
    }
}

/// A single call statement, optionally `return`ed: the callee name is
/// the first capture. An assignment (`VAR = FUN_x();`) or a control-flow
/// keyword (`if (...)`) is not a call statement — the line must *be*
/// the call.
static SOLE_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:return\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\);?$")
        .expect("the sole-call pattern is a valid regex")
});

/// Find the sole call a thunk body contains. When the body's
/// statements — with empty lines and bare `return;`s dropped — are
/// exactly one line, and that line is a call, the answer is that
/// call's callee name plus the body's own line as the finding's
/// evidence. A body that does more than call, or that has no call at
/// all, is not a thunk: the answer is `None`.
fn sole_tail_call(pairing: &[(String, String)]) -> Option<(String, String)> {
    let (start, end) = brace_span(pairing);
    let statements: Vec<&(String, String)> = pairing[start..end]
        .iter()
        .filter(|(_, line)| !line.is_empty() && line != "return;")
        .collect();
    let [(original, normalized)] = statements.as_slice() else {
        return None;
    };
    let callee = SOLE_CALL.captures(normalized)?.get(1)?;
    Some((callee.as_str().to_string(), original.clone()))
}

/// The match one body inherits from a claimed parent: the parent's
/// symbol, family, and suggestion, at the given `confidence`, with the
/// inheriting body's own `evidence` line. The parent's admission note —
/// what the match says about its own version authority (P19-3) — is
/// inherited with the claim: a propagated match admits exactly what the
/// match it was inherited from admits.
fn inherited_match(
    parent: &LibmatchFinding,
    function: &str,
    confidence: Confidence,
    evidence: String,
) -> LibmatchMatch {
    LibmatchMatch {
        function: function.to_string(),
        symbol: parent.target().to_string(),
        family: parent.family(),
        suggestion: parent.suggestion().to_string(),
        confidence,
        evidence,
        admission: (!parent.admission().is_empty()).then(|| parent.admission().to_string()),
    }
}

/// The inheriting body's evidence: the line standing where the matched
/// body's evidence line stands, taken from the duplicate's own
/// decompile. Identical shapes line up brace line to brace line, so
/// the position of the matched body's evidence line within its brace
/// span is also the position of the duplicate's matching line. When
/// that lookup misses — an evidence line outside the brace span (a
/// signature pattern that matched the prototype) or a span that runs
/// short — the duplicate's first brace statement stands in instead, so
/// the finding still quotes the duplicate's own decompile.
fn inherited_evidence(
    parent: &[(String, String)],
    duplicate: &[(String, String)],
    evidence: &str,
) -> String {
    let (parent_open, parent_close) = brace_span(parent);
    let (duplicate_open, duplicate_close) = brace_span(duplicate);
    parent[parent_open..parent_close]
        .iter()
        .position(|(original, _)| original == evidence)
        .and_then(|offset| duplicate.get(duplicate_open + offset))
        .or_else(|| duplicate[duplicate_open..duplicate_close].first())
        .map(|(original, _)| original.clone())
        .unwrap_or_else(|| evidence.to_string())
}
