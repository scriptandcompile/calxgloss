//! Loop structure detection.
//!
//! The loop shapes Ghidra's pseudo-C leaves behind — counted `for`,
//! conditional `while`, `do { } while`, and `goto`-back-to-label loops —
//! are read off the per-body control flow graph, not re-scanned from the
//! text, so the loop count, the nesting depth, and (later) the density
//! and depth readings all come off one graph and cannot disagree.
//!
//! One finding lands per function, not per loop: the loop count, the
//! maximum nesting depth, and the kinds seen. A spelled-out loop header
//! is strong evidence (confidence 70); a body whose only loops are
//! goto-driven is the weaker inference of a flattened loop (60).
//! Nesting comes out at its real depth — a loop inside a chain case
//! body reads deeper than a top-level loop, so a chain reading and a
//! loop reading never contradict each other.

use calxgloss_types::Confidence;

use crate::cfg::Cfg;
use crate::types::{LoopKind, LoopNesting};

/// Detector for the loop structure of one decompiled body.
#[derive(Debug, Clone)]
pub struct LoopDetector {
    /// Minimum number of loops a body must carry to be reported.
    min_loops: usize,
}

impl Default for LoopDetector {
    fn default() -> Self {
        Self { min_loops: 1 }
    }
}

impl LoopDetector {
    /// Create a detector with the default threshold (one loop reports).
    pub fn new() -> Self {
        Self::default()
    }

    /// Lower or raise the loop count a body needs to be reported.
    pub fn with_min_loops(mut self, min_loops: usize) -> Self {
        self.min_loops = min_loops;
        self
    }

    /// The loop count a body must carry to be reported.
    pub fn min_loops(&self) -> usize {
        self.min_loops
    }

    /// Read the loop structure of one decompiled function body off its
    /// control flow graph: one finding for the whole body, or none when
    /// the graph shows no loops (or fewer than `min_loops`).
    pub(crate) fn detect(&self, name: &str, code: &str) -> Option<LoopNesting> {
        let cfg = Cfg::build(code);
        let loops = cfg.loops();
        if loops.is_empty() || loops.len() < self.min_loops {
            return None;
        }

        // Depths are the graph's brace depths; re-anchor them to the
        // body's statement level so a top-level loop reads 1 however the
        // body text is wrapped, and each level of nesting — loop inside
        // a loop, or inside a chain case body — adds one.
        let base = statement_depth(code);
        let max_depth = loops
            .iter()
            .map(|loop_| loop_.depth - base + 1)
            .max()
            .unwrap_or(1)
            .max(1) as usize;

        // Kinds in first-seen body order, deduped: the body's own shape
        // story, diff-stable across scans.
        let mut kinds_seen: Vec<LoopKind> = Vec::new();
        for loop_ in loops {
            if !kinds_seen.contains(&loop_.kind) {
                kinds_seen.push(loop_.kind);
            }
        }

        // A spelled-out loop header is the strong reading; a goto back
        // to a label is an inference over the jump, so a body whose only
        // loops are goto-driven pays the lower rung.
        let structured = kinds_seen.iter().any(LoopKind::is_structured);
        let confidence = Confidence::new(if structured { 70 } else { 60 });

        // The Rust structures the shapes correspond to, deduped the same
        // way: do-while and goto both land on `loop`.
        let mut rust: Vec<&str> = Vec::new();
        for kind in &kinds_seen {
            let shape = kind.rust_shape();
            if !rust.contains(&shape) {
                rust.push(shape);
            }
        }
        let suggestion = if structured {
            format!(
                "express as Rust {} at nesting depth {max_depth}",
                rust.join("/")
            )
        } else {
            format!("express as Rust loop at nesting depth {max_depth} (goto-driven)")
        };

        let labels = kinds_seen
            .iter()
            .map(|kind| kind.label())
            .collect::<Vec<_>>()
            .join("/");
        let plural = if loops.len() == 1 { "" } else { "s" };
        let evidence = format!(
            "{} loop{plural}: {labels} (max depth {max_depth})",
            loops.len()
        );

        Some(LoopNesting {
            function: name.to_string(),
            loop_count: loops.len(),
            max_depth,
            kinds_seen,
            suggestion,
            confidence,
            evidence,
        })
    }
}

/// The brace depth the function body's statements sit at. Ghidra's
/// decompile wraps them in `{ ... }` under the signature line — the `{`
/// on its own line, as the bridge reports it — so its statements sit
/// one level in; a hand-written body that starts straight at the
/// statements sits at zero. Mirrors the recursion detector's body-start
/// scan; a signature carrying the opening brace inline reads one level
/// deeper, the same approximation the CFG documents for braceless
/// bodies.
fn statement_depth(body: &str) -> i32 {
    i32::from(body.lines().any(|l| l.trim_start().starts_with('{')))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(code: &str) -> Option<LoopNesting> {
        LoopDetector::default().detect("loopy", code)
    }

    #[test]
    fn for_while_and_do_while_land_one_finding() {
        let record = detect(
            "\
for (i = 0; i < 3; i = i + 1) {
    f();
}
while (x) {
    g();
}
do {
    h();
} while (y);",
        )
        .expect("three loop heads read as loops");
        assert_eq!(record.function, "loopy");
        assert_eq!(record.loop_count, 3);
        assert_eq!(record.max_depth, 1);
        assert_eq!(
            record.kinds_seen,
            [LoopKind::For, LoopKind::While, LoopKind::DoWhile]
        );
        assert_eq!(u8::from(record.confidence), 70);
        assert_eq!(
            record.suggestion,
            "express as Rust for/while/loop at nesting depth 1"
        );
        assert_eq!(record.evidence, "3 loops: for/while/do-while (max depth 1)");
    }

    #[test]
    fn nested_loops_report_the_maximum_depth() {
        let record = detect(
            "\
for (i = 0; i < 3; i = i + 1) {
    while (x) {
        f();
    }
}",
        )
        .expect("two loop heads read as loops");
        assert_eq!(record.loop_count, 2);
        assert_eq!(record.max_depth, 2);
        assert_eq!(record.kinds_seen, [LoopKind::For, LoopKind::While]);
        assert_eq!(
            record.suggestion,
            "express as Rust for/while at nesting depth 2"
        );
    }

    #[test]
    fn a_loop_in_a_chain_case_body_counts_at_its_real_depth() {
        let record = detect(
            "\
if (local_4 == 1) {
    while (x) {
        f();
    }
}
else if (local_4 == 2) {
    g();
}",
        )
        .expect("the loop inside the first arm reads as a loop");
        assert_eq!(record.loop_count, 1);
        // Nested under the chain, not beside it: the chain reading and
        // this loop reading agree about where the loop sits.
        assert_eq!(record.max_depth, 2);
        assert_eq!(u8::from(record.confidence), 70);
    }

    #[test]
    fn a_goto_back_to_a_label_reads_as_a_loop_at_60() {
        let record = detect(
            "\
loop_start:
    i = i + 1;
    if (i < 10) {
        goto loop_start;
    }",
        )
        .expect("a goto back to an earlier label is a loop");
        assert_eq!(record.loop_count, 1);
        assert_eq!(record.kinds_seen, [LoopKind::Goto]);
        assert_eq!(record.max_depth, 1);
        assert_eq!(u8::from(record.confidence), 60);
        assert_eq!(
            record.suggestion,
            "express as Rust loop at nesting depth 1 (goto-driven)"
        );
        assert_eq!(record.evidence, "1 loop: goto (max depth 1)");
    }

    #[test]
    fn a_structured_header_lifts_a_goto_driven_body_to_70() {
        // The weaker rung is only for a body whose ONLY loops are
        // goto-driven; one spelled-out header is spelled-out evidence.
        // The goto targets the label block and the while heads its own
        // block, so the graph sees two loops, not one header claimed
        // twice.
        let record = detect(
            "\
loop_start:
    i = i + 1;
    if (i < 10) {
        goto loop_start;
    }
    while (x) {
        f();
    }",
        )
        .expect("both loops read");
        assert_eq!(record.loop_count, 2);
        assert_eq!(record.kinds_seen, [LoopKind::Goto, LoopKind::While]);
        assert_eq!(u8::from(record.confidence), 70);
    }

    #[test]
    fn a_body_with_no_loops_yields_no_finding() {
        assert!(detect("if (x) {\n    f();\n}\ng();").is_none());
        assert!(detect("return;").is_none());
    }

    #[test]
    fn loop_keywords_in_string_literals_invent_nothing() {
        assert!(
            detect(
                "\
puts(\"for (i = 0; i < 3; i = i + 1) {\");
puts(\"while (x) {\");
puts(\"do { } while (y);\");"
            )
            .is_none()
        );
    }

    #[test]
    fn a_truncated_body_still_counts_the_visible_head() {
        // Ghidra cutting a decompile off mid-brace loses the back edge
        // but not the spelled-out header — the reading degrades, it does
        // not panic or invent a nesting level.
        let record = detect("while (x) {\n    f();").expect("the visible head still reads");
        assert_eq!(record.loop_count, 1);
        assert_eq!(record.kinds_seen, [LoopKind::While]);
        assert_eq!(record.max_depth, 1);
    }

    #[test]
    fn a_ghidra_wrapped_body_reads_its_top_level_loop_at_depth_1() {
        // The real decompile shape — signature line, then the body's own
        // braces — re-anchors to the statement level, so the wrapping
        // never invents a nesting level.
        let record = detect(
            "\
undefined FUN_18003e750(void)

{
  for (i = 0; i < 3; i = i + 1) {
    f();
  }
}",
        )
        .expect("the wrapped for reads as a loop");
        assert_eq!(record.loop_count, 1);
        assert_eq!(record.max_depth, 1);
    }

    #[test]
    fn min_loops_is_configurable() {
        let two_loops = "while (x) {\n    f();\n}\nwhile (y) {\n    g();\n}";
        assert!(
            LoopDetector::default()
                .with_min_loops(2)
                .detect("loopy", "while (x) {\n    f();\n}")
                .is_none()
        );
        let record = LoopDetector::default()
            .with_min_loops(2)
            .detect("loopy", two_loops)
            .expect("two loops clear the raised threshold");
        assert_eq!(record.loop_count, 2);
        assert_eq!(LoopDetector::default().min_loops(), 1);
    }

    #[test]
    fn the_detector_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LoopDetector>();
    }
}
