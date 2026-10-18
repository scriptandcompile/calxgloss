//! Branch density classification.
//!
//! The branching structure of one decompiled body is read off the
//! per-body control flow graph, not re-scanned from the text: the
//! conditional edges out of `if`/`else if` heads counted against the
//! basic blocks decide whether the body reads as a dispatcher or a
//! scan. Loop conditions are iteration, not branching, so they count
//! as blocks and edges of the loop story the loop finding already
//! tells — a loop scan stays a sequential scan here, and the two
//! readings come off one graph and cannot disagree. A real `switch`
//! is not modelled on the graph either (the chain detector reads
//! switch chains textually), so a switch body counts no conditional
//! edges and reads as a scan: the switch finding already names it.
//!
//! One finding lands per function: a body at or above the heavy
//! threshold reads as a dispatch-table candidate (a `match` or a
//! dispatch table expresses a wide if/else-if ladder or many
//! conditionals better than the ladder itself); below it reads as a
//! sequential scan (keep it straight-line, or reach for an iterator).
//! The classification is a structural inference, so it sits at
//! confidence 60 — visibly weaker than a named shape like a switch
//! chain — and carries the branch count and the block count as
//! evidence. A body below the minimum block count reports nothing: a
//! two-block accessor is neither a dispatcher nor a scan.

use calxgloss_types::Confidence;

use crate::cfg::{Cfg, Terminator};
use crate::types::{BranchClassification, BranchDensity};

/// Classifier for the branching structure of one decompiled body.
#[derive(Debug, Clone)]
pub struct BranchDensityDetector {
    /// Minimum number of basic blocks a body must carry to be
    /// classified at all.
    min_blocks: usize,
    /// Conditional-edge / block ratio at or above which the body reads
    /// as a dispatch-table candidate.
    heavy_threshold: f64,
}

impl Default for BranchDensityDetector {
    fn default() -> Self {
        Self {
            min_blocks: 4,
            heavy_threshold: 0.6,
        }
    }
}

impl BranchDensityDetector {
    /// Create a detector with the default thresholds (four blocks
    /// classify, and 0.6 conditional edges per block reads heavy).
    pub fn new() -> Self {
        Self::default()
    }

    /// Lower or raise the block count a body needs to be classified.
    pub fn with_min_blocks(mut self, min_blocks: usize) -> Self {
        self.min_blocks = min_blocks;
        self
    }

    /// Lower or raise the conditional-edge / block ratio that reads as
    /// branch-heavy.
    pub fn with_heavy_threshold(mut self, heavy_threshold: f64) -> Self {
        self.heavy_threshold = heavy_threshold;
        self
    }

    /// Classify one decompiled function body from its control flow
    /// graph, or report nothing when the graph is too small to say
    /// anything (fewer than `min_blocks` blocks — or no blocks at all).
    pub(crate) fn detect(&self, name: &str, code: &str) -> Option<BranchDensity> {
        let cfg = Cfg::build(code);
        let block_count = cfg.blocks().len();
        if block_count == 0 || block_count < self.min_blocks {
            return None;
        }

        // Conditional edges are the taken / not-taken exits of an
        // if/else-if head. A loop head's condition is iteration, not
        // dispatch — the loop finding names loops, so counting them
        // here would let a plain loop scan read as a dispatcher.
        let branch_count = cfg
            .edges()
            .iter()
            .filter(|edge| {
                matches!(
                    cfg.block(edge.from).map(|block| block.terminator),
                    Some(Terminator::Branch)
                )
            })
            .count();
        let density = branch_count as f64 / block_count as f64;

        let classification = if density >= self.heavy_threshold {
            BranchClassification::DispatchTable
        } else {
            BranchClassification::SequentialScan
        };
        let suggestion = match classification {
            BranchClassification::DispatchTable => "express as a match or dispatch table",
            BranchClassification::SequentialScan => "keep straight-line or express as an iterator",
        };
        let evidence = format!(
            "{branch_count} conditional edges / {block_count} blocks (density {density:.2})"
        );

        Some(BranchDensity {
            function: name.to_string(),
            branch_count,
            block_count,
            classification,
            suggestion: suggestion.to_string(),
            confidence: Confidence::new(60),
            evidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(code: &str) -> Option<BranchDensity> {
        BranchDensityDetector::default().detect("branchy", code)
    }

    #[test]
    fn a_wide_if_else_if_ladder_reads_as_a_dispatch_table_candidate() {
        let record = detect(
            "\
if (local_4 == 1) {
    a();
}
else if (local_4 == 2) {
    b();
}
else if (local_4 == 3) {
    c();
}
else {
    d();
}",
        )
        .expect("a four-arm ladder is wide enough to classify");
        assert_eq!(record.function, "branchy");
        assert_eq!(record.branch_count, 6);
        assert_eq!(record.block_count, 7);
        assert_eq!(record.classification, BranchClassification::DispatchTable);
        // A structural inference, visibly weaker than a named shape.
        assert_eq!(u8::from(record.confidence), 60);
        assert_eq!(record.suggestion, "express as a match or dispatch table");
        assert_eq!(
            record.evidence,
            "6 conditional edges / 7 blocks (density 0.86)"
        );
    }

    #[test]
    fn many_conditionals_read_as_a_dispatch_table_candidate() {
        // Not one wide chain: four separate tests in a short body read
        // just as branch-heavy.
        let record = detect(
            "\
if (x == 1) {
    a();
}
if (x == 2) {
    b();
}
if (x == 3) {
    c();
}
if (x == 4) {
    d();
}",
        )
        .expect("four conditionals in eight blocks are branch-heavy");
        // Seven, not eight: the last test's not-taken edge leaves the
        // body, and an edge with no block to land on is no edge.
        assert_eq!(record.branch_count, 7);
        assert_eq!(record.block_count, 8);
        assert_eq!(record.classification, BranchClassification::DispatchTable);
    }

    #[test]
    fn a_branch_light_body_reads_as_a_sequential_scan() {
        // Two loops over the data, no if/else-if branching at all: the
        // loop story belongs to the loop finding, and this reading
        // keeps the scan a scan.
        let record = detect(
            "\
i = 0;
while (i < 10) {
    local_4 = local_4 + a[i];
    i = i + 1;
}
i = 0;
while (i < 10) {
    b[i] = local_4;
    i = i + 1;
}",
        )
        .expect("four blocks are big enough to classify");
        assert_eq!(record.branch_count, 0);
        assert_eq!(record.block_count, 4);
        assert_eq!(record.classification, BranchClassification::SequentialScan);
        assert_eq!(u8::from(record.confidence), 60);
        assert_eq!(
            record.suggestion,
            "keep straight-line or express as an iterator"
        );
        assert_eq!(
            record.evidence,
            "0 conditional edges / 4 blocks (density 0.00)"
        );
    }

    #[test]
    fn a_loop_with_one_guard_still_reads_as_a_sequential_scan() {
        // The odd test inside a loop is a guard, not dispatch: two
        // conditional edges across five blocks stay under the heavy
        // threshold.
        let record = detect(
            "\
total = 0;
if (count > 0) {
    while (i < count) {
        total = total + a[i];
        i = i + 1;
    }
}
return total;",
        )
        .expect("five blocks are big enough to classify");
        assert_eq!(record.branch_count, 2);
        assert_eq!(record.block_count, 5);
        assert_eq!(record.classification, BranchClassification::SequentialScan);
    }

    #[test]
    fn a_body_below_the_minimum_size_reports_nothing() {
        // The two-block accessor the minimum exists for: neither a
        // dispatcher nor a scan.
        assert!(detect("if (param_1 == 0) {\n    return;\n}").is_none());
        // A single-loop body is three blocks — still too small to
        // classify a ratio over.
        assert!(
            detect("while (x) {\n    f();\n}\nreturn;").is_none(),
            "three blocks sit below the four-block minimum"
        );
        assert!(detect("return;").is_none());
    }

    #[test]
    fn thresholds_and_the_minimum_size_are_configurable() {
        let ladder = "\
if (local_4 == 1) {
    a();
}
else if (local_4 == 2) {
    b();
}
else if (local_4 == 3) {
    c();
}
else {
    d();
}";
        // The default reads the seven-block ladder as branch-heavy...
        let record = BranchDensityDetector::default()
            .detect("branchy", ladder)
            .expect("the default thresholds classify the ladder");
        assert_eq!(record.classification, BranchClassification::DispatchTable);

        // ...a raised minimum size silences it...
        assert!(
            BranchDensityDetector::default()
                .with_min_blocks(8)
                .detect("branchy", ladder)
                .is_none(),
            "seven blocks sit below the raised minimum"
        );

        // ...and a raised heavy threshold reads it as a scan.
        let record = BranchDensityDetector::default()
            .with_heavy_threshold(0.9)
            .detect("branchy", ladder)
            .expect("a body big enough to classify still classifies");
        assert_eq!(record.classification, BranchClassification::SequentialScan);
    }

    #[test]
    fn branch_keywords_in_string_literals_invent_nothing() {
        assert!(
            detect(
                "\
puts(\"if (a) { b(); }\");
puts(\"else if (c) { d(); }\");
puts(\"while (e) { f(); }\");"
            )
            .is_none(),
            "branching spelled inside strings invents no blocks and no edges"
        );
    }

    #[test]
    fn a_truncated_body_still_classifies_the_visible_graph() {
        // The decompiler cutting a decompile off mid-arm loses the last arm's
        // not-taken edge — the reading degrades, it does not panic.
        let record = detect(
            "\
if (a) {
    x();
}
else if (b) {
    y();",
        )
        .expect("the visible chain still classifies");
        assert_eq!(record.branch_count, 3);
        assert_eq!(record.block_count, 4);
        assert_eq!(record.classification, BranchClassification::DispatchTable);
    }

    #[test]
    fn the_detector_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BranchDensityDetector>();
    }
}
