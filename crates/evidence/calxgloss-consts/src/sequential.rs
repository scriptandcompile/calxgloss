//! Sequential enum candidate detection.
//!
//! [`SequentialDetector`] reads a function's decompiled body for
//! `switch` statements and collects their case values. A run of
//! three or more contiguous ascending values — `case 0: case 1:
//! case 2:` — is the shape an enumerated state takes when the
//! compiler lowers it to a jump table; the finding names the run and
//! suggests the Rust `enum` whose variants would stand in for the
//! bare integers.

use std::collections::BTreeSet;

use crate::tokenize::{Token, tokenize};
use crate::types::{Confidence, EnumCandidate};

/// One `switch` block's worth of case values, with the lines the
/// labels were read from.
#[derive(Debug, Default)]
struct SwitchBlock {
    values: Vec<i64>,
    lines: BTreeSet<usize>,
}

/// Finds contiguous runs of switch case values in decompiled bodies.
///
/// The detector is stateless; [`with_default_threshold`] configures
/// the standard "runs of three or more" bar, and
/// [`with_min_run`](Self::with_min_run) swaps it whole.
#[derive(Debug, Clone)]
pub struct SequentialDetector {
    min_run: usize,
}

impl SequentialDetector {
    /// A detector reading candidates at the standard threshold: three
    /// or more contiguous values make an enum candidate.
    pub fn with_default_threshold() -> Self {
        Self { min_run: 3 }
    }

    /// A detector that reports a candidate once a run reaches
    /// `min_run` contiguous values.
    pub fn with_min_run(min_run: usize) -> Self {
        Self { min_run }
    }

    /// The enum candidates in one decompiled body — one per qualifying
    /// run, in the order their switches appear.
    ///
    /// Each `switch` in the body is read separately: its case values
    /// are sorted and the contiguous ascending runs extracted. A run
    /// of [`min_run`](Self::min_run) or more becomes a candidate;
    /// scattered values that never run together do not.
    pub fn detect(&self, function: &str, body: &str) -> Vec<EnumCandidate> {
        let tokens = tokenize(body);
        let mut blocks = Vec::new();
        let mut index = 0usize;
        while index < tokens.len() {
            if tokens[index].ident() == Some("switch") {
                index = self.read_switch(&tokens, index, &mut blocks);
            } else {
                index += 1;
            }
        }

        let mut candidates = Vec::new();
        for block in &blocks {
            for run in qualifying_runs(&block.values, self.min_run) {
                let min = run[0];
                let max = run[run.len() - 1];
                candidates.push(EnumCandidate {
                    function: function.to_string(),
                    count: run.len(),
                    values: run,
                    suggestion: format!("enum State {{ /* variants for {min}..={max} */ }}"),
                    confidence: Confidence::new(70),
                    evidence: evidence(body, &block.lines),
                });
            }
        }
        candidates
    }

    /// Reads the `switch` block starting at `switch_index` into
    /// `blocks`, and returns the token index just past it.
    ///
    /// Only labels directly inside the block count; a nested `switch`
    /// is read as its own block, appended to `blocks` in the order
    /// the scan reaches it, so the two switches never share values.
    fn read_switch(
        &self,
        tokens: &[Token<'_>],
        switch_index: usize,
        blocks: &mut Vec<SwitchBlock>,
    ) -> usize {
        let Some(open) = tokens[switch_index + 1..]
            .iter()
            .position(|t| t.is_punct(&["{"]))
            .map(|offset| switch_index + 1 + offset)
        else {
            return switch_index + 1;
        };

        blocks.push(SwitchBlock::default());
        let block_index = blocks.len() - 1;
        let mut depth = 0usize;
        let mut index = open;
        while index < tokens.len() {
            let token = &tokens[index];
            if token.is_punct(&["{"]) {
                depth += 1;
            } else if token.is_punct(&["}"]) {
                depth -= 1;
                if depth == 0 {
                    return index + 1;
                }
            } else if depth == 1 {
                if token.ident() == Some("switch") {
                    index = self.read_switch(tokens, index, blocks);
                    continue;
                }
                if token.ident() == Some("case")
                    && let Some((value, label_end)) = read_case_value(tokens, index + 1)
                {
                    blocks[block_index].values.push(value);
                    blocks[block_index].lines.insert(token.line);
                    index = label_end;
                }
            }
            index += 1;
        }
        // An unbalanced body (truncated decompile) still yields the
        // cases read up to the end.
        tokens.len()
    }
}

/// The value of a `case` label starting at `index` — an optional
/// leading `-` and an integer literal — and the index just past the
/// value. A non-integer label (an enum constant) reads as no value.
fn read_case_value(tokens: &[Token<'_>], index: usize) -> Option<(i64, usize)> {
    let negative = tokens.get(index).is_some_and(|t| t.is_punct(&["-"]));
    let value_index = if negative { index + 1 } else { index };
    let value = tokens.get(value_index)?.int()?;
    let value = i64::try_from(value).ok()?;
    Some((if negative { -value } else { value }, value_index + 1))
}

/// The contiguous ascending runs of at least `min_run` values within
/// one switch, deduplicated and in ascending order.
fn qualifying_runs(values: &[i64], min_run: usize) -> Vec<Vec<i64>> {
    let sorted: Vec<i64> = {
        let mut set: Vec<i64> = values.to_vec();
        set.sort_unstable();
        set.dedup();
        set
    };

    let mut runs = Vec::new();
    let mut start = 0usize;
    for end in 1..=sorted.len() {
        let run_continues = end < sorted.len() && sorted[end] == sorted[end - 1] + 1;
        if !run_continues {
            if end - start >= min_run {
                runs.push(sorted[start..end].to_vec());
            }
            start = end;
        }
    }
    runs
}

/// The decompiled case lines a candidate was read from, joined for
/// evidence.
fn evidence(body: &str, lines: &BTreeSet<usize>) -> String {
    lines
        .iter()
        .filter_map(|line| body.lines().nth(line - 1))
        .map(str::trim)
        .collect::<Vec<&str>>()
        .join(" ")
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(body: &str) -> Vec<EnumCandidate> {
        SequentialDetector::with_default_threshold().detect("FUN_18003ab00", body)
    }

    #[test]
    fn a_run_of_four_case_values_reads_as_a_candidate() {
        let candidates = detect(
            r#"  switch(local_10) {
  case 0:
    uVar1 = 1;
    break;
  case 1:
    uVar1 = 2;
    break;
  case 2:
    uVar1 = 3;
    break;
  case 3:
    uVar1 = 4;
  }"#,
        );
        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.function, "FUN_18003ab00");
        assert_eq!(candidate.values, vec![0, 1, 2, 3]);
        assert_eq!(candidate.count, 4);
        assert_eq!(candidate.confidence, Confidence::new(70));
        assert_eq!(
            candidate.suggestion,
            "enum State { /* variants for 0..=3 */ }"
        );
        assert!(candidate.evidence.contains("case 0:"));
        assert!(candidate.evidence.contains("case 3:"));
    }

    #[test]
    fn only_the_qualifying_run_of_a_scattered_switch_is_reported() {
        let candidates = detect(
            r#"  switch(uVar2) {
  case 0:
  case 1:
  case 2:
    handle();
    break;
  case 7:
    other();
    break;
  case 9:
    last();
  }"#,
        );
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].values, vec![0, 1, 2]);
        assert_eq!(candidates[0].count, 3);
    }

    #[test]
    fn two_runs_in_one_switch_are_two_candidates() {
        let candidates = detect(
            r#"  switch(uVar2) {
  case 0:
  case 1:
  case 2:
    a();
    break;
  case 10:
  case 0xb:
  case 12:
    b();
  }"#,
        );
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].values, vec![0, 1, 2]);
        assert_eq!(candidates[1].values, vec![10, 11, 12]);
    }

    #[test]
    fn a_run_of_two_is_not_a_candidate() {
        assert!(
            detect(
                r#"  switch(uVar2) {
  case 0:
    a();
    break;
  case 1:
    b();
  }"#
            )
            .is_empty()
        );
    }

    #[test]
    fn non_contiguous_values_never_run() {
        assert!(
            detect(
                r#"  switch(uVar2) {
  case 0:
  case 4:
  case 8:
  case 0xc:
    dispatch();
  }"#
            )
            .is_empty()
        );
    }

    #[test]
    fn if_else_chains_are_not_switches() {
        assert!(
            detect(
                r#"  if (uVar2 == 0) {
  }
  else if (uVar2 == 1) {
  }
  else if (uVar2 == 2) {
  }"#
            )
            .is_empty()
        );
    }

    #[test]
    fn a_nested_switch_belongs_to_its_own_block() {
        let candidates = detect(
            r#"  switch(outer) {
  case 5:
    switch(inner) {
    case 0:
    case 1:
    case 2:
      inner_dispatch();
    }
    break;
  }"#,
        );
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].values, vec![0, 1, 2]);
    }

    #[test]
    fn negative_case_values_run_like_positive_ones() {
        let candidates = detect(
            r#"  switch(error) {
  case -3:
  case -2:
  case -1:
    fail();
  }"#,
        );
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].values, vec![-3, -2, -1]);
        assert_eq!(
            candidates[0].suggestion,
            "enum State { /* variants for -3..=-1 */ }"
        );
    }

    #[test]
    fn a_custom_threshold_reaches_the_detector() {
        let body = r#"  switch(uVar2) {
  case 0:
  case 1:
  case 2:
    a();
  }"#;
        assert!(
            SequentialDetector::with_min_run(4)
                .detect("FUN_18003ab00", body)
                .is_empty()
        );
        let candidates = SequentialDetector::with_min_run(2).detect("FUN_18003ab00", body);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].count, 3);
    }
}
