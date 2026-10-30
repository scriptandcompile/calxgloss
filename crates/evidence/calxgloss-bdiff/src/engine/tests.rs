// Tests for the module above, split out of the file they test.
use super::*;
use crate::types::CARRY_OVER_CONFIDENCE_FLOOR;
use calxgloss_types::BinaryIdentity;

/// One listed function with a body that names itself, so body-
/// related tests can spell "unrelated bodies" honestly.
fn function(name: &str, address: u64) -> FunctionEntry {
    FunctionEntry {
        name: name.into(),
        address,
        body: format!("// body of {name}"),
    }
}

/// One listed function with a spelled-out decompiled body, for the
/// body-family fixtures that need real Ghidra spellings.
fn function_with_body(name: &str, address: u64, body: &str) -> FunctionEntry {
    FunctionEntry {
        name: name.into(),
        address,
        body: body.into(),
    }
}

#[test]
fn a_fun_renamed_function_with_byte_equal_normalized_bodies_pairs_at_90() {
    // The function merely moved: the new address brought a new
    // FUN_ spelling and the rebuild re-lettered Ghidra's invented
    // variables, but through the shared normalizer the two bodies
    // are byte-equal shapes — the body family pairs them at 90
    // (track #233's ladder, second band).
    let old_body = "\
{
   uint uVar1;
   uVar1 = DAT_140045a68;
   if (uVar1 != 0) {
      FUN_140002000(uVar1);
   }
   return;
}";
    let new_body = "\
{
   uint iVar4;
   iVar4 = DAT_140047120;
   if (iVar4 != 0) {
      FUN_140002000(iVar4);
   }
   return;
}";
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function_with_body("FUN_140001000", 0x140001000, old_body)],
        &[],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function_with_body("FUN_140009000", 0x140009000, new_body)],
        &[],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert_eq!(
        document.pairings.len(),
        1,
        "the moved function pairs through the body family"
    );
    let record = &document.pairings[0];
    assert_eq!(record.old_function, "FUN_140001000");
    assert_eq!(record.new_function, "FUN_140009000");
    assert_eq!(record.family, MatchFamily::NormalizedBody);
    assert_eq!(record.confidence.value(), BODY_EQUAL_CONFIDENCE);
    assert_eq!(
        record.evidence,
        ["normalized bodies are byte-equal (8 lines)"],
        "the record carries the normalized-body summary as its evidence"
    );
}

/// One version's snapshot with a stable stand-in hash.
fn snapshot(
    binary: &str,
    hash: &str,
    functions: Vec<FunctionEntry>,
    exports: &[&str],
) -> ScanSnapshot {
    ScanSnapshot {
        binary: BinaryIdentity::new(binary),
        bytes_sha256: hash.into(),
        functions,
        exports: exports.iter().map(|name| (*name).to_string()).collect(),
    }
}

#[test]
fn an_exported_name_present_in_both_versions_pairs_at_95() {
    // The exported name is the program's own spelling; its address
    // shifting between versions changes nothing.
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![
            function("fixture_init", 0x1000),
            function("FUN_10001200", 0x1200),
        ],
        &["fixture_init"],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function("fixture_init", 0x4000)],
        &["fixture_init"],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert_eq!(document.pairings.len(), 1, "the export pairs once");
    let record = &document.pairings[0];
    assert_eq!(record.old_function, "fixture_init");
    assert_eq!(record.new_function, "fixture_init");
    assert_eq!(record.confidence.value(), NAME_IDENTITY_CONFIDENCE);
    assert_eq!(record.confidence.value(), 95);
    assert_eq!(record.family, MatchFamily::NameIdentity);
    assert_eq!(record.evidence, ["exported name fixture_init"]);
}

#[test]
fn a_demangled_name_present_in_both_versions_pairs_at_95() {
    // A `::`-qualified demangled name pairs even with no export
    // table entry behind it — the demangler's spelling is the
    // binary's own name for the function.
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function("Widget::render(void)", 0x1000)],
        &[],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function("Widget::render(void)", 0x9000)],
        &[],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert_eq!(document.pairings.len(), 1);
    assert_eq!(
        document.pairings[0].evidence,
        ["demangled name Widget::render(void)"]
    );
}

#[test]
fn a_demangled_operator_spelling_pairs() {
    // The demangled `operator.` dot form the decompiler writes for
    // C++ operators keeps its dot and brackets in the listing.
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function("operator.new(unsigned long long)", 0x1000)],
        &[],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function("operator.new(unsigned long long)", 0x2000)],
        &[],
    );
    assert_eq!(
        pair_versions(&old, &new)
            .expect("one identity")
            .pairings
            .len(),
        1
    );
}

#[test]
fn an_equal_address_derived_spelling_claims_nothing() {
    // A `FUN_…` name match means the address held — the address-
    // derived spelling is the relocation signal itself, and a lone
    // signal claims nothing (ADR-0038). The bodies stay unrelated so
    // no body-family evidence corroborates the lone address claim.
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function_with_body(
            "FUN_140001000",
            0x140001000,
            "{\n   return uVar1 + 1;\n}",
        )],
        &[],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function_with_body(
            "FUN_140001000",
            0x140001000,
            "{\n   DAT_140045a68 = 3;\n   return;\n}",
        )],
        &[],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert!(
        document.pairings.is_empty(),
        "a FUN_ spelling pairing is a lone address claim"
    );
}

#[test]
fn equal_address_with_unrelated_bodies_pairs_nothing() {
    // The lone-signal gate, spelled out: two functions sit at the
    // same address with different names and unrelated bodies — and
    // both are even exported, under different names. Nothing pairs:
    // relocations lie, and equal addresses claim nothing on their
    // own.
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function("old_entry", 0x140001100)],
        &["old_entry"],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function("new_entry", 0x140001100)],
        &["new_entry"],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert!(
        document.pairings.is_empty(),
        "a lone address equality claims nothing"
    );
}

#[test]
fn a_near_equal_body_pairs_on_the_structural_diff_ratio() {
    // Ten normalized lines, one changed statement between builds:
    // the shapes are not byte-equal, so the pair scores on its
    // structural-diff ratio — inside the band between the carry-
    // over floor and the byte-equal 90 (ticket #296) — and the
    // record carries the normalized-body diff as its evidence.
    let old_body = "\
{
   uint uVar1;
   uVar1 = DAT_140045a68;
   if (uVar1 != 0) {
      FUN_140002000(uVar1);
   }
   DAT_140045a70 = uVar1;
   uVar1 = uVar1 + 1;
   return;
}";
    // The rebuild stored the bumped counter instead: one normalized
    // line replaced out of ten, everything else the same shape.
    let new_body = "\
{
   uint iVar7;
   iVar7 = DAT_140047120;
   if (iVar7 != 0) {
      FUN_140002000(iVar7);
   }
   DAT_140047200 = iVar7;
   iVar7 = iVar7 + 2;
   return;
}";
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function_with_body("FUN_140001000", 0x140001000, old_body)],
        &[],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function_with_body("FUN_140009000", 0x140009000, new_body)],
        &[],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert_eq!(document.pairings.len(), 1, "the near-equal pair pairs");
    let record = &document.pairings[0];
    assert_eq!(record.family, MatchFamily::NormalizedBody);
    assert!(
        record.confidence.value() > CARRY_OVER_CONFIDENCE_FLOOR
            && record.confidence.value() < BODY_EQUAL_CONFIDENCE,
        "a near-equal score stands inside the band, got {}",
        record.confidence.value()
    );
    // A worked example, not a recompute: one of ten normalized
    // lines changed, so the ratio puts the score at 89.
    assert_eq!(record.confidence.value(), 89);
    assert_eq!(
        record.evidence,
        [
            "normalized body diff: 1 of 10 lines differ (90% similar)",
            "changed: VAR = VAR + 1; -> VAR = VAR + 2;",
        ],
        "the evidence line summarizes the normalized-body diff and quotes it"
    );
}

#[test]
fn an_added_line_reads_as_an_added_line_in_the_evidence() {
    // The new build's routine grew one extra call. The shapes still
    // pair, but the evidence must spell the edit honestly: a line
    // the new body has and the old one does not is *added*, not a
    // change squeezed onto the wrong pair of lines.
    let old_body = "\
{
   uint uVar1;
   uVar1 = DAT_140045a68;
   if (uVar1 != 0) {
      FUN_140002000(uVar1);
   }
   DAT_140045a70 = uVar1;
   uVar1 = uVar1 + 1;
   return;
}";
    let new_body = "\
{
   uint iVar7;
   iVar7 = DAT_140047120;
   if (iVar7 != 0) {
      FUN_140002000(iVar7);
      FUN_140002100(iVar7);
   }
   DAT_140047200 = iVar7;
   iVar7 = iVar7 + 1;
   return;
}";
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function_with_body("FUN_140001000", 0x140001000, old_body)],
        &[],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function_with_body("FUN_140009000", 0x140009000, new_body)],
        &[],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert_eq!(document.pairings.len(), 1);
    let record = &document.pairings[0];
    // Eleven normalized lines, one added: 91% similar, score 89.
    assert_eq!(record.confidence.value(), 89);
    assert_eq!(
        record.evidence,
        [
            "normalized body diff: 1 of 11 lines differ (91% similar)",
            "added: FUN_140002100(VAR);",
        ]
    );
}

#[test]
fn a_removed_line_reads_as_a_removed_line_in_the_evidence() {
    // The mirror image: the update dropped a call. The evidence
    // names it *removed*, from the old body's side.
    let old_body = "\
{
   uint uVar1;
   uVar1 = DAT_140045a68;
   if (uVar1 != 0) {
      FUN_140002000(uVar1);
      FUN_140002100(uVar1);
   }
   DAT_140045a70 = uVar1;
   uVar1 = uVar1 + 1;
   return;
}";
    let new_body = "\
{
   uint iVar7;
   iVar7 = DAT_140047120;
   if (iVar7 != 0) {
      FUN_140002000(iVar7);
   }
   DAT_140047200 = iVar7;
   iVar7 = iVar7 + 1;
   return;
}";
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function_with_body("FUN_140001000", 0x140001000, old_body)],
        &[],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function_with_body("FUN_140009000", 0x140009000, new_body)],
        &[],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert_eq!(document.pairings.len(), 1);
    let record = &document.pairings[0];
    assert_eq!(record.confidence.value(), 89);
    assert_eq!(
        record.evidence,
        [
            "normalized body diff: 1 of 11 lines differ (91% similar)",
            "removed: FUN_140002100(VAR);",
        ]
    );
}

#[test]
fn many_changed_lines_quote_three_edits_and_say_so() {
    // Five replaced statements in a 23-line shape: the summary
    // counts every edit, but the quoted evidence stays auditable —
    // the first few edits in body order, and a line naming the
    // ones it left out.
    let middle: Vec<String> = (0..20)
        .map(|i| format!("   FUN_140002000(uVar1, {i});"))
        .collect();
    let mut changed: Vec<String> = middle.clone();
    for i in [3usize, 7, 11, 15, 19] {
        changed[i] = format!("   FUN_140002000(uVar1, {i}) + 1;");
    }
    let old_body = format!("{{\n{}\n   return;\n}}", middle.join("\n"));
    let new_body = format!("{{\n{}\n   return;\n}}", changed.join("\n"));

    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function_with_body("FUN_140001000", 0x140001000, &old_body)],
        &[],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function_with_body("FUN_140009000", 0x140009000, &new_body)],
        &[],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert_eq!(document.pairings.len(), 1);
    let record = &document.pairings[0];
    // 5 edits over 23 lines: 79% similar, score 87.
    assert_eq!(record.confidence.value(), 87);
    assert_eq!(
        record.evidence,
        [
            "normalized body diff: 5 of 23 lines differ (79% similar)",
            "changed: FUN_140002000(VAR, 3); -> FUN_140002000(VAR, 3) + 1;",
            "changed: FUN_140002000(VAR, 7); -> FUN_140002000(VAR, 7) + 1;",
            "changed: FUN_140002000(VAR, 11); -> FUN_140002000(VAR, 11) + 1;",
            "(+2 more edits)",
        ]
    );
}

#[test]
fn two_blank_kept_bodies_pair_nothing() {
    // A kept body that holds nothing — a decompile failure, a stub
    // the scan listed without a body — normalizes to nothing. Two
    // blanks are "byte-equal" only vacuously: a lone structural
    // coincidence claims nothing (ADR-0038).
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function_with_body("FUN_140001000", 0x140001000, "")],
        &[],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function_with_body("FUN_140009000", 0x140009000, "")],
        &[],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert!(
        document.pairings.is_empty(),
        "blank bodies claiming a byte-equal pair is a lone-coincidence claim"
    );
}

#[test]
fn two_clearly_different_bodies_pair_nothing() {
    // An initializer and a parser share only Ghidra's boilerplate —
    // the braces and the bare return — out of ten normalized lines
    // each: about 30% similar, under the floor, and the body
    // family (the only family in play here) claims nothing.
    let old_body = "\
{
   uint uVar1;
   uint uVar2;
   uVar1 = DAT_140045a68;
   uVar2 = DAT_140045a70;
   FUN_140002000(uVar1, uVar2);
   uVar2 = uVar1 & 0xff;
   FUN_140002100(uVar2);
   return;
}";
    let new_body = "\
{
   char cVar3;
   int iVar4;
   cVar3 = *(char *)0x1400460a0;
   iVar4 = *(int *)0x1400460a8;
   while (cVar3 != '\\0') {
      FUN_140004400(cVar3, iVar4);
      cVar3 = *(char *)(0x1400460a0 + 1);
   }
   return;
}";
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function_with_body("FUN_140001000", 0x140001000, old_body)],
        &[],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function_with_body("FUN_140009000", 0x140009000, new_body)],
        &[],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert!(
        document.pairings.is_empty(),
        "a clearly different body pairs nothing, floor enforced"
    );
}

#[test]
fn a_plain_internal_name_match_claims_nothing_yet() {
    // A stripped private symbol that kept its name across versions
    // is not an export and not demangled: no family pairs on that
    // spelling alone. The bodies here are unrelated, so the body
    // family that landed with #296 has nothing to corroborate.
    // Equal bodies under one internal name would pair through the
    // body family, on the body evidence, never the name.
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function_with_body(
            "helper_parse",
            0x1000,
            "{\n   return uVar1 + 1;\n}",
        )],
        &[],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function_with_body(
            "helper_parse",
            0x3000,
            "{\n   DAT_140045a68 = 3;\n   return;\n}",
        )],
        &[],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert!(document.pairings.is_empty());
}

#[test]
fn a_second_best_pairing_is_dropped() {
    // One-to-one resolution over a mixed-strength candidate set,
    // the shape the whole ladder hands resolution now that #296 and
    // #297 have landed their families (the scores here are
    // synthetic stand-ins for the body and topology families; the
    // resolution rule is the shipped one): A's best claim is X at
    // 95, so A's 90 claim on Y drops, and Y then pairs with B.
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function("a", 1), function("b", 2)],
        &[],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function("x", 3), function("y", 4)],
        &[],
    );
    let candidates = vec![
        Candidate {
            old: 0,
            new: 0,
            confidence: 95,
            family: MatchFamily::NameIdentity,
            evidence: vec!["best".into()],
        },
        Candidate {
            old: 0,
            new: 1,
            confidence: 90,
            family: MatchFamily::NameIdentity,
            evidence: vec!["second best".into()],
        },
        Candidate {
            old: 1,
            new: 1,
            confidence: 85,
            family: MatchFamily::NameIdentity,
            evidence: vec!["next".into()],
        },
    ];

    let winners = resolve_one_to_one(candidates, &old.functions, &new.functions);
    let records: Vec<&PairingRecord> = winners.iter().map(|(_, _, record)| record).collect();
    assert_eq!(records.len(), 2);
    assert_eq!(
        (
            records[0].old_function.as_str(),
            records[0].new_function.as_str()
        ),
        ("a", "x")
    );
    assert_eq!(
        (
            records[1].old_function.as_str(),
            records[1].new_function.as_str()
        ),
        ("b", "y")
    );
    assert!(
        !records
            .iter()
            .any(|r| r.old_function == "a" && r.new_function == "y"),
        "a candidate's second-best pairing is dropped"
    );
}

#[test]
fn a_tie_keeps_the_first_seen_pairing_in_scan_order() {
    // Two old functions compete for one new function at equal
    // strength: the one first seen in the old scan's listing wins,
    // the other stays unpaired (ADR-0028's positional precedent).
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function("a", 1), function("b", 2)],
        &[],
    );
    let new = snapshot("game.dll", "new-hash", vec![function("x", 3)], &[]);
    let candidates = vec![
        Candidate {
            old: 0,
            new: 0,
            confidence: 95,
            family: MatchFamily::NameIdentity,
            evidence: vec!["first".into()],
        },
        Candidate {
            old: 1,
            new: 0,
            confidence: 95,
            family: MatchFamily::NameIdentity,
            evidence: vec!["later".into()],
        },
    ];

    let winners = resolve_one_to_one(candidates, &old.functions, &new.functions);
    assert_eq!(winners.len(), 1);
    assert_eq!(
        old.functions[winners[0].0].name, "a",
        "the first seen in scan order keeps the pair"
    );
}

/// A decompiled body of listed calls followed by filler assignments:
/// the filler pushes a new-side body past the line-gap skip, so a
/// renamed pair can only meet through the call graph, never through
/// the body family.
fn padded_body(calls: &[&str], assignments: usize) -> String {
    let mut lines = vec!["{".to_string()];
    lines.extend(calls.iter().map(|call| format!("   {call}(uVar1);")));
    lines.extend((0..assignments).map(|i| format!("   uVar1 = uVar1 + {i};")));
    lines.push("}".to_string());
    lines.join("\n")
}

#[test]
fn a_renamed_callee_pairs_at_70_through_two_paired_callers() {
    // The headline claim of the ladder's third band (ticket #297):
    // a FUN_-renamed internal whose body changed too much to pair,
    // but both its callers are exported names that paired on their
    // own — the call map, built purely from the snapshots' bodies,
    // agrees on the callee through those two paired neighbors.
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![
            function_with_body("present(void)", 0x1000, "{\n\tFUN_140001337();\n}"),
            function_with_body("startup(void)", 0x1100, "{\n\tFUN_140001337();\n}"),
            function_with_body("FUN_140001337", 0x1200, "{\n\treturn;\n}"),
        ],
        &["present(void)", "startup(void)"],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![
            function_with_body("present(void)", 0x4000, "{\n\tFUN_140009937();\n}"),
            function_with_body("startup(void)", 0x4100, "{\n\tFUN_140009937();\n}"),
            function_with_body("FUN_140009937", 0x4200, &padded_body(&[], 10)),
        ],
        &["present(void)", "startup(void)"],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert_eq!(
        document.pairings.len(),
        3,
        "the two callers pair by name, the callee through topology"
    );
    let record = document
        .pairings
        .iter()
        .find(|record| record.old_function == "FUN_140001337")
        .expect("the renamed callee pairs through the call graph");
    assert_eq!(record.new_function, "FUN_140009937");
    assert_eq!(record.family, MatchFamily::CallTopology);
    assert_eq!(record.confidence.value(), TOPOLOGY_CONFIDENCE);
    assert!(
        record.confidence.value() < CARRY_OVER_CONFIDENCE_FLOOR,
        "topology alone sits below the carry-over floor"
    );
    assert_eq!(
        record.evidence,
        [
            "call-graph topology through 2 paired neighbors",
            "FUN_140001337 is called by paired neighbor present(void) -> present(void)",
            "FUN_140001337 is called by paired neighbor startup(void) -> startup(void)",
        ],
        "the record names each paired-neighbor line it stood on"
    );
}

#[test]
fn a_lone_paired_neighbor_claims_nothing() {
    // Same call graph, but only one of the two callers still calls
    // the renamed callee in the new listing: a lone agreeing
    // neighbor is a lone signal (ADR-0038) and the callee stays
    // unpaired.
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![
            function_with_body("present(void)", 0x1000, "{\n\tFUN_140001337();\n}"),
            function_with_body("startup(void)", 0x1100, "{\n\tFUN_140001337();\n}"),
            function_with_body("FUN_140001337", 0x1200, "{\n\treturn;\n}"),
        ],
        &["present(void)", "startup(void)"],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![
            function_with_body("present(void)", 0x4000, "{\n\treturn;\n}"),
            function_with_body("startup(void)", 0x4100, "{\n\tFUN_140009937();\n}"),
            function_with_body("FUN_140009937", 0x4200, &padded_body(&[], 10)),
        ],
        &["present(void)", "startup(void)"],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert_eq!(
        document
            .pairings
            .iter()
            .filter(|record| record.family == MatchFamily::CallTopology)
            .count(),
        0,
        "one agreeing paired neighbor is not topology"
    );
    assert_eq!(
        document
            .pairings
            .iter()
            .map(|record| record.old_function.as_str())
            .collect::<Vec<_>>(),
        ["present(void)", "startup(void)"],
        "only the name pairs stand"
    );
}

#[test]
fn a_renamed_chain_pairs_through_neighbors_that_converged_themselves() {
    // Propagation iterates to a fixed point (ticket #297's AC). The
    // snapshot lists the chain's leaf first, so the leaf's
    // neighbors are still unpaired when the first pass walks the
    // listing — the leaf pairs only after the chain's roots have
    // converged through the exported callers. Three renamed links,
    // three claim rounds, one deterministic fixed point.
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![
            function_with_body("root_a(void)", 0x1000, "{\n\tFUN_14000a101();\n}"),
            function_with_body(
                "root_b(void)",
                0x1100,
                "{\n\tFUN_14000a101();\n\tFUN_14000a202();\n}",
            ),
            function_with_body("FUN_14000a303", 0x1200, "{\n\treturn;\n}"),
            function_with_body("FUN_14000a202", 0x1300, "{\n\tFUN_14000a303();\n}"),
            function_with_body(
                "FUN_14000a101",
                0x1400,
                "{\n\tFUN_14000a202();\n\tFUN_14000a303();\n}",
            ),
        ],
        &["root_a(void)", "root_b(void)"],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![
            function_with_body("root_a(void)", 0x4000, &padded_body(&["FUN_14000f777"], 8)),
            function_with_body(
                "root_b(void)",
                0x4100,
                &padded_body(&["FUN_14000f777", "FUN_14000f888"], 7),
            ),
            function_with_body("FUN_14000f999", 0x4200, &padded_body(&[], 10)),
            function_with_body("FUN_14000f888", 0x4300, &padded_body(&["FUN_14000f999"], 9)),
            function_with_body(
                "FUN_14000f777",
                0x4400,
                &padded_body(&["FUN_14000f888", "FUN_14000f999"], 8),
            ),
        ],
        &["root_a(void)", "root_b(void)"],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert_eq!(
        document
            .pairings
            .iter()
            .map(|record| (record.old_function.as_str(), record.new_function.as_str()))
            .collect::<Vec<_>>(),
        [
            ("root_a(void)", "root_a(void)"),
            ("root_b(void)", "root_b(void)"),
            ("FUN_14000a303", "FUN_14000f999"),
            ("FUN_14000a202", "FUN_14000f888"),
            ("FUN_14000a101", "FUN_14000f777"),
        ],
        "every renamed link in the chain pairs through converged neighbors"
    );
    for record in document.pairings.iter().skip(2) {
        assert_eq!(record.family, MatchFamily::CallTopology);
        assert_eq!(record.confidence.value(), TOPOLOGY_CONFIDENCE);
    }
    let leaf = document
        .pairings
        .iter()
        .find(|record| record.old_function == "FUN_14000a303")
        .expect("the leaf paired through the chain");
    assert_eq!(
        leaf.evidence,
        [
            "call-graph topology through 2 paired neighbors",
            "FUN_14000a303 is called by paired neighbor FUN_14000a202 -> FUN_14000f888",
            "FUN_14000a303 is called by paired neighbor FUN_14000a101 -> FUN_14000f777",
        ],
        "the leaf names the links that had already converged when it claimed"
    );
}

#[test]
fn a_body_pair_the_topology_agrees_on_rides_above_both_readings() {
    // The agreement bump (the P12.6 flag-family precedent): a
    // byte-equal body pair at 90 that the call graph also agrees on
    // through two paired callers is two independent families
    // reading one pair. The record scores above either single
    // reading, landing on name identity's band without leaving the
    // body family, and gains the neighbor evidence lines.
    let old_body = "\
{
   uint uVar1;
   uVar1 = DAT_140045a68;
   if (uVar1 != 0) {
      FUN_140002000(uVar1);
   }
   return;
}";
    let new_body = "\
{
   uint iVar4;
   iVar4 = DAT_140049a68;
   if (iVar4 != 0) {
      FUN_140002000(iVar4);
   }
   return;
}";
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![
            function_with_body("present(void)", 0x1000, "{\n\tFUN_14000c001();\n}"),
            function_with_body("startup(void)", 0x1100, "{\n\tFUN_14000c001();\n}"),
            function_with_body("FUN_14000c001", 0x1200, old_body),
        ],
        &["present(void)", "startup(void)"],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![
            function_with_body("present(void)", 0x4000, "{\n\tFUN_14000dd99();\n}"),
            function_with_body("startup(void)", 0x4100, "{\n\tFUN_14000dd99();\n}"),
            function_with_body("FUN_14000dd99", 0x4200, new_body),
        ],
        &["present(void)", "startup(void)"],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert_eq!(
        document.pairings.len(),
        3,
        "two name pairs and the corroborated body pair"
    );
    let record = document
        .pairings
        .iter()
        .find(|record| record.old_function == "FUN_14000c001")
        .expect("the moved internal still pairs through the body family");
    assert_eq!(record.new_function, "FUN_14000dd99");
    assert_eq!(
        record.family,
        MatchFamily::NormalizedBody,
        "a corroborating topology is not a competing claim"
    );
    assert_eq!(
        record.confidence.value(),
        BODY_EQUAL_CONFIDENCE + TOPOLOGY_AGREEMENT_BUMP
    );
    assert!(record.confidence.value() > BODY_EQUAL_CONFIDENCE);
    assert!(record.confidence.value() > TOPOLOGY_CONFIDENCE);
    assert_eq!(
        record.evidence,
        [
            "normalized bodies are byte-equal (8 lines)",
            "call-graph topology corroborates through 2 paired neighbors",
            "FUN_14000c001 is called by paired neighbor present(void) -> present(void)",
            "FUN_14000c001 is called by paired neighbor startup(void) -> startup(void)",
        ],
        "the body record keeps its body line and gains the neighbor lines"
    );
    for record in document.pairings.iter().take(2) {
        assert_eq!(record.family, MatchFamily::NameIdentity);
        assert_eq!(record.confidence.value(), NAME_IDENTITY_CONFIDENCE);
        assert!(
            record
                .evidence
                .iter()
                .all(|line| !line.contains("paired neighbor")),
            "name pairs that topology merely repeats are left alone"
        );
    }
}

#[test]
fn an_exported_demangled_name_keeps_the_export_evidence() {
    // A C++ export reads as both families at once; generation puts
    // the exported claim first and resolution drops the candidate's
    // second claim on the very same pair.
    let name = "ns::widget_draw(void)";
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function(name, 0x1000)],
        &[name],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function(name, 0x8000)],
        &[name],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert_eq!(document.pairings.len(), 1, "one pair, one record");
    assert_eq!(
        document.pairings[0].evidence,
        [format!("exported name {name}")]
    );
}

#[test]
fn pairings_stand_in_old_scan_order() {
    // Two scans of one version pair diff cleanly: records come back
    // in the old listing's order, not the order they were resolved.
    let old = snapshot(
        "game.dll",
        "old-hash",
        vec![function("zeta", 1), function("alpha", 2)],
        &["zeta", "alpha"],
    );
    let new = snapshot(
        "game.dll",
        "new-hash",
        vec![function("alpha", 3), function("zeta", 4)],
        &["alpha", "zeta"],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    let old_side: Vec<&str> = document
        .pairings
        .iter()
        .map(|r| r.old_function.as_str())
        .collect();
    assert_eq!(old_side, ["zeta", "alpha"]);
}

#[test]
fn the_document_names_both_hashes_and_both_full_listings() {
    // A stale document must be detectable — it names the exact byte
    // pair it was computed for — and the review side (the CLI
    // breakdown, #300) derives old-only and new-only from the two
    // complete listings.
    let old = snapshot(
        "game.dll",
        "aaa",
        vec![
            function("fixture_init", 0x1000),
            function("FUN_10001200", 0x1200),
        ],
        &["fixture_init"],
    );
    let new = snapshot(
        "game.dll",
        "bbb",
        vec![
            function("fixture_init", 0x4000),
            function("brand_new", 0x5000),
        ],
        &["fixture_init", "brand_new"],
    );

    let document = pair_versions(&old, &new).expect("one identity");
    assert_eq!(document.binary, "game.dll");
    assert_eq!(document.old_bytes_sha256, "aaa");
    assert_eq!(document.new_bytes_sha256, "bbb");
    assert_eq!(document.old_functions, ["fixture_init", "FUN_10001200"]);
    assert_eq!(document.new_functions, ["fixture_init", "brand_new"]);
    assert_eq!(document.pairings.len(), 1);
}

#[test]
fn two_different_binary_identities_are_refused() {
    // The pass pairs versions of one binary; mixing identities is a
    // caller error it names, not a pairing it guesses at.
    let old = snapshot("a.dll", "aaa", Vec::new(), &[]);
    let new = snapshot("b.dll", "bbb", Vec::new(), &[]);
    match pair_versions(&old, &new) {
        Err(BdiffError::IdentityMismatch { old, new }) => {
            assert_eq!(old, "a.dll");
            assert_eq!(new, "b.dll");
        }
        other => panic!("expected the identity refusal, got {other:?}"),
    }
}
