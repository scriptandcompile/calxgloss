//! Issue #424 (P26.8) at the headless render seam: the queue view shows
//! the one *conformance verdict* — the same facts the terminal prints,
//! read off the shared model's payload, never computed here — and the
//! unit detail shows the unit's own *obligation entry*. An absent entry
//! renders the spelled-out unknown, never a zero and never a pass. The
//! test rides the booted world and its browser helpers (issue #471),
//! and self-skips when no Chrome/Chromium is installed.

use super::conformance_web::stage_obligation_ledger;
use super::support::DashboardTab;
use super::*;

/// JS expression reading the queue view's conformance strip text,
/// empty while absent.
const CONFORMANCE_STRIP: &str = "document.getElementById('queue-conformance')?.textContent || ''";

fn conformance_strip_text(tab: &DashboardTab) -> String {
    tab.eval_text(CONFORMANCE_STRIP)
}

/// JS expression reading the unit detail's obligation section text,
/// empty while the section is absent. The section is found by its
/// title, the way a reviewer reads it.
const OBLIGATION_SECTION: &str = r#"(() => {
    const titles = [...document.querySelectorAll('#queue-detail-body .detail-section-title')];
    const title = titles.find(e => e.textContent.trim() === 'Obligation');
    return title ? title.parentElement.textContent : '';
})()"#;

fn obligation_section_text(tab: &DashboardTab) -> String {
    tab.eval_text(OBLIGATION_SECTION)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_conformance_and_obligation_render_unknown_then_filed() {
    let world = support::ReviewWorld::boot_plain().await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Switch to the queue view; the strip renders with the list.
    tab.click(".nav-tab[data-view=\"queue\"]");

    // Nothing filed anywhere: the strip names the unknown verdict with
    // its cause and says never a clean run — the honest reading, never
    // a pass and never a collapsed zero.
    let unknown_visible = tab
        .wait_for_text(CONFORMANCE_STRIP, |strip| {
            strip.contains("unknown: no ledger filed") && strip.contains("never a clean run")
        })
        .await;
    let strip = conformance_strip_text(&tab);
    assert!(
        unknown_visible,
        "the queue strip should render the unknown verdict with its cause, got: {strip:?}"
    );
    assert!(
        !strip.contains("complete"),
        "with no ledger filed the strip never renders a complete verdict: {strip:?}"
    );

    // Open the open unit's detail: its obligation section spells the
    // unknown reading — nothing filed for its binary is never zero.
    tab.click("#full-queue-list [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"]");
    let unknown_obligation = tab
        .wait_for_text(OBLIGATION_SECTION, |section| {
            section.contains("Unknown") && section.contains("never shown as zero")
        })
        .await;
    let section = obligation_section_text(&tab);
    assert!(
        unknown_obligation,
        "the unit detail should spell the unknown obligation reading, got: {section:?}"
    );

    // File a ledger: the strip turns to the incomplete reading beside
    // its first broken link, and the unit detail names its entry's
    // fields — attempt, owner digest, required case kinds, disposition,
    // and receipt citation.
    {
        let mut entry = calxgloss_types::ObligationEntry::new(
            "DrawPrimitive",
            2,
            "aaaa1111",
            calxgloss_types::ObligationDisposition::ClaimedVerified,
        );
        entry.receipt_digest = Some("sha256:cafe".to_string());
        stage_obligation_ledger(world.repo_path().as_path(), "game_logic.dll", vec![entry]);
    }
    tab.reload();
    tab.click(".nav-tab[data-view=\"queue\"]");

    let incomplete_visible = tab
        .wait_for_text(CONFORMANCE_STRIP, |strip| {
            strip.contains("game_logic.dll — incomplete")
        })
        .await;
    let strip = conformance_strip_text(&tab);
    assert!(
        incomplete_visible,
        "a filed ledger should turn the strip to the incomplete reading, got: {strip:?}"
    );

    // The unit's own entry now rides the detail with every field AC 2
    // names — the same joined reading the row above was computed from.
    tab.click("#full-queue-list [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"]");
    let entry_visible = tab
        .wait_for_text(OBLIGATION_SECTION, |section| {
            section.contains("positive, negative, malformed")
                && section.contains("claimed verified")
                && section.contains("sha256:cafe")
                && section.contains("aaaa1111")
        })
        .await;
    let section = obligation_section_text(&tab);
    assert!(
        entry_visible,
        "the unit detail should name the entry's attempt, owner digest, \
         required case kinds, disposition, and receipt citation, got: {section:?}"
    );
    assert!(
        section.contains("Attempt") && section.contains("2"),
        "the entry speaks for attempt 2: {section:?}"
    );
}
