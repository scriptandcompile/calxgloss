//! Issue #424 (P26.8) at the headless render seam: the queue view shows
//! the one *conformance verdict* — the same facts the terminal prints,
//! read off the shared model's payload, never computed here — and the
//! unit detail shows the unit's own *obligation entry*. An absent entry
//! renders the spelled-out unknown, never a zero and never a pass. The
//! tests self-skip when no Chrome/Chromium is installed.

use super::conformance_web::stage_obligation_ledger;
use super::*;

/// The queue view's conformance strip text, empty while absent.
fn conformance_strip_text(tab: &headless_chrome::Tab) -> String {
    eval_text(
        tab,
        "document.getElementById('queue-conformance')?.textContent || ''",
    )
}

/// The unit detail's obligation section text, empty while the section is
/// absent. The section is found by its title, the way a reviewer reads it.
fn obligation_section_text(tab: &headless_chrome::Tab) -> String {
    eval_text(
        tab,
        r#"(() => {
            const titles = [...document.querySelectorAll('#queue-detail-body .detail-section-title')];
            const title = titles.find(e => e.textContent.trim() === 'Obligation');
            return title ? title.parentElement.textContent : '';
        })()"#,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_conformance_and_obligation_render_unknown_then_filed() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Switch to the queue view; the strip renders with the list.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"queue\"]')?.click() === undefined",
        false,
    )
    .expect("click queue tab");

    // Nothing filed anywhere: the strip names the unknown verdict with
    // its cause and says never a clean run — the honest reading, never
    // a pass and never a collapsed zero.
    let mut unknown_visible = false;
    for _ in 0..25 {
        let strip = conformance_strip_text(&tab);
        if strip.contains("unknown: no ledger filed") && strip.contains("never a clean run") {
            unknown_visible = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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
    tab.evaluate(
        "document.querySelector('#full-queue-list \
            [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"]')?.click() === undefined",
        false,
    )
    .expect("click the open unit row");
    let mut unknown_obligation = false;
    for _ in 0..25 {
        let section = obligation_section_text(&tab);
        if section.contains("Unknown") && section.contains("never shown as zero") {
            unknown_obligation = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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
        stage_obligation_ledger(fixture.repo_path().as_path(), "game_logic.dll", vec![entry]);
    }
    tab.reload(false, None)
        .expect("reload after filing the ledger");
    tab.wait_until_navigated().expect("wait for reload");
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"queue\"]')?.click() === undefined",
        false,
    )
    .expect("click queue tab again");

    let mut incomplete_visible = false;
    for _ in 0..25 {
        let strip = conformance_strip_text(&tab);
        if strip.contains("game_logic.dll — incomplete") {
            incomplete_visible = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let strip = conformance_strip_text(&tab);
    assert!(
        incomplete_visible,
        "a filed ledger should turn the strip to the incomplete reading, got: {strip:?}"
    );

    // The unit's own entry now rides the detail with every field AC 2
    // names — the same joined reading the row above was computed from.
    tab.evaluate(
        "document.querySelector('#full-queue-list \
            [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"]')?.click() === undefined",
        false,
    )
    .expect("click the open unit row again");
    let mut entry_visible = false;
    for _ in 0..25 {
        let section = obligation_section_text(&tab);
        if section.contains("positive, negative, malformed")
            && section.contains("claimed verified")
            && section.contains("sha256:cafe")
            && section.contains("aaaa1111")
        {
            entry_visible = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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

    tab.close_target().ok();
    drop(browser);
}
