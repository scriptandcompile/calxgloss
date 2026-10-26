//! The generic scan command — one CLI handler riding the scan registry's
//! descriptor rows (issue #339, spec #337).
//!
//! Every scan subcommand repeats the same body: resolve the workspace,
//! load the engine over `target_dir/<binary>`, run the scan, persist the
//! document, print a report. The pipeline already writes that shape once
//! in [`scan_registry`]'s rows; this module lets the CLI read it from the
//! same place. What is genuinely per-engine lives in one contribution
//! entry per scan subcommand: the cached-document loader (through the
//! engine's own persistor, as the `--show` path has always done), the
//! report printer, a derivation of the registry's [`ScanRunOptions`] from
//! the command's clap flags, and optionally a post-scan step holding the
//! retained engine source and the loaded document. The entry names the
//! registry row it serves; the scan itself — engine build, scan, persist,
//! warn-and-continue degradation, document location — stays the row's,
//! with its operator-visible wording byte-for-byte.
//!
//! The generic flow, in order:
//!
//! * `--show` is a pure report: the entry's loader reads the filed
//!   document and the printer prints it. A missing document fails with
//!   the entry's own remediation wording, naming the exact command that
//!   would produce it. The engine is never loaded on this path.
//! * A scan run loads the engine exactly once — the settings-aware Kuna
//!   load honoring the `[analysis]` per-function budgets (ADR-0050's
//!   carried line that P39 folds engine loading) — wraps it as the
//!   pipeline's shared read source, and hands the row a [`ScanContext`]
//!   with empty latches (a one-shot CLI run orders with nothing; the
//!   callback row's own pre-scan hook composes from cached documents with
//!   no latch). The CLI's force-rescan contract travels as the
//!   overwrite policy: the phase's cached-hit short-circuit is not
//!   adopted here.
//! * After a successful run the freshly filed document is loaded back
//!   through the entry's loader — the accepted extra disk read that makes
//!   the run's report and a later `--show` report the same read of the
//!   same document — the post-scan step runs over the retained source
//!   and the loaded document, and the printer prints.
//!
//! The clap variant blocks in the CLI argument types stay untouched;
//! [`ScanFlags`] is the shape the routing arm hands the entry's flag
//! interpretation. The managed-binary CLI guard applies where it applies
//! today — the translate/auto paths, never a scan command — so this
//! handler never calls it.
//!
//! Today the table has its first rider, `typesdb`; the other fifteen
//! scan arms keep working untouched until their tickets (spec #337's
//! trail #340–#342) flood the table and lock it to the registry roster.

use std::any::Any;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, bail};
use calxgloss_decomp::PipelineSource;
use calxgloss_translator::scan_registry::{ScanContext, ScanLatches, ScanRunOptions, scan_rows};

use crate::Settings;
use crate::utils::*;

/// A loaded scan document, type-erased so one entry shape can carry the
/// fifteen different document types the engines file. The entry's own
/// loader produces it and the entry's own printer and post-scan step
/// read it back, so the downcast never crosses entries.
type LoadedDocument = Arc<dyn Any + Send + Sync>;

/// The entry's cached-document loader: read the filed document through
/// the engine's own persistor. A missing document arrives as the entry's
/// remediation error, naming the exact producing command.
type LoadStep = Arc<dyn Fn(&Path, &str) -> Result<LoadedDocument>>;

/// The entry's report printer, over the loaded document.
type PrintStep = Arc<dyn Fn(&dyn Any, &Path, &str) -> Result<()>>;

/// The entry's flag interpretation: the command's parsed flags in, the
/// registry's per-run options out. Each entry reads only its own
/// command's flags; the overwrite policy is the handler's to set.
type OptionsStep = Arc<dyn Fn(&ScanFlags) -> ScanRunOptions>;

/// The entry's optional post-scan step: the retained engine source, the
/// workspace and binary, and the loaded document — the seam the
/// type-inference write-back rides when its ticket arrives, and the
/// home of the one side effect a registry row does not file (the type
/// database's generated Rust declarations).
type PostScanStep = Arc<dyn Fn(&PipelineSource, &Path, &str, &dyn Any) -> Result<()>>;

/// The parsed flags of one scan command run, exactly as its clap variant
/// holds them: `binary` and `show` sit on every scan variant, and the
/// per-engine flags ride alongside as their entries' tickets land. The
/// clap blocks stay in the CLI argument types; this is the shape the
/// routing arm hands the entry for interpretation.
pub(crate) struct ScanFlags {
    /// The binary to scan and the document is named after.
    pub binary: String,
    /// Print the cached document instead of running the scan.
    pub show: bool,
    /// Do not attempt the type-database scan's vtable-method tag
    /// write-back — read by the type-database entry's flag derivation.
    pub no_tag: bool,
}

/// The entry's typed post-scan step, over the retained engine source
/// and the entry's own document type.
type PostScanFn<D> = fn(&PipelineSource, &Path, &str, &D) -> Result<()>;

/// One scan subcommand's whole CLI-side contribution, still typed over
/// its engine's document type: what the generic command cannot know on
/// its own. [`ScanContribution::new`] erases it into the table's shape,
/// exactly as the registry's own [`ScanDescriptor::new`](calxgloss_translator::scan_registry::ScanDescriptor::new)
/// erases a typed row.
pub(crate) struct ScanContributionSteps<D> {
    /// The registry row this entry serves, named by its identity in the
    /// registry's table.
    pub row: &'static str,
    /// Loads the filed document through the engine's own persistor.
    pub load: fn(&Path, &str) -> Result<D>,
    /// Prints the report over the loaded document.
    pub print: fn(&D, &Path, &str) -> Result<()>,
    /// Derives the per-run options from the command's parsed flags.
    pub derive_options: fn(&ScanFlags) -> ScanRunOptions,
    /// An optional step over the retained engine source and the loaded
    /// document, run after the scan and before the report.
    pub post_scan: Option<PostScanFn<D>>,
}

/// One contribution entry, type-erased as the table will hold it: the
/// entry's identity plus the four erased steps. The loader and printer
/// are the entry's own pair, so the erased document always downcasts
/// back to the type the entry was built with.
pub(crate) struct ScanContribution {
    /// The registry row this entry serves.
    row: &'static str,
    load: LoadStep,
    print: PrintStep,
    derive_options: OptionsStep,
    post_scan: Option<PostScanStep>,
}

impl ScanContribution {
    /// Erase one typed contribution into the table's shape — the single
    /// constructor, mirroring the registry's own erasure. A document the
    /// loader hands back is always the entry's own type, so a downcast
    /// miss would be a wiring bug inside one entry, not a runtime hazard
    /// across two; it still surfaces as an error rather than a panic.
    pub(crate) fn new<D>(steps: ScanContributionSteps<D>) -> Self
    where
        D: Any + Send + Sync,
    {
        let row = steps.row;
        Self {
            row,
            load: Arc::new(
                move |workspace: &Path, binary: &str| -> Result<LoadedDocument> {
                    Ok(Arc::new((steps.load)(workspace, binary)?))
                },
            ),
            print: Arc::new(move |document: &dyn Any, workspace: &Path, binary: &str| {
                let typed = typed_document::<D>(row, document)?;
                (steps.print)(typed, workspace, binary)
            }),
            derive_options: Arc::new(move |flags| (steps.derive_options)(flags)),
            post_scan: steps.post_scan.map(|step| {
                Arc::new(
                    move |source: &PipelineSource,
                          workspace: &Path,
                          binary: &str,
                          document: &dyn Any| {
                        let typed = typed_document::<D>(row, document)?;
                        step(source, workspace, binary, typed)
                    },
                ) as PostScanStep
            }),
        }
    }
}

/// Read one entry's own document type back out of the erased handle.
fn typed_document<'a, D: Any>(row: &str, document: &'a dyn Any) -> Result<&'a D> {
    document.downcast_ref::<D>().ok_or_else(|| {
        anyhow::anyhow!("the document loaded for the `{row}` command is not of its own type")
    })
}

/// Run one scan subcommand through the generic shape: load the row's
/// document and print it (`--show`), or load the engine once, run the
/// registry row with the CLI's force-rescan overwrite policy, read the
/// freshly filed document back, run the entry's post-scan step, and
/// print. The report printed after a run and the report `--show` prints
/// later are the same read of the same document.
pub(crate) async fn handle_scan_command(
    entry: &ScanContribution,
    flags: &ScanFlags,
    workspace: &Path,
    settings: &Settings,
) -> Result<()> {
    // The row this entry serves: the scan shape, its wording, and its
    // document location all live there.
    let row = scan_rows()
        .into_iter()
        .find(|row| row.name() == entry.row)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the CLI entry for `{}` names no scan row in the pipeline's registry",
                entry.row
            )
        })?;

    if flags.show {
        // A pure report on the cached document: never load the engine.
        let document = (entry.load)(workspace, &flags.binary)?;
        (entry.print)(document.as_ref(), workspace, &flags.binary)?;
        return Ok(());
    }

    // The engine load, folded in here (ADR-0050's carried line that P39
    // folds engine loading): the settings-aware Kuna load honoring the
    // `[analysis]` per-function budgets, wrapped as the pipeline's
    // shared read source and retained for the post-scan step.
    let source = load_kuna_source(settings, &flags.binary)?;

    let options = ScanRunOptions {
        // The CLI's force-rescan contract: a scan command always
        // re-scans, so the phase's cached-hit short-circuit is bypassed
        // (issue #338's overwrite policy); a failed re-scan still leaves
        // the previously filed document in place, because only a
        // successful scan saves.
        overwrite_filed_document: true,
        ..(entry.derive_options)(flags)
    };
    let ctx = ScanContext {
        binary: flags.binary.clone(),
        workspace: workspace.to_path_buf(),
        source: PipelineSource::Kuna(source.clone()),
        // A one-shot CLI run orders with nothing: the phase's latches
        // stay empty and the callback row's own pre-scan hook composes
        // from cached documents regardless.
        latches: ScanLatches::default(),
    };
    if !row.run_with_options(ctx, options).await {
        // The row already warned with its own byte-for-byte wording;
        // the CLI's job is only to make the failure the process exit.
        bail!(
            "the {} scan failed for {}; the registry row's warning was logged above",
            entry.row,
            flags.binary
        );
    }

    // The accepted extra disk read: load the document the row just
    // filed through the entry's own loader, so the run's report and a
    // later `--show` report are the same read of the same document.
    let document = (entry.load)(workspace, &flags.binary)?;

    if let Some(post_scan) = &entry.post_scan {
        post_scan(
            &PipelineSource::Kuna(source),
            workspace,
            &flags.binary,
            document.as_ref(),
        )?;
    }

    (entry.print)(document.as_ref(), workspace, &flags.binary)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use calxgloss_config::{FileConfig, Layers, LoadedConfig};
    use calxgloss_typesdb::persist::TypeDatabasePersistor;

    use super::*;
    use crate::commands::typesdb;

    /// A temp workspace over a copy of the fixture target: the binary
    /// sits at the workspace root, which doubles as the target dir, so
    /// a plain `--binary fixture-target` resolves to the copy — the same
    /// layout the process-level tests use.
    fn fixture_workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp workspace");
        let fixture = calxgloss_testfixtures::fixture_target_path().expect("fixture target");
        std::fs::copy(&fixture, dir.path().join("fixture-target"))
            .expect("copy fixture into workspace");
        dir
    }

    /// Settings resolving `target_dir` to `dir` and everything else to
    /// defaults, so the engine load and the `[analysis]` fold ride the
    /// same path production takes.
    fn settings_over(dir: &Path) -> Settings {
        let layers = Layers::default();
        let flags = FileConfig {
            target_dir: Some(dir.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let loaded = LoadedConfig {
            file: FileConfig::default(),
            path: None,
            searched: Vec::new(),
        };
        Settings::resolve(&layers, flags, &loaded)
    }

    /// Parse the `typesdb` shape of flags — the entry's rider.
    fn typesdb_flags(no_tag: bool) -> ScanFlags {
        ScanFlags {
            binary: "fixture-target".to_string(),
            show: false,
            no_tag,
        }
    }

    #[tokio::test]
    async fn the_ridden_typesdb_entry_files_the_document_and_the_declarations() {
        // The whole ride end to end: the generic command files the
        // document at the row's own `document_path`, the post-scan step
        // writes the declarations, and the run succeeds.
        let ws = fixture_workspace();
        let entry = typesdb::contribution();
        handle_scan_command(
            &entry,
            &typesdb_flags(false),
            ws.path(),
            &settings_over(ws.path()),
        )
        .await
        .expect("the typesdb ride succeeds over the fixture");

        let row = scan_rows()
            .into_iter()
            .find(|row| row.name() == entry.row)
            .expect("the entry names a registry row");
        let filed = row.document_path(ws.path(), "fixture-target");
        assert!(
            filed.is_file(),
            "the document must sit at the row's own path: {}",
            filed.display()
        );
        let persistor = TypeDatabasePersistor::new(ws.path());
        assert_eq!(
            filed,
            persistor.path_for("fixture-target"),
            "the row's location and the entry's persistor must name one path"
        );
        assert!(
            persistor.decls_exists("fixture-target"),
            "the declarations file is the post-scan step's one side effect"
        );
        let db = persistor
            .load("fixture-target")
            .expect("the filed document parses");
        assert_eq!(db.metadata.binary, "fixture-target");
    }

    #[tokio::test]
    async fn show_with_no_filed_document_fails_naming_the_producing_command() {
        // Remediation wording: the failure names the exact command that
        // would produce the document — never a bare "no document".
        let ws = fixture_workspace();
        let error = handle_scan_command(
            &typesdb::contribution(),
            &ScanFlags {
                binary: "fixture-target".to_string(),
                show: true,
                no_tag: false,
            },
            ws.path(),
            &settings_over(ws.path()),
        )
        .await
        .expect_err("an unscanned show must fail");
        let message = error.to_string();
        assert!(
            message.contains("run `calxgloss typesdb --binary fixture-target`"),
            "the failure names the exact producing command, got: {message}"
        );
    }

    #[tokio::test]
    async fn show_reads_the_filed_document_without_touching_the_engine() {
        // With the filed document in place and the target itself gone,
        // `--show` still succeeds: nothing on this path reads the
        // program, so nothing loads the engine.
        let ws = fixture_workspace();
        handle_scan_command(
            &typesdb::contribution(),
            &typesdb_flags(false),
            ws.path(),
            &settings_over(ws.path()),
        )
        .await
        .expect("the scan ride succeeds");
        std::fs::remove_file(ws.path().join("fixture-target")).expect("target gone");

        handle_scan_command(
            &typesdb::contribution(),
            &ScanFlags {
                binary: "fixture-target".to_string(),
                show: true,
                no_tag: false,
            },
            ws.path(),
            &settings_over(ws.path()),
        )
        .await
        .expect("a show over a filed document needs no engine");
    }

    #[tokio::test]
    async fn a_scan_command_run_always_rescans_over_a_filed_document() {
        // The CLI's force-rescan contract: the overwrite policy travels,
        // the phase's cached-hit short-circuit is not adopted. A second
        // run over a tampered filed document succeeds only by re-scanning
        // and replacing it — a short-circuited run would have failed
        // loading the tamper.
        let ws = fixture_workspace();
        handle_scan_command(
            &typesdb::contribution(),
            &typesdb_flags(false),
            ws.path(),
            &settings_over(ws.path()),
        )
        .await
        .expect("the first ride succeeds");

        let persistor = TypeDatabasePersistor::new(ws.path());
        let filed = persistor.path_for("fixture-target");
        std::fs::write(&filed, r#"{"metadata":{"binary":"sentinel"}}"#)
            .expect("tamper the filed document");

        handle_scan_command(
            &typesdb::contribution(),
            &typesdb_flags(false),
            ws.path(),
            &settings_over(ws.path()),
        )
        .await
        .expect("the second run re-scans and replaces the tampered document");
        let contents = std::fs::read_to_string(&filed).expect("the re-filed document");
        assert!(
            !contents.contains("sentinel"),
            "the re-scan must replace the tampered document outright"
        );
        persistor
            .load("fixture-target")
            .expect("the re-filed document parses");
    }

    #[test]
    fn the_no_tag_flag_derives_the_write_suppression_through_the_options_record() {
        // `--no-tag` reaches the row as the write-suppression signal;
        // the row interprets it inside its own build step (issue #338).
        let suppressed = typesdb::derive_run_options(&typesdb_flags(true));
        assert!(
            suppressed.suppress_write_back,
            "--no-tag suppresses the write-back"
        );
        let plain = typesdb::derive_run_options(&typesdb_flags(false));
        assert!(
            !plain.suppress_write_back,
            "without --no-tag the engine's own write-back stands"
        );
        assert!(plain.set_override_file.is_none());
        assert!(
            !plain.overwrite_filed_document,
            "the overwrite policy is the handler's to set, never the entry's"
        );
    }
}
