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
//! * `--show` is a report on the cached document: the entry's loader
//!   reads the filed document and the printer prints it. A missing
//!   document fails with the entry's own remediation wording, naming
//!   the exact command that would produce it. The engine is loaded on
//!   this path only when a step actually reads the program — an entry
//!   whose post-scan step wants the engine for this command line (the
//!   type-inference write-back under `--write-back`) answers so through
//!   its own `show_loads_program` step; `--show` alone never loads it.
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
//! The table is complete (issue #341): all fifteen scan commands ride
//! through [`ride`], which maps each clap variant onto its entry and
//! flags, and one `main.rs` arm drives them all. The three last riders
//! carry their per-engine flags in [`ScanFlags`] — the set-override file
//! (`algorithm --patterns`, `libmatch --signatures`) reaches the row
//! build through the registry's own options record, and the
//! type-inference write-back rides the entry's post-scan step over the
//! retained engine source. `bdiff` has no registry row and stays
//! outside the generic path. The suite's pairing tests pin this complete
//! contribution table against the registry roster one-for-one — the
//! pair can never drift silently (issue #342).

use std::any::Any;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Result, bail};
use calxgloss_decomp::PipelineSource;
use calxgloss_translator::scan_registry::{ScanContext, ScanLatches, ScanRunOptions, scan_rows};

use crate::Settings;
use crate::utils::*;

/// A loaded scan document, type-erased so one entry shape can carry the
/// fifteen different document types the engines file. The entry's own
/// loader produces it, and the entry's own printer and post-scan step
/// read it back, so the downcast never crosses entries. The handler owns
/// it as a `Box` so its post-scan step can take `&mut` of the entry's
/// own document (the type-inference step leaves its write-back report
/// there for the printer to render).
type LoadedDocument = Box<dyn Any + Send + Sync>;

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

/// The parsed flags of one scan command run, exactly as its clap variant
/// holds them: `binary` and `show` sit on every scan variant, and the
/// per-engine flags ride alongside. The clap blocks stay in the CLI
/// argument types; this is the shape the routing arm hands the entry for
/// interpretation.
pub(crate) struct ScanFlags {
    /// The binary to scan and the document is named after.
    pub binary: String,
    /// Print the cached document instead of running the scan.
    pub show: bool,
    /// Do not attempt the type-database scan's vtable-method tag
    /// write-back — read by the type-database entry's flag derivation.
    pub no_tag: bool,
    /// A JSON set document to scan in place of the engine's built-in
    /// set — `algorithm --patterns` and `libmatch --signatures` reach
    /// the row build through the registry's own set-override option,
    /// which each capable row interprets inside its own engine build.
    pub set_override_file: Option<PathBuf>,
    /// Apply the surviving inferences back through the engine type-write
    /// API — read by the type-inference entry's post-scan step.
    pub write_back: bool,
    /// The confidence floor (0–100) a record needs to be written back;
    /// only read alongside `write_back`.
    pub confidence_floor: u8,
}

/// The future an entry's post-scan step hands back — a write-back pass
/// is async, like the registry row's own scan, and rides the same
/// boxed-future shape, borrowing the source and the document it works
/// over.
pub(crate) type PostScanFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// The entry's optional post-scan step: the retained engine source, the
/// workspace and binary, the command line's flags, and the loaded
/// document as the entry can mutate it — the seam the type-inference
/// write-back rides, and the home of the one side effect a registry row
/// does not file (the type database's generated Rust declarations).
/// The erased post-scan step the table holds: one entry's typed step,
/// downcast-bridged to the table's erased document. A trait (not an
/// `Fn` trait object) because the bridged call ties one shared lifetime
/// across the erased arguments and the returned future — the shape a
/// hand-written impl states exactly and closure inference cannot.
trait ErasedPostScan {
    /// Run the entry's step over one erased call, its document read
    /// back as the entry's own type. A downcast miss is an
    /// entry-internal wiring bug and surfaces as an error, never a
    /// panic.
    fn call<'a>(
        &'a self,
        source: &'a PipelineSource,
        workspace: &'a Path,
        binary: &'a str,
        flags: &'a ScanFlags,
        document: &'a mut (dyn Any + Send + Sync),
    ) -> Result<PostScanFuture<'a>>;
}

/// One entry's post-scan step with its row name, kept typed until the
/// erased call reads the document back.
struct PostScanEntry<D> {
    /// The row named in downcast-miss wording.
    row: &'static str,
    /// The entry's typed step.
    step: PostScanFn<D>,
}

impl<D> ErasedPostScan for PostScanEntry<D>
where
    D: Any + Send + Sync,
{
    fn call<'a>(
        &'a self,
        source: &'a PipelineSource,
        workspace: &'a Path,
        binary: &'a str,
        flags: &'a ScanFlags,
        document: &'a mut (dyn Any + Send + Sync),
    ) -> Result<PostScanFuture<'a>> {
        let typed = typed_document_mut::<D>(self.row, document)?;
        Ok((self.step)(source, workspace, binary, flags, typed))
    }
}

/// The table's erased post-scan step.
type PostScanStep = Arc<dyn ErasedPostScan>;

/// The entry's typed post-scan step, over the retained engine source,
/// the command line's flags, and the entry's own document type as the
/// entry can mutate it.
pub(crate) type PostScanFn<D> = for<'a> fn(
    &'a PipelineSource,
    &'a Path,
    &'a str,
    &'a ScanFlags,
    &'a mut D,
) -> PostScanFuture<'a>;

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
    /// document, run after the scan and before the report prints — the
    /// step leaves whatever the report needs of it in the entry's own
    /// document. The scan-run path runs the step whenever the entry has
    /// one; the step interprets its own flags.
    pub post_scan: Option<PostScanFn<D>>,
    /// Whether the `--show` path loads the engine at all for this
    /// command line: only a post-scan step that reads the program — the
    /// type-inference write-back under `--write-back` — answers true.
    /// `--show` alone never loads the engine; `--show --write-back`
    /// does. The scan-run path always loads it, since the scan needs it.
    pub show_loads_program: fn(&ScanFlags) -> bool,
}

/// One contribution entry, type-erased as the table will hold it: the
/// entry's identity plus the five erased steps. The loader and printer
/// are the entry's own pair, so the erased document always downcasts
/// back to the type the entry was built with.
pub(crate) struct ScanContribution {
    /// The registry row this entry serves.
    row: &'static str,
    load: LoadStep,
    print: PrintStep,
    derive_options: OptionsStep,
    post_scan: Option<PostScanStep>,
    show_loads_program: fn(&ScanFlags) -> bool,
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
                    Ok(Box::new((steps.load)(workspace, binary)?))
                },
            ),
            print: Arc::new(move |document: &dyn Any, workspace: &Path, binary: &str| {
                let typed = typed_document::<D>(row, document)?;
                (steps.print)(typed, workspace, binary)
            }),
            derive_options: Arc::new(move |flags| (steps.derive_options)(flags)),
            post_scan: steps
                .post_scan
                .map(|step| Arc::new(PostScanEntry { row, step }) as PostScanStep),
            show_loads_program: steps.show_loads_program,
        }
    }
}

/// Read one entry's own document type back out of the erased handle.
fn typed_document<'a, D: Any>(row: &str, document: &'a dyn Any) -> Result<&'a D> {
    document.downcast_ref::<D>().ok_or_else(|| {
        anyhow::anyhow!("the document loaded for the `{row}` command is not of its own type")
    })
}

/// Read one entry's own document type back mutably, for its post-scan
/// step. Same wiring as [`typed_document`]: a miss is an entry-internal
/// bug and surfaces as an error rather than a panic.
fn typed_document_mut<'a, D: Any>(
    row: &str,
    document: &'a mut (dyn Any + Send + Sync),
) -> Result<&'a mut D> {
    document.downcast_mut::<D>().ok_or_else(|| {
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
        // A report on the cached document: the engine is loaded here
        // only when the entry's post-scan step reads the program for
        // this exact command line — `--show` alone never loads it,
        // `--show --write-back` does. The step runs before the printer
        // and leaves its follow-on report in the entry's own document,
        // so the printed order matches the scan path's.
        let mut document = (entry.load)(workspace, &flags.binary)?;
        if let Some(post_scan) = &entry.post_scan
            && (entry.show_loads_program)(flags)
        {
            let source = load_kuna_source(settings, &flags.binary)?;
            post_scan
                .call(
                    &source.into(),
                    workspace,
                    &flags.binary,
                    flags,
                    document.as_mut(),
                )?
                .await?;
        }
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
    let mut document = (entry.load)(workspace, &flags.binary)?;

    // The entry's post-scan step runs over the retained source and the
    // loaded document before the report prints — the declarations the
    // type-database step writes and the write-back report the
    // type-inference step leaves behind are both rendered from the
    // document and disk state the printer then reads. The step
    // interprets its own flags: without `--write-back` the
    // type-inference step does nothing.
    if let Some(post_scan) = &entry.post_scan {
        post_scan
            .call(
                &PipelineSource::Kuna(source),
                workspace,
                &flags.binary,
                flags,
                document.as_mut(),
            )?
            .await?;
    }

    (entry.print)(document.as_ref(), workspace, &flags.binary)?;
    Ok(())
}

/// The ride table (issues #339–#341): every clap variant that reaches a
/// registry row through the generic handler, mapped to its module's
/// contribution entry and the [`ScanFlags`] read off the variant. The
/// `main.rs` arm matches exactly these variants and hands the pair to
/// [`handle_scan_command`]; the only variant outside the table is
/// `bdiff`, which has no row to ride and keeps its dedicated pure-report
/// arm. Adding a command to the table is one entry here and one variant
/// in the arm, and the suite's roster assertion below pins the two
/// together. Adding an engine is one registry row plus one small
/// contribution entry: the pairing tests below pin the contribution
/// table against the registry roster one-for-one, so the pair can never
/// drift silently (issue #342).
pub(crate) fn ride(command: &crate::cli_types::Command) -> Option<(ScanContribution, ScanFlags)> {
    use crate::cli_types::Command;
    let (entry, flags) = match command {
        Command::Typesdb {
            binary,
            show,
            no_tag,
        } => (
            crate::commands::typesdb::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: *no_tag,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            },
        ),
        Command::ControlFlow { binary, show } => (
            crate::commands::controlflow::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: false,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            },
        ),
        Command::Memory { binary, show } => (
            crate::commands::memory::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: false,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            },
        ),
        Command::Sync { binary, show } => (
            crate::commands::sync::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: false,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            },
        ),
        Command::GlobalState { binary, show } => (
            crate::commands::globalstate::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: false,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            },
        ),
        Command::Consts { binary, show } => (
            crate::commands::consts::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: false,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            },
        ),
        Command::Errhandling { binary, show } => (
            crate::commands::errhandling::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: false,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            },
        ),
        Command::Floatsimd { binary, show } => (
            crate::commands::floatsimd::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: false,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            },
        ),
        Command::StringCtx { binary, show } => (
            crate::commands::stringctx::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: false,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            },
        ),
        Command::ApiDetect { binary, show } => (
            crate::commands::apidetect::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: false,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            },
        ),
        Command::Serialize { binary, show } => (
            crate::commands::serialize::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: false,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            },
        ),
        Command::Callback { binary, show } => (
            crate::commands::callback::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: false,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            },
        ),
        // The three flag-carrying riders (issue #341): each variant's
        // per-engine flag reaches its row build or post-scan step
        // through the flags below, interpreted by the entry alone.
        Command::Algorithm {
            binary,
            show,
            patterns,
        } => (
            crate::commands::algorithm::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: false,
                set_override_file: patterns.clone(),
                write_back: false,
                confidence_floor: 0,
            },
        ),
        Command::Libmatch {
            binary,
            show,
            signatures,
        } => (
            crate::commands::libmatch::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: false,
                set_override_file: signatures.clone(),
                write_back: false,
                confidence_floor: 0,
            },
        ),
        Command::Typeinfer {
            binary,
            show,
            write_back,
            confidence_floor,
        } => (
            crate::commands::typeinfer::contribution(),
            ScanFlags {
                binary: binary.clone(),
                show: *show,
                no_tag: false,
                set_override_file: None,
                write_back: *write_back,
                confidence_floor: *confidence_floor,
            },
        ),
        _ => return None,
    };
    Some((entry, flags))
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
            set_override_file: None,
            write_back: false,
            confidence_floor: 0,
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
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
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
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
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

    #[test]
    fn the_set_override_flags_derive_the_registry_option_for_both_capable_entries() {
        // `algorithm --patterns` and `libmatch --signatures` reach the
        // row build through the same option: each entry maps its flag
        // onto `set_override_file` and nothing else (issue #341).
        use crate::commands::{algorithm, libmatch};
        let path = std::path::PathBuf::from("my-database.json");
        let flags = ScanFlags {
            binary: "fixture-target".to_string(),
            show: false,
            no_tag: false,
            set_override_file: Some(path.clone()),
            write_back: false,
            confidence_floor: 0,
        };
        for (named, derived) in [
            ("algorithm", algorithm::derive_run_options(&flags)),
            ("libmatch", libmatch::derive_run_options(&flags)),
        ] {
            assert_eq!(
                derived.set_override_file.as_deref(),
                Some(path.as_path()),
                "{named}'s set-override flag arrives as the registry option"
            );
            assert!(
                !derived.suppress_write_back,
                "{named} never touches the write-suppression option"
            );
            assert!(
                !derived.overwrite_filed_document,
                "the overwrite policy is the handler's to set, never {named}'s"
            );
        }
        let plain = algorithm::derive_run_options(&ScanFlags {
            set_override_file: None,
            ..flags
        });
        assert!(
            plain.set_override_file.is_none(),
            "without the flag the row scans its built-in set"
        );
    }

    /// The fixture's real shapes renamed to custom names, copied from the
    /// pipeline's override tests: a file's set replaces the built-in one
    /// whole, so a filed document carrying only these claims proves the
    /// option drove the row's own engine build (issue #338's behavior,
    /// observed here from the CLI side).
    const CUSTOM_PATTERN_DATABASE: &str = r#"{
        "control_flow": [
            {
                "name": "custom_fixture_scan_shape",
                "category": "searching",
                "match_patterns": ["\\b(for|while) \\(", "==", "\\b(return|break)\\b"],
                "exclude_patterns": ["(?:/ 2\\b|>> 1)", "% "],
                "min_lines": 10
            }
        ]
    }"#;

    const CUSTOM_SIGNATURE_DATABASE: &str = r#"{
        "signatures": [
            {
                "symbol": "custom_fixture_strlen",
                "family": "crt",
                "match_patterns": [
                    "while \\(\\*VAR( != '\\\\0')?\\)",
                    "VAR = (?:VAR \\+ 1|&VAR\\[1\\])"
                ],
                "exclude_patterns": ["\\bmalloc\\b", "\\bfree\\b"],
                "min_lines": 6,
                "suggestion": "count bytes to the NUL — the fixture's scan loop"
            }
        ]
    }"#;

    #[tokio::test]
    async fn a_set_override_file_scans_the_fixture_from_the_file_s_own_set() {
        // The CLI-side end of the set-override option (issue #341): the
        // flag reaches the row through the entry's derivation, the row
        // interprets it in its own engine build, and the filed document
        // carries the file's renamed claims over the fixture target.
        let ws = fixture_workspace();
        let settings = settings_over(ws.path());

        let patterns = ws.path().join("custom-patterns.json");
        std::fs::write(&patterns, CUSTOM_PATTERN_DATABASE).expect("custom pattern database");
        handle_scan_command(
            &crate::commands::algorithm::contribution(),
            &ScanFlags {
                binary: "fixture-target".to_string(),
                show: false,
                no_tag: false,
                set_override_file: Some(patterns),
                write_back: false,
                confidence_floor: 0,
            },
            ws.path(),
            &settings,
        )
        .await
        .expect("the overridden algorithm ride succeeds");
        let document = calxgloss_algorithm::persist::AlgorithmPersistor::new(ws.path())
            .load("fixture-target")
            .expect("the overridden run filed an algorithm document");
        assert!(
            !document.hints.is_empty()
                && document
                    .hints
                    .iter()
                    .all(|hint| hint.algorithm == "custom_fixture_scan_shape"),
            "the document carries the file's claims and no built-in ones: {:?}",
            document
                .hints
                .iter()
                .map(|hint| &hint.algorithm)
                .collect::<Vec<_>>()
        );

        let signatures = ws.path().join("custom-signatures.json");
        std::fs::write(&signatures, CUSTOM_SIGNATURE_DATABASE).expect("custom signature database");
        handle_scan_command(
            &crate::commands::libmatch::contribution(),
            &ScanFlags {
                binary: "fixture-target".to_string(),
                show: false,
                no_tag: false,
                set_override_file: Some(signatures),
                write_back: false,
                confidence_floor: 0,
            },
            ws.path(),
            &settings,
        )
        .await
        .expect("the overridden libmatch ride succeeds");
        let document = calxgloss_libmatch::persist::LibmatchPersistor::new(ws.path())
            .load("fixture-target")
            .expect("the overridden run filed a known-library document");
        assert!(
            document
                .findings
                .iter()
                .any(|finding| finding.target() == "custom_fixture_strlen")
                && document
                    .findings
                    .iter()
                    .all(|finding| finding.target() == "custom_fixture_strlen"),
            "the document names the fixture only through the file's symbol: {:?}",
            document
                .findings
                .iter()
                .map(|finding| finding.target())
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn a_malformed_set_override_file_fails_the_run_and_files_nothing() {
        // A malformed override file fails the scan naming its own path —
        // the row's warning carries the database error (logged above
        // this assertion in-process), and the handler turns the failed
        // row into a failed run that files nothing (issue #341).
        for (cli, entry) in [
            ("algorithm", crate::commands::algorithm::contribution()),
            ("libmatch", crate::commands::libmatch::contribution()),
        ] {
            let entry_row = entry.row;
            let ws = fixture_workspace();
            let malformed = ws.path().join("broken-database.json");
            std::fs::write(&malformed, "{ this is not a database document")
                .expect("malformed override file");
            let error = handle_scan_command(
                &entry,
                &ScanFlags {
                    binary: "fixture-target".to_string(),
                    show: false,
                    no_tag: false,
                    set_override_file: Some(malformed),
                    write_back: false,
                    confidence_floor: 0,
                },
                ws.path(),
                &settings_over(ws.path()),
            )
            .await
            .expect_err(&format!("a {cli} run with a malformed override must fail"));
            assert!(
                error
                    .to_string()
                    .contains(&format!("the {entry_row} scan failed for fixture-target")),
                "the handler makes the failed row the exit, got: {error}"
            );
            (entry.load)(ws.path(), "fixture-target")
                .expect_err(&format!("the failed {cli} run must file no document"));
        }
    }

    #[tokio::test]
    async fn the_write_back_step_applies_on_the_scan_path_and_the_show_path() {
        // The type-inference follow-on (issue #341): `--write-back
        // --confidence-floor 0` applies through the typeinfer crate's
        // own write-back API over the retained source on the scan path,
        // `--show --write-back` loads the engine and applies over the
        // filed document, and `--show` without the flag never loads the
        // engine at all — with the target gone it still reports.
        let ws = fixture_workspace();
        let settings = settings_over(ws.path());
        let entry = crate::commands::typeinfer::contribution();
        let write_back = ScanFlags {
            binary: "fixture-target".to_string(),
            show: false,
            no_tag: false,
            set_override_file: None,
            write_back: true,
            confidence_floor: 0,
        };

        handle_scan_command(&entry, &write_back, ws.path(), &settings)
            .await
            .expect("the scan path applies the write-back under the flag");
        let document = ws.path().join("re/analysis/typeinfer/fixture-target.json");
        assert!(document.is_file(), "the ride files at {document:?}");

        handle_scan_command(
            &entry,
            &ScanFlags {
                show: true,
                ..write_back
            },
            ws.path(),
            &settings,
        )
        .await
        .expect("--show --write-back loads the engine and applies over the filed document");

        std::fs::remove_file(ws.path().join("fixture-target")).expect("target gone");
        handle_scan_command(
            &entry,
            &ScanFlags {
                binary: "fixture-target".to_string(),
                show: true,
                no_tag: false,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            },
            ws.path(),
            &settings,
        )
        .await
        .expect("--show without --write-back never loads the engine");
    }

    #[tokio::test]
    async fn a_write_back_without_its_target_load_fails_naming_the_write() {
        // The show-path engine load sits behind the flag: with the
        // document filed but the target gone, `--show --write-back`
        // fails — there is no program to write into — while `--show`
        // alone (the test above) stands.
        let ws = fixture_workspace();
        let settings = settings_over(ws.path());
        let entry = crate::commands::typeinfer::contribution();
        handle_scan_command(
            &entry,
            &ScanFlags {
                binary: "fixture-target".to_string(),
                show: false,
                no_tag: false,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            },
            ws.path(),
            &settings,
        )
        .await
        .expect("the plain typeinfer ride files the document");
        std::fs::remove_file(ws.path().join("fixture-target")).expect("target gone");

        let error = handle_scan_command(
            &entry,
            &ScanFlags {
                binary: "fixture-target".to_string(),
                show: true,
                no_tag: false,
                set_override_file: None,
                write_back: true,
                confidence_floor: 0,
            },
            ws.path(),
            &settings,
        )
        .await
        .expect_err("--show --write-back without its target must fail");
        assert!(
            error.to_string().contains("with the Kuna engine")
                && error.to_string().contains("fixture-target"),
            "the failure names the engine load and its target, got: {error}"
        );
    }

    /// The ride table's roster as (CLI command name, entry) pairs — the
    /// behavior suite's and the pairing tests' driver. A command joining
    /// or leaving the generic path changes here, in `ride`, and in the
    /// `main.rs` arm together; the roster assertion below pins the three.
    fn ridden_table() -> Vec<(&'static str, ScanContribution)> {
        use crate::commands::{
            algorithm, apidetect, callback, consts, controlflow, errhandling, floatsimd,
            globalstate, libmatch, memory, serialize, stringctx, sync, typeinfer,
        };
        vec![
            ("typesdb", typesdb::contribution()),
            ("controlflow", controlflow::contribution()),
            ("memory", memory::contribution()),
            ("sync", sync::contribution()),
            ("globalstate", globalstate::contribution()),
            ("consts", consts::contribution()),
            ("errhandling", errhandling::contribution()),
            ("floatsimd", floatsimd::contribution()),
            ("stringctx", stringctx::contribution()),
            ("apidetect", apidetect::contribution()),
            ("serialize", serialize::contribution()),
            ("callback", callback::contribution()),
            ("algorithm", algorithm::contribution()),
            ("libmatch", libmatch::contribution()),
            ("typeinfer", typeinfer::contribution()),
        ]
    }

    /// The fifteen clap variants the `main.rs` arm routes, all over the
    /// fixture binary with the flags at their defaults.
    fn ridden_commands() -> Vec<crate::cli_types::Command> {
        use crate::cli_types::Command;
        let binary = || "fixture-target".to_string();
        vec![
            Command::Typesdb {
                binary: binary(),
                show: false,
                no_tag: false,
            },
            Command::ControlFlow {
                binary: binary(),
                show: false,
            },
            Command::Memory {
                binary: binary(),
                show: false,
            },
            Command::Sync {
                binary: binary(),
                show: false,
            },
            Command::GlobalState {
                binary: binary(),
                show: false,
            },
            Command::Consts {
                binary: binary(),
                show: false,
            },
            Command::Errhandling {
                binary: binary(),
                show: false,
            },
            Command::Floatsimd {
                binary: binary(),
                show: false,
            },
            Command::StringCtx {
                binary: binary(),
                show: false,
            },
            Command::ApiDetect {
                binary: binary(),
                show: false,
            },
            Command::Serialize {
                binary: binary(),
                show: false,
            },
            Command::Callback {
                binary: binary(),
                show: false,
            },
            Command::Algorithm {
                binary: binary(),
                show: false,
                patterns: None,
            },
            Command::Libmatch {
                binary: binary(),
                show: false,
                signatures: None,
            },
            Command::Typeinfer {
                binary: binary(),
                show: false,
                write_back: false,
                confidence_floor: 70,
            },
        ]
    }

    #[test]
    fn the_ride_table_maps_each_ridden_variant_to_its_own_entry() {
        // The `main.rs` arm, `ride`, and the contribution modules are one
        // roster: every routed variant yields its entry and its flags,
        // and the fifteen rows they serve are exactly the registry's.
        let entries = ridden_table();
        assert_eq!(
            entries
                .iter()
                .map(|(_, entry)| entry.row)
                .collect::<Vec<_>>(),
            vec![
                "type-database",
                "control-flow",
                "memory-lifecycle",
                "concurrency",
                "global-state",
                "constants",
                "error-handling",
                "float-simd",
                "string-context",
                "library-api",
                "serialization",
                "callback-detection",
                "algorithm-recognition",
                "known-library",
                "type-inference",
            ],
            "the ride roster is the fifteen scan commands"
        );
        let commands = ridden_commands();
        assert_eq!(commands.len(), entries.len());
        for (command, (cli, entry)) in commands.iter().zip(&entries) {
            let (ridden, flags) = ride(command).unwrap_or_else(|| panic!("{cli} must ride"));
            assert_eq!(ridden.row, entry.row, "{cli} rides its own entry");
            assert_eq!(flags.binary, "fixture-target");
            assert!(!flags.show, "the routed variants parse show off by default");
            assert!(
                !flags.no_tag,
                "only the typesdb variant carries --no-tag; the others ride with it off"
            );
            assert!(
                flags.set_override_file.is_none(),
                "only the algorithm and libmatch variants carry a set override; \
                 the others ride with it unset"
            );
            assert!(
                !flags.write_back,
                "only the typeinfer variant carries --write-back; the others ride without it"
            );
        }

        // The per-engine flags ride along on their own variants: the
        // set-override paths and the write-back pair arrive on the
        // flags exactly as clap parsed them.
        use crate::cli_types::Command;
        let override_path = std::path::PathBuf::from("my-database.json");
        for (command, named) in [
            (
                Command::Algorithm {
                    binary: "fixture-target".to_string(),
                    show: false,
                    patterns: Some(override_path.clone()),
                },
                "algorithm",
            ),
            (
                Command::Libmatch {
                    binary: "fixture-target".to_string(),
                    show: false,
                    signatures: Some(override_path.clone()),
                },
                "libmatch",
            ),
        ] {
            let (_, flags) = ride(&command).unwrap_or_else(|| panic!("{named} must ride"));
            assert_eq!(
                flags.set_override_file.as_deref(),
                Some(override_path.as_path()),
                "{named}'s set-override flag arrives on the ride flags"
            );
        }
        let (_, flags) = ride(&Command::Typeinfer {
            binary: "fixture-target".to_string(),
            show: true,
            write_back: true,
            confidence_floor: 99,
        })
        .expect("typeinfer rides");
        assert!(flags.show);
        assert!(flags.write_back);
        assert_eq!(flags.confidence_floor, 99);

        // Outside the table: the cross-binary diff has no registry row
        // to ride at all, and keeps its pure-report arm.
        assert!(
            ride(&Command::Bdiff {
                binary: "fixture-target".to_string(),
            })
            .is_none(),
            "the command keeps its dedicated path"
        );
    }

    /// The pairing pin (issue #342), the `libmatch` drift doctrine paid
    /// in at the CLI side: the CLI contribution table and the registry
    /// roster must name the same rows, one entry per row. The fault list
    /// is the data-level verdict — empty means paired, and each fault
    /// spells its drift: a roster row no CLI entry names, an entry
    /// naming a row the roster does not hold, or two entries crowded
    /// onto one row. Adding an engine is one registry row plus one
    /// small contribution entry, and neither half can drift silently.
    /// The pair's twin is the translator's named-roster test
    /// `the_registered_rows_are_exactly_the_named_roster`
    /// (crates/pipeline/calxgloss-translator/src/pipeline.rs): that one
    /// pins the roster against its spelled list so a row enters only by
    /// review, this one pins every roster row to exactly one CLI
    /// contribution. Completeness follows: the behavior suite's walk
    /// `every_ridden_command_files_shows_rescans_and_survives_a_failed_rescan`
    /// drives the very entries read here, so a green pairing means every
    /// engine in the roster is pinned through the generic handler.
    fn pairing_faults(entry_rows: &[&str], roster_rows: &[&str]) -> Vec<String> {
        let mut faults = Vec::new();
        for row in roster_rows {
            let entries_naming = entry_rows.iter().filter(|name| *name == row).count();
            match entries_naming {
                1 => {}
                0 => faults.push(format!(
                    "registry row '{row}' has no CLI contribution entry"
                )),
                count => faults.push(format!(
                    "registry row '{row}' is named by {count} CLI entries, not one"
                )),
            }
        }
        for name in entry_rows {
            if !roster_rows.contains(name) {
                faults.push(format!(
                    "CLI entry naming row '{name}' is not in the registry roster"
                ));
            }
        }
        faults
    }

    #[test]
    fn the_cli_contribution_table_pairs_one_for_one_with_the_registry_roster() {
        // Fifteen entries against fifteen rows, green: both sides read
        // from their tables' own data, never a spelled name list.
        let entry_rows: Vec<&str> = ridden_table().iter().map(|(_, entry)| entry.row).collect();
        let roster_rows: Vec<&str> = scan_rows().iter().map(|row| row.name()).collect();
        assert_eq!(entry_rows.len(), 15, "one CLI entry per scan command");
        assert_eq!(
            roster_rows.len(),
            15,
            "the roster holds the fifteen scan rows"
        );
        let faults = pairing_faults(&entry_rows, &roster_rows);
        assert!(
            faults.is_empty(),
            "every registry row must have exactly one CLI entry naming it, and \
             every entry must name a row in the roster: {faults:#?}"
        );
    }

    #[test]
    fn the_pairing_fails_when_a_roster_row_has_no_cli_entry() {
        // Proven in-test with a fixture row: what a new engine's registry
        // row looks like before its CLI contribution is reviewed must
        // come back as a fault — the pin bites before any real drift.
        let entry_rows: Vec<&str> = ridden_table().iter().map(|(_, entry)| entry.row).collect();
        let mut roster_rows: Vec<&str> = scan_rows().iter().map(|row| row.name()).collect();
        roster_rows.push("fixture-row-without-a-cli-entry");

        let faults = pairing_faults(&entry_rows, &roster_rows);
        assert_eq!(
            faults
                .iter()
                .filter(|fault| fault.contains("fixture-row-without-a-cli-entry"))
                .count(),
            1,
            "a roster row no entry names must fault exactly once: {faults:?}"
        );
    }

    #[test]
    fn the_pairing_fails_when_a_cli_entry_names_a_row_outside_the_roster() {
        // The orphan direction, proven with a fixture entry: an entry
        // naming a row the roster does not hold faults. And one-for-one
        // means exactly one — a fixture entry crowding onto a row that
        // already has its entry faults too.
        let entry_rows: Vec<&str> = ridden_table().iter().map(|(_, entry)| entry.row).collect();
        let roster_rows: Vec<&str> = scan_rows().iter().map(|row| row.name()).collect();

        let mut orphaned = entry_rows.clone();
        orphaned.push("fixture-entry-naming-no-row");
        let faults = pairing_faults(&orphaned, &roster_rows);
        assert_eq!(
            faults
                .iter()
                .filter(|fault| fault.contains("fixture-entry-naming-no-row"))
                .count(),
            1,
            "an entry naming no roster row must fault exactly once: {faults:?}"
        );

        let mut crowded = entry_rows.clone();
        crowded.push(crowded[0]);
        let faults = pairing_faults(&crowded, &roster_rows);
        assert_eq!(
            faults.len(),
            1,
            "the crowded row is the only fault: {faults:?}"
        );
        assert!(
            faults[0].contains(entry_rows[0]),
            "two entries naming one row must fault against that row: {faults:?}"
        );
    }

    #[tokio::test]
    async fn every_ridden_command_files_shows_rescans_and_survives_a_failed_rescan() {
        // The behavior suite over the whole ride table (issues #339–#341):
        // every entry the pairing tests pin green rides this walk, so the
        // fifteen entries here are the whole table — every engine in the
        // roster is pinned through the generic handler (issue #342's
        // completeness half).
        // each routed command scans the fixture and files its document
        // at the row's own `document_path` (the report's print rides the
        // same Ok path), a `--show` over an unscanned workspace fails
        // naming the exact producing command, a re-scan replaces the
        // filed document outright, a failed re-scan leaves the previous
        // document in place, and a `--show` over the filed document with
        // the target gone succeeds — the entry never loads the engine to
        // report what it already holds.
        for (cli, entry) in ridden_table() {
            let ws = fixture_workspace();
            let settings = settings_over(ws.path());
            let flags = ScanFlags {
                binary: "fixture-target".to_string(),
                show: false,
                no_tag: false,
                set_override_file: None,
                write_back: false,
                confidence_floor: 0,
            };

            // Scenario: `--show` with nothing filed fails naming the
            // command that would produce the document.
            let error = handle_scan_command(
                &entry,
                &ScanFlags {
                    binary: flags.binary.clone(),
                    show: true,
                    no_tag: false,
                    set_override_file: None,
                    write_back: false,
                    confidence_floor: 0,
                },
                ws.path(),
                &settings,
            )
            .await
            .expect_err(&format!(
                "{cli} --show over an unscanned workspace must fail"
            ));
            assert!(
                error
                    .to_string()
                    .contains(&format!("run `calxgloss {cli} --binary fixture-target`")),
                "the {cli} remediation names the exact producing command, got: {error}"
            );

            // Scenario: the scan ride succeeds and files the document
            // at the row's own path, readable back through the entry.
            handle_scan_command(&entry, &flags, ws.path(), &settings)
                .await
                .unwrap_or_else(|e| panic!("the {cli} ride must succeed: {e}"));
            let row = scan_rows()
                .into_iter()
                .find(|row| row.name() == entry.row)
                .expect("the entry names a registry row");
            let filed = row.document_path(ws.path(), "fixture-target");
            assert!(
                filed.is_file(),
                "{cli} must file its document at the row's own path: {}",
                filed.display()
            );
            (entry.load)(ws.path(), "fixture-target")
                .unwrap_or_else(|e| panic!("the filed {cli} document must read back: {e}"));

            // Scenario: the re-scan replaces the filed document — the
            // CLI never adopts the cached-hit short-circuit. Tamper the
            // document first: a short-circuited run would fail loading
            // the tamper, so a successful run IS the re-scan.
            std::fs::write(&filed, r#"{"metadata":{"binary":"sentinel"}}"#)
                .expect("tamper the filed document");
            handle_scan_command(&entry, &flags, ws.path(), &settings)
                .await
                .unwrap_or_else(|e| {
                    panic!("the {cli} re-scan must replace the tampered file: {e}")
                });
            let replaced = std::fs::read_to_string(&filed).expect("the re-filed document");
            assert!(
                !replaced.contains("sentinel"),
                "the {cli} re-scan must overwrite the filed document outright"
            );

            // Scenario: a failed re-scan leaves the previous document
            // in place. With the target gone the engine load fails
            // before the row runs, so nothing touches the filed file.
            let before = std::fs::read(&filed).expect("the filed document");
            std::fs::remove_file(ws.path().join("fixture-target")).expect("target gone");
            handle_scan_command(&entry, &flags, ws.path(), &settings)
                .await
                .expect_err(&format!("a {cli} run without its target must fail"));
            assert_eq!(
                std::fs::read(&filed).expect("the document after the failed re-scan"),
                before,
                "a failed {cli} re-scan must leave the previous document untouched"
            );
            (entry.load)(ws.path(), "fixture-target")
                .unwrap_or_else(|e| panic!("the previous {cli} document must still parse: {e}"));

            // Scenario: with the target gone but the document filed,
            // `--show` still succeeds — the report path reads only the
            // filed document, never the program.
            handle_scan_command(
                &entry,
                &ScanFlags {
                    binary: flags.binary.clone(),
                    show: true,
                    no_tag: false,
                    set_override_file: None,
                    write_back: false,
                    confidence_floor: 0,
                },
                ws.path(),
                &settings,
            )
            .await
            .unwrap_or_else(|e| {
                panic!("a {cli} --show over a filed document needs no engine: {e}")
            });
        }
    }

    #[tokio::test]
    async fn the_callback_riding_observes_the_cached_type_inference() {
        // The enrichment the old CLI wired by hand now rides the row's
        // own pre-scan hook: with a filed type-inference document the
        // `callback-detection` row composes real callable contracts into
        // its engine, and the filed type-inference records read back
        // through `callback_signature_map` prove the document the hook
        // composes from is in place. Without the document the ride is
        // exactly what it was (issue #173's degradation, observed over
        // the fixture).
        let flags = ScanFlags {
            binary: "fixture-target".to_string(),
            show: false,
            no_tag: false,
            set_override_file: None,
            write_back: false,
            confidence_floor: 0,
        };

        // Enriched workspace: the producing row's ride files the
        // type-inference document the callback row's hook composes from.
        let enriched = fixture_workspace();
        handle_scan_command(
            &crate::commands::typeinfer::contribution(),
            &flags,
            enriched.path(),
            &settings_over(enriched.path()),
        )
        .await
        .expect("the type-inference ride succeeds over the fixture");

        // Plain workspace: never scanned beside the callback ride.
        let plain = fixture_workspace();

        let callback_entry = crate::commands::callback::contribution();
        for ws in [&enriched, &plain] {
            handle_scan_command(
                &callback_entry,
                &flags,
                ws.path(),
                &settings_over(ws.path()),
            )
            .await
            .unwrap_or_else(|e| panic!("the callback ride must succeed: {e}"));
        }

        // Enrichment observed over the fixture: the composed callable
        // contracts the row's hook reads are present exactly where the
        // type-inference document is filed.
        let composed =
            calxgloss_translator::callback_signature_map(enriched.path(), "fixture-target");
        let unenriched =
            calxgloss_translator::callback_signature_map(plain.path(), "fixture-target");
        assert!(
            !composed.is_empty(),
            "the callback row composed no callable contracts from the filed type-inference document"
        );
        assert!(
            unenriched.is_empty(),
            "without a type-inference document the callback scan stays un-enriched"
        );
    }
}
