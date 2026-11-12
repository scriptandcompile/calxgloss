//! Dashboard builder — assembles [`ReviewDashboard`] from git + file artifacts.
//!
//! The [`DashboardBuilder`] reads a Git repository's branches, patch
//! records, send-back records, and baseline files, and assembles them
//! into a complete review dashboard.
//!
//! Branch state is authoritative for acceptance: a branch merged into
//! `main` is `Accepted`. The failing verdicts instead come from their
//! records — a send-back record makes a unit `SendBack`, and a
//! patch-request record makes it `PatchRequested`. Both records survive a
//! rebuild, so `auto_block_units` has failing units to start its
//! `Blocked` cascade from.
//!
//! The builder also records the dependency edges that the cascade
//! follows. A function unit depends on its DLL's classification unit and
//! on the shim-layer unit that its classification requires — the same
//! dependency that the branch-creation policy (`DependencyChecker`)
//! gates `create_branch` on. So when a shim or classification is sent
//! back, everything translating on top of it shows as blocked.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use calxgloss_git::{DependencyChecker, GitManager};
use calxgloss_types::DllCategory;
use calxgloss_types::dashboard::{
    ReviewDashboard, ReviewSkips, ReviewStatus, Staleness, UnitOfWork, WorkKind,
};
use calxgloss_types::{
    BinaryIdentity, BinaryUnknownLedger, ClassificationOverrides, EffectiveLedger, PersistError,
    UnitObligation, UnitUnknowns, UnknownRecord, UnknownResolutions, classification_record_dir,
    read_classification_record, read_unknown_ledger, read_unknown_resolutions, unknown_ledger_dir,
    work_kind_for_prefix,
};
use chrono::Utc;

use super::audit::binary_unknown_ledger;

/// Parses a git branch name like `re/game_logic.dll/DrawSpritev1` or
/// `re/classify/game_logic.dllv1` into its components. Delegates to
/// [`calxgloss_types::parse_branch_name`], the one owner of the branch-name
/// grammar (issue #69). Only branches whose names start with `re/` parse;
/// a branch without an attempt suffix reads as the first attempt.
pub fn parse_branch_name(name: &str) -> Option<BranchParts> {
    let parts = calxgloss_types::parse_branch_name(name.strip_prefix("re/")?)?;
    Some(BranchParts {
        kind: parts.kind,
        binary: parts.binary,
        function: parts.function,
        attempt: parts.attempt.unwrap_or(1),
    })
}

#[derive(Debug)]
pub struct BranchParts {
    kind: WorkKind,
    binary: BinaryIdentity,
    function: Option<String>,
    attempt: u32,
}

/// Holds parsed data from a single patch record.
#[derive(Debug, Default)]
#[allow(dead_code)]
struct PatchData {
    llm_model: Option<String>,
    baseline_tests_passed: Option<usize>,
    baseline_tests_total: Option<usize>,
    verification_tests_passed: Option<usize>,
    verification_tests_total: Option<usize>,
    unit_confidence: Option<f32>,
    context_tier: Option<usize>,
}

/// Assembles a [`ReviewDashboard`] from the state of a Git repository.
pub struct DashboardBuilder<'a> {
    git: &'a GitManager,
    repo_path: PathBuf,
}

impl<'a> DashboardBuilder<'a> {
    /// Creates a new builder for the given git repository.
    pub fn new(git: &'a GitManager) -> Self {
        Self {
            git,
            repo_path: git.repo_path().to_path_buf(),
        }
    }

    /// Builds the full dashboard, returning a [`ReviewDashboard`].
    pub fn build(&self) -> Result<ReviewDashboard, anyhow::Error> {
        let mut units_by_key: HashMap<String, Vec<UnitOfWork>> = HashMap::new();

        // 1. Discover translation branches
        let branches = self.git.list_translation_branches()?;
        let mut seen_keys: HashMap<String, u32> = HashMap::new();

        for branch in &branches {
            let parts = match parse_branch_name(branch) {
                Some(p) => p,
                None => continue,
            };

            let key = unit_key(&parts);
            let existing_attempt = seen_keys.entry(key.clone()).or_insert(0);

            if parts.attempt > *existing_attempt {
                *existing_attempt = parts.attempt;
            }
        }

        // 2. Scan patch records for per-attempt data
        let patch_records = self.read_all_patch_records()?;

        // 2b. Scan send-back records for sent-back verdicts
        let sent_back_keys = self.read_all_send_back_records()?;

        // 2c. Read the reviewer's skip set (issue #75)
        let skipped_keys = self.read_skips();

        // 2c'. Read the unknown ledgers and the reviewer's resolutions
        // document (issue #376) so open records ride the derived model the
        // way parking reasons do. A ledger that was never filed, carries no
        // `records` key, or failed to parse leaves its units *unknown* —
        // never an honest zero — and a corrupt resolutions document makes
        // every unit's settled state unknown too. Both degrade with a
        // warning here, on this derived surface; the resolve/dismiss
        // endpoints still fail loudly on the same corrupt documents.
        let unknown_resolutions = match read_unknown_resolutions(&self.repo_path) {
            Ok(resolutions) => Some(resolutions),
            Err(err) => {
                eprintln!(
                    "  [unknowns] resolutions document unreadable, open-unknown state unknown: {err}"
                );
                None
            }
        };
        let mut ledger_cache: HashMap<String, Option<Vec<UnknownRecord>>> = HashMap::new();

        // 2d. Read the classification records and the operator's
        // classification overrides, and use them to build the set of
        // *parked* binaries — those whose in-force category is
        // `DotNetManaged` (issue #235). The override wins over the
        // record, the same precedence every other consumer applies. A
        // parked binary's units of work take the derived
        // `DoNotTranslate` status; the record's reason is kept in
        // `known_gaps` so the queue view can explain the parking.
        let classified = self.read_classification_records();
        let overrides = self.read_classification_overrides()?;
        let parked = parked_classifications(&classified, &overrides);

        // 3. Read baseline data
        let baselines = self.read_all_baselines()?;

        // 4. Determine the *latest* attempt for each key and build units
        for (key, latest_attempt) in &seen_keys {
            let mut unit = self.build_unit(&branches, key, *latest_attempt, &patch_records);

            // Open unknown records ride the unit the way parking reasons
            // ride below (issue #376): scoped by the unit's own function —
            // a functionless unit carries the records filed against the
            // binary itself — then joined to the reviewer's resolutions at
            // read time, never from a stored copy of the join.
            unit.unknowns = derive_unit_unknowns(
                self.ledger_records(&mut ledger_cache, unit.binary.as_str()),
                unknown_resolutions.as_ref(),
                unit.function.as_deref(),
            );

            // The baseline map keys `{file}/{func}` verbatim. The unit
            // key also ends with the attempt, so only that part is
            // stripped — the binary part is already the verbatim filename
            // (issue #68, issue #67).
            let baseline_key = strip_attempt_suffix(key);
            if let Some(baseline) = baselines.get(baseline_key) {
                unit.baseline_tests_total = Some(baseline.test_count);
                unit.baseline_tests_passed = Some(baseline.pass_count);
            }

            let has_patch = patch_records
                .iter()
                .any(|pr| pr.key == *key && pr.attempt <= *latest_attempt);
            let patch_requested = patch_records
                .iter()
                .any(|pr| pr.key == *key && pr.patch_request.is_some());
            let sent_back = sent_back_keys.contains(key.as_str());

            let merged = self.is_branch_merged(key);

            // Branch state is authoritative for acceptance. Failing
            // verdicts come from the durable records. A send-back at this
            // attempt outranks a patch request: re-patching after a
            // send-back puts the request on the *next* attempt's key,
            // never this one. A reviewer's explicit skip (issue #75)
            // outranks the artifact-derived failing and pending states —
            // unskipping restores them.
            unit.status = if merged {
                ReviewStatus::Accepted
            } else if let Some(reason) = parked.get(unit.binary.as_str()) {
                // Do Not Translate (issue #235): the binary's in-force
                // classification is DotNetManaged. That is a fact about
                // the binary itself: it outranks reviewer skips and
                // artifact-derived verdicts, and changes only when the
                // record or an override changes. The documented reason
                // is recorded in known_gaps for the queue view.
                if let Some(reason) = reason {
                    unit.known_gaps.push(reason.clone());
                }
                ReviewStatus::DoNotTranslate
            } else if skipped_keys.contains(key.as_str()) {
                ReviewStatus::Skipped
            } else if sent_back {
                ReviewStatus::SendBack
            } else if patch_requested {
                ReviewStatus::PatchRequested
            } else if has_patch {
                ReviewStatus::PendingReview
            } else {
                ReviewStatus::Queued
            };

            units_by_key.entry(unit.id.clone()).or_default().push(unit);
        }

        // 5. Also check for classified DLLs not covered by translation
        // branches. A parked (.NET managed) binary's synthetic classify
        // unit is *not* auto-accepted — it takes the derived
        // do-not-translate status so the parking stays visible
        // (issue #235). Unknowns filed against the binary itself belong
        // to this unit (issue #376).
        for cls in &classified {
            let key = format!("classify/{}", cls.binary);
            if !seen_keys.contains_key(&key) {
                let parked_unit = parked.contains_key(&cls.binary);
                let known_gaps = parked
                    .get(&cls.binary)
                    .and_then(|reason| reason.clone())
                    .map(|reason| vec![reason])
                    .unwrap_or_default();
                let unit = UnitOfWork {
                    id: key.clone(),
                    name: format!("Classify {}", cls.binary),
                    kind: WorkKind::DllClassification,
                    binary: cls.binary.clone().into(),
                    function: None,
                    attempt: 1,
                    status: if parked_unit {
                        ReviewStatus::DoNotTranslate
                    } else {
                        ReviewStatus::Accepted
                    },
                    accepted: !parked_unit,
                    unit_confidence: Some(0.95),
                    baseline_tests_passed: None,
                    baseline_tests_total: None,
                    verification_tests_passed: None,
                    verification_tests_total: None,
                    llm_model: Some("classificator".to_string()),
                    context_tier: Some(0),
                    dependencies: vec![],
                    created_at: cls.classified_at,
                    updated_at: cls.classified_at,
                    known_gaps,
                    stale: Staleness::Fresh,
                    unknowns: derive_unit_unknowns(
                        self.ledger_records(&mut ledger_cache, &cls.binary),
                        unknown_resolutions.as_ref(),
                        None,
                    ),
                    // A classification is not a unit of restitch work: the
                    // obligation ledger never rosters it, and its reading
                    // stays the honest unknown (issue #424).
                    obligation: UnitObligation::unknown(),
                };
                units_by_key.entry(key).or_default().push(unit);
            }
        }

        // 6. Flatten and de-duplicate units
        let mut units: Vec<UnitOfWork> = units_by_key
            .into_values()
            .map(|mut v| {
                v.sort_by_key(|u| u.attempt);
                v.pop().unwrap()
            })
            .collect();

        // 6. Record the dependency edges from the branch model so the
        //    failing verdicts above cascade `Blocked` down the graph. A
        //    function unit depends on:
        //    - its DLL's classification unit (`classify/{binary}`), and
        //    - the shim-layer unit its classification requires. These are
        //      exactly the `DependencyChecker` results that gate branch
        //      creation in `GitManager::create_branch`, so the dashboard
        //      graph shows the same work that the branch model says must
        //      merge first.
        let classify_ids: HashMap<String, String> = units
            .iter()
            .filter(|u| u.kind == WorkKind::DllClassification)
            .map(|u| {
                let binary = u.id.strip_prefix("classify/").unwrap_or(&u.id);
                (strip_attempt_suffix(binary).to_string(), u.id.clone())
            })
            .collect();

        let shim_ids: HashMap<String, String> = units
            .iter()
            .filter(|u| u.kind == WorkKind::ShimLayer)
            .filter_map(|u| u.function.clone().map(|krate| (krate, u.id.clone())))
            .collect();

        let classified_by_dll: HashMap<String, &ClassifiedDll> =
            classified.iter().map(|c| (c.binary.clone(), c)).collect();

        let checker = DependencyChecker::new();
        for unit in &mut units {
            if unit.kind != WorkKind::FunctionTranslation {
                continue;
            }
            let dll_key = unit.binary.as_str();

            if let Some(class_id) = classify_ids.get(dll_key)
                && !unit.dependencies.contains(class_id)
            {
                unit.dependencies.push(class_id.clone());
            }

            if let Some(cls) = classified_by_dll.get(dll_key)
                && let Some(category) = &cls.category
            {
                let required =
                    checker.check(&cls.binary, category, cls.crate_replacement.as_deref());
                for branch in &required.required {
                    // The required dependencies are branch names
                    // (`re/shim/{crate}`); the matching dashboard unit has
                    // the same name parts as a shim unit.
                    if let Some(shim_parts) = parse_branch_name(branch)
                        && let Some(krate) = &shim_parts.function
                        && let Some(shim_id) = shim_ids.get(krate)
                        && !unit.dependencies.contains(shim_id)
                    {
                        unit.dependencies.push(shim_id.clone());
                    }
                }
            }
        }

        // Issue #377: the per-binary unknown audit ledger, on the model and
        // derived exactly the way the run close prints it — one join over
        // the pipeline's filed ledgers, so the terminal and the close can
        // never disagree. Every binary the worklist named gets a row, and
        // every ledger filed under `re/unknowns/` gets one too, so a binary
        // with a filed ledger but no branch is still named at the close.
        let mut ledger_binaries: BTreeSet<String> = units
            .iter()
            .map(|unit| unit.binary.as_str().to_string())
            .collect();
        if let Ok(entries) = std::fs::read_dir(unknown_ledger_dir(&self.repo_path)) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) == Some("json")
                    && let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
                {
                    ledger_binaries.insert(stem.to_string());
                }
            }
        }
        let unknown_ledgers: Vec<BinaryUnknownLedger> = ledger_binaries
            .iter()
            .map(|binary| {
                binary_unknown_ledger(
                    binary,
                    self.ledger_records(&mut ledger_cache, binary)
                        .map(|records| &records[..]),
                    unknown_resolutions.as_ref(),
                )
            })
            .collect();

        // Issue #419 (P26.3): the per-binary conformance verdict rides the
        // same model, derived fresh on every build — the obligation
        // ledger joined at read time, never a stored copy that could
        // drift. Every translated unit's binary and every ledger filed
        // under `re/obligations/` gets a row. Supporting shim and
        // classification branches are not target binaries and get none —
        // their pseudo-binary would only print a false "no ledger filed"
        // verdict (issue #419).
        let conformance_set = super::conformance::conformance_binaries(
            &self.repo_path,
            units
                .iter()
                .filter(|unit| unit.kind == WorkKind::FunctionTranslation)
                .map(|unit| unit.binary.as_str().to_string()),
        );

        let mut dashboard = ReviewDashboard::new(units);
        dashboard.unknown_ledgers = unknown_ledgers;

        // The read seam joins the obligation ledgers with the reviewer's
        // live records — the same skip set, parked classifications, and
        // unit override records the review surfaces above read (issue
        // #420).
        // The reviewer unit override record joins the conformance rows
        // through the shared handle's fallible open: a never-filed
        // record yields an empty handle that joins nothing, and a
        // corrupt one stops the build naming the fault (issue #459).
        let unit_overrides = match calxgloss_types::OverrideControl::try_open(&self.repo_path) {
            Ok(control) => Some(control),
            Err(err) => {
                return Err(
                    anyhow::Error::from(err).context("reading the reviewer unit override record")
                );
            }
        };
        let conformance_join = super::conformance::ConformanceJoin {
            skipped: skipped_keys.iter().cloned().collect(),
            parked: parked
                .iter()
                .map(|(binary, reason)| (binary.as_str(), reason.clone()))
                .collect(),
            overrides: unit_overrides,
        };
        dashboard.conformance = super::conformance::derive_binary_conformance(
            self.git,
            &conformance_set,
            &dashboard.unknown_ledgers,
            &conformance_join,
        );

        // Issue #424 (P26.8): each function-translation unit also carries
        // its own *obligation entry*, filled from the same ledger read and
        // the same live-record join as the per-binary rows just derived —
        // the unit detail and the queue view read one derivation and can
        // never disagree. A binary whose ledger was never filed yields no
        // entry: every unit of that binary keeps the unknown reading,
        // never a closed obligation.
        let unit_obligations = super::conformance::derive_unit_obligations(
            &self.repo_path,
            &conformance_set,
            &conformance_join,
        );
        for unit in dashboard
            .review_queue
            .iter_mut()
            .chain(dashboard.recent_activity.iter_mut())
        {
            if unit.kind != WorkKind::FunctionTranslation {
                continue;
            }
            let Some(function) = unit.function.as_deref() else {
                continue;
            };
            unit.obligation = unit_obligations
                .get(unit.binary.as_str())
                .and_then(|by_attempt| by_attempt.get(&(function.to_string(), unit.attempt)))
                .cloned()
                .unwrap_or_default();
        }

        // Issue #409 (P24.8): the scenario status rides the same model,
        // derived from the filed scenario documents the same way for the
        // terminal dashboard and the web review API alike — target-binary
        // evidence beside the queue, never per-unit evidence.
        dashboard.scenario_statuses = super::scenarios::derive_scenario_statuses(&self.repo_path);

        let blocked = dashboard.auto_block_units();
        if blocked > 0 {
            eprintln!(
                "  [auto-block] Marked {} units as blocked due to unmet dependencies",
                blocked
            );
        }

        Ok(dashboard)
    }

    /// Reads every patch record under `re/patches/{binary}/{function}/v{N}.json`
    /// (written by `GitManager::store_failure` for failures and by the review
    /// UI's request-patch action for patch requests).
    fn read_all_patch_records(&self) -> Result<Vec<PatchRecordEntry>, anyhow::Error> {
        let mut records = Vec::new();
        for file in read_record_tree::<calxgloss_git::PatchRecord>(
            &self.repo_path.join("re").join("patches"),
        )? {
            let patch = file.record;
            records.push(PatchRecordEntry {
                key: format!("{}/{}/v{}", file.binary, patch.function, file.attempt),
                attempt: file.attempt,
                compilation_errors: patch.compilation_errors.len(),
                test_failures: patch.test_failures.len(),
                committed_at: patch.committed_at,
                patch_request: patch.patch_request,
            });
        }
        Ok(records)
    }

    /// Reads the reviewer skip set from `re/review/skips.json` (issue #75).
    /// A missing or corrupt file degrades to an empty set — skip state is
    /// advisory review data, never a build error.
    fn read_skips(&self) -> std::collections::HashSet<String> {
        read_review_skips(&self.repo_path)
    }

    /// One binary's ledger records, read once per build and cached. The
    /// cache carries the honesty reading: `None` means unknown — the
    /// ledger was never filed, carries no `records` key, or failed to
    /// parse — and only `Some(records)`, filed with an explicit list,
    /// speaks. A corrupt document degrades to unknown *here*, on the
    /// derived surface, with a warning; the resolve/dismiss endpoints
    /// still fail loudly on the same document.
    fn ledger_records<'c>(
        &self,
        cache: &'c mut HashMap<String, Option<Vec<UnknownRecord>>>,
        binary: &str,
    ) -> Option<&'c Vec<UnknownRecord>> {
        cache
            .entry(binary.to_string())
            .or_insert_with(|| {
                match read_unknown_ledger(&self.repo_path, &BinaryIdentity::from(binary)) {
                    Ok(EffectiveLedger::Filed(records)) => Some(records),
                    Ok(EffectiveLedger::Unknown) => None,
                    Err(err) => {
                        eprintln!(
                            "  [unknowns] {binary}: ledger unreadable, open-unknown state unknown: {err}"
                        );
                        None
                    }
                }
            })
            .as_ref()
    }

    /// Reads every send-back record under
    /// `re/rejections/{binary}/{function}/v{N}.json` (written by
    /// `GitManager::reject_branch`), returning the unit keys
    /// (`{binary}/{function}/v{attempt}`) whose attempt a reviewer sent back.
    ///
    /// Without this read the `SendBack` verdict is invisible after a
    /// rebuild: branch state alone cannot tell a sent-back branch from a
    /// queued one, and `auto_block_units` would have no failing unit to
    /// start blocking from.
    fn read_all_send_back_records(
        &self,
    ) -> Result<std::collections::HashSet<String>, anyhow::Error> {
        let mut keys = std::collections::HashSet::new();
        for file in
            read_record_tree::<SendBackRecord>(&self.repo_path.join("re").join("rejections"))?
        {
            keys.insert(format!(
                "{}/{}/v{}",
                file.binary, file.record.function, file.attempt
            ));
        }
        Ok(keys)
    }

    /// Reads every baseline artifact under
    /// `re/baseline/{file}/{func}/baseline.json` (the layout written by
    /// `calxgloss-testgen`), keying the map `{file}/{func}` with both
    /// directory names verbatim — the binary directory's name is the
    /// filename with extension (issue #68), so `foo.dll` and `foo.exe`
    /// stay distinct entries.
    fn read_all_baselines(&self) -> Result<HashMap<String, BaselineData>, anyhow::Error> {
        let mut baselines = HashMap::new();
        let baseline_dir = self.repo_path.join("re").join("baseline");
        if !baseline_dir.exists() {
            return Ok(baselines);
        }

        for file_dir in std::fs::read_dir(&baseline_dir)? {
            let file_dir = file_dir?;
            if !file_dir.path().is_dir() {
                continue;
            }
            let file = file_dir.file_name().to_string_lossy().to_string();

            for func_dir in std::fs::read_dir(file_dir.path())? {
                let func_dir = func_dir?;
                if !func_dir.path().is_dir() {
                    continue;
                }
                let func_name = func_dir.file_name().to_string_lossy().to_string();

                let baseline_path = func_dir.path().join("baseline.json");
                if !baseline_path.exists() {
                    continue;
                }

                let content = std::fs::read_to_string(&baseline_path)?;
                let tests: Vec<calxgloss_types::TestResult> = match serde_json::from_str(&content) {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                let test_count = tests.len();
                let pass_count = tests.iter().filter(|t| t.passed).count();

                baselines.insert(
                    format!("{}/{}", file, func_name),
                    BaselineData {
                        test_count,
                        pass_count,
                    },
                );
            }
        }

        Ok(baselines)
    }

    /// Reads every classification record under `re/classify/{binary}.json`
    /// (written by the `classify` command). The category and crate
    /// replacement are parsed leniently — a record that fails to parse
    /// still counts as classified, it just declares no shim dependency.
    fn read_classification_records(&self) -> Vec<ClassifiedDll> {
        read_classification_records(&self.repo_path)
    }

    /// Reads the operator's classification overrides through the shared
    /// read (issue #459): a missing document is the clean state — no
    /// overrides, so the records apply exactly as written — and a corrupt
    /// one is a fault the build reports, never an empty map that would
    /// hide reviewer decisions.
    fn read_classification_overrides(&self) -> Result<ClassificationOverrides, anyhow::Error> {
        Ok(read_classification_overrides(&self.repo_path)?)
    }

    fn is_branch_merged(&self, key: &str) -> bool {
        let all_branches = match self.git.list_branches() {
            Ok(b) => b,
            Err(_) => return false,
        };

        for branch in all_branches {
            if !branch.starts_with("re/") {
                continue;
            }
            let branch_parts = parse_branch_name(&branch);
            if let Some(bp) = branch_parts {
                let branch_key = unit_key(&bp);
                if branch_key == key
                    && let Ok(merged) = self.is_branch_merged_into_main(&branch)
                    && merged
                {
                    return true;
                }
            }
        }
        false
    }

    fn is_branch_merged_into_main(&self, branch_name: &str) -> Result<bool, anyhow::Error> {
        let main_ref = self
            .git
            .repo()
            .find_branch("main", git2::BranchType::Local)
            .ok()
            .and_then(|b| b.get().peel_to_commit().ok());

        let branch_ref = self
            .git
            .repo()
            .find_branch(branch_name, git2::BranchType::Local)
            .ok()
            .and_then(|b| b.get().peel_to_commit().ok());

        match (main_ref, branch_ref) {
            (Some(main_commit), Some(branch_commit)) => {
                let is_ancestor = self
                    .git
                    .repo()
                    .graph_ahead_behind(branch_commit.id(), main_commit.id())
                    .map(|(ahead, _)| ahead == 0)
                    .unwrap_or(false);
                Ok(is_ancestor)
            }
            _ => Ok(false),
        }
    }

    fn build_unit(
        &self,
        branches: &[String],
        key: &str,
        latest_attempt: u32,
        patch_records: &[PatchRecordEntry],
    ) -> UnitOfWork {
        let parts = parse_branch_name_for_key(key, latest_attempt);
        let display_name = match &parts.function {
            Some(func) => format!("Translate {}", func),
            None => format!("Classify {}", parts.binary),
        };

        let id = if let Some(ref func) = parts.function {
            format!("{}/{}/v{}", parts.binary, func, latest_attempt)
        } else {
            format!("classify/{}", parts.binary)
        };

        let patch_data = patch_records
            .iter()
            .filter(|pr| {
                pr.key.contains(parts.binary.as_str())
                    && pr.key.contains(parts.function.as_deref().unwrap_or(""))
            })
            .max_by_key(|pr| pr.attempt);

        let patch_info = patch_data.map(|pr| {
            let err_count = pr.compilation_errors + pr.test_failures;
            if err_count > 0 {
                0.3 + (0.1 * err_count as f32).min(0.6)
            } else {
                0.8
            }
        });

        let now = Utc::now();
        // The unit's work is dated by its branch tip commit when the branch
        // exists — the build clock would make every unit "just now" on each
        // dashboard rebuild. Fall back to the patch record, then to now.
        let branch_time = branches
            .iter()
            .find(|b| {
                parse_branch_name(b)
                    .is_some_and(|bp| unit_key(&bp) == key && bp.attempt == latest_attempt)
            })
            .and_then(|b| self.git.branch_commit_time(b).ok());
        let (updated_at, stale) = match branch_time {
            Some(t) => (t, Staleness::from_elapsed(now, t)),
            None => patch_data
                .map(|pr| {
                    let dt = chrono::DateTime::parse_from_rfc3339(&pr.committed_at)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or(now);
                    let staleness = Staleness::from_elapsed(now, dt);
                    (dt, staleness)
                })
                .unwrap_or((now, Staleness::Fresh)),
        };

        UnitOfWork {
            id,
            name: display_name,
            kind: parts.kind,
            binary: parts.binary,
            function: parts.function,
            attempt: latest_attempt,
            status: ReviewStatus::Queued,
            accepted: false,
            unit_confidence: patch_data.map(|_| patch_info.unwrap_or(0.5)),
            baseline_tests_passed: None,
            baseline_tests_total: None,
            verification_tests_passed: None,
            verification_tests_total: None,
            llm_model: None,
            context_tier: None,
            dependencies: vec![],
            created_at: now,
            updated_at,
            known_gaps: vec![],
            stale,
            unknowns: UnitUnknowns::unknown(),
            // Filled from the filed obligation ledger after the read seam
            // joins (issue #424); until then the reading is the honest
            // unknown, never a closed obligation.
            obligation: UnitObligation::unknown(),
        }
    }
}

/// Reads the reviewer skip set from `re/review/skips.json` (issue #75).
/// A missing or corrupt file degrades to an empty set — skip state is
/// advisory review data, never a build error. The builder and the run
/// close's conformance derivation (issue #423) read through this one
/// function so the live skip set can never decide a unit one way on the
/// terminal and another way at the close.
pub(crate) fn read_review_skips(workspace: &std::path::Path) -> std::collections::HashSet<String> {
    let path = ReviewSkips::path_in(workspace);
    let skips: ReviewSkips = match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => ReviewSkips::default(),
    };
    skips.skipped.into_iter().collect()
}

/// Every classification record under `re/classify/{binary}.json` (written
/// by the `classify` command), read through the shared classification
/// read (issue #457). The category and crate replacement are parsed
/// leniently — a record that fails to parse still counts as classified,
/// it just declares no shim dependency. Shared by the builder and the
/// run close's conformance derivation (issue #423).
pub(crate) fn read_classification_records(workspace: &std::path::Path) -> Vec<ClassifiedDll> {
    let classify_dir = classification_record_dir(workspace);
    if !classify_dir.exists() {
        return Vec::new();
    }

    let entries = match std::fs::read_dir(&classify_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut dlls = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let file_name = entry.file_name().to_string_lossy().to_string();
        if file_name.ends_with(".json") {
            let dll_name = file_name.trim_end_matches(".json").to_string();
            // The record's mtime says when the classification happened. The
            // build clock would make it "just now" on every refresh.
            let classified_at = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(chrono::DateTime::<chrono::Utc>::from)
                .unwrap_or_else(chrono::Utc::now);
            // The lenient policy is a decision made at this site (issue #457).
            // A record whose bytes do not parse still counts the binary as
            // classified. Its category, crate replacement, and reason stay
            // honestly unknown. The shared module's read names missing and
            // corrupt apart; matching every fault keeps this site's choice
            // visible to the compiler, not left to a default value.
            let record = read_classification_record(workspace, &BinaryIdentity::new(&dll_name));
            dlls.push(match record {
                Ok(record) => ClassifiedDll {
                    binary: dll_name,
                    category: record.category,
                    crate_replacement: record.crate_replacement,
                    reason: record.reason,
                    classified_at,
                },
                Err(
                    PersistError::NotFound { .. }
                    | PersistError::Json { .. }
                    | PersistError::Io { .. },
                ) => ClassifiedDll {
                    binary: dll_name,
                    category: None,
                    crate_replacement: None,
                    reason: None,
                    classified_at,
                },
            });
        }
    }
    dlls
}

/// Reads the operator's classification overrides from
/// `re/analysis/classification_overrides.json` (written by the web
/// classification endpoints) through the shared read (issue #459): a
/// missing document is `Ok(default)` — no overrides, so the records apply
/// exactly as written — and a present-but-unreadable one comes back as a
/// fault naming the document. Shared by the builder and the run close's
/// conformance derivation (issue #423).
pub(crate) fn read_classification_overrides(
    workspace: &std::path::Path,
) -> Result<ClassificationOverrides, PersistError> {
    match calxgloss_types::read_classification_overrides(workspace) {
        Ok(records) => Ok(records),
        // A never-overridden workspace is the documented clean state:
        // the records apply exactly as written.
        Err(PersistError::NotFound { .. }) => Ok(ClassificationOverrides::default()),
        Err(fault) => Err(fault),
    }
}

/// The *parked* binaries among the classification records — those whose
/// in-force category is `DotNetManaged` (issue #235). The override wins
/// over the record, the same precedence every other consumer applies. The
/// record's reason rides beside each binary. Shared by the builder's queue
/// and both conformance readers (issue #420, issue #423).
pub(crate) fn parked_classifications(
    classified: &[ClassifiedDll],
    overrides: &ClassificationOverrides,
) -> HashMap<String, Option<String>> {
    classified
        .iter()
        .filter_map(|c| {
            let r#override = overrides.overrides.get(&c.binary);
            let category = r#override
                .map(|o| o.category.clone())
                .or_else(|| c.category.clone())?;
            if category != DllCategory::DotNetManaged {
                return None;
            }
            let reason = match r#override {
                Some(o) => Some(o.override_reason()),
                None => c.reason.clone(),
            };
            Some((c.binary.clone(), reason))
        })
        .collect()
}

/// The unit's open unknown records, scoped by the unit's own function and
/// joined to the reviewer's resolutions at read time (issue #376) — the
/// same scoping rule the resolve/dismiss endpoint applies: functionless
/// records belong to the binary itself and ride its classification unit.
///
/// Honesty rides through untouched: `None` ledger (never filed, no
/// `records` key, unreadable) and an unreadable resolutions document both
/// leave the unit *unknown*, never an honest zero.
fn derive_unit_unknowns(
    records: Option<&Vec<UnknownRecord>>,
    resolutions: Option<&UnknownResolutions>,
    function: Option<&str>,
) -> UnitUnknowns {
    let (Some(records), Some(resolutions)) = (records, resolutions) else {
        return UnitUnknowns::unknown();
    };
    let scoped: Vec<UnknownRecord> = records
        .iter()
        .filter(|record| record.function.as_deref() == function)
        .cloned()
        .collect();
    UnitUnknowns::from_joined(&resolutions.join(&scoped))
}

fn unit_key(parts: &BranchParts) -> String {
    match &parts.function {
        Some(func) => format!("{}/{}/v{}", parts.binary, func, parts.attempt),
        None => format!("classify/{}", parts.binary),
    }
}

fn parse_branch_name_for_key(key: &str, default_attempt: u32) -> BranchParts {
    if key.starts_with("classify/") {
        let binary = key.strip_prefix("classify/").unwrap_or(key);
        return BranchParts {
            kind: WorkKind::DllClassification,
            binary: binary.to_string().into(),
            function: None,
            attempt: default_attempt,
        };
    }

    let (base, _) = key.rsplit_once('/').unwrap_or((key, ""));
    let parts: Vec<&str> = base.splitn(2, '/').collect();

    BranchParts {
        kind: parts
            .first()
            .and_then(|s| work_kind_for_prefix(s))
            .unwrap_or(WorkKind::FunctionTranslation),
        binary: parts
            .first()
            .map(|s| s.to_string())
            .unwrap_or_default()
            .into(),
        function: parts.get(1).map(|s| s.to_string()),
        attempt: default_attempt,
    }
}

/// Strips a trailing `/v{N}` attempt suffix from a classification unit's
/// binary segment so branch-derived ids (`classify/{file}/vN`) and
/// record-derived ids (`classify/{file}`) key to the same verbatim binary
/// filename. The binary's identity keeps its extension (issue #68).
fn strip_attempt_suffix(name: &str) -> &str {
    match name.rsplit_once("/v") {
        Some((base, n)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => base,
        _ => name,
    }
}

#[derive(Debug)]
struct PatchRecordEntry {
    key: String,
    attempt: u32,
    compilation_errors: usize,
    test_failures: usize,
    committed_at: String,
    /// The reviewer's stated issue when this record is a patch *request*
    /// (written by the review UI's request-patch action); `None` on plain
    /// pipeline failure records and successful retry records.
    patch_request: Option<String>,
}

/// The fields the builder needs from a send-back record
/// (`re/rejections/{binary}/{function}/v{N}.json`, written by
/// `GitManager::reject_branch`); the attempt comes from the file name.
#[derive(Debug, serde::Deserialize)]
struct SendBackRecord {
    function: String,
}

/// One record file from the shared review-record tree: the DLL directory
/// name (verbatim, extension included), the attempt number from the file
/// name, and the deserialized record.
struct RecordFile<T> {
    binary: String,
    attempt: u32,
    record: T,
}

/// Walks the `{root}/{binary}/{function}/v{N}.json` layout shared by patch and
/// send-back records, deserializing every `*.json` file into `T`. A missing
/// root yields nothing; unreadable or malformed files are skipped.
fn read_record_tree<T: serde::de::DeserializeOwned>(
    root: &std::path::Path,
) -> Result<Vec<RecordFile<T>>, anyhow::Error> {
    let mut files = Vec::new();
    if !root.exists() {
        return Ok(files);
    }

    for dll_dir in std::fs::read_dir(root)? {
        let dll_dir = dll_dir?;
        // Record directories are named with the verbatim binary filename
        // (issue #68).
        let binary = dll_dir.file_name().to_string_lossy().to_string();

        if !dll_dir.path().is_dir() {
            continue;
        }

        for func_dir in std::fs::read_dir(dll_dir.path())? {
            let func_dir = func_dir?;
            if !func_dir.path().is_dir() {
                continue;
            }

            for entry in std::fs::read_dir(func_dir.path())? {
                let entry = entry?;
                let file_name = entry.file_name().to_string_lossy().to_string();
                if !file_name.ends_with(".json") {
                    continue;
                }

                let attempt = file_name
                    .strip_prefix("v")
                    .and_then(|s| s.trim_end_matches(".json").parse().ok())
                    .unwrap_or(0);

                let content = std::fs::read_to_string(entry.path())?;
                let record: T = match serde_json::from_str(&content) {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                files.push(RecordFile {
                    binary: binary.clone(),
                    attempt,
                    record,
                });
            }
        }
    }

    Ok(files)
}

#[derive(Debug)]
struct BaselineData {
    test_count: usize,
    pass_count: usize,
}

/// A DLL with a classification record on disk. `binary` is the record file name
/// minus `.json` (the `classify` command keeps the `.dll` extension in it);
/// the category and crate replacement decide the shim dependency edge, and
/// the reason explains a parked (`DotNetManaged`) classification.
#[derive(Debug)]
pub(crate) struct ClassifiedDll {
    binary: String,
    category: Option<DllCategory>,
    crate_replacement: Option<String>,
    reason: Option<String>,
    /// When the record was written (its file mtime).
    classified_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_branch_name_reads_shim_branch() {
        let parts = parse_branch_name("re/shim/wgpu").expect("shim branch parses");
        assert_eq!(parts.kind, WorkKind::ShimLayer);
        assert_eq!(parts.binary, "shim");
        assert_eq!(parts.function.as_deref(), Some("wgpu"));
        assert_eq!(unit_key(&parts), "shim/wgpu/v1");
    }

    #[test]
    fn parse_branch_name_for_key_keeps_supporting_work_kind() {
        // A shim unit rebuilt from its key must stay at the shim level in
        // the dependency graph, not become a function translation.
        let parts = parse_branch_name_for_key("shim/wgpu/v2", 2);
        assert_eq!(parts.kind, WorkKind::ShimLayer);
        assert_eq!(parts.binary, "shim");
        assert_eq!(parts.function.as_deref(), Some("wgpu"));

        let parts = parse_branch_name_for_key("game_logic.dll/DrawSprite/v1", 1);
        assert_eq!(parts.kind, WorkKind::FunctionTranslation);
        assert_eq!(parts.binary, "game_logic.dll");
        assert_eq!(parts.function.as_deref(), Some("DrawSprite"));
    }

    #[test]
    fn strip_attempt_suffix_keys_record_and_branch_id_shapes() {
        // Record-derived ids have no attempt, branch-derived ids do;
        // both must key to the same verbatim binary filename.
        assert_eq!(strip_attempt_suffix("d3d9.dll"), "d3d9.dll");
        assert_eq!(strip_attempt_suffix("game_logic.dll/v1"), "game_logic.dll");
    }

    #[test]
    fn baselines_attach_to_units_by_verbatim_file_and_function() {
        // Baseline artifacts live at `re/baseline/{file}/{func}/baseline.json`
        // (the layout testgen writes); the builder joins them to units on the
        // verbatim `{file}/{func}` key — no extension stripping, so
        // `game_logic.dll` and `game_logic.exe` stay distinct units (issue #67).
        let dir = tempfile::tempdir().expect("temp dir");
        let git = init_test_repo(dir.path());

        git.create_branch("game_logic.dll", "DrawPrimitive", 1, None)
            .expect("binary translation branch");
        git.create_branch("game_logic.exe", "DrawPrimitive", 1, None)
            .expect("exe translation branch");
        write_baseline(
            &git,
            "game_logic.dll",
            "DrawPrimitive",
            &[true, true, false],
        );
        write_baseline(&git, "game_logic.exe", "DrawPrimitive", &[true]);

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");

        let dll_unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");
        assert_eq!(dll_unit.baseline_tests_total, Some(3));
        assert_eq!(dll_unit.baseline_tests_passed, Some(2));

        let exe_unit = find_unit(&dashboard, "game_logic.exe/DrawPrimitive/v1");
        assert_eq!(exe_unit.baseline_tests_total, Some(1));
        assert_eq!(exe_unit.baseline_tests_passed, Some(1));
    }

    /// Initialises a test git repo (a `main` branch with one commit) in `path`.
    fn init_test_repo(path: &std::path::Path) -> GitManager {
        let config = calxgloss_git::InitConfig {
            author_name: "Calxgloss Test".into(),
            author_email: "test@calxgloss.test".into(),
            committer_name: None,
            committer_email: None,
        };
        GitManager::init_repo(path, Some(config)).expect("init git repo")
    }

    /// Writes a `re/baseline/{file}/{func}/baseline.json` artifact in the
    /// exact `Vec<TestResult>` shape testgen persists, one result per entry
    /// of `passed`.
    fn write_baseline(git: &GitManager, file: &str, function: &str, passed: &[bool]) {
        let results: Vec<calxgloss_types::TestResult> = passed
            .iter()
            .map(|&p| calxgloss_types::TestResult {
                test_case: calxgloss_types::TestCase {
                    inputs: serde_json::json!({"x": 1}),
                    expected_return: serde_json::json!(1),
                    expected_side_effects: vec![],
                    expected_api_calls: vec![],
                    origin: calxgloss_types::CaseOrigin::Generated,
                    case_kind: None,
                },
                actual_return: serde_json::json!(1),
                actual_side_effects: vec![],
                actual_api_calls: vec![],
                passed: p,
                error: None,
            })
            .collect();
        let dir = git
            .repo_path()
            .join("re")
            .join("baseline")
            .join(file)
            .join(function);
        std::fs::create_dir_all(&dir).expect("baseline dir");
        std::fs::write(
            dir.join("baseline.json"),
            serde_json::to_string(&results).expect("serialize baseline"),
        )
        .expect("write baseline");
    }

    #[test]
    fn skipped_units_keep_skipped_status_across_rebuilds() {
        // The reviewer's skip set at `re/review/skips.json` (issue #75) is
        // applied over the artifact-derived status for unmerged units, so a
        // skipped unit stays out of the active queue after a rebuild.
        let dir = tempfile::tempdir().expect("temp dir");
        let git = init_test_repo(dir.path());

        let branch = git
            .create_branch("game_logic.dll", "DrawPrimitive", 1, None)
            .expect("translation branch")
            .branch;
        std::fs::write(dir.path().join("translation.c"), "// translated").expect("write source");
        git.commit(&branch, "re: translate DrawPrimitive", &[])
            .expect("commit on branch");

        write_skips(&git, &["game_logic.dll/DrawPrimitive/v1"]);

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");

        let unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");
        assert_eq!(unit.status, ReviewStatus::Skipped);
    }

    #[test]
    fn merged_units_stay_accepted_despite_skip() {
        // Branch state is authoritative for acceptance: a merged branch is
        // Accepted even if the skip set still names the unit.
        let dir = tempfile::tempdir().expect("temp dir");
        let git = init_test_repo(dir.path());

        git.create_branch("game_logic.dll", "DrawPrimitive", 1, None)
            .expect("translation branch");

        write_skips(&git, &["game_logic.dll/DrawPrimitive/v1"]);

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");

        let unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");
        assert_eq!(unit.status, ReviewStatus::Accepted);
    }

    /// Writes a `re/review/skips.json` artifact naming the given unit ids.
    fn write_skips(git: &GitManager, ids: &[&str]) {
        let dir = git.repo_path().join("re").join("review");
        std::fs::create_dir_all(&dir).expect("review dir");
        let skips = ReviewSkips {
            skipped: ids.iter().map(|s| s.to_string()).collect(),
        };
        std::fs::write(
            dir.join("skips.json"),
            serde_json::to_string(&skips).expect("serialize skips"),
        )
        .expect("write skips");
    }

    /// Fetches a built unit by id from either dashboard list.
    fn find_unit<'a>(dashboard: &'a ReviewDashboard, id: &str) -> &'a UnitOfWork {
        dashboard
            .review_queue
            .iter()
            .chain(dashboard.recent_activity.iter())
            .find(|u| u.id == id)
            .unwrap_or_else(|| panic!("unit {id} present in dashboard"))
    }

    // ── .NET managed parking (issue #235) ──

    /// Creates an unmerged translation branch: one commit on the branch so
    /// it is genuinely ahead of `main` and the builder treats it as
    /// unmerged work.
    fn start_unmerged_branch(git: &GitManager, binary: &str, function: &str) {
        let branch = git
            .create_branch(binary, function, 1, None)
            .expect("translation branch")
            .branch;
        let file = git.repo_path().join("src").join(format!(
            "{}_{}.rs",
            binary.replace('.', "_"),
            function
        ));
        std::fs::create_dir_all(file.parent().expect("src dir")).expect("src dir");
        std::fs::write(&file, "// translated").expect("write source");
        git.commit(&branch, &format!("re: translate {function}"), &[])
            .expect("commit on branch");
    }

    /// Writes a `re/classify/{binary}.json` record with the given category
    /// (variant name verbatim) and reason.
    fn write_classification(git: &GitManager, binary: &str, category: &str, reason: &str) {
        let dir = git.repo_path().join("re").join("classify");
        std::fs::create_dir_all(&dir).expect("classify dir");
        let record = serde_json::json!({ "category": category, "reason": reason });
        std::fs::write(
            dir.join(format!("{binary}.json")),
            serde_json::to_string(&record).expect("serialize classification"),
        )
        .expect("write classification");
    }

    /// Writes a `re/analysis/classification_overrides.json` map steering
    /// `binary` to the given category.
    fn write_classification_override(git: &GitManager, binary: &str, category: &str) {
        let dir = git.repo_path().join("re").join("analysis");
        std::fs::create_dir_all(&dir).expect("analysis dir");
        let overrides = serde_json::json!({
            "overrides": {
                binary: { "category": category, "crate_replacement": null, "known_runtime": false }
            }
        });
        std::fs::write(
            dir.join("classification_overrides.json"),
            serde_json::to_string(&overrides).expect("serialize overrides"),
        )
        .expect("write overrides");
    }

    #[test]
    fn parked_managed_units_park_with_reason_and_sort_after_skipped() {
        // A DotNetManaged classification record parks the binary's units at
        // the queue end with the record's reason in known_gaps; a skipped
        // native unit still sorts before them (stories 5, 10, 12, 27).
        let dir = tempfile::tempdir().expect("temp dir");
        let git = init_test_repo(dir.path());

        start_unmerged_branch(&git, "game_logic.dll", "DrawPrimitive");
        start_unmerged_branch(&git, "managed_app.dll", "Main");
        write_classification(
            &git,
            "managed_app.dll",
            "DotNetManaged",
            "we do not yet decompile .NET programs",
        );
        write_classification(&git, "game_logic.dll", "ProjectSpecific", "project binary");
        write_skips(&git, &["game_logic.dll/DrawPrimitive/v1"]);

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");

        let parked = find_unit(&dashboard, "managed_app.dll/Main/v1");
        assert_eq!(parked.status, ReviewStatus::DoNotTranslate);
        assert!(
            parked
                .known_gaps
                .iter()
                .any(|g| g.contains("we do not yet decompile .NET programs")),
            "the queue view carries the record's reason, got: {:?}",
            parked.known_gaps
        );

        let skipped = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");
        assert_eq!(skipped.status, ReviewStatus::Skipped);

        // Both stay visible in the full queue view, parked units last.
        let ids: Vec<&str> = dashboard
            .review_queue
            .iter()
            .map(|u| u.id.as_str())
            .collect();
        let skipped_at = ids
            .iter()
            .position(|id| *id == "game_logic.dll/DrawPrimitive/v1")
            .expect("skipped unit in queue view");
        let parked_at = ids
            .iter()
            .position(|id| *id == "managed_app.dll/Main/v1")
            .expect("parked unit in queue view");
        assert!(
            parked_at > skipped_at,
            "parked units sort after skipped, queue order: {ids:?}"
        );

        // The synthetic classify unit is parked too — not auto-accepted.
        let classify = find_unit(&dashboard, "classify/managed_app.dll");
        assert_eq!(classify.status, ReviewStatus::DoNotTranslate);
        assert!(
            !classify.accepted,
            "a parked classification is not accepted"
        );
        assert_eq!(
            find_unit(&dashboard, "classify/game_logic.dll").status,
            ReviewStatus::Accepted
        );
    }

    #[test]
    fn parked_units_are_exempt_from_the_auto_block_cascade() {
        // A parked function unit depends on its parked classify unit — an
        // unaccepted dependency the cascade would normally block; the
        // derived status outranks it (story 13).
        let dir = tempfile::tempdir().expect("temp dir");
        let git = init_test_repo(dir.path());

        start_unmerged_branch(&git, "managed_app.dll", "Main");
        write_classification(
            &git,
            "managed_app.dll",
            "DotNetManaged",
            "we do not yet decompile .NET programs",
        );

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");

        let unit = find_unit(&dashboard, "managed_app.dll/Main/v1");
        assert!(
            unit.dependencies
                .iter()
                .any(|d| d == "classify/managed_app.dll"),
            "the branch-model edge is wired, got: {:?}",
            unit.dependencies
        );
        assert_eq!(unit.status, ReviewStatus::DoNotTranslate);
    }

    #[test]
    fn a_corrupt_classification_record_still_lists_the_binary_with_no_category() {
        // The builder's lenient policy, stated at its own site (issue #457):
        // a record whose bytes do not parse keeps the binary listed. Its
        // synthetic classify unit still stands, and nothing parks it — the
        // category is honestly unknown and no reason is invented. The
        // unreadable record never reads as an unclassified binary.
        let dir = tempfile::tempdir().expect("temp dir");
        let git = init_test_repo(dir.path());

        let classify = classification_record_dir(git.repo_path());
        std::fs::create_dir_all(&classify).expect("classify dir");
        std::fs::write(classify.join("broken.dll.json"), "{ not json")
            .expect("file an unparseable record");

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");

        // The read itself: the corrupt record still lists the binary, with
        // category, crate replacement, and reason all honestly unknown.
        let listed = read_classification_records(dir.path());
        assert_eq!(
            listed.len(),
            1,
            "the corrupt record keeps the binary listed"
        );
        assert_eq!(
            listed[0].binary, "broken.dll",
            "the file's name keys the row"
        );
        assert!(
            listed[0].category.is_none(),
            "an unreadable record leaves the category unknown, not invented"
        );
        assert!(listed[0].crate_replacement.is_none(), "no shim is implied");
        assert!(listed[0].reason.is_none(), "no reason is invented");

        let unit = find_unit(&dashboard, "classify/broken.dll");
        assert_eq!(
            unit.status,
            ReviewStatus::Accepted,
            "a corrupt record does not park the binary it names"
        );
        assert!(
            unit.known_gaps.is_empty(),
            "no reason is invented for a record that cannot be read: {:?}",
            unit.known_gaps
        );
    }

    #[test]
    fn parked_status_survives_rebuilds() {
        // Parking comes from the durable record, not session state — a
        // rebuild re-derives the same status (story 11).
        let dir = tempfile::tempdir().expect("temp dir");
        let git = init_test_repo(dir.path());

        start_unmerged_branch(&git, "managed_app.dll", "Main");
        write_classification(
            &git,
            "managed_app.dll",
            "DotNetManaged",
            "we do not yet decompile .NET programs",
        );

        for round in 1..=2 {
            let dashboard = DashboardBuilder::new(&git)
                .build()
                .unwrap_or_else(|_| panic!("dashboard builds (round {round})"));
            assert_eq!(
                find_unit(&dashboard, "managed_app.dll/Main/v1").status,
                ReviewStatus::DoNotTranslate,
                "parking survives rebuild round {round}"
            );
        }
    }

    #[test]
    fn override_away_from_managed_releases_the_units() {
        // Operator overrides work at the dashboard layer too: an override
        // away from DotNetManaged releases the parked units, and the
        // parking reason no longer shows in known_gaps (stories 21, 22).
        let dir = tempfile::tempdir().expect("temp dir");
        let git = init_test_repo(dir.path());

        start_unmerged_branch(&git, "managed_app.dll", "Main");
        write_classification(
            &git,
            "managed_app.dll",
            "DotNetManaged",
            "we do not yet decompile .NET programs",
        );
        write_classification_override(&git, "managed_app.dll", "ProjectSpecific");

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");

        let unit = find_unit(&dashboard, "managed_app.dll/Main/v1");
        assert_eq!(unit.status, ReviewStatus::Queued);
        assert!(
            !unit
                .known_gaps
                .iter()
                .any(|g| g.contains("we do not yet decompile")),
            "the parked reason is gone once the override releases the binary, got: {:?}",
            unit.known_gaps
        );
    }

    // ─── Open unknown records on the derived model (issue #376) ────────

    /// One ledger record with the smallest fields the pins need.
    fn unknown_record(
        id: &str,
        function: Option<&str>,
        severity: calxgloss_types::UnknownSeverity,
    ) -> UnknownRecord {
        UnknownRecord {
            id: id.to_string(),
            binary: BinaryIdentity::from("game_logic.dll"),
            function: function.map(str::to_string),
            kind: calxgloss_types::UnknownKind::CoverageFacet,
            severity,
            question: format!("What is {id} really?"),
            required_evidence: "call-site survey".to_string(),
            origin: calxgloss_types::UnknownOrigin::CaseSet {
                case_set: "cs-1".to_string(),
            },
            first_seen: 1,
            last_seen: 1,
            revision: 1,
        }
    }

    /// Files `re/unknowns/game_logic.dll.json` with the given reading:
    /// `None` writes the document without a `records` key (the keyless
    /// reading), `Some` files the list — empty or not — under the key.
    fn write_ledger(dir: &std::path::Path, records: Option<Vec<UnknownRecord>>) {
        let dir_path = dir.join("re").join("unknowns");
        std::fs::create_dir_all(&dir_path).expect("unknowns dir");
        let doc = serde_json::json!({ "binary": "game_logic.dll", "filed_at": 1 });
        let mut doc = doc;
        if let Some(records) = records {
            doc["records"] = serde_json::to_value(&records).expect("records serialize");
        }
        std::fs::write(dir_path.join("game_logic.dll.json"), doc.to_string()).expect("file ledger");
    }

    /// A unit's branch the unknowns can ride on.
    fn one_unit_repo(dir: &std::path::Path) -> GitManager {
        let git = init_test_repo(dir);
        git.create_branch("game_logic.dll", "DrawPrimitive", 1, None)
            .expect("translation branch");
        git
    }

    #[test]
    fn unit_with_a_filed_ledger_carries_its_open_records_and_severity_counts() {
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        write_ledger(
            dir.path(),
            Some(vec![
                unknown_record(
                    "u-a",
                    Some("DrawPrimitive"),
                    calxgloss_types::UnknownSeverity::Blocking,
                ),
                unknown_record(
                    "u-b",
                    Some("DrawPrimitive"),
                    calxgloss_types::UnknownSeverity::Notable,
                ),
            ]),
        );

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");

        let open = unit
            .unknowns
            .open
            .as_ref()
            .expect("filed ledger reads open");
        assert_eq!(open.len(), 2, "both filed records ride the unit");
        assert_eq!(
            unit.unknowns.open_count(),
            Some(2),
            "the unit carries its open count"
        );
        let by_severity = &unit.unknowns.open_by_severity;
        assert_eq!(
            by_severity.get(&calxgloss_types::UnknownSeverity::Blocking),
            Some(&1)
        );
        assert_eq!(
            by_severity.get(&calxgloss_types::UnknownSeverity::Notable),
            Some(&1)
        );
    }

    #[test]
    fn records_scoped_to_another_function_never_ride_the_unit() {
        // The same scoping rule the resolve/dismiss endpoint applies:
        // a record function-scoped to `OtherFunction` belongs to that
        // function's unit, not this one.
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        write_ledger(
            dir.path(),
            Some(vec![unknown_record(
                "u-x",
                Some("OtherFunction"),
                calxgloss_types::UnknownSeverity::Blocking,
            )]),
        );

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");

        assert_eq!(
            unit.unknowns.open.as_deref(),
            Some(&[][..]),
            "a filed ledger scoped to nobody here is the honest known-and-none, not unknown"
        );
        assert_eq!(unit.unknowns.open_count(), Some(0));
    }

    #[test]
    fn functionless_records_are_scoped_away_from_function_units() {
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        write_ledger(
            dir.path(),
            Some(vec![unknown_record(
                "u-bin",
                None,
                calxgloss_types::UnknownSeverity::Material,
            )]),
        );

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");

        assert_eq!(unit.unknowns.open_count(), Some(0));
    }

    #[test]
    fn no_ledger_at_all_leaves_the_unit_unknown_never_zero() {
        // The first reading: nobody ever filed a ledger. The unit says
        // *unknown* — `None` open, no counts — and the surfaces render
        // it as unknown, never as an innocent 0.
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");

        assert!(unit.unknowns.open.is_none(), "absent ledger is unknown");
        assert_eq!(unit.unknowns.open_count(), None);
    }

    #[test]
    fn filed_ledger_without_a_records_key_is_unknown_too() {
        // The second reading: the document exists but never spoke — the
        // `records` key is absent (the ADR-0053 absent-field rule), so it
        // must not be laundered into known-and-none.
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        write_ledger(dir.path(), None);

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");

        assert!(unit.unknowns.open.is_none(), "keyless ledger is unknown");
    }

    /// The filed contract document as `scenario declare` keeps exactly one
    /// per target binary (issue #409).
    fn file_scenario_contract(workspace: &std::path::Path, binary: &str, scenario: &str) {
        let path = calxgloss_types::scenario_contracts_path(
            workspace,
            &calxgloss_types::BinaryIdentity::from(binary),
        );
        std::fs::create_dir_all(path.parent().expect("contracts dir")).expect("contracts dir");
        std::fs::write(
            &path,
            serde_json::json!({
                "binary": binary,
                "filed_at": 1,
                "scenarios": { scenario: {
                    "name": scenario,
                    "working_dir": ".",
                    "cols": 80,
                    "rows": 24,
                    "idle_timeout_ms": 5000,
                    "max_run_ms": 15000,
                    "finalization_grace_ms": 1000,
                    "max_output_bytes": 65536,
                    "normalization": { "version": "norm-v1" }
                }}
            })
            .to_string(),
        )
        .expect("file contract document");
    }

    #[test]
    fn filed_scenario_documents_ride_the_dashboard_as_per_binary_scenario_status() {
        // Issue #409: the dashboard carries the scenario status beside
        // the queue — and a binary with no filed scenario documents gets
        // no row at all, never a fabricated nothing-declared checklist.
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        file_scenario_contract(dir.path(), "eqgame.exe", "boot");

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");

        assert_eq!(
            dashboard.scenario_statuses.len(),
            1,
            "only eqgame.exe speaks"
        );
        assert_eq!(dashboard.scenario_statuses[0].binary, "eqgame.exe");
        let boot = &dashboard.scenario_statuses[0].scenarios[0];
        assert_eq!(boot.scenario, "boot");
        assert!(boot.declared, "the filed contract declares it");
        assert!(!boot.captured, "no capture filed — not-captured");
        assert_eq!(
            boot.verdict,
            calxgloss_types::ScenarioVerdictReading::Unassessed,
            "no verdict filed — unassessed"
        );
        assert!(
            !dashboard
                .scenario_statuses
                .iter()
                .any(|status| status.binary == "game_logic.dll"),
            "the unit's binary with no scenario documents gets no row"
        );
    }

    #[test]
    fn filed_empty_ledger_is_the_honest_known_and_none() {
        // The third reading, kept distinct from both others all the way
        // to the model: a filed, explicitly empty list says nobody has
        // anything open — and only that says it.
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        write_ledger(dir.path(), Some(vec![]));

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");

        assert_eq!(unit.unknowns.open_count(), Some(0), "known-and-none");
        assert!(unit.unknowns.open.is_some());
    }

    #[test]
    fn corrupt_ledger_degrades_to_unknown_but_never_fails_the_build() {
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        let ledger_dir = dir.path().join("re").join("unknowns");
        std::fs::create_dir_all(&ledger_dir).expect("unknowns dir");
        std::fs::write(ledger_dir.join("game_logic.dll.json"), "{ not json")
            .expect("corrupt ledger");

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("a corrupt ledger never fails the derived build");
        let unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");

        assert!(unit.unknowns.open.is_none(), "unreadable ledger is unknown");
    }

    #[test]
    fn corrupt_resolutions_document_makes_every_unit_unknown_not_empty() {
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        write_ledger(
            dir.path(),
            Some(vec![unknown_record(
                "u-a",
                Some("DrawPrimitive"),
                calxgloss_types::UnknownSeverity::Blocking,
            )]),
        );
        let review_dir = dir.path().join("re").join("review");
        std::fs::create_dir_all(&review_dir).expect("review dir");
        std::fs::write(review_dir.join("unknown_resolutions.json"), "{{ broken")
            .expect("corrupt resolutions");

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("a corrupt resolutions document never fails the derived build");
        let unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");

        assert!(
            unit.unknowns.open.is_none(),
            "with unreadable resolutions nobody can say open from settled — unknown, never the raw ledger list"
        );
    }

    #[test]
    fn settled_records_read_as_settled_not_open() {
        // The join rides apart: the reviewer resolved one record and
        // dismissed another; what remains open is only the unsetled
        // remainder, and the settled counts stand beside it — visibly
        // distinct from open, without the model storing its own copy
        // of the join.
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        let rec_a = unknown_record(
            "u-a",
            Some("DrawPrimitive"),
            calxgloss_types::UnknownSeverity::Blocking,
        );
        let rec_b = unknown_record(
            "u-b",
            Some("DrawPrimitive"),
            calxgloss_types::UnknownSeverity::Material,
        );
        let rec_c = unknown_record(
            "u-c",
            Some("DrawPrimitive"),
            calxgloss_types::UnknownSeverity::Notable,
        );
        write_ledger(
            dir.path(),
            Some(vec![rec_a.clone(), rec_b.clone(), rec_c.clone()]),
        );

        let mut resolutions = UnknownResolutions::default();
        resolutions
            .resolve(&rec_a, "evidence arrived", 1, 5)
            .expect("resolve");
        resolutions
            .dismiss(&rec_b, "not a gap", 1, 6)
            .expect("dismiss");
        let review_dir = dir.path().join("re").join("review");
        std::fs::create_dir_all(&review_dir).expect("review dir");
        std::fs::write(
            review_dir.join("unknown_resolutions.json"),
            serde_json::to_string(&resolutions).expect("serialize resolutions"),
        )
        .expect("file resolutions");

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");

        let open = unit.unknowns.open.as_ref().expect("ledger is filed");
        assert_eq!(open.len(), 1, "only the unsetled record is open");
        assert_eq!(open[0].id, "u-c");
        assert_eq!(unit.unknowns.resolved, 1);
        assert_eq!(unit.unknowns.dismissed, 1);
    }

    // ─── Per-binary unknown audit ledger on the model (issue #377) ──────

    use super::super::{audit, conformance};

    fn find_ledger<'a>(
        dashboard: &'a ReviewDashboard,
        binary: &str,
    ) -> &'a calxgloss_types::BinaryUnknownLedger {
        dashboard
            .unknown_ledgers
            .iter()
            .find(|ledger| ledger.binary == binary)
            .unwrap_or_else(|| {
                panic!(
                    "{binary} must be named in the audit ledgers, got {:?}",
                    dashboard
                        .unknown_ledgers
                        .iter()
                        .map(|l| &l.binary)
                        .collect::<Vec<_>>()
                )
            })
    }

    #[test]
    fn the_model_carries_a_per_binary_ledger_with_settles_kept_apart() {
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        let rec_a = unknown_record(
            "u-a",
            Some("DrawPrimitive"),
            calxgloss_types::UnknownSeverity::Blocking,
        );
        let rec_b = unknown_record(
            "u-b",
            Some("OtherFunction"),
            calxgloss_types::UnknownSeverity::Material,
        );
        let rec_c = unknown_record("u-c", None, calxgloss_types::UnknownSeverity::Notable);
        write_ledger(
            dir.path(),
            Some(vec![rec_a.clone(), rec_b.clone(), rec_c.clone()]),
        );
        let mut resolutions = UnknownResolutions::default();
        resolutions
            .resolve(&rec_a, "evidence arrived", 1, 5)
            .expect("resolve");
        resolutions
            .dismiss(&rec_b, "not a gap", 1, 6)
            .expect("dismiss");
        let review_dir = dir.path().join("re").join("review");
        std::fs::create_dir_all(&review_dir).expect("review dir");
        std::fs::write(
            review_dir.join("unknown_resolutions.json"),
            serde_json::to_string(&resolutions).expect("serialize resolutions"),
        )
        .expect("file resolutions");

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let ledger = find_ledger(&dashboard, "game_logic.dll");

        // The binary row is the binary-level ledger: every filed record for
        // the binary is counted, whatever unit it scopes to.
        let open = ledger.unknowns.open.as_ref().expect("filed ledger");
        assert_eq!(
            open.len(),
            1,
            "only the unsetled record is open at binary level"
        );
        assert_eq!(open[0].id, "u-c");
        assert_eq!(ledger.unknowns.resolved, 1);
        assert_eq!(ledger.unknowns.dismissed, 1);
        assert_eq!(
            ledger
                .unknowns
                .open_by_severity
                .get(&calxgloss_types::UnknownSeverity::Notable),
            Some(&1),
            "the open severity counts are the open ones"
        );
    }

    #[test]
    fn an_unfiled_ledger_names_the_binary_as_unknown_not_clean() {
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let ledger = find_ledger(&dashboard, "game_logic.dll");

        assert!(
            ledger.unknowns.open.is_none(),
            "absent ledger is unknown, and unknown never launders to clean"
        );
    }

    #[test]
    fn a_filed_ledger_binary_with_no_unit_is_still_named_at_the_close() {
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        let ledger_dir = dir.path().join("re").join("unknowns");
        std::fs::create_dir_all(&ledger_dir).expect("unknowns dir");
        std::fs::write(
            ledger_dir.join("engine_helpers.dll.json"),
            r#"{"binary": "engine_helpers.dll", "filed_at": 1, "records": []}"#,
        )
        .expect("file second ledger");

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let ledger = find_ledger(&dashboard, "engine_helpers.dll");

        assert_eq!(
            ledger.unknowns.open.as_deref(),
            Some(&[][..]),
            "the filed empty ledger reads honest-none at the close"
        );
        assert!(
            dashboard
                .review_queue
                .iter()
                .all(|unit| unit.binary.as_str() != "engine_helpers.dll"),
            "the binary is named for its ledger, not for any unit of work"
        );
    }

    #[test]
    fn the_model_ledgers_and_the_run_close_derivation_agree() {
        // The agreement pin (retargeted from the terminal's printed lines
        // at issue #485): the builder's model ledgers and the run-close
        // derivation read the same documents through the same join. Same
        // documents in, identical readings out — the two derivations
        // cannot disagree.
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        write_ledger(
            dir.path(),
            Some(vec![
                unknown_record(
                    "u-a",
                    Some("DrawPrimitive"),
                    calxgloss_types::UnknownSeverity::Blocking,
                ),
                unknown_record("u-b", None, calxgloss_types::UnknownSeverity::Material),
            ]),
        );
        let ledger_dir = dir.path().join("re").join("unknowns");
        std::fs::write(
            ledger_dir.join("keyless_engine.dll.json"),
            r#"{"binary": "keyless_engine.dll", "filed_at": 1}"#,
        )
        .expect("file keyless ledger");

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let binaries: Vec<String> = dashboard
            .unknown_ledgers
            .iter()
            .map(|ledger| ledger.binary.clone())
            .collect();
        let run_close = audit::derive_binary_unknown_ledgers(dir.path(), &binaries);

        assert_eq!(run_close.len(), dashboard.unknown_ledgers.len());
        for (model, close) in dashboard.unknown_ledgers.iter().zip(&run_close) {
            assert_eq!(model.binary, close.binary);
            assert_eq!(
                model.unknowns, close.unknowns,
                "{}: the model build and the run-close derivation must read the same ledger",
                model.binary,
            );
        }
    }

    #[test]
    fn the_model_conformance_rows_and_the_run_close_derivation_agree() {
        // The conformance agreement pin (issue #423, retargeted from the
        // terminal's printed lines at issue #485). The builder derives the
        // model's conformance rows; the run close derives its own rows
        // straight from the filed documents through the same read seam, so
        // the two derivations must land on identical rows. The fixture
        // reaches every join path: a reviewer skip, a reviewer unit
        // override, a parked classification, a filed disposition, and a
        // ledger document with only an envelope.
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        write_ledger(
            dir.path(),
            Some(vec![unknown_record(
                "u-b",
                None,
                calxgloss_types::UnknownSeverity::Material,
            )]),
        );
        // The reviewer's skip set speaks for DrawPrimitive, and the
        // reviewer's unit override record speaks for OtherFunction. The
        // claim on DrawPrimitive cites a receipt pair, so a reader that
        // ignored the live skip set would close that obligation and print a
        // different line here.
        stage_obligation_ledger(
            dir.path(),
            "game_logic.dll",
            vec![
                claimed_verified_entry("DrawPrimitive", 1, "sha256:cafe"),
                calxgloss_types::ObligationEntry::new(
                    "OtherFunction",
                    1,
                    "",
                    calxgloss_types::ObligationDisposition::NoBaseline,
                ),
            ],
        );
        stage_skip_set(dir.path(), &["game_logic.dll/DrawPrimitive/v1"]);
        stage_unit_override(dir.path(), "game_logic.dll", "OtherFunction");
        // A second target whose own classification record parks every unit,
        // so the parked join speaks before any claim is read.
        stage_parked_classification(dir.path(), "managed_app");
        stage_obligation_ledger(
            dir.path(),
            "managed_app",
            vec![calxgloss_types::ObligationEntry::new(
                "Main",
                1,
                "",
                calxgloss_types::ObligationDisposition::NoBaseline,
            )],
        );
        // A third target whose ledger document names no roster at all.
        stage_envelope_only_ledger(dir.path(), "tampered.dll");

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let binaries: Vec<String> = dashboard
            .conformance
            .iter()
            .map(|row| row.binary.clone())
            .collect();
        let run_close = conformance::derive_run_conformance(dir.path(), &binaries)
            .expect("the run close folds its conformance rows");

        assert_eq!(run_close.len(), dashboard.conformance.len());
        for (model, close) in dashboard.conformance.iter().zip(&run_close) {
            assert_eq!(model.binary, close.binary);
            assert_eq!(
                model, close,
                "{}: the model build and the run-close derivation must read the same conformance row",
                model.binary,
            );
        }

        // A pin over rows that never joined anything proves nothing, so the
        // fixture has to reach each live record the read seam joins with.
        let links: Vec<&str> = dashboard
            .conformance
            .iter()
            .filter_map(|row| row.first_open.as_ref())
            .map(|open| open.link.as_str())
            .collect();
        assert!(
            links
                .iter()
                .any(|link| link.contains("skip set names this unit")),
            "no row names the reviewer's skip set: {links:?}"
        );
        assert!(
            links
                .iter()
                .any(|link| link.contains("classification parks it")),
            "no row names a parked classification: {links:?}"
        );
        assert!(
            dashboard
                .conformance
                .iter()
                .any(|row| row.tally.overridden > 0),
            "no row counts a reviewer unit override"
        );
        assert!(
            dashboard.conformance.iter().any(|row| row
                .causes
                .contains(&calxgloss_types::ConformanceUnknownCause::DigestMismatch)),
            "no row reads the envelope-only ledger as an input error"
        );
    }

    #[test]
    fn a_corrupt_unit_override_record_stops_the_dashboard_naming_the_fault() {
        // The join over reviewer overrides reads through the shared
        // read: a corrupt record is a fault the build reports, never
        // an empty join that would hide reviewer decisions (issue #459).
        let dir = tempfile::tempdir().expect("temp dir");
        let git = init_test_repo(dir.path());
        std::fs::create_dir_all(dir.path().join("re").join("analysis")).expect("analysis dir");
        std::fs::write(
            calxgloss_types::override_records_path(dir.path()),
            "{ not json",
        )
        .expect("corrupt the override record");

        let err = DashboardBuilder::new(&git)
            .build()
            .expect_err("a corrupt override record is a fault, not an empty join");
        let message = format!("{err:#}");
        assert!(
            message.contains("unit_overrides.json"),
            "the fault names the unreadable record: {message}"
        );
    }

    #[test]
    fn a_corrupt_classification_override_document_stops_the_dashboard_naming_the_fault() {
        // Same for the whole-workspace classification override document.
        let dir = tempfile::tempdir().expect("temp dir");
        let git = init_test_repo(dir.path());
        std::fs::create_dir_all(dir.path().join("re").join("analysis")).expect("analysis dir");
        std::fs::write(
            calxgloss_types::classification_override_records_path(dir.path()),
            "{ not json",
        )
        .expect("corrupt the override document");

        let err = DashboardBuilder::new(&git)
            .build()
            .expect_err("a corrupt override document is a fault, not a default");
        let message = format!("{err:#}");
        assert!(
            message.contains("classification_overrides.json"),
            "the fault names the unreadable document: {message}"
        );
    }

    #[test]
    fn the_run_close_conformance_read_reports_a_corrupt_record_as_a_fault() {
        // The run close's conformance derivation reads the same records: a
        // corrupt one is a fault, matching the model's refusal.
        let dir = tempfile::tempdir().expect("temp dir");
        let workspace = dir.path().join("repo");
        std::fs::create_dir_all(workspace.join("re").join("analysis")).expect("analysis dir");
        std::fs::write(
            calxgloss_types::override_records_path(&workspace),
            "{ not json",
        )
        .expect("corrupt the override record");

        let err = conformance::derive_run_conformance(&workspace, &["app.exe".to_string()])
            .expect_err("a corrupt record stops the fold naming the fault");
        let message = format!("{err:#}");
        assert!(
            message.contains("unit_overrides.json"),
            "the fault names the unreadable record: {message}"
        );
    }

    /// Files one target's obligation ledger at `re/obligations/{binary}.json`,
    /// sealed through the same filing call every writer uses.
    fn stage_obligation_ledger(
        workspace: &std::path::Path,
        binary: &str,
        entries: Vec<calxgloss_types::ObligationEntry>,
    ) {
        let ledger = calxgloss_types::ObligationLedger::file(binary, entries, 1_700_000_000)
            .expect("the ledger seals");
        calxgloss_types::save_json(
            &calxgloss_types::obligation_ledger_path(workspace, &ledger.binary),
            &ledger,
        )
        .expect("file the obligation ledger");
    }

    /// One green claim as a filed ledger stores it: the claim cites the
    /// receipt pair named by `receipt_digest`.
    fn claimed_verified_entry(
        function: &str,
        attempt: u32,
        receipt_digest: &str,
    ) -> calxgloss_types::ObligationEntry {
        let mut entry = calxgloss_types::ObligationEntry::new(
            function,
            attempt,
            "",
            calxgloss_types::ObligationDisposition::ClaimedVerified,
        );
        entry.receipt_digest = Some(receipt_digest.to_string());
        entry
    }

    /// Files the reviewer skip set naming these unit keys, in the shape the
    /// review surfaces write it.
    fn stage_skip_set(workspace: &std::path::Path, units: &[&str]) {
        std::fs::create_dir_all(workspace.join("re").join("review")).expect("review dir");
        std::fs::write(
            ReviewSkips::path_in(workspace),
            serde_json::json!({ "skipped": units }).to_string(),
        )
        .expect("file the reviewer skip set");
    }

    /// Files the reviewer's unit override record for `{binary}/{function}` at
    /// `re/analysis/unit_overrides.json`.
    fn stage_unit_override(workspace: &std::path::Path, binary: &str, function: &str) {
        std::fs::create_dir_all(workspace.join("re").join("analysis")).expect("analysis dir");
        std::fs::write(
            calxgloss_types::override_records_path(workspace),
            serde_json::json!({
                "overrides": {
                    format!("{binary}/{function}"): { "reviewer_notes": "checked line by line" }
                }
            })
            .to_string(),
        )
        .expect("file the unit override record");
    }

    /// Files the classification record that parks one binary's units, the
    /// shape the `classify` command files at `re/classify/{binary}.json`.
    fn stage_parked_classification(workspace: &std::path::Path, binary: &str) {
        let path = workspace
            .join("re")
            .join("classify")
            .join(format!("{binary}.json"));
        std::fs::create_dir_all(path.parent().expect("classify dir")).expect("classify dir");
        std::fs::write(
            &path,
            serde_json::json!({
                "category": "DotNetManaged",
                "reason": "the plugin carries a managed runtime, so nothing here needs restitching"
            })
            .to_string(),
        )
        .expect("file the classification record");
    }

    /// Files an obligation ledger document holding only its envelope: a name
    /// and a filing time, no roster, and no digest for a reader to check.
    fn stage_envelope_only_ledger(workspace: &std::path::Path, binary: &str) {
        std::fs::create_dir_all(workspace.join("re").join("obligations")).expect("obligations dir");
        std::fs::write(
            workspace
                .join("re")
                .join("obligations")
                .join(format!("{binary}.json")),
            format!(r#"{{"binary": "{binary}", "filed_at": 1}}"#),
        )
        .expect("file an envelope-only ledger");
    }

    // ── the unit's obligation entry (issue #424, P26.8) ────────────────

    #[test]
    fn a_filed_obligation_entry_rides_its_unit_with_the_fields_the_unit_detail_names() {
        // The web unit detail renders the unit's obligation entry from the
        // derived model. The build seam fills it: the attempt the entry
        // speaks for, its owner digest, the required case kinds, the
        // disposition, and the receipt citation (issue #424, AC 2).
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        let mut entry = calxgloss_types::ObligationEntry::new(
            "DrawPrimitive",
            1,
            "aaaa1111",
            calxgloss_types::ObligationDisposition::ClaimedVerified,
        );
        entry.receipt_digest = Some("sha256:cafe".to_string());
        stage_obligation_ledger(dir.path(), "game_logic.dll", vec![entry]);

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");

        let entry = unit
            .obligation
            .entry
            .as_ref()
            .expect("the filed entry rides the unit");
        assert_eq!(entry.attempt, 1, "the entry speaks for attempt 1");
        assert_eq!(entry.owner_commit, "aaaa1111", "the owner digest rides");
        assert_eq!(
            entry.required_case_kinds,
            calxgloss_types::CaseKind::ALL,
            "the required case kinds ride from the closed roster"
        );
        assert_eq!(
            entry.disposition,
            calxgloss_types::ObligationDisposition::ClaimedVerified,
            "with no live record standing, the filed disposition speaks"
        );
        assert_eq!(
            entry.receipt_digest.as_deref(),
            Some("sha256:cafe"),
            "the receipt citation rides as filed"
        );
    }

    #[test]
    fn a_unit_whose_binary_has_no_filed_ledger_reads_the_unknown_obligation_never_a_closed_one() {
        // The builder files nothing on its own, so a never-filed ledger
        // leaves the unit's reading unknown (issue #424, AC 4).
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");

        assert!(
            unit.obligation.entry.is_none(),
            "a never-filed ledger leaves the unit unknown, never closed"
        );
    }

    #[test]
    fn a_live_record_decides_the_unit_obligation_at_the_read_like_the_conformance_row() {
        // The two surfaces read one derivation (issue #424, AC 1): where
        // the reviewer's skip set stands for the unit, the unit's
        // obligation reads *skipped* with that record's reason beside it —
        // the same join the per-binary row tallies, not the filed claim.
        let dir = tempfile::tempdir().expect("temp dir");
        let git = one_unit_repo(dir.path());
        stage_obligation_ledger(
            dir.path(),
            "game_logic.dll",
            vec![claimed_verified_entry("DrawPrimitive", 1, "sha256:cafe")],
        );
        stage_skip_set(dir.path(), &["game_logic.dll/DrawPrimitive/v1"]);

        let dashboard = DashboardBuilder::new(&git)
            .build()
            .expect("dashboard builds");
        let unit = find_unit(&dashboard, "game_logic.dll/DrawPrimitive/v1");

        let entry = unit
            .obligation
            .entry
            .as_ref()
            .expect("the filed entry still rides the unit");
        assert_eq!(
            entry.disposition,
            calxgloss_types::ObligationDisposition::Skipped,
            "the live skip record decides the disposition at the read"
        );
        let reason = entry
            .disposition_reason
            .as_deref()
            .expect("the deciding record states its reason");
        assert!(
            reason.contains("skip set"),
            "the reason names the record that decided: {reason}"
        );
    }
}
