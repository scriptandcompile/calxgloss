//! The classification seam: the reader's reads of the classification
//! records under `re/classify/` and the persisted override layer, and the
//! one place that combines a record with its override into the decision
//! actually in force (issue #461).

use super::*;

impl ReviewSurfaceReader {
    /// The classification panel's reading for one binary (issue #461):
    /// the recorded classification through the shared classification
    /// read, plus this binary's entry in the persisted override layer.
    pub fn classification_pair(&self, binary: &str) -> Result<ClassificationPair, ServerError> {
        let recorded =
            match read_classification_record(&self.repo_path, &BinaryIdentity::new(binary)) {
                Ok(record) => record
                    .category
                    .as_ref()
                    .map(|category| RecordedClassification {
                        category: category_name(category),
                        strategy: strategy_label(record.strategy.as_ref()),
                        crate_replacement: record.crate_replacement,
                        known_runtime: record.known_runtime,
                        reason: record.reason,
                    }),
                Err(PersistError::NotFound { .. }) => None,
                // The panel's corrupt policy, stated at this site (issue
                // #461): an unreadable record never reads as "never
                // classified". The binary stays listed, the category
                // reads honestly unknown, and the reason names the fault
                // — the same words the terminal view carries (issue #458).
                Err(fault) => Some(RecordedClassification {
                    category: "unknown".to_string(),
                    strategy: String::new(),
                    crate_replacement: None,
                    known_runtime: false,
                    reason: Some(format!("record unreadable: {fault}")),
                }),
            };
        let overrides = self.classification_overrides()?;
        Ok(ClassificationPair {
            recorded,
            r#override: overrides.overrides.get(binary).cloned(),
        })
    }

    /// The persisted override layer, read through the shared module
    /// (issue #459): a never-filed document is the clean no-override
    /// state; a corrupt one is a server fault naming the document, never
    /// a silent "the reviewer never overrode anything".
    pub fn classification_overrides(&self) -> Result<ClassificationOverrides, ServerError> {
        match read_classification_overrides(&self.repo_path) {
            Ok(overrides) => Ok(overrides),
            Err(PersistError::NotFound { .. }) => Ok(ClassificationOverrides::default()),
            Err(fault) => Err(ServerError::internal(&format!(
                "classification override document unreadable: {fault}"
            ))),
        }
    }

    /// Every classification document under the record tree, read through
    /// the shared classification module. A corrupt document keeps its
    /// named fault instead of vanishing, so each surface states its
    /// keep-or-skip policy at the site that renders the row (issue #461).
    pub fn classification_documents(&self) -> Vec<ClassificationDocument> {
        let mut documents = Vec::new();
        let Ok(entries) = std::fs::read_dir(classification_record_dir(&self.repo_path)) else {
            return documents;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let listed_as = path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default();
            let reading =
                read_classification_record(&self.repo_path, &BinaryIdentity::new(&listed_as)).map(
                    |record| ClassificationReading {
                        binary: (!record.binary.is_empty()).then_some(record.binary),
                        category: record.category,
                        strategy: strategy_label(record.strategy.as_ref()),
                        crate_replacement: record.crate_replacement,
                        exports_count: record.exports_count.unwrap_or(0),
                        imports_count: record.imports_count.unwrap_or(0),
                        known_runtime: record.known_runtime,
                        reason: record.reason,
                    },
                );
            documents.push(ClassificationDocument { listed_as, reading });
        }
        documents
    }

    /// The binaries pages' reading (issue #461): the records the row set
    /// keeps — a corrupt record, or one naming no binary or no category,
    /// is no record at all — composed with the persisted override layer
    /// keyed by binary identity verbatim.
    pub fn binary_classifications(&self) -> Result<BinaryClassifications, ServerError> {
        let mut records = HashMap::new();
        for document in self.classification_documents() {
            if let Ok(reading) = document.reading
                && let Some(name) = reading.binary.as_deref()
                && reading.category.is_some()
            {
                records.insert(BinaryIdentity::new(name), reading);
            }
        }
        Ok(BinaryClassifications {
            records,
            overrides: self.classification_overrides()?,
        })
    }
}

/// What the classification panel answers for one binary: the recorded
/// classification as filed, and the reviewer's override in force. The
/// reader composes both through the shared record reads (issue #461).
#[derive(Debug)]
pub struct ClassificationPair {
    /// The record's account of the binary. Honest renderings: `None`
    /// when no record was ever filed; a filed-but-unreadable record
    /// still lists the binary, with its category `unknown` and its
    /// reason naming the fault that stopped the read.
    pub recorded: Option<RecordedClassification>,
    /// The override keyed to this binary verbatim, `None` when the
    /// override document names none.
    pub r#override: Option<BinaryClassificationOverride>,
}

/// One classification document under the record tree, named by the file
/// that files it and read through the shared module. The `Err` arm keeps
/// the named fault that stops the document declaring anything.
#[derive(Debug)]
pub struct ClassificationDocument {
    /// The record tree's file stem — the sanitized identity the
    /// `classify` command filed the record under.
    pub listed_as: String,
    pub reading: Result<ClassificationReading, PersistError>,
}

/// Everything one readable classification record declares. The fields
/// ride whole so no surface re-reads the raw document for its reasoning
/// or its counts (issue #461).
#[derive(Debug, Clone)]
pub struct ClassificationReading {
    /// The binary the record names in its own body, when it names one.
    pub binary: Option<String>,
    pub category: Option<DllCategory>,
    pub strategy: String,
    pub crate_replacement: Option<String>,
    pub exports_count: usize,
    pub imports_count: usize,
    pub known_runtime: bool,
    pub reason: Option<String>,
}

/// The composed classification surface the binaries pages render from:
/// the kept records keyed by the identity each names, the override layer
/// keyed verbatim, and one place that combines a record with its
/// override into the decision in force.
#[derive(Debug)]
pub struct BinaryClassifications {
    records: HashMap<BinaryIdentity, ClassificationReading>,
    overrides: ClassificationOverrides,
}

impl BinaryClassifications {
    /// How many readable records the row set keeps.
    pub fn count(&self) -> usize {
        self.records.len()
    }

    /// Every kept record — the binaries list renders one row per record.
    pub fn values(&self) -> impl Iterator<Item = &ClassificationReading> {
        self.records.values()
    }

    /// Resolve the requested spelling to one kept record through the
    /// case-insensitive binary rule every other server comparison makes;
    /// no readable record under any spelling is an honest 404, never an
    /// empty shell. Deterministic when several spellings of one name
    /// each hold a record: the alphabetically first verbatim identity
    /// wins.
    pub fn find(&self, name: &str) -> Result<&ClassificationReading, ServerError> {
        self.records
            .values()
            .filter(|record| binary_matches(record.binary.as_deref().unwrap_or(""), name))
            .min_by_key(|record| record.binary.as_deref().unwrap_or(""))
            .ok_or_else(|| {
                ServerError::not_found(&format!(
                    "no readable classification record for binary: {name}"
                ))
            })
    }

    /// The override keyed to a kept record's verbatim identity — the
    /// same exact-match rule the override endpoints and the analyzer hold.
    pub fn override_for(
        &self,
        record: &ClassificationReading,
    ) -> Option<&BinaryClassificationOverride> {
        self.overrides.overrides.get(record.binary.as_deref()?)
    }

    /// The classification decision actually in force for one kept record:
    /// the recorded classification with the persisted override layer
    /// applied on top. Computed in one place so the summary rows and the
    /// detail panel can never disagree about what the analyzer would act
    /// on.
    pub fn in_force(&self, record: &ClassificationReading) -> InForceDecision {
        in_force_decision(record, self.override_for(record))
    }
}

/// The classification decision actually in force for one record.
pub struct InForceDecision {
    pub category: String,
    pub strategy: String,
    pub crate_replacement: Option<String>,
    pub reason: Option<String>,
    pub overridden: bool,
}

/// Combine one record with its override (exact-key match — the same rule
/// the override endpoints and the analyzer hold). The result matches what
/// the analyzer would act on: under an override it uses the override's
/// synthesized reason, and it names a crate only in crate-replacement
/// mode. There the recorded crate stands in for the analyzer's table
/// fallback (the web crate does not link the classification table).
pub(super) fn in_force_decision(
    record: &ClassificationReading,
    r#override: Option<&BinaryClassificationOverride>,
) -> InForceDecision {
    let recorded_category = record
        .category
        .as_ref()
        .map(category_name)
        .unwrap_or_else(|| "unknown".to_string());
    match r#override {
        Some(o) => InForceDecision {
            category: category_name(&o.category),
            strategy: o.strategy_label().to_string(),
            crate_replacement: if o.is_crate_replacement() {
                o.crate_replacement
                    .clone()
                    .or_else(|| record.crate_replacement.clone())
            } else {
                None
            },
            reason: Some(o.override_reason()),
            overridden: true,
        },
        None => InForceDecision {
            category: recorded_category,
            strategy: record.strategy.clone(),
            crate_replacement: record.crate_replacement.clone(),
            reason: record.reason.clone(),
            overridden: false,
        },
    }
}

/// The category's wire name — the serde variant name the record tree and
/// every review surface spell categories with.
pub(super) fn category_name(category: &DllCategory) -> String {
    serde_json::to_value(category)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

/// The strategy label as the pipeline rows read it: a unit variant is a
/// bare string ("PalMapping"), a data-carrying variant a tagged object
/// ({"CrateReplacement": {…}}) whose tag is the label.
pub(super) fn strategy_label(strategy: Option<&serde_json::Value>) -> String {
    match strategy {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Object(obj)) => obj.keys().next().cloned().unwrap_or_default(),
        _ => String::new(),
    }
}
