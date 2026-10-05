//! String-guided struct inference.
//!
//! [`StringInferenceEngine`] with `infer_structures()` runs the full
//! collect → cluster → infer → score pipeline: literals come from the
//! bridge's `list_strings` (regex filter plus quality filtering),
//! cross-reference clustering groups them into candidate structs, and
//! confidence scoring filters candidates against a configurable threshold.
//!
//! The evidence is co-reference. A function that reads `flowname`, `screen`,
//! and `nextflow` is reading one object's fields, so those literals cluster
//! together and the cluster becomes a candidate whose fields carry the
//! literal names. None of this was declared in the program — a candidate is a
//! hypothesis, and its score says how strongly the evidence supports it.

use crate::error::{Result, TypesDbError};
use crate::types::{Confidence, FieldType, InferredField, InferredStruct, NameOrigin};
use calxgloss_ghidra::{GhidraClient, GhidraError, StringLiteral, Xref};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use tracing::{debug, info};

/// The string reads an inference run performs.
///
/// [`GhidraClient`] implements it directly; tests implement it over canned
/// responses so the filtering, clustering, and scoring logic runs without a
/// server. The futures are `Send` so a run can be driven from an
/// orchestrating task.
pub trait StringSource {
    /// Every defined string in the program, optionally regex-filtered,
    /// collected across pages.
    fn strings(
        &self,
        filter: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Vec<StringLiteral>>> + Send;

    /// References to `address` — the instructions pointing at a literal, each
    /// naming its enclosing function.
    fn xrefs_to(&self, address: u64)
    -> impl std::future::Future<Output = Result<Vec<Xref>>> + Send;
}

impl StringSource for GhidraClient {
    async fn strings(&self, filter: Option<&str>) -> Result<Vec<StringLiteral>> {
        Ok(self.list_strings(filter).await?)
    }

    async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
        Ok(self.xrefs_to(address, None).await?)
    }
}

// ============================================================
// Screening limits
// ============================================================

/// Shortest literal worth clustering. A one-character literal names nothing.
const MIN_LITERAL_LEN: usize = 2;

/// Longest literal worth clustering. A sentence is a message, not a field
/// name.
const MAX_LITERAL_LEN: usize = 64;

/// Shortest qualifier or stem a name may come from.
const MIN_NAME_PART: usize = 3;

/// A function pointing at more literals than this is a hub — a logging or
/// formatting function — and does not evidence one struct.
const MAX_HUB_FANOUT: usize = 24;

/// Default cap on the literals whose cross-references are fetched, so a run
/// stays bounded on a binary holding tens of thousands of them.
const DEFAULT_MAX_LITERALS: usize = 5_000;

/// Default minimum literals for a cluster to be a candidate.
const DEFAULT_MIN_FIELDS: usize = 2;

/// Default confidence a candidate must reach to be reported.
const DEFAULT_MIN_CONFIDENCE: u8 = 40;

/// Ghidra's generated-name prefixes. A stem shared by generated names names
/// nothing.
const AUTO_NAME_PREFIXES: [&str; 4] = ["FUN_", "DAT_", "LABEL_", "thunk_"];

/// Characters that separate a qualifier from the name it qualifies. `_` is
/// left out deliberately: in snake_case it joins words rather than
/// qualifying them.
const NAME_SEPARATORS: [char; 4] = ['.', ':', ' ', '-'];

/// The separators a function name is cut at to find its stem. Underscores
/// qualify C-style names as often as punctuation qualifies literals.
const STEM_SEPARATORS: [char; 5] = ['_', '.', ':', ' ', '-'];

/// The literal-shape patterns the screening and the kind inference use,
/// compiled once per run rather than per literal.
struct Shapes {
    format_spec: Regex,
    integer: Regex,
    float: Regex,
}

impl Shapes {
    fn new() -> Self {
        Self {
            format_spec: Regex::new(r"%[-+ #0]*[0-9]*(\.[0-9]+)?[a-zA-Z]").expect("static pattern"),
            integer: Regex::new(r"^[+-]?[0-9]+$").expect("static pattern"),
            float: Regex::new(r"^[+-]?([0-9]+\.[0-9]*|\.[0-9]+)$").expect("static pattern"),
        }
    }
}

// ============================================================
// Clusters
// ============================================================

/// Literals tied together by shared referencing functions, plus the functions
/// that tied them.
struct Cluster {
    literals: Vec<StringLiteral>,
    functions: Vec<String>,
}

/// Literals grouped by the functions that reference them.
///
/// Literals are unioned through their referencing functions, so a chain of
/// co-references pulls a whole field list into one group. A hub function is
/// skipped — it points at literals of many objects — and a literal no
/// function references cannot join a group at all.
async fn cluster_literals(
    literals: &[StringLiteral],
    referrers: &[BTreeSet<String>],
) -> Vec<Cluster> {
    let mut fanout: HashMap<&str, usize> = HashMap::new();
    for functions in referrers {
        for function in functions {
            *fanout.entry(function.as_str()).or_default() += 1;
        }
    }
    let is_key = |function: &str| fanout.get(function).is_some_and(|n| *n <= MAX_HUB_FANOUT);

    let mut parent: Vec<usize> = (0..literals.len()).collect();
    let mut first: HashMap<&str, usize> = HashMap::new();
    for (index, functions) in referrers.iter().enumerate() {
        for function in functions {
            if !is_key(function) {
                continue;
            }
            if let Some(&other) = first.get(function.as_str()) {
                union(&mut parent, index, other);
            } else {
                first.insert(function.as_str(), index);
            }
        }
    }

    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for index in 0..literals.len() {
        groups
            .entry(find(&mut parent, index))
            .or_default()
            .push(index);
    }

    groups
        .into_values()
        .map(|members| {
            let functions: BTreeSet<&String> = members
                .iter()
                .flat_map(|&i| referrers[i].iter())
                .filter(|function| is_key(function))
                .collect();
            Cluster {
                literals: members.iter().map(|&i| literals[i].clone()).collect(),
                functions: functions.into_iter().cloned().collect(),
            }
        })
        .collect()
}

/// The representative of `index`'s group, flattening the path on the way out.
fn find(parent: &mut [usize], mut index: usize) -> usize {
    let mut root = index;
    while parent[root] != root {
        root = parent[root];
    }
    while parent[index] != root {
        let next = parent[index];
        parent[index] = root;
        index = next;
    }
    root
}

/// Merge two literals' groups.
fn union(parent: &mut [usize], a: usize, b: usize) {
    let (a, b) = (find(parent, a), find(parent, b));
    if a != b {
        parent[a.max(b)] = a.min(b);
    }
}

// ============================================================
// Naming and typing
// ============================================================

/// The struct name a cluster suggests, and where it came from.
fn name_for(cluster: &Cluster) -> (String, NameOrigin) {
    if let Some(prefix) = literal_prefix(&cluster.literals) {
        return (type_name(&prefix), NameOrigin::LiteralPrefix);
    }
    if let Some(stem) = function_stem(&cluster.functions) {
        return (type_name(&stem), NameOrigin::FunctionStem);
    }
    (
        format!("strings_at_{:x}", cluster.literals[0].address),
        NameOrigin::Address,
    )
}

/// The qualifier every literal in the cluster shares (`player.x`, `player.y`
/// → `player`), when they share one.
fn literal_prefix(literals: &[StringLiteral]) -> Option<String> {
    let keys: Vec<&str> = literals.iter().map(|l| key_part(&l.value)).collect();
    let mut shared: &str = keys.first()?;
    for key in keys.iter().skip(1) {
        shared = common_prefix(shared, key);
    }
    let qualifier = shared.trim_end_matches(NAME_SEPARATORS);
    if qualifier.len() < MIN_NAME_PART || !qualifier.starts_with(|c: char| c.is_ascii_alphabetic())
    {
        return None;
    }
    // The shared text has to qualify the names rather than be the start of a
    // shared word: every literal must continue past it with a separator.
    keys.iter()
        .all(|key| {
            key.get(qualifier.len()..).is_some_and(|rest| {
                rest.starts_with(NAME_SEPARATORS)
                    && rest[1..].starts_with(|c: char| c.is_ascii_alphabetic())
            })
        })
        .then(|| qualifier.to_string())
}

/// The stem the cluster's functions share (`Widget_getWidth`,
/// `Widget_getHeight` → `Widget`), when they share a usable one.
fn function_stem(functions: &[String]) -> Option<String> {
    let mut shared: &str = functions.first()?;
    if functions.iter().any(|f| is_auto_name(f)) {
        return None;
    }
    for function in functions.iter().skip(1) {
        shared = common_prefix(shared, function);
    }
    let stem = shared.split(STEM_SEPARATORS).next()?;
    if stem.len() < MIN_NAME_PART || !stem.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return None;
    }
    // A stem that is the whole of a function name is that name, not a stem.
    functions
        .iter()
        .all(|f| f.len() > stem.len())
        .then(|| stem.to_string())
}

/// Whether a name is one Ghidra generated, carrying no information.
fn is_auto_name(name: &str) -> bool {
    AUTO_NAME_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// A name fragment as a type-style identifier (`player` → `Player`).
fn type_name(part: &str) -> String {
    let cleaned = sanitize_identifier(part).unwrap_or_default();
    let mut chars = cleaned.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// The leading text two names share.
fn common_prefix<'a>(a: &'a str, b: &str) -> &'a str {
    let end = a
        .char_indices()
        .zip(b.chars())
        .take_while(|((_, left), right)| *left == *right)
        .map(|((at, ch), _)| at + ch.len_utf8())
        .last()
        .unwrap_or(0);
    &a[..end]
}

/// The naming part of a literal: the text before a `key=value` assignment.
fn key_part(value: &str) -> &str {
    value.split_once('=').map_or(value, |(key, _)| key).trim()
}

/// The text a literal names a field with: its key, with the cluster's
/// qualifier removed.
fn field_key<'a>(literal: &'a StringLiteral, qualifier: Option<&str>) -> &'a str {
    let key = key_part(&literal.value);
    qualifier
        .and_then(|qualifier| {
            key.strip_prefix(qualifier)
                .and_then(|rest| rest.strip_prefix(NAME_SEPARATORS))
        })
        .unwrap_or(key)
}

/// A literal's text as a field name: separators collapse to underscores and
/// anything that cannot appear in an identifier is dropped.
fn sanitize_identifier(raw: &str) -> Option<String> {
    let mut name = String::new();
    for c in raw.trim().chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            name.push(c);
        } else if !name.ends_with('_') {
            name.push('_');
        }
    }
    let name = name
        .trim_matches('_')
        .trim_start_matches(|c: char| c.is_ascii_digit())
        .to_string();
    (!name.is_empty()).then_some(name)
}

/// The kind a literal suggests for the field it names.
///
/// A `key=value` literal types the field from what is assigned to it; a bare
/// identifier only says the field holds text.
fn infer_field_type(value: &str, shapes: &Shapes) -> FieldType {
    let assigned = value
        .split_once('=')
        .map_or(value, |(_, assigned)| assigned)
        .trim();
    if assigned.is_empty() {
        return FieldType::Unknown;
    }
    if shapes.integer.is_match(assigned) {
        return FieldType::Integer;
    }
    if shapes.float.is_match(assigned) {
        return FieldType::Float;
    }
    if matches!(
        assigned.to_ascii_lowercase().as_str(),
        "true" | "false" | "yes" | "no"
    ) {
        return FieldType::Boolean;
    }
    FieldType::String
}

/// Whether a literal is worth clustering.
///
/// The defined-string listing carries sentences, paths, format strings, and
/// numeric blobs alongside the identifier-shaped text that names fields, and
/// a cluster built from that junk describes nothing.
fn is_useful_literal(value: &str, shapes: &Shapes) -> bool {
    let length = value.chars().count();
    if !(MIN_LITERAL_LEN..=MAX_LITERAL_LEN).contains(&length) {
        return false;
    }
    // Control characters and non-ASCII text come from encoded data Ghidra
    // guessed a string boundary inside of, not from a name.
    if !value.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return false;
    }
    // A format string belongs to a call, not to a struct.
    if shapes.format_spec.is_match(value) {
        return false;
    }
    // A backslash marks a Windows path, and a literal with no letters at all
    // is a number or a date. Neither names a field.
    if value.contains('\\') || !value.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    // A field name is one token: a multi-word literal is prose unless it
    // reads as a `key=value` assignment.
    if !value.contains('=') && value.split_whitespace().count() > 1 {
        return false;
    }
    true
}

/// Confidence that one cluster describes a single struct, 0–100.
///
/// More literals is stronger evidence than fewer, several functions agreeing
/// is stronger than one, a name that came out of the data is stronger than a
/// placeholder, and literals that already read as field names are stronger
/// than ones that had to be cleaned up.
fn score(cluster: &Cluster, origin: NameOrigin, clean_fields: usize, fields: usize) -> u8 {
    let breadth = cluster.literals.len().min(5) * 8;
    let agreement = cluster.functions.len().min(4) * 5;
    let naming = match origin {
        NameOrigin::LiteralPrefix => 25,
        NameOrigin::FunctionStem => 15,
        NameOrigin::Address => 0,
    };
    let shape = (20 * clean_fields).checked_div(fields).unwrap_or(0);
    (breadth + agreement + naming + shape).min(100) as u8
}

/// Whether an error means "nothing readable at that literal" rather than "the
/// server could not answer".
///
/// A literal whose cross-references cannot be read simply fails to cluster,
/// degrading one candidate. Anything else — transport, a reported server
/// failure — is a broken run, because every later literal would hit it too.
fn is_reference_miss(error: &TypesDbError) -> bool {
    matches!(
        error,
        TypesDbError::Ghidra(GhidraError::NotFound { .. } | GhidraError::Malformed { .. })
    )
}

// ============================================================
// Engine
// ============================================================

/// String-guided struct inference over the program's literals.
///
/// The engine is generic over [`StringSource`] so tests can drive it with
/// canned responses; [`new`](Self::new) builds one over a live
/// [`GhidraClient`].
#[derive(Debug, Clone)]
pub struct StringInferenceEngine<S = GhidraClient> {
    source: S,
    filter: Option<String>,
    min_fields: usize,
    min_confidence: u8,
    max_literals: usize,
    pointer_size: u64,
}

impl StringInferenceEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client.
    pub fn new(client: &GhidraClient) -> StringInferenceEngine<GhidraClient> {
        Self::with_source(client.clone())
    }
}

impl<S> StringInferenceEngine<S> {
    /// An engine over any source that can read strings and cross-references.
    pub fn with_source(source: S) -> Self {
        Self {
            source,
            filter: None,
            min_fields: DEFAULT_MIN_FIELDS,
            min_confidence: DEFAULT_MIN_CONFIDENCE,
            max_literals: DEFAULT_MAX_LITERALS,
            pointer_size: 8,
        }
    }

    /// Regex the bridge filters its string listing by.
    pub fn with_string_filter(mut self, pattern: impl Into<String>) -> Self {
        self.filter = Some(pattern.into());
        self
    }

    /// Report candidates with at least `count` fields.
    pub fn with_min_fields(mut self, count: usize) -> Self {
        self.min_fields = count.max(1);
        self
    }

    /// Report candidates scoring `threshold` or higher.
    pub fn with_min_confidence(mut self, threshold: u8) -> Self {
        self.min_confidence = threshold;
        self
    }

    /// Fetch cross-references for at most `count` literals.
    pub fn with_max_literals(mut self, count: usize) -> Self {
        self.max_literals = count;
        self
    }

    /// Override the pointer size assumed for text-typed fields (a 32-bit
    /// program uses 4).
    pub fn with_pointer_size(mut self, pointer_size: u64) -> Self {
        self.pointer_size = pointer_size.max(1);
        self
    }

    /// Infer every struct candidate the program's literals support, strongest
    /// evidence first.
    pub async fn infer_structures(&self) -> Result<Vec<InferredStruct>>
    where
        S: StringSource,
    {
        let shapes = Shapes::new();
        let literals = self.collect_literals(&shapes).await?;
        if literals.len() < self.min_fields {
            info!("No literals left to cluster");
            return Ok(Vec::new());
        }
        let clusters = self.cluster(&literals).await?;
        debug!(clusters = clusters.len(), "Clustered string literals");

        let mut candidates: Vec<InferredStruct> = clusters
            .iter()
            .filter(|cluster| cluster.literals.len() >= self.min_fields)
            .map(|cluster| self.infer_candidate(cluster, &shapes))
            .filter(|candidate| candidate.confidence >= self.min_confidence)
            .collect();
        // Names break ties so a run over the same program is deterministic.
        candidates.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.name.cmp(&b.name))
        });
        info!(
            count = candidates.len(),
            threshold = self.min_confidence,
            "Inferred struct candidates"
        );
        Ok(candidates)
    }

    /// The program's literals, screened and deduplicated.
    ///
    /// The same text defined at several addresses is one field name, and the
    /// lowest address is the canonical one. What survives is capped so a run
    /// stays bounded on a binary holding tens of thousands of literals.
    async fn collect_literals(&self, shapes: &Shapes) -> Result<Vec<StringLiteral>>
    where
        S: StringSource,
    {
        let listing = self.source.strings(self.filter.as_deref()).await?;
        let mut by_value: BTreeMap<String, StringLiteral> = BTreeMap::new();
        for literal in listing {
            if !is_useful_literal(&literal.value, shapes) {
                continue;
            }
            if by_value
                .get(&literal.value)
                .is_some_and(|kept| kept.address <= literal.address)
            {
                continue;
            }
            by_value.insert(literal.value.clone(), literal);
        }
        let mut literals: Vec<StringLiteral> = by_value.into_values().collect();
        literals.sort_by_key(|literal| literal.address);
        literals.truncate(self.max_literals);
        debug!(count = literals.len(), "Collected string literals");
        Ok(literals)
    }

    /// One cross-reference read per literal, then the grouping.
    ///
    /// A literal whose references cannot be read is dropped from clustering;
    /// a server failure aborts the run.
    async fn cluster(&self, literals: &[StringLiteral]) -> Result<Vec<Cluster>>
    where
        S: StringSource,
    {
        let mut referrers: Vec<BTreeSet<String>> = Vec::with_capacity(literals.len());
        for literal in literals {
            let xrefs = match self.source.xrefs_to(literal.address).await {
                Ok(xrefs) => xrefs,
                Err(miss) if is_reference_miss(&miss) => {
                    debug!(
                        address = format_args!("{:#x}", literal.address),
                        "Could not read a literal's references"
                    );
                    Vec::new()
                }
                Err(e) => return Err(e),
            };
            referrers.push(xrefs.into_iter().filter_map(|x| x.function).collect());
        }
        Ok(cluster_literals(literals, &referrers).await)
    }

    /// One cluster as a candidate: a name, fields taken from the literals, and
    /// a score for how well the evidence supports reading them as one struct.
    fn infer_candidate(&self, cluster: &Cluster, shapes: &Shapes) -> InferredStruct {
        let (name, origin) = name_for(cluster);
        let qualifier = (origin == NameOrigin::LiteralPrefix)
            .then(|| literal_prefix(&cluster.literals))
            .flatten();

        let mut fields = Vec::new();
        let mut clean = 0usize;
        let mut cursor = 0u64;
        for literal in &cluster.literals {
            let key = field_key(literal, qualifier.as_deref());
            let Some(mut field) = self.infer_field(literal, key, shapes) else {
                continue;
            };
            if key == field.name {
                clean += 1;
            }
            // Offsets accumulate over the sizes that are known, each field
            // starting on a 4-byte boundary; a field whose kind has no size
            // of its own stays unplaced.
            field.offset = field.size.map(|size| {
                let at = cursor.div_ceil(4) * 4;
                cursor = at + size;
                at
            });
            fields.push(field);
        }

        InferredStruct {
            confidence: Confidence::new(score(cluster, origin, clean, fields.len())),
            name,
            name_origin: origin,
            fields,
            referenced_by: cluster.functions.clone(),
        }
    }

    /// One literal as a field: the name it carries and the kind its shape
    /// suggests. A literal with nothing nameable in it is not a field.
    fn infer_field(
        &self,
        literal: &StringLiteral,
        key: &str,
        shapes: &Shapes,
    ) -> Option<InferredField> {
        let field_type = infer_field_type(&literal.value, shapes);
        Some(InferredField {
            name: sanitize_identifier(key)?,
            field_type,
            size: field_type.suggested_size(self.pointer_size),
            offset: None,
            source_value: literal.value.clone(),
            source_address: literal.address,
        })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn literal(value: &str, address: u64) -> StringLiteral {
        StringLiteral {
            address,
            value: value.to_string(),
        }
    }

    /// A reference from `at` inside `function`.
    fn reference(at: u64, function: &str) -> Xref {
        Xref {
            address: at,
            function: Some(function.to_string()),
            kind: Some("DATA".to_string()),
        }
    }

    /// A source over canned listings and cross-references, recording every
    /// listing filter and every address whose references were fetched.
    struct MockSource {
        literals: Vec<StringLiteral>,
        xrefs: HashMap<u64, Vec<Xref>>,
        unreadable: Vec<u64>,
        busy: Vec<u64>,
        listing_failure: bool,
        filters: Mutex<Vec<Option<String>>>,
        reads: Mutex<Vec<u64>>,
    }

    impl MockSource {
        fn new(literals: Vec<StringLiteral>) -> Self {
            Self {
                literals,
                xrefs: HashMap::new(),
                unreadable: Vec::new(),
                busy: Vec::new(),
                listing_failure: false,
                filters: Mutex::new(Vec::new()),
                reads: Mutex::new(Vec::new()),
            }
        }

        /// The functions that point at `address`.
        fn referenced_by(&mut self, address: u64, functions: &[&str]) {
            self.xrefs.insert(
                address,
                functions
                    .iter()
                    .enumerate()
                    .map(|(i, f)| reference(0x1800_0100 + i as u64, f))
                    .collect(),
            );
        }

        fn unreadable(&mut self, address: u64) {
            self.unreadable.push(address);
        }

        fn busy_at(&mut self, address: u64) {
            self.busy.push(address);
        }

        fn filter_log(&self) -> Vec<Option<String>> {
            self.filters.lock().unwrap().clone()
        }

        fn read_log(&self) -> Vec<u64> {
            self.reads.lock().unwrap().clone()
        }
    }

    impl StringSource for MockSource {
        async fn strings(&self, filter: Option<&str>) -> Result<Vec<StringLiteral>> {
            self.filters
                .lock()
                .unwrap()
                .push(filter.map(str::to_string));
            if self.listing_failure {
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                }
                .into());
            }
            Ok(self.literals.clone())
        }

        async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
            self.reads.lock().unwrap().push(address);
            if self.busy.contains(&address) {
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                }
                .into());
            }
            if self.unreadable.contains(&address) {
                return Err(GhidraError::NotFound {
                    kind: "cross-references",
                    query: format!("{address:x}"),
                }
                .into());
            }
            Ok(self.xrefs.get(&address).cloned().unwrap_or_default())
        }
    }

    fn engine_over(source: MockSource) -> StringInferenceEngine<MockSource> {
        StringInferenceEngine {
            source,
            filter: None,
            min_fields: DEFAULT_MIN_FIELDS,
            min_confidence: 0,
            max_literals: DEFAULT_MAX_LITERALS,
            pointer_size: 8,
        }
    }

    /// The startup-flow keys eqmain reads in one function: eight literals, no
    /// shared qualifier, one referencing function.
    fn flow_fixture() -> MockSource {
        let values = [
            "startupflow",
            "flowname",
            "screen",
            "screenname",
            "event",
            "nextflow",
            "action",
            "actiondata",
        ];
        let literals: Vec<StringLiteral> = values
            .iter()
            .enumerate()
            .map(|(i, v)| literal(v, 0x1801_29340 + 8 * i as u64))
            .collect();
        let mut source = MockSource::new(literals);
        for i in 0..values.len() {
            source.referenced_by(0x1801_29340 + 8 * i as u64, &["FUN_18000b620"]);
        }
        source
    }

    #[tokio::test]
    async fn infer_recovers_a_struct_from_qualified_literals() {
        let mut source = MockSource::new(vec![
            literal("player.x", 0x1801_2900),
            literal("player.y", 0x1801_2910),
            literal("player.heading", 0x1801_2920),
        ]);
        for address in [0x1801_2900, 0x1801_2910, 0x1801_2920] {
            source.referenced_by(address, &["FUN_18000b620", "FUN_18000c100"]);
        }

        let candidates = engine_over(source).infer_structures().await.unwrap();
        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.name, "Player");
        assert_eq!(candidate.name_origin, NameOrigin::LiteralPrefix);
        assert!(candidate.is_named());
        // The qualifier names the struct; what is left of each literal names
        // the field.
        let names: Vec<&str> = candidate.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["x", "y", "heading"]);
        assert_eq!(
            candidate.referenced_by,
            vec!["FUN_18000b620".to_string(), "FUN_18000c100".to_string()]
        );
        // 3 literals + 2 functions + a name from the data + clean names.
        assert_eq!(candidate.confidence, 24 + 10 + 25 + 20);
    }

    #[tokio::test]
    async fn literals_are_clustered_by_the_functions_that_reference_them() {
        let mut source = MockSource::new(vec![
            literal("width", 0x100),
            literal("height", 0x108),
            literal("unrelated", 0x110),
            literal("volume", 0x118),
        ]);
        source.referenced_by(0x100, &["Widget_getSize"]);
        source.referenced_by(0x108, &["Widget_getSize"]);
        source.referenced_by(0x110, &["Sound_getLevel"]);
        source.referenced_by(0x118, &["Sound_getLevel"]);

        let candidates = engine_over(source).infer_structures().await.unwrap();
        assert_eq!(candidates.len(), 2);
        let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["Sound", "Widget"]);
        let widget = candidates.iter().find(|c| c.name == "Widget").unwrap();
        assert_eq!(widget.name_origin, NameOrigin::FunctionStem);
        assert_eq!(widget.fields.len(), 2);
    }

    #[tokio::test]
    async fn a_chain_of_co_references_pulls_one_field_list_together() {
        // `middle` is the only literal both functions point at, so the two
        // pairs it joins become one cluster.
        let mut source = MockSource::new(vec![
            literal("width", 0x100),
            literal("count", 0x108),
            literal("height", 0x110),
        ]);
        source.referenced_by(0x100, &["FUN_a"]);
        source.referenced_by(0x108, &["FUN_a", "FUN_b"]);
        source.referenced_by(0x110, &["FUN_b"]);

        let candidates = engine_over(source).infer_structures().await.unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].fields.len(), 3);
        assert_eq!(candidates[0].referenced_by.len(), 2);
    }

    #[tokio::test]
    async fn a_literal_no_function_references_and_a_lone_literal_are_not_candidates() {
        let mut source = MockSource::new(vec![
            literal("orphan", 0x100),
            literal("lonely", 0x108),
            literal("partner", 0x110),
        ]);
        source.referenced_by(0x108, &["FUN_a"]);
        source.referenced_by(0x110, &["FUN_a"]);

        let engine = engine_over(source).with_min_fields(3);
        assert!(engine.infer_structures().await.unwrap().is_empty());

        let engine = engine_over(MockSource::new(vec![literal("only", 0x100)]));
        assert!(engine.infer_structures().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn junk_literals_are_screened_out_before_clustering() {
        let mut source = MockSource::new(vec![
            literal("    %0s", 0x100),
            literal("Error loading skin: loading default skin instead.", 0x108),
            literal("1024", 0x110),
            literal("UIFiles\\default\\", 0x118),
            literal("a", 0x120),
            literal("x\0y", 0x128),
            // The same name defined twice: one field, the lower address.
            literal("JournalFilename", 0x138),
            literal("JournalFilename", 0x130),
            literal("LoggingOn", 0x140),
        ]);
        for address in [0x130, 0x138, 0x140] {
            source.referenced_by(address, &["FUN_180006da0"]);
        }

        let engine = engine_over(source);
        let candidates = engine.infer_structures().await.unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].fields.len(), 2);
        // Only the surviving literals had their references fetched.
        assert_eq!(engine.source.read_log(), vec![0x130, 0x140]);
    }

    #[tokio::test]
    async fn a_hub_function_does_not_merge_unrelated_literals() {
        // A logging function pointing at 25 literals is not evidence that
        // those literals are one object.
        let mut literals = Vec::new();
        for i in 0..25u64 {
            literals.push(literal(&format!("message_{i}"), 0x200 + 8 * i));
        }
        literals.push(literal("width", 0x400));
        literals.push(literal("height", 0x408));
        let mut source = MockSource::new(literals);
        for i in 0..25u64 {
            source.referenced_by(0x200 + 8 * i, &["FUN_logger"]);
        }
        source.referenced_by(0x400, &["Widget_getSize"]);
        source.referenced_by(0x408, &["Widget_getSize"]);

        let candidates = engine_over(source).infer_structures().await.unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "Widget");
        assert_eq!(candidates[0].fields.len(), 2);
    }

    #[tokio::test]
    async fn field_kinds_come_from_the_shape_of_the_literal() {
        let mut source = MockSource::new(vec![
            literal("cfg.width=100", 0x100),
            literal("cfg.ratio=0.5", 0x108),
            literal("cfg.enabled=true", 0x110),
            literal("cfg.title", 0x118),
        ]);
        for address in [0x100, 0x108, 0x110, 0x118] {
            source.referenced_by(address, &["FUN_18000b620"]);
        }

        let candidates = engine_over(source).infer_structures().await.unwrap();
        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.name, "Cfg");
        let kinds: Vec<FieldType> = candidate.fields.iter().map(|f| f.field_type).collect();
        assert_eq!(
            kinds,
            vec![
                FieldType::Integer,
                FieldType::Float,
                FieldType::Boolean,
                FieldType::String,
            ]
        );
        // 4 + 4 + 1 + 8 bytes, laid out in literal order.
        let offsets: Vec<Option<u64>> = candidate.fields.iter().map(|f| f.offset).collect();
        assert_eq!(offsets, vec![Some(0), Some(4), Some(8), Some(12)]);
        assert_eq!(candidate.size(), Some(17));
    }

    /// Two literals, one function, nothing to name them after: weak.
    fn weak_pair() -> MockSource {
        let mut source = MockSource::new(vec![literal("alpha", 0x100), literal("beta", 0x108)]);
        source.referenced_by(0x100, &["FUN_a"]);
        source.referenced_by(0x108, &["FUN_a"]);
        source
    }

    #[tokio::test]
    async fn the_confidence_threshold_filters_candidates() {
        let candidates = engine_over(weak_pair())
            .with_min_confidence(DEFAULT_MIN_CONFIDENCE)
            .infer_structures()
            .await
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence, 16 + 5 + 20);
        assert_eq!(candidates[0].name, "strings_at_100");
        assert!(!candidates[0].is_named());

        let candidates = engine_over(weak_pair())
            .with_min_confidence(50)
            .infer_structures()
            .await
            .unwrap();
        assert!(candidates.is_empty());
    }

    #[tokio::test]
    async fn candidates_are_reported_strongest_first() {
        let mut source = MockSource::new(vec![
            literal("weak_one", 0x100),
            literal("weak_two", 0x108),
            literal("player.x", 0x200),
            literal("player.y", 0x208),
            literal("player.z", 0x210),
            literal("player.w", 0x218),
        ]);
        source.referenced_by(0x100, &["FUN_a"]);
        source.referenced_by(0x108, &["FUN_a"]);
        for address in [0x200, 0x208, 0x210, 0x218] {
            source.referenced_by(address, &["FUN_b", "FUN_c", "FUN_d"]);
        }

        let candidates = engine_over(source)
            .with_min_confidence(DEFAULT_MIN_CONFIDENCE)
            .infer_structures()
            .await
            .unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].name, "Player");
        assert!(candidates[0].confidence > candidates[1].confidence);
    }

    #[tokio::test]
    async fn an_unreadable_reference_list_degrades_one_literal() {
        let mut source = flow_fixture();
        source.unreadable(0x1801_29348);

        let candidates = engine_over(source).infer_structures().await.unwrap();
        assert_eq!(candidates.len(), 1);
        // The literal whose references could not be read cannot cluster.
        assert_eq!(candidates[0].fields.len(), 7);
    }

    #[tokio::test]
    async fn a_server_failure_aborts_the_run() {
        let mut source = flow_fixture();
        source.busy_at(0x1801_29348);

        let result = engine_over(source).infer_structures().await;
        assert!(matches!(
            result,
            Err(TypesDbError::Ghidra(GhidraError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn a_failed_listing_aborts_the_run() {
        let mut source = flow_fixture();
        source.listing_failure = true;

        let result = engine_over(source).infer_structures().await;
        assert!(matches!(
            result,
            Err(TypesDbError::Ghidra(GhidraError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn the_string_filter_reaches_the_listing() {
        let engine = engine_over(flow_fixture()).with_string_filter("flow");
        let candidates = engine.infer_structures().await.unwrap();
        assert_eq!(engine.source.filter_log(), vec![Some("flow".to_string())]);
        assert!(!candidates.is_empty());
    }

    #[tokio::test]
    async fn the_literal_cap_bounds_the_reference_reads() {
        let engine = engine_over(flow_fixture()).with_max_literals(3);
        let candidates = engine.infer_structures().await.unwrap();
        assert_eq!(engine.source.read_log().len(), 3);
        assert_eq!(candidates[0].fields.len(), 3);
    }

    #[tokio::test]
    async fn the_flow_keys_eqmain_reads_in_one_function_form_one_candidate() {
        let candidates = engine_over(flow_fixture())
            .with_min_confidence(DEFAULT_MIN_CONFIDENCE)
            .infer_structures()
            .await
            .unwrap();
        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        // Ghidra named neither the struct nor its functions, so the candidate
        // is named after the literals it came from.
        assert_eq!(candidate.name, "strings_at_180129340");
        assert_eq!(candidate.fields.len(), 8);
        assert_eq!(candidate.confidence, 40 + 5 + 20);
        assert!(
            candidate
                .fields
                .iter()
                .all(|f| f.field_type == FieldType::String)
        );
    }

    #[test]
    fn literals_are_screened_for_quality() {
        let shapes = Shapes::new();
        for good in [
            "flowname",
            "Journal.txt",
            "width=100",
            "eqlsPlayerData.ini",
            "WDT_EQLS_Def_Bordered",
        ] {
            assert!(is_useful_literal(good, &shapes), "{good} should survive");
        }
        for junk in [
            "",
            "x",
            "%d: %s",
            "Error in your GUI XML files.  Check UIErrors.txt.",
            "12345",
            "C:\\p4\\EverQuest\\live\\eqmain.cpp",
            "0.000000",
            "chat logging turned OFF.",
            "Ünïcödé",
        ] {
            assert!(
                !is_useful_literal(junk, &shapes),
                "{junk} should be screened"
            );
        }
    }

    #[test]
    fn field_names_are_made_into_identifiers() {
        assert_eq!(sanitize_identifier("width").as_deref(), Some("width"));
        assert_eq!(
            sanitize_identifier("eqlsPlayerData.ini").as_deref(),
            Some("eqlsPlayerData_ini")
        );
        assert_eq!(sanitize_identifier("  3d view ").as_deref(), Some("d_view"));
        assert_eq!(sanitize_identifier("1234").as_deref(), None);
        assert_eq!(sanitize_identifier("...").as_deref(), None);
    }

    #[test]
    fn qualifiers_and_stems_name_a_struct() {
        let qualified = vec![
            literal("player.x", 0x100),
            literal("player.y", 0x108),
            literal("player.heading", 0x110),
        ];
        assert_eq!(literal_prefix(&qualified).as_deref(), Some("player"));

        // A shared word start is not a qualifier.
        let shared_word = vec![literal("screen", 0x100), literal("screenname", 0x108)];
        assert_eq!(literal_prefix(&shared_word), None);
        // Snake_case joins words rather than qualifying them.
        let snake = vec![literal("get_width", 0x100), literal("get_height", 0x108)];
        assert_eq!(literal_prefix(&snake), None);

        let methods = vec![
            "Widget_getWidth".to_string(),
            "Widget_getHeight".to_string(),
        ];
        assert_eq!(function_stem(&methods).as_deref(), Some("Widget"));
        // Ghidra's generated names carry nothing to name a struct after.
        let generated = vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()];
        assert_eq!(function_stem(&generated), None);
        // A stem that is the whole of one name is that name.
        let whole = vec!["Widget".to_string(), "WidgetFactory".to_string()];
        assert_eq!(function_stem(&whole), None);
    }

    #[test]
    fn literal_shape_decides_the_field_kind() {
        let shapes = Shapes::new();
        assert_eq!(infer_field_type("width=100", &shapes), FieldType::Integer);
        assert_eq!(infer_field_type("ratio=-0.5", &shapes), FieldType::Float);
        assert_eq!(
            infer_field_type("enabled=FALSE", &shapes),
            FieldType::Boolean
        );
        assert_eq!(
            infer_field_type("title=Sir Bezzek", &shapes),
            FieldType::String
        );
        assert_eq!(infer_field_type("flowname", &shapes), FieldType::String);
        assert_eq!(infer_field_type("flowname=", &shapes), FieldType::Unknown);
    }

    #[test]
    fn scoring_rewards_breadth_agreement_and_a_name_from_the_data() {
        let cluster = |count: usize, functions: usize| Cluster {
            literals: (0..count).map(|i| literal("field", i as u64)).collect(),
            functions: (0..functions)
                .map(|i| format!("FUN_{i}"))
                .collect::<Vec<_>>(),
        };
        assert_eq!(score(&cluster(1, 1), NameOrigin::Address, 1, 1), 8 + 5 + 20);
        // The parts sum past the ceiling, so the score is capped at 100.
        assert_eq!(score(&cluster(5, 4), NameOrigin::LiteralPrefix, 5, 5), 100);
        // More literals and more functions than that add nothing: the score
        // saturates rather than crowding out the other signals.
        assert_eq!(score(&cluster(9, 9), NameOrigin::LiteralPrefix, 9, 9), 100);
        // Names that had to be cleaned up count for nothing.
        assert_eq!(score(&cluster(2, 1), NameOrigin::Address, 0, 2), 16 + 5);
    }
}
