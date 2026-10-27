//! Plugin architecture detection.
//!
//! This module provides [`PluginDetector`]. The detector holds the
//! dynamic-loading names a scan checks decompiled bodies against: the
//! module-load spellings (`LoadLibrary`, `LoadLibraryEx`, `dlopen`),
//! the entry-point-resolve spellings (`GetProcAddress`, `dlsym`), and
//! the standard plugin entry-point names (`Plugin_Init`,
//! `GetPluginInfo`, `GetExportTable`, `RegisterPlugin`, and the
//! related spellings). It reads each body's dynamic-loading shape.
//!
//! A plugin architecture is the dynamic half of callback dispatch.
//! The other detectors read a table or registration inside one
//! binary; this detector reads a boundary that crosses binaries: a
//! module loaded at run time, its entry points resolved by name, and
//! a host API table (a struct of function pointers) handed into an
//! entry point so the plugin can call back:
//!
//! ```c
//! hMod = LoadLibrary("plugin.dll");
//! init = (code *)GetProcAddress(hMod, "Plugin_Init");
//! Plugin_Init(&host_api);
//! ```
//!
//! [`PluginDetector::detect`] runs the reading. A full
//! load-and-resolve pair in one body is one finding at
//! [`PLUGIN_CONFIDENCE`]. A lone resolve call or a lone entry-point
//! name without its partner is a fragment at
//! [`PLUGIN_FRAGMENT_CONFIDENCE`]. A host API table passed into an
//! entry point deepens the same finding instead of making a second
//! one. A lone load call — a DLL pulled in for its exports, with no
//! entry point resolved — says nothing about a plugin boundary and is
//! not recorded.

use crate::callback_reg::{direct_calls, is_decompiler_minted, strip_to_identifier};
use crate::types::PluginArchitecture;
use calxgloss_decomp::DecompiledFunction;

use calxgloss_types::{CallSite, line_at};

// ============================================================
// Detector
// ============================================================

/// Plugin architecture detection over decompiled functions.
///
/// The detector owns three name sets a scan checks bodies against:
/// the module-load names, the entry-point-resolve names, and the
/// plugin entry-point names. All are plain callees, matched whole.
/// The sets are configurable: supply them all at once through
/// [`with_names`](Self::with_names), or add names one at a time with
/// [`add_load`](Self::add_load), [`add_resolve`](Self::add_resolve)
/// and [`add_entry_point`](Self::add_entry_point).
/// [`loads`](Self::loads), [`resolves`](Self::resolves) and
/// [`entry_points`](Self::entry_points) report them in configuration
/// order, so two detectors built the same way scan identically and
/// results diff cleanly. The standard sets ([`default_load_names`],
/// [`default_resolve_names`], [`default_entry_point_names`]) hold the
/// Win32 and POSIX loader spellings and the entry-point conventions
/// most common in binaries. A program that loads or exports under
/// different names configures those through
/// [`with_names`](Self::with_names). The detector holds no scan
/// source of its own and never writes back to the program. One
/// detector serves an entire scan and can be shared by reference
/// across concurrent per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PluginDetector {
    loads: Vec<String>,
    resolves: Vec<String>,
    entry_points: Vec<String>,
}

impl PluginDetector {
    /// A detector with no names configured. It finds nothing in any
    /// body it is handed until the standard sets arrive through
    /// [`with_default_names`](Self::with_default_names) or names are
    /// added one at a time through [`add_load`](Self::add_load) and
    /// its siblings.
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard name sets —
    /// [`default_load_names`], [`default_resolve_names`] and
    /// [`default_entry_point_names`] — each in its configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(
            default_load_names(),
            default_resolve_names(),
            default_entry_point_names(),
        )
    }

    /// A detector that scans against exactly `loads`, `resolves` and
    /// `entry_points`, each set kept in the order it is given.
    pub fn with_names(
        loads: impl IntoIterator<Item = impl Into<String>>,
        resolves: impl IntoIterator<Item = impl Into<String>>,
        entry_points: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            loads: loads.into_iter().map(Into::into).collect(),
            resolves: resolves.into_iter().map(Into::into).collect(),
            entry_points: entry_points.into_iter().map(Into::into).collect(),
        }
    }

    /// Add one module-load name to the set this detector scans against.
    pub fn add_load(&mut self, name: impl Into<String>) {
        self.loads.push(name.into());
    }

    /// Add one entry-point-resolve name to the set this detector scans
    /// against.
    pub fn add_resolve(&mut self, name: impl Into<String>) {
        self.resolves.push(name.into());
    }

    /// Add one plugin entry-point name to the set this detector scans
    /// against.
    pub fn add_entry_point(&mut self, name: impl Into<String>) {
        self.entry_points.push(name.into());
    }

    /// The module-load names this detector scans against, in
    /// configuration order.
    pub fn loads(&self) -> &[String] {
        &self.loads
    }

    /// The entry-point-resolve names this detector scans against, in
    /// configuration order.
    pub fn resolves(&self) -> &[String] {
        &self.resolves
    }

    /// The plugin entry-point names this detector scans against, in
    /// configuration order.
    pub fn entry_points(&self) -> &[String] {
        &self.entry_points
    }

    /// The plugin-architecture reading for one function's body.
    ///
    /// The reading walks the body's direct calls in source order,
    /// outside string literals, matching whole names only. It reports
    /// at most one [`PluginArchitecture`] for the body, naming the
    /// first configured load call, the first configured resolve call,
    /// and the first configured entry-point call it sees. A
    /// load-and-resolve pair is the full shape: kept at
    /// [`PLUGIN_CONFIDENCE`] with the load call's line as evidence. A
    /// lone resolve call or a lone entry-point name is a fragment,
    /// kept at [`PLUGIN_FRAGMENT_CONFIDENCE`] with the lone call's
    /// line. The first entry-point argument that names a plain
    /// identifier the decompiler did not mint is read as the host API
    /// table; it deepens the same finding and never makes a second
    /// one. A body with only a load call, or with none of the
    /// configured names, reports nothing, so two scans of one body
    /// diff cleanly.
    pub fn detect(&self, func: &DecompiledFunction) -> Vec<PluginArchitecture> {
        let calls = direct_calls(&func.body);
        let mut load: Option<&CallSite> = None;
        let mut resolve: Option<&CallSite> = None;
        let mut entry: Option<&CallSite> = None;
        for call in &calls {
            if self.loads.iter().any(|name| name == call.callee) {
                load.get_or_insert(call);
            } else if self.resolves.iter().any(|name| name == call.callee) {
                resolve.get_or_insert(call);
            } else if self.entry_points.iter().any(|name| name == call.callee) {
                entry.get_or_insert(call);
            }
        }

        let pair = load.is_some() && resolve.is_some();
        if !pair && resolve.is_none() && entry.is_none() {
            // A lone load call pulls a DLL in for its exports; with no
            // resolve and no entry-point name there is no plugin
            // boundary to claim.
            return Vec::new();
        }

        // The line the claim rests on: the load call for the full
        // pair, the earlier lone call for a fragment.
        let lone = match (resolve, entry) {
            (Some(resolve), Some(entry)) => Some(if resolve.offset <= entry.offset {
                resolve
            } else {
                entry
            }),
            (Some(resolve), None) => Some(resolve),
            (None, Some(entry)) => Some(entry),
            (None, None) => None,
        };
        let Some(evidence_call) = (if pair { load.or(lone) } else { lone }) else {
            return Vec::new();
        };

        let host_table = entry.and_then(|call| host_table_arg(&call.args));
        vec![PluginArchitecture {
            function: func.name.clone(),
            load: load.map(|call| call.callee.to_string()),
            resolve: resolve.map(|call| call.callee.to_string()),
            entry_point: entry.map(|call| call.callee.to_string()),
            host_table,
            suggestion: PLUGIN_SUGGESTION.to_string(),
            confidence: if pair {
                PLUGIN_CONFIDENCE
            } else {
                PLUGIN_FRAGMENT_CONFIDENCE
            }
            .into(),
            evidence: line_at(&func.body, evidence_call.offset),
        }]
    }
}

// ============================================================
// The reading
// ============================================================

/// Confidence of a full load-and-resolve shape: the load call and the
/// resolve call beside it are explicit body evidence of a module being
/// loaded and its entry points resolved by name — a plugin boundary —
/// but the entry-point contract itself is not read from the body.
const PLUGIN_CONFIDENCE: u8 = 70;

/// Confidence of a fragment: a lone resolve call or a lone entry-point
/// name shows only half the shape. The other half — the load, or the
/// host side that resolved and called the entry point — is not in
/// this body, so the claim scores one band below the full pair.
const PLUGIN_FRAGMENT_CONFIDENCE: u8 = 60;

/// The Rust pattern a plugin architecture suggests: a trait-object
/// plugin boundary — a boxed `Plugin` trait object handed out by a
/// loader crate — so the host↔plugin contract survives translation as
/// a trait instead of opaque loader calls.
const PLUGIN_SUGGESTION: &str = "Box<dyn Plugin> (loader crate)";

/// The host API table named by an entry-point call's arguments: the
/// first top-level argument that names a plain identifier once its
/// cast and leading `&` are stripped. Decompiler-minted names
/// (`local_10`, `param_2`, `uVar3`) name storage the decompiler
/// invented, not a table the program named. `NULL` hands nothing
/// over. Those arguments are skipped; a literal or an unnamed
/// expression names no table either.
fn host_table_arg(args: &[&str]) -> Option<String> {
    args.iter()
        .copied()
        .filter_map(strip_to_identifier)
        .find(|name| !is_decompiler_minted(name) && name != "NULL")
}

// ============================================================
// The standard name sets
// ============================================================

/// The standard module-load names: the Win32 spellings (`LoadLibrary`,
/// `LoadLibraryEx`) and the POSIX one (`dlopen`) a scan recognizes as
/// pulling a module in at run time. These are conventions, not laws:
/// a program that loads modules under a different name configures its
/// own names through [`PluginDetector::with_names`].
pub fn default_load_names() -> Vec<String> {
    ["LoadLibrary", "LoadLibraryEx", "dlopen"]
        .into_iter()
        .map(String::from)
        .collect()
}

/// The standard entry-point-resolve names: the Win32 spelling
/// (`GetProcAddress`) and the POSIX one (`dlsym`) a scan recognizes as
/// resolving a named entry point out of a loaded module.
pub fn default_resolve_names() -> Vec<String> {
    ["GetProcAddress", "dlsym"]
        .into_iter()
        .map(String::from)
        .collect()
}

/// The standard plugin entry-point names: the spellings a plugin
/// binary exports and a host calls at the boundary — `Plugin_Init` and
/// `Plugin_Unload`, the info and API getters (`GetPluginInfo`,
/// `GetPluginAPI`, `GetExportTable`), and the registration spellings
/// (`RegisterPlugin`, `InitializePlugin`). These are conventions, not
/// laws: a program that exports under different names configures them
/// through [`PluginDetector::with_names`].
pub fn default_entry_point_names() -> Vec<String> {
    [
        "Plugin_Init",
        "Plugin_Unload",
        "GetPluginInfo",
        "GetPluginAPI",
        "GetExportTable",
        "RegisterPlugin",
        "InitializePlugin",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn function(body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_1800412a0".into(),
            signature: "undefined FUN_1800412a0(void)".into(),
            body: format!("\nundefined FUN_1800412a0(void)\n\n{{\n{body}\n}}\n"),
        }
    }

    fn detect(body: &str) -> Vec<PluginArchitecture> {
        PluginDetector::with_default_names().detect(&function(body))
    }

    fn one(body: &str) -> PluginArchitecture {
        let findings = detect(body);
        assert_eq!(findings.len(), 1, "exactly one plugin finding");
        findings.into_iter().next().unwrap()
    }

    #[test]
    fn a_new_detector_starts_with_no_names() {
        // Construction is free: empty, equal however it is made, and
        // clones interchangeable.
        let detector = PluginDetector::new();
        assert!(detector.loads().is_empty());
        assert!(detector.resolves().is_empty());
        assert!(detector.entry_points().is_empty());
        assert_eq!(detector, PluginDetector::default());
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_keeps_the_names_it_is_configured_with() {
        let detector =
            PluginDetector::with_names(["my_load"], ["my_resolve"], ["InitPlugin", "FetchTable"]);
        // Configuration order is scan order: two detectors built the
        // same way see the same names in the same order.
        let loads: Vec<&str> = detector.loads().iter().map(String::as_str).collect();
        let resolves: Vec<&str> = detector.resolves().iter().map(String::as_str).collect();
        let entries: Vec<&str> = detector.entry_points().iter().map(String::as_str).collect();
        assert_eq!(loads, ["my_load"]);
        assert_eq!(resolves, ["my_resolve"]);
        assert_eq!(entries, ["InitPlugin", "FetchTable"]);
    }

    #[test]
    fn added_names_join_their_sets_in_order() {
        let mut detector = PluginDetector::new();
        detector.add_load("LoadLibrary");
        detector.add_resolve("dlsym");
        detector.add_entry_point("Plugin_Init");
        detector.add_entry_point("GetPluginInfo");
        assert_eq!(detector.loads(), ["LoadLibrary"]);
        assert_eq!(detector.resolves(), ["dlsym"]);
        assert_eq!(detector.entry_points(), ["Plugin_Init", "GetPluginInfo"]);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // One detector is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PluginDetector>();
    }

    #[test]
    fn the_standard_names_name_the_loader_and_entry_point_families() {
        let loads = default_load_names();
        assert!(loads.contains(&"LoadLibrary".to_string()));
        assert!(loads.contains(&"LoadLibraryEx".to_string()));
        assert!(loads.contains(&"dlopen".to_string()));
        let resolves = default_resolve_names();
        assert!(resolves.contains(&"GetProcAddress".to_string()));
        assert!(resolves.contains(&"dlsym".to_string()));
        let entries = default_entry_point_names();
        assert!(entries.contains(&"Plugin_Init".to_string()));
        assert!(entries.contains(&"GetPluginInfo".to_string()));
        assert!(entries.contains(&"GetExportTable".to_string()));
        assert!(entries.contains(&"RegisterPlugin".to_string()));
    }

    #[test]
    fn a_detector_built_with_the_standard_sets_carries_them() {
        let detector = PluginDetector::with_default_names();
        assert_eq!(detector.loads(), default_load_names());
        assert_eq!(detector.resolves(), default_resolve_names());
        assert_eq!(detector.entry_points(), default_entry_point_names());
        assert!(PluginDetector::new().loads().is_empty());
    }

    #[test]
    fn a_load_and_resolve_pair_is_one_plugin_finding() {
        // The full load-and-resolve shape: the module load and the
        // entry-point resolve in one body, at the full-pair
        // confidence, with the loader call's line as evidence. The
        // entry-point name inside GetProcAddress's literal argument
        // is prose, not a call.
        let record = one("\
  hMod = LoadLibrary(\"plugin.dll\");
  init = (code *)GetProcAddress(hMod, \"Plugin_Init\");");
        assert_eq!(record.function, "FUN_1800412a0");
        assert_eq!(record.load.as_deref(), Some("LoadLibrary"));
        assert_eq!(record.resolve.as_deref(), Some("GetProcAddress"));
        assert_eq!(record.entry_point, None);
        assert_eq!(record.host_table, None);
        assert_eq!(record.confidence.value(), 70);
        assert_eq!(record.suggestion, "Box<dyn Plugin> (loader crate)");
        assert_eq!(record.evidence, "hMod = LoadLibrary(\"plugin.dll\");");
    }

    #[test]
    fn a_dlopen_and_dlsym_pair_is_one_plugin_finding() {
        let record = one("\
  handle = dlopen(\"plugin.so\", 1);
  init = dlsym(handle, \"Plugin_Init\");");
        assert_eq!(record.load.as_deref(), Some("dlopen"));
        assert_eq!(record.resolve.as_deref(), Some("dlsym"));
        assert_eq!(record.confidence.value(), 70);
        assert_eq!(record.evidence, "handle = dlopen(\"plugin.so\", 1);");
    }

    #[test]
    fn a_lone_resolve_call_is_a_fragment_finding() {
        // A resolve call with no visible load shows only half the
        // shape: kept, but one band below the pair.
        let record = one("  init = GetProcAddress(hMod, \"Plugin_Init\");");
        assert_eq!(record.load, None);
        assert_eq!(record.resolve.as_deref(), Some("GetProcAddress"));
        assert_eq!(record.confidence.value(), 60);
        assert_eq!(
            record.evidence,
            "init = GetProcAddress(hMod, \"Plugin_Init\");"
        );
    }

    #[test]
    fn a_lone_entry_point_name_is_a_fragment_finding() {
        // A direct call to a configured entry-point name, with no
        // loader calls in the body, shows the plugin boundary from the
        // call side alone.
        let record = one("  Plugin_Init(&host_api);");
        assert_eq!(record.load, None);
        assert_eq!(record.resolve, None);
        assert_eq!(record.entry_point.as_deref(), Some("Plugin_Init"));
        assert_eq!(record.confidence.value(), 60);
        assert_eq!(record.evidence, "Plugin_Init(&host_api);");
    }

    #[test]
    fn a_lone_load_call_reports_nothing() {
        // Pulling a DLL in for its exports, with no entry point
        // resolved and no entry-point name called, says nothing about
        // a plugin boundary.
        assert!(detect("  hMod = LoadLibrary(\"helper.dll\");").is_empty());
    }

    #[test]
    fn a_resolve_and_entry_point_without_a_load_stay_a_fragment() {
        // Both halves of the resolve side are visible but the load is
        // not, so the full shape is not claimed. The evidence is the
        // earlier of the two lone calls.
        let record = one("\
  init = GetProcAddress(hMod, \"Plugin_Init\");
  Plugin_Init(&host_api);");
        assert_eq!(record.load, None);
        assert_eq!(record.resolve.as_deref(), Some("GetProcAddress"));
        assert_eq!(record.entry_point.as_deref(), Some("Plugin_Init"));
        assert_eq!(record.confidence.value(), 60);
        assert_eq!(
            record.evidence,
            "init = GetProcAddress(hMod, \"Plugin_Init\");"
        );
    }

    #[test]
    fn a_host_api_table_deepens_the_finding_rather_than_making_a_second() {
        // The full shape plus the entry-point call plus the host API
        // table handed into it: one deepened finding. The entry point
        // and the table go into the same record, and the evidence
        // stays the loader call.
        let record = one("\
  hMod = LoadLibrary(\"plugin.dll\");
  init = (code *)GetProcAddress(hMod, \"Plugin_Init\");
  Plugin_Init(&host_api);");
        assert_eq!(record.load.as_deref(), Some("LoadLibrary"));
        assert_eq!(record.resolve.as_deref(), Some("GetProcAddress"));
        assert_eq!(record.entry_point.as_deref(), Some("Plugin_Init"));
        assert_eq!(record.host_table.as_deref(), Some("host_api"));
        assert_eq!(record.confidence.value(), 70);
        assert_eq!(record.evidence, "hMod = LoadLibrary(\"plugin.dll\");");
    }

    #[test]
    fn a_host_table_on_a_lone_entry_point_deepens_the_fragment() {
        let record = one("  GetExportTable(&host_api);");
        assert_eq!(record.entry_point.as_deref(), Some("GetExportTable"));
        assert_eq!(record.host_table.as_deref(), Some("host_api"));
        assert_eq!(record.confidence.value(), 60);
    }

    #[test]
    fn two_loader_pairs_in_one_body_make_one_finding() {
        // A body either has a plugin architecture or it does not: the
        // record keeps the first pair's spellings and the first load
        // line, and a second module loaded in the same body adds
        // nothing and duplicates nothing.
        let record = one("\
  hMod1 = LoadLibrary(\"a.dll\");
  f1 = GetProcAddress(hMod1, \"Plugin_Init\");
  hMod2 = LoadLibrary(\"b.dll\");
  f2 = GetProcAddress(hMod2, \"GetPluginInfo\");");
        assert_eq!(record.load.as_deref(), Some("LoadLibrary"));
        assert_eq!(record.evidence, "hMod1 = LoadLibrary(\"a.dll\");");
    }

    #[test]
    fn a_plugin_shape_inside_a_string_literal_invents_nothing() {
        // The scan reads code, not prose: a full loader shape inside
        // a string literal is not a load.
        assert!(
            detect("  printf(\"LoadLibrary(x); GetProcAddress(x, \\\"Plugin_Init\\\");\");")
                .is_empty()
        );
    }

    #[test]
    fn a_longer_or_qualified_name_matches_no_configured_name() {
        // Whole names only: a longer spelling is a different symbol,
        // and a qualified or member-accessed callee is another one.
        assert!(
            detect(
                "\
  hMod = MyLoadLibrary(\"plugin.dll\");
  init = ns::GetProcAddress(hMod, \"Plugin_Init\");
  loader.dlopen(\"plugin.so\");
  Plugin_InitEx(&host_api);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_truncated_body_reports_nothing() {
        // A decompile that stops mid-call leaves no balanced call to
        // read; nothing is claimed from a half-line.
        assert!(
            detect(
                "\
  hMod = LoadLibrary(\"plugin.dll\");
  init = GetProcAddress(hMod,"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_detector_with_no_names_reports_nothing() {
        // The standard default sets are what make these names match:
        // a bare detector, with no names configured, reads even the
        // fullest shape as ordinary calls.
        let detector = PluginDetector::new();
        let func = function(
            "\
  hMod = LoadLibrary(\"plugin.dll\");
  init = GetProcAddress(hMod, \"Plugin_Init\");
  Plugin_Init(&host_api);",
        );
        assert!(detector.detect(&func).is_empty());
    }

    #[test]
    fn custom_names_match_like_the_standard_ones() {
        // A program that uses its own spellings for loading and
        // exporting configures them and gets the same reading.
        let detector = PluginDetector::with_names(["OpenModule"], ["BindEntry"], ["InitPlugin"]);
        let func = function(
            "\
  mod = OpenModule(\"extra.mod\");
  init = BindEntry(mod, \"InitPlugin\");
  InitPlugin(&api_table);",
        );
        let findings = detector.detect(&func);
        assert_eq!(findings.len(), 1);
        let record = &findings[0];
        assert_eq!(record.load.as_deref(), Some("OpenModule"));
        assert_eq!(record.resolve.as_deref(), Some("BindEntry"));
        assert_eq!(record.entry_point.as_deref(), Some("InitPlugin"));
        assert_eq!(record.host_table.as_deref(), Some("api_table"));
        assert_eq!(record.confidence.value(), 70);
    }

    #[test]
    fn a_cast_or_address_of_on_the_host_table_is_seen_through() {
        // `(host_api_t *)&host_api` names the same table the bare
        // spelling does.
        let record = one("  Plugin_Init((host_api_t *)&host_api);");
        assert_eq!(record.host_table.as_deref(), Some("host_api"));
    }

    #[test]
    fn a_decompiler_minted_entry_point_argument_names_no_table() {
        // `param_1` is the decompiler's own storage name: the entry
        // point is still recorded as a fragment, but no table is
        // claimed for it.
        let record = one("  Plugin_Init(param_1);");
        assert_eq!(record.entry_point.as_deref(), Some("Plugin_Init"));
        assert_eq!(record.host_table, None);
        assert_eq!(record.confidence.value(), 60);
    }
}
