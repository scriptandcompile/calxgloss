//! COM interface suggestion over the classified import listing and the
//! call-graph names.
//!
//! A binary that imports `CoCreateInstance`, calls `QueryInterface`,
//! and exports `?QueryInterface@IDataSource@@…` is driving a COM
//! interface, but each of those reads as an unrelated entry.
//! [`detect_com`] reads the COM story off the classified import
//! findings the [`ImportTableScanner`](crate::import_table) already
//! emitted plus the names the built call graph already carries — no new
//! [`ScanSource`](crate::engine::ScanSource) reads — and lands
//! [`ComInterface`] claims: one per interface whose name a decorated
//! import name recovers, naming the interface and the method names it
//! saw and carrying the decorated names as evidence, or one binary-level
//! runtime claim when the signals carry no name to recover. The Rust
//! shape every COM claim points at is a trait carrying the interface's
//! methods, not a pile of free functions.
//!
//! The honesty gates are the point of the module: the three signal
//! kinds are known COM runtime imports (`CoCreateInstance`,
//! `CoTaskMemAlloc`, …), the IUnknown-shape method names — the *trio*
//! `QueryInterface`/`AddRef`/`Release` together, since a lone `Release`
//! import is too common a name to claim COM on — and MSVC-decorated
//! method names whose qualified part names the interface. A binary with
//! no COM signals claims nothing; a named-interface claim suppresses
//! the runtime-level one and sits visibly above it in confidence; and
//! the individual import entries stay beside the structural claim
//! rather than being replaced by it.

use crate::types::{ApiFinding, ComInterface, Confidence};

/// Confidence of a named-interface claim: the interface name is
/// recovered from a decorated name the binary itself spells, a solid
/// structural read — level with the other structural readings at 70.
pub const COM_NAMED_CONFIDENCE: u8 = 70;

/// Confidence of a runtime-level claim: the COM signals are runtime
/// imports or bare IUnknown-shape names with no interface behind them,
/// a weaker read — visibly below a named-interface claim.
pub const COM_RUNTIME_CONFIDENCE: u8 = 50;

/// The Rust shape a named-interface claim suggests: the interface
/// modeled as a trait carrying its methods. The accessor appends the
/// interface name and its method listing so the prompt row names the
/// surface it is translating.
pub const COM_INTERFACE_SUGGESTION: &str = "model the COM interface as a Rust trait carrying its methods — one trait method per interface method — instead of a pile of free functions";

/// The Rust shape a runtime-level claim suggests: interface use still
/// modeled as traits, not the COM runtime calls transliterated as free
/// functions.
pub const COM_RUNTIME_SUGGESTION: &str = "the binary drives the COM runtime — model interface use as a Rust trait carrying the interface's methods instead of transliterating the COM runtime calls as free functions";

/// The COM runtime imports whose presence says the binary drives the
/// component model.
const COM_RUNTIME_IMPORTS: &[&str] = &[
    "CoCreateInstance",
    "CoCreateInstanceEx",
    "CoGetClassObject",
    "CoInitialize",
    "CoInitializeEx",
    "CoInitializeSecurity",
    "CoUninitialize",
    "CoTaskMemAlloc",
    "CoTaskMemFree",
    "CoTaskMemRealloc",
    "CoMarshalInterface",
    "CoUnmarshalInterface",
    "CoSetProxyBlanket",
    "StringFromCLSID",
    "StringFromGUID2",
    "CLSIDFromProgID",
    "ProgIDFromCLSID",
];

/// The IUnknown shape: the three method names every COM interface
/// answers. Only the whole trio on a name list counts as a COM signal —
/// one of them alone, `Release` most of all, is too common a name to
/// claim the component model on.
const IUNKNOWN_METHODS: &[&str] = &["QueryInterface", "AddRef", "Release"];

/// Recover `(method, interface)` from an MSVC-decorated method name:
/// `?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z` says
/// `QueryInterface` on `IDataSource`. The name opens with `?`, the
/// method token runs to the first `@`, and the qualified class path
/// that follows closes with `@@` before the access code — its
/// innermost (leftmost) segment names the interface. Anything else —
/// a plain name, a decorated data object (`?IDataSource@@3UA@@A`, whose
/// class segment comes out empty), a name with no `@@` closure — is not
/// a decorated method name and recovers nothing.
fn decorated_method(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix('?')?;
    let (method, qualified) = rest.split_once('@')?;
    if method.is_empty() || qualified.is_empty() {
        return None;
    }
    if !qualified.contains("@@") {
        return None;
    }
    let class = match qualified.find('@') {
        Some(end) => &qualified[..end],
        None => qualified,
    };
    if class.is_empty() {
        return None;
    }
    Some((method, class))
}

/// One interface's claim under construction: the name, the method
/// names seen for it, and the decorated names behind them, each in
/// first-seen order and each carried once however often it appears.
struct InterfaceClaim {
    interface: String,
    methods: Vec<String>,
    evidence: Vec<String>,
}

/// Read the COM signals out of the classified import findings and the
/// call-graph names.
///
/// The names read are the import entries' API names in listing order,
/// then the call-graph node and callee names — the names the scan
/// already holds, so no new [`ScanSource`](crate::engine::ScanSource)
/// reads are made. A decorated name groups its method under the
/// interface it names; when at least one interface was recovered,
/// [`detect_com`] returns one [`ApiFinding::ComInterface`] per
/// interface, in first-seen order, at
/// [`COM_NAMED_CONFIDENCE`]. When none was recovered but the listing
/// carries COM runtime imports or the whole IUnknown trio, it returns
/// exactly one runtime-level claim naming the signals seen as evidence,
/// at the visibly lower [`COM_RUNTIME_CONFIDENCE`]. A listing with no
/// COM signals returns nothing. Only import entries stand on the gate:
/// a usage finding repeats an import the listing already carries.
pub fn detect_com(findings: &[ApiFinding], graph_names: &[String]) -> Vec<ApiFinding> {
    let mut interfaces: Vec<InterfaceClaim> = Vec::new();
    let mut runtime: Vec<String> = Vec::new();
    let mut iunknown: Vec<String> = Vec::new();

    let names = findings
        .iter()
        .filter_map(|finding| match finding {
            ApiFinding::Import(record) => Some(record.api.as_str()),
            _ => None,
        })
        .chain(graph_names.iter().map(String::as_str));

    for name in names {
        if let Some((method, interface)) = decorated_method(name) {
            let claim = interfaces
                .iter_mut()
                .find(|claim| claim.interface == interface);
            let claim = match claim {
                Some(claim) => claim,
                None => {
                    interfaces.push(InterfaceClaim {
                        interface: interface.to_string(),
                        methods: Vec::new(),
                        evidence: Vec::new(),
                    });
                    interfaces.last_mut().expect("just pushed")
                }
            };
            if !claim.methods.iter().any(|seen| seen == method) {
                claim.methods.push(method.to_string());
            }
            if !claim.evidence.iter().any(|seen| seen == name) {
                claim.evidence.push(name.to_string());
            }
        } else if COM_RUNTIME_IMPORTS.contains(&name) && !runtime.iter().any(|seen| seen == name) {
            runtime.push(name.to_string());
        } else if IUNKNOWN_METHODS.contains(&name) && !iunknown.iter().any(|seen| seen == name) {
            iunknown.push(name.to_string());
        }
    }

    if !interfaces.is_empty() {
        return interfaces
            .into_iter()
            .map(|claim| {
                ApiFinding::ComInterface(ComInterface {
                    interface: Some(claim.interface),
                    methods: claim.methods,
                    evidence: claim.evidence.join(", "),
                    confidence: Confidence::new(COM_NAMED_CONFIDENCE),
                })
            })
            .collect();
    }

    if runtime.is_empty() && iunknown.len() < IUNKNOWN_METHODS.len() {
        return Vec::new();
    }

    vec![ApiFinding::ComInterface(ComInterface {
        interface: None,
        methods: Vec::new(),
        evidence: runtime
            .iter()
            .chain(&iunknown)
            .cloned()
            .collect::<Vec<String>>()
            .join(", "),
        confidence: Confidence::new(COM_RUNTIME_CONFIDENCE),
    })]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ApiSignature, ApiUsage};

    fn import(api: &str) -> ApiFinding {
        ApiFinding::Import(ApiSignature {
            api: api.into(),
            library: None,
            rust_crate: None,
            category: None,
            features: Vec::new(),
            confidence: Confidence::new(0),
        })
    }

    fn usage(api: &str) -> ApiFinding {
        ApiFinding::ApiUsage(ApiUsage {
            function: "FUN_18003ab00".into(),
            api: api.into(),
            library: "SomeLibrary".into(),
            rust_crate: "some_crate".into(),
            category: None,
            features: Vec::new(),
            direct: true,
            confidence: Confidence::new(80),
            evidence: format!("FUN_18003ab00 → {api}"),
        })
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn a_decorated_interface_recovers_its_name_and_method_listing() {
        // The named case is the point: three decorated names on one
        // interface land one claim naming the interface, its methods,
        // and the decorated names as evidence.
        let listing = [
            import("?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z"),
            import("?AddRef@IDataSource@@UEAAKXZ"),
            import("?Release@IDataSource@@UEAAKXZ"),
        ];
        let findings = detect_com(&listing, &[]);
        assert_eq!(findings.len(), 1, "one claim per interface");
        let ApiFinding::ComInterface(record) = &findings[0] else {
            unreachable!("the named claim reads as its own record");
        };
        assert_eq!(record.interface.as_deref(), Some("IDataSource"));
        assert_eq!(
            record.methods,
            [
                "QueryInterface".to_string(),
                "AddRef".to_string(),
                "Release".to_string()
            ],
            "the method listing is carried, in first-seen order"
        );
        assert_eq!(
            record.evidence,
            "?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z, ?AddRef@IDataSource@@UEAAKXZ, ?Release@IDataSource@@UEAAKXZ"
        );
        assert_eq!(findings[0].kind(), "com_interface");
        assert_eq!(
            findings[0].function(),
            "",
            "the claim belongs to the binary"
        );
    }

    #[test]
    fn each_decorated_interface_gets_its_own_finding_in_first_seen_order() {
        let listing = [
            import("?QueryInterface@IStream@@UEAAJPEAXPEAPEAX@Z"),
            import("?Read@IStream@@UEAAJPEAKI@Z"),
            import("?Release@IDataSource@@UEAAKXZ"),
        ];
        let findings = detect_com(&listing, &[]);
        assert_eq!(findings.len(), 2, "one claim per interface");
        assert_eq!(findings[0].target(), "IStream");
        assert_eq!(findings[1].target(), "IDataSource");
    }

    #[test]
    fn the_iunknown_shape_counts_as_com() {
        // The bare trio with no runtime import and no decoration still
        // says the component model — one binary-level claim naming the
        // signals seen.
        let listing = [
            import("QueryInterface"),
            import("AddRef"),
            import("Release"),
        ];
        let findings = detect_com(&listing, &[]);
        assert_eq!(findings.len(), 1, "one claim per binary");
        assert_eq!(findings[0].target(), "COM runtime");
        assert_eq!(findings[0].evidence(), "QueryInterface, AddRef, Release");
        assert_eq!(
            findings[0].confidence(),
            Confidence::new(COM_RUNTIME_CONFIDENCE)
        );
    }

    #[test]
    fn runtime_only_imports_yield_one_binary_level_finding() {
        let listing = [
            import("CoCreateInstance"),
            import("CoTaskMemAlloc"),
            import("CoTaskMemFree"),
        ];
        let findings = detect_com(&listing, &[]);
        assert_eq!(findings.len(), 1, "the Option cap is one claim per binary");
        let ApiFinding::ComInterface(record) = &findings[0] else {
            unreachable!("the runtime claim reads as its own record");
        };
        assert_eq!(record.interface, None, "no name to recover");
        assert!(record.methods.is_empty());
        assert_eq!(
            findings[0].evidence(),
            "CoCreateInstance, CoTaskMemAlloc, CoTaskMemFree"
        );
    }

    #[test]
    fn a_named_interface_suppresses_the_runtime_claim() {
        // Runtime imports beside a recoverable name: the named regime
        // wins, and the decorated names are the evidence — the runtime
        // imports stay as their own import entries beside the claim.
        let listing = [
            import("CoCreateInstance"),
            import("?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z"),
        ];
        let findings = detect_com(&listing, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target(), "IDataSource");
        assert_eq!(
            findings[0].confidence(),
            Confidence::new(COM_NAMED_CONFIDENCE)
        );
    }

    #[test]
    fn a_no_signal_listing_claims_nothing() {
        let listing = [
            import("inflate"),
            import("CreateFileA"),
            import("VendorSpecialFunction"),
        ];
        assert!(
            detect_com(&listing, &[]).is_empty(),
            "an ordinary binary is not over-read as COM"
        );
    }

    #[test]
    fn a_lone_iunknown_method_claims_nothing() {
        // The shape is the trio: one or two of the names alone —
        // `Release` most of all — are too common to claim COM on.
        assert!(detect_com(&[import("QueryInterface")], &[]).is_empty());
        assert!(detect_com(&[import("Release"), import("AddRef")], &[]).is_empty());
    }

    #[test]
    fn only_import_entries_stand_on_the_gate() {
        // A usage finding repeats an import the listing already
        // carries; the gate reads the import entries, not the usages.
        let listing = [usage("CoCreateInstance"), usage("QueryInterface")];
        assert!(detect_com(&listing, &[]).is_empty());
    }

    #[test]
    fn call_graph_names_carry_the_signals_too() {
        // A decorated thunk name in the call graph, with no COM import
        // in the listing, still lands the named claim.
        let listing = [import("inflate")];
        let findings = detect_com(
            &listing,
            &names(&["?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z"]),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target(), "IDataSource");

        // And the bare trio as callee names opens the runtime gate.
        let findings = detect_com(&listing, &names(&["QueryInterface", "AddRef", "Release"]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target(), "COM runtime");
    }

    #[test]
    fn a_name_seen_in_both_listings_is_carried_once() {
        let decorated = "?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z";
        let findings = detect_com(&[import(decorated)], &names(&[decorated]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence(), decorated, "the name rides once");
        let ApiFinding::ComInterface(record) = &findings[0] else {
            unreachable!("the named claim reads as its own record");
        };
        assert_eq!(record.methods, ["QueryInterface".to_string()]);
    }

    #[test]
    fn named_claims_sit_above_runtime_claims_in_confidence() {
        const { assert!(COM_NAMED_CONFIDENCE > COM_RUNTIME_CONFIDENCE) };
        let named = detect_com(
            &[import("?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z")],
            &[],
        );
        let runtime = detect_com(&[import("CoCreateInstance")], &[]);
        assert_eq!(named[0].confidence(), Confidence::new(COM_NAMED_CONFIDENCE));
        assert_eq!(
            runtime[0].confidence(),
            Confidence::new(COM_RUNTIME_CONFIDENCE)
        );
        assert!(named[0].confidence() > runtime[0].confidence());
    }

    #[test]
    fn the_suggestions_name_the_trait_shape() {
        let named = detect_com(
            &[
                import("?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z"),
                import("?Release@IDataSource@@UEAAKXZ"),
            ],
            &[],
        );
        let suggestion = named[0].suggestion();
        assert!(suggestion.contains("trait"), "got: {suggestion}");
        assert!(suggestion.contains("IDataSource"), "got: {suggestion}");
        assert!(
            suggestion.contains("QueryInterface, Release"),
            "the method listing rides the suggestion: {suggestion}"
        );

        let runtime = detect_com(&[import("CoCreateInstance")], &[]);
        let suggestion = runtime[0].suggestion();
        assert!(suggestion.contains("trait"), "got: {suggestion}");
        assert!(suggestion.contains("COM"), "got: {suggestion}");
    }

    #[test]
    fn decorated_names_that_are_not_method_names_recover_nothing() {
        // A decorated data object (`?IDataSource@@3UA@@A`) and a name
        // with no `@@` closure are not decorated methods: no interface
        // is recovered and no claim lands.
        let listing = [
            import("?IDataSource@@3UA@@A"),
            import("?QueryInterface@IDataSource"),
        ];
        assert!(detect_com(&listing, &[]).is_empty());
    }

    #[test]
    fn a_nested_class_path_recovers_the_innermost_name() {
        // `?Read@A@B@@` is `Read` on the class `A` nested in `B`: the
        // innermost segment names the interface.
        let findings = detect_com(&[import("?Read@A@B@@UEAAJPEAKI@Z")], &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target(), "A");
    }

    #[test]
    fn the_detector_state_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ComInterface>();
        assert_send_sync::<ApiFinding>();
    }
}
