//! Signature synthesis helpers: the calling-convention spellings, the
//! callback signature map over a workspace, and the hallucination detector's
//! construction.

use super::*;

// ============================================================
// Signature synthesis helpers
// ============================================================

/// The calling-convention keywords that the testgen signature parser picks
/// out of a signature — the same closed set, so a decompiler line the
/// parser reads as carrying a convention never gets a keyword written
/// over it (issue #251, part of #226).
pub(super) const CONVENTION_SPELLINGS: [&str; 6] = [
    "__stdcall",
    "__cdecl",
    "__fastcall",
    "__thiscall",
    "__naked",
    "__retpoline",
];

/// Whether `signature` already names a calling convention in the slot
/// the parser reads — between the return type and the parameter list. A
/// parameter list cannot hold these keywords, so only the part before the
/// opening parenthesis is checked.
pub(super) fn names_convention(signature: &str) -> bool {
    let before_paren = signature.split('(').next().unwrap_or(signature);
    CONVENTION_SPELLINGS
        .iter()
        .any(|spelling| before_paren.contains(spelling))
}

/// Write `convention` into `signature` between the return type and the
/// declarator's name — the slot the parser reads — leaving the parameter
/// list as it is. Returns None when there is no name to write before (no
/// whitespace between the return type and the name), which leaves the
/// signature exactly as the decompiler wrote it.
pub(super) fn spell_convention(signature: &str, convention: &str) -> Option<String> {
    let open = signature.find('(')?;
    let before = signature[..open].trim_end();
    let name_start = before.rfind(|c: char| c.is_whitespace())? + 1;
    if name_start == 0 {
        return None;
    }
    let mut refined = signature[..name_start].to_string();
    refined.push_str(convention);
    refined.push(' ');
    refined.push_str(&signature[name_start..]);
    Some(refined)
}

// ============================================================
// Hallucination detector helpers
// ============================================================

/// Build a [`HallucinationDetector`] from the program's symbols and the
/// PAL API catalogue.
///
/// The detector's set of known-good symbols is the union of:
/// 1. every analysis engine function (exports and user-defined functions)
/// 2. every analysis engine import (DLL imports)
/// 3. every Windows API name in the PAL mapping table
pub async fn build_hallucination_detector(
    source: &KunaSource,
    api_mappings: &ApiMappings,
) -> HallucinationDetector {
    // Analysis engine functions
    let engine_functions: Vec<String> = ScanSource::functions(source)
        .await
        .ok()
        .into_iter()
        .flatten()
        .map(|f| f.name)
        .collect();

    // Analysis engine imports
    let engine_imports: Vec<String> = ScanSource::imports(source)
        .await
        .ok()
        .into_iter()
        .flatten()
        .map(|s| s.name)
        .collect();

    // Gather the Windows API names from the PAL mapping table
    let _windows_apis: Vec<String> = api_mappings
        .iter()
        .map(|m| m.windows_api.to_string())
        .collect();

    HallucinationDetector::new(engine_functions, engine_imports)
}

/// Build the callback scan's signature map from the type-inference
/// document cached for `binary` under `workspace`.
///
/// The callback engine takes its callable contracts by injection (see
/// [`calxgloss_callback::signatures`]); this is the only place that
/// reads the type-inference scan's saved per-binary document and
/// builds those contracts, so the CLI `callback` command and the
/// batch pre-analysis get the same enrichment (issue #173,
/// ADR-0036). A missing or corrupt document — the type-inference scan
/// never ran, or its artifact is broken — gives an empty map and the
/// callback scan quietly falls back to its plain suggestions: a
/// broken artifact next door never fails the scan.
///
/// The map is honest about what the records prove. A function joins
/// it only when its parameter records cover positions `0..n`
/// **contiguously** and a return record is there: a gap means a
/// middle parameter the records never typed, and a contract that
/// skipped it would put every type after it in the wrong place; no
/// parameter records at all cannot tell a zero-parameter callback
/// from one whose parameters were never read; and with no return
/// reading, the contract would claim a unit return that nobody read.
pub fn callback_signature_map(workspace: &Path, binary: &str) -> SignatureMap {
    let persistor = TypeInferPersistor::new(workspace);
    match persistor.load(binary) {
        Ok(result) => compose_signature_map(&result),
        Err(TypeInferError::NotFound { path }) => {
            debug!(
                binary,
                path = %path.display(),
                "No type-inference document cached; the callback scan runs without signature enrichment"
            );
            SignatureMap::new()
        }
        Err(error) => {
            warn!(
                binary,
                error = %error,
                "Type-inference document unreadable; the callback scan runs without signature enrichment"
            );
            SignatureMap::new()
        }
    }
}

/// Group one type-inference document's per-function records into the
/// callable contracts that the callback engine uses: the parameter
/// records by position, and the function's return record.
pub(super) fn compose_signature_map(result: &TypeInferenceResult) -> SignatureMap {
    // First-seen wins per slot, matching the tie-break that the
    // inference scan itself uses for conflicts: a well-formed document
    // holds one record per slot anyway.
    let mut params: HashMap<&str, Vec<(usize, &str)>> = HashMap::new();
    let mut returns: HashMap<&str, &str> = HashMap::new();
    for inference in &result.inferences {
        match inference {
            InferredType::Param(record) => params
                .entry(record.function.as_str())
                .or_default()
                .push((record.param_index, record.inferred_type.as_str())),
            InferredType::Return(record) => {
                returns
                    .entry(record.function.as_str())
                    .or_insert(record.inferred_type.as_str());
            }
            // Locals and call-site readings describe storage, not the
            // callable's contract.
            _ => {}
        }
    }

    let mut signatures = SignatureMap::new();
    for (function, mut slots) in params {
        // A stable sort keeps the first-seen record in front among equal
        // positions, and the dedup step then reduces a repeated position
        // to its first reading.
        slots.sort_by_key(|(index, _)| *index);
        slots.dedup_by_key(|(index, _)| *index);
        if slots
            .iter()
            .enumerate()
            .any(|(position, (index, _))| position != *index)
        {
            continue;
        }
        let Some(return_type) = returns.get(function) else {
            continue;
        };
        signatures.insert(
            function.to_string(),
            CallableSignature {
                param_types: slots
                    .into_iter()
                    .map(|(_, inferred_type)| inferred_type.to_string())
                    .collect(),
                return_type: Some(return_type.to_string()),
            },
        );
    }
    signatures
}
