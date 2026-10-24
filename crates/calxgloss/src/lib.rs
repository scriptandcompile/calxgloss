//! Calxgloss — unified library re-exporting all workspace crates.
//!
//! This crate re-exports all public types, structs, enums, and functions
//! from the Calxgloss workspace crates for convenient single-crate access.
//!
//! # Usage
//!
//! ```
//! use calxgloss::{KunaSource, LlmClient, TranslationPipeline, ApiMappings};
//! ```

// ============================================================
// calxgloss-types — shared data structures
// ============================================================

pub use calxgloss_types::dll::*;
pub use calxgloss_types::error::TypesError;
pub use calxgloss_types::function::*;
pub use calxgloss_types::git::*;
pub use calxgloss_types::test::*;
pub use calxgloss_types::verification::{FailedTest, VerificationResult};

// Dashboard types
pub use calxgloss_types::dashboard::{
    DependencyEdge, DependencyGraph, DependencyNode, ReviewAction, ReviewActionKind,
    ReviewDashboard, ReviewStatus, StatusCounts, UnitOfWork, WorkKind,
};

// Context tier types
pub use calxgloss_types::context_tier::ContextTier;

// Progress event types
pub use calxgloss_types::confidence::Confidence;
pub use calxgloss_types::progress::{
    NoUnitInFlight, PipelineControl, PipelineRunRequest, PipelineState, PipelineTransitionError,
    ProgressEvent, RunPhase, RunRequestSignal, RunScope, RunTarget, StopSignal, TranslationEvents,
    UnitCancellation,
};
pub use calxgloss_types::scan::{EngineProvenance, ScanMetadata};
pub use calxgloss_types::scope::{
    FunctionRef, ScopeControl, TranslationConstraints, TranslationScope,
};
pub use calxgloss_types::{
    BinaryClassificationOverride, ClassificationOverrideControl, ClassificationOverrides,
    classification_override_records_path,
};
pub use calxgloss_types::{
    FunctionOverride, OverrideControl, UnitOverrides, override_records_path, unit_override_key,
};

// ============================================================
// calxgloss-decomp — the analysis seam, and calxgloss-kuna — the engine
// ============================================================

pub use calxgloss_decomp::CachedScanSource;
pub use calxgloss_decomp::DecompiledFunction;
pub use calxgloss_decomp::EngineError;
pub use calxgloss_decomp::FunctionSummary;
pub use calxgloss_decomp::PipelineSource;
pub use calxgloss_decomp::StringLiteral;
pub use calxgloss_decomp::Symbol;
pub use calxgloss_decomp::Xref;
pub use calxgloss_decomp::rva_from_va;
pub use calxgloss_kuna::KunaSource;

// ============================================================
// calxgloss-llm — Local LLM client
// ============================================================

pub use calxgloss_llm::LlmClient;
pub use calxgloss_llm::LlmConfig;
pub use calxgloss_llm::LlmError;
pub use calxgloss_llm::LlmMessage;
pub use calxgloss_llm::LlmResponse;
pub use calxgloss_llm::MessageRole;
pub use calxgloss_llm::strip_code_fences;

// ============================================================
// calxgloss-prompts — Prompt templates and rendering
// ============================================================

pub use calxgloss_prompts::TestCaseFormatted;
pub use calxgloss_prompts::TranslateTemplate;
pub use calxgloss_prompts::build_translate_prompt;
pub use calxgloss_prompts::error::PromptError;

// ============================================================
// calxgloss-pal — Platform Abstraction Layer mappings
// ============================================================

pub use calxgloss_pal::ApiMapping;
pub use calxgloss_pal::ApiMappings;
pub use calxgloss_pal::mapping_count;

// ============================================================
// calxgloss-analysis — DLL classification & API tagging
// ============================================================

pub use calxgloss_analysis::AnalysisError;
pub use calxgloss_analysis::Analyzer;
pub use calxgloss_analysis::DllClassification;
pub use calxgloss_analysis::FunctionAnalysis;
pub use calxgloss_analysis::Result as AnalysisResult;
pub use calxgloss_analysis::Strategy;
pub use calxgloss_analysis::classify_dll_name;
pub use calxgloss_analysis::crate_replacement_for;

// ============================================================
// calxgloss-callgraph — call graph analysis and ordering
// ============================================================

pub use calxgloss_callgraph::builder::CallGraphBuilder;
pub use calxgloss_callgraph::context::{
    CallEdgeInfo, CallGraphNode, CalleeGroup, ContextEnricher, ContextEnricherConfig,
    FunctionContext, LeafApiContext, skipped_contexts,
};
pub use calxgloss_callgraph::leaf_detector::{
    ApiSignature, LeafCategory, LeafDetector, TransitiveLeafContext,
};
pub use calxgloss_callgraph::models::{CallGraph, CallGraphEdge, CallType, FunctionCallGraph};
pub use calxgloss_callgraph::ordering::{
    FunctionTranslationPlan, StateSharingEdges, TranslationOrderer, TranslationPriority,
};
pub use calxgloss_callgraph::persist::CallGraphPersistor;
pub use calxgloss_callgraph::root_detector::{
    ConfigurableRootDetector, RootAction, RootDetector, RootDetectorConfig, RootPattern,
    RootPatternConfig,
};

// ============================================================
// calxgloss-typesdb — data structure recovery
// ============================================================

pub use calxgloss_typesdb::{Result as TypesDbResult, TypesDbError};

// ============================================================
// calxgloss-memory — memory lifecycle / RAII detection
// ============================================================

// The crate's `Result` alias is deliberately not re-exported:
// `MemoryResult` already names the per-binary document, and a second
// alias spelled like it would read as the same thing.
pub use calxgloss_memory::MemoryError;
pub use calxgloss_memory::types::{
    AllocationType, CountStyle, HandleLifecycle, HandleType, MemoryFinding, MemoryHint,
    MemoryResult, ReferenceCount,
};

// ============================================================
// calxgloss-stringctx — string & configuration context
// ============================================================

// The crate's `Result` alias is deliberately not re-exported:
// `StringContextResult` already names the per-binary document, and a second
// alias spelled like it would read as the same thing. The crate's
// `ScanMetadata` is the shared one from calxgloss-types, already
// named here.
pub use calxgloss_stringctx::{
    ClassifiedString, CrossFunctionAnalyzer, CrossFunctionFlow, FormatCall, FormatHint,
    FormatStringEngine, FormatStringUse, HybridXrefMapper, LocalizationDetector,
    LocalizationSignalKind, LocalizationSignals, MappedString, StringClassification,
    StringClassifyEngine, StringContextEngine, StringContextPersistor, StringContextResult,
    StringCtxError, StringFinding, StringSource,
};

// ============================================================
// calxgloss-sync — concurrency & synchronization detection
// ============================================================

// The crate's `Result` alias is deliberately not re-exported:
// `SyncResult` already names the per-binary document, and a second
// alias spelled like it would read as the same thing. The crate's
// `ScanMetadata` is the shared one from calxgloss-types, already
// named here.
pub use calxgloss_sync::SyncError;
pub use calxgloss_sync::types::{
    AtomicOperation, ConcurrencyHint, SyncFinding, SyncResult, SyncType, ThreadSpawn,
};

// ============================================================
// calxgloss-globalstate — global-state reference sets
// ============================================================

// The crate's `Result` alias is deliberately not re-exported:
// `GlobalStateResult` already names the per-binary document, and a
// second alias spelled like it would read as the same thing. The
// crate's `ScanMetadata` is the shared one from calxgloss-types,
// already named here.
pub use calxgloss_globalstate::GlobalStateError;
pub use calxgloss_globalstate::types::{
    AccessKind, FunctionPurity, GlobalAccess, GlobalStateFinding, GlobalStateResult,
    SharedGlobalRecord,
};

// ============================================================
// calxgloss-floatsimd — float/SIMD usage flags
// ============================================================

// The crate's `Result` alias is deliberately not re-exported:
// `FloatsimdResult` already names the per-binary document, and a
// second alias spelled like it would read as the same thing. The
// crate's `ScanMetadata` is the shared one from calxgloss-types,
// already named here.
pub use calxgloss_floatsimd::FloatsimdError;
pub use calxgloss_floatsimd::types::{
    FloatsimdFinding, FloatsimdRecord, FloatsimdResult, ShapeKind,
};

// ============================================================
// calxgloss-consts — constant & enum recovery
// ============================================================

// The crate's `Result` alias is deliberately not re-exported:
// `ConstResult` already names the per-binary document, and a second
// alias spelled like it would read as the same thing. The crate's
// `ScanMetadata` is the shared one from calxgloss-types, already
// named here.
pub use calxgloss_consts::ConstError;
pub use calxgloss_consts::types::{
    BitflagGroup, ConstFinding, ConstResult, DataTable, EnumCandidate, NamedConstant,
};

// ============================================================
// calxgloss-apidetect — library & API identification
// ============================================================

// The crate's `Result` alias is deliberately not re-exported:
// `ApiDetectionResult` already names the per-binary document, and a second
// alias spelled like it would read as the same thing. The crate's
// `ScanMetadata` is the shared one from calxgloss-types, already
// named here. `ApiSignature` is also not re-exported: it clashes with the
// leaf_detector::ApiSignature already named here — reach it as
// `calxgloss_apidetect::types::ApiSignature` if needed.
pub use calxgloss_apidetect::api_summary::ApiSummaryDetector;
pub use calxgloss_apidetect::import_table::ImportTableScanner;
pub use calxgloss_apidetect::lib_mapping::MappingDatabase;
pub use calxgloss_apidetect::{ApiDetectionResult, ApiError, ApiFinding, ApiUsage};

// ============================================================
// calxgloss-callback — callback & function-pointer table detection
// ============================================================

// The crate's `Result` alias is deliberately not re-exported:
// `CallbackResult` already names the per-binary document, and a second
// alias spelled like it would read as the same thing. The crate's
// `ScanMetadata` is the shared one from calxgloss-types, already
// named here.
pub use calxgloss_callback::CallbackError;
pub use calxgloss_callback::signatures::{CallableSignature, SignatureMap};
pub use calxgloss_callback::types::{
    CallbackChain, CallbackFinding, CallbackRegistration, CallbackResult, FpArrayCall, JumpTable,
    PluginArchitecture,
};

// ============================================================
// calxgloss-controlflow — control-flow pattern recognition
// ============================================================

// The crate's `Result` alias is deliberately not re-exported:
// `ControlFlowResult` already names the per-binary document, and a second
// alias spelled like it would read as the same thing. The crate's
// `ScanMetadata` is the shared one from calxgloss-types, already
// named here.
pub use calxgloss_controlflow::ControlFlowError;
pub use calxgloss_controlflow::types::{
    BranchClassification, BranchDensity, ControlFlowFinding, ControlFlowResult, LoopKind,
    LoopNesting, MutualRecursion, SelfRecursion, StateMachine, SwitchChain,
};

// ============================================================
// calxgloss-libmatch — known-library function identification
// ============================================================

// The crate's `Result` alias is deliberately not re-exported:
// `LibmatchResult` already names the per-binary document, and a second
// alias spelled like it would read as the same thing. The crate's
// `ScanMetadata` is the shared one from calxgloss-types, already
// named here.
pub use calxgloss_libmatch::LibmatchError;
pub use calxgloss_libmatch::types::{
    LibmatchFinding, LibmatchMatch, LibmatchResult, LibraryFamily,
};

// ============================================================
// calxgloss-errhandling — error-handling idiom detection
// ============================================================

// The crate's `Result` alias is deliberately not re-exported:
// `ErrhandlingResult` already names the per-binary document, and a
// second alias spelled like it would read as the same thing. The crate's
// `ScanMetadata` is the shared one from calxgloss-types, already named
// here.
pub use calxgloss_errhandling::ErrhandlingError;
// The propagation analyzer type is deliberately not re-exported:
// the facade's `CrossFunctionAnalyzer` name already belongs to the
// string-context crate's pass, as it has since before the memory and
// errhandling passes adopted the same in-crate name.
pub use calxgloss_errhandling::{
    ErrhandlingFinding, ErrhandlingResult, ErrorCode, ErrorCodeSite, ExceptionApiCall, GotoCleanup,
    InheritedErrorCode, NamedHandler, RaiseException, SehFrame,
};

// ============================================================
// calxgloss-bdiff — binary-version function pairing
// ============================================================

// The crate's `Result` alias is deliberately not re-exported:
// `PairingDocument` already names the per-version-pair document, and a
// second alias spelled like a result would read as the same thing.
// The pass and the persistor are named beside the types because the
// pairing document has no engine — `pair_versions` is the whole scan.
pub use calxgloss_bdiff::BdiffError;
pub use calxgloss_bdiff::{
    BODY_EQUAL_CONFIDENCE, BODY_SIMILARITY_FLOOR, CARRY_OVER_CONFIDENCE_FLOOR, FunctionEntry,
    MatchFamily, NAME_IDENTITY_CONFIDENCE, PairingDocument, PairingRecord, ScanSnapshot,
    TOPOLOGY_AGREEMENT_BUMP, TOPOLOGY_CONFIDENCE, TOPOLOGY_MIN_PAIRED_NEIGHBORS,
};
pub use calxgloss_bdiff::{BdiffPersistor, pair_versions};

// ============================================================
// calxgloss-serialize — endianness & serialization detection
// ============================================================

// The crate's `Result` alias is deliberately not re-exported:
// `SerializeResult` already names the per-binary document, and a second
// alias spelled like it would read as the same thing. The crate's
// `ScanMetadata` is the shared one from calxgloss-types, already
// named here.
pub use calxgloss_serialize::SerializeError;
pub use calxgloss_serialize::types::{
    BitPackPattern, BitPackRecord, ByteSwapOperation, MagicFormat, SerializeFinding,
    SerializeResult,
};

// ============================================================
// calxgloss-typeinfer — type inference and propagation
// ============================================================

// The crate's `ScanMetadata` is deliberately not re-exported:
// `calxgloss-types::scan::ScanMetadata` already owns that name here.
// Its `ScanSource` re-export is deliberately not re-exported either: the
// shared trait already stands here under that name, from
// `calxgloss_algorithm::engine`.
pub use calxgloss_typeinfer::engine::TypeInferEngine;
pub use calxgloss_typeinfer::error::{Result as TypeInferResult, TypeInferError};
pub use calxgloss_typeinfer::known_type::{
    ExtractedCall, KNOWN_SIGNATURES, KnownSignature, KnownTypePropagationEngine, SignatureArg,
    SignatureMatch,
};
pub use calxgloss_typeinfer::param_size::ParameterSizeDetector;
pub use calxgloss_typeinfer::persist::TypeInferPersistor;
pub use calxgloss_typeinfer::this_ptr::ThisPointerDetector;
pub use calxgloss_typeinfer::types::{
    CallingConvention, InferenceMethod, InferenceScope, InferredCallType, InferredConvention,
    InferredLocalType, InferredParamType, InferredType, TypeInferenceResult,
};

// ============================================================
// calxgloss-algorithm — algorithm recognition
// ============================================================

// The crate's `ScanMetadata` is deliberately not re-exported (same name
// clash as `calxgloss-typeinfer` above).
pub use calxgloss_algorithm::callback_db::{
    CallbackDetection, CallbackPattern, CallbackPatternDb, HostMatch, TypeHint, TypeTarget,
};
pub use calxgloss_algorithm::cfg_patterns::CfgPatternMatcher;
pub use calxgloss_algorithm::engine::{AlgorithmEngine, ScanSource};
pub use calxgloss_algorithm::error::{AlgorithmError, Result as AlgorithmResult};
pub use calxgloss_algorithm::persist::AlgorithmPersistor;
pub use calxgloss_algorithm::string_hints::{StringHintEngine, StringSignature};
pub use calxgloss_algorithm::types::{
    AlgorithmCategory, AlgorithmHint, AlgorithmPattern, AlgorithmRecognitionResult, DetectionMethod,
};

// ============================================================
// calxgloss-testgen — FFI bindings, test input generation
// ============================================================

pub use calxgloss_testgen::BaselineRunner;
pub use calxgloss_testgen::DisassemblyEdgeCases;
pub use calxgloss_testgen::EdgeCaseSource;
pub use calxgloss_testgen::FfiBinding;
pub use calxgloss_testgen::FfiBindingBuilder;
pub use calxgloss_testgen::ParameterTypeInfo;
pub use calxgloss_testgen::TestContext;
pub use calxgloss_testgen::TestGenerator;
pub use calxgloss_testgen::generate_ffi_binding;
pub use calxgloss_testgen::generate_test_inputs;
pub use calxgloss_testgen::parse_signature;

// ============================================================
// calxgloss-translator — Translation pipeline
// ============================================================

pub use calxgloss_translator::BatchTranslationResult;
pub use calxgloss_translator::FunctionResult;
pub use calxgloss_translator::Result as TranslatorResult;
pub use calxgloss_translator::Translation;
pub use calxgloss_translator::TranslationPipeline;
pub use calxgloss_translator::Translator;
pub use calxgloss_translator::TranslatorError;

// ============================================================
// calxgloss-verify — Compilation and behavioral verification
// ============================================================

pub use calxgloss_verify::CompileResult;
pub use calxgloss_verify::Stubs;

// NOTE: FailedTest, TestCase, and VerificationResult are re-exported
// from calxgloss-types above (calxgloss-verify re-exports them for
// convenience, but we only need one copy)

// ============================================================
// calxgloss-git — Git branch/commit/merge automation
// ============================================================

pub use calxgloss_git::BranchResult;
pub use calxgloss_git::GitManager;
pub use calxgloss_git::InitConfig;
pub use calxgloss_git::MergeResult;
pub use calxgloss_git::PatchRecord;

// ============================================================
// calxgloss-reports — Terminal output formatting
// ============================================================

pub use calxgloss_reports::print_batch_summary;
pub use calxgloss_reports::print_classification_report;
pub use calxgloss_reports::print_failure;
pub use calxgloss_reports::print_git_status;
pub use calxgloss_reports::print_success;
pub use calxgloss_reports::print_translation_summary;
pub use calxgloss_reports::print_verification_results;
pub use calxgloss_reports::prompt_acceptance;

// ============================================================
// calxgloss-config — layered configuration
// ============================================================

// The generic names are qualified on re-export so the crate root stays
// readable: `load_config`, `CONFIG_PROJECT_FILE`, `CONFIG_EXAMPLE`.
pub use calxgloss_config::{
    ConfigError, EXAMPLE as CONFIG_EXAMPLE, FileConfig, Layers, LlmSection, LoadedConfig,
    PROJECT_FILE as CONFIG_PROJECT_FILE, Resolved, Source, defaults, load as load_config,
};
