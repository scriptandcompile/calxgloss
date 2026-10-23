# REA native artifact intelligence — formats, inventories, dumps, firmware

> Part of the [REA overview](README.md). What REA knows about a *file as an
> artifact* before and beside any disassembly: container/decoder tooling,
> whole-file inventories and diffs, crash-core and firmware lanes — the pieces
> 20-rea-inventory.md §3 marks ●. The query surface, providers and raw-binary
> loading are in 31-deep-native-analysis.md and are not repeated here.

## What REA does

REA separates "what is this file / what's in it / how does it differ" from
"what does its code do". The first family runs **without any engine session**:
no Hopper/Ghidra/IDA target, no toolchain installation, no execution of the file
itself (go-binaries.md:1–6, pe-certificates.md:1–11). The second family
(`open_binary` + providers) is chapter 31's territory; the seam is explicit —
firmware extracts return file paths you hand to `open_binary` separately
(firmware-analysis.md:134–151).

### Whole-file inventory & comparison

- **`inspect_artifact` / `inventory_artifact`** — the general container
  inventory: application bundles, ZIP/APK/IPA/MSIX/AppX, ASAR, DMG, directories
  return a complete artifact graph of content-addressed nodes and path
  occurrences; graph manifest IDs are citable (skill
  `native-and-artifacts.md:426–431`). Nodes identify bytes by SHA-256; the same
  bytes at different paths keep per-occurrence kind/format/executable-role
  (apple-application-analysis.md:44–50).
- **`compare_artifacts`** — takes two `inspect_artifact` Evidence records (or
  resolves a retained summary back to its complete parent,
  `src/application/artifacts/ArtifactComparisonEvidence.ts:14–61`) and diffs the
  graphs. Comparison requires **matching `coverage.scope`** (`root` vs
  `container-entries`) and `complete` graph members/traversal before any
  "unchanged" conclusion; missing members yield `truncated`, integrity
  mismatches stay contradictions, and "static artifact equality does not
  establish unchanged runtime behavior" (docs/mcp-contracts.md:37–46).
- **`compare_bundles`** — file-level comparison of two saved Evidence bundle
  JSONs (`left_bundle_path`/`right_bundle_path`,
  `src/contracts/toolContractExamples.ts:87–90`), so version histories kept as
  exported bundles can be re-diffed after sessions close.
- **`binary_overview`** — per-target engine inventory counts (documents,
  segments, procedures, strings); covered in 31-deep-native-analysis.md. Its
  artifact relevance is identity: every Evidence envelope carries artifact path,
  **byte length and SHA-256** of the selected bytes (binary-diagnostics.md:35,
  go-binaries.md:74), and sub-objects get their own digests — each PE resource
  payload (binary-diagnostics.md:194), each BEAM chunk (erlang-beam.md:26), each
  extracted firmware file (firmware-analysis.md:96). Model files split the
  identity honestly: default `hash: "header"` digests only the metadata
  directory and sets `artifact.sha256: null` — "a header digest is not a
  commitment to the weights"; `hash: "full"` streams the rest explicitly
  (model-artifacts.md:28–40).
- **Release-compare routing** (skill `native-and-artifacts.md:3–12`): export
  `list_procedures` Evidence from each target *before closing* it, then
  `match_native_functions` pairs unique exact names plus optional observed body
  bytes; unpaired observations never "prove additions/removals".

### Format decoders built into REA (no external tools)

All built-in, TypeScript, read-only; all support CLI and MCP with the
summary + `parent_evidence_id` + `inspect_analysis_view` pagination pattern
introduced in chapter 31.

| Format | Tool | Yields |
|---|---|---|
| Go binaries (ELF/PE/Mach-O) | `inspect_go_binary` | compiler version string (verbatim + base64), module path, main module path/version/checksum/replacement, dependency list in original order, build settings (`GOOS`, `vcs.revision`…), unparsed lines retained (go-binaries.md:72–101) |
| Rust binaries | `inspect_rust_binary` | cargo-auditable `.dep-v0` section (ELF/PE, `__DATA,.dep-v0` Mach-O): full package graph, dependency edges, root index, cycle indices, compressed/uncompressed sizes; plus `rustc_commit` from a `/rustc/<40-hex>/` path, flagged `evidence_kind: inferred` (rust-binaries.md:85–106) |
| PE Authenticode | `inspect_pe_certificates` | `IMAGE_DIRECTORY_ENTRY_SECURITY` presence, `WIN_CERTIFICATE` entries (length/revision/type/payload SHA-256), PKCS#7 digest OIDs, embedded X.509 issuer/subject/serial/validity, subject-key-ID hex (pe-certificates.md:24–35) |
| PE resources | `inspect_pe_resources` | 3-level type/name/language tree with numeric-ID vs UTF-16-name identity, original offsets/lengths, per-payload SHA-256, icon-group references — opaque otherwise (binary-diagnostics.md:173–217) |
| PE & ELF exports | `inspect_native_exports` | PE export directory (ordinals, aliases, forwarders) or ELF `.dynsym` with version/hidden-version semantics, offline on any host (binary-diagnostics.md:303–344) |
| ELF notes | `inspect_elf_notes` | `PT_NOTE`/`SHT_NOTE` tables, note owners/types, GNU build-id, ABI tags, gold version; descriptor hashes + hex preview (elf-notes.md:23–34) |
| Unity IL2CPP | `inspect_il2cpp_metadata` | `global-metadata.dat` v24/27/29/31/39: images, types, methods, fields/properties/events/parameters with owners, string literals, index widths; with `--binary` also links every method to its code address in `GameAssembly`/`libil2cpp.so` without symbols, and can emit Ghidra name seeds (il2cpp-metadata.md:1–21, 187–260, 313–333) |
| Godot PCK | `inspect_artifact`/`extract_artifact` | PCK formats 2/3/4: engine version, declared file count, per-member logical path/offset/declared MD5 vs observed SHA-256; also finds PCKs embedded at the start or via 12-byte EOF trailer inside executables (godot-pck.md:1–37) |
| Erlang BEAM | `inspect_erlang_beam` | `FOR1`/`BEAM` IFF chunks, atom tables (pre- and post-OTP 28), exports/imports/lambdas resolved to names, Code-chunk header (erlang-beam.md:23–36) |
| CUDA/AMD GPU code | `inspect_gpu_code_objects` | fatbins, CUBIN, PTX, Clang HIP bundles incl. CCOB v1–v3 inside ELF/PE sections: target inventory (`target` vs `payload_target`), kernel params/registers/shared bytes per representation, PTX retained as UTF-8 text artifacts (gpu-code-objects.md:1–9, 79–99) |
| Flutter / Dart AOT ◐ | `identify_flutter_build`, `inspect_dart_aot` | APK-parsed Dart snapshot hash (maps to an SDK build via external datasets), per-ABI `libapp.so` digests, engine GNU build-id; `_kDart*Snapshot*` sections via dynsym, package/URI string pools as lower-bound counts (flutter-analysis.md:1–48) |
| Mach-O / bundles / plists / ObjC ◐ | `inspect_macho`, `open_bundle_resources` + `inspect_plist` / `inspect_asset_catalog` / `decode_interface_builder` / `inspect_keyed_archive`, `trace_dylib_resolution`, `get_objc_classes`/`demangle_swift` | Mach-O layout and exports; Apple app-graph projection by path convention (roles are "path conventions, not parsed plists"), @rpath dyld resolution per executable (skill `native-and-artifacts.md:14–28, 433–446`; apple-application-analysis.md:1–8) |
| Model files ◐ | `inspect_model_artifact` | GGUF v2/v3 + safetensors declarations: typed metadata, tensor names/dtypes/shapes/offsets with storage-validation states; parameter counts are "derived from declarations, not measurements"; no weights interpreted (model-artifacts.md:1–7, 72–77) |
| Any file | `inspect_byte_entropy` | Shannon entropy per block (256–65536 B), high/low run classification for packer/crypto triage; "entropy does not prove encryption" (binary-diagnostics.md:219–268) |

CPython `.pyc`, SQLite snapshots, WASM (WABT) and APK signatures follow the
same shape (skill `native-and-artifacts.md:124–157, 184–220`); out of scope here.

### Caller-supplied tool lanes

REA never installs engines; it supervises **caller-provided** binaries with
pinned, provenance-recorded profiles and env-var absolute paths:

- **pwntools 4.15.0 / pyelftools 0.33 / Unicorn 2.1.2** (`REA_PWNTOOLS_PYTHON`,
  isolated mode, owned cache): offline ELF layout via `inspect_binary_layout` —
  sections/segments, symbols with table+entry index, REL/RELA/RELR relocation
  detail, DT_NEEDED/PT_INTERP names, mitigation *inferences* (canary/PIE/NX/
  RELRO) — and the crash-core decoder (binary-diagnostics.md:9–30;
  recorded-crashes.md:14–16).
- **Binwalk 3.1.x + Unblob 26.6.x** (`REA_BINWALK_COMMAND`,
  `REA_UNBLOB_COMMAND`): `inspect-firmware-regions` and `extract-firmware` as
  owned `prlimit`-bounded processes, version-banner checked per request,
  unmodified pinned submodules for provenance (firmware-analysis.md:1–51).
  Extraction publishes into a fresh absent directory with exclusive
  symlink-resistant writes and digest readback (firmware-analysis.md:127–133),
  then hands verified ELF children to `open_binary` for Ghidra
  (firmware-analysis.md:134–151).
- **GDB 13.1 + pwndbg 2026.09.15** (`REA_PWNDBG_GDB/_GDBINIT/_VENV_PATH`):
  optional debugger mapping context for crash cores only
  (recorded-crashes.md:44–58).

### Crash/dump forensics

`inspect_recorded_crash` reads a caller-selected Linux ELF64 core, x86-64 or
AArch64, independently of any open target (recorded-crashes.md:1–20): every
`NT_PRSTATUS` note becomes a separate recorded **thread** with historical PID,
SIGINFO (signed number/code/errno; only SIGSEGV codes 1/2 decode the
fault-address union), and the complete ABI register set (27/34 registers)
losslessly bound to source bytes; every note — including unfamiliar owners —
keeps owner/descriptor bytes and source ranges (recorded-crashes.md:22–38).
`--debugger-context` adds **mapping candidates** through an owned, locked-down
GDB/pwndbg session (no initfiles/auto-load/debuginfod; `NT_FILE` names must be
absolute, traversal-free paths or enrichment is refused while the base decode
survives); results are marked `derived` vs `observed` (recorded-crashes.md:44–85).
Historical PIDs "never select a live process or authorize attach/control", and
the verification lane proves it with strace `-yy` syscall catalogs and live
sentinels (recorded-crashes.md:40–42, 103–128).

### Skill routing (`native-and-artifacts.md`, artifact sections)

The skill routes by **question, not format habit**: "which Go compiler/modules"
→ `inspect_go_binary` (no `open_binary`, no Go install); "which crates in
`.dep-v0`" → `inspect_rust_binary`; "signer/X.509 fields" →
`inspect_pe_certificates`; PT_NOTE/build-id → `inspect_elf_notes`; "chunks and
atoms" → `inspect_erlang_beam`; "thread registers of this core" →
`inspect_recorded_crash`; single-file ELF facts → `inspect_binary_layout` then
`inspect_analysis_view` instead of re-running the decoder
(skill `native-and-artifacts.md:46–56, 86–122, 134–142, 159–182`). Extraction
intent → `extract_artifact` (REA picks the fresh temp dir; symlinks/encrypted
entries are inventory facts, not extractable files) and
`inspect_byte_entropy` to triage *before* extraction
(skill `native-and-artifacts.md:448–469`). Every routing entry carries the same
posture: preserve artifact SHA-256 and original file ranges; a missing
structure is an *unknown*, never proof of absence; observed metadata
"does not authenticate its claims".

### Evidence honesty: the admitted-semantics pattern

REA's docs state exactly which fields were parsed and which remain unproven.
Representative admissions:

1. **Go**: `build_info: null` "does not prove that the binary is not Go"; a
   GOPATH-mode build's empty dependency array "does not establish the absence
   of dependencies"; `module.complete` only says every *present* line parsed,
   not that the inventory is complete (go-binaries.md:92–93, 103–109, 142–143).
2. **Rust**: missing `.dep-v0` "does not mean the binary has no dependencies";
   the `/rustc/<40-hex>/` hash is `evidence_kind: inferred` and "not a claim
   that that compiler produced the binary"; unknown format revisions decode via
   "the highest known preceding revision" with a limitation naming the unverified
   fallback (rust-binaries.md:103–106, 117–123).
3. **PE certs / ELF notes**: a missing security directory is "observed absence
   of that directory… not proof the image is unsigned in every catalog or
   overlay sense", and no signature/chain/timestamp verification happens
   (pe-certificates.md:37–39, 55–56); a missing note table is likewise "not
   proof the image never carried notes in another container" (elf-notes.md:35–37).
4. **IL2CPP linking**: on x86-64 fallback, module arrays found by scanning
   executable bytes for RIP-relative references make the Evidence **inferred** —
   instruction boundaries and runtime use unverified — while static-table
   associations are **derived** and module records stay file observations
   (il2cpp-metadata.md:211–214); name/count agreement is "structural evidence,
   not a cryptographic same-build proof" (il2cpp-metadata.md:214–215).

## Comparison with calxgloss

### What calxgloss has in the same shape

calxgloss's artifact knowledge is **PE-only and inference-based**, because its
whole point is translating native Windows PEs whose authors embedded nothing:

- **Format/classification**: `calxgloss-analysis` classifies DLLs
  (UI/rendering/game-logic/…) and parks managed PEs detected from the COM
  descriptor (ADR-0044) — the closest analogue to REA's "what runtime family is
  this" hints, but a per-binary pipeline decision, not an on-demand answer.
  There is no Mach-O/ELF/APK/IL2CPP/PCK/BEAM decoder anywhere in the workspace.
- **`calxgloss-apidetect`** reads import tables and maps library→crate —
  overlapping REA's `inspect_native_exports`/ELF linkage names, but pointed at
  translation shims rather than inventory, and PE imports only (no export
  tables, no ELF versioned symbols).
- **`calxgloss-stringctx`** (nine-category string classification, per-function
  string maps) parallels REA's IL2CPP `string_literals` and Dart string pools —
  but calxgloss *derives* meaning from context; REA only *reports declared*
  literals.
- **Known-library identification** is where the two projects choose opposite
  evidence. REA's `rust-binaries`/`go-binaries` read *declared* metadata: exact
  when present. Go's build info is embedded by the toolchain by default, so
  `inspect_go_binary` usually works — but stripping removes it. cargo-auditable
  is an opt-in link flag that almost nobody uses in the wild, so
  `inspect_rust_binary` mostly returns `auditable_metadata: null`.
  `calxgloss-libmatch` instead **identifies statically linked CRT/STL by
  function-body signature matching** — strictly stronger in the metadata-free
  case REA's rust lane assumes away, at the cost of never yielding exact
  versions (a matched body names an MSVC CRT/STL symbol and family, not a
  toolset build number).
  REA's own honesty pattern concedes its declared metadata "does not
  authenticate the packages or the compiler" (rust-binaries.md:124–125).
- **Cert/signature facts**: nothing. calxgloss never parses
  `IMAGE_DIRECTORY_ENTRY_SECURITY`, resources, or debug directories; REA's
  `inspect_pe_certificates`/`inspect_pe_resources` have no calxgloss rival even
  though both operate on calxgloss's exact input format.

### calxgloss-only

Whole-binary unattended operation; engine write-back of inferred types
(ADR-0020/0021); the memory/sync/consts/callback/controlflow/serialize
evidence families; RTTI/vtable recovery; **executing the original DLL** via
`testgen` to capture baseline behavior; PAL mapping and restitching; the review
UI; failure-informed retry strategies.

### REA-only

Multi-format container decoders (ELF/Mach-O/fat-Mach-O slicing/IL2CPP/PCK/
BEAM/GPU/model/Go/Rust); Authenticode + PE resource + PE/ELF export offline
decoders; crash-core and register-level dump forensics; Binwalk/Unblob firmware
extraction with gap ledgers and native handoff; byte-entropy triage;
`compare_artifacts`/`compare_bundles` version diffing; per-subject content
digests and scoped-row identity; summary+retained-Evidence delivery discipline.

### Verdict

For artifact intelligence, the projects are almost disjoint. REA is a
format-aware analyst's toolbox: dozens of honest, bounded, no-install decoders
over any container, wired to question-driven routing. calxgloss has *no*
artifact-intelligence layer at all — its scanners are one PE-specific evidence
family aimed at one downstream consumer (the translation prompt). calxgloss's
inference engines beat REA at recovering facts that were never declared
(types, memory discipline, statically-linked library identity by body); REA
beats calxgloss at everything that *is* declared, and at every question a
human would ask about a file before disassembling it.

### Steal ideas

1. **Admitted-semantics in evidence reports**: calxgloss's `libmatch`/
   `apidetect` output could carry REA-style coverage fields — "signature match,
   version unknown", "import table parsed, delay imports unexamined" — so
   prompts and reviewers never read an inferred claim as an observed one
   (pattern: pe-certificates.md:37–39, rust-binaries.md:117–118).
2. **Artifact-digest identity for the scan cache**: ADR-0043's cache is keyed
   on binary bytes + program name + cache format — already digest-shaped.
   Adopting REA's practice of digesting every *sub-object* (per-export,
   per-import-table-entry, per-resource-node SHA-256, binary-diagnostics.md:194)
   would let the cache survive binaries that differ only in unrelated regions,
   and would give libmatch content-addressed library fingerprints.
3. **`compare_artifacts`-style before/after diff at restitch**: diff the PE
   inventory (exports, imports, section digests, cert table) of the original DLL
   against its restitched counterpart, with REA's rule that scope must match
   before claiming "unchanged" (mcp-contracts.md:37–46); a cheap equivalence
   tripwire ahead of the test suite.
4. **Crash-dump-driven test inputs**: calxgloss's `testgen` invents inputs and
   `edge_case_fix` retries blindly. Consuming Windows minidumps/ELF cores
   REA-style — per-thread registers, fault address, module maps as *mapping
   candidates only* (recorded-crashes.md:22–42) — turns real crashes into
   concrete reproduction inputs and baseline tests.
5. **Entropy + note triage in classification warmup**: `inspect_byte_entropy`
   block profiles (binary-diagnostics.md:219–268) and debug-directory/build-id
   parsing are a few dozen lines of PE walking that would upgrade
   `calxgloss-analysis` packing/obfuscation classification from heuristic name
   checks to measured evidence — and flag which DLLs deserve more context tiers.

## Sources

REA (`/tmp/opencode/rea`, commit 28a33ca):

- `docs/binary-diagnostics.md` (offline ELF layout, PE resources, byte entropy, PE/ELF exports)
- `docs/recorded-crashes.md`
- `docs/go-binaries.md`, `docs/rust-binaries.md`
- `docs/pe-certificates.md`, `docs/elf-notes.md`
- `docs/il2cpp-metadata.md`, `docs/gpu-code-objects.md`
- `docs/erlang-beam.md`, `docs/godot-pck.md`
- `docs/firmware-analysis.md`
- `docs/apple-application-analysis.md` (skimmed), `docs/flutter-analysis.md` (skimmed), `docs/model-artifacts.md` (skimmed)
- `.agents/skills/reverse-engineer-anything/references/native-and-artifacts.md` (artifact-routing sections only)
- `docs/mcp-contracts.md:37–57` (inventory coverage + comparison rules)
- `src/application/artifacts/ArtifactComparisonEvidence.ts`, `src/contracts/toolContractExamples.ts`

calxgloss: `docs/rea/10-calxgloss-baseline.md`, `docs/rea/20-rea-inventory.md` §3,
`docs/rea/31-deep-native-analysis.md` (overlap avoided), ADR-0020/0021/0043/0044,
`crates/evidence/calxgloss-{libmatch,apidetect,stringctx,analysis}`.
