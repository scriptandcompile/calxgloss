# ADR-0001: Switch the Ghidra bridge to bethington/ghidra-mcp v6.0.0

- **Status:** Accepted
- **Date:** 2026-10-03
- **Deciders:** Arthur (solo project)

## Context

calxgloss talks to Ghidra over HTTP via a GhidraMCP plugin. The stock
LaurieWired GhidraMCP plugin 1.4 (~20 endpoints, plain-text responses) had two
gaps that would have forced us to maintain a patched fork:

1. **Type-library listing** — no way to enumerate Ghidra's TypeManager
   (needed by P1 Data Structure Recovery: named types, struct layouts, enum
   values, including types never applied to symbols).
2. **Type creation for write-back** — no `create_struct`/`create_enum`/etc.,
   so inferred types could not flow back into Ghidra (P2's write-back work,
   and the stock plugin's "Base type not found" dead end).

The stock plugin also lacks: paged data-item listing, real xref endpoints
(forcing callee-scraping from decompiled text in `function_report`), a
metadata endpoint (forcing a min-segment `image_base()` hack), a `program=`
selector on program-scoped endpoints (the silent "current program" hazard
documented in `client.rs`), batch decompile, and function tags.

## Decision

Replace the stock plugin with
[bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) **v6.0.0
(stable)** — 272 JSON REST endpoints, built for Ghidra 12.1.2 (no Ghidra
upgrade needed), installed as the `GhidraMCP-6.0.0.zip` release into
`~/.config/ghidra/ghidra_12.1.2_PUBLIC/Extensions/GhidraMCP`. A headless
server exposes the same API.

- `calxgloss-ghidra` keeps talking raw HTTP to the Java plugin.
- **Ports:** the bridge default is 8080; we run our load instance on a custom
  port, **8089** (8080 is taken by the local AI).
- **Strict Naming Enforcement is off** in Tool Options (we don't want the
  Hungarian-notation gates on write endpoints).
- Consider `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1` once multiple programs
  can be open.

Both fork-forcing gaps are solved upstream: TypeManager listing
(`list_data_types`, `list_data_type_categories`, `search_data_types`,
`get_struct_layout`, `get_enum_values`) and type creation
(`create_struct`, `add_struct_field`, `modify_struct_field`, `create_enum`,
`create_typedef`, `create_union`, `apply_data_type`, `set_global`).

## Consequences

**Gains (client workarounds removed):**
`get_function_callers`/`get_function_callees`/`get_full_call_graph`/
`get_bulk_xrefs` replace decompiled-text callee scraping; `get_metadata`
replaces the `image_base()` hack; a `program=` selector fixes the
current-program hazard; batch decompile (`decompile_function?functions=a,b,c`);
function tags (`add_function_tag`/`list_function_tags`).

**Caveats:**
- **Not everything is JSON.** Verified live against v6.0.0: most endpoints
  still answer `text/plain` (including `list_data_types`, `list_data_items`,
  `get_struct_layout`, `get_enum_values`); misses arrive as prose sentinels
  (`Structure not found: X`), not JSON errors. Parsers must accept both
  shapes. See `docs/ghidra_endpoint_map.md` for the full endpoint
  mapping and record formats.
- **Strict version coupling:** the extension jar is compiled against one
  Ghidra build (`extension.properties` → `version=12.1.2`). A Ghidra upgrade
  silently breaks the bridge; `doctor` must compare the pair (see
  `ghidra_integration.md` §5.3).
- v6.0.0 renames vs dev-branch docs: `set_variable_type` →
  `set_local_variable_type`/`set_decompiler_variable_type`/
  `batch_set_variable_types`; `rename_symbol` → `rename_function`/
  `rename_data`/`rename_variables`/`rename_label`.

The client port itself completed 2026-10-03 (P1 Phase 0a); type write-back
wrappers were deferred to P2 Phase 5 (no P1 consumer at the time).
