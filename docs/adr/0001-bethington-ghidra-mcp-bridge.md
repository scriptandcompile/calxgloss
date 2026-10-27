# ADR-0001: Switch the Ghidra bridge to bethington/ghidra-mcp v6.0.0

- **Status:** Superseded by ADR-0041 (2026-10-18, issue #214 — the bridge and its client are deleted; Kuna is the only engine)
- **Date:** 2026-10-03
- **Deciders:** Arthur (solo project)

## Context

calxgloss talks to Ghidra over HTTP through a GhidraMCP plugin. The stock
LaurieWired GhidraMCP plugin 1.4 had about 20 endpoints and answered in
plain text. It had two gaps that would have forced us to maintain a patched
fork:

1. **Type-library listing** — the plugin had no way to list Ghidra's
   TypeManager. P1 Data Structure Recovery needs that list: named types,
   struct layouts, and enum values, including types that were never applied
   to symbols.
2. **Type creation for write-back** — the plugin has no
   `create_struct`/`create_enum`/etc., so inferred types could not flow back
   into Ghidra. This blocked P2's write-back work, and it ran into the
   stock plugin's "Base type not found" dead end.

The stock plugin also lacks other things. It has no paged data-item listing.
It has no real xref endpoints, so `function_report` scraped callees out of
decompiled text. It has no metadata endpoint, so we used a min-segment
`image_base()` hack. Its program-scoped endpoints have no `program=`
selector, which created the silent "current program" hazard documented in
`client.rs`. It also lacks batch decompile and function tags.

## Decision

Replace the stock plugin with
[bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) **v6.0.0
(stable)**. It has 272 JSON REST endpoints and is built for Ghidra 12.1.2,
so no Ghidra upgrade is needed. It is installed as the `GhidraMCP-6.0.0.zip`
release into
`~/.config/ghidra/ghidra_12.1.2_PUBLIC/Extensions/GhidraMCP`. A headless
server exposes the same API.

- `calxgloss-ghidra` keeps talking raw HTTP to the Java plugin.
- **Ports:** the bridge defaults to 8080. We run our load instance on a
  custom port, **8089**, because the local AI already uses 8080.
- **Strict Naming Enforcement is off** in Tool Options. We do not want the
  Hungarian-notation gates on write endpoints.
- Consider `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1` once more than one
  program can be open.

The new plugin solves both fork-forcing gaps upstream. It provides
TypeManager listing (`list_data_types`, `list_data_type_categories`,
`search_data_types`, `get_struct_layout`, `get_enum_values`) and type
creation (`create_struct`, `add_struct_field`, `modify_struct_field`,
`create_enum`, `create_typedef`, `create_union`, `apply_data_type`,
`set_global`).

## Consequences

**Gains (client workarounds removed):**
`get_function_callers`/`get_function_callees`/`get_full_call_graph`/
`get_bulk_xrefs` replace the workarounds that scraped callees out of
decompiled text. `get_metadata` replaces the `image_base()` hack. A
`program=` selector fixes the current-program hazard. Batch decompile works
(`decompile_function?functions=a,b,c`). Function tags work
(`add_function_tag`/`list_function_tags`).

**Caveats:**
- **Not everything is JSON.** Checked live against v6.0.0: most endpoints
  still answer `text/plain`, including `list_data_types`, `list_data_items`,
  `get_struct_layout`, and `get_enum_values`. A miss arrives as a prose
  sentinel (`Structure not found: X`), not as a JSON error. Parsers must
  accept both shapes. See `docs/ghidra_endpoint_map.md` for the full
  endpoint mapping and record formats.
- **Strict version coupling:** the extension jar is compiled against one
  Ghidra build (`extension.properties` → `version=12.1.2`). A Ghidra upgrade
  breaks the bridge silently, so `doctor` must compare the pair (see
  `ghidra_integration.md` §5.3).
- v6.0.0 renamed endpoints compared to the dev-branch docs:
  `set_variable_type` became
  `set_local_variable_type`/`set_decompiler_variable_type`/
  `batch_set_variable_types`, and `rename_symbol` became `rename_function`/
  `rename_data`/`rename_variables`/`rename_label`.

The client port itself finished on 2026-10-03 (P1 Phase 0a). The type
write-back wrappers waited for P2 Phase 5, because P1 had no consumer for
them at the time.
