# GhidraMCP v6.0.0 — Endpoint Mapping & Record Formats

Reference for the `calxgloss-ghidra` client port (P1 Phase 0a, completed
2026-10-03; decision recorded in
`docs/adr/0001-bethington-ghidra-mcp-bridge.md`). Use `GET /mcp/schema` on a
running server as the authoritative endpoint/param list.

## Stock plugin → bethington bridge

| `calxgloss-ghidra` method | Stock plugin | bethington bridge |
|---|---|---|
| `list_functions` | `list_functions` | `list_functions` (paged: `offset`/`limit`) or `list_functions_enhanced` |
| `search_functions` | `searchFunctions` | `search_functions` |
| `decompile_function` | `decompile_function` | `decompile_function` (adds `functions=` batch + `timeout`) |
| `decompile_function_by_name` | POST `decompile` | `decompile_function?functions=<name>` |
| `disassemble_function` | `disassemble_function` | `disassemble_function` |
| `function_body` | `get_function_by_address` | `get_function_by_address` |
| `xrefs_to` / `xrefs_from` | `xrefs_to` / `xrefs_from` | `get_xrefs_to` / `get_xrefs_from` (JSON, typed ref categories) |
| `function_xrefs` | `function_xrefs` | `get_function_xrefs` |
| `exports` / `imports` | `exports` / `imports` | `list_exports` / `list_imports` |
| `strings` | `strings` | `list_strings` (regex `filter`, quality filtering) |
| `namespaces` / `classes` / `methods` | `namespaces` / `classes` / `methods` | `list_namespaces` / `list_classes` / `list_methods` |
| `segments` / `image_base` | `segments` | `list_segments`; prefer `get_metadata` for image base |
| `current_address` / `current_function` | same | same (GUI only) |
| `probe` | `get_current_address` + `get_current_function` | `check_connection` + `get_metadata` |
| *(wrappers added by the port)* | — | `list_data_items` (paged), `list_data_items_by_xrefs`, `list_data_types`, `get_struct_layout`, `get_enum_values`, `get_function_callers`/`get_function_callees`, `get_bulk_xrefs`, `read_memory`, `add_function_tag` |

> **v6.0.0 naming:** the dev-branch docs' `set_variable_type` is
> `set_local_variable_type`/`set_decompiler_variable_type`/`batch_set_variable_types`
> in v6.0.0; `rename_symbol` is split into `rename_function`/`rename_data`/
> `rename_variables`/`rename_label`.

## Record formats

Verified against the live v6.0.0 plugin: most endpoints answer `text/plain`,
including the Phase 0a additions: `list_data_types`
(`name | category | N bytes | path`), `list_data_items`
(`LABEL @ addr [TYPE] (N bytes)`), and `get_struct_layout`/`get_enum_values`
(header block + ` | ` field lines; misses arrive as prose sentinels like
`Structure not found: X`, not `{"error": ...}`, so parsers must refuse them).
Only a handful answer JSON (`get_current_address`, `get_current_function`,
`list_imports`, `list_open_programs`); `list_data_items_by_xrefs` accepts
`format=json`. `parse.rs` fixtures are re-captured live and the parsers
accept both shapes.

Domain facts that survive the switch: vftables appear in `list_data_items` as
`vftable`-named items preceded by `vftable_meta_ptr` entries (MSVC RTTI
pattern), `vftable` names are **not unique** — key by address, and
`eqmain.dll` has ~22k–40k data items (page with `offset`/`limit`).
