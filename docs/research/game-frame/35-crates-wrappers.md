# GameFrame's artifact layer: 28 crates and the replacement-DLL wrappers

> Part of the [game-frame overview](README.md). The reusable Rust artifacts game-frame
> ships: every crate in the 28-member `crates/` workspace, the 10-member `wrappers/`
> replacement-DLL workspace, and the concrete evidence each artifact carries (case-study
> originals, emulator runs, golden comparisons, in-repo tests). The launcher crate is
> ch.34 §5's; the crates' existence claims here were verified at HEAD `f195a07` by opening
> every crate's README, Cargo.toml and test files. LOC here is **src-only**
> (`find crates/<c>/src -name '*.rs' -exec cat {} + | wc -l`), which runs below the
> inventory §11 numbers (those fold in each crate's README + Cargo.toml); test counts are
> `grep -c '#\[test\]'` per crate (in-src + `tests/`). ch.20 §11–12 are the count baseline.

## 1. The workspace doctrine

`crates/` is one Cargo workspace. Its header states the doctrine verbatim: "Clean
implementations of hardware and runtime pieces that many old games need, taken from the
case-study reimplementations and made generic. Each crate has its own README"
(`crates/Cargo.toml:1-2`); the 28 members are listed on one line at `:5`; shared package
fields pin `version = "0.1.0"`, `edition = "2021"`, `license = "Apache-2.0"`,
`rust-version = "1.80"` (`:7-12`). The frame-side crates (`frame`, `frame-ui`, `library`,
`game-source`, `disc-image`) raise themselves to `rust-version = "1.85"`, and `game-source`
and `disc-image` use `edition = "2024"` — the emulation core lags, the platform pieces
lead.

`docs/crates/README.md` is the crate encyclopedia and the admission bar. The admission
rules (`:81-93`): a crate "comes from a reimplementation where it was checked against the
original program, or, for a platform piece such as the library, from a port where it was
used"; it is generic — "no game's names, formats or rules in its code"; "its tests run
without any game's files" and tool-dependent tests skip when the tool is missing; "no
`unsafe` code, few dependencies, and builds for `wasm32-unknown-unknown`"; third-party
code keeps its licence notice (the `gameframe-wma` exception, `crates/wma/THIRD_PARTY.md:3-5`
— tables taken from oxideav-wma 0.0.4, MIT). The table at `:7-36` carries **28 provenance
rows**, each naming the case study or original program the crate was checked against —
this is the crate-to-evidence map §9 leans on.

Two doctrine paragraphs make the crates *conditional* infrastructure rather than
assumed-correct dependencies: "When to use a crate, and when to check it first"
(`docs/crates/README.md:69-79`) — find the game's own copy of the chip or runtime code,
run *it* under GameFrame's emulator (`re-emulate`), and "compare the results with the
crate bit for bit" before trusting a dependency; the same text ships as a copy-paste
agent prompt (`:38-51`). Consumption is by git dependency (`:58-61`); the owner "may
relicense owned work, including a crate as `Apache-2.0 OR MIT`" (`:66-67`).

The 28 split into two economies: **emulation artifacts** (chips, codecs, math, cards —
each checked against an original program) and **frame plumbing** (`frame`, `frame-ui`,
`library`, `game-source`, `report`, `disc-image`, `bitmap-font` — checked by hand, by
synthetic tests, or against the frame demo instead). A stale number to correct: the
dossier's own ch.00 intro says "31 crates"; the workspace lists **28** members
(`crates/Cargo.toml:5`, 28 README rows, 29 `Cargo.toml` incl. the root) — ch.20 §11's
count is right.

**vs calxgloss:** calxgloss's 34-crate workspace is a *single machine* — every crate is a
stage of one pipeline and nothing is consumable outside it. game-frame's 28 crates are
*shelf goods*: published for third parties to `git = "…"` them into their own ports
(`docs/crates/README.md:55-61`), with an explicit buyer-beware contract (check against
your game first). Same language, opposite workspace intent.

## 2. Crate ledger — all 28

Categories are this dossier's; "prov." names the original program or case study the
crate's README claims it was checked against (empty = modelled from documents only).
Provenance rows condensed from `docs/crates/README.md:9-36`; LOC = src-only (see header
for the exact command); deps = `[dependencies]` + `[target.*]` lines in `Cargo.toml`;
tests = `#[test]` in src / in `tests/` (files listed in §3–§7).

| Crate | Category | src LOC | Deps | Tests in/out | Prov. (checked against) |
|---|---|---:|---:|---|---|
| `wma` | codec | 10,608 | 0 | 2 / 1 (`tests/ffmpeg_parity.rs`) | Un-Banished, vs FFmpeg `wmav2` |
| `sound-blaster` | chip-emulation | 4,749 | 2 (opl2,opl3) | 0 / 19 (`tests/device.rs`) | CT1741 firmware 4.05 static trace |
| `frame` | frame-contract | 2,266 | 4 | 7 / 29 (`tests/frame.rs`) | Un-Banished, POD, Hardwar + demo/sh-game |
| `indeo` | codec | 2,453 | 0 | 0 / 3 (`tests/streams.rs`) | POD — 13,663 pictures vs Intel's codec under emulation |
| `powervr` | graphics-pipeline | 1,920 | 0 | 12 / 8 (`tests/scenes.rs`) | POD PowerVR build (traced; no card) |
| `voodoo` | graphics-pipeline | 1,979 | 1 (texel) | 29 / 3 (`tests/formats.rs`) | SST-1 spec; POD 3dfx build (no card) |
| `library` | frame-contract | 1,497 | 7 | 0 / 11 (`tests/library.rs`) | Un-Banished browser store; hand-checked vs page |
| `game-source` | player-data | 1,643 | 6 | 7 / 0 | POD; tests run a local HTTP server |
| `msvc-crt` | math-parity | 1,530 | 0 | 7 / 0 | Un-Banished — 200,000 calls per float fn |
| `ymz263` | chip-emulation | 1,214 | 0 | 0 / 12 (`tests/chip.rs`) | GSS toolkit + Wave/MIDI driver trace |
| `disc-image` | player-data | 1,112 | 0 | 2 / 6 (`tests/synthetic.rs`) | POD; synthetic images in tests |
| `frame-ui` | frame-contract | 1,283 | 8 | 2 / 0 | hand-checked in frame-demo (browser + macOS) |
| `d3d` | graphics-pipeline | 1,107 | 0 | 6 / 5 (`tests/execute.rs`) | POD Direct3D build (traced; no card) |
| `adlib-gold` | chip-emulation | 931 | 2 (opl3,ymz263) | 5 / 8 (2 files) | GSSOPL3.DRV trace + Gold dev toolkit |
| `opl2` | chip-emulation | 1,106 | 0 | 8 / 0 | Frontier: Elite II — sample-for-sample |
| `turbo-pascal` | math-parity | 636 | 0 | 0 / 8 (`tests/runtime.rs`) | Tyrian 2026 — 40k operands / 90k draws |
| `report` | frame-contract | 537 | 3 | 0 / 2 (`tests/report.rs`) | POD + Hardwar; tested through frame `Link` |
| `saa1099` | chip-emulation | 652 | 0 | **none** | Philips handbook + static driver traces only |
| `opl3` | chip-emulation | 508 | 1 (opl2) | 2 / 0 | YMF262 datasheet + GSSOPL3.DRV trace |
| `sn76496` | chip-emulation | 548 | 0 | **none** | TI/PCjr/Tandy docs + Sierra driver traces |
| `bitmap-font` | utility | 580 | 0 | 5 / 0 | Hardwar `HARDS.FNT`/`HARDL.FNT`; eye-checked |
| `mmx` | math-parity (SIMD) | 343 | 0 | 0 / 9 (`tests/semantics.rs`) | POD MMX mixer — 500 channels |
| `rage` | graphics-pipeline | 294 | 2 (raster,texel) | 3 / 1 (`tests/tables.rs`) | POD ATI build + ATI SDK guide |
| `yac512` | chip-emulation | 249 | 0 | 3 / 0 | YAC512/YMF262 datasheets + timing measure |
| `virge` | graphics-pipeline | 229 | 2 (raster,texel) | 2 / 1 (`tests/tables.rs`) | POD S3 build + `S3DTK.H` |
| `raster` | graphics-pipeline | 227 | 0 | 3 / 0 | POD (shared by rage/virge) |
| `texel` | graphics-pipeline | 157 | 0 | 0 / 4 (`tests/layouts.rs`) | POD; SST-1 format table for widening |
| `scale` | graphics-pipeline | 97 | 0 | 0 / 5 (`tests/scalers.rs`) | POD replacement libraries show frames scaled |
| **total** | — | **40,455** | — | **≈105 / ≈135** | 18 `tests/` dirs, 54 test files |

These src figures sum to the 43,667 Rust lines in 189 `.rs` files that ch.20 §11 counts;
`wc -l` was run on `crates/<c>/src/**/*.rs` only (40,455) — inner `#[test]` modules are
inside that count, while the 54 files under `crates/*/tests` add the other 3,212 lines.
Test counts are `#[test]` occurrences, an approximation —
`tests/run.sh` counts real passes at run time. Two facts stand out: **`saa1099` and
`sn76496` have no tests at all** in the repo (no `tests/`, no `#[cfg(test)]` — verified by
grep), consistent with their READMEs' "static traces … remain open" posture
(`docs/crates/README.md:11-12`); and the biggest crate (`wma`, 10,608 L of pure
decoder) has almost no unit tests, its proof being one parity test against FFmpeg (§6).
Dependency economy: 16 of 28 crates have **zero** dependencies; the only non-workspace
deps in the whole graph are `dioxus 0.7.10` + `pulldown-cmark` (`frame-ui`), `ureq 3.4`
(`game-source`, desktop only), `serde`/`serde_json`/`web-time` (`frame`, `report`,
`library`) — everything else is intra-workspace edges: `opl3→opl2`, `adlib-gold→opl3,
ymz263`, `sound-blaster→opl2,opl3`, `rage/virge→raster,texel`, `voodoo→texel`,
`frame→report,disc-image`, `library→game-source→disc-image`, `frame-ui→frame,library`.

## 3. Sound-chip crates (opl2, opl3, adlib-gold, yac512, saa1099, sn76496, sound-blaster, ymz263)

**`opl2` (YM3812/OPL2)** is the one chip crate with output-parity evidence: it runs at the
chip's own 49,716 Hz (3,579,545/72, `crates/opl2/README.md:6-7`), models the log-sine and
exponent tables, phase and envelope generators, waveforms, feedback, rhythm, noise, timers
and CSM from "published die and datasheet analyses" (`:8-11`), is integer and
deterministic "including WebAssembly" (`:12-14`), band-limited resampler (`:14`); "Its
output is identical sample for sample to the original driver running on that project's DOS
runtime (*measured*)" — Frontier: Elite II's own AdLib driver (`:17-19`). The rest, at
ledger level:

| Crate — models | README | Tests | Validation stance |
|---|---|---|---|
| `opl3` (YMF262 on the OPL2 core: 2 banks, 18 ch, 4-op pairs, 8 waveforms, serial DAC frames) | `crates/opl3/README.md:3-6` | 2 inner | datasheets + slot-timing measurement; "does not use source code from another emulator" (`:8`); the `GSSOPL3.DRV` trace "does not provide output-parity evidence" (`:10`); quantization "not been measured against hardware" (`:119`), hardware recording "not a release blocker" (`:133`) |
| `adlib-gold` (Gold/GSS ports + Control Chip: bank switch, busy, EEPROM, relocation) | `crates/adlib-gold/README.md:3-5` | 5 + 8 | Gold Developer Toolkit v1.01 + independent static `GSSOPL3.DRV` trace (`:7-11`); TDA8425/analog/DMA-IRQ "remain open" (`docs/crates/README.md:15`) |
| `ymz263` (YMZ263B MMA: 2 PCM/ADPCM FIFOs, dividers, timers, DMA state, MIDI FIFOs, UART) | `crates/ymz263/README.md:3-6` | 12 (`chip.rs`) | datasheet + toolkit + static GSS driver trace; ADPCM rounding/interleave/status "need software comparisons" (`:62`, `:69`) |
| `yac512` (YAC512 serial receiver: FSEL formats, two channel latches) | `crates/yac512/README.md:3-5` | 3 inner | Yamaha datasheets + published serial timing measurement (`:7-11`); analog transfer curve open (`docs/crates/README.md:13`) |
| `saa1099` (SAA1099 + two-chip CMS port, detection-IC model) | `crates/saa1099/README.md:3-20` | **none** | Philips 1986 handbook + static `CMSDRV.COM`/Sierra traces (`:22-27`); noise taps/seed "deterministic candidates" (`:31-34`); comparison deferred to `docs/hardware/cms-saa1099.md` (`:27`) |
| `sn76496` (TI PSG + PCjr write-only + Tandy eight-port adapters, audio muxes) | `crates/sn76496/README.md:3-21` | **none** | PCjr Tech Reference + Tandy service manual + Sierra `JR.DRV`/`TANDY.DRV` traces; "contains no copied emulator code" (`:23-30`); LFSR taps/seed are candidates (`:34-36`); plan in `docs/hardware/tandy-psg.md` (`:30`) |
| `sound-blaster` (DSP 1.xx–4.xx, CT1335/1345/1745 mixers, SB16 MPU-401, embeds OPL2/OPL3) | `crates/sound-blaster/README.md:3-5` | 19 (`device.rs`) | Creative HW reference + static CT1741 firmware 4.05 trace; ADPCM "not yet been compared sample-for-sample", reference byte unset (`:99-104`); Creative's RE restriction "a consideration rather than a blanket ban" (`:8-15`) |

No chip crate ships a recording or golden sample; bit-exactness claims for sound live at
the *case-study* level (Frontier's driver), not inside the crates. The split: **one crate
output-parity measured, two document models with zero tests (verified: no `tests/`, no
`#[cfg(test)]`), five trace-and-spec models with honest open gaps.**

## 4. Math-parity crates: msvc-crt, turbo-pascal (mmx in §5)

These exist because bit-exact ports require the *original* math, not IEEE-correct math.
The doctrine line: "`sinf`, `cosf`, `atan2f`, `powf`, `expf` come from the C runtime the
game shipped with. They differ in the last bit between runtimes. Emulate them and
reimplement the caller" (`docs/ABI.md:73`). The crate-check contract
(`docs/crates/README.md:69-79`) is the `re-port` loop applied to dependencies.

| Crate | src L / tests | Reproduces | Proof — and its honest limit |
|---|---|---|---|
| `msvc-crt` | 1,530 / 7+0 | `sinf`/`cosf`/`acosf`/`atan2f` "operation by operation" — MSVC's are not correctly rounded, Rust's `f32::sin` "can differ in the last bit, which can change a simulation" (`crates/msvc-crt/README.md:9`); `qsort` as median-of-three quicksort + shortsort for partitions ≤8 so "Equal elements can change order" matches (`:10`); `rand`/`srand` 32-bit LCG with `RAND_MAX` 32,767 (`:11`); bounded `memory`/`string`/`parse`/`convert` (`:7-15`) | floats "match Banished's copies of the runtime on 200,000 calls each", sort matches "on recorded sorts (*measured* with GameFrame's emulator)" (`:26-27`) — proven against **Un-Banished's own inlined CRT copies under emulation**, not Microsoft's DLL; the added x86 routines are *observed* from "exported functions and selected decompiles" of 2008–2013 CRT DLLs, "not yet compared call by call with each DLL" (`:29-36`); the 7 tests check ulp bounds, known `rand` values, and that the sort is *unstable* on purpose (`:83-85`) |
| `turbo-pascal` | 636 / 0+8 | `Real48` — the 6-byte software-real with the System unit's full routine set: "Programs built without the 8087 option do all `Real` arithmetic in software, with their own rounding. IEEE doubles give different last bits" (`crates/turbo-pascal/README.md:8`); `TurboRandom` (`RandSeed`/`Random`/`Randomize`) — "the order and the values of the draws are behaviour" (`:9`); `PascalReader`/`PascalWriter`/`PStr` on-disk layouts (`:10`) | from Tyrian 2026: "every `Real` routine here matches the original program on 40,000 random operands, and 90,000 random draws match bit for bit (*measured* under GameFrame's DOS emulator). `div` is measured only for divisors of 2.0" (`:12-15`); the 8 `tests/runtime.rs` tests are property tests only — "The bit-for-bit checks against the original runtime live in the Tyrian 2026 project, which has the program" (`crates/turbo-pascal/tests/runtime.rs:1-2`) |

**`mmx`** (§5's ledger but same family — exact integer SIMD): the Pentium MMX packed
instructions as bit-for-bit Rust functions on `u64` (`crates/mmx/README.md:3-10`), because
"Games of 1997 to 1999 used MMX in hand-written assembly: sound mixers, software texture
mappers" and a port "gives the same bits as the original, on every platform, WebAssembly
included" (`:12-14`). A model of POD's MMX sound mixer built on the crate "matched the
original routine, run under GameFrame's emulator, on 500 random channels of 500
(*measured*)" (`:17-19`); the 9 `tests/semantics.rs` tests re-check instruction semantics
(saturation, shifts, `pmaddwd`'s overflow case) in isolation.

Calxgloss contrast: its float-simd evidence scan exists precisely because it refuses this
work — principle 1 targets observable behavior, and last-bit float parity with MSVC is
"deliberately out of scope" (baseline, "Ground truth converges" anchor). game-frame turns
that out-of-scope detail into a whole dependency class.

## 5. Graphics-pipeline crates (d3d, mmx, powervr, rage, virge, voodoo, raster, texel, scale)

Two tiers live here: **full software models of specific cards/APIs** (`voodoo`,
`powervr`, `d3d`) and **shared substrate** the card models and the wrapper DLLs are
assembled from (`raster`, `texel`, `scale`, `mmx`, plus the knowledge packs `rage`,
`virge`). The README-declared validation status of the three big models is identical and
honest: "**Nothing has been compared with a real card yet**" — `crates/voodoo/README.md:29`,
`crates/powervr/README.md:33`, `crates/d3d/README.md:31` (deviations from the spec land in
`Deviation:` comments, voodoo:29). Their evidence is *traced call streams* from POD's
per-card builds, not pixels from hardware.

| Model | src L / tests | What it replays | Key rules |
|---|---|---|---|
| `voodoo` | 1,979 / 32 (most-tested) | SST-1 pixel pipeline "in the order of the Glide 2.x reference manual's pipeline" + a software Glide 2.x context (`Glide`) with calls by their Glide names, "at any multiple of the game's resolution" (`crates/voodoo/README.md:7-24`; SST-1 spec rev 1.61 `:23-24`) | combine units' integer arithmetic (0–256 factor, truncating product, clamp), chroma key, table fog, Z (`ooz`) and W (`1/oow`) buffers, RGB565 with 4×4 ordered dither, gamma out |
| `powervr` | 1,920 / 20 | PCX2 as VideoLogic's SGL 3.1 drives it — a **scene graph** (`sgl_render`), not a triangle API (`crates/powervr/README.md:3-9`) | driver's exact spotlight formula `(1 − min((1 − cos) log2 c, 1))²` "as PowerVR's driver (`SGLMID4.dll`) works it"; per-pixel nearest-opaque wins whatever the order; translucent passes in order; 565 out (`:17-24`) |
| `d3d` | 1,107 / 11 | Direct3D 3 execute buffers: `Builder` writes, `exec::parse` reads `D3DOP_PROCESSVERTICES`/`STATERENDER`/`TRIANGLE` (`crates/d3d/README.md:9-13`) | D3D fill rules: "pixel centres at integer coordinates and the top-left filling convention, so triangles that share an edge draw each pixel once" (`:15-16`) |

| Piece | src L / tests | Role | Evidence discipline |
|---|---|---|---|
| `rage` | 294 / 3+1 | "everything GameFrame knows" about ATI3DCIF — format enums, state ids, function lists from the ATI 3D Rage Programmer's Guide rev 1.30 with page cites (`crates/rage/README.md:3-9`); a modest `draw` path through `raster`; texturing/fog/Z "Not here yet" (`:16-17`) | `tests/tables.rs` pins the table names; consumed twice over — "The `wrappers/ati3dcif` DLL and Un-POD's ATI renderer both draw with it" (`:14`) |
| `virge` | 229 / 2+1 | the S3D Toolkit twin — tables from `S3DTK.H`, S3D ToolKit SDK 2.6 (`crates/virge/README.md:8`), same open gaps (`:16`) | same DLL-and-port double consumption (`:13`) |
| `raster` | 227 / 3+0 | the triangle rasteriser for 8/15/16-bit buffers, up to eight interpolated attributes, a shader closure | fill rule carries its evidence label: screen-space interpolation "*inferred* for the ATI Rage and S3 ViRGE"; "Whether the chips rounded edges exactly this way is *unknown*" (`crates/raster/README.md:9-13`) |
| `texel` | 157 / 0+4 | the decade's texel layouts — RGB565, ARGB1555, 4444, 332, YIQ behind a `Yiq` trait for 3dfx's NCC table — plus the 2:1 point reduction | sub-8-bit channels "widen by bit replication … as the chips' own colour paths did", cited to SST-1 §5.50 (`crates/texel/README.md:3-11`) |
| `scale` | 97 / 0+5 | whole-multiple frame scaling: nearest, Scale2x/EPX, a CRT look | "*Scale the frame after it is finished, never the game's own buffers, so the game's drawing stays bit for bit the original's*" (`crates/scale/README.md:15-16`) — born from POD's replacement Glide/DirectDraw libraries (`:18-20`) |

Provenance for the whole cluster is one game: **POD: Planet of Death (1997)**, "whose ATI
build was traced with it", "whose PowerVR build was traced with it", etc.
(`docs/crates/README.md:19-27`) — and the unifying purpose is the seam: the crates let the
*traced* calls from an original card build be re-driven at modern resolutions, while
`wrappers/` lets the *live* original drive them directly (§8).

## 6. Codec crates: indeo, wma

**`indeo`** (2,453 L) is the project's clean-room flagship and the tightest fit with the
re-cleanroom doctrine. It decodes Intel Indeo Video Interactive 4.1 (FourCC `IV41`) "as
Intel's own Video for Windows codec `IR41_32.DLL` (R4.11.15.91) does on its Pentium path,
picture for picture: the same bytes in Intel's `IF09` (YVU9) layout"
(`crates/indeo/README.md:3-5`). The clean-room discipline: "Every rule comes from Intel's
own `IR41_32.DLL`, read in its code and run under GameFrame's emulator
(`tools/emu/pe32_emu.py`). No other decoder's source, data or description of its
internals was read", with the POD project's evidence pages naming the DLL address behind
every rule (`:8-12`). The verdict: "On all 13,663 pictures of POD Gold's six videos, each
picture is byte-identical to the one Intel's codec gives under the emulator (*measured*,
2026-10-24)" (`:13-14`). Legal hygiene goes one step further — **the tables are not in
the crate**: `Tables::from_dll` reads codebooks, scan orders and quantiser matrices from
*the player's own copy* of Intel's DLL (`:15-18`). In-repo tests are self-contained —
streams and tables built inside the test (`tests/streams.rs`, `README:52`); the real
13,663-picture comparison lives in the POD project, which holds the files. It builds for
32-bit Windows (`:7`) so `wrappers/ir41` can ship it as `ir41_32.dll` (§8).

**`wma`** (10,608 L — the workspace's largest crate) is a pure-Rust WMA v2 decoder
(format tag `0x161`) for xWMA and ASF streams, no deps, `wasm32`-ready
(`crates/wma/README.md:3-9`). Its oracle is **FFmpeg**, not an original decoder binary:
"Checked against FFmpeg's `wmav2` decoder: on every sound of Banished (in Un-Banished),
and in this crate's tests on tones and noise that FFmpeg encodes. The signal-to-noise
ratio must be at least 60 dB; the tests measure about 130 dB" (`:10-12`) — note the bar
is *perceptual parity*, not bit-exactness, because no WMA bitstream ground truth was
available; the `tests/ffmpeg_parity.rs` test skips when `ffmpeg` is absent (`:94-95`),
exactly per the tool-skip rule. Third-party data tables (oxideav-wma, MIT) keep their
notice in `crates/wma/THIRD_PARTY.md:1-5`.

The pair straddles the project's two verification ceilings: indeo reaches **bit-for-bit
picture equality against the original codec under emulation** (the re-cleanroom ideal),
wma settles at **≥60 dB SNR against a reference implementation** (an external oracle —
closer to how calxgloss accepts "observable behavior" equivalence than to game-frame's
own doctrine, and labelled as such in the README).

## 7. The frame-contract cluster (frame, frame-ui, library, game-source, report, disc-image, bitmap-font)

**`frame` (2,266 src L) is the versioned port↔frame contract**, and it is where
game-frame's "the frame around every port" claim becomes concrete code. The pieces, at
their source lines:

- **Events.** `Event { topic, data, from, id }` (`crates/frame/src/event.rs:27`); wire
  form is one JSON object, e.g.
  `{"topic":"config.set","data":{"key":"video.fog","value":false},"from":"frame","id":7}`
  (`crates/frame/README.md:28`). Topics are `area.action`, listeners match exact/prefix/`*`
  (`:31-34`); the closed roster — `frame.ready/open/close/exit/preference`,
  `config.set/changed/options`, `render.select`, `device.select`,
  `game.start/stop/status`, `input.press`, `library.changed`, `report.new`,
  `log.message` — is tabulated at `README.md:36-55` with directions and data, and lives
  in code as `crates/frame/src/event.rs:77` (`pub mod topics`). Games may invent topics;
  the console shows unknown ones (`README.md:32-34`).
- **The manifest.** The game "describes itself once, when the frame starts" and the frame
  "draws only what the manifest names" (`README.md:60-61`): capabilities
  (`start, renderers, devices, settings, input, library`), renderers and device slots
  each with a **coverage grade**, settings (`toggle/choice/range/text`, dynamic options
  via `from: {"files": …}` or `{"game": true}`), controls (`README.md:63-99`). Grades are
  a closed five-step enum — `Missing · Experimental · Partial · Good · Exact`, where
  `Exact` means "Checked against the original, frame for frame"
  (`crates/frame/src/manifest.rs:58-70`); a renderer may carry `done`/`total` counts and
  notes (`README.md:90-92`). Device slots (`video/sound/music/input`) share global ids,
  and `device::known(id)` names the GameFrame crate or wrapper modelling each device —
  the contract's pointer back into this chapter's artifact shelf (`README.md:100-109`,
  `crates/frame/src/device.rs`). Unported devices declare a `stand_in`, so "every listed
  device starts end to end" and the gap writes `unported` reports
  (`README.md:107-115`). `CONTRACT = "1.1"`; a larger major version is refused
  (`crates/frame/src/manifest.rs:15`, `:224-226`).
- **Three ways to join.** Rust: implement `Game` — `manifest()`,
  `on_event(&Event, &mut Outbox)`, optional `poll()` (`crates/frame/src/game.rs:9-21`);
  `Outbox` has `send/status/log` (`:24-40`). Any language: `Process::spawn` runs a JSON-lines
  program whose first stdout line is its manifest (`README.md:126-129`) — and the test
  suite proves that claim with a literal shell script
  (`crates/frame/tests/frame.rs:159`, `:222`, `:286`: `Process::spawn("sh", ["-c", script])`).
  The port's *own end*: `Link::wait(&mut game, start)` (`crates/frame/src/link.rs:49-55`, `wait_on` at `:57`)
  and `Respawn::spawn` (`crates/frame/src/respawn.rs:33`) for one-window-per-process winit ports — "POD's and Hardwar's
  launchers run their games this way" (`README.md:138-143`). Config-only: `Configured::from_json` reads a `frame.json` and
  substitutes `{renderer}`/`{device:SLOT}`/`{setting:KEY}` into a command
  (`crates/frame/src/configured.rs:56`, `:67`, `README.md:145-161`) — the shape `launcher/`
  (ch.34 §5) turns into an app.
- **Session, settings, demo.** `Session` (`crates/frame/src/session.rs:19`) wires game +
  listeners + state machine; `Settings` persists `frame.*` keys to one JSON object and
  the `--frame/--launcher/--no-frame` flags decide first-run visibility
  (`README.md:176-183`); `Demo` is the built-in stand-in game that presses its own
  controls so the console shows traffic (`README.md:185-192`). 36 tests total, the
  `tests/frame.rs` set being the JSON-lines and manifest-resolution proofs.

| Part | src L / tests | What it is | Verification |
|---|---|---|---|
| `frame-ui` | 1,283 / 2+0 | The frame's views as Dioxus 0.7 components (browser + desktop): launcher, renderer choice "with coverage grades", settings, library, help, event console — talking to the game *only* through `Session` (`crates/frame-ui/README.md:3-5`); one module per view (`src/views/{console,library,page,play,settings}.rs`); `src/themes.rs:7` = `THEMES` embedded CSS, single-sourced from `templates/library-page/themes/*.css` — `tests/run.sh:1876` fails if a page theme is missing from it | "Checked by hand in the frame demo, in a browser and on a macOS desktop" (`docs/crates/README.md:34`); only 2 tests — the UI's verification is human, by doctrine |
| `library` | 1,497 / 0+11 | Player-data spine: game data, saves, opt-in sections (mods, screenshots, recordings) declared in one `library.json` shared with the library-page template (`crates/library/README.md:3-7`); desktop stores keep `ROOT/SECTION/NAME` so "players can copy saves by hand" (`:40`); browser store = IndexedDB with **AES-GCM on by default**, non-extractable WebCrypto key (`:59-61`), big files plain in OPFS (`:66-67`) | 11 tests on the folder/memory stores; "the browser store was checked by hand against the page" (`:89`); provenance a three-way merge — Un-Banished's start page, POD's sources, Hardwar's crates (`docs/crates/README.md:32`) |
| `game-source` | 1,643 / 7+0 | One `Source` trait over a folder, a CD image read in place, layered patches, and a URL the player supplies — resume + MD5 native, 1 MiB HTTP ranges in the browser; "The crate holds no URL" (`crates/game-source/README.md:4`) | tests run a local HTTP server for resume, ranges, MD5 (`README.md:41-42`) |
| `report` | 537 / 0+2 | The *unported-path* ledger: `unported!`/`mismatch!` (macros at `crates/report/src/lib.rs:244`, `:259`) write one JSON + one Markdown file per place, the Markdown "a GitHub issue's body, laid out for an agent to debug from" (`README.md:14-16`); Dev/Production modes (`lib.rs:122-138`); `GAMEFRAME_STRICT=1` panics after filing (`lib.rs:142`, `:168`) | the artifact-level twin of calxgloss's `UnknownRecord`s — except it emits a *launchable* bug for an agent |
| `disc-image` | 1,112 / 2+6 | CD images in place — CUE+BIN (Mode 1, Mode 2 Form 1), cooked ISO, ISO 9660 with Joliet — every read through a `ReadAt` trait, missing bytes failing with a `Missing` error naming chunks that `game-source` resolves over HTTP ranges (`crates/disc-image/README.md:3-12`) | tests build a synthetic image "in every layout the crate reads" (`:36-38`, `tests/synthetic.rs:1-2`) — the no-game-files rule done properly |
| `bitmap-font` | 580 / 5+0 | A game's bitmap font cells → a TrueType font *built in memory* (`head/hhea/maxp/OS/2/hmtx/cmap4/loca/glyf/name/post`, `crates/bitmap-font/README.md:12-13`) served as a CSS `@font-face` data URL, so a theme writes "in the game's own letters"; "commit none of the game" — Hardwar's launcher regenerates `HARDS.FNT`/`HARDL.FNT` every start (`:18`) | 5 table tests; the font "checked by eye in the frame on macOS" (`docs/crates/README.md:36`) |

## 8. `wrappers/` — the replacement-DLL workspace

The rule up front: "Each DLL here has the original's file name and exports, so the
unchanged game loads it. The DLL then draws the game's picture on today's machine at the
size you choose" (`wrappers/README.md:5-7`). The workspace has **10 members** —
`glide, shim, ati3dcif, s3dtkw, ddraw, scalers, sgl, pixels, maxi94, ir41`
(`wrappers/Cargo.toml:7`) — built only for `i686-pc-windows-gnu` (`.cargo/config.toml`
wired through `scripts/zcc.sh`, ch.34 §2's linker row), with two profiles: debug keeps
symbols, logs the first 50 calls of each gap; release is LTO-stripped, logs each gap once
(`wrappers/Cargo.toml:15-34`, `wrappers/README.md:78-84`). All come from the POD case
study: "They run its unchanged 3dfx, ATI, S3 and PowerVR builds" (`:30-32`).

The five documented 3D-card DLLs, plus the extras ch.20 §12 counts:

| Member | DLL / role | src L | in-repo tests | Coverage (impl / exported) | Backed by |
|---|---|---:|---|---|---|
| `glide` | `glide2x.dll` — Glide 2.x → OpenGL at any size | 5,673 | 21 | 156 / 156 (`README.md:47`) | `gameframe-voodoo` + `texel` (Cargo `:16-17`) |
| `sgl` | `sgl.dll` — SGL scene graph + immediate → OpenGL | 3,875 | 23 | 61 / 134 (`:48`) | `gameframe-powervr` (Cargo `:15`) |
| `ddraw` | `ddraw.dll` — DirectDraw 1–3, every surface in memory, any mode granted, frame shown scaled | 1,063 | 0 | 2 / 9 (`:51`) | `scalers`, `pixels` |
| `ati3dcif` | `ati3dcif.dll` — ATI Rage faces in software | 230 | 0 | 6 / 17 (`:49`) | `gameframe-rage` (Cargo `:12`) |
| `s3dtkw` | `s3dtkw.dll` — ViRGE S3D Toolkit faces | 243 | 0 | 6 / 6 (`:50`) | `gameframe-virge` (Cargo `:12`) |
| `ir41` | `ir41_32.dll` — Indeo 4.1 Vfw codec shim, same `DriverProc` export | 502 | 4 | n/a | `gameframe-indeo` (Cargo `:13`) |
| `maxi94` | `94DLL32.dll` — Guillemot Maxi Sound 64 → Wine wave outs (audio, no picture) | 693 | 8 | 6 ordinal calls (`maxi94/README.md:8`) | shim only |
| `shim` | shared crate: `WRAPPER_*` settings, Win95 port-I/O emulation via a vectored exception handler, in-memory EXE patches, gap log, call log | 803 | 7 | n/a | — |
| `scalers` | nearest/Scale2x/CRT for `ddraw` (its CRT adds the column mask) | 145 | 4 | n/a | — |
| `pixels` | RGB555/565 → 8-bit, DIB/palette readers for `glide` | 135 | 2 | n/a | — |

**The .def machinery.** Seven `.def` export tables exist — `glide2x.def, sgl.def,
ddraw.def, ir41_32.def, maxi94.def, ati3dcif.def, s3dtkw.def` (verified by `find`) —
matching ch.20 §12's seven; `zcc.sh` links each DLL with its crate's `.def`
(`wrappers/README.md:88-90`). The generator is **`wrappers/stubgen.py`** (133 L): from
each crate's `api.tsv` — "the original library's API table" read from the original DLL's
own code (the `ret N` of each function) or its SDK import library by
`tools/pe/apitable.py` (`wrappers/README.md:53-56`) — it writes the `.def` (with the
rustc-internal export names, `_grDrawLine@8=grDrawLine@8`) and a `src/stubs.rs` line
`shim::stub!` per unimplemented export, "A stub logs its call with its arguments and
returns the `stub` value", failing the build if any call is defined with the wrong
calling convention (`wrappers/stubgen.py:10-26`). So the coverage grades in the table
above are **generated counts over the original library's full export list**: "Each DLL
exports every call the original library exports, so a game that imports any of them
loads" (`wrappers/README.md:40-43`). The CHANGELOG ladder shows the climb: 131/156 Glide
calls at v1.2.0 (`CHANGELOG.md:418`), 156/156 at HEAD (`glide/README.md:7-9`).

**Coverage posture.** `docs/hardware/replacement-libraries.md:1-9` frames the posture:
"A replacement library with the original's file name and exports runs the unchanged game.
It can also draw at a higher resolution, log every call, or serve as the first piece of a
port" — the method is from POD; the game's files and the original DLLs stay outside the
repo, "Only the tables, which hold names and sizes, are here"
(`wrappers/README.md:61-62`). Use under Wine needs
`WINEDLLOVERRIDES="ddraw=n,b;sgl=n;glide=n;glide2x=n"` (`:108-111`) because Wine ships
its own `ddraw.dll`. The shared knobs (`:116-122`): `WRAPPER_WINDOW_CLASS`,
`WRAPPER_MARKER` (the RGB565 `0x0821` "not drawn" colour for 2D-over-3D compositing),
`WRAPPER_PATCHES` (in-memory EXE patches so "the EXE on disk stays unchanged",
`shim/README.md:13-14`), and the log files per DLL.

**The call log** is the verification feature that ties wrappers back to the toolkit.
`WRAPPER_CALLS=FILE` writes "every call the game makes" into Glide/SGL/ATI3DCIF/S3DToolkit,
one line each, in the format `tools/verify/seqdiff.py` compares; pointer arguments are
written as their values, texture/frame-buffer data as size+hash;
`WRAPPER_CALLS_FRAMES=100-102` limits frames (`CHANGELOG.md:21-28`, shipped in
unreleased 1.5.0-dev; `docs/hardware/wrappers.md:155-156`, `:236-260` with a worked
example). Implementation lives in `wrappers/shim/src/calls.rs` — the off path costs "one
atomic load per call" (`:23`), frame windowing at `:40`/`:57` — and the Glide side writes
vertices "as the fields the card reads under the current state (`wrappers/glide/src/used.rs`),
so leftover values in unread fields do not make two logs differ" (`CHANGELOG.md:25-27`);
`lfb_pixels` lines capture CPU-written frame-buffer pixels
(`docs/hardware/wrappers.md:253`, `:273`). Its stated purpose: "It is the game's side of
the seam between the game and its renderer … Record it from the original, write the same
lines from the port's device interface, and compare the two with `tools/verify/seqdiff.py`.
The first line that differs names the call where the port went wrong" (`wrappers.md:238-242`).
Host-side testing is narrow by design: `cargo test --release --target <host>` for
`scalers, pixels, shim, sgl, maxi94` (+`glide` in `tests/run.sh:1908`), plus
"checks each export table against its `.def` file, and runs `python3 wrappers/stubgen.py
--check`" (`wrappers/README.md:93-97`).

## 9. How the artifacts are validated

The ladder of proofs, strongest first, with its concrete witnesses:

| Kind of proof | Where it happens | Witness |
|---|---|---|
| Output bit-identity vs the original program under emulation | crates + case-study projects | indeo: 13,663 pictures vs Intel's codec (`indeo/README.md:13-14`); opl2: sample-for-sample vs Frontier's AdLib driver (`opl2/README.md:17-19`); turbo-pascal: 40k operands / 90k draws (`turbo-pascal/README.md:12-15`); msvc-crt: 200k calls each (`msvc-crt/README.md:26-27`); mmx: 500/500 channels (`mmx/README.md:17-19`) |
| Original program **live** through the artifact | wrappers + POD | "They run its unchanged 3dfx, ATI, S3 and PowerVR builds" (`wrappers/README.md:30-32`); POD's own launchers use `Link`/`Respawn` (`frame/README.md:143`) |
| Reference-implementation parity (external oracle) | wma only | ≥60 dB SNR vs FFmpeg `wmav2`, measured ~130 dB (`wma/README.md:10-12`, `:94-95`) |
| Synthetic golden tests in-repo | 18 tests dirs | disc-image builds its own images (`synthetic.rs:1-2`); game-source a local HTTP server (`README.md:41`); frame a shell-script game (`frame/tests/frame.rs:159`); mmx/texel/scale semantics tables |
| Static traces / datasheets only (deferred comparison) | saa1099, sn76496, opl3, ymz263, adlib-gold, sound-blaster | "remain open" provenance column (`docs/crates/README.md:10-16`); no card ever compared (`voodoo:29`, `powervr:33`, `d3d:31`) |
| Hand-checked | frame-ui, bitmap-font, library browser store | "by hand … browser and on a macOS desktop" (`docs/crates/README.md:34`, `:36`; `library/README.md:89`) |

**Case studies feed back, one direction.** The provenance map
(`docs/crates/README.md:9-36`) is extraction, not consumption: Un-Banished → `wma`,
`msvc-crt`, `frame`; Tyrian 2026 → `turbo-pascal`; Frontier: Elite II → `opl2`; POD → the
graphics cluster plus `indeo`, `disc-image`, `game-source` + all five wrapper DLLs +
`report`; Hardwar → `bitmap-font`, `library`, `report`. The heavy comparisons — 13,663
pictures, 200k calls, 90k draws — are **not reproducible from this repo**: the games, DLLs
and recordings live in the case-study projects by the licensing rule ("Never put the
game's files into this repository", `wrappers/README.md:106-107`), and the crate rule keeps
in-repo tests game-free (`docs/crates/README.md:87-88`).

**And the CI absence again.** The only workflow is `site.yml` (`.github/workflows/` —
verified by `ls`; ch.20 §16): **nothing in CI builds or tests any crate.** The ~240 tests
run when a human or agent runs `tests/run.sh` — `cargo test --release` in `crates/` with a
pass count (`tests/run.sh:1856-1859`), theme-sync checks against `frame-ui::THEMES`
(`:1876`), the host-side wrapper tests plus the export-table and `stubgen --check` audits
(`:1908`, `:1889`). Proven instruments, no pipeline gate — the same position calxgloss's
baseline notes for its verifier (ch.10 "Where the verifier lives").

## 10. vs calxgloss: the output-thesis collision

calxgloss's output thesis and game-frame's artifact layer are close relatives that
refuse each other's core moves. calxgloss translates a Windows PE into a *cross-platform
Rust workspace*; its Windows-API answer is **calxgloss-pal, a mapping database** — per-API
rows with a `rust_equivalent` and a "[PAL placeholder — …]" note
(`crates/integrations/calxgloss-pal/src/data.rs:75-111`, verified) that feeds prompts as
"API MAPPING REFERENCE" but is never compiled or linked. It ships *no* stand-in DLLs, no
chip crates, and principle 1 explicitly buys "observable behavior, not instruction
sequences" (`README.md:11-19`), which puts MSVC last-bit float parity deliberately out of
scope. game-frame ships the exact opposite inventory: **compiled** stand-in DLLs with the
original's file name and decorated exports (`wrappers/README.md:5-7`), and *bit-for-bit*
math crates (`msvc-crt`, `turbo-pascal`, `mmx`) whose whole reason to exist is reproducing
a specific runtime's wrong-in-the-last-bit behavior (`docs/ABI.md:73`).

Neither posture is accidental; each fits its goal. calxgloss's unit of work is a
*function* being moved off x86/Windows for good — so any compiled Windows-shaped shim in
the output would be a failure of the thesis, and PAL-as-database keeps the mapping
advisory, reviewable, and free of a maintenance burden (a suggestion the LLM may ignore;
trace containment judges behavior, ADR-0057). game-frame's unit of work is a *game* that
must keep running, unchanged, *today* — so a compiled shim is the product itself
(`glide2x.dll` runs POD's unchanged 3dfx EXE), and bit-exact math is the price of the
"bit for bit" parity bar (ch.00; the re-port/re-verify loop). The collision point is
identical input (an old Windows binary) with incompatible success criteria: calxgloss
succeeds when the original is no longer needed; game-frame succeeds when the original is
still running — on top of crates that *are* the future port.

**The replacement library as oracle** is the trick calxgloss has no analogue for, and it
inverts the wrapper's role mid-flight. A game-frame wrapper is simultaneously product and
instrument: once `glide2x.dll` stands between the unchanged game and a modern GPU,
`WRAPPER_CALLS` records "every call the game makes" with pointer values resolved and bulk
data hashed (`CHANGELOG.md:21-28`; `wrappers/shim/src/calls.rs`), and that log —
"the game's side of the seam" (`docs/hardware/wrappers.md:238-242`) — becomes the
reference stream the port's device interface must reproduce line-for-line via
`tools/verify/seqdiff.py`. The original binary thus runs as a **live oracle on modern
hardware, without an emulator**, and its call stream becomes golden data. calxgloss
achieves the same "run the original" ground truth the other way: Wine loads the real DLL,
`WineRunner` drives per-function harnesses and captures values plus the ordered API-call
sequence (baseline, "Verification & evidence"). Same move — original-as-oracle — three
differences: granularity (whole-frame render calls vs per-function values), host (a
shimmed process vs Wine), and what is compared (call *streams* diffed by `seqdiff.py` vs
value equality + ordered trace *containment*). Notably game-frame's own wrappers are *not*
bit-exact oracles ("Nothing has been compared with a real card yet", §5) — their oracle
value is exact call capture, and the bit-exactness is supplied on the port side.
calxgloss's Wine baselines carry no such caveat because Wine *is* the Windows-behavior
reference for its purposes.

**The crate-reuse economy** is the last split. calxgloss reuses nothing compiled across
runs: PAL is data, libmatch is a static symbol DB, the output workspace is one-shot per
target; every pipeline rebuilds everything. game-frame's artifact layer is an economy in
the literal sense — intra-workspace edges (six wrappers consuming five emulation crates
by `path = "../../crates/…"`, e.g. `wrappers/ir41/Cargo.toml:13`), git-dependency
distribution to third-party ports (`docs/crates/README.md:58-61`), and a documented
admission bar for adding to the shelf (`:81-93`) with a buyer-beware re-check contract
(`:69-79`). calxgloss's analogue — accumulate *evidence*, not binaries — is cheaper to
keep honest (data is reviewable; a compiled chip model can silently disagree with your
game, which is exactly why game-frame's own README tells you to re-measure it per game
before use). A calxgloss that adopted game-frame's crates would import last-bit MSVC
fidelity it has sworn off; a game-frame that adopted calxgloss's PAL-as-data would lose
the one thing that makes its unchanged-game story work: a DLL the game's import table can
actually find.

## Sources

game-frame clone at `f195a074`, all opened at the cited lines:
`crates/Cargo.toml:1-12` · `docs/crates/README.md:1-93` (provenance table :7-36, rules
:81-93, check-first doctrine :69-79, git-dep usage :55-61) · per-crate
`README.md` + `Cargo.toml` for all 28 crates (cited inline in §2–§7; README line
references from `crates/<c>/README.md`) · per-crate tests: 18 `tests/` dirs, 19 test
files, names in §2 · `crates/frame/src/{game,event,manifest,session,link,respawn,configured}.rs`
anchors · `crates/report/src/lib.rs:122-138,244,259` · `crates/frame-ui/src/themes.rs:7` ·
`crates/turbo-pascal/tests/runtime.rs:1-2` · `crates/disc-image/tests/synthetic.rs:1-2` ·
`crates/frame/tests/frame.rs:159,222,286` · `crates/wma/THIRD_PARTY.md:1-5` ·
`wrappers/README.md:1-131` · `wrappers/Cargo.toml:1-34` · `wrappers/stubgen.py:1-27` ·
`wrappers/shim/src/calls.rs:2,17,23,40,53,57` · `wrappers/{glide,sgl,ddraw,ir41,maxi94,shim,scalers,pixels}/README.md`
· `wrappers/{glide,sgl,ati3dcif,s3dtkw,ir41}/Cargo.toml` path deps · 7 `.def` files
(verified by `find wrappers -name '*.def'`) · `CHANGELOG.md:21-28` (call log, 1.5.0-dev),
`:418` (Glide 131/156 at 1.2.0) · `docs/hardware/wrappers.md:150-160,236-260,273` ·
`docs/hardware/replacement-libraries.md:1-40` · `docs/ABI.md:73` ·
`docs/case-studies/README.md:1-20` · `tests/run.sh:1856-1859,1876,1908` ·
`.github/workflows/` (only `site.yml`, verified by `ls`). Counts:
`find crates/<c>/src -name '*.rs' -exec cat {} + | wc -l` per crate (src-only totals:
40,455; per-crate in §2); `grep -c '#\[test\]'` per crate for test counts; same find/cat
method for `wrappers/*/src` (13,362 src L).
calxgloss side at HEAD `40fbf91f`: `crates/integrations/calxgloss-pal/src/data.rs:75-111`
(PAL placeholder rows, verified) · `README.md:11-19` (principle 1) ·
ch.10-calxgloss-baseline.md "Naming & typing" §3, "Verification & evidence", and the
"Wine instead of wrapper" anchors. Cross-references: ch.20 §11–12 (counts, folded-in
README LOC), ch.34 §2 (zcc.sh row), ch.34 §5 (launcher), ch.33 (seqdiff/seq tools),
ch.21 (release ladder).
