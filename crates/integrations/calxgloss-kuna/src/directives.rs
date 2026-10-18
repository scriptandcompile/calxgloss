//! The calxgloss-owned directive plane for one target binary (issue #209).
//!
//! Kuna has no persistent program — it "never writes back into the image" —
//! so under `engine = kuna` a type write-back does not mutate a saved
//! project: it appends a fact to a directive file calxgloss owns, in Kuna's
//! own `--assert` line syntax, and every load replays that file through the
//! engine's assertion plane (ADR-0039's state model). The file is the
//! durable form; the in-memory [`DirectivePlane`] is its ordered mirror.
//!
//! Each [`TypeWriteSource`](calxgloss_ghidra::TypeWriteSource) call compiles
//! to exactly one directive through the pure `*_directive` compilers here —
//! golden-testable without a loaded program:
//!
//! * `set_function_prototype` → `prototype 0x<addr> <C declaration>` — the
//!   address form, because a PE import thunk and its IAT slot share a name
//!   and only the address picks the executable one.
//! * `set_local_variable_type` → `type <func>::<var> <C type>` — qualified
//!   with the function's canonical name, because an unqualified symbol
//!   means "the function under decompile" and is rejected on a whole-binary
//!   run.
//! * `create_struct` / `create_enum` / `create_typedef` → `typedef <C
//!   declaration>` — the C declaration the engine's own parser interns.
//! * `add_struct_field` → regenerate the owning `typedef struct` record:
//!   Kuna refuses to re-body an existing record, and calxgloss owns the
//!   directive set, so replacing the record in place is the honest form.
//!   The regenerated record takes effect on the next load.
//!
//! The plane keeps records in write order (a declaration's dependencies
//! precede it), replaces a struct's record in place on regeneration so that
//! order survives, and saves atomically so a torn file can never poison the
//! next load.

use std::path::{Path, PathBuf};

use kuna_console::assertions::{Body, Directive};
use kuna_console::assertsyntax::parse_directive;

use crate::error::{KunaError, Result};

/// One field of a structure to be created, as the Kuna write seam takes it.
///
/// The directive plane lays fields out in the order given — the C
/// declaration it compiles to carries no explicit offsets — so `offset` is
/// carried for shape parity with the seam and never rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KunaNewField<'a> {
    /// The field's name in the type.
    pub name: &'a str,
    /// The field's type — any C type the engine's parser can resolve,
    /// including a named type declared by an earlier directive.
    pub type_name: &'a str,
    /// Not rendered: the directive plane lays out naturally.
    pub offset: Option<u32>,
}

impl<'a> KunaNewField<'a> {
    /// A field laid out in the order given.
    pub fn new(name: &'a str, type_name: &'a str) -> Self {
        Self {
            name,
            type_name,
            offset: None,
        }
    }
}

/// The directive file a target's write-backs persist to, under the record
/// of effort: `{workspace}/re/kuna/{binary}.kuna` (spec #203's state model).
pub fn directive_file_path(workspace: &Path, target: &Path) -> PathBuf {
    let binary = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "target".to_string());
    workspace
        .join("re")
        .join("kuna")
        .join(format!("{binary}.kuna"))
}

/// The header every calxgloss directive file opens with, so a human reading
/// the file knows what replays it and a hand-edit follows the same shape.
const FILE_HEADER: &str = "\
# calxgloss directive plane — one directive per line in Kuna --assert syntax.
# Replayed on every Kuna load of this target; a # begins a comment.";

// ============================================================
// The compilers: one write-seam call, one directive
// ============================================================

/// `set_function_prototype` → `prototype 0x<addr> <C declaration>`.
///
/// The address form is deliberate: Kuna canonicalizes a name to its entry
/// address anyway, and the address reaches the executable function where a
/// PE import thunk and its IAT slot share one name. A trailing `;` on the
/// prototype text is trimmed — the directive grammar wants the bare
/// declaration.
pub fn prototype_directive(address: u64, prototype: &str) -> Directive {
    let func = format!("0x{address:x}");
    let decl = prototype
        .trim()
        .trim_end_matches(';')
        .trim_end()
        .to_string();
    Directive {
        raw: format!("prototype {func} {decl}"),
        body: Body::Prototype { func, decl },
    }
}

/// `set_local_variable_type` → `type <func>::<var> <C type>`.
///
/// `function` must be the loaded program's canonical name for the target —
/// the directive binds by exact name, and an unqualified directive is
/// rejected on anything but a one-function decompile.
pub fn local_type_directive(function: &str, variable: &str, type_name: &str) -> Directive {
    Directive {
        raw: format!("type {function}::{variable} {type_name}"),
        body: Body::Type {
            func: Some(function.to_string()),
            symbol: variable.to_string(),
            decl: type_name.to_string(),
        },
    }
}

/// `create_struct` → `typedef struct <name> { <type> <name>; ... };`.
///
/// Fields keep the order they were given; an explicit offset is not
/// representable in the C declaration and is not rendered.
pub fn struct_directive(name: &str, fields: &[KunaNewField<'_>]) -> Directive {
    let rendered: Vec<(&str, &str)> = fields
        .iter()
        .map(|field| (field.type_name, field.name))
        .collect();
    struct_record_directive(name, &rendered)
}

/// The regenerated form of a struct record: the same `typedef struct`
/// declaration compiled from `(type, name)` pairs, which is what
/// `add_struct_field` re-bodies the owning record with.
pub fn struct_record_directive(name: &str, fields: &[(&str, &str)]) -> Directive {
    let body = fields
        .iter()
        .map(|(type_name, field_name)| format!("{type_name} {field_name};"))
        .collect::<Vec<_>>()
        .join(" ");
    let decl = format!("struct {name} {{ {body} }};");
    Directive {
        raw: format!("typedef {decl}"),
        body: Body::Typedef { decl },
    }
}

/// `create_enum` → `typedef enum <name> : <underlying> { A = 1, B = -3 };`.
///
/// The trait's `size` becomes the enum's C23 fixed underlying type — Kuna
/// otherwise sizes an enum by its values, and the seam promises a specific
/// width. A signed underlying type is chosen when any member is negative,
/// so the members survive the parse exactly as given.
pub fn enum_directive(name: &str, values: &[(&str, i64)], size: u32) -> Directive {
    let signed = values.iter().any(|(_, value)| *value < 0);
    let underlying = enum_underlying(size, signed);
    let members = values
        .iter()
        .map(|(member, value)| format!("{member} = {value}"))
        .collect::<Vec<_>>()
        .join(", ");
    let decl = format!("enum {name} : {underlying} {{ {members} }};");
    Directive {
        raw: format!("typedef {decl}"),
        body: Body::Typedef { decl },
    }
}

/// The C spelling of the enum width the seam asks for (1, 2, 4, or 8
/// bytes; anything else rounds up to the next spelled width).
fn enum_underlying(size: u32, signed: bool) -> &'static str {
    match (size, signed) {
        (0 | 1, false) => "unsigned char",
        (0 | 1, true) => "signed char",
        (2, false) => "unsigned short",
        (2, true) => "signed short",
        (3 | 4, false) => "unsigned int",
        (3 | 4, true) => "signed int",
        (_, false) => "unsigned long long",
        (_, true) => "signed long long",
    }
}

/// `create_typedef` → `typedef <base_type> <name>;`.
pub fn typedef_directive(name: &str, base_type: &str) -> Directive {
    let decl = format!("typedef {base_type} {name};");
    Directive {
        raw: format!("typedef {decl}"),
        body: Body::Typedef { decl },
    }
}

// ============================================================
// Reading calxgloss's own struct records back
// ============================================================

/// The structure name a `typedef struct <name> { ... };` record declares,
/// or `None` for any other record — anonymous structs included.
fn declared_struct_name(decl: &str) -> Option<&str> {
    let rest = decl.trim().strip_prefix("struct")?.trim_start();
    let name_end = rest.find(['{', ' ']).unwrap_or(rest.len());
    let name = rest[..name_end].trim();
    (!name.is_empty() && rest[name_end..].trim_start().starts_with('{')).then_some(name)
}

/// The `(type, name)` pairs a calxgloss struct record declares, read back
/// from the record's own text — calxgloss composed the shape, so parsing it
/// is parsing its own output, not general C. `None` when the record is not
/// that shape: a bitfield (`unsigned int a : 3`) or any spelling the
/// regeneration cannot re-render honestly.
fn struct_record_fields(decl: &str) -> Option<Vec<(&str, &str)>> {
    let open = decl.find('{')?;
    let close = decl.rfind('}')?;
    if close < open {
        return None;
    }
    let mut fields = Vec::new();
    for entry in decl[open + 1..close].split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if entry.contains(':') {
            return None;
        }
        let (type_name, name) = entry.rsplit_once(char::is_whitespace)?;
        fields.push((type_name.trim(), name.trim()));
    }
    Some(fields)
}

// ============================================================
// The plane: the ordered directive set and its file
// ============================================================

/// What became of one directive the source carries — the engine's own
/// per-directive [`Outcome`](kuna_console::assertions::Outcome) lifted to a
/// plain record: `status` is `applied` or `rejected`, and a directive not
/// yet reached by an apply or a decompile reports as rejected with the
/// detail `not reached by this run` — a local-type directive waits on the
/// decompile of its function, and a regenerated struct record waits for
/// the next load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectiveOutcome {
    /// The directive's text, as it stands in the file.
    pub directive: String,
    /// What became of it: `applied` or `rejected`; a directive not yet
    /// reached reports as rejected with the detail `not reached by this
    /// run`.
    pub status: String,
    /// Why it was rejected, when it was.
    pub detail: Option<String>,
}

/// The ordered directive set for one target binary, mirrored on a file in
/// the record of effort.
///
/// The set is append-ordered — a declaration always sits after the
/// declarations it references — and [`replace_struct_record`](Self::replace_struct_record)
/// swaps a record in place so that order survives a regeneration. A plane
/// opened without a file still answers every write; it just persists
/// nowhere.
#[derive(Debug)]
pub struct DirectivePlane {
    file: Option<PathBuf>,
    directives: Vec<Directive>,
}

impl DirectivePlane {
    /// An empty plane that persists nowhere.
    pub fn in_memory() -> Self {
        Self {
            file: None,
            directives: Vec::new(),
        }
    }

    /// Open `file` as the plane, replaying its directives into the set.
    ///
    /// A missing file is an empty plane at that path — the first write
    /// creates it. A line the directive grammar refuses is a named
    /// [`KunaError::DirectiveFileInvalid`] naming the path and line: a
    /// half-understood directive file must never load as a quiet partial
    /// replay.
    pub fn open(file: &Path) -> Result<Self> {
        let mut directives = Vec::new();
        if file.is_file() {
            let text = std::fs::read_to_string(file).map_err(|source| KunaError::Io {
                path: file.display().to_string(),
                reason: source.to_string(),
            })?;
            for (number, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let directive =
                    parse_directive(line).map_err(|reason| KunaError::DirectiveFileInvalid {
                        path: file.display().to_string(),
                        line: number + 1,
                        reason,
                    })?;
                directives.push(directive);
            }
        }
        Ok(Self {
            file: Some(file.to_path_buf()),
            directives,
        })
    }

    /// The directives, in write order.
    pub fn directives(&self) -> &[Directive] {
        &self.directives
    }

    /// The file the plane persists to, when it persists anywhere.
    pub fn file(&self) -> Option<&Path> {
        self.file.as_deref()
    }

    /// Append one directive, returning its index in the set — the slot
    /// whose outcome an apply reports.
    pub fn push(&mut self, directive: Directive) -> usize {
        self.directives.push(directive);
        self.directives.len() - 1
    }

    /// Remove the last directive — the rollback of a push whose apply the
    /// engine refused.
    pub fn pop(&mut self) -> Option<Directive> {
        self.directives.pop()
    }

    /// The index and `(type, name)` fields of the last struct record
    /// declaring `name`, when the plane holds one it can honestly
    /// regenerate. A record the field reader refuses (a bitfield spelling)
    /// answers `None` with the index in hand, so the caller can name the
    /// conflict rather than corrupt the record.
    pub fn struct_record(&self, name: &str) -> Option<(usize, Vec<(&str, &str)>)> {
        let index = self.directives.iter().rposition(|directive| {
            matches!(&directive.body, Body::Typedef { decl } if declared_struct_name(decl) == Some(name))
        })?;
        let decl = match &self.directives[index].body {
            Body::Typedef { decl } => decl.as_str(),
            _ => return None,
        };
        struct_record_fields(decl).map(|fields| (index, fields))
    }

    /// The index of the last struct record declaring `name`, even one whose
    /// fields cannot be read back — so a bitfield-bearing record reports a
    /// named conflict instead of being skipped.
    pub fn struct_record_index(&self, name: &str) -> Option<usize> {
        self.directives.iter().rposition(|directive| {
            matches!(&directive.body, Body::Typedef { decl } if declared_struct_name(decl) == Some(name))
        })
    }

    /// Swap the record at `index` for a regenerated one, keeping its place
    /// in the write order.
    pub fn replace(&mut self, index: usize, directive: Directive) {
        self.directives[index] = directive;
    }

    /// Write the plane back to its file — header, then one directive per
    /// line — atomically: a temp file beside the target renamed onto it, so
    /// a failed save can never leave a half-written directive file where a
    /// replayable one used to be.
    pub fn save(&self) -> Result<()> {
        let Some(file) = &self.file else {
            return Ok(());
        };
        let mut text = String::from(FILE_HEADER);
        for directive in &self.directives {
            text.push('\n');
            text.push_str(&directive.raw);
            text.push('\n');
        }
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent).map_err(|source| KunaError::Io {
                path: parent.display().to_string(),
                reason: source.to_string(),
            })?;
        }
        let tmp = file.with_extension("kuna.tmp");
        let written = (|| -> std::io::Result<()> {
            std::fs::write(&tmp, &text)?;
            std::fs::rename(&tmp, file)
        })();
        if let Err(source) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(KunaError::Io {
                path: file.display().to_string(),
                reason: source.to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_decl(directive: &Directive) -> &str {
        match &directive.body {
            Body::Typedef { decl } => decl,
            other => panic!("expected a typedef body, got {other:?}"),
        }
    }

    #[test]
    fn a_prototype_call_compiles_to_the_address_form_directive() {
        let directive = prototype_directive(0x1400_01000, "int fixture_tick(int count);");
        assert_eq!(
            directive.raw,
            "prototype 0x140001000 int fixture_tick(int count)"
        );
        assert_eq!(
            directive.body,
            Body::Prototype {
                func: "0x140001000".to_string(),
                decl: "int fixture_tick(int count)".to_string(),
            }
        );
    }

    #[test]
    fn a_local_variable_type_call_compiles_to_a_qualified_type_directive() {
        let directive = local_type_directive("fixture_status", "param_1", "COLOR");
        assert_eq!(directive.raw, "type fixture_status::param_1 COLOR");
        assert_eq!(
            directive.body,
            Body::Type {
                func: Some("fixture_status".to_string()),
                symbol: "param_1".to_string(),
                decl: "COLOR".to_string(),
            }
        );
    }

    #[test]
    fn a_struct_creation_compiles_to_a_typedef_plane_struct_declaration() {
        let fields = [KunaNewField::new("x", "int"), KunaNewField::new("y", "int")];
        let directive = struct_directive("tagPOINT", &fields);
        assert_eq!(directive.raw, "typedef struct tagPOINT { int x; int y; };");
        assert_eq!(body_decl(&directive), "struct tagPOINT { int x; int y; };");
    }

    #[test]
    fn an_enum_creation_compiles_to_a_fixed_underlying_type_declaration() {
        let values = [("RED", 1), ("GREEN", 2), ("BLUE", -3)];
        let unsigned = enum_directive("COLOR", &[("RED", 1), ("GREEN", 2)], 2);
        assert_eq!(
            unsigned.raw,
            "typedef enum COLOR : unsigned short { RED = 1, GREEN = 2 };"
        );
        let signed = enum_directive("COLOR", &values, 4);
        assert_eq!(
            signed.raw,
            "typedef enum COLOR : signed int { RED = 1, GREEN = 2, BLUE = -3 };"
        );
    }

    #[test]
    fn a_typedef_call_compiles_to_a_typedef_plane_declaration() {
        let directive = typedef_directive("ULONG", "unsigned long");
        // The doubled keyword is the grammar, not a slip: the directive
        // keyword is `typedef`, and its argument must be a C declaration
        // that itself spells the typedef — a bare `unsigned long ULONG;`
        // would parse as a variable.
        assert_eq!(directive.raw, "typedef typedef unsigned long ULONG;");
        assert_eq!(body_decl(&directive), "typedef unsigned long ULONG;");
    }

    #[test]
    fn every_compiled_directive_survives_the_file_text_round_trip() {
        let cases = [
            prototype_directive(0x180001000, "unsigned int fixture_tick(void)"),
            local_type_directive("fixture_status", "param_1", "COLOR"),
            struct_directive(
                "tagPOINT",
                &[KunaNewField::new("x", "int"), KunaNewField::new("y", "int")],
            ),
            enum_directive("COLOR", &[("RED", 1), ("BLUE", -3)], 4),
            typedef_directive("ULONG", "unsigned long"),
        ];
        for directive in cases {
            let reparsed =
                parse_directive(&directive.raw).expect("the compiled text must parse back");
            assert_eq!(reparsed, directive, "round trip broke {}", directive.raw);
        }
    }

    #[test]
    fn a_struct_record_reads_its_own_fields_back() {
        let directive = struct_directive(
            "tagPOINT",
            &[
                KunaNewField::new("x", "int"),
                KunaNewField::new("y", "POINT *"),
            ],
        );
        assert_eq!(
            declared_struct_name(body_decl(&directive)),
            Some("tagPOINT")
        );
        assert_eq!(
            struct_record_fields(body_decl(&directive)).expect("fields should read back"),
            vec![("int", "x"), ("POINT *", "y")]
        );
    }

    #[test]
    fn a_bitfield_record_refuses_to_read_back() {
        let decl = "struct BITS { unsigned int a : 3; unsigned int b : 5; };";
        assert_eq!(declared_struct_name(decl), Some("BITS"));
        assert!(struct_record_fields(decl).is_none());
    }

    #[test]
    fn non_struct_records_are_not_owners() {
        assert_eq!(declared_struct_name("typedef unsigned long ULONG;"), None);
        assert_eq!(
            declared_struct_name("enum COLOR : unsigned int { RED = 1 };"),
            None
        );
        assert_eq!(declared_struct_name("struct { int x; };"), None);
    }

    #[test]
    fn the_plane_replays_a_file_and_replaces_a_struct_record_in_place() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("target.dll.kuna");
        std::fs::write(
            &file,
            "# header\n\ntypedef struct tagPOINT { int x; int y; };\nprototype 0x180001000 int f(void)\n",
        )
        .expect("seed file should write");

        let mut plane = DirectivePlane::open(&file).expect("the plane should open");
        assert_eq!(plane.directives().len(), 2);

        let index = plane
            .struct_record("tagPOINT")
            .expect("the struct record is owned")
            .0;
        let fields = vec![("int", "x"), ("int", "y"), ("int", "z")];
        plane.replace(index, struct_record_directive("tagPOINT", &fields));
        plane.save().expect("the plane should save");

        let text = std::fs::read_to_string(&file).expect("the file should read back");
        assert_eq!(
            text.lines()
                .filter(|line| line.contains("tagPOINT"))
                .count(),
            1
        );
        assert!(text.contains("typedef struct tagPOINT { int x; int y; int z; };"));
        assert!(text.contains("prototype 0x180001000 int f(void)"));
    }

    #[test]
    fn a_missing_directive_file_is_an_empty_plane_at_that_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let plane = DirectivePlane::open(&dir.path().join("absent.kuna")).expect("absent is empty");
        assert!(plane.directives().is_empty());
        assert_eq!(plane.file(), Some(dir.path().join("absent.kuna").as_path()));
    }

    #[test]
    fn a_line_the_grammar_refuses_names_the_file_and_line() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("broken.kuna");
        std::fs::write(&file, "# fine\ntypedef\n").expect("seed file should write");
        let error = DirectivePlane::open(&file).expect_err("a bare keyword must not load");
        assert!(
            matches!(&error, KunaError::DirectiveFileInvalid { line, .. } if *line == 2),
            "the named failure should point at line 2: {error}"
        );
    }

    #[test]
    fn the_directive_file_path_follows_the_record_of_effort_convention() {
        assert_eq!(
            directive_file_path(Path::new("/ws"), Path::new("/targets/eqmain.dll")),
            PathBuf::from("/ws/re/kuna/eqmain.dll.kuna")
        );
    }
}
