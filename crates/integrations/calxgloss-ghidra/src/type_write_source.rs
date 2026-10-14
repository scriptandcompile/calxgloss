//! The write-side seam for pushing types back into a Ghidra program.
//!
//! [`ScanSource`](crate::ScanSource) is the read-only sibling: everything an
//! evidence engine pulls *out* of Ghidra. This trait is what calxgloss puts
//! *in* — the v6.0.0 bridge's type-writing endpoints, the capability
//! ADR-0001 chose that bridge for: setting a function's prototype, setting
//! the type of one of a function's variables, and creating the named types
//! an inferred type refers to but the Type Manager does not hold yet
//! (structure, enumeration, typedef, structure field).
//!
//! Deliberately absent:
//!
//! * **A cached implementation.** The read cache never wraps writes —
//!   writes are never cached, following the `add_function_tag` precedent —
//!   so only [`GhidraClient`] implements this trait. A write-back pass is
//!   handed the raw client, and every write reaches the server.
//! * **Renaming, comments, tags, globals** — the bridge has endpoints for
//!   those too; this seam covers only what type write-back needs.
//!
//! Endpoint naming follows the bridge's v6.0.0 spelling recorded in
//! `docs/ghidra_endpoint_map.md`: the dev-branch docs' `set_variable_type`
//! is `set_local_variable_type` here, and both setters address the function
//! by address — the bridge parses that parameter as an address and refuses
//! a name.

use crate::client::{GhidraClient, Result};

/// One field of a structure to be created, as `create_struct` takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewStructField<'a> {
    /// The field's name in the Type Manager.
    pub name: &'a str,
    /// The field's type — any data type Ghidra can resolve, including a
    /// named type created earlier in the same pass.
    pub type_name: &'a str,
    /// The byte offset to place the field at; `None` lets Ghidra append it.
    pub offset: Option<u32>,
}

impl<'a> NewStructField<'a> {
    /// A field Ghidra appends at the end of the structure.
    pub fn new(name: &'a str, type_name: &'a str) -> Self {
        Self {
            name,
            type_name,
            offset: None,
        }
    }

    /// Place the field at that byte offset instead of appending it.
    pub fn at_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }
}

/// The type-writing operations the v6.0.0 bridge offers, the write-side
/// sibling of [`ScanSource`](crate::ScanSource).
///
/// [`GhidraClient`] implements it over the live HTTP API — and it is the
/// only implementer: the read cache deliberately never wraps writes, so a
/// type-write pass is handed the raw client and every write reaches the
/// server. The futures are `Send` so a write-back pass can be driven from
/// an orchestrating task.
pub trait TypeWriteSource {
    /// Set the full prototype — return type and parameter types — of the
    /// function at `function_address`.
    ///
    /// The name inside the prototype text does not rename the function: the
    /// bridge parses the signature and applies it at the address. A calling
    /// convention spelled inside the prototype text is honoured; the
    /// function's plate comment survives the change.
    fn set_function_prototype(
        &self,
        function_address: u64,
        prototype: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Set the type of the variable (local or parameter) named `variable`
    /// in the function at `function_address`.
    ///
    /// The bridge refuses an `undefined*` target — the write must name a
    /// concrete type — and a miss on `variable` answers with the names it
    /// *does* know, which the error message carries.
    fn set_local_variable_type(
        &self,
        function_address: u64,
        variable: &str,
        type_name: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Create a new structure named `name` with `fields`.
    ///
    /// Every field type must already resolve in the Type Manager — create
    /// the named types a layout refers to before the layout that uses them
    /// — and a same-named type already in the manager is an error, not a
    /// silent replace.
    fn create_struct(
        &self,
        name: &str,
        fields: &[NewStructField<'_>],
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Create a new enumeration named `name`, `size` bytes wide (1, 2, 4,
    /// or 8), whose members are `values` (member name → value).
    fn create_enum(
        &self,
        name: &str,
        values: &[(&str, i64)],
        size: u32,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Create a typedef `name` as an alias for `base_type` — any type
    /// Ghidra can resolve, pointer spellings (`char *`) included.
    fn create_typedef(
        &self,
        name: &str,
        base_type: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Add one field to the existing structure `struct_name`.
    ///
    /// `offset` of `Some` places the field at that byte offset (growing the
    /// structure to fit); `None` appends it at the end.
    fn add_struct_field(
        &self,
        struct_name: &str,
        field_name: &str,
        field_type: &str,
        offset: Option<u32>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

impl TypeWriteSource for GhidraClient {
    // The trait's `Result` is the client's own, so each method delegates
    // straight through; the inherent methods win over the trait's in method
    // resolution, exactly as with `ScanSource`.
    async fn set_function_prototype(&self, function_address: u64, prototype: &str) -> Result<()> {
        self.set_function_prototype(function_address, prototype)
            .await
    }

    async fn set_local_variable_type(
        &self,
        function_address: u64,
        variable: &str,
        type_name: &str,
    ) -> Result<()> {
        self.set_local_variable_type(function_address, variable, type_name)
            .await
    }

    async fn create_struct(&self, name: &str, fields: &[NewStructField<'_>]) -> Result<()> {
        self.create_struct(name, fields).await
    }

    async fn create_enum(&self, name: &str, values: &[(&str, i64)], size: u32) -> Result<()> {
        self.create_enum(name, values, size).await
    }

    async fn create_typedef(&self, name: &str, base_type: &str) -> Result<()> {
        self.create_typedef(name, base_type).await
    }

    async fn add_struct_field(
        &self,
        struct_name: &str,
        field_name: &str,
        field_type: &str,
        offset: Option<u32>,
    ) -> Result<()> {
        self.add_struct_field(struct_name, field_name, field_type, offset)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CachedGhidraSource;

    /// The read cache must never grow a write impl — writes belong to the
    /// raw client so every one reaches the server (the function-tag
    /// precedent). These two impls are the tripwire: the moment anyone
    /// writes `impl TypeWriteSource for CachedGhidraSource`, the blanket
    /// impl and the concrete one collide (E0119) and the crate stops
    /// compiling. Negative reasoning is only available inside the crate
    /// that defines the trait, which is why the guard lives here rather
    /// than in the integration tests.
    trait WriteSourceProbe {}

    struct Probe<T>(std::marker::PhantomData<T>);

    impl<T: TypeWriteSource> WriteSourceProbe for Probe<T> {}

    impl WriteSourceProbe for Probe<CachedGhidraSource> {}

    #[test]
    fn the_cache_never_implements_the_write_trait() {
        // The tripwire is the impls above; this call names the contract
        // for whoever reads the compile failure.
        fn assert_probe<T: WriteSourceProbe>() {}
        assert_probe::<Probe<CachedGhidraSource>>();
    }
}
