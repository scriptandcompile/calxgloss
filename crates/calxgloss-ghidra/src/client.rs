//! The [`GhidraConfig`] and [`GhidraClient`] — connection settings and HTTP API client.

use crate::error;
use crate::error::Classification;
use crate::model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, FunctionBody, FunctionReport,
    FunctionSummary, OpenProgram, Segment, StringLiteral, StructLayout, Symbol, Xref,
};
use crate::parse;
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, info, instrument, trace, warn};
use url::Url;

/// Result of a GhidraMCP operation.
pub type Result<T> = std::result::Result<T, GhidraError>;

/// Page size used when the client collects a paged endpoint in full.
///
/// The server defaults to 100 per page, which means hundreds of round trips
/// for a large binary's listings; a larger page trades one bigger response
/// for far fewer requests.
const DATA_PAGE: usize = 1000;

// ============================================================
// Error types
// ============================================================

/// Errors from talking to GhidraMCP.
#[derive(Debug, thiserror::Error)]
pub enum GhidraError {
    /// The request could not be delivered, or its body could not be read.
    ///
    /// The hint matters because the GhidraMCP bridge only serves requests while
    /// a CodeBrowser is open, so a refused connection usually means a closed
    /// window rather than a broken server.
    #[error(
        "Could not reach GhidraMCP at {url}: {source}\nGhidra must be running with the \
            GhidraMCP extension loaded and a program open in a CodeBrowser"
    )]
    Transport { url: String, source: reqwest::Error },

    /// The server answered, and its answer was an explanation rather than a
    /// result.
    ///
    /// `status` is the HTTP status. Most failures arrive as `200` with the
    /// explanation in the body, so this is `Some(200)` far more often than a
    /// real transport-level status.
    #[error("Ghidra reported an error: {message}")]
    Reported {
        status: Option<u16>,
        message: String,
    },

    /// Nothing in the open program matched the request.
    #[error("Ghidra has no {kind} matching '{query}'")]
    NotFound { kind: &'static str, query: String },

    /// A response was a result but did not have the shape the endpoint promises.
    #[error("Could not read {kind} from Ghidra's response: {detail}")]
    Malformed { kind: &'static str, detail: String },

    /// The configured base URL could not be parsed.
    #[error("Server URL is invalid: {0}")]
    InvalidUrl(#[from] url::ParseError),
}

// ============================================================
// Configuration
// ============================================================

/// Connection settings for a GhidraMCP server.
#[derive(Debug, Clone)]
pub struct GhidraConfig {
    /// Base URL of the GhidraMCP bridge, e.g. `http://127.0.0.1:8080`.
    pub base_url: Url,

    /// How long to wait for a response.
    ///
    /// Decompiling a large function is slow inside Ghidra, so this is generous
    /// relative to a normal HTTP call.
    pub timeout: Duration,

    /// Optional bearer token, for a server behind a proxy.
    pub api_key: Option<String>,
}

impl GhidraConfig {
    /// Default configuration for a base URL.
    ///
    /// # Errors
    ///
    /// Returns [`GhidraError::InvalidUrl`] if `base_url` is not a valid URL.
    pub fn new(base_url: &str) -> std::result::Result<Self, GhidraError> {
        Ok(Self {
            base_url: Url::parse(base_url)?,
            timeout: Duration::from_secs(120),
            api_key: None,
        })
    }

    /// Override the request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send a bearer token with every request.
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }
}

// ============================================================
// Client
// ============================================================

/// A client for the GhidraMCP API.
///
/// Every query runs against the program currently open in Ghidra, so a client
/// is valid for as long as that program is. The 6.x bridge can hold several
/// programs at once; [`switch_program`](Self::switch_program) moves which one
/// queries run against, and opening a different program by hand changes what
/// these methods return without the client noticing.
#[derive(Debug, Clone)]
pub struct GhidraClient {
    config: GhidraConfig,
    http: Client,
}

impl GhidraClient {
    // =========================================================
    // Construction
    // =========================================================

    /// Create a client with default settings.
    pub fn new(base_url: &str) -> std::result::Result<Self, GhidraError> {
        Self::from_config(GhidraConfig::new(base_url)?)
    }

    /// Create a client from explicit settings.
    pub fn from_config(config: GhidraConfig) -> std::result::Result<Self, GhidraError> {
        let http = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|source| GhidraError::Transport {
                url: config.base_url.to_string(),
                source,
            })?;
        info!(base_url = %config.base_url, "Created GhidraClient");
        Ok(Self { config, http })
    }

    /// The base URL of the server.
    pub fn base_url(&self) -> &Url {
        &self.config.base_url
    }

    // =========================================================
    // Transport
    // =========================================================

    /// Issue a GET and return the body, having established that it is a result.
    ///
    /// This is the single point where server errors become client errors, so
    /// every other method can assume it received content.
    async fn get_text(&self, endpoint: &str, params: &[(&str, String)]) -> Result<String> {
        let mut url = self.config.base_url.join(endpoint)?;
        // The query string is only touched when there is one to add. Merely
        // calling `query_pairs_mut` appends a bare `?`, and Ghidra rejects a
        // request path carrying one as an unknown context.
        if !params.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in params {
                pairs.append_pair(k, v);
            }
        }

        trace!(%url, endpoint, "GET");
        let mut request = self.http.get(url.clone());
        if let Some(ref key) = self.config.api_key {
            request = request.bearer_auth(key);
        }
        self.deliver(request, &url).await
    }

    /// Issue a POST with a JSON body and return the body, having established
    /// that it is a result.
    ///
    /// The write endpoints answer `{"status":"success",...}` on success and
    /// `{"error":"..."}` on failure; the failure shape goes through
    /// [`error::classify`] like every other response.
    async fn post_json(&self, endpoint: &str, payload: &serde_json::Value) -> Result<String> {
        let url = self.config.base_url.join(endpoint)?;
        trace!(%url, endpoint, "POST");
        let mut request = self.http.post(url.clone()).json(payload);
        if let Some(ref key) = self.config.api_key {
            request = request.bearer_auth(key);
        }
        self.deliver(request, &url).await
    }

    /// Send a built request and establish that its body is a result.
    async fn deliver(&self, request: reqwest::RequestBuilder, url: &Url) -> Result<String> {
        let send = |source: reqwest::Error| GhidraError::Transport {
            url: url.to_string(),
            source,
        };
        let response = request.send().await.map_err(send)?;
        let status = response.status();
        let body = response.text().await.map_err(send)?;
        trace!(%status, bytes = body.len(), "GOT");

        // The 6.x bridge answers an unknown endpoint with a real 404 and an
        // HTML body, which no content parser would recognise.
        if !status.is_success() {
            return Err(GhidraError::Reported {
                status: Some(status.as_u16()),
                message: Self::describe_error_body(&body),
            });
        }

        match error::classify(&body) {
            Classification::Content => Ok(body),
            Classification::Failure(message) => Err(GhidraError::Reported {
                status: Some(status.as_u16()),
                message: message.to_string(),
            }),
            Classification::FailureWithStatus(code, message) => Err(GhidraError::Reported {
                status: Some(code),
                message: message.to_string(),
            }),
            Classification::Unrecognised(body) => Err(GhidraError::Reported {
                status: Some(status.as_u16()),
                message: if body.is_empty() {
                    "the server returned an empty response".to_string()
                } else {
                    format!("the server returned an unrecognised response: {body}")
                },
            }),
        }
    }

    /// Render an address the way the server's endpoints expect: bare hex.
    fn addr(address: u64) -> String {
        format!("{address:x}")
    }

    /// Make an error-status body readable, stripping the HTML the PicoServer
    /// wraps its 404 pages in.
    fn describe_error_body(body: &str) -> String {
        let stripped = body
            .replace("<h1>", "")
            .replace("</h1>", " ")
            .trim()
            .to_string();
        if stripped.is_empty() {
            "the server returned an empty response".to_string()
        } else {
            stripped
        }
    }

    // =========================================================
    // Program state
    // =========================================================

    /// Every function Ghidra knows about in the open program.
    ///
    /// This is the whole program at once — a large binary returns several
    /// thousand entries — so prefer [`search_functions`](Self::search_functions)
    /// when a name is known.
    #[instrument(skip(self))]
    pub async fn list_functions(&self) -> Result<Vec<FunctionSummary>> {
        let body = self.get_text("list_functions", &[]).await?;
        let functions = parse::parse_function_listing(&body);
        debug!(count = functions.len(), "Listed functions");
        Ok(functions)
    }

    /// Functions whose name contains `query`.
    ///
    /// An empty result is reported as [`GhidraError::NotFound`] rather than an
    /// empty vector, because "no such function" and "the query found nothing
    /// yet" are different situations and only the first is an error.
    #[instrument(skip(self), fields(query))]
    pub async fn search_functions(
        &self,
        query: &str,
        limit: Option<usize>,
    ) -> Result<Vec<FunctionSummary>> {
        let mut params: Vec<(&str, String)> = vec![("name_pattern", query.to_string())];
        if let Some(n) = limit {
            params.push(("limit", n.to_string()));
        }
        let body = self.get_text("search_functions", &params).await?;
        let found = parse::parse_function_listing(&body);
        if found.is_empty() {
            return Err(GhidraError::NotFound {
                kind: "function",
                query: query.to_string(),
            });
        }
        debug!(count = found.len(), query, "Searched functions");
        Ok(found)
    }

    /// The address Ghidra's cursor is at.
    #[instrument(skip(self))]
    pub async fn current_address(&self) -> Result<u64> {
        let body = self.get_text("get_current_address", &[]).await?;
        parse::parse_current_address(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "the current address",
            detail: body.trim().to_string(),
        })
    }

    /// The function under Ghidra's cursor.
    #[instrument(skip(self))]
    pub async fn current_function(&self) -> Result<FunctionBody> {
        let body = self.get_text("get_current_function", &[]).await?;
        parse::parse_current_function(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "the current function",
            detail: body.trim().to_string(),
        })
    }

    /// The program's memory layout.
    ///
    /// The lowest segment start is the image base, which is what turns a Ghidra
    /// virtual address into a file-relative one.
    #[instrument(skip(self))]
    pub async fn segments(&self) -> Result<Vec<Segment>> {
        let body = self.get_text("list_segments", &[]).await?;
        Ok(parse::parse_segments(&body))
    }

    /// The base address the open program is loaded at.
    #[instrument(skip(self))]
    pub async fn image_base(&self) -> Result<u64> {
        self.segments()
            .await?
            .iter()
            .map(|s| s.start)
            .min()
            .ok_or_else(|| GhidraError::Malformed {
                kind: "the program layout",
                detail: "the server listed no segments".to_string(),
            })
    }

    // =========================================================
    // Function queries
    // =========================================================

    /// The pseudo-C for the function at `address`.
    ///
    /// `address` may be any address inside the function, not just its entry.
    #[instrument(skip(self), fields(address = format_args!("{address:#x}")))]
    pub async fn decompile_function(&self, address: u64) -> Result<DecompiledFunction> {
        let body = self
            .get_text("decompile_function", &[("address", Self::addr(address))])
            .await?;
        parse::parse_decompiled(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "decompiled output",
            detail: body.trim().to_string(),
        })
    }

    /// The pseudo-C for a function named by Ghidra.
    ///
    /// The 6.x bridge dropped the old POST-by-name endpoint, so the name is
    /// resolved through [`search_functions`](Self::search_functions) and the
    /// body is pulled by address. An exact name match wins over the substring
    /// matches the search also returns.
    #[instrument(skip(self), fields(function))]
    pub async fn decompile_function_by_name(&self, function: &str) -> Result<DecompiledFunction> {
        let matches = self.search_functions(function, Some(10)).await?;
        let found = matches
            .iter()
            .find(|f| f.name == function)
            .or(matches.first())
            .ok_or_else(|| GhidraError::NotFound {
                kind: "function",
                query: function.to_string(),
            })?;
        self.decompile_function(found.address).await
    }

    /// The disassembly listing for the function at `address`.
    #[instrument(skip(self), fields(address = format_args!("{address:#x}")))]
    pub async fn disassemble_function(&self, address: u64) -> Result<String> {
        self.get_text("disassemble_function", &[("address", Self::addr(address))])
            .await
    }

    /// Entry point and body range of the function at `address`.
    #[instrument(skip(self), fields(address = format_args!("{address:#x}")))]
    pub async fn function_body(&self, address: u64) -> Result<FunctionBody> {
        let body = self
            .get_text(
                "get_function_by_address",
                &[("address", Self::addr(address))],
            )
            .await?;
        parse::parse_function_body(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "function metadata",
            detail: body.trim().to_string(),
        })
    }

    /// Everything worth knowing about the function at `address`.
    ///
    /// This is the convenience the pipeline wants, assembled from four
    /// endpoints: the decompiled body, the disassembly, the body range, and the
    /// cross-references to the entry point.
    ///
    /// Callees are read out of the decompiled text rather than from a call-graph
    /// endpoint, because the server has no such endpoint and building a faithful
    /// list would cost a request per call site. A call through a function
    /// pointer therefore does not appear in `callees`.
    #[instrument(skip(self), fields(address = format_args!("{address:#x}")))]
    pub async fn function_report(&self, address: u64) -> Result<FunctionReport> {
        let decompiled = self.decompile_function(address).await?;

        // The remaining three enrich the decompilation rather than define it, so
        // a function that decompiles is still reported when they fail — a
        // missing call site is not a reason to lose the body.
        let disassembly = self
            .disassemble_function(address)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "Could not read disassembly; reporting without it");
                String::new()
            });
        let body = self.function_body(address).await.ok();
        let callers = self.callers(address).await.unwrap_or_else(|e| {
            warn!(error = %e, "Could not read cross-references; reporting without callers");
            Vec::new()
        });

        let callees = parse::callees_from_decompiled(&decompiled.body);
        let name = body
            .as_ref()
            .map(|b| b.name.clone())
            .unwrap_or_else(|| decompiled.name.clone());

        info!(%name, address = format_args!("{address:#x}"), callees = callees.len(), "Read function report");
        Ok(FunctionReport {
            name,
            address,
            decompiled,
            disassembly,
            body,
            callers,
            callees,
        })
    }

    // =========================================================
    // Cross-references
    // =========================================================

    /// References to `address` — who points at it.
    ///
    /// The server returns a 200 with an empty body when there are no
    /// cross-references, which is a valid "no results" response rather than
    /// an error.
    #[instrument(skip(self), fields(address = format_args!("{address:#x}")))]
    pub async fn xrefs_to(&self, address: u64, limit: Option<usize>) -> Result<Vec<Xref>> {
        let mut params: Vec<(&str, String)> = vec![("address", Self::addr(address))];
        if let Some(n) = limit {
            params.push(("limit", n.to_string()));
        }
        let body = self.get_text("get_xrefs_to", &params).await;
        match body {
            Ok(body) => Ok(parse::parse_xrefs(&body)),
            Err(GhidraError::Reported { message: ref m, .. })
                if m == "the server returned an empty response" =>
            {
                Ok(Vec::new())
            }
            Err(e) => Err(e),
        }
    }

    /// References from `address` — what it points at.
    ///
    /// A function's *entry* has no outgoing references, because nothing inside
    /// it is the source. Pass the address of a call instruction to learn its
    /// target.
    ///
    /// The server returns a 200 with an empty body when there are no
    /// cross-references, which is a valid "no results" response rather than
    /// an error.
    #[instrument(skip(self), fields(address = format_args!("{address:#x}")))]
    pub async fn xrefs_from(&self, address: u64, limit: Option<usize>) -> Result<Vec<Xref>> {
        let mut params: Vec<(&str, String)> = vec![("address", Self::addr(address))];
        if let Some(n) = limit {
            params.push(("limit", n.to_string()));
        }
        let body = self.get_text("get_xrefs_from", &params).await;
        match body {
            Ok(body) => Ok(parse::parse_xrefs(&body)),
            Err(GhidraError::Reported { message: ref m, .. })
                if m == "the server returned an empty response" =>
            {
                Ok(Vec::new())
            }
            Err(e) => Err(e),
        }
    }

    /// References to a function, found by name.
    ///
    /// The server returns a 200 with an empty body when there are no
    /// cross-references, which is a valid "no results" response rather than
    /// an error.
    #[instrument(skip(self), fields(function))]
    pub async fn function_xrefs(&self, function: &str, limit: Option<usize>) -> Result<Vec<Xref>> {
        let mut params: Vec<(&str, String)> = vec![("name", function.to_string())];
        if let Some(n) = limit {
            params.push(("limit", n.to_string()));
        }
        let body = self.get_text("get_function_xrefs", &params).await;
        match body {
            Ok(body) => Ok(parse::parse_xrefs(&body)),
            Err(GhidraError::Reported { message: ref m, .. })
                if m == "the server returned an empty response" =>
            {
                Ok(Vec::new())
            }
            Err(e) => Err(e),
        }
    }

    /// Names of the functions that call the function at `address`.
    ///
    /// Cross-references that name no enclosing function are dropped, so this
    /// answers "which functions call this" and not "how many references exist".
    #[instrument(skip(self), fields(address = format_args!("{address:#x}")))]
    pub async fn callers(&self, address: u64) -> Result<Vec<String>> {
        let xrefs = self.xrefs_to(address, None).await?;
        let mut names: Vec<String> = Vec::new();
        for x in xrefs {
            if let Some(f) = x.function
                && !names.contains(&f)
            {
                names.push(f);
            }
        }
        Ok(names)
    }

    // =========================================================
    // Symbols and data
    // =========================================================

    /// Symbols the program exports.
    #[instrument(skip(self))]
    pub async fn exports(&self, limit: Option<usize>) -> Result<Vec<Symbol>> {
        let params = limit
            .map(|n| vec![("limit", n.to_string())])
            .unwrap_or_default();
        let body = self.get_text("list_exports", &params).await?;
        Ok(parse::parse_symbols(&body, false))
    }

    /// Symbols the program imports.
    ///
    /// Imports that resolve to an external module arrive with an `EXTERNAL:`
    /// address, which is a slot the loader fills rather than a location in the
    /// program. The 6.x bridge answers JSON; older builds answered the same
    /// `name -> address` text as exports, and both shapes are accepted.
    #[instrument(skip(self))]
    pub async fn imports(&self, limit: Option<usize>) -> Result<Vec<Symbol>> {
        let params = limit
            .map(|n| vec![("limit", n.to_string())])
            .unwrap_or_default();
        let body = self.get_text("list_imports", &params).await?;
        Ok(parse::parse_symbols_json(&body, true)
            .unwrap_or_else(|| parse::parse_symbols(&body, true)))
    }

    /// String literals defined in the program.
    #[instrument(skip(self), fields(filter))]
    pub async fn strings(
        &self,
        limit: Option<usize>,
        filter: Option<&str>,
    ) -> Result<Vec<StringLiteral>> {
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(n) = limit {
            params.push(("limit", n.to_string()));
        }
        if let Some(f) = filter {
            params.push(("filter", f.to_string()));
        }
        let body = self.get_text("list_strings", &params).await?;
        Ok(parse::records(&body)
            .into_iter()
            .filter_map(parse::parse_string_literal)
            .collect())
    }

    /// Namespaces defined in the program.
    #[instrument(skip(self))]
    pub async fn namespaces(&self, limit: Option<usize>) -> Result<Vec<String>> {
        let params = limit
            .map(|n| vec![("limit", n.to_string())])
            .unwrap_or_default();
        let body = self.get_text("list_namespaces", &params).await?;
        Ok(parse::records(&body)
            .into_iter()
            .map(str::to_string)
            .collect())
    }

    /// Classes defined in the program.
    #[instrument(skip(self))]
    pub async fn classes(&self, limit: Option<usize>) -> Result<Vec<String>> {
        let params = limit
            .map(|n| vec![("limit", n.to_string())])
            .unwrap_or_default();
        let body = self.get_text("list_classes", &params).await?;
        Ok(parse::records(&body)
            .into_iter()
            .map(str::to_string)
            .collect())
    }

    /// Methods defined in the program.
    #[instrument(skip(self))]
    pub async fn methods(&self, limit: Option<usize>) -> Result<Vec<String>> {
        let params = limit
            .map(|n| vec![("limit", n.to_string())])
            .unwrap_or_default();
        let body = self.get_text("list_methods", &params).await?;
        Ok(parse::records(&body)
            .into_iter()
            .map(str::to_string)
            .collect())
    }

    // =========================================================
    // Type Manager and defined data
    // =========================================================

    /// Every named type in Ghidra's Type Manager, optionally filtered by
    /// category or name fragment.
    ///
    /// The Type Manager holds types that were never applied to a symbol, so
    /// this sees more than the symbol table. Pages are collected until the
    /// server runs out.
    #[instrument(skip(self), fields(category))]
    pub async fn list_data_types(&self, category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
        let mut all = Vec::new();
        let mut offset = 0;
        loop {
            let page = self.data_types_page(category, offset, DATA_PAGE).await?;
            let got = page.len();
            all.extend(page);
            if got < DATA_PAGE {
                return Ok(all);
            }
            offset += got;
        }
    }

    /// One page of the Type Manager listing, with the server's own
    /// `offset`/`limit` windowing.
    #[instrument(skip(self), fields(category, offset, limit))]
    pub async fn data_types_page(
        &self,
        category: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<DataTypeEntry>> {
        let mut params: Vec<(&str, String)> =
            vec![("offset", offset.to_string()), ("limit", limit.to_string())];
        if let Some(c) = category {
            params.push(("category", c.to_string()));
        }
        let body = self.get_text("list_data_types", &params).await?;
        Ok(parse::parse_data_types(&body))
    }

    /// Field layout of a structure from the Type Manager.
    ///
    /// A name the Type Manager does not know becomes [`GhidraError::NotFound`];
    /// a name that resolves to a non-structure becomes [`GhidraError::Malformed`]
    /// carrying the server's explanation.
    #[instrument(skip(self), fields(name))]
    pub async fn get_struct_layout(&self, name: &str) -> Result<StructLayout> {
        let body = self
            .get_text("get_struct_layout", &[("struct_name", name.to_string())])
            .await?;
        if let Some(missing) = body.trim().strip_prefix("Structure not found: ") {
            return Err(GhidraError::NotFound {
                kind: "structure",
                query: missing.trim().to_string(),
            });
        }
        parse::parse_struct_layout(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "structure layout",
            detail: body.trim().to_string(),
        })
    }

    /// Members and values of an enumeration from the Type Manager.
    ///
    /// Error mapping follows [`get_struct_layout`](Self::get_struct_layout).
    #[instrument(skip(self), fields(name))]
    pub async fn get_enum_values(&self, name: &str) -> Result<EnumDefinition> {
        let body = self
            .get_text("get_enum_values", &[("enum_name", name.to_string())])
            .await?;
        if let Some(missing) = body.trim().strip_prefix("Enumeration not found: ") {
            return Err(GhidraError::NotFound {
                kind: "enumeration",
                query: missing.trim().to_string(),
            });
        }
        parse::parse_enum_values(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "enumeration values",
            detail: body.trim().to_string(),
        })
    }

    /// Every defined data object in the listing, collected across pages.
    ///
    /// Large binaries hold tens of thousands of defined items, so this pages
    /// through the whole listing; use [`data_items_page`](Self::data_items_page)
    /// to work a window at a time.
    #[instrument(skip(self))]
    pub async fn list_data_items(&self) -> Result<Vec<DataItem>> {
        let mut all = Vec::new();
        let mut offset = 0;
        loop {
            let page = self.data_items_page(offset, DATA_PAGE).await?;
            let got = page.len();
            all.extend(page);
            if got < DATA_PAGE {
                return Ok(all);
            }
            offset += got;
        }
    }

    /// One page of defined data items, with the server's own `offset`/`limit`
    /// windowing.
    #[instrument(skip(self), fields(offset, limit))]
    pub async fn data_items_page(&self, offset: usize, limit: usize) -> Result<Vec<DataItem>> {
        let params = [("offset", offset.to_string()), ("limit", limit.to_string())];
        let body = self.get_text("list_data_items", &params).await?;
        Ok(parse::parse_data_items(&body))
    }

    /// The raw bytes at `address`.
    ///
    /// This is how the contents of a defined data object are read — a vtable's
    /// method pointers, an RTTI locator — which no listing endpoint reports.
    #[instrument(skip(self), fields(address = format_args!("{address:#x}"), length))]
    pub async fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        let params = [
            ("address", Self::addr(address)),
            ("length", length.to_string()),
        ];
        let body = self.get_text("read_memory", &params).await?;
        parse::parse_memory_bytes(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "memory bytes",
            detail: body.trim().to_string(),
        })
    }

    // =========================================================
    // Write-back
    // =========================================================

    /// Attach `tag` to a function, naming it by address or by name.
    ///
    /// The tag is created if it does not exist. Only functions take tags: a
    /// data address is refused with `No function found for ...`.
    #[instrument(skip(self), fields(function, tag))]
    pub async fn add_function_tag(&self, function: &str, tag: &str) -> Result<()> {
        let payload = serde_json::json!({ "function": function, "tags": tag });
        self.post_json("add_function_tag", &payload).await?;
        Ok(())
    }

    // =========================================================
    // Availability and program selection
    // =========================================================

    /// Whether the server is up and a program is open.
    ///
    /// The bridge only serves requests while a CodeBrowser is open, so this is
    /// the check to run before a long pipeline to fail early with a clear
    /// reason.
    pub async fn probe(&self) -> Result<ProgramInfo> {
        let body = self.get_text("get_current_address", &[]).await?;
        let address = parse::parse_current_address(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "the current address",
            detail: body.trim().to_string(),
        })?;
        let program = parse::json_string(&body, "program").unwrap_or_default();
        let function = self.current_function().await?;
        info!(
            program = %program,
            function = %function.name,
            address = format_args!("{address:#x}"),
            "GhidraMCP is serving"
        );
        Ok(ProgramInfo {
            program,
            function: function.name,
            address,
        })
    }

    /// The programs currently open in the Ghidra instance.
    ///
    /// The 6.x bridge can hold several at once; queries answer against the
    /// current one, which [`switch_program`](Self::switch_program) changes.
    #[instrument(skip(self))]
    pub async fn open_programs(&self) -> Result<Vec<OpenProgram>> {
        let body = self.get_text("list_open_programs", &[]).await?;
        let programs = parse::parse_open_programs(&body);
        debug!(count = programs.len(), "Listed open programs");
        Ok(programs)
    }

    /// Make `program` the one queries run against.
    ///
    /// `program` is the name or project path shown by
    /// [`open_programs`](Self::open_programs). Every other method on this
    /// client follows the switch, so a pipeline that assumed the previous
    /// program's addresses must re-resolve them.
    #[instrument(skip(self), fields(program))]
    pub async fn switch_program(&self, program: &str) -> Result<()> {
        let body = self
            .get_text("switch_program", &[("program", program.to_string())])
            .await?;
        let switched_to = parse::json_string(&body, "switched_to").unwrap_or_default();
        info!(program = %switched_to, "Switched GhidraMCP's current program");
        Ok(())
    }
}

/// A summary of what the server is currently serving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramInfo {
    /// Name of the open program, as the server reports it.
    pub program: String,
    /// Name of the function under Ghidra's cursor.
    pub function: String,
    /// Address of Ghidra's cursor.
    pub address: u64,
}

/// Convert a Ghidra virtual address into a file-relative one.
///
/// The program's image base is the lowest mapped address, and subtracting it
/// yields the RVA the PE headers index exports and imports by.
pub fn rva_from_va(image_base: u64, va: u64) -> Option<u32> {
    let rva = va.checked_sub(image_base)?;
    u32::try_from(rva).ok()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = GhidraConfig::new("http://127.0.0.1:8080").unwrap();
        assert_eq!(config.base_url.as_str(), "http://127.0.0.1:8080/");
        assert_eq!(config.timeout, Duration::from_secs(120));
        assert!(config.api_key.is_none());
    }

    #[test]
    fn test_config_rejects_a_non_url() {
        assert!(GhidraConfig::new("not-a-url").is_err());
    }

    #[test]
    fn test_client_exposes_its_base_url() {
        let client = GhidraClient::new("http://127.0.0.1:8080").unwrap();
        assert_eq!(client.base_url().as_str(), "http://127.0.0.1:8080/");
    }

    #[test]
    fn test_addresses_are_sent_as_bare_hex() {
        // Ghidra writes addresses without a prefix and does not parse one, so
        // the client must not add it.
        assert_eq!(GhidraClient::addr(0x18008ed50), "18008ed50");
    }

    #[test]
    fn test_rva_from_va() {
        assert_eq!(rva_from_va(0x180000000, 0x18008ed50), Some(0x8ed50));
        // A VA below the image base is not addressable, and silently wrapping
        // would produce a plausible-looking but wrong RVA.
        assert_eq!(rva_from_va(0x180000000, 0x17ffffff), None);
    }

    #[test]
    fn test_reported_error_mentions_the_message() {
        let err = GhidraError::Reported {
            status: Some(200),
            message: "Function not found".to_string(),
        };
        assert!(err.to_string().contains("Function not found"));
    }
}
