//! Static file serving: HTML fallback for the frontend.

use axum::{
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::Html,
};

/// Headers every static response carries: the content type plus
/// revalidation metadata. `no-cache` (not `no-store`) lets the browser
/// reuse its copy but forces it to ask the server first — so an edited
/// CSS/JS file shows up on the next reload instead of being heuristically
/// cached stale and mixing old markup with new styles.
fn static_headers(content_type: &'static str, etag: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    if let Some(value) = etag.and_then(|etag| HeaderValue::from_str(etag).ok()) {
        headers.insert(header::ETAG, value);
    }
    headers
}

/// Fallback for static file requests.
///
/// Reads from the `static/` directory relative to this crate's manifest
/// directory. Uses the raw request URI since `axum::extract::Path` doesn't
/// work with `fallback_service`.
pub async fn static_fallback(
    req: axum::http::Request<axum::body::Body>,
) -> (StatusCode, HeaderMap, Html<String>) {
    // Parse the path from the request URI
    let path_str = req.uri().path().to_string();

    // Only handle GET requests, reject everything else
    if req.method() != Method::GET {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            static_headers("text/plain", None),
            Html("405 Method Not Allowed".to_string()),
        );
    }

    // Reject path traversal
    if path_str.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            static_headers("text/plain", None),
            Html("400 Bad Request".to_string()),
        );
    }

    let base = env!("CARGO_MANIFEST_DIR");
    let file_path = std::path::Path::new(base)
        .join("static")
        .join(path_str.trim_start_matches('/'));

    if !file_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            static_headers("text/html", None),
            Html("<h1>404 Not Found</h1>".to_string()),
        );
    }

    // ETag from mtime + size: cheap, and changes whenever the file does.
    let etag = file_path.metadata().ok().map(|meta| {
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("\"{mtime:x}-{:x}\"", meta.len())
    });

    // A matching If-None-Match means the browser's copy is current.
    if let Some(etag) = &etag {
        let matches = req
            .headers()
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == etag);
        if matches {
            return (
                StatusCode::NOT_MODIFIED,
                static_headers("text/html", Some(etag)),
                Html(String::new()),
            );
        }
    }

    // Read the file content
    let content = match std::fs::read_to_string(&file_path) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                static_headers("text/plain", None),
                Html("500 Internal Server Error".to_string()),
            );
        }
    };

    // Set appropriate content types based on file extension
    let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let content_type = match ext {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        _ => "application/octet-stream",
    };

    (
        StatusCode::OK,
        static_headers(content_type, etag.as_deref()),
        Html(content),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    async fn get(path: &str, if_none_match: Option<&str>) -> (StatusCode, HeaderMap) {
        let mut builder = Request::builder().uri(path);
        if let Some(etag) = if_none_match {
            builder = builder.header(header::IF_NONE_MATCH, etag);
        }
        let req = builder.body(axum::body::Body::empty()).expect("request");
        let (status, headers, _) = static_fallback(req).await;
        (status, headers)
    }

    #[tokio::test]
    async fn static_assets_revalidate_so_edits_take_effect_on_reload() {
        // Without revalidation headers the browser heuristically caches
        // stale CSS/JS, mixing old markup with new styles — the pipeline
        // rows grew a column the header didn't have.
        let (status, headers) = get("/js/binary-rows.js", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(header::CACHE_CONTROL).map(|v| v.as_bytes()),
            Some(b"no-cache".as_ref()),
            "static assets must revalidate"
        );
        let etag = headers
            .get(header::ETAG)
            .expect("static assets carry an etag")
            .clone();

        // A browser copy tagged with the current etag gets a 304.
        let (status, _) = get(
            "/js/binary-rows.js",
            Some(etag.to_str().expect("ascii etag")),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_MODIFIED);
    }
}
