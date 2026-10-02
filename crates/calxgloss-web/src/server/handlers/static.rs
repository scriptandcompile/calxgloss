//! Static file serving: HTML fallback for the frontend.

use axum::{
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    response::Html,
};

/// Fallback for static file requests.
///
/// Reads from the `static/` directory relative to this crate's manifest
/// directory. Uses the raw request URI since `axum::extract::Path` doesn't
/// work with `fallback_service`.
pub async fn static_fallback(
    req: axum::http::Request<axum::body::Body>,
) -> (StatusCode, [(HeaderName, HeaderValue); 1], Html<String>) {
    // Parse the path from the request URI
    let path_str = req.uri().path().to_string();

    // Only handle GET requests, reject everything else
    if req.method() != Method::GET {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"))],
            Html("405 Method Not Allowed".to_string()),
        );
    }

    // Reject path traversal
    if path_str.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"))],
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
            [(header::CONTENT_TYPE, HeaderValue::from_static("text/html"))],
            Html("<h1>404 Not Found</h1>".to_string()),
        );
    }

    // Read the file content
    let content = match std::fs::read_to_string(&file_path) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"))],
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
        [(header::CONTENT_TYPE, HeaderValue::from_static(content_type))],
        Html(content),
    )
}
