use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use sentry::protocol::{Breadcrumb, Level};
use std::collections::BTreeMap;
use std::time::Instant;

/// Check if HTTP logging middleware is enabled via environment variable
/// Defaults to true if not set
fn is_http_logging_enabled() -> bool {
    std::env::var("SENTRY_ENABLE_HTTP_LOGGING")
        .ok()
        .and_then(|s| s.parse::<bool>().ok())
        .unwrap_or(true)
}

/// Add a lightweight breadcrumb for successful requests (< 400)
/// Only captures HTTP metadata, no bodies
fn add_lightweight_breadcrumb(method: &str, path: &str, status: StatusCode, duration_ms: u128) {
    let mut data = BTreeMap::new();
    data.insert(
        "method".to_string(),
        serde_json::Value::String(method.to_string()),
    );
    data.insert(
        "url".to_string(),
        serde_json::Value::String(path.to_string()),
    );
    data.insert(
        "status_code".to_string(),
        serde_json::Value::Number(status.as_u16().into()),
    );
    data.insert(
        "duration_ms".to_string(),
        serde_json::Value::Number((duration_ms as u64).into()),
    );

    sentry::Hub::current().add_breadcrumb(Breadcrumb {
        ty: "http".to_string(),
        category: Some("http.request".to_string()),
        message: Some(format!(
            "{} {} {} ({}ms)",
            method,
            path,
            status.as_u16(),
            duration_ms
        )),
        data,
        level: Level::Info,
        ..Default::default()
    });
}

/// Add a request breadcrumb with metadata (for errors >= 400)
fn add_request_breadcrumb(method: &str, path: &str) {
    let mut data = BTreeMap::new();
    data.insert(
        "method".to_string(),
        serde_json::Value::String(method.to_string()),
    );
    data.insert(
        "url".to_string(),
        serde_json::Value::String(path.to_string()),
    );

    sentry::Hub::current().add_breadcrumb(Breadcrumb {
        ty: "http".to_string(),
        category: Some("http.request".to_string()),
        message: Some(format!("{} {}", method, path)),
        data,
        level: Level::Info,
        ..Default::default()
    });
}

/// Add a response breadcrumb with error information (for errors >= 400)
/// Only includes error status text, NO response body
fn add_response_breadcrumb(status: StatusCode, duration_ms: u128) {
    let mut data = BTreeMap::new();
    data.insert(
        "status_code".to_string(),
        serde_json::Value::Number(status.as_u16().into()),
    );
    data.insert(
        "duration_ms".to_string(),
        serde_json::Value::Number((duration_ms as u64).into()),
    );

    // Add error reason phrase if available
    if let Some(reason) = status.canonical_reason() {
        data.insert(
            "error".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
    }

    let level = if status.is_server_error() {
        Level::Error
    } else if status.is_client_error() {
        Level::Warning
    } else {
        Level::Info
    };

    sentry::Hub::current().add_breadcrumb(Breadcrumb {
        ty: "http".to_string(),
        category: Some("http.response".to_string()),
        message: Some(format!("{} ({}ms)", status.as_u16(), duration_ms)),
        data,
        level,
        ..Default::default()
    });
}

/// HTTP logging middleware for Sentry
///
/// Security: Does NOT capture request/response bodies (auth service)
///
/// For successful requests (< 400):
/// - Single lightweight breadcrumb with method, path, status, duration
///
/// For error requests (>= 400):
/// - Request breadcrumb with method, path
/// - Response breadcrumb with status, duration, error reason text
/// - NO body data captured
pub async fn http_logging_middleware(request: Request, next: Next) -> Response {
    if !is_http_logging_enabled() {
        return next.run(request).await;
    }

    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let start = Instant::now();

    // Process request - no body buffering needed
    let response = next.run(request).await;

    let duration_ms = start.elapsed().as_millis();
    let status = response.status();

    // Only add detailed breadcrumbs for errors
    if status.as_u16() >= 400 {
        log::error!(
            "HTTP Error: {} {} -> {} ({}ms)",
            method,
            path,
            status.as_u16(),
            duration_ms
        );
        add_request_breadcrumb(&method, &path);
        add_response_breadcrumb(status, duration_ms);
    } else {
        // Success: lightweight single breadcrumb
        add_lightweight_breadcrumb(&method, &path, status, duration_ms);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http_logging_enabled_default() {
        // Should default to true when env var is not set
        std::env::remove_var("SENTRY_ENABLE_HTTP_LOGGING");
        assert!(is_http_logging_enabled());
    }

    #[test]
    fn test_is_http_logging_enabled_true() {
        std::env::set_var("SENTRY_ENABLE_HTTP_LOGGING", "true");
        assert!(is_http_logging_enabled());
        std::env::remove_var("SENTRY_ENABLE_HTTP_LOGGING");
    }

    #[test]
    fn test_is_http_logging_enabled_false() {
        std::env::set_var("SENTRY_ENABLE_HTTP_LOGGING", "false");
        assert!(!is_http_logging_enabled());
        std::env::remove_var("SENTRY_ENABLE_HTTP_LOGGING");
    }

    #[test]
    fn test_lightweight_breadcrumb_format() {
        // Test that breadcrumb data is properly formatted
        // This is a smoke test - actual breadcrumb verification would require
        // mocking the Sentry SDK
        add_lightweight_breadcrumb("GET", "/api/test", StatusCode::OK, 42);
    }

    #[test]
    fn test_error_breadcrumb_format() {
        // Test that error breadcrumbs are properly formatted
        add_request_breadcrumb("POST", "/oauth/token");
        add_response_breadcrumb(StatusCode::BAD_REQUEST, 123);
    }
}
