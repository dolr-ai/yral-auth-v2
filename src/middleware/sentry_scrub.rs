use sentry::protocol::{Breadcrumb, Context, Event, Request};
use std::collections::BTreeMap;
use std::sync::Arc;

/// List of sensitive field names to redact from Sentry events
/// These are commonly found in OAuth/OIDC auth flows
const SENSITIVE_FIELDS: &[&str] = &[
    // OAuth/OIDC sensitive parameters
    "code",
    "code_verifier",
    "code_challenge",
    "client_secret",
    "refresh_token",
    "access_token",
    "id_token",
    // Generic auth fields
    "authorization",
    "bearer",
    "token",
    "api_key",
    "secret",
    "password",
    "private_key",
    "session_token",
    "auth_token",
    // JWT fields
    "jwt",
    "jwk",
    "delegated_identity",
    "identity_jwk",
];

const REDACTED: &str = "[REDACTED]";

/// Check if a field name is sensitive (case-insensitive)
fn is_sensitive_field(field_name: &str) -> bool {
    let field_lower = field_name.to_lowercase();
    SENSITIVE_FIELDS
        .iter()
        .any(|sensitive| field_lower.contains(sensitive))
}

/// Scrub sensitive data from a request object
fn scrub_request(mut request: Request) -> Request {
    // Scrub query string
    if let Some(query) = request.query_string.as_mut() {
        if SENSITIVE_FIELDS
            .iter()
            .any(|field| query.to_lowercase().contains(field))
        {
            *query = REDACTED.to_string();
        }
    }

    // Scrub headers
    for (key, value) in request.headers.iter_mut() {
        if is_sensitive_field(key) {
            *value = REDACTED.to_string();
        }
    }

    // Scrub cookies
    if let Some(cookies) = request.cookies.as_mut() {
        if SENSITIVE_FIELDS
            .iter()
            .any(|field| cookies.to_lowercase().contains(field))
        {
            *cookies = REDACTED.to_string();
        }
    }

    // Note: We never capture body data, so no need to scrub it
    request.data = None;

    request
}

/// Scrub sensitive data from breadcrumbs
fn scrub_breadcrumbs(breadcrumbs: &mut [Breadcrumb]) {
    for breadcrumb in breadcrumbs.iter_mut() {
        // Scrub breadcrumb data
        for (key, value) in breadcrumb.data.iter_mut() {
            if is_sensitive_field(key) {
                *value = serde_json::Value::String(REDACTED.to_string());
            }
        }

        // Scrub breadcrumb message if it contains sensitive field names
        if let Some(message) = breadcrumb.message.as_mut() {
            if SENSITIVE_FIELDS
                .iter()
                .any(|field| message.to_lowercase().contains(field))
            {
                *message = format!("{} (scrubbed)", message.split(':').next().unwrap_or(""));
            }
        }
    }
}

/// Scrub sensitive data from contexts
fn scrub_contexts(contexts: &mut BTreeMap<String, Context>) {
    for (_key, context) in contexts.iter_mut() {
        match context {
            Context::Other(map) => {
                for (key, value) in map.iter_mut() {
                    if is_sensitive_field(key) {
                        *value = serde_json::Value::String(REDACTED.to_string());
                    }
                }
            }
            _ => {
                // Other context types (Device, OS, Runtime, etc.) don't contain sensitive data
            }
        }
    }
}

/// Scrub sensitive data from exception values
fn scrub_exception_values(values: &mut [sentry::protocol::Exception]) {
    for exception in values.iter_mut() {
        // Scrub exception value (message) if it contains sensitive patterns
        if let Some(value) = exception.value.as_mut() {
            if SENSITIVE_FIELDS
                .iter()
                .any(|field| value.to_lowercase().contains(field))
            {
                *value = format!("{} (scrubbed)", value.split(':').next().unwrap_or("Error"));
            }
        }
    }
}

/// Main scrubbing function to remove sensitive data from Sentry events
pub fn scrub_sensitive_data(mut event: Event<'static>) -> Option<Event<'static>> {
    // Scrub request data
    if let Some(request) = event.request.take() {
        event.request = Some(scrub_request(request));
    }

    // Scrub breadcrumbs
    scrub_breadcrumbs(&mut event.breadcrumbs.values);

    // Scrub contexts
    scrub_contexts(&mut event.contexts);

    // Scrub exceptions
    scrub_exception_values(&mut event.exception.values);

    Some(event)
}

/// Create a before_send callback that scrubs sensitive data
pub fn create_before_send() -> Arc<
    dyn Fn(sentry::protocol::Event<'static>) -> Option<sentry::protocol::Event<'static>>
        + Send
        + Sync,
> {
    Arc::new(scrub_sensitive_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sensitive_field() {
        assert!(is_sensitive_field("authorization"));
        assert!(is_sensitive_field("Authorization"));
        assert!(is_sensitive_field("client_secret"));
        assert!(is_sensitive_field("refresh_token"));
        assert!(is_sensitive_field("code_verifier"));
        assert!(!is_sensitive_field("user_id"));
        assert!(!is_sensitive_field("timestamp"));
    }

    #[test]
    fn test_scrub_request_headers() {
        let mut request = Request::default();
        request
            .headers
            .insert("authorization".to_string(), "Bearer secret".to_string());
        request
            .headers
            .insert("content-type".to_string(), "application/json".to_string());

        let scrubbed = scrub_request(request);
        assert_eq!(scrubbed.headers.get("authorization").unwrap(), REDACTED);
        assert_eq!(
            scrubbed.headers.get("content-type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_scrub_request_query_string() {
        let mut request = Request::default();
        request.query_string = Some("code=abc123&state=xyz".to_string());

        let scrubbed = scrub_request(request);
        assert_eq!(scrubbed.query_string.unwrap(), REDACTED);
    }
}
