use axum::http::HeaderMap;
use leptos::prelude::ServerFnError;
use leptos_axum::extract;

pub async fn get_server_url_from_request() -> Result<String, ServerFnError> {
    let headers: HeaderMap = extract().await?;

    Ok(get_server_url_from_headers(&headers))
}

pub fn get_server_url_from_headers(headers: &HeaderMap) -> String {
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:3000");

    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|s| s.to_str().ok())
        .unwrap_or("http");

    format!("{}://{}", scheme, host)
}
