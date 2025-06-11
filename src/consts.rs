use web_time::Duration;

pub const GOOGLE_ISSUER_URL: &str = "https://accounts.google.com";
pub const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

pub const APPLE_ISSUER_URL: &str = "https://account.apple.com";

/// Delegation Expiry, 7 days
pub const ACCESS_TOKEN_MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 7);
/// Refresh expiry, 30 days
pub const REFRESH_TOKEN_MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 30);

pub const AUTH_TOKEN_KID: &str = "default";
