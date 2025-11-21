//
// Google's documentation: https://developers.google.com/identity/sign-in/web/backend-auth
//
// Key points from Google docs:
// - "These keys are regularly rotated; examine the Cache-Control header
//   in the response to determine when you should retrieve them again."
// - Use JWK format: https://www.googleapis.com/oauth2/v3/certs
// - PEM format also available: https://www.googleapis.com/oauth2/v1/certs

use std::time::Duration;

/// Configuration for JWK rotation handling
pub struct JwkRotationConfig {
    /// How often to check if JWKs need refreshing (default: 5 minutes)
    pub check_interval: Duration,
}

impl Default for JwkRotationConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(5 * 60), // 5 minutes
        }
    }
}

/// Start a background task to periodically refresh JWKs for Google OAuth
pub fn start_jwk_refresh_task(
    google_provider: std::sync::Arc<crate::oauth_provider::GoogleOAuthProvider>,
    config: JwkRotationConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!(
            "JWK refresh task started with check interval: {:?}",
            config.check_interval
        );

        let mut interval = tokio::time::interval(config.check_interval);

        loop {
            interval.tick().await;

            // Check if the Google OAuth client needs JWK refresh
            if google_provider.needs_jwk_refresh() {
                tracing::info!("Google OAuth client JWKs need refresh, updating...");

                match google_provider.refresh_client_jwks().await {
                    Ok(()) => {
                        tracing::info!("Successfully refreshed Google OAuth JWKs");
                    }
                    Err(e) => {
                        tracing::error!("Failed to refresh Google OAuth JWKs: {}", e);
                        // Continue the loop to try again later
                    }
                }
            } else {
                tracing::debug!("Google OAuth client JWKs are still fresh");
            }
        }
    })
}
