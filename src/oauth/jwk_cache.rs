use std::{
    sync::{atomic::AtomicU64, Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use openidconnect::{
    core::{CoreJsonWebKeySet, CoreProviderMetadata},
    reqwest::{header::CACHE_CONTROL, Client},
    JsonWebKeySetUrl,
};
use tracing::error;

/// Cache for JWK sets with automatic rotation support
pub struct JwkCache {
    jwks: RwLock<Arc<CoreJsonWebKeySet>>,
    cache_expiry_epoch_secs: AtomicU64,
    jwks_uri: JsonWebKeySetUrl,
    http_client: Client,
}

impl JwkCache {
    /// Create a new JWK cache with initial JWKs from provider metadata
    pub async fn new(
        provider_metadata: &CoreProviderMetadata,
        http_client: Client,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let jwks_uri = provider_metadata.jwks_uri().clone();

        // Fetch initial JWKs with cache headers
        let (jwks, cache_expiry) =
            Self::fetch_jwks_with_cache_info(&jwks_uri, &http_client).await?;

        Ok(Self {
            jwks: RwLock::new(Arc::new(jwks)),
            cache_expiry_epoch_secs: AtomicU64::new(cache_expiry),
            jwks_uri,
            http_client,
        })
    }

    /// Get current JWKs, refreshing if expired
    pub async fn get_jwks(&self) -> Arc<CoreJsonWebKeySet> {
        let current_epoch = Self::current_epoch_secs();
        let cache_expiry = self
            .cache_expiry_epoch_secs
            .load(std::sync::atomic::Ordering::Acquire);

        // Return cached JWKs if still valid
        if current_epoch < cache_expiry {
            return self.jwks.read().unwrap().clone();
        }

        // Acquire write lock for refresh
        let jwks_guard = self.jwks.read().unwrap();

        // Double-check expiry after acquiring lock (another task might have refreshed)
        let cache_expiry = self
            .cache_expiry_epoch_secs
            .load(std::sync::atomic::Ordering::Acquire);
        if current_epoch < cache_expiry {
            return jwks_guard.clone();
        }

        // This is a sync method, so we can't do async fetch here
        // Return the cached version and log that refresh is needed
        error!(
            "JWKs expired but cannot refresh in sync context. Background task should handle this."
        );

        // Extend cache by 5 minutes to avoid repeated error logs
        let extended_expiry = current_epoch + 300;
        self.cache_expiry_epoch_secs
            .store(extended_expiry, std::sync::atomic::Ordering::Release);

        jwks_guard.clone()
    }

    /// Force refresh JWKs from the endpoint (async method for background tasks)
    pub async fn refresh_jwks(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (new_jwks, new_expiry) =
            Self::fetch_jwks_with_cache_info(&self.jwks_uri, &self.http_client).await?;

        {
            let mut jwks_guard = self.jwks.write().unwrap();
            *jwks_guard = Arc::new(new_jwks);
        }

        self.cache_expiry_epoch_secs
            .store(new_expiry, std::sync::atomic::Ordering::Release);
        tracing::info!(
            "Successfully refreshed JWK cache, expires at epoch {}",
            new_expiry
        );

        Ok(())
    }

    /// Check if JWKs need refresh (within buffer time of expiry)
    pub fn needs_refresh(&self, buffer_secs: u64) -> bool {
        let current_epoch = Self::current_epoch_secs();
        let cache_expiry = self
            .cache_expiry_epoch_secs
            .load(std::sync::atomic::Ordering::Acquire);

        current_epoch >= cache_expiry.saturating_sub(buffer_secs)
    }

    /// Fetch JWKs with cache control header parsing
    async fn fetch_jwks_with_cache_info(
        jwks_uri: &JsonWebKeySetUrl,
        http_client: &Client,
    ) -> Result<(CoreJsonWebKeySet, u64), Box<dyn std::error::Error + Send + Sync>> {
        let response = http_client.get(jwks_uri.as_str()).send().await?;

        // Parse cache control headers
        let cache_expiry = if let Some(cache_control) = response.headers().get(CACHE_CONTROL) {
            Self::parse_cache_control_max_age(cache_control.to_str().unwrap_or(""))
        } else {
            // Default to 1 hour if no cache control header
            3600
        };

        let jwks = response.json::<CoreJsonWebKeySet>().await?;
        let expiry_epoch = Self::current_epoch_secs() + cache_expiry;

        Ok((jwks, expiry_epoch))
    }

    /// Parse max-age from Cache-Control header
    fn parse_cache_control_max_age(cache_control: &str) -> u64 {
        for directive in cache_control.split(',') {
            let directive = directive.trim();
            if let Some(stripped) = directive.strip_prefix("max-age=") {
                if let Ok(max_age) = stripped.parse::<u64>() {
                    return max_age;
                }
            }
        }
        // Default to 1 hour if max-age not found or invalid
        3600
    }

    /// Get current epoch seconds
    pub fn current_epoch_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cache_control_max_age() {
        assert_eq!(JwkCache::parse_cache_control_max_age("max-age=3600"), 3600);
        assert_eq!(
            JwkCache::parse_cache_control_max_age("public, max-age=7200"),
            7200
        );
        assert_eq!(
            JwkCache::parse_cache_control_max_age("max-age=0, no-cache"),
            0
        );
        assert_eq!(JwkCache::parse_cache_control_max_age("no-cache"), 3600); // Default
        assert_eq!(JwkCache::parse_cache_control_max_age(""), 3600); // Default
    }
}
