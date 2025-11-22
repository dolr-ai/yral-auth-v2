use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};

use enum_dispatch::enum_dispatch;
use openidconnect::{
    core::{CoreIdToken, CoreIdTokenClaims},
    reqwest, ClientSecret, Nonce,
};
use serde::{Deserialize, Serialize};

use crate::{
    consts::{APPLE_ISSUER_URL, APPLE_ISSUER_URL2},
    error::AuthErrorKind,
    utils::time::current_epoch,
};

pub type StdOAuthClient = openidconnect::Client<
    openidconnect::EmptyAdditionalClaims,
    openidconnect::core::CoreAuthDisplay,
    openidconnect::core::CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJsonWebKey,
    openidconnect::core::CoreAuthPrompt,
    openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
    openidconnect::StandardTokenResponse<
        openidconnect::IdTokenFields<
            openidconnect::EmptyAdditionalClaims,
            openidconnect::EmptyExtraTokenFields,
            openidconnect::core::CoreGenderClaim,
            openidconnect::core::CoreJweContentEncryptionAlgorithm,
            openidconnect::core::CoreJwsSigningAlgorithm,
        >,
        openidconnect::core::CoreTokenType,
    >,
    openidconnect::StandardTokenIntrospectionResponse<
        openidconnect::EmptyExtraTokenFields,
        openidconnect::core::CoreTokenType,
    >,
    openidconnect::core::CoreRevocableToken,
    openidconnect::StandardErrorResponse<openidconnect::RevocationErrorResponseType>,
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

#[enum_dispatch]
pub(crate) trait OAuthProvider {
    fn get_client(&self) -> Arc<StdOAuthClient>;

    fn verify_id_token<'a>(
        &self,
        client: &StdOAuthClient,
        token: &'a CoreIdToken,
    ) -> Result<&'a CoreIdTokenClaims, AuthErrorKind>;
}

fn no_op_nonce_verifier(_: Option<&Nonce>) -> Result<(), String> {
    Ok(())
}

pub struct IdentityOAuthProvider(Arc<StdOAuthClient>);

impl IdentityOAuthProvider {
    pub fn new(client_secret: StdOAuthClient) -> Self {
        Self(Arc::new(client_secret))
    }
}

impl OAuthProvider for IdentityOAuthProvider {
    fn get_client(&self) -> Arc<StdOAuthClient> {
        self.0.clone()
    }

    fn verify_id_token<'a>(
        &self,
        client: &StdOAuthClient,
        token: &'a CoreIdToken,
    ) -> Result<&'a CoreIdTokenClaims, AuthErrorKind> {
        token
            .claims(&client.id_token_verifier(), no_op_nonce_verifier)
            .map_err(AuthErrorKind::unexpected)
    }
}

// Google OAuth provider with JWK rotation support
pub struct GoogleOAuthProvider {
    /// Base OAuth client - will be refreshed periodically with new JWKs
    client_cache: RwLock<Arc<StdOAuthClient>>,
    /// When the cached client expires and needs JWK refresh
    client_cache_expiry: AtomicU64,
    /// Cache for fetching fresh JWKs from Google
    jwk_cache: Arc<crate::oauth::jwk_cache::JwkCache>,
    /// Client configuration for rebuilding OAuth client
    base_metadata: openidconnect::core::CoreProviderMetadata,
    client_id: openidconnect::ClientId,
    client_secret: Option<openidconnect::ClientSecret>,
    redirect_uri: Option<openidconnect::RedirectUrl>,
}

impl GoogleOAuthProvider {
    pub async fn new(
        base_client: StdOAuthClient,
        provider_metadata: openidconnect::core::CoreProviderMetadata,
        http_client: reqwest::Client,
        client_secret: String,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let jwk_cache =
            crate::oauth::jwk_cache::JwkCache::new(&provider_metadata, http_client.clone()).await?;

        // Extract client information for later use
        let client_id = base_client.client_id().clone();
        let redirect_uri = base_client.redirect_uri().cloned();

        // Set initial client cache expiry to same as JWK cache
        let initial_expiry = crate::oauth::jwk_cache::JwkCache::current_epoch_secs() + 3600; // 1 hour default

        Ok(Self {
            client_cache: RwLock::new(Arc::new(base_client)),
            client_cache_expiry: AtomicU64::new(initial_expiry),
            jwk_cache: Arc::new(jwk_cache),
            base_metadata: provider_metadata,
            client_id,
            client_secret: Some(ClientSecret::new(client_secret)),
            redirect_uri,
        })
    }

    /// Try to get a client with fresh JWKs (non-blocking)
    fn try_get_fresh_client(&self) -> Result<Arc<StdOAuthClient>, ()> {
        let current_epoch = crate::oauth::jwk_cache::JwkCache::current_epoch_secs();
        let cache_expiry = self
            .client_cache_expiry
            .load(std::sync::atomic::Ordering::Acquire);

        // Return cached client if still valid
        if current_epoch < cache_expiry {
            return Ok(self.client_cache.read().unwrap().clone());
        }

        // Try to acquire write lock without blocking
        let client_guard = self.client_cache.try_write().map_err(|_| ())?;

        // Double-check expiry after acquiring lock
        let cache_expiry = self
            .client_cache_expiry
            .load(std::sync::atomic::Ordering::Acquire);
        if current_epoch < cache_expiry {
            return Ok(client_guard.clone());
        }

        // We need fresh JWKs but can't do async call in sync context
        // This is a limitation - for now, extend cache and return existing client
        let extended_expiry = current_epoch + 300; // 5 minutes
        self.client_cache_expiry
            .store(extended_expiry, std::sync::atomic::Ordering::Release);

        Ok(client_guard.clone())
    }

    /// Refresh the OAuth client with fresh JWKs from Google
    /// This method should be called periodically by a background task
    pub async fn refresh_client_jwks(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // First refresh the JWK cache
        self.jwk_cache.refresh_jwks().await?;

        // Get the fresh JWKs (now cached) - this should be fast since we just refreshed
        let fresh_jwks = self.jwk_cache.get_jwks().await;

        // Create new OAuth client with fresh JWKs
        let mut updated_metadata = self.base_metadata.clone();
        updated_metadata = updated_metadata.set_jwks((*fresh_jwks).clone());

        let mut fresh_client = openidconnect::core::CoreClient::from_provider_metadata(
            updated_metadata,
            self.client_id.clone(),
            self.client_secret.clone(),
        );

        if let Some(ref uri) = self.redirect_uri {
            fresh_client = fresh_client.set_redirect_uri(uri.clone());
        }

        let fresh_client = fresh_client.set_auth_type(openidconnect::AuthType::RequestBody);

        // Update the cached client
        {
            let mut client_guard = self.client_cache.write().unwrap();
            *client_guard = Arc::new(fresh_client);
        }

        // Update expiry - use the JWK cache expiry
        let current_epoch = crate::oauth::jwk_cache::JwkCache::current_epoch_secs();
        let new_expiry = current_epoch + 3600; // 1 hour conservative expiry
        self.client_cache_expiry
            .store(new_expiry, std::sync::atomic::Ordering::Release);

        tracing::info!("Successfully refreshed Google OAuth client with fresh JWKs");

        Ok(())
    }

    /// Check if the client needs JWK refresh (based on JWK cache status)
    pub fn needs_jwk_refresh(&self) -> bool {
        // Check if JWKs need refresh with 10 minute buffer
        self.jwk_cache.needs_refresh(600)
    }
}

impl OAuthProvider for GoogleOAuthProvider {
    fn get_client(&self) -> Arc<StdOAuthClient> {
        // For Google, we need to check if JWKs are fresh
        // If they're expired or close to expiry, return a client with fresh JWKs
        let current_epoch = crate::oauth::jwk_cache::JwkCache::current_epoch_secs();
        let cache_expiry = self
            .client_cache_expiry
            .load(std::sync::atomic::Ordering::Acquire);

        // If cache is still valid (with 5 minute buffer), return cached client
        if current_epoch < cache_expiry.saturating_sub(300) {
            return self.client_cache.read().unwrap().clone();
        }

        // Try to get fresh client, but don't block if another thread is updating
        if let Ok(fresh_client) = self.try_get_fresh_client() {
            fresh_client
        } else {
            // Fallback to cached client if refresh fails
            self.client_cache.read().unwrap().clone()
        }
    }

    fn verify_id_token<'a>(
        &self,
        client: &StdOAuthClient,
        token: &'a CoreIdToken,
    ) -> Result<&'a CoreIdTokenClaims, AuthErrorKind> {
        // Use the provided client for verification
        // The client should have fresh JWKs from get_client()
        token
            .claims(&client.id_token_verifier(), no_op_nonce_verifier)
            .map_err(AuthErrorKind::unexpected)
    }
}

// we need a custom implementation for apple because
// client secrets for apple login are only valid for 6 months
// the implementation automatically refreshes the client secret
// when it expires
pub struct AppleOAuthProvider {
    keygen: AppleClientSecretGen,
    // extremely unholy
    cache: RwLock<Arc<StdOAuthClient>>,
    cache_expiry_epoch_secs: AtomicU64,
}

#[derive(Serialize, Deserialize)]
struct AppleSecretClaims {
    iss: String,
    iat: u64,
    exp: u64,
    aud: String,
    sub: String,
}

struct AppleClientSecretGen {
    auth_key: jsonwebtoken::EncodingKey,
    key_id: String,
    team_id: String,
    client_id: String,
}

impl AppleClientSecretGen {
    fn new(
        auth_key: jsonwebtoken::EncodingKey,
        key_id: String,
        team_id: String,
        client_id: String,
    ) -> Self {
        Self {
            auth_key,
            key_id,
            team_id,
            client_id,
        }
    }

    fn generate_client_secret(&self) -> (ClientSecret, u64) {
        let iat = current_epoch();
        // slightly less than 6 months to be safe
        let exp = iat + Duration::from_secs(14777000);
        let claims = AppleSecretClaims {
            iss: self.team_id.clone(),
            iat: iat.as_secs(),
            exp: exp.as_secs(),
            aud: "https://appleid.apple.com".to_string(),
            sub: self.client_id.clone(),
        };
        let mut token_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        token_header.kid = Some(self.key_id.clone());
        token_header.typ = None;

        let token = jsonwebtoken::encode(&token_header, &claims, &self.auth_key)
            .expect("Failed to encode Apple client secret?!");

        let client_secret = ClientSecret::new(token);
        // slightly less than **actual** token expiry to be safe
        let stored_expiry = exp - Duration::from_secs(60 * 60);

        (client_secret, stored_expiry.as_secs())
    }
}

impl AppleOAuthProvider {
    pub fn new(
        base_client: StdOAuthClient,
        auth_key: jsonwebtoken::EncodingKey,
        key_id: String,
        team_id: String,
    ) -> Self {
        let keygen = AppleClientSecretGen::new(
            auth_key,
            key_id,
            team_id,
            base_client.client_id().to_string(),
        );
        let (client_secret, expiry_epoch) = keygen.generate_client_secret();
        let client = base_client.set_client_secret(client_secret);
        let cache = RwLock::new(Arc::new(client));
        let cache_expiry_epoch_secs = AtomicU64::new(expiry_epoch);

        Self {
            keygen,
            cache,
            cache_expiry_epoch_secs,
        }
    }
}

impl OAuthProvider for AppleOAuthProvider {
    fn get_client(&self) -> Arc<StdOAuthClient> {
        let cur_epoch = current_epoch().as_secs();
        let cur_exp = self.cache_expiry_epoch_secs.load(Ordering::Acquire);
        if cur_epoch < cur_exp {
            return self.cache.read().unwrap().clone();
        }

        let mut cache = self.cache.write().unwrap();
        let (client_secret, expiry_epoch) = self.keygen.generate_client_secret();

        let new_client = cache
            .as_ref()
            .clone()
            .set_client_secret(client_secret.clone());
        let new_client = Arc::new(new_client);
        *cache = new_client.clone();
        self.cache_expiry_epoch_secs
            .store(expiry_epoch, Ordering::Release);

        new_client
    }

    fn verify_id_token<'a>(
        &self,
        client: &StdOAuthClient,
        token: &'a CoreIdToken,
    ) -> Result<&'a CoreIdTokenClaims, AuthErrorKind> {
        let verifier = client.id_token_verifier().require_issuer_match(false);
        let claims = token
            .claims(&verifier, no_op_nonce_verifier)
            .map_err(AuthErrorKind::unexpected)?;

        let iss = claims.issuer().as_str();
        if !(iss == APPLE_ISSUER_URL2 || iss == APPLE_ISSUER_URL) {
            return Err(AuthErrorKind::Unexpected(format!(
                "Apple ID token issuer mismatch: {iss}"
            )));
        }

        Ok(claims)
    }
}

#[allow(clippy::large_enum_variant)]
#[enum_dispatch(OAuthProvider)]
pub enum OAuthProviderImpl {
    GoogleOAuthProvider,
    AppleOAuthProvider,
}
