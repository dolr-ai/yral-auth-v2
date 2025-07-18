#[cfg(test)]
mod tests;
mod whitelist;

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};

use crate::{
    consts::{
        ACCESS_TOKEN_MAX_AGE, BACKEND_ACCESS_TOKEN_MAX_AGE, BACKEND_REFRESH_TOKEN_MAX_AGE,
        REFRESH_TOKEN_MAX_AGE,
    },
    error::AuthErrorKind,
    oauth::client_validation::whitelist::default_oauth_clients,
};
use enum_dispatch::enum_dispatch;
use regex::Regex;
use url::Url;
use web_time::Duration;

pub struct ValidationRes {
    pub kind: OAuthClientType,
    pub access_max_age: Duration,
    pub refresh_max_age: Duration,
}

impl From<OAuthClientType> for ValidationRes {
    fn from(client_type: OAuthClientType) -> Self {
        match client_type {
            OAuthClientType::BackendService => Self {
                kind: client_type,
                access_max_age: BACKEND_ACCESS_TOKEN_MAX_AGE,
                refresh_max_age: BACKEND_REFRESH_TOKEN_MAX_AGE,
            },
            _ => Self {
                kind: client_type,
                access_max_age: ACCESS_TOKEN_MAX_AGE,
                refresh_max_age: REFRESH_TOKEN_MAX_AGE,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OAuthClientType {
    Web,
    Native,
    Preview,
    BackendService,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OAuthClient {
    pub client_id: String,
    pub redirect_urls: Vec<Url>,
    pub client_type: OAuthClientType,
}

#[enum_dispatch]
pub(crate) trait ClientIdValidator {
    async fn lookup_client(&self, client_id: &str) -> Result<&OAuthClient, AuthErrorKind>;

    async fn validate_id_and_redirect(
        &self,
        client_id: &str,
        redirect_uri: &Url,
    ) -> Result<(), AuthErrorKind> {
        let client = self.lookup_client(client_id).await?;
        self.validate_redirect_uri(client, Some(redirect_uri))?;

        Ok(())
    }

    fn validate_redirect_uri(
        &self,
        client: &OAuthClient,
        redirect_uri: Option<&Url>,
    ) -> Result<(), AuthErrorKind> {
        let Some(redirect_uri) = redirect_uri else {
            return Ok(());
        };

        if client.client_type == OAuthClientType::Preview {
            static PR_PREVIEW_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
                Regex::new(r"^(https:\/\/)?pr-\d*-dolr-ai-hot-or-not-web-leptos-ssr\.fly\.dev\/auth\/google_redirect$")
                    .unwrap()
            });

            let valid = PR_PREVIEW_PATTERN.is_match_at(redirect_uri.as_str(), 0);
            if valid {
                return Ok(());
            } else {
                return Err(AuthErrorKind::UnauthorizedRedirectUri(
                    redirect_uri.to_string(),
                ));
            }
        }

        if !client.redirect_urls.contains(redirect_uri) {
            return Err(AuthErrorKind::UnauthorizedRedirectUri(
                redirect_uri.to_string(),
            ));
        }

        Ok(())
    }

    #[cfg(feature = "ssr")]
    async fn full_validation(
        &self,
        validation_key: &jsonwebtoken::DecodingKey,
        client_id: &str,
        redirect_uri: Option<&Url>,
        client_secret: Option<&str>,
    ) -> Result<ValidationRes, AuthErrorKind> {
        use crate::oauth::jwt::ClientSecretClaims;

        let client = self.lookup_client(client_id).await?;
        self.validate_redirect_uri(client, redirect_uri)?;

        if client.client_type == OAuthClientType::Native {
            return Ok(client.client_type.into());
        }

        let Some(client_secret) = client_secret else {
            return Err(AuthErrorKind::UnauthorizedClient(client_id.to_string()));
        };

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_audience(&[client_id]);

        jsonwebtoken::decode::<ClientSecretClaims>(client_secret, validation_key, &validation)
            .map_err(|_| AuthErrorKind::UnauthorizedClient(client_id.to_string()))?;

        Ok(client.client_type.into())
    }
}

impl<T: ClientIdValidator> ClientIdValidator for Arc<T> {
    async fn lookup_client(&self, client_id: &str) -> Result<&OAuthClient, AuthErrorKind> {
        self.as_ref().lookup_client(client_id).await
    }
}

pub struct ConstClientIdValidator {
    clients: HashMap<String, OAuthClient>,
}

impl Default for ConstClientIdValidator {
    fn default() -> Self {
        Self {
            clients: default_oauth_clients(),
        }
    }
}

impl ClientIdValidator for ConstClientIdValidator {
    async fn lookup_client(&self, client_id: &str) -> Result<&OAuthClient, AuthErrorKind> {
        self.clients
            .get(client_id)
            .ok_or_else(|| AuthErrorKind::UnauthorizedClient(client_id.to_string()))
    }
}

#[derive(Clone)]
#[enum_dispatch(ClientIdValidator)]
pub enum ClientIdValidatorImpl {
    Const(Arc<ConstClientIdValidator>),
}
