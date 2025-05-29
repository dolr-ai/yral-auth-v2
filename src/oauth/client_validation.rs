use std::sync::{Arc, LazyLock};

use crate::error::AuthErrorKind;
use enum_dispatch::enum_dispatch;
use regex::Regex;
use url::Url;

#[derive(Debug, Clone, PartialEq)]
pub enum OAuthClientType {
    Web,
    Native,
    Preview,
}

#[derive(Debug, Clone)]
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
                Regex::new(r"^(https:\/\/)?pr-\d*-dolr-ai-hot-or-not-web-leptos-ssr\.fly\.dev$")
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
    ) -> Result<(), AuthErrorKind> {
        use crate::oauth::jwt::ClientSecretClaims;

        let client = self.lookup_client(client_id).await?;
        self.validate_redirect_uri(client, redirect_uri)?;

        if client.client_type == OAuthClientType::Native {
            return Ok(());
        }

        let Some(client_secret) = client_secret else {
            return Err(AuthErrorKind::UnauthorizedClient(client_id.to_string()));
        };

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_audience(&[client_id]);

        jsonwebtoken::decode::<ClientSecretClaims>(client_secret, validation_key, &validation)
            .map_err(|_| AuthErrorKind::UnauthorizedClient(client_id.to_string()))?;

        Ok(())
    }
}

impl<T: ClientIdValidator> ClientIdValidator for Arc<T> {
    async fn lookup_client(&self, client_id: &str) -> Result<&OAuthClient, AuthErrorKind> {
        self.as_ref().lookup_client(client_id).await
    }
}

pub struct ConstClientIdValidator {
    clients: Vec<OAuthClient>,
}

impl Default for ConstClientIdValidator {
    fn default() -> Self {
        Self {
            clients: vec![
                // Yral
                OAuthClient {
                    client_id: "31122c67-4801-4e70-82f0-08e12daa4f2d".to_string(),
                    redirect_urls: vec!["https://localhost:3000/".parse().unwrap()],
                    client_type: OAuthClientType::Web,
                },
                // Yral IOS
                OAuthClient {
                    client_id: "e1a6a7fb-8a1d-42dc-87b4-13ff94ecbe34".to_string(),
                    redirect_urls: vec![
                        "com.yral.iosApp://oauth/callback".parse().unwrap(),
                        "com.yral.iosApp.staging://oauth/callback".parse().unwrap(),
                    ],
                    client_type: OAuthClientType::Native,
                },
                // Yral Next.js
                OAuthClient {
                    client_id: "6a0101eb-8496-4afb-ba48-425187c3a30d".to_string(),
                    redirect_urls: vec![
                        "https://pumpdump.wtf/api/oauth/callback".parse().unwrap(),
                        "https://pd.dev/api/oauth/callback".parse().unwrap(),
                        "http://localhost:5190/api/oauth/callback".parse().unwrap(),
                        "https://pump-dump-kit.fly.dev/api/oauth/callback"
                            .parse()
                            .unwrap(),
                    ],
                    client_type: OAuthClientType::Web,
                },
                OAuthClient {
                    client_id: "c89b29de-8366-4e62-9b9e-c29585740acf".to_string(),
                    redirect_urls: vec!["yral://oauth/callback".parse().unwrap()],
                    client_type: OAuthClientType::Native,
                },
                OAuthClient {
                    client_id: "5c86a459-493d-463e-965d-be6ed74f3e5f".to_string(),
                    redirect_urls: vec![],
                    client_type: OAuthClientType::Preview,
                },
            ],
        }
    }
}

impl ClientIdValidator for ConstClientIdValidator {
    async fn lookup_client(&self, client_id: &str) -> Result<&OAuthClient, AuthErrorKind> {
        let client = self.clients.iter().find(|c| c.client_id == client_id);
        let Some(client) = client else {
            return Err(AuthErrorKind::UnauthorizedClient(client_id.to_string()));
        };
        Ok(client)
    }
}

#[derive(Clone)]
#[enum_dispatch(ClientIdValidator)]
pub enum ClientIdValidatorImpl {
    Const(Arc<ConstClientIdValidator>),
}
