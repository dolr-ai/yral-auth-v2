#[cfg(feature = "ssr")]
pub mod jwk_cache;
#[cfg(feature = "ssr")]
pub mod jwt;

use std::{
    fmt::{self, Display},
    str::FromStr,
};

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use candid::Principal;
use serde::{Deserialize, Serialize};
use url::Url;
use yral_identity::Signature;

use crate::{consts::ACCESS_TOKEN_MAX_AGE, error::AuthErrorKind};

pub mod client_validation;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SupportedOAuthProviders {
    #[cfg(feature = "google-oauth")]
    Google,
    #[cfg(feature = "apple-oauth")]
    Apple,
    #[cfg(feature = "phone-auth")]
    Phone,
}

impl Display for SupportedOAuthProviders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "google-oauth")]
            Self::Google => write!(f, "google"),
            #[cfg(feature = "apple-oauth")]
            Self::Apple => write!(f, "apple"),
            #[cfg(feature = "phone-auth")]
            Self::Phone => write!(f, "phone"),
            #[allow(unreachable_patterns)]
            _ => Err(fmt::Error),
        }
    }
}

impl FromStr for SupportedOAuthProviders {
    type Err = AuthErrorKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            #[cfg(feature = "google-oauth")]
            "google" => Ok(Self::Google),
            #[cfg(feature = "apple-oauth")]
            "apple" => Ok(Self::Apple),
            #[cfg(feature = "phone-auth")]
            "phone" => Ok(Self::Phone),
            _ => Err(AuthErrorKind::InvalidProvider(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AuthResponse {
    #[serde(rename = "code")]
    Code,
}

impl Display for AuthResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthResponse::Code => write!(f, "code"),
        }
    }
}

impl FromStr for AuthResponse {
    type Err = AuthErrorKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "code" => Ok(Self::Code),
            _ => Err(AuthErrorKind::InvalidResponseType(s.to_string())),
        }
    }
}

use serde::de::{self, Deserializer, Visitor};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    #[serde(rename = "S256")]
    S256,
}

impl FromStr for CodeChallengeMethod {
    type Err = AuthErrorKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "S256" => Ok(Self::S256),
            _ => Err(AuthErrorKind::InvalidCodeChallengeMethod(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CodeChallenge(pub [u8; 32]);

impl Serialize for CodeChallenge {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            // JSON, query params, text formats
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0);

            serializer.serialize_str(&encoded)
        } else {
            // postcard / bincode / binary formats
            serializer.serialize_newtype_struct("CodeChallenge", &self.0)
        }
    }
}

impl<'de> Deserialize<'de> for CodeChallenge {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            // JSON, query params
            struct StrVisitor;

            impl<'de> Visitor<'de> for StrVisitor {
                type Value = CodeChallenge;

                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("a base64url-encoded PKCE code_challenge")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    use std::str::FromStr;
                    CodeChallenge::from_str(v).map_err(E::custom)
                }
            }

            deserializer.deserialize_str(StrVisitor)
        } else {
            // postcard / bincode
            let arr = <[u8; 32]>::deserialize(deserializer)?;
            Ok(CodeChallenge(arr))
        }
    }
}

impl FromStr for CodeChallenge {
    type Err = AuthErrorKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = [0u8; 32];
        let len = BASE64_URL_SAFE_NO_PAD
            .decode_slice(s, &mut res)
            .map_err(|_| AuthErrorKind::InvalidCodeChallenge(s.to_string()))?;
        if len != 32 {
            return Err(AuthErrorKind::InvalidCodeChallenge(s.to_string()));
        }

        Ok(Self(res))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AuthLoginHint {
    pub user_principal: Principal,
    pub signature: Signature,
}

impl FromStr for AuthLoginHint {
    type Err = AuthErrorKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res: Self = serde_json::from_str(s).map_err(|_| AuthErrorKind::InvalidLoginHint)?;

        Ok(res)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct AuthQuery {
    pub response_type: AuthResponse,
    pub client_id: String,
    pub redirect_uri: Url,
    pub state: String,
    pub code_challenge: CodeChallenge,
    pub code_challenge_method: CodeChallengeMethod,
    pub nonce: Option<String>,
    pub login_hint: Option<AuthLoginHint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "grant_type")]
pub enum AuthGrantQuery {
    #[serde(rename = "authorization_code")]
    AuthorizationCode {
        code: String,
        redirect_uri: Url,
        code_verifier: String,
        client_id: String,
        client_secret: Option<String>,
    },
    #[serde(rename = "refresh_token")]
    RefreshToken {
        refresh_token: String,
        client_id: String,
        client_secret: Option<String>,
    },
    #[serde(rename = "client_credentials")]
    ClientCredentials {
        client_id: String,
        client_secret: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthCodeErrorKind {
    #[serde(rename = "invalid_request")]
    InvalidRequest,
    #[serde(rename = "access_denied")]
    AccessDenied,
    #[serde(rename = "unauthorized_client")]
    UnauthorizedClient,
    #[serde(rename = "unsupported_response_type")]
    UnsupportedResponseType,
    #[serde(rename = "server_error")]
    ServerError,
}

impl From<AuthErrorKind> for AuthCodeErrorKind {
    fn from(error: AuthErrorKind) -> Self {
        match error {
            AuthErrorKind::InvalidResponseType(_) => Self::UnsupportedResponseType,
            AuthErrorKind::MissingParam(_) => Self::InvalidRequest,
            AuthErrorKind::Unexpected(_) => Self::ServerError,
            AuthErrorKind::UnauthorizedClient(_) => Self::UnauthorizedClient,
            AuthErrorKind::UnauthorizedRedirectUri(_) => Self::InvalidRequest,
            AuthErrorKind::InvalidUri(_) => Self::InvalidRequest,
            AuthErrorKind::InvalidCodeChallenge(_) => Self::InvalidRequest,
            AuthErrorKind::InvalidCodeChallengeMethod(_) => Self::InvalidRequest,
            AuthErrorKind::InvalidLoginHint => Self::InvalidRequest,
            AuthErrorKind::InvalidProvider(_) => Self::ServerError,
            AuthErrorKind::Banned => Self::AccessDenied,
            AuthErrorKind::InvalidPhoneNumber => Self::InvalidRequest,
            AuthErrorKind::OtpCookieNotFound => Self::InvalidRequest,
            AuthErrorKind::InvalidOtp => Self::InvalidRequest,
            AuthErrorKind::ExpiredOtp => Self::InvalidRequest,
            AuthErrorKind::PhoneMismatch => Self::InvalidRequest,
            AuthErrorKind::AuthClientCookieNotFound => Self::InvalidRequest,
            AuthErrorKind::InvalidOtpToken(_) => Self::InvalidRequest,
        }
    }
}

impl Display for AuthCodeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => write!(f, "invalid_request"),
            Self::AccessDenied => write!(f, "access_denied"),
            Self::UnauthorizedClient => write!(f, "unauthorized_client"),
            Self::UnsupportedResponseType => write!(f, "unsupported_response_type"),
            Self::ServerError => write!(f, "server_error"),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodeError {
    pub error: AuthCodeErrorKind,
    pub error_description: String,
    pub state: Option<String>,
    pub redirect_uri: String,
}

impl AuthCodeError {
    pub fn new(
        error: AuthErrorKind,
        state: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let error_description = error.to_string();
        Self {
            error: error.into(),
            error_description,
            state,
            redirect_uri: redirect_uri.into(),
        }
    }

    pub fn to_redirect(self) -> String {
        let mut res = format!(
            "{}?error={}&error_description={}",
            self.redirect_uri, self.error, self.error_description
        );
        if let Some(state) = self.state {
            res.push_str(&format!("&state={state}"));
        }
        res
    }

    #[cfg(not(feature = "ssr"))]
    pub fn capture(self) -> Self {
        self
    }

    #[cfg(feature = "ssr")]
    pub fn capture(self) -> Self {
        sentry::with_scope(
            |scope| {
                scope.set_tag("flow", "oauth_callback");
                scope.set_tag("error_kind", self.error.to_string());
                scope.set_extra("auth_error_message", self.error_description.clone().into());
            },
            || {
                sentry::capture_message("OAuth callback failed", sentry::Level::Error);
            },
        );

        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenGrantErrorKind {
    #[serde(rename = "invalid_request")]
    InvalidRequest,
    #[serde(rename = "invalid_client")]
    InvalidClient,
    #[serde(rename = "invalid_grant")]
    InvalidGrant,
    #[serde(rename = "unauthorized_client")]
    UnauthorizedClient,
    #[serde(rename = "unsupported_grant_type")]
    UnsupportedGrantType,
    #[serde(rename = "invalid_scope")]
    InvalidScope,
    #[serde(rename = "server_error")]
    ServerError,
}

impl TokenGrantErrorKind {
    #[cfg(feature = "ssr")]
    pub fn status_code(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;

        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::InvalidClient => StatusCode::UNAUTHORIZED,
            Self::InvalidGrant => StatusCode::UNAUTHORIZED,
            Self::UnauthorizedClient => StatusCode::UNAUTHORIZED,
            Self::UnsupportedGrantType => StatusCode::BAD_REQUEST,
            Self::InvalidScope => StatusCode::BAD_REQUEST,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenGrantError {
    pub error: TokenGrantErrorKind,
    pub error_description: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TokenType {
    Bearer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenGrantRes {
    pub access_token: String,
    pub id_token: String,
    pub token_type: TokenType,
    // seconds
    pub expires_in: usize,
    pub refresh_token: String,
}

impl TokenGrantRes {
    pub fn new(access_token: String, id_token: String, refresh_token: String) -> Self {
        Self {
            access_token,
            id_token,
            token_type: TokenType::Bearer,
            expires_in: ACCESS_TOKEN_MAX_AGE.as_secs() as usize,
            refresh_token,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TokenGrantResult {
    Ok(TokenGrantRes),
    Err(TokenGrantError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialOIDCConfig {
    pub jwks_uri: String,
}
