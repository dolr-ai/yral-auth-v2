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
pub enum SupportedOAuthProviders {
    Google,
    Apple,
}

impl Display for SupportedOAuthProviders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Google => write!(f, "google"),
            Self::Apple => write!(f, "apple"),
        }
    }
}

impl FromStr for SupportedOAuthProviders {
    type Err = AuthErrorKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "google" => Ok(Self::Google),
            "apple" => Ok(Self::Apple),
            _ => Err(AuthErrorKind::InvalidProvider(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AuthResponseCode;

impl FromStr for AuthResponseCode {
    type Err = AuthErrorKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "code" => Ok(Self),
            _ => Err(AuthErrorKind::InvalidResponseType(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CodeChallengeMethodS256;

impl FromStr for CodeChallengeMethodS256 {
    type Err = AuthErrorKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "S256" => Ok(Self),
            _ => Err(AuthErrorKind::InvalidCodeChallengeMethod(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CodeChallenge(pub [u8; 32]);

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

pub fn login_hint_message() -> yral_identity::msg_builder::Message {
    use yral_identity::msg_builder::Message;

    Message::default().method_name("yral_auth_v2_login_hint".into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct AuthQuery {
    pub response_type: AuthResponseCode,
    pub client_id: String,
    pub redirect_uri: Url,
    pub state: String,
    pub code_challenge: CodeChallenge,
    pub code_challenge_method: CodeChallengeMethodS256,
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
