use std::fmt::Display;

use leptos::{prelude::*, server_fn::codec::JsonEncoding};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum AuthErrorKind {
    #[error("Invalid response type: {0}")]
    InvalidResponseType(String),
    #[error("Missing auth query parameter: {0}")]
    MissingParam(String),
    #[error("Unexpected error: {0}")]
    Unexpected(String),
    #[error("Unauthorized client: {0}")]
    UnauthorizedClient(String),
    #[error("Unauthorized redirect URI: {0}")]
    UnauthorizedRedirectUri(String),
    #[error("Invalid URI: {0}")]
    InvalidUri(String),
    #[error("Invalid code challenge method: {0}, supported methods: S256")]
    InvalidCodeChallengeMethod(String),
    #[error("Invalid code challenge: {0}")]
    InvalidCodeChallenge(String),
    #[error("Invalid provider: {0}")]
    InvalidProvider(String),
    #[error("Invalid login hint")]
    InvalidLoginHint,
    #[error("Invalid phone number")]
    InvalidPhoneNumber,
    #[error("User has been banned")]
    Banned,
    // Merged from VerifyPhoneErrorKind
    #[error("OTP cookie not found")]
    OtpCookieNotFound,
    #[error("Invalid OTP code")]
    InvalidOtp,
    #[error("Expired OTP")]
    ExpiredOtp,
    #[error("Phone number mismatch")]
    PhoneMismatch,
    #[error("Auth client cookie not found")]
    AuthClientCookieNotFound,
    #[error("Invalid OTP token: {0}")]
    InvalidOtpToken(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Error)]
pub struct AuthError {
    error: AuthErrorKind,
    error_description: String,
}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error_description)
    }
}

impl From<AuthErrorKind> for AuthError {
    fn from(value: AuthErrorKind) -> Self {
        AuthError {
            error_description: value.to_string(),
            error: value,
        }
    }
}

impl AuthErrorKind {
    pub fn missing_param(param: impl Into<String>) -> Self {
        Self::MissingParam(param.into())
    }

    pub fn unexpected(msg: impl Display) -> Self {
        Self::Unexpected(msg.to_string())
    }
}

impl FromServerFnError for AuthError {
    type Encoder = JsonEncoding;

    fn from_server_fn_error(value: ServerFnErrorErr) -> Self {
        let auth_error_kind =
            AuthErrorKind::unexpected(format!("Server function error: {}", value.to_string()));
        AuthError {
            error_description: auth_error_kind.to_string(),
            error: auth_error_kind,
        }
    }
}

#[cfg(feature = "ssr")]
impl AuthErrorKind {
    pub fn status_code(&self) -> axum::http::StatusCode {
        let status_code = match &self {
            AuthErrorKind::InvalidUri(_)
            | AuthErrorKind::InvalidCodeChallengeMethod(_)
            | AuthErrorKind::InvalidCodeChallenge(_)
            | AuthErrorKind::InvalidProvider(_)
            | AuthErrorKind::InvalidLoginHint
            | AuthErrorKind::InvalidPhoneNumber
            | AuthErrorKind::UnauthorizedClient(_)
            | AuthErrorKind::UnauthorizedRedirectUri(_)
            | AuthErrorKind::InvalidResponseType(_)
            | AuthErrorKind::MissingParam(_)
            | AuthErrorKind::InvalidOtp
            | AuthErrorKind::ExpiredOtp
            | AuthErrorKind::PhoneMismatch
            | AuthErrorKind::AuthClientCookieNotFound
            | AuthErrorKind::OtpCookieNotFound
            | AuthErrorKind::InvalidOtpToken(_) => axum::http::StatusCode::BAD_REQUEST,

            AuthErrorKind::Banned => axum::http::StatusCode::FORBIDDEN,
            AuthErrorKind::Unexpected(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        };

        status_code
    }
}
