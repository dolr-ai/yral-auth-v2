use std::fmt::Display;

use leptos::{prelude::*, server_fn::codec::JsonEncoding};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
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

use serde::de::{self, Deserializer, Visitor};
use serde::ser::Serializer;
use std::fmt;

impl serde::Serialize for AuthErrorKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let name = match self {
            AuthErrorKind::InvalidResponseType(_) => "InvalidResponseType",
            AuthErrorKind::MissingParam(_) => "MissingParam",
            AuthErrorKind::Unexpected(_) => "Unexpected",
            AuthErrorKind::UnauthorizedClient(_) => "UnauthorizedClient",
            AuthErrorKind::UnauthorizedRedirectUri(_) => "UnauthorizedRedirectUri",
            AuthErrorKind::InvalidUri(_) => "InvalidUri",
            AuthErrorKind::InvalidCodeChallengeMethod(_) => "InvalidCodeChallengeMethod",
            AuthErrorKind::InvalidCodeChallenge(_) => "InvalidCodeChallenge",
            AuthErrorKind::InvalidProvider(_) => "InvalidProvider",
            AuthErrorKind::InvalidLoginHint => "InvalidLoginHint",
            AuthErrorKind::InvalidPhoneNumber => "InvalidPhoneNumber",
            AuthErrorKind::Banned => "Banned",
            AuthErrorKind::OtpCookieNotFound => "OtpCookieNotFound",
            AuthErrorKind::InvalidOtp => "InvalidOtp",
            AuthErrorKind::ExpiredOtp => "ExpiredOtp",
            AuthErrorKind::PhoneMismatch => "PhoneMismatch",
            AuthErrorKind::AuthClientCookieNotFound => "AuthClientCookieNotFound",
            AuthErrorKind::InvalidOtpToken(_) => "InvalidOtpToken",
        };
        serializer.serialize_str(name)
    }
}

impl<'de> serde::Deserialize<'de> for AuthErrorKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VariantVisitor;
        impl<'de> Visitor<'de> for VariantVisitor {
            type Value = AuthErrorKind;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string representing AuthErrorKind variant name")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match v {
                    "InvalidResponseType" => Ok(AuthErrorKind::InvalidResponseType(String::new())),
                    "MissingParam" => Ok(AuthErrorKind::MissingParam(String::new())),
                    "Unexpected" => Ok(AuthErrorKind::Unexpected(String::new())),
                    "UnauthorizedClient" => Ok(AuthErrorKind::UnauthorizedClient(String::new())),
                    "UnauthorizedRedirectUri" => {
                        Ok(AuthErrorKind::UnauthorizedRedirectUri(String::new()))
                    }
                    "InvalidUri" => Ok(AuthErrorKind::InvalidUri(String::new())),
                    "InvalidCodeChallengeMethod" => {
                        Ok(AuthErrorKind::InvalidCodeChallengeMethod(String::new()))
                    }
                    "InvalidCodeChallenge" => {
                        Ok(AuthErrorKind::InvalidCodeChallenge(String::new()))
                    }
                    "InvalidProvider" => Ok(AuthErrorKind::InvalidProvider(String::new())),
                    "InvalidLoginHint" => Ok(AuthErrorKind::InvalidLoginHint),
                    "InvalidPhoneNumber" => Ok(AuthErrorKind::InvalidPhoneNumber),
                    "Banned" => Ok(AuthErrorKind::Banned),
                    "OtpCookieNotFound" => Ok(AuthErrorKind::OtpCookieNotFound),
                    "InvalidOtp" => Ok(AuthErrorKind::InvalidOtp),
                    "ExpiredOtp" => Ok(AuthErrorKind::ExpiredOtp),
                    "PhoneMismatch" => Ok(AuthErrorKind::PhoneMismatch),
                    "AuthClientCookieNotFound" => Ok(AuthErrorKind::AuthClientCookieNotFound),
                    "InvalidOtpToken" => Ok(AuthErrorKind::InvalidOtpToken(String::new())),
                    _ => Err(E::unknown_variant(
                        v,
                        &[
                            "InvalidResponseType",
                            "MissingParam",
                            "Unexpected",
                            "UnauthorizedClient",
                            "UnauthorizedRedirectUri",
                            "InvalidUri",
                            "InvalidCodeChallengeMethod",
                            "InvalidCodeChallenge",
                            "InvalidProvider",
                            "InvalidLoginHint",
                            "InvalidPhoneNumber",
                            "Banned",
                            "OtpCookieNotFound",
                            "InvalidOtp",
                            "ExpiredOtp",
                            "PhoneMismatch",
                            "AuthClientCookieNotFound",
                            "InvalidOtpToken",
                        ],
                    )),
                }
            }
        }
        deserializer.deserialize_str(VariantVisitor)
    }
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
            AuthErrorKind::unexpected(format!("Server function error: {}", value));
        AuthError {
            error_description: auth_error_kind.to_string(),
            error: auth_error_kind,
        }
    }
}

#[cfg(feature = "ssr")]
impl AuthErrorKind {
    pub fn status_code(&self) -> axum::http::StatusCode {
        match &self {
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
        }
    }
}
