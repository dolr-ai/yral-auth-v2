use std::{fmt::Display, str::FromStr};

use leptos::prelude::*;

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
    #[error("User has been banned")]
    Banned,
}

impl AuthErrorKind {
    pub fn missing_param(param: impl Into<String>) -> Self {
        Self::MissingParam(param.into())
    }

    pub fn unexpected(msg: impl Display) -> Self {
        Self::Unexpected(msg.to_string())
    }
}
