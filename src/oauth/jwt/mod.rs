use candid::Principal;
use serde::{Deserialize, Serialize};
use url::Url;
use yral_types::delegated_identity::DelegatedIdentityWire;

use super::CodeChallenge;

#[cfg(feature = "ssr")]
pub mod generate;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodeClaims {
    aud: String,
    exp: usize,
    iat: usize,
    iss: String,
    pub sub: Principal,
    pub ext_redirect_uri: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub ext_code_challenge_s256: CodeChallenge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokenClaims {
    aud: String,
    exp: usize,
    iat: usize,
    iss: String,
    sub: Principal,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    ext_is_anonymous: bool,
    ext_delegated_identity: DelegatedIdentityWire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    aud: String,
    exp: usize,
    iat: usize,
    iss: String,
    pub sub: Principal,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    pub ext_is_anonymous: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSecretClaims {
    aud: String,
    exp: usize,
    iat: usize,
    iss: String,
    pub sub: String,
}
