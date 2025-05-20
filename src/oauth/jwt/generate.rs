use candid::Principal;
use yral_types::delegated_identity::DelegatedIdentityWire;

use super::{AccessTokenClaims, AuthCodeClaims, IdTokenClaims, RefreshTokenClaims};
use crate::{
    consts::{ACCESS_TOKEN_MAX_AGE, REFRESH_TOKEN_MAX_AGE},
    oauth::AuthQuery,
    utils::time::current_epoch_secs,
};

pub fn generate_code_grant_jwt(
    encoding_key: &jsonwebtoken::EncodingKey,
    user_principal: Principal,
    host: &str,
    query: AuthQuery,
) -> String {
    let iat = current_epoch_secs();

    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
        &AuthCodeClaims {
            aud: query.client_id.clone(),
            iat,
            exp: iat + 10 * 60,
            iss: host.to_string(),
            sub: user_principal,
            ext_redirect_uri: query.redirect_uri,
            nonce: query.nonce,
            ext_code_challenge_s256: query.code_challenge,
        },
        encoding_key,
    )
    .expect("Failed to encode JWT")
}

/// Generates access token and id token JWTs
/// the first token is the access token
/// the second token is the id token
pub fn generate_access_token_and_id_token_jwt(
    encoding_key: &jsonwebtoken::EncodingKey,
    user_principal: Principal,
    identity: DelegatedIdentityWire,
    host: &str,
    client_id: &str,
    nonce: Option<String>,
    is_anonymous: bool,
) -> (String, String) {
    let iat = current_epoch_secs();

    let access_claims = AccessTokenClaims {
        aud: client_id.to_string(),
        exp: iat + ACCESS_TOKEN_MAX_AGE.as_secs() as usize,
        iat,
        iss: host.to_string(),
        sub: user_principal,
        nonce: nonce.clone(),
        ext_is_anonymous: is_anonymous,
    };
    let id_claims = IdTokenClaims {
        aud: client_id.to_string(),
        exp: iat + ACCESS_TOKEN_MAX_AGE.as_secs() as usize,
        iat,
        iss: host.to_string(),
        sub: user_principal,
        nonce,
        ext_is_anonymous: is_anonymous,
        ext_delegated_identity: identity,
    };

    let access_token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
        &access_claims,
        encoding_key,
    )
    .expect("failed to encode JWT");
    let id_token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
        &id_claims,
        encoding_key,
    )
    .expect("failed to encode JWT");

    (access_token, id_token)
}

pub fn generate_refresh_token_jwt(
    encoding_key: &jsonwebtoken::EncodingKey,
    user_principal: Principal,
    host: &str,
    client_id: &str,
    nonce: Option<String>,
    is_anonymous: bool,
) -> String {
    let iat = current_epoch_secs();

    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
        &RefreshTokenClaims {
            aud: client_id.to_string(),
            exp: iat + REFRESH_TOKEN_MAX_AGE.as_secs() as usize,
            iat,
            iss: host.to_string(),
            sub: user_principal,
            nonce,
            ext_is_anonymous: is_anonymous,
        },
        encoding_key,
    )
    .expect("failed to encode JWT")
}
