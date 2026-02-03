use web_time::Duration;

use candid::Principal;
use yral_types::delegated_identity::DelegatedIdentityWire;

use super::{AccessTokenClaims, AuthCodeClaims, IdTokenClaims, RefreshTokenClaims};
use crate::{consts::AUTH_TOKEN_KID, oauth::AuthQuery, utils::time::current_epoch_secs};

pub fn generate_code_grant_jwt(
    encoding_key: &jsonwebtoken::EncodingKey,
    user_principal: Principal,
    server_url: &str,
    query: AuthQuery,
    email: Option<String>,
) -> String {
    let iat = current_epoch_secs();

    jsonwebtoken::encode(
        &jwt_header(),
        &AuthCodeClaims {
            aud: query.client_id.clone(),
            iat,
            exp: iat + 10 * 60,
            iss: server_url.to_string(),
            sub: user_principal,
            ext_redirect_uri: query.redirect_uri,
            nonce: query.nonce,
            ext_code_challenge_s256: query.code_challenge,
            ext_email: email,
        },
        encoding_key,
    )
    .expect("Failed to encode JWT")
}

fn jwt_header() -> jsonwebtoken::Header {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(AUTH_TOKEN_KID.to_string());

    header
}

/// Generates access token and id token JWTs
/// the first token is the access token
/// the second token is the id token
#[allow(clippy::too_many_arguments)]
pub fn generate_access_token_and_id_token_jwt(
    encoding_key: &jsonwebtoken::EncodingKey,
    user_principal: Principal,
    identity: DelegatedIdentityWire,
    client_id: &str,
    nonce: Option<String>,
    is_anonymous: bool,
    max_age: Duration,
    email: Option<String>,
    ai_account_delegated_identities: Vec<DelegatedIdentityWire>,
    server_url: &str,
) -> (String, String) {
    let iat = current_epoch_secs();

    let access_claims = AccessTokenClaims {
        aud: client_id.to_string(),
        exp: iat + max_age.as_secs() as usize,
        iat,
        iss: server_url.to_string(),
        sub: user_principal,
        nonce: nonce.clone(),
        ext_is_anonymous: is_anonymous,
    };
    let id_claims = IdTokenClaims {
        aud: client_id.to_string(),
        exp: iat + max_age.as_secs() as usize,
        iat,
        iss: server_url.to_string(),
        sub: user_principal,
        nonce,
        ext_is_anonymous: is_anonymous,
        ext_delegated_identity: identity,
        email,
        ext_ai_account_delegated_identities: ai_account_delegated_identities,
    };

    let header = jwt_header();

    let access_token =
        jsonwebtoken::encode(&header, &access_claims, encoding_key).expect("failed to encode JWT");
    let id_token =
        jsonwebtoken::encode(&header, &id_claims, encoding_key).expect("failed to encode JWT");

    (access_token, id_token)
}

#[allow(clippy::too_many_arguments)]
pub fn generate_refresh_token_jwt(
    encoding_key: &jsonwebtoken::EncodingKey,
    user_principal: Principal,
    client_id: &str,
    nonce: Option<String>,
    is_anonymous: bool,
    max_age: Duration,
    email: Option<String>,
    server_url: &str,
) -> String {
    let iat = current_epoch_secs();

    jsonwebtoken::encode(
        &jwt_header(),
        &RefreshTokenClaims {
            aud: client_id.to_string(),
            exp: iat + max_age.as_secs() as usize,
            iat,
            iss: server_url.to_string(),
            sub: user_principal,
            nonce,
            ext_is_anonymous: is_anonymous,
            ext_email: email,
        },
        encoding_key,
    )
    .expect("failed to encode JWT")
}
