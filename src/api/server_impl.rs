use std::sync::Arc;

use axum::{
    response::{IntoResponse, Response},
    Extension, Form, Json,
};
use candid::Principal;
use ic_agent::{
    identity::{Delegation, Secp256k1Identity, SignedDelegation},
    Identity,
};
use sha2::{Digest, Sha256};
use url::Url;
use web_time::Duration;
use yral_types::delegated_identity::DelegatedIdentityWire;

use crate::{
    context::server::ServerCtx,
    kv::KVStore,
    oauth::{
        client_validation::{ClientIdValidator, ValidationRes},
        jwt::{
            generate::{generate_access_token_and_id_token_jwt, generate_refresh_token_jwt},
            AuthCodeClaims, RefreshTokenClaims,
        },
        AuthGrantQuery, PartialOIDCConfig, TokenGrantError, TokenGrantErrorKind, TokenGrantRes,
        TokenGrantResult,
    },
    utils::{identity::generate_random_identity_and_save, time::current_epoch},
};

async fn verify_client_secret(
    ctx: &ServerCtx,
    client_id: &str,
    client_secret: Option<String>,
    redirect_uri: Option<&Url>,
) -> Result<ValidationRes, TokenGrantError> {
    ctx.validator
        .full_validation(
            &ctx.jwk_pairs.client_tokens.decoding_key,
            client_id,
            redirect_uri,
            client_secret.as_deref(),
        )
        .await
        .map_err(|e| TokenGrantError {
            error: TokenGrantErrorKind::InvalidClient,
            error_description: e.to_string(),
        })
}

impl IntoResponse for TokenGrantResult {
    fn into_response(self) -> Response {
        match self {
            Self::Ok(res) => Json(res).into_response(),
            Self::Err(e) => {
                let status_code = e.error.status_code();
                let mut res = Json(e).into_response();
                *res.status_mut() = status_code;
                res
            }
        }
    }
}

pub async fn handle_well_known_jwks(Extension(ctx): Extension<Arc<ServerCtx>>) -> Response {
    Json(ctx.jwk_pairs.well_known_jwks.clone()).into_response()
}

pub async fn handle_oidc_configuration(Extension(ctx): Extension<Arc<ServerCtx>>) -> Response {
    let jwks_uri = format!("{}/.well-known/jwks.json", ctx.server_url,);

    Json(PartialOIDCConfig { jwks_uri }).into_response()
}

pub async fn handle_oauth_token_grant(
    Extension(ctx): Extension<Arc<ServerCtx>>,
    Form(req): Form<AuthGrantQuery>,
) -> Response {
    let res = match req {
        AuthGrantQuery::AuthorizationCode {
            code,
            redirect_uri,
            code_verifier,
            client_id,
            client_secret,
        } => {
            handle_authorization_code_grant(
                &ctx,
                code,
                redirect_uri,
                code_verifier,
                client_id,
                client_secret,
            )
            .await
        }
        AuthGrantQuery::RefreshToken {
            refresh_token,
            client_id,
            client_secret,
        } => handle_refresh_token_grant(&ctx, refresh_token, client_id, client_secret).await,
        AuthGrantQuery::ClientCredentials {
            client_id,
            client_secret,
        } => handle_client_credentials_grant(&ctx, client_id, client_secret).await,
    };

    match res {
        Ok(grant) => Json(grant).into_response(),
        Err(e) => {
            let status_code = e.error.status_code();
            let mut res = Json(e).into_response();
            *res.status_mut() = status_code;
            res
        }
    }
}

fn delegate_identity(from: &impl Identity, max_age: Duration) -> DelegatedIdentityWire {
    let mut rng = rand::thread_rng();
    let to_secret = k256::SecretKey::random(&mut rng);
    let to_secret_jwk = to_secret.to_jwk();
    let to_identity = Secp256k1Identity::from_private_key(to_secret);
    let expiry = current_epoch() + max_age;
    let delegation = Delegation {
        pubkey: to_identity.public_key().unwrap(),
        expiration: expiry.as_nanos() as u64,
        targets: None,
    };
    let sig = from.sign_delegation(&delegation).unwrap();
    let signed_delegation = SignedDelegation {
        delegation,
        signature: sig.signature.unwrap(),
    };

    let mut delegation_chain = from.delegation_chain();
    delegation_chain.push(signed_delegation);

    DelegatedIdentityWire {
        from_key: sig.public_key.unwrap(),
        to_secret: to_secret_jwk,
        delegation_chain,
    }
}

fn generate_access_token_with_identity(
    ctx: &ServerCtx,
    identity: Secp256k1Identity,
    client_id: &str,
    nonce: Option<String>,
    is_anonymous: bool,
    res: ValidationRes,
) -> TokenGrantRes {
    let delegated_identity = delegate_identity(&identity, res.access_max_age);
    let user_principal = identity.sender().unwrap();

    let (access_token, id_token) = generate_access_token_and_id_token_jwt(
        &ctx.jwk_pairs.auth_tokens.encoding_key,
        user_principal,
        delegated_identity,
        &ctx.server_url,
        client_id,
        nonce.clone(),
        is_anonymous,
        res.access_max_age,
    );
    let refresh_token = generate_refresh_token_jwt(
        &ctx.jwk_pairs.auth_tokens.encoding_key,
        user_principal,
        &ctx.server_url,
        client_id,
        nonce,
        is_anonymous,
        res.refresh_max_age,
    );

    TokenGrantRes::new(access_token, id_token, refresh_token)
}

async fn generate_access_token(
    ctx: &ServerCtx,
    user_principal: Principal,
    client_id: &str,
    nonce: Option<String>,
    is_anonymous: bool,
    validation_res: ValidationRes,
) -> Result<TokenGrantRes, TokenGrantError> {
    let identity_jwk = ctx
        .kv_store
        .read(user_principal.to_text())
        .await
        .map_err(|e| TokenGrantError {
            error: TokenGrantErrorKind::ServerError,
            error_description: e.to_string(),
        })?
        .ok_or_else(|| TokenGrantError {
            error: TokenGrantErrorKind::ServerError,
            error_description: format!("unknown principal {user_principal}"),
        })?;

    let sk = k256::SecretKey::from_jwk_str(&identity_jwk).map_err(|_| TokenGrantError {
        error: TokenGrantErrorKind::ServerError,
        error_description: "invalid identity in store?!".into(),
    })?;
    let id = Secp256k1Identity::from_private_key(sk);

    let grant = generate_access_token_with_identity(
        ctx,
        id,
        client_id,
        nonce,
        is_anonymous,
        validation_res,
    );

    Ok(grant)
}

async fn handle_authorization_code_grant(
    ctx: &ServerCtx,
    code: String,
    redirect_uri: Url,
    code_verifier: String,
    client_id: String,
    client_secret: Option<String>,
) -> Result<TokenGrantRes, TokenGrantError> {
    let validation_res =
        verify_client_secret(ctx, &client_id, client_secret, Some(&redirect_uri)).await?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_audience(&[&client_id]);
    validation.set_issuer(&[&ctx.server_url]);

    let auth_code = jsonwebtoken::decode::<AuthCodeClaims>(
        &code,
        &ctx.jwk_pairs.auth_tokens.decoding_key,
        &validation,
    )
    .map_err(|e| TokenGrantError {
        error: TokenGrantErrorKind::InvalidGrant,
        error_description: e.to_string(),
    })?;

    let code_claims = auth_code.claims;
    if code_claims.ext_redirect_uri != redirect_uri {
        return Err(TokenGrantError {
            error: TokenGrantErrorKind::InvalidGrant,
            error_description: "Invalid redirect URI".to_string(),
        });
    }

    let mut verifier_hash = Sha256::new();
    verifier_hash.update(code_verifier.as_bytes());
    let verifier_hash: [u8; 32] = verifier_hash.finalize().into();
    if verifier_hash != code_claims.ext_code_challenge_s256.0 {
        return Err(TokenGrantError {
            error: TokenGrantErrorKind::InvalidGrant,
            error_description: "Invalid code verifier".to_string(),
        });
    }

    let grant = generate_access_token(
        ctx,
        code_claims.sub,
        &client_id,
        code_claims.nonce.clone(),
        false,
        validation_res,
    )
    .await?;

    Ok(grant)
}

async fn handle_refresh_token_grant(
    ctx: &ServerCtx,
    refresh_token: String,
    client_id: String,
    client_secret: Option<String>,
) -> Result<TokenGrantRes, TokenGrantError> {
    let validation_res = verify_client_secret(ctx, &client_id, client_secret, None).await?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_audience(&[&client_id]);
    validation.set_issuer(&[&ctx.server_url]);

    let refresh_token = jsonwebtoken::decode::<RefreshTokenClaims>(
        &refresh_token,
        &ctx.jwk_pairs.auth_tokens.decoding_key,
        &validation,
    )
    .map_err(|e| TokenGrantError {
        error: TokenGrantErrorKind::InvalidGrant,
        error_description: e.to_string(),
    })?;

    let refresh_claims = refresh_token.claims;

    let grant = generate_access_token(
        ctx,
        refresh_claims.sub,
        &client_id,
        None,
        refresh_claims.ext_is_anonymous,
        validation_res,
    )
    .await?;

    Ok(grant)
}

async fn handle_client_credentials_grant(
    ctx: &ServerCtx,
    client_id: String,
    client_secret: Option<String>,
) -> Result<TokenGrantRes, TokenGrantError> {
    let validation_res = verify_client_secret(ctx, &client_id, client_secret, None).await?;

    let identity = generate_random_identity_and_save(&ctx.kv_store)
        .await
        .map_err(|e| TokenGrantError {
            error: TokenGrantErrorKind::ServerError,
            error_description: e.to_string(),
        })?;

    let grant =
        generate_access_token_with_identity(ctx, identity, &client_id, None, true, validation_res);

    Ok(grant)
}
