use ic_agent::Identity;
use web_time::Duration;

use axum::{http::header, response::IntoResponse};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    PrivateCookieJar,
};
use base64::{prelude::BASE64_URL_SAFE, Engine};
use candid::Principal;
use leptos::prelude::{expect_context, ServerFnError};
use leptos_axum::{extract_with_state, ResponseOptions};
use openidconnect::{
    core::CoreAuthenticationFlow, AuthorizationCode, CsrfToken, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, Scope,
};
use serde::{Deserialize, Serialize};

use crate::{
    context::server::expect_server_ctx,
    error::AuthErrorKind,
    kv::{KVError, KVStore, KVStoreImpl},
    oauth::{
        jwt::generate::generate_code_grant_jwt, login_hint_message, AuthLoginHint, AuthQuery,
        SupportedOAuthProviders,
    },
    oauth_provider::OAuthProvider,
    utils::identity::generate_random_identity_and_save,
};

const PKCE_VERIFIER_COOKIE: &str = "oauth-pkce-verifier";
const CSRF_TOKEN_COOKIE: &str = "oauth-csrf-token";

#[derive(Serialize, Deserialize)]
struct OAuthState {
    pub csrf_token: CsrfToken,
    pub provider: SupportedOAuthProviders,
    pub client_state: String,
}

fn set_cookies(resp: &ResponseOptions, jar: impl IntoResponse) {
    let resp_jar = jar.into_response();
    for cookie in resp_jar
        .headers()
        .get_all(header::SET_COOKIE)
        .into_iter()
        .cloned()
    {
        resp.append_header(header::SET_COOKIE, cookie);
    }
}

pub async fn get_oauth_url_impl(
    provider: SupportedOAuthProviders,
    client_state: String,
) -> Result<String, ServerFnError> {
    let ctx = expect_server_ctx();

    let oauth_provider = ctx
        .oauth_providers
        .get(&provider)
        .ok_or_else(|| ServerFnError::new("unsupported provider"))?
        .get_client();

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let oauth_state = OAuthState {
        csrf_token: CsrfToken::new_random(),
        provider,
        client_state,
    };
    let oauth_state_raw = postcard::to_stdvec(&oauth_state)
        .map_err(|_| ServerFnError::new("failed to serialize oauth state"))?;
    let oauth_state_b64 = BASE64_URL_SAFE.encode(oauth_state_raw);

    let authorize_builder = oauth_provider
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            move || CsrfToken::new(oauth_state_b64),
            Nonce::new_random,
        )
        .set_pkce_challenge(pkce_challenge);
    let (auth_url, oauth_csrf_token, _) = if provider == SupportedOAuthProviders::Google {
        authorize_builder
            .add_scope(Scope::new("email".to_string()))
            .url()
    } else {
        authorize_builder.url()
    };

    let mut jar: PrivateCookieJar = extract_with_state(&ctx.cookie_key).await?;

    let cookie_life = Duration::from_secs(60 * 10).try_into().unwrap(); // 10 minutes
    let pkce_cookie = Cookie::build((PKCE_VERIFIER_COOKIE, pkce_verifier.secret().clone()))
        .same_site(SameSite::None)
        .path("/")
        .max_age(cookie_life)
        .http_only(true)
        .build();
    jar = jar.add(pkce_cookie);

    let csrf_cookie = Cookie::build((CSRF_TOKEN_COOKIE, oauth_csrf_token.secret().clone()))
        .same_site(SameSite::None)
        .path("/")
        .max_age(cookie_life)
        .http_only(true)
        .build();
    jar = jar.add(csrf_cookie);

    let resp: ResponseOptions = expect_context();

    set_cookies(&resp, jar);

    Ok(auth_url.to_string())
}

fn principal_lookup_key(provider: SupportedOAuthProviders, sub_id: &str) -> String {
    format!("{provider}-login-{sub_id}")
}

async fn try_extract_principal_from_oauth_sub(
    provider: SupportedOAuthProviders,
    kv: &KVStoreImpl,
    sub_id: &str,
) -> Result<Option<String>, KVError> {
    let key = principal_lookup_key(provider, sub_id);
    let Some(principal_str) = kv.read(key).await? else {
        return Ok(None);
    };

    // TODO: remove this after spacetime migration and handling
    if kv.has_key(principal_str.clone()).await? {
        Ok(Some(principal_str))
    } else {
        Ok(None)
    }
}

async fn principal_from_login_hint_or_generate_and_save(
    provider: SupportedOAuthProviders,
    kv: &KVStoreImpl,
    sub_id: &str,
    login_hint: Option<AuthLoginHint>,
) -> Result<Principal, AuthErrorKind> {
    let user_principal = if let Some(login_hint) = login_hint {
        let msg = login_hint_message();
        login_hint
            .signature
            .verify_identity(login_hint.user_principal, msg)
            .map_err(|_| AuthErrorKind::InvalidLoginHint)?;
        login_hint.user_principal
    } else {
        let identity = generate_random_identity_and_save(kv)
            .await
            .map_err(|_| AuthErrorKind::unexpected("failed to generate id"))?;
        identity.sender().unwrap()
    };

    kv.write(
        principal_lookup_key(provider, sub_id),
        user_principal.to_text(),
    )
    .await
    .map_err(|_| AuthErrorKind::unexpected("failed to associated id with oauth"))?;

    Ok(user_principal)
}

async fn generate_oauth_login_code(
    code: String,
    pkce_verifier: PkceCodeVerifier,
    provider: SupportedOAuthProviders,
    query: AuthQuery,
) -> Result<String, AuthErrorKind> {
    let ctx = expect_server_ctx();
    let oauth_impl = ctx
        .oauth_providers
        .get(&provider)
        .ok_or_else(|| AuthErrorKind::unexpected(format!("provider unavailable: {provider}")))?;
    let oauth2 = oauth_impl.get_client();

    let token_res = oauth2
        .exchange_code(AuthorizationCode::new(code))
        .map_err(AuthErrorKind::unexpected)?
        .set_pkce_verifier(pkce_verifier)
        .request_async(&ctx.oauth_http_client)
        .await
        .map_err(AuthErrorKind::unexpected)?;

    let id_token = token_res
        .extra_fields()
        .id_token()
        .ok_or_else(|| AuthErrorKind::unexpected("Google did not return an ID token"))?;

    // we don't use a nonce
    let claims = oauth_impl.verify_id_token(&oauth2, id_token)?;
    let sub_id = claims.subject();
    let email = claims.email().map(|e| String::from(e.clone()));

    let maybe_principal = try_extract_principal_from_oauth_sub(provider, &ctx.kv_store, sub_id)
        .await
        .map_err(AuthErrorKind::unexpected)?;
    let principal = if let Some(principal_str) = maybe_principal {
        Principal::from_text(principal_str)
            .map_err(|_| AuthErrorKind::unexpected("Invalid principal from KV"))?
    } else {
        principal_from_login_hint_or_generate_and_save(
            provider,
            &ctx.kv_store,
            sub_id,
            query.login_hint.clone(),
        )
        .await?
    };

    let code_grant = generate_code_grant_jwt(
        &ctx.jwk_pairs.auth_tokens.encoding_key,
        principal,
        &ctx.server_url,
        query,
        email,
    );

    Ok(code_grant)
}

pub async fn perform_oauth_login_impl(
    code: String,
    state: String,
) -> Result<String, ServerFnError> {
    let ctx = expect_server_ctx();
    let mut jar: PrivateCookieJar = extract_with_state(&ctx.cookie_key).await?;

    let csrf_cookie = jar
        .get(CSRF_TOKEN_COOKIE)
        .ok_or_else(|| ServerFnError::new("csrf token not found"))?;
    if state != csrf_cookie.value() {
        return Err(ServerFnError::new("CSRF token mismatch"));
    }

    let pkce_cookie = jar
        .get(PKCE_VERIFIER_COOKIE)
        .ok_or_else(|| ServerFnError::new("pkce verifier not found"))?;
    let pkce_verifier = PkceCodeVerifier::new(pkce_cookie.value().to_owned());

    jar = jar.remove(PKCE_VERIFIER_COOKIE);
    jar = jar.remove(CSRF_TOKEN_COOKIE);
    let resp: ResponseOptions = expect_context();
    set_cookies(&resp, jar);

    let state_raw = BASE64_URL_SAFE
        .decode(state)
        .map_err(|_| ServerFnError::new("failed to decode state"))?;
    let state: OAuthState = postcard::from_bytes(&state_raw)
        .map_err(|_| ServerFnError::new("failed to deserialize state"))?;
    let query_raw = BASE64_URL_SAFE
        .decode(state.client_state)
        .map_err(|_| ServerFnError::new("failed to decode client state"))?;

    let query: AuthQuery = postcard::from_bytes(&query_raw)
        .map_err(|_| ServerFnError::new("failed to deserialize query"))?;
    let req_state = query.state.clone();
    let mut redirect_uri = query.redirect_uri.clone();

    let res = generate_oauth_login_code(code, pkce_verifier, state.provider, query).await;
    match res {
        Ok(grant) => redirect_uri
            .query_pairs_mut()
            .clear()
            .append_pair("code", &grant)
            .append_pair("state", &req_state),
        Err(e) => redirect_uri
            .query_pairs_mut()
            .clear()
            .append_pair("error", &e.to_string())
            .append_pair("state", &req_state),
    };

    Ok(redirect_uri.to_string())
}
