use std::{ops::Add, sync::Arc, time::Duration};

use axum_extra::extract::{PrivateCookieJar, cookie::Cookie};
use candid::Principal;
use leptos::prelude::expect_context;
use leptos_axum::{ResponseOptions, extract_with_state};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{api::identity_provider::{principal_from_login_hint_or_generate_and_save, try_extract_principal_from_oauth_sub}, context::{message_delivery_service::MessageDeliveryError, server::ServerCtx}, error::AuthErrorKind, oauth::{AuthQuery, SupportedOAuthProviders, jwt::generate::generate_code_grant_jwt}, page::oauth_login::verify_phone_auth::VerifyPhoneOtpRequest, utils::{cookies::set_cookies, time::current_epoch}};

#[derive(Serialize, Deserialize)]
struct OneTimePassCodeClaim {
    pub phone_number: String,
    pub code_hash_s256: Vec<u8>,
    pub exp: u64,
}


#[derive(Deserialize, Serialize, Debug, Clone)]
struct PhoneAuthRequest  {
    client_id: String,
    client_secret: String,
    phone_number: String,
}


pub async fn generate_otp_and_set_cookie(server_context: &ServerCtx, phone_number: String, auth_client_query: AuthQuery) -> Result<(), AuthErrorKind> {

    let  private_cookie_jar: PrivateCookieJar = extract_with_state(&server_context.cookie_key).await.map_err(|e| AuthErrorKind::Unexpected(e.to_string()))?;

    let token = send_authorization_code_for_phone_number(&server_context, phone_number.clone()).await?;

    let otp_cookie = Cookie::build(("otp_token", token.clone()))
        .http_only(true)
        .secure(true)
        .path("/")
        .same_site(axum_extra::extract::cookie::SameSite::None)
        .build();

    let auth_client_query_raw = serde_json::to_string(&auth_client_query).map_err(|e| AuthErrorKind::Unexpected(e.to_string()))?;

    let client_auth_query_cookie = Cookie::build(("auth_client_query", auth_client_query_raw)).http_only(true).secure(true).path("/").same_site(axum_extra::extract::cookie::SameSite::None).build();


    let cookie = private_cookie_jar.add(otp_cookie);
    let cookie = cookie.add(client_auth_query_cookie);

    let resp: ResponseOptions = expect_context();

    set_cookies(&resp, cookie);

    Ok(())
}



async fn send_authorization_code_for_phone_number(ctx: &ServerCtx, phone_number: String) -> Result<String, AuthErrorKind> {
    
    let one_time_passcode: u32 = rand::thread_rng().gen_range(100000..999999);


    println!("Sending OTP {one_time_passcode} to phone number {phone_number}");

    let mut hasher = Sha256::new();
    hasher.update(one_time_passcode.to_string().as_bytes());

    let otp_hash = hex::encode(hasher.finalize());

    let expiry = current_epoch().add(Duration::from_secs(300)); // OTP valid for 5 minutes

    let otp_claim = OneTimePassCodeClaim {
        phone_number: phone_number.clone(),
        code_hash_s256: otp_hash.as_bytes().to_vec(),
        exp: expiry.as_nanos() as u64,
    };


    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
        &otp_claim,
        &ctx.jwk_pairs.auth_tokens.encoding_key,
    ).map_err(|e| AuthErrorKind::Unexpected(e.to_string()))?;


    //TODO: send OTP to user via SMS gateway
    ctx.message_delivery_service.send_message(&phone_number, &one_time_passcode.to_string()).await.map_err(|e| 
    match e {
        MessageDeliveryError::InvalidRecipient => AuthErrorKind::InvalidPhoneNumber,
        _ => AuthErrorKind::Unexpected("Failed to send OTP".to_string()),
    })?;


    Ok(token)
}




pub async fn verify_phone_one_time_passcode(server_context: &Arc<ServerCtx>, verify_request: VerifyPhoneOtpRequest) -> Result<(String, Url), AuthErrorKind> {


    let  private_cookie_jar: PrivateCookieJar = extract_with_state(&server_context.cookie_key).await.map_err(|e| AuthErrorKind::Unexpected(e.to_string()))?;
    let otp_cookie = private_cookie_jar.get("otp_token").ok_or_else(|| AuthErrorKind::OtpCookieNotFound)?;
    let auth_client_query_raw = private_cookie_jar.get("auth_client_query").ok_or_else(|| AuthErrorKind::AuthClientCookieNotFound)?.value().to_string();

    let auth_client_query :AuthQuery= serde_json::from_str(&auth_client_query_raw).map_err(|e| AuthErrorKind::Unexpected(format!("failed to deserialize auth client query: {e}")))?;
    if !auth_client_query.state.eq(&verify_request.client_state) {
        return Err(AuthErrorKind::Unexpected("state token mismatch".to_owned()));
    }

    let token = otp_cookie.value().to_owned();

    let decoded_token = jsonwebtoken::decode::<OneTimePassCodeClaim>(
        &token,
        &server_context.jwk_pairs.auth_tokens.decoding_key,
        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256),
    ).map_err(|e| AuthErrorKind::InvalidOtpToken(e.to_string()))?;

    if decoded_token.claims.phone_number != verify_request.phone_number {
        return Err(AuthErrorKind::PhoneMismatch);
    }

    if decoded_token.claims.exp < current_epoch().as_nanos() as u64 {
        return Err(AuthErrorKind::ExpiredOtp);
    }

    let mut hasher = Sha256::new();
    hasher.update(verify_request.code.as_bytes());

    let code_hash = hex::encode(hasher.finalize());

    if code_hash.as_bytes() != decoded_token.claims.code_hash_s256 {
        return Err(AuthErrorKind::InvalidOtp);
    }
    let provider = SupportedOAuthProviders::Phone;

    //TODO: add client code grant and clear the cookies.
    let user_principal: Principal = if let Some(user_principal) = try_extract_principal_from_oauth_sub(provider, &server_context.kv_store, &verify_request.phone_number, None).await? {
        Principal::from_text(user_principal).map_err(|_e| AuthErrorKind::Unexpected("Invalid principal from kv".to_owned()))?
    } else {
        let user_principal = principal_from_login_hint_or_generate_and_save(provider, &server_context.kv_store, &verify_request.phone_number, auth_client_query.login_hint.clone(), None).await?;
        user_principal
    };

    let mut redirect_uri = auth_client_query.redirect_uri.clone();
    let client_state = auth_client_query.state.clone();

    let token = generate_code_grant_jwt(&server_context.jwk_pairs.auth_tokens.encoding_key, user_principal, &server_context.server_url, auth_client_query, None);

    redirect_uri.query_pairs_mut().clear().append_pair("code", token.as_str()).append_pair("state", client_state.as_str());
    Ok((token, redirect_uri))
}
