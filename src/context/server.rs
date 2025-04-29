use std::{collections::HashMap, env, sync::Arc};

use axum::extract::FromRef;
use leptos::{config::LeptosOptions, prelude::expect_context};
use leptos_axum::AxumRouteListing;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata},
    reqwest, ClientId, ClientSecret, IssuerUrl, RedirectUrl,
};

use crate::{
    consts::{APPLE_ISSUER_URL, GOOGLE_ISSUER_URL},
    kv::KVStoreImpl,
    oauth::{client_validation::ClientIdValidatorImpl, SupportedOAuthProviders},
    oauth_provider::{
        AppleOAuthProvider, IdentityOAuthProvider, OAuthProviderImpl, StdOAuthClient,
    },
};

#[derive(FromRef, Clone)]
pub struct ServerState {
    pub leptos_options: LeptosOptions,
    pub routes: Vec<AxumRouteListing>,
    pub ctx: Arc<ServerCtx>,
}

pub struct JwkPair {
    pub encoding_key: jsonwebtoken::EncodingKey,
    pub decoding_key: jsonwebtoken::DecodingKey,
}

impl JwkPair {
    pub fn load_from_env(encoding_env: &str, decoding_env: &str) -> Self {
        let jwt_pem =
            env::var(encoding_env).unwrap_or_else(|_| panic!("`{encoding_env}` is required!"));
        let jwt_pub_pem =
            env::var(decoding_env).unwrap_or_else(|_| panic!("`{decoding_env}` is required!"));

        let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(jwt_pem.as_bytes())
            .unwrap_or_else(|_| panic!("invalid `{encoding_env}`"));
        let decoding_key = jsonwebtoken::DecodingKey::from_ed_pem(jwt_pub_pem.as_bytes())
            .unwrap_or_else(|_| panic!("invalid `{decoding_env}`"));

        Self {
            encoding_key,
            decoding_key,
        }
    }
}

pub struct JwkPairs {
    pub auth_tokens: JwkPair,
    pub client_tokens: JwkPair,
}

impl Default for JwkPairs {
    fn default() -> Self {
        Self {
            auth_tokens: JwkPair::load_from_env("JWT_ED_PEM", "JWT_PUB_ED_PEM"),
            client_tokens: JwkPair::load_from_env("CLIENT_JWT_ED_PEM", "CLIENT_JWT_PUB_ED_PEM"),
        }
    }
}

pub struct ServerCtx {
    pub oauth_http_client: reqwest::Client,
    pub oauth_providers: HashMap<SupportedOAuthProviders, OAuthProviderImpl>,
    pub cookie_key: axum_extra::extract::cookie::Key,
    pub jwk_pairs: JwkPairs,
    pub kv_store: KVStoreImpl,
    pub validator: ClientIdValidatorImpl,
}

impl ServerCtx {
    async fn init_oauth_client(
        client_id_env: &str,
        issuer_url: IssuerUrl,
        redirect_url: RedirectUrl,
        http_client: &reqwest::Client,
    ) -> StdOAuthClient {
        let client_id =
            env::var(client_id_env).unwrap_or_else(|_| panic!("`{client_id_env}` is required!"));

        let oauth_metadata = CoreProviderMetadata::discover_async(issuer_url, http_client)
            .await
            .unwrap();

        CoreClient::from_provider_metadata(oauth_metadata, ClientId::new(client_id), None)
            .set_redirect_uri(redirect_url)
            .set_auth_type(openidconnect::AuthType::RequestBody)
    }

    async fn init_oauth_providers(
        http_client: &reqwest::Client,
    ) -> HashMap<SupportedOAuthProviders, OAuthProviderImpl> {
        let mut oauth_providers = HashMap::new();

        let redirect_uri =
            env::var("OAUTH_REDIRECT_URL").expect("`OAUTH_REDIRECT_URI` is required!");
        let redirect_uri = RedirectUrl::new(redirect_uri).expect("Invalid `OAUTH_REDIRECT_URI`");

        // Google OAuth
        let google_client_secret =
            env::var("GOOGLE_CLIENT_SECRET").expect("`GOOGLE_CLIENT_SECRET` is required!");

        let google_oauth = Self::init_oauth_client(
            "GOOGLE_CLIENT_ID",
            IssuerUrl::new(GOOGLE_ISSUER_URL.to_string()).unwrap(),
            redirect_uri.clone(),
            http_client,
        )
        .await
        .set_client_secret(ClientSecret::new(google_client_secret));
        let google_oauth = IdentityOAuthProvider::new(google_oauth);
        oauth_providers.insert(SupportedOAuthProviders::Google, google_oauth.into());

        // Apple OAuth
        let apple_team_id = env::var("APPLE_TEAM_ID").expect("`APPLE_TEAM_ID` is required!");
        let apple_key_id = env::var("APPLE_KEY_ID").expect("`APPLE_KEY_ID` is required!");
        let apple_auth_key =
            env::var("APPLE_AUTH_KEY_PEM").expect("`APPLE_AUTH_KEY_PEM` is required!");
        let apple_auth_key = jsonwebtoken::EncodingKey::from_ec_pem(apple_auth_key.as_bytes())
            .expect("invalid `APPLE_AUTH_KEY_PEM`");

        let apple_oauth = Self::init_oauth_client(
            "APPLE_CLIENT_ID",
            IssuerUrl::new(APPLE_ISSUER_URL.to_string()).unwrap(),
            redirect_uri.clone(),
            http_client,
        )
        .await;
        let apple_oauth =
            AppleOAuthProvider::new(apple_oauth, apple_auth_key, apple_key_id, apple_team_id);

        oauth_providers.insert(SupportedOAuthProviders::Apple, apple_oauth.into());

        oauth_providers
    }

    fn init_cookie_key() -> axum_extra::extract::cookie::Key {
        let cookie_key_str = env::var("COOKIE_KEY").expect("`COOKIE_KEY` is required!");
        let cookie_key_raw =
            hex::decode(cookie_key_str).expect("Invalid `COOKIE_KEY` (must be length 128 hex)");
        axum_extra::extract::cookie::Key::from(&cookie_key_raw)
    }

    pub async fn init_kv_store() -> KVStoreImpl {
        #[cfg(not(feature = "redis-kv"))]
        {
            use crate::kv::redb_kv::ReDBKV;
            KVStoreImpl::ReDB(ReDBKV::new().unwrap())
        }
        #[cfg(feature = "redis-kv")]
        {
            use crate::kv::redis_kv::RedisKV;
            let redis_url = env::var("REDIS_URL").expect("`REDIS_URL` is required!");
            KVStoreImpl::Redis(
                RedisKV::new(&redis_url)
                    .await
                    .expect("Failed to initialize RedisKV"),
            )
        }
    }

    pub async fn new() -> Self {
        let oauth_http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");
        let oauth_providers = Self::init_oauth_providers(&oauth_http_client).await;

        let cookie_key = Self::init_cookie_key();

        let kv_store = Self::init_kv_store().await;

        Self {
            oauth_http_client,
            oauth_providers,
            cookie_key,
            jwk_pairs: JwkPairs::default(),
            kv_store,
            validator: ClientIdValidatorImpl::Const(Default::default()),
        }
    }
}

pub fn expect_server_ctx() -> Arc<ServerCtx> {
    expect_context()
}
