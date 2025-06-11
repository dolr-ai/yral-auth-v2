use std::{collections::HashMap, env, sync::Arc};

use axum::extract::FromRef;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::jwk::{self, Jwk};
use leptos::{config::LeptosOptions, prelude::expect_context};
use leptos_axum::AxumRouteListing;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata},
    reqwest, ClientId, ClientSecret, IssuerUrl, RedirectUrl,
};
use p256::pkcs8::DecodePublicKey;

use crate::{
    consts::{APPLE_ISSUER_URL, AUTH_TOKEN_KID, GOOGLE_ISSUER_URL},
    kv::KVStoreImpl,
    oauth::{
        client_validation::ClientIdValidatorImpl, jwt::JsonWebKeySet, SupportedOAuthProviders,
    },
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
    fn load_encoding_key_from_env(encoding_env: &str) -> jsonwebtoken::EncodingKey {
        let jwt_pem =
            env::var(encoding_env).unwrap_or_else(|_| panic!("`{encoding_env}` is required!"));
        jsonwebtoken::EncodingKey::from_ed_pem(jwt_pem.as_bytes())
            .unwrap_or_else(|_| panic!("invalid `{encoding_env}`"))
    }

    pub fn load_from_env(encoding_env: &str, decoding_env: &str) -> Self {
        let encoding_key = Self::load_encoding_key_from_env(encoding_env);

        let jwt_pub_pem =
            env::var(decoding_env).unwrap_or_else(|_| panic!("`{decoding_env}` is required!"));
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
    pub well_known_jwks: JsonWebKeySet,
}

impl Default for JwkPairs {
    fn default() -> Self {
        let auth_jwt_pub_pem =
            env::var("JWT_PUB_EC_PEM").unwrap_or_else(|_| panic!("`JWT_PUB_EC_PEM` is required!"));
        let auth_jwt_ec_pub = p256::ecdsa::VerifyingKey::from_public_key_pem(&auth_jwt_pub_pem)
            .expect("Invalid `JWT_PUB_ED_PEM`");
        let auth_jwt_ec = auth_jwt_ec_pub.to_encoded_point(false);

        let auth_jwt_x = auth_jwt_ec.x().unwrap();
        let auth_jwt_x_b64 = BASE64_URL_SAFE_NO_PAD.encode(auth_jwt_x);
        let auth_jwt_y = auth_jwt_ec.y().unwrap();
        let auth_jwt_y_b64 = BASE64_URL_SAFE_NO_PAD.encode(auth_jwt_y);

        let auth_jwt_decoding_key =
            jsonwebtoken::DecodingKey::from_ec_components(&auth_jwt_x_b64, &auth_jwt_y_b64)
                .unwrap();

        let auth_jwt_decoding_jwk = Jwk {
            common: jwk::CommonParameters {
                public_key_use: Some(jwk::PublicKeyUse::Signature),
                key_algorithm: Some(jwk::KeyAlgorithm::ES256),
                key_id: Some(AUTH_TOKEN_KID.into()),
                ..Default::default()
            },
            algorithm: jwk::AlgorithmParameters::EllipticCurve(jwk::EllipticCurveKeyParameters {
                key_type: jwk::EllipticCurveKeyType::EC,
                curve: jwk::EllipticCurve::P256,
                x: auth_jwt_x_b64,
                y: auth_jwt_y_b64,
            }),
        };

        let auth_jwt_pem =
            env::var("JWT_EC_PEM").unwrap_or_else(|_| panic!("`JWT_EC_PEM` is required!"));

        Self {
            auth_tokens: JwkPair {
                encoding_key: jsonwebtoken::EncodingKey::from_ec_pem(auth_jwt_pem.as_bytes())
                    .expect("invalid `JWT_EC_PEM`"),
                decoding_key: auth_jwt_decoding_key,
            },
            client_tokens: JwkPair::load_from_env("CLIENT_JWT_ED_PEM", "CLIENT_JWT_PUB_ED_PEM"),
            well_known_jwks: JsonWebKeySet {
                keys: vec![auth_jwt_decoding_jwk],
            },
        }
    }
}

pub struct ServerCtx {
    pub oauth_http_client: reqwest::Client,
    pub server_url: String,
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
    ) -> Result<StdOAuthClient, String> {
        let client_id =
            env::var(client_id_env).unwrap_or_else(|_| panic!("`{client_id_env}` is required!"));

        let oauth_metadata = CoreProviderMetadata::discover_async(issuer_url, http_client)
            .await
            .map_err(|e| format!("Failed to discover OAuth metadata: {e}"))?;

        let client =
            CoreClient::from_provider_metadata(oauth_metadata, ClientId::new(client_id), None)
                .set_redirect_uri(redirect_url)
                .set_auth_type(openidconnect::AuthType::RequestBody);

        Ok(client)
    }

    async fn init_google_oauth_client(
        http_client: &reqwest::Client,
        redirect_uri: &RedirectUrl,
        oauth_providers: &mut HashMap<SupportedOAuthProviders, OAuthProviderImpl>,
    ) -> Result<(), String> {
        let google_client_secret =
            env::var("GOOGLE_CLIENT_SECRET").expect("`GOOGLE_CLIENT_SECRET` is required!");

        let google_oauth = Self::init_oauth_client(
            "GOOGLE_CLIENT_ID",
            IssuerUrl::new(GOOGLE_ISSUER_URL.to_string()).unwrap(),
            redirect_uri.clone(),
            http_client,
        )
        .await?
        .set_client_secret(ClientSecret::new(google_client_secret));

        let google_oauth = IdentityOAuthProvider::new(google_oauth);
        oauth_providers.insert(SupportedOAuthProviders::Google, google_oauth.into());

        Ok(())
    }

    async fn init_apple_oauth_client(
        http_client: &reqwest::Client,
        redirect_uri: &RedirectUrl,
        oauth_providers: &mut HashMap<SupportedOAuthProviders, OAuthProviderImpl>,
    ) -> Result<(), String> {
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
        .await?;
        let apple_oauth =
            AppleOAuthProvider::new(apple_oauth, apple_auth_key, apple_key_id, apple_team_id);

        oauth_providers.insert(SupportedOAuthProviders::Apple, apple_oauth.into());

        Ok(())
    }

    async fn init_oauth_providers(
        http_client: &reqwest::Client,
        server_url: &str,
    ) -> HashMap<SupportedOAuthProviders, OAuthProviderImpl> {
        let mut oauth_providers = HashMap::new();

        let redirect_uri = format!("{server_url}/oauth_callback");
        let redirect_uri = RedirectUrl::new(redirect_uri).expect("Invalid `SERVER_URL`");

        // Google OAuth
        if let Err(e) =
            Self::init_google_oauth_client(http_client, &redirect_uri, &mut oauth_providers).await
        {
            log::error!("Failed to initialize Google OAuth: {e}, ignoring");
        }

        // Apple OAuth
        if let Err(e) =
            Self::init_apple_oauth_client(http_client, &redirect_uri, &mut oauth_providers).await
        {
            log::error!("Failed to initialize Apple OAuth: {e}, ignoring");
        }

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

        let server_url = env::var("SERVER_URL").expect("`SERVER_URL` is required");
        let server_url = server_url
            .strip_suffix("/")
            .unwrap_or(&server_url)
            .to_string();

        let oauth_providers = Self::init_oauth_providers(&oauth_http_client, &server_url).await;

        let cookie_key = Self::init_cookie_key();

        let kv_store = Self::init_kv_store().await;

        Self {
            oauth_http_client,
            oauth_providers,
            server_url,
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
