use base64::{prelude::BASE64_URL_SAFE, Engine};
use leptos::{either::Either, prelude::*};
use leptos_router::{
    components::Redirect,
    hooks::{use_navigate, use_query},
    params::{Params, ParamsError},
    NavigateOptions,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    components::{spinner::Spinner, whatsapp_symbol::WhatsAppSymbol, yral_symbol::YralSymbol},
    error::AuthErrorKind,
    oauth::{
        client_validation::{ClientIdValidator, ClientIdValidatorImpl},
        AuthCodeError, AuthLoginHint, AuthQuery, AuthResponse as AuthResponseCode, CodeChallenge,
        CodeChallengeMethod, SupportedOAuthProviders,
    },
};

use crate::components::google_symbol::GoogleSymbol;

#[cfg(feature = "apple-oauth")]
use crate::components::apple_symbol::AppleSymbol;

#[derive(Debug, Clone, Params, PartialEq)]
pub struct RedirectUriQuery {
    redirect_uri: Option<String>,
}

#[derive(Debug, Clone, Params, PartialEq)]
pub struct StateQuery {
    state: Option<String>,
}

#[derive(Debug, Clone, Params, PartialEq)]
pub struct AuthQueryMaybe {
    response_type: Option<AuthResponseCode>,
    client_id: Option<String>,
    code_challenge: Option<CodeChallenge>,
    code_challenge_method: Option<CodeChallengeMethod>,
    nonce: Option<String>,
    login_hint: Option<AuthLoginHint>,
    provider: Option<SupportedOAuthProviders>,
}

impl AuthQueryMaybe {
    pub async fn validate(
        self,
        validator: &impl ClientIdValidator,
        redirect_uri: String,
        state: String,
    ) -> Result<AuthQuery, AuthErrorKind> {
        let client_id = self
            .client_id
            .ok_or_else(|| AuthErrorKind::missing_param("client_id"))?;
        let redirect_uri =
            Url::parse(&redirect_uri).map_err(|_| AuthErrorKind::InvalidUri(redirect_uri))?;

        validator
            .validate_id_and_redirect(&client_id, &redirect_uri)
            .await?;

        Ok(AuthQuery {
            response_type: self
                .response_type
                .ok_or_else(|| AuthErrorKind::missing_param("response_type"))?,
            client_id,
            state,
            redirect_uri,
            code_challenge: self
                .code_challenge
                .ok_or_else(|| AuthErrorKind::missing_param("code_challenge"))?,
            code_challenge_method: self
                .code_challenge_method
                .ok_or_else(|| AuthErrorKind::missing_param("code_challenge_method"))?,
            login_hint: self.login_hint,
            nonce: self.nonce,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum AuthKind {
    Default(Box<AuthQuery>),
    Redirect(String),
}

#[component]
pub fn AuthPage() -> impl IntoView {
    let redirect_query = use_query::<RedirectUriQuery>();
    let state_query = use_query::<StateQuery>();
    let auth_query_maybe = use_query::<AuthQueryMaybe>();

    let validator = expect_context::<ClientIdValidatorImpl>();

    let auth_query = Resource::new(
        move || {
            (
                redirect_query.get(),
                auth_query_maybe.get(),
                state_query.get(),
            )
        },
        move |(redirect_query, auth_query_maybe, state_query)| {
            let validator = validator.clone();
            async move {
                let redirect_uri = match redirect_query {
                    Ok(RedirectUriQuery {
                        redirect_uri: Some(uri),
                    }) => uri,
                    _ => {
                        return Err(AuthCodeError::new(
                            AuthErrorKind::missing_param("redirect_uri"),
                            None,
                            "/error",
                        ))
                    }
                };
                let state = match state_query {
                    Ok(StateQuery { state: Some(state) }) => state,
                    _ => {
                        return Err(AuthCodeError::new(
                            AuthErrorKind::missing_param("state"),
                            None,
                            redirect_uri.clone(),
                        ))
                    }
                };

                let res = match auth_query_maybe {
                    Ok(q) => {
                        let provider = q.provider;
                        q.validate(&validator, redirect_uri.clone(), state.clone())
                            .await
                            .map(|q| (q, provider))
                    }
                    Err(ParamsError::MissingParam(param)) => {
                        Err(AuthErrorKind::missing_param(param))
                    }
                    Err(ParamsError::Params(e)) => match e.downcast_ref::<AuthErrorKind>() {
                        Some(e) => Err(e.clone()),
                        None => Err(AuthErrorKind::Unexpected(e.to_string())),
                    },
                };
                let (query, provider) =
                    res.map_err(|e| AuthCodeError::new(e, Some(state), redirect_uri.clone()))?;
                let Some(provider) = provider else {
                    return Ok(AuthKind::Default(Box::new(query)));
                };

                let state_raw = postcard::to_stdvec(&query).unwrap();
                let state = BASE64_URL_SAFE.encode(state_raw);
                let redirect_path = format!("/oauth_redirector?provider={provider}&state={state}");
                Ok(AuthKind::Redirect(redirect_path))
            }
        },
    );

    view! {
        <div class="w-dvw h-dvh flex justify-center items-center bg-neutral-900">
            <Suspense fallback=Spinner>
                {move || Suspend::new(async move {
                    let auth = auth_query.await;
                    match auth {
                        Ok(AuthKind::Default(auth)) => Either::Left(view! { <LoginContent auth /> }),
                        Ok(AuthKind::Redirect(path)) => Either::Right(view! { <Redirect path /> }),
                        Err(e) => Either::Right(view! { <Redirect path=e.to_redirect() /> }),
                    }
                })}
            </Suspense>
        </div>
    }
}

#[component]
pub fn LoginContent(auth: Box<AuthQuery>) -> impl IntoView {
    let auth_store = StoredValue::new(auth);

    view! {
        <div class="flex flex-col items-center text-white cursor-auto">
            <YralSymbol class="rounded-full mb-6 text-8xl" />
            <span class="text-2xl mb-4">Login to Yral</span>
            <div class="flex flex-col w-full gap-4 items-center">

                {#[cfg(feature = "phone-auth")]
                {
                    view! {
                        <LoginButton
                            auth=auth_store
                            attr:class="flex flex-row justify-center cursor-pointer items-center justify-between gap-1 rounded-full bg-white pr-4 hover:bg-neutral-200"
                            provider=SupportedOAuthProviders::Phone
                        >
                            <div class="grid grid-cols-1 place-items-center pl-2 py-2 rounded-full">
                                <WhatsAppSymbol class="text-xl rounded-full" />
                            </div>
                            <span class="text-neutral-900">{"Continue with Whatsapp"}</span>
                        </LoginButton>
                    }
                }} {#[cfg(feature = "google-oauth")]
                {
                    view! {
                        <LoginButton
                            auth=auth_store
                            attr:class="flex flex-row justify-center cursor-pointer items-center justify-between gap-1 rounded-full bg-white pr-4 hover:bg-neutral-200"
                            provider=SupportedOAuthProviders::Google
                        >
                            <div class="grid grid-cols-1 place-items-center pl-2 py-2 rounded-full">
                                <GoogleSymbol class="text-xl rounded-full" />
                            </div>
                            <span class="text-neutral-900">{"Continue with Google"}</span>
                        </LoginButton>
                    }
                }} {#[cfg(feature = "apple-oauth")]
                {
                    view! {
                        <LoginButton
                            auth=auth_store
                            attr:class="flex flex-row justify-center cursor-pointer items-center pr-4 bg-white rounded-full border border-gray-300 hover:bg-neutral-200"
                            provider=SupportedOAuthProviders::Apple
                        >
                            <div class="grid grid-cols-1 place-items-center">
                                <AppleSymbol class="text-4xl" />
                            </div>
                            <span class="text-black">{"Continue with Apple"}</span>
                        </LoginButton>
                    }
                }}
            </div>
        </div>
    }
}

#[component]
pub fn LoginButton(
    auth: StoredValue<Box<AuthQuery>>,
    children: Children,
    provider: SupportedOAuthProviders,
) -> impl IntoView {
    let redirect_to_oauth = move || {
        let state_raw = auth.with_value(|a| postcard::to_stdvec(a).unwrap());
        let state = BASE64_URL_SAFE.encode(state_raw);
        let redirect_path = format!("/oauth_redirector?provider={provider}&state={state}");

        let nav = use_navigate();
        (nav)(&redirect_path, NavigateOptions::default());
    };

    view! { <button on:click=move |_| redirect_to_oauth()>{children()}</button> }
}
