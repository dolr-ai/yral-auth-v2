use leptos::prelude::*;
use leptos_router::{hooks::use_query, params::Params};

use crate::{components::spinner::Spinner, error::AuthErrorKind, oauth::AuthCodeError};

#[derive(Params, Debug, PartialEq, Clone)]
pub struct OAuthQuery {
    pub code: Option<String>,
    pub state: Option<String>,
}

#[server]
pub async fn perform_oauth_login(code: String, state: String) -> Result<String, ServerFnError> {
    use crate::api::oauth_server_impl::perform_oauth_login_impl;
    perform_oauth_login_impl(code, state).await
}

#[component]
fn UrlOrIntentRedirect(url: String) -> impl IntoView {
    #[cfg(feature = "ssr")]
    {
        use leptos_axum::redirect;
        redirect(&url);
    }
    #[cfg(not(feature = "ssr"))]
    {
        let res = window()
            .location()
            .set_href(&url)
            .map_err(|e| format!("{e:?}"));
        if let Err(e) = res {
            log::error!("Failed to redirect: {e}");
        }
    }
}

#[component]
pub fn OAuthCallbackPage() -> impl IntoView {
    let query = use_query::<OAuthQuery>();
    let res = Resource::new(
        move || query.get(),
        async move |query| {
            let Ok(query) = query else {
                return Err(AuthCodeError::new(
                    AuthErrorKind::missing_param("state"),
                    None,
                    "/error",
                ));
            };
            let Some(state_b64) = query.state else {
                return Err(AuthCodeError::new(
                    AuthErrorKind::missing_param("state"),
                    None,
                    "/error",
                ));
            };
            let Some(code) = query.code else {
                return Err(AuthCodeError::new(
                    AuthErrorKind::missing_param("code"),
                    None,
                    "/error",
                ));
            };

            perform_oauth_login(code, state_b64).await.map_err(|e| {
                AuthCodeError::new(AuthErrorKind::Unexpected(e.to_string()), None, "/error")
            })
        },
    );

    view! {
        <Suspense fallback=move || {
            view! {
                <div class="w-dvw h-dvh flex items-center justify-center bg-black">
                    <Spinner />
                </div>
            }
        }>
            {move || Suspend::new(async move {
                let redirect_res = res.await.unwrap_or_else(|e| e.to_redirect());
                view! { <UrlOrIntentRedirect url=redirect_res /> }
            })}
        </Suspense>
    }
}
