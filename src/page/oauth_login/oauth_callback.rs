use leptos::prelude::*;
use leptos_router::{components::Redirect, hooks::use_query, params::Params};

use crate::{
    components::spinner::Spinner,
    error::{AuthError, AuthErrorKind},
};

#[derive(Params, Debug, PartialEq, Clone)]
pub struct OAuthQuery {
    pub code: Option<String>,
    pub state: Option<String>,
}

#[server]
pub async fn perform_oauth_login(code: String, state: String) -> Result<String, ServerFnError> {
    use super::server_impl::perform_oauth_login_impl;
    perform_oauth_login_impl(code, state).await
}

#[component]
pub fn OAuthCallbackPage() -> impl IntoView {
    let query = use_query::<OAuthQuery>();
    let res = Resource::new(
        move || query.get(),
        async move |query| {
            let Ok(query) = query else {
                return Err(AuthError::new(
                    AuthErrorKind::missing_param("code"),
                    "/error",
                ));
            };
            let Some(code) = query.code else {
                return Err(AuthError::new(
                    AuthErrorKind::missing_param("code"),
                    "/error",
                ));
            };
            let Some(state_b64) = query.state else {
                return Err(AuthError::new(
                    AuthErrorKind::missing_param("state"),
                    "/error",
                ));
            };

            perform_oauth_login(code, state_b64)
                .await
                .map_err(|e| AuthError::new(AuthErrorKind::Unexpected(e.to_string()), "/error"))
        },
    );

    view! {
        <Suspense fallback=move || view! { <div class="w-dvw h-dvh flex items-center justify-center bg-black"><Spinner/></div> }>
            {move || Suspend::new(async move {
                let redirect_res = res.await.unwrap_or_else(|e| e.as_redirect());
                view! { <Redirect path=redirect_res/> }
            })}
        </Suspense>
    }
}
