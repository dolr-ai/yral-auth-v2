use std::sync::Arc;

use leptos::server;
use leptos::prelude::*;
use leptos::server_fn::codec::Json;
use leptos_router::NavigateOptions;
use leptos_router::components::Redirect;
use leptos_router::hooks::{use_navigate, use_query};
use leptos_router::params::Params;
use serde::{Deserialize, Serialize};

use crate::components::spinner::Spinner;
use crate::error::AuthError;
use crate::error::AuthErrorKind;
use crate::oauth::AuthQuery;
use crate::oauth::client_validation::ClientIdValidator;

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize, Params)]
struct AuthClientQuery {
    auth_client_state: Option<String>,
}


#[cfg(feature = "ssr")]
async  fn handle_phone_auth_impl(
    auth_client_query: AuthQuery,
    phone_number: String,
) -> Result<(), AuthErrorKind> {
    use crate::api::phone_auth::generate_otp_and_set_cookie;

    let server_ctx = expect_context::<Arc<crate::context::server::ServerCtx>>();

    server_ctx
        .validator
        .validate_id_and_redirect(
            &auth_client_query.client_id,
            &auth_client_query.redirect_uri,
        )
        .await?;

    generate_otp_and_set_cookie(&server_ctx, phone_number, auth_client_query).await

}


#[server(endpoint = "/phone_auth_login", input = Json, output = Json)]
async fn handle_phone_auth(
    auth_client_query: AuthQuery,
    phone_number: String,
) -> Result<(), AuthError> {

    let result = handle_phone_auth_impl(auth_client_query, phone_number).await;
    let response_options = expect_context::<leptos_axum::ResponseOptions>();

    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            print!("Error in handle_phone_auth: {:?}", e.status_code());
            let status_code = e.status_code();
            response_options.set_status(status_code);
            Err(e.into())
        }
    }
    
}


#[component]
pub fn PhoneAuthLogin() -> impl IntoView {

    let auth_client_query = use_query::<AuthClientQuery>();


    let nav = use_navigate();
    let submit_action = Action::new({
        let nav = nav.clone();
        move |(auth_client_query, phone_number): &(AuthQuery, String)| {
            let auth_client_query = auth_client_query.clone();
            let phone_number = phone_number.clone();
            let nav = nav.clone();
            async move {
                let client_state = auth_client_query.state.clone();
                handle_phone_auth(auth_client_query, phone_number.clone()).await.map_err(|e|e.to_string())?;
                let redirect_path = format!("/phone/verify?phone={}&auth_client_state={}",
                    phone_number,
                    client_state
                );
                leptos::logging::log!("Navigating to {}", redirect_path);
                nav(&redirect_path, NavigateOptions { replace: true, ..Default::default() });
                leptos::logging::log!("Navigation completed");
                Ok::<_, String>(())
            }
        }
    });


    let client_auth_query = Resource::new_blocking(
        move || auth_client_query.get(),
        async move |query| {
            let query = query.map_err(|e|e.to_string())?;
            let Some(state) = query.auth_client_state else {
                return Err("missing auth_client_state".to_string());
            };

            use crate::oauth::AuthQuery;
            use base64::{Engine, prelude::BASE64_URL_SAFE};

            let auth_client_query_raw = BASE64_URL_SAFE
                .decode(state)
                .map_err(|e| format!("invalid state {e:?}"))?;
            let auth_client_query: AuthQuery = postcard::from_bytes(&auth_client_query_raw)
                .map_err(|e| format!("invalid auth query {}", e.to_string()))?;

            Ok(auth_client_query)
        },
    );

    let (phone_number, set_phone_number) = signal(String::new());
    let (error_message, set_error_message) = signal(Option::<String>::None);

    view! {
        <Suspense fallback=|| {
            view! {
                <div class="w-dvw h-dvh bg-black flex justify-center items-center">
                    <Spinner />
                </div>
            }
        }>
            {move || Suspend::new(async move {
                let client_query_res = client_auth_query.await;
                match client_query_res {
                    Err(e) => view! { <Redirect path=format!("/error?error={e}") /> }.into_any(),
                    Ok(auth_client_query) => {
                        view! {
                            <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                                <div class="bg-white rounded-lg shadow-xl max-w-md w-full mx-4">
                                    <div class="p-6">
                                        <div class="space-y-4">
                                            <h2 class="text-2xl font-bold text-gray-900">
                                                "Phone Login"
                                            </h2>
                                            <p class="text-gray-600">
                                                "Enter your phone number to continue"
                                            </p>

                                            {move || {
                                                error_message
                                                    .get()
                                                    .map(|msg| {
                                                        view! {
                                                            <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
                                                                {msg}
                                                            </div>
                                                        }
                                                    })
                                            }}

                                            <input
                                                type="tel"
                                                placeholder="+1 (555) 123-4567"
                                                class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                                prop:value=phone_number
                                                on:input=move |ev| {
                                                    println!("Phone input changed: {:?}", ev);
                                                    set_phone_number.set(event_target_value(&ev));
                                                }
                                            />

                                            <button
                                                class="w-full bg-blue-600 text-white py-3 px-4 rounded-lg font-semibold hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
                                                // You may need to define send_otp or replace with the correct handler
                                                on:click=move |_| {
                                                    let auth_client_query = auth_client_query.clone();
                                                    let phone_number = phone_number.get();
                                                    let submit_action = submit_action.clone();
                                                    submit_action.dispatch((auth_client_query, phone_number));
                                                }
                                                disabled=move || {
                                                    submit_action.pending().get()
                                                        || phone_number.get().is_empty()
                                                }
                                            >
                                                {move || {
                                                    if submit_action.pending().get() {
                                                        "Sending..."
                                                    } else {
                                                        "Next"
                                                    }
                                                }}
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        }
                            .into_any()
                    }
                }
            })}
        </Suspense>
    }
}
