use std::sync::Arc;

use leptos::html::nav;
use leptos::logging::log;
use leptos::prelude::*;
use leptos_router::hooks::use_query;
use leptos_router::params::Params;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::AuthError;
use crate::components::otp_input::OtpInput;

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize, Params)]
struct VerifyQuery {
    phone: Option<String>,
    auth_client_state: Option<String>,

}


#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct VerifyPhoneOtpRequest {
    pub code: String, //otp code
    pub phone_number: String, // phone number
    pub client_state: String // client state (csrf token)
}

#[server]
pub async fn verify_phone_auth(verify_request: VerifyPhoneOtpRequest) -> Result<(String, Url), AuthError> {
    use crate::context::server::ServerCtx;
    use crate::api::phone_auth::verify_phone_one_time_passcode;

    let server_ctx = expect_context::<Arc<ServerCtx>>();

    let (token, redirect_uri) = verify_phone_one_time_passcode(&server_ctx, verify_request).await?;

    Ok((token, redirect_uri))

}

#[component]
pub fn VerifyPhoneAuth() -> impl IntoView {
    let query = use_query::<VerifyQuery>();

    let (error_message, set_error_message) = signal(Option::<String>::None);
    let (is_resending, set_is_resending) = signal(false);

    let phone_number = move || {
        query
            .get()
            .ok()
            .and_then(|q| q.phone)
            .unwrap_or_else(|| "Unknown".to_string())
    };

    let verify_action = Action::new(move |otp: &String| {
        let otp = otp.clone();
        async move {
            // Get phone and auth_client_state from query
            let query_result = query.get();
            if let Ok(q) = query_result {
                let phone = q.phone.clone().unwrap_or_default();
                let client_state = q.auth_client_state.clone().unwrap_or_default();
                
                let verify_request = VerifyPhoneOtpRequest {
                    code: otp,
                    phone_number: phone,
                    client_state,
                };
                
                let navigate = leptos_router::hooks::use_navigate();
                match verify_phone_auth(verify_request).await {
                    Ok(token) => {

                        let (_token, redirect_uri) = token;
                        // Only call use_navigate on the client, not during SSR
                        navigate(&redirect_uri.to_string(), Default::default());
                        Ok(())
                    }
                    Err(e) => {
                        set_error_message.set(Some(format!("Verification failed: {}", e)));
                        Ok(())
                    }
                }
            } else {
                Err("Missing verification details".to_string())
            }
        }
    });

    let handle_otp_complete = move |otp: String| {
        set_error_message.set(None);
        verify_action.dispatch(otp);
    };

    // Watch for action completion and update error message
    Effect::new(move |_| {
        if let Some(result) = verify_action.value().get() {
            if let Err(e) = result {
                set_error_message.set(Some(e));
            }
        }
    });

    let handle_otp_change = move |_otp: String| {
        // Clear error when user starts typing
        if error_message.get().is_some() {
            set_error_message.set(None);
        }
    };

    let handle_resend = move |_| {
        set_is_resending.set(true);
        set_error_message.set(None);

        // TODO: Implement actual resend OTP logic
        log!("Resending OTP to: {}", phone_number());

        set_timeout(
            move || {
                set_is_resending.set(false);
                // TODO: Show success message
            },
            std::time::Duration::from_secs(1),
        );
    };

    view! {
        <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div class="bg-white rounded-lg shadow-xl max-w-md w-full mx-4">
                <div class="p-6">
                    <div class="space-y-6">
                        <div class="text-center">
                            <h2 class="text-2xl font-bold text-gray-900 mb-2">
                                "Verify Phone Number"
                            </h2>
                            <p class="text-gray-600 text-sm">"We've sent a 6-digit code to"</p>
                            <p class="text-gray-900 font-semibold text-lg mt-1">{phone_number}</p>
                        </div>

                        {move || {
                            error_message
                                .get()
                                .map(|msg| {
                                    view! {
                                        <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm">
                                            {msg}
                                        </div>
                                    }
                                })
                        }}

                        <div class="py-4">
                            <OtpInput
                                digit_count=6
                                on_complete=Callback::new(handle_otp_complete)
                                on_change=Callback::new(handle_otp_change)
                                disabled=Signal::derive(move || verify_action.pending().get())
                            />
                        </div>

                        {move || {
                            if verify_action.pending().get() {
                                view! {
                                    <div class="flex justify-center items-center py-4">
                                        <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                                        <span class="ml-3 text-gray-600">"Verifying..."</span>
                                    </div>
                                }
                                    .into_any()
                            } else {
                                view! {
                                    <div class="text-center">
                                        <p class="text-gray-600 text-sm mb-2">
                                            "Didn't receive the code?"
                                        </p>
                                        <button
                                            class="text-blue-600 font-semibold hover:text-blue-700 disabled:text-gray-400 disabled:cursor-not-allowed transition-colors"
                                            on:click=handle_resend
                                            disabled=is_resending.get()
                                        >
                                            {move || {
                                                if is_resending.get() {
                                                    "Sending..."
                                                } else {
                                                    "Resend Code"
                                                }
                                            }}
                                        </button>
                                    </div>
                                }
                                    .into_any()
                            }
                        }}

                        <div class="pt-4 border-t border-gray-200">
                            <p class="text-gray-500 text-xs text-center">
                                "Enter the 6-digit code we sent to your phone. "
                                "The code expires in 10 minutes."
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}
