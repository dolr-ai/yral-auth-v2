use leptos::prelude::*;

use leptos_router::hooks::use_query;
use leptos_router::params::Params;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize, Params)]
struct ErrorQuery {
    error: Option<String>,
}

#[component]
pub fn ErrorPage() -> impl IntoView {
    let query = use_query::<ErrorQuery>();

    let error_string = move || {
        query
            .get()
            .ok()
            .and_then(|q| q.error)
            .unwrap_or_else(|| "An unknown error occurred.".to_string())
    };

    view! {
        <div class="flex flex-col justify-center items-center bg-black w-dvw h-dvh">
            <img src="/images/error-logo.svg" />
            <h1 class="p-2 text-2xl font-bold text-white md:text-3xl">"oh no!"</h1>
            <div class="px-8 mb-4 w-full text-xs text-center resize-none md:w-2/3 md:text-sm lg:w-1/3 text-white/60">
                {error_string.clone()}
            </div>
        </div>
    }
}
