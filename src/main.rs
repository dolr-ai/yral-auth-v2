use std::sync::Arc;

use axum::{
    body::Body as AxumBody,
    extract::{Path, State},
    http::Request,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Router,
};
use leptos::{config::get_configuration, logging::log, prelude::provide_context};
use leptos_axum::{generate_route_list, handle_server_fns_with_context, LeptosRoutes};
use yral_auth_v2::{
    api::server_impl::{
        handle_oauth_token_grant, handle_oidc_configuration, handle_well_known_jwks,
    },
    app::{shell, App},
    context::server::{ServerCtx, ServerState},
};

async fn server_fn_handler(
    State(app_state): State<ServerState>,
    _path: Path<String>,
    request: Request<AxumBody>,
) -> impl IntoResponse {
    handle_server_fns_with_context(
        move || {
            provide_context(app_state.ctx.clone());
        },
        request,
    )
    .await
}

async fn leptos_routes_handler(state: State<ServerState>, req: Request<AxumBody>) -> Response {
    let State(app_state) = state.clone();
    let handler = leptos_axum::render_route_with_context(
        app_state.routes.clone(),
        move || {
            provide_context(app_state.ctx.clone());
        },
        move || shell(app_state.leptos_options.clone()),
    );
    handler(state, req).await.into_response()
}

fn server_routes(ctx: Arc<ServerCtx>) -> Router {
    Router::new()
        .route("/oauth/token", post(handle_oauth_token_grant))
        .route("/.well-known/jwks.json", get(handle_well_known_jwks))
        .route(
            "/.well-known/openid-configuration",
            get(handle_oidc_configuration),
        )
        .layer(Extension(ctx))
}

#[tokio::main]
async fn main() {
    let _guard = sentry::init((
        "https://c53f9a4a36ea0d767540c5e8ee31f2ee@apm.yral.com/5",
        sentry::ClientOptions {
            release: sentry::release_name!(),
            // Capture user IPs and potentially sensitive headers when using HTTP server integrations
            // see https://docs.sentry.io/platforms/rust/data-management/data-collected for more info
            send_default_pii: true,
            ..Default::default()
        },
    ));

    simple_logger::init_with_level(log::Level::Debug).expect("couldn't initialize logging");

    let conf = get_configuration(None).unwrap();
    let addr = conf.leptos_options.site_addr;
    let leptos_options = conf.leptos_options;
    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(App);

    dotenvy::dotenv().ok();

    let ctx = Arc::new(ServerCtx::new().await);
    let app_state = ServerState {
        leptos_options,
        routes: routes.clone(),
        ctx: ctx.clone(),
    };

    let app = Router::new()
        .route(
            "/api/*fn_name",
            get(server_fn_handler).post(server_fn_handler),
        )
        .leptos_routes_with_handler(routes, get(leptos_routes_handler))
        .fallback(leptos_axum::file_and_error_handler::<ServerState, _>(shell))
        .with_state(app_state)
        .merge(server_routes(ctx))
        .layer(sentry_tower::NewSentryLayer::new_from_top())
        .layer(sentry_tower::SentryLayer::new_from_top());

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    log!("listening on http://{}", &addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
