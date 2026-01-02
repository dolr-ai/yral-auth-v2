use leptos::prelude::{expect_context, provide_context};

use crate::oauth::client_validation::ClientIdValidatorImpl;

#[cfg(feature = "ssr")]
pub mod server;

#[cfg(all(feature = "ssr", feature = "phone-auth"))]
pub mod message_delivery_service;

pub fn provide_client_id_validator() {
    provide_context(ClientIdValidatorImpl::Const(Default::default()));
}

pub fn client_id_validator() -> ClientIdValidatorImpl {
    expect_context::<ClientIdValidatorImpl>()
}
