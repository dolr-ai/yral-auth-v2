use candid::Principal;
use sentry::protocol::User;

/// Set Sentry user context using a Principal
///
/// This is safe to use as it only exposes the Principal string,
/// never any sensitive identity data like private keys or delegations
pub fn set_user_context(user_principal: Principal) {
    sentry::configure_scope(|scope| {
        scope.set_user(Some(User {
            id: Some(user_principal.to_text()),
            ..Default::default()
        }));
    });
}

/// Set Sentry user context with additional metadata
///
/// # Arguments
/// * `user_principal` - The user's Principal identifier
/// * `email` - Optional email address
/// * `is_anonymous` - Whether this is an anonymous user
pub fn set_user_context_with_metadata(
    user_principal: Principal,
    email: Option<String>,
    is_anonymous: bool,
) {
    sentry::configure_scope(|scope| {
        let mut user = User {
            id: Some(user_principal.to_text()),
            ..Default::default()
        };

        if let Some(email) = email {
            user.email = Some(email);
        }

        user.other.insert(
            "is_anonymous".to_string(),
            serde_json::Value::Bool(is_anonymous),
        );

        scope.set_user(Some(user));
    });
}

/// Clear the current user context
pub fn clear_user_context() {
    sentry::configure_scope(|scope| {
        scope.set_user(None);
    });
}

/// Add a custom tag to the current Sentry scope
///
/// Useful for categorizing errors by client type, grant type, etc.
pub fn add_tag(key: &str, value: &str) {
    sentry::configure_scope(|scope| {
        scope.set_tag(key, value);
    });
}

/// Add structured context data to the current Sentry scope
///
/// # Arguments
/// * `key` - The context key (e.g., "oauth_flow", "client_info")
/// * `context` - A serializable context object
pub fn add_context<C: serde::Serialize>(key: &str, context: C) {
    if let Ok(value) = serde_json::to_value(context) {
        sentry::configure_scope(|scope| {
            scope.set_context(
                key,
                sentry::protocol::Context::Other(
                    value
                        .as_object()
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .collect(),
                ),
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_user_context() {
        let principal = Principal::from_text("2vxsx-fae").unwrap();
        set_user_context(principal);
        // Actual verification would require mocking the Sentry SDK
    }

    #[test]
    fn test_set_user_context_with_metadata() {
        let principal = Principal::from_text("2vxsx-fae").unwrap();
        set_user_context_with_metadata(principal, Some("test@example.com".to_string()), false);
    }

    #[test]
    fn test_clear_user_context() {
        clear_user_context();
    }

    #[test]
    fn test_add_tag() {
        add_tag("grant_type", "authorization_code");
    }
}
