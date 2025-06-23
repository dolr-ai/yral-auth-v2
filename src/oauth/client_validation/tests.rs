use super::{whitelist::whitelist, OAuthClient, OAuthClientType};
use std::collections::HashMap;

#[test]
pub fn test_whitelist_macro() {
    let mut cl = HashMap::new();

    let client1 = OAuthClient {
        client_id: "test-client-1".to_string(),
        redirect_urls: vec!["https://example.com/callback".parse().unwrap()],
        client_type: OAuthClientType::Web,
    };
    let client2 = OAuthClient {
        client_id: "test-client-2".to_string(),
        redirect_urls: vec![
            "https://example.com/callback2".parse().unwrap(),
            "https://example.com/callback3".parse().unwrap(),
            "https://example.com/callback4".parse().unwrap(),
        ],
        client_type: OAuthClientType::Native,
    };
    let client3 = OAuthClient {
        client_id: "test-client-3".to_string(),
        redirect_urls: vec!["https://example.com/callback3".parse().unwrap()],
        client_type: OAuthClientType::Web,
    };
    let client4 = OAuthClient {
        client_id: "test-client-4".to_string(),
        redirect_urls: vec![],
        client_type: OAuthClientType::Preview,
    };

    whitelist!(
        cl,
        {
            "test-client-1",
            ["https://example.com/callback"],
            OAuthClientType::Web
        },
        {
            "test-client-2",
            ["https://example.com/callback2", "https://example.com/callback3", "https://example.com/callback4"],
            OAuthClientType::Native
        },
        {
            "test-client-3",
            ["https://example.com/callback3"],
            OAuthClientType::Web
        },
        {
            "test-client-4",
            [],
            OAuthClientType::Preview
        },
    );
    assert!(cl.get(client1.client_id.as_str()) == Some(&client1));
    assert!(cl.get(client2.client_id.as_str()) == Some(&client2));
    assert!(cl.get(client3.client_id.as_str()) == Some(&client3));
    assert!(cl.get(client4.client_id.as_str()) == Some(&client4));
}
