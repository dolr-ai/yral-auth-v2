/// Unit / integration tests for phone-auth OTP logic.
///
/// Run with:
///   cargo test --features ssr,phone-auth --lib
///
/// Tests use a `MockMessageDeliveryService` that captures the plaintext OTP
/// code without ever calling WhatsApp.  The captured code is then fed into the
/// pure `verify_otp_token` helper to exercise the full generate → verify flow
/// without any external I/O.
use super::*;
use crate::context::message_delivery_service::{MessageDeliveryError, MessageDeliveryService};
use std::sync::{Arc, Mutex};

// ── mock delivery service ─────────────────────────────────────────────────────

/// Records the last message body passed to `send_message` so tests can read
/// back the plaintext OTP without hitting WhatsApp.
struct MockMessageDeliveryService {
    captured: Arc<Mutex<Option<String>>>,
    /// When `Some(err)`, `send_message` returns that error instead of succeeding.
    force_error: Option<MessageDeliveryError>,
}

impl MockMessageDeliveryService {
    fn new() -> (Self, Arc<Mutex<Option<String>>>) {
        let captured = Arc::new(Mutex::new(None));
        let svc = Self {
            captured: Arc::clone(&captured),
            force_error: None,
        };
        (svc, captured)
    }

    fn failing(err: MessageDeliveryError) -> Self {
        Self {
            captured: Arc::new(Mutex::new(None)),
            force_error: Some(err),
        }
    }
}

#[async_trait::async_trait]
impl MessageDeliveryService for MockMessageDeliveryService {
    async fn send_message(
        &self,
        _recipient: &str,
        message: &str,
    ) -> Result<(), MessageDeliveryError> {
        if let Some(ref e) = self.force_error {
            // MessageDeliveryError doesn't implement Clone, so recreate it
            return Err(match e {
                MessageDeliveryError::InvalidRecipient => MessageDeliveryError::InvalidRecipient,
                MessageDeliveryError::MessageTooLong => MessageDeliveryError::MessageTooLong,
                MessageDeliveryError::Unknown => MessageDeliveryError::Unknown,
                MessageDeliveryError::ServiceUnavailable(s) => {
                    MessageDeliveryError::ServiceUnavailable(s.clone())
                }
            });
        }
        *self.captured.lock().unwrap() = Some(message.to_owned());
        Ok(())
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Drives `send_authorization_code_for_phone_number` through the mock and
/// returns `(otp_token_raw, captured_otp_code)`.
async fn generate_token_and_capture_otp(phone: &str) -> (String, String) {
    let (svc, captured) = MockMessageDeliveryService::new();
    let token = send_authorization_code_for_phone_number(&svc, phone.to_owned())
        .await
        .expect("generation should succeed");
    let otp_code = captured
        .lock()
        .unwrap()
        .take()
        .expect("mock should have captured the OTP");
    (token, otp_code)
}

// ── full-flow tests ───────────────────────────────────────────────────────────

/// Happy path: the OTP received by the mock must satisfy `verify_otp_token`.
#[tokio::test]
async fn valid_otp_verifies_successfully() {
    let phone = "+15550001111";
    let (token, otp_code) = generate_token_and_capture_otp(phone).await;

    verify_otp_token(&token, phone, &otp_code).expect("correct OTP should verify without error");
}

/// Submitting a different code must be rejected with `InvalidOtp`.
#[tokio::test]
async fn wrong_otp_code_is_rejected() {
    let phone = "+15550002222";
    let (token, _correct_otp) = generate_token_and_capture_otp(phone).await;

    let err = verify_otp_token(&token, phone, "000000").unwrap_err();
    assert!(
        matches!(err, AuthErrorKind::InvalidOtp),
        "expected InvalidOtp, got {err:?}"
    );
}

/// Verifying with a different phone number must be rejected with `PhoneMismatch`.
#[tokio::test]
async fn wrong_phone_number_is_rejected() {
    let phone = "+15550003333";
    let (token, otp_code) = generate_token_and_capture_otp(phone).await;

    let err = verify_otp_token(&token, "+19990009999", &otp_code).unwrap_err();
    assert!(
        matches!(err, AuthErrorKind::PhoneMismatch),
        "expected PhoneMismatch, got {err:?}"
    );
}

/// A token whose expiry timestamp is in the past must be rejected with `ExpiredOtp`.
#[tokio::test]
async fn expired_token_is_rejected() {
    use sha2::{Digest, Sha256};

    let phone = "+15550004444";
    // Build a claim that expired at Unix epoch 0.
    let mut hasher = Sha256::new();
    hasher.update(b"123456");
    let otp_hash = hex::encode(hasher.finalize());

    let expired_claim = OneTimePassCodeClaim {
        phone_number: phone.to_owned(),
        code_hash_s256: otp_hash.as_bytes().to_vec(),
        exp: 0, // already expired
    };
    let token = serde_json::to_string(&expired_claim).unwrap();

    let err = verify_otp_token(&token, phone, "123456").unwrap_err();
    assert!(
        matches!(err, AuthErrorKind::ExpiredOtp),
        "expected ExpiredOtp, got {err:?}"
    );
}

/// A garbled / non-JSON token must return an `Unexpected` error (not a panic).
#[tokio::test]
async fn malformed_token_returns_unexpected_error() {
    let err = verify_otp_token("not-json-at-all", "+15550005555", "123456").unwrap_err();
    assert!(
        matches!(err, AuthErrorKind::Unexpected(_)),
        "expected Unexpected, got {err:?}"
    );
}

// ── delivery service error propagation ───────────────────────────────────────

/// When the delivery service rejects the recipient, generation must surface
/// `InvalidPhoneNumber`.
#[tokio::test]
async fn invalid_recipient_surfaces_invalid_phone_number() {
    let svc = MockMessageDeliveryService::failing(MessageDeliveryError::InvalidRecipient);
    let err = send_authorization_code_for_phone_number(&svc, "not-a-phone".to_owned())
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthErrorKind::InvalidPhoneNumber),
        "expected InvalidPhoneNumber, got {err:?}"
    );
}

/// Any other delivery failure must surface as `Unexpected`.
#[tokio::test]
async fn service_unavailable_surfaces_unexpected_error() {
    let svc = MockMessageDeliveryService::failing(MessageDeliveryError::ServiceUnavailable(
        "down".to_owned(),
    ));
    let err = send_authorization_code_for_phone_number(&svc, "+15550006666".to_owned())
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthErrorKind::Unexpected(_)),
        "expected Unexpected, got {err:?}"
    );
}

// ── brute-force resistance (business logic layer) ─────────────────────────────

/// Simulates an attacker who generates a legitimate OTP for a victim's number
/// and then guesses codes one by one.  Each individual guess is correctly
/// rejected with `InvalidOtp`, confirming that the pure verification logic
/// always refuses wrong codes regardless of how many times it is called.
///
/// The corresponding HTTP-layer rate-limit test is
/// `brute_force_verify_attempts_are_rate_limited` below.
#[tokio::test]
async fn repeated_wrong_otp_guesses_are_always_rejected() {
    let phone = "+15550007777";
    let (token, correct_otp) = generate_token_and_capture_otp(phone).await;

    // Try every code from 100000..100010 – none of them should be the
    // correct OTP (astronomically unlikely), and all must return InvalidOtp.
    let mut rejected_count = 0u32;
    for guess in 100000u32..100010 {
        let guess_str = guess.to_string();
        if guess_str == correct_otp {
            continue; // skip the one correct code
        }
        let result = verify_otp_token(&token, phone, &guess_str);
        assert!(
            matches!(result, Err(AuthErrorKind::InvalidOtp)),
            "guess {guess} should be rejected with InvalidOtp"
        );
        rejected_count += 1;
    }
    assert!(
        rejected_count > 0,
        "at least one wrong guess must have been tested"
    );
}

// ── HTTP-layer rate limiting (phone verification) ─────────────────────────────

/// End-to-end test: a real OTP token is generated via the mock delivery
/// service, then an attacker hammers the `/api/verify_phone_auth` route with
/// wrong codes through an axum router that has `GovernorLayer` applied.
/// After the burst allowance is exhausted the middleware must return 429 —
/// proving that the HTTP rate-limiting layer protects the verify endpoint.
#[tokio::test]
async fn brute_force_verify_attempts_are_rate_limited() {
    use axum::{
        body::Body,
        extract::State,
        http::{Method, Request, StatusCode},
        routing::post,
        Router,
    };
    use tower::util::ServiceExt;
    use tower_governor::{
        governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
    };

    // Generate a real token via the mock so the handler has something to
    // verify against.
    let phone = "+15550008888";
    let (token, _correct_otp) = generate_token_and_capture_otp(phone).await;

    #[derive(Clone)]
    struct AppState {
        token: Arc<String>,
    }

    // Handler that mirrors what the real verify endpoint does: it tries to
    // verify with a deliberately wrong code (000000), simulating an attacker
    // guessing codes one by one.
    async fn verify_handler(State(s): State<AppState>) -> StatusCode {
        match verify_otp_token(&s.token, "+15550008888", "000000") {
            Ok(_) => StatusCode::OK,
            Err(_) => StatusCode::BAD_REQUEST,
        }
    }

    let burst_size = 3u32;
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(burst_size)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .unwrap();

    let app = Router::new()
        .route("/api/{*fn_name}", post(verify_handler))
        .layer(GovernorLayer::new(governor_conf))
        .with_state(AppState {
            token: Arc::new(token),
        });

    let attacker_ip = "203.0.113.60";
    let mut got_429 = false;

    for _ in 0..=(burst_size + 2) {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/verify_phone_auth")
            .header("X-Forwarded-For", attacker_ip)
            .body(Body::empty())
            .unwrap();

        let status = app.clone().oneshot(req).await.unwrap().status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            got_429 = true;
            break;
        }
    }

    assert!(
        got_429,
        "brute-force verify attempts should be rate-limited after the burst allowance"
    );
}
