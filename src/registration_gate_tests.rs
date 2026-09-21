//! The registration gate, end to end (Task 7).
//!
//! A software WebAuthn authenticator is exactly the attacker's tool: it
//! produces a ceremony indistinguishable from a real one without any hardware.
//! The gate must refuse it on the grounds that it **never attested**, not on
//! the grounds that its passkey looked wrong — nothing downstream can tell a
//! synthetic passkey from a real one.
//!
//! These live in the binary target rather than `tests/registration_gate.rs`
//! because `AppState` is bin-local (see the note at the top of `src/lib.rs`).
//! Moving it into the library to satisfy a test layout would drag `db`,
//! `patreon` and `device_check` along with it.

use crate::AppState;
use crate::device_check::{RegistrationTicket, SESSION_REG_TICKET_KEY};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Extension, Router};
use tower::ServiceExt;
use tower_sessions::{MemoryStore, SessionManagerLayer};

/// The registration surface, wired exactly as `main()` wires it.
async fn gate_router() -> Router {
    unsafe {
        std::env::set_var("AWS_REGION", "us-east-1");
        std::env::set_var("AWS_ACCESS_KEY_ID", "fake_access_key");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "fake_secret_key");
    }
    let app_state: AppState = crate::test_helpers::build_test_app_state().await;

    // POST /register is left out: it needs the Patreon extension and a live
    // DynamoDB, and the ticket check it performs is covered by
    // `authn::tests::a_session_holding_an_expired_ticket_is_refused`.
    Router::new()
        .route("/register/:username", get(crate::authn::start_register))
        .route(
            "/device-check/register-challenge",
            get(crate::device_check::register_challenge),
        )
        // Test-only: stands in for a successful attestation, which needs
        // hardware. It writes the same ticket `register_attest` writes, into
        // the same session key, so `start_register` cannot tell the
        // difference — which is the point.
        .route("/test-only/seed-ticket", get(seed_ticket))
        .layer(Extension(app_state))
        .layer(SessionManagerLayer::new(MemoryStore::default()))
}

/// Writes a live [`RegistrationTicket`] into the caller's session.
async fn seed_ticket(session: tower_sessions::Session) -> StatusCode {
    let now = chrono::Utc::now().timestamp();
    session
        .insert(
            SESSION_REG_TICKET_KEY,
            RegistrationTicket {
                key_id: "attested-key".into(),
                issued_at: now,
                expires_at: now + 300,
            },
        )
        .await
        .unwrap();
    StatusCode::OK
}

/// The `Set-Cookie` value a response establishes, reduced to a `Cookie` header.
fn session_cookie(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .expect("a session must be established")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

fn register_uri(username: &str) -> String {
    format!("/register/{username}?handle={username}.arkavo.social&did=did:key:z6MkTest")
}

#[tokio::test]
async fn registration_without_a_ticket_is_refused() {
    let app = gate_router().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(register_uri("softbot"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "an unattested caller must be refused before the ceremony begins"
    );
}

#[tokio::test]
async fn no_webauthn_challenge_leaks_to_an_unattested_caller() {
    let app = gate_router().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(register_uri("doesnotexist"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);

    // Not a substring search for "challenge": the refusal text names the
    // preflight route, which contains that word. The property is that no
    // WebAuthn credential-creation options come back — their presence is what
    // would confirm the handle is registerable.
    assert!(
        serde_json::from_slice::<serde_json::Value>(&body).is_err(),
        "the refusal must not be a WebAuthn options document: {text}"
    );
    assert!(
        !text.contains("publicKey") && !text.contains("\"challenge\""),
        "no WebAuthn challenge may leak to an unattested caller: {text}"
    );
}

#[tokio::test]
async fn the_refusal_does_not_depend_on_whether_the_handle_exists() {
    // The gate is checked before any DB lookup, so these two must be
    // byte-identical. If they ever diverge, /register has become a handle
    // oracle for callers who never attested.
    let taken = gate_router().await;
    let free = gate_router().await;

    let a = taken
        .oneshot(
            Request::builder()
                .uri(register_uri("alice"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let a_status = a.status();
    let a_body = axum::body::to_bytes(a.into_body(), 64 * 1024)
        .await
        .unwrap();

    let b = free
        .oneshot(
            Request::builder()
                .uri(register_uri("zzzznobody"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let b_status = b.status();
    let b_body = axum::body::to_bytes(b.into_body(), 64 * 1024)
        .await
        .unwrap();

    assert_eq!(a_status, StatusCode::FORBIDDEN);
    assert_eq!(a_status, b_status);
    assert_eq!(
        a_body, b_body,
        "the refusal must not vary with the username"
    );
}

#[tokio::test]
async fn a_ticketed_session_is_not_refused_by_the_gate() {
    // Keeps the gate honest in the other direction: "refuse everything" would
    // pass every test above. The request still fails — there is no DynamoDB
    // behind it — but it must not fail with 403, which is the only status
    // this gate produces.
    let app = gate_router().await;

    let seeded = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/test-only/seed-ticket")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(seeded.status(), StatusCode::OK);
    let cookie = session_cookie(&seeded);

    let response = app
        .oneshot(
            Request::builder()
                .uri(register_uri("softbot"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a ticketed session must reach the ceremony, not the gate"
    );
}

#[tokio::test]
async fn the_preflight_challenge_itself_needs_no_attestation() {
    // The way in must stay open, or the gate is a lockout rather than a gate.
    let app = gate_router().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/device-check/register-challenge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
