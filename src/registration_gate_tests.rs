//! The registration gate, end to end (Task 7).
//!
//! A software WebAuthn authenticator is exactly the attacker's tool: it
//! produces a ceremony indistinguishable from a real one without any hardware.
//! The gate must refuse it on the grounds that it **never attested**, not on
//! the grounds that its passkey looked wrong — nothing downstream can tell a
//! synthetic passkey from a real one.
//!
//! Two layers. The start-side tests below need no database: the gate is
//! checked before any lookup. The ceremony tests at the bottom drive a real
//! software authenticator (`webauthn-authenticator-rs` `SoftPasskey`) through
//! `GET /register/:username` and `POST /register` against DynamoDB Local, and
//! cover what only the finish side does — the ticket re-check, the budget
//! charge, consuming the ticket, and refusing a replay. They skip unless
//! `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set, as CI's `test` job sets it.
//!
//! These live in the binary target rather than `tests/registration_gate.rs`
//! because `AppState` is bin-local (see the note at the top of `src/lib.rs`).
//! Moving it into the library to satisfy a test layout would drag `db`,
//! `patreon` and `device_check` along with it.

use crate::AppState;
use crate::device_check::{RegistrationTicket, SESSION_REG_TICKET_KEY};
use axum::body::Body;
use axum::extract::Query;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Extension, Router};
use std::sync::Arc;
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

    // POST /register is left out: it needs a live DynamoDB. See
    // `ceremony_router` for the finish side.
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

#[derive(serde::Deserialize)]
struct SeedParams {
    key_id: Option<String>,
    /// Seconds from now; negative seeds an already-expired ticket.
    expires_in: Option<i64>,
}

/// Writes a [`RegistrationTicket`] into the caller's session — live and for
/// `attested-key` unless the query says otherwise.
async fn seed_ticket(
    session: tower_sessions::Session,
    Query(params): Query<SeedParams>,
) -> StatusCode {
    let now = chrono::Utc::now().timestamp();
    session
        .insert(
            SESSION_REG_TICKET_KEY,
            RegistrationTicket {
                key_id: params.key_id.unwrap_or_else(|| "attested-key".into()),
                issued_at: now,
                expires_at: now + params.expires_in.unwrap_or(300),
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

// ---------------------------------------------------------------------------
// The finish side, driven by a real software authenticator
// ---------------------------------------------------------------------------

use crate::db::DynamoDBStore;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};

/// The whole registration surface, including `POST /register`, over a real
/// store.
fn ceremony_router(store: Arc<DynamoDBStore>) -> Router {
    let app_state = crate::test_helpers::build_test_app_state_with_store(store);
    // Patreon disabled: `materialize_for_user` returns before touching Redis,
    // so the unreachable client below is never dialled.
    let redis =
        fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None);
    let patreon = crate::patreon::PatreonState::new(None, None, redis);
    Router::new()
        .route("/register/:username", get(crate::authn::start_register))
        .route("/register", post(crate::authn::finish_register))
        .route("/test-only/seed-ticket", get(seed_ticket))
        .layer(Extension(app_state))
        .layer(Extension(patreon))
        .layer(SessionManagerLayer::new(MemoryStore::default()))
}

/// One client session: a fresh username and a fresh attested `key_id`, so
/// runs never collide in a DynamoDB Local that outlives them.
struct Ceremony {
    app: Router,
    store: Arc<DynamoDBStore>,
    cookie: String,
    username: String,
    key_id: String,
}

impl Ceremony {
    /// A session holding a live ticket, or `None` without DynamoDB Local.
    async fn begin() -> Option<Self> {
        let store = Arc::new(crate::db::tests::local_store()?);
        let id = uuid::Uuid::new_v4().simple().to_string();
        let mut c = Ceremony {
            app: ceremony_router(store.clone()),
            store,
            cookie: String::new(),
            username: format!("gate-{}", &id[..12]),
            key_id: format!("gate-test-{id}"),
        };
        let seeded = c.seed(300).await;
        c.cookie = session_cookie(&seeded);
        Some(c)
    }

    async fn send(
        &self,
        request: axum::http::request::Builder,
        body: Body,
    ) -> axum::response::Response {
        let request = if self.cookie.is_empty() {
            request
        } else {
            request.header("cookie", &self.cookie)
        };
        self.app
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap()
    }

    async fn get(&self, uri: &str) -> axum::response::Response {
        self.send(Request::builder().uri(uri), Body::empty()).await
    }

    /// (Re)write this session's ticket, `expires_in` seconds from now.
    async fn seed(&self, expires_in: i64) -> axum::response::Response {
        let response = self
            .get(&format!(
                "/test-only/seed-ticket?key_id={}&expires_in={expires_in}",
                self.key_id
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        response
    }

    /// `GET /register/:username`, which must admit this ticketed session.
    async fn options(&self) -> CreationChallengeResponse {
        let response = self.get(&register_uri(&self.username)).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "start_register must admit a ticket"
        );
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&body).expect("start_register returns WebAuthn creation options")
    }

    async fn finish(&self, credential: &RegisterPublicKeyCredential) -> axum::response::Response {
        self.send(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/json"),
            Body::from(serde_json::to_vec(credential).unwrap()),
        )
        .await
    }

    async fn credential_count(&self) -> usize {
        self.store
            .get_user_by_name(&self.username)
            .await
            .unwrap()
            .map_or(0, |u| u.credentials.len())
    }

    /// Slots this key has spent; `None` if it was never charged.
    async fn registrations(&self) -> Option<u32> {
        self.store
            .get_attest_key_record(&self.key_id)
            .await
            .unwrap()
            .map(|r| r.registrations)
    }
}

/// Answer the creation options with a software passkey — the attacker's tool,
/// and indistinguishable from a real one to everything after the gate.
fn soft_authenticator_signs(options: CreationChallengeResponse) -> RegisterPublicKeyCredential {
    WebauthnAuthenticator::new(SoftPasskey::new(true))
        .do_registration(
            url::Url::parse("https://identity.arkavo.net").unwrap(),
            options,
        )
        .expect("the soft authenticator must produce a registration")
}

#[tokio::test]
async fn a_soft_authenticator_with_a_ticket_registers_and_spends_it() {
    // The gate in the other direction, end to end: a legitimate ceremony must
    // still complete. A soft authenticator stands in for the platform passkey
    // because nothing after the gate can tell them apart.
    let Some(c) = Ceremony::begin().await else {
        return;
    };

    let response = c.finish(&soft_authenticator_signs(c.options().await)).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("x-auth-token"));
    assert_eq!(c.credential_count().await, 1);
    assert_eq!(
        c.registrations().await,
        Some(1),
        "finish charges exactly one slot"
    );

    // The ticket was consumed: the same session cannot start a second account.
    let again = c.get(&register_uri(&format!("{}-2", c.username))).await;
    assert_eq!(
        again.status(),
        StatusCode::FORBIDDEN,
        "one ticket buys one account"
    );
}

#[tokio::test]
async fn a_ticket_that_expires_mid_ceremony_is_refused_at_finish() {
    // start_register only proves the ceremony *began* under a valid ticket.
    let Some(c) = Ceremony::begin().await else {
        return;
    };
    let options = c.options().await;
    c.seed(-1).await;

    let response = c.finish(&soft_authenticator_signs(options)).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(c.credential_count().await, 0, "no credential may be stored");
    assert_eq!(
        c.registrations().await,
        None,
        "a refused finish is not billed"
    );
}

#[tokio::test]
async fn a_replayed_finish_does_not_mint_a_second_credential() {
    let Some(c) = Ceremony::begin().await else {
        return;
    };
    let credential = soft_authenticator_signs(c.options().await);
    assert_eq!(c.finish(&credential).await.status(), StatusCode::OK);

    let replay = c.finish(&credential).await;

    assert_ne!(replay.status(), StatusCode::OK);
    assert_eq!(c.credential_count().await, 1);
    assert_eq!(c.registrations().await, Some(1), "a replay spends nothing");
}

#[tokio::test]
async fn an_exhausted_budget_refuses_at_finish() {
    // The preflight's budget check is advisory. If a concurrent registration
    // spends the key's last slot between attest and finish, finish must refuse
    // rather than overdraw.
    let Some(c) = Ceremony::begin().await else {
        return;
    };
    let options = c.options().await;
    let mut spent = 0;
    while c.store.reserve_attest_registration(&c.key_id).await.is_ok() {
        spent += 1;
        assert!(spent < 100, "the budget never ran out");
    }

    let response = c.finish(&soft_authenticator_signs(options)).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(c.credential_count().await, 0, "no credential may be stored");
    assert_eq!(
        c.registrations().await,
        Some(spent),
        "no slot beyond the budget"
    );
}
