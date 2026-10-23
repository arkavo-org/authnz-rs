//! Passkey session renewal (#108). The pure tests (messages, refusal bodies,
//! and that a renewed token never passes for a fresh assertion) always run;
//! the ones through the real handlers and the store return early unless
//! `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set, as CI's `test` job sets it.

use crate::AppState;
use crate::authentication_tests::{Registered, registered_account, unique_name};
use crate::constants::{
    PASSKEY_SESSION_TOKEN_SECONDS, SESSION_IDLE_LIMIT_SECONDS, SESSION_MAX_SECONDS,
};
use crate::db::Session;
use crate::session::{
    Ended, SessionError, open_message, refresh_message, session_id_for, signout_message,
};
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, post};
use axum::{Extension, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

/// A client's Secure Enclave key, in software.
struct Device {
    key: SigningKey,
}

impl Device {
    fn new() -> Self {
        Self {
            key: SigningKey::random(&mut OsRng),
        }
    }

    /// The 65-byte X9.63 point, base64url.
    fn public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key.verifying_key().to_encoded_point(false).as_bytes())
    }

    /// Raw r||s over `message`, base64url.
    fn sign(&self, message: &str) -> String {
        let sig: Signature = self.key.sign(message.as_bytes());
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }
}

/// The verified claims of a token as the server reads it.
fn claims_of(state: &AppState, token: &str) -> crate::cwt::ArkavoClaims {
    crate::cwt::verify(
        &crate::cwt::decode_from_header(token).unwrap(),
        &state.cwt_keys,
        &crate::cwt::VerifyOptions {
            expected_iss: None,
            expected_aud: Some("arkavo"),
            now: Utc::now().timestamp(),
            skew_secs: crate::cwt::DEFAULT_SKEW_SECS,
        },
    )
    .unwrap()
}

/// A renewed passkey token for `user`: minted now, asserted `age` seconds ago.
fn renewed_token(state: &AppState, user: Uuid, age: i64) -> String {
    let now = Utc::now().timestamp();
    let claims = crate::authn::passkey_auth_claims(state, &user).with_auth_time(now - age);
    crate::cwt::encode_for_header(
        &crate::cwt::mint(&claims, &state.cwt_signing_key, &state.cwt_kid).unwrap(),
    )
}

fn token_headers(token: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("X-Auth-Token", token.parse().unwrap());
    h
}

fn fake_aws() {
    unsafe {
        std::env::set_var("AWS_REGION", "us-east-1");
        std::env::set_var("AWS_ACCESS_KEY_ID", "fake_access_key");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "fake_secret_key");
    }
}

// ---- pure ----

#[test]
fn messages_and_session_id_are_byte_exact() {
    let id = Uuid::parse_str("0f0e0d0c-0b0a-8908-8706-050403020100").unwrap();
    assert_eq!(
        open_message("0a1b2c3d-0000-4000-8000-000000000001", &[1, 2, 3], "BKEY"),
        "arkavo-session-open-v1\n0a1b2c3d-0000-4000-8000-000000000001\nAQID\nBKEY"
    );
    assert_eq!(
        refresh_message(&id, "7.c2VjcmV0"),
        "arkavo-session-refresh-v1\n0f0e0d0c-0b0a-8908-8706-050403020100\n7.c2VjcmV0"
    );
    assert_eq!(
        signout_message(&id),
        "arkavo-session-signout-v1\n0f0e0d0c-0b0a-8908-8706-050403020100"
    );
    let a = session_id_for(&[7; 16]);
    assert_eq!(a, session_id_for(&[7; 16]), "deterministic per cti");
    assert_ne!(a, session_id_for(&[8; 16]));
    assert_eq!(a.get_version_num(), 8);
}

/// The refusal bodies are the contract (docs/session-renewal.md).
#[tokio::test]
async fn refusal_bodies_are_the_contract() {
    async fn body(e: SessionError) -> (StatusCode, Value) {
        let resp = e.into_response();
        let st = resp.status();
        assert_eq!(resp.headers()["cache-control"], "no-store");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (st, serde_json::from_slice(&bytes).unwrap())
    }
    for (why, reason) in [
        (Ended::NotFound, "not_found"),
        (Ended::InvalidProof, "invalid_proof"),
        (Ended::InvalidCredential, "invalid_credential"),
        (Ended::Reused, "reused"),
        (Ended::Idle, "idle"),
        (Ended::Expired, "expired"),
        (Ended::AccountDeleted, "account_deleted"),
    ] {
        let (st, b) = body(SessionError::Ended(why)).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert_eq!(
            (b["error"].as_str(), b["reason"].as_str()),
            (Some("session_ended"), Some(reason))
        );
    }
    for (e, st, code) in [
        (
            SessionError::PasskeyAssertionRequired("x".into()),
            StatusCode::UNAUTHORIZED,
            "passkey_assertion_required",
        ),
        (
            SessionError::InvalidPublicKey,
            StatusCode::BAD_REQUEST,
            "invalid_public_key",
        ),
        (
            SessionError::InvalidProof,
            StatusCode::BAD_REQUEST,
            "invalid_proof",
        ),
        (
            SessionError::SessionExists,
            StatusCode::CONFLICT,
            "session_exists",
        ),
    ] {
        let (got, b) = body(e).await;
        assert_eq!((got, b["error"].as_str()), (st, Some(code)));
        assert!(b.get("reason").is_none());
    }
}

/// A renewed token never counts as a recent passkey assertion: every
/// freshness check reads its `auth_time`, and it is still accepted where
/// no freshness is asked.
#[tokio::test]
async fn a_renewed_token_never_passes_for_a_fresh_assertion() {
    fake_aws();
    let state = crate::test_helpers::build_test_app_state().await;
    let user = Uuid::new_v4();
    let day = SESSION_MAX_SECONDS - 60;
    let renewed = renewed_token(&state, user, day);
    let claims = claims_of(&state, &renewed);
    assert!(Utc::now().timestamp() - claims.iat < 60, "minted now");
    assert_eq!(
        crate::cwt::passkey_assertion_time(&claims),
        claims.iat - day
    );

    // OIDC auth_time (max_age, and the agents:delegate Bearer path).
    assert_eq!(
        crate::oidc::webauthn_auth_time(&claims),
        Some(claims.iat - day)
    );

    // Delegation, recovery and account deletion read this age.
    let (subject, asserted) =
        crate::agent::verify_passkey_auth_token(&state, &token_headers(&renewed))
            .expect("a renewed token is a passkey auth CWT");
    assert_eq!((subject, asserted), (user, claims.iat - day));
    for max_age in [
        crate::constants::ENROLLMENT_TOKEN_MAX_AGE_SECONDS,
        crate::constants::ACCOUNT_DELETION_TOKEN_MAX_AGE_SECONDS,
        crate::constants::RECOVERY_TOKEN_MAX_AGE_SECONDS,
        crate::constants::AGENTS_DELEGATE_MAX_AUTH_AGE_SECONDS,
    ] {
        assert!(!crate::oidc::within_age(asserted, claims.iat, max_age));
    }

    // Account deletion end to end: refused before any lookup.
    let app = Router::new()
        .route("/account", delete(crate::account::delete_account))
        .layer(Extension(state.clone()))
        .layer(Extension(crate::account_tests::patreon_off()))
        .layer(Extension(crate::apple_tokens::AppleTokens::disabled()));
    let resp = app
        .oneshot(
            Request::delete("/account")
                .header("X-Auth-Token", &renewed)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // An original token's assertion is its iat, as before.
    let fresh = crate::test_helpers::auth_cwt_aged(&state, user, 0);
    let (_, at) = crate::agent::verify_passkey_auth_token(&state, &token_headers(&fresh)).unwrap();
    assert_eq!(at, claims_of(&state, &fresh).iat);

    // The short-lived lifetime still tells it from a registration CWT.
    assert_eq!(claims.exp - claims.iat, PASSKEY_SESSION_TOKEN_SECONDS);
}

// ---- through the handlers (DynamoDB Local) ----

struct Harness {
    state: AppState,
    app: Router,
}

fn harness(r: &Registered) -> Harness {
    let state = crate::test_helpers::build_test_app_state_with_store(r.ceremony.store.clone());
    let app = Router::new()
        .route("/session", post(crate::session::open_session))
        .route("/session/refresh", post(crate::session::refresh_session))
        .route("/session/signout", post(crate::session::signout_session))
        .route("/account", delete(crate::account::delete_account))
        .layer(Extension(state.clone()))
        .layer(Extension(crate::account_tests::patreon_off()))
        .layer(Extension(crate::apple_tokens::AppleTokens::disabled()));
    Harness { state, app }
}

impl Harness {
    async fn send(&self, req: Request<Body>) -> (StatusCode, Value) {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, body)
    }

    async fn post(&self, path: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
        let mut req = Request::post(path).header("content-type", "application/json");
        if let Some(t) = token {
            req = req.header("X-Auth-Token", t);
        }
        self.send(req.body(Body::from(body.to_string())).unwrap())
            .await
    }

    /// Open a session with `token` for `device`, signing honestly.
    async fn open(&self, token: &str, device: &Device) -> (StatusCode, Value) {
        let claims = claims_of(&self.state, token);
        let pk = device.public_key();
        let proof = device.sign(&open_message(&claims.sub, &claims.cti, &pk));
        self.post(
            "/session",
            Some(token),
            json!({"publicKey": pk, "proof": proof}),
        )
        .await
    }

    async fn refresh(&self, device: &Device, id: &str, credential: &str) -> (StatusCode, Value) {
        let sid = Uuid::parse_str(id).unwrap();
        let signature = device.sign(&refresh_message(&sid, credential));
        self.post(
            "/session/refresh",
            None,
            json!({"sessionId": id, "credential": credential, "signature": signature}),
        )
        .await
    }

    async fn signout(&self, device: &Device, id: &str) -> (StatusCode, Value) {
        let sid = Uuid::parse_str(id).unwrap();
        let signature = device.sign(&signout_message(&sid));
        self.post(
            "/session/signout",
            None,
            json!({"sessionId": id, "signature": signature}),
        )
        .await
    }

    /// A session written straight to the store, with a known credential.
    async fn stored(
        &self,
        r: &Registered,
        device: &Device,
        assertion_at: i64,
        last_renewed_at: i64,
    ) -> (String, String) {
        let session_id = Uuid::new_v4();
        let credential = "1.c3RvcmVk".to_string();
        let session = Session {
            session_id,
            user_id: r.user_id,
            public_key: device
                .key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            assertion_at,
            last_renewed_at,
            generation: 1,
            credential_hash: Sha256::digest(credential.as_bytes()).to_vec(),
        };
        self.state
            .db_store
            .open_session(&session, last_renewed_at)
            .await
            .unwrap();
        (session_id.to_string(), credential)
    }
}

fn reason(body: &Value) -> Option<&str> {
    assert_eq!(body["error"], "session_ended", "{body}");
    body["reason"].as_str()
}

#[tokio::test]
async fn a_session_renews_rotates_and_ends_on_reuse() {
    let Some(r) = registered_account(&unique_name()).await else {
        return;
    };
    let h = harness(&r);
    let device = Device::new();
    let sign_in = crate::test_helpers::auth_cwt_aged(&h.state, r.user_id, 10);
    let asserted = claims_of(&h.state, &sign_in).iat;

    let (st, opened) = h.open(&sign_in, &device).await;
    assert_eq!(st, StatusCode::CREATED, "{opened}");
    let id = opened["sessionId"].as_str().unwrap().to_string();
    assert_eq!(
        id,
        session_id_for(&claims_of(&h.state, &sign_in).cti).to_string()
    );
    assert_eq!(opened["sessionExpiresAt"], asserted + SESSION_MAX_SECONDS);
    assert_eq!(opened["idleTimeoutSeconds"], SESSION_IDLE_LIMIT_SECONDS);
    let first = opened["credential"].as_str().unwrap().to_string();
    assert!(first.starts_with("1."));

    // One token, one session.
    let (st, again) = h.open(&sign_in, &device).await;
    assert_eq!(
        (st, again["error"].as_str()),
        (StatusCode::CONFLICT, Some("session_exists"))
    );

    let (st, renewed) = h.refresh(&device, &id, &first).await;
    assert_eq!(st, StatusCode::OK, "{renewed}");
    let token = renewed["token"].as_str().unwrap();
    let claims = claims_of(&h.state, token);
    assert_eq!(claims.sub, r.user_id.to_string());
    assert_eq!(
        claims.custom.auth_time,
        Some(asserted),
        "the opening assertion"
    );
    assert_eq!(claims.custom.idp.as_deref(), Some("webauthn"));
    assert_eq!(
        claims.custom.arkavo_account_id.as_deref(),
        Some(r.user_id.to_string().as_str())
    );
    assert!(claims.custom.scope.is_none());
    assert_eq!(renewed["expiresAt"], claims.exp);
    let second = renewed["credential"].as_str().unwrap().to_string();
    assert!(second.starts_with("2."));

    // The renewed token works where a passkey token is taken...
    crate::agent::verify_passkey_auth_token(&h.state, &token_headers(token)).unwrap();
    // ...but opens no session of its own.
    let (st, b) = h.open(token, &device).await;
    assert_eq!(
        (st, b["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("passkey_assertion_required"))
    );

    let (st, third) = h.refresh(&device, &id, &second).await;
    assert_eq!(st, StatusCode::OK, "{third}");

    // A spent credential ends the session (RFC 9700)...
    let (st, b) = h.refresh(&device, &id, &first).await;
    assert_eq!((st, reason(&b)), (StatusCode::UNAUTHORIZED, Some("reused")));
    // ...so the current one is refused too.
    let current = third["credential"].as_str().unwrap();
    let (st, b) = h.refresh(&device, &id, current).await;
    assert_eq!(
        (st, reason(&b)),
        (StatusCode::UNAUTHORIZED, Some("not_found"))
    );
}

#[tokio::test]
async fn opening_needs_a_fresh_original_token_and_the_key_s_proof() {
    let Some(r) = registered_account(&unique_name()).await else {
        return;
    };
    let h = harness(&r);
    let device = Device::new();
    let pk = device.public_key();
    let proof_for = |token: &str| {
        let c = claims_of(&h.state, token);
        device.sign(&open_message(&c.sub, &c.cti, &pk))
    };

    let (st, b) = h
        .post("/session", None, json!({"publicKey": pk, "proof": "AA"}))
        .await;
    assert_eq!(
        (st, b["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("passkey_assertion_required"))
    );

    let stale = crate::test_helpers::auth_cwt_aged(&h.state, r.user_id, 301);
    let (st, b) = h
        .post(
            "/session",
            Some(&stale),
            json!({"publicKey": pk, "proof": proof_for(&stale)}),
        )
        .await;
    assert_eq!(
        (st, b["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("passkey_assertion_required"))
    );

    let renewed = renewed_token(&h.state, r.user_id, 0);
    let (st, b) = h
        .post(
            "/session",
            Some(&renewed),
            json!({"publicKey": pk, "proof": proof_for(&renewed)}),
        )
        .await;
    assert_eq!(
        (st, b["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("passkey_assertion_required"))
    );

    // A registration CWT is not a passkey sign-in.
    let (st, _) = h
        .post(
            "/session",
            Some(&r.token),
            json!({"publicKey": pk, "proof": "AA"}),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let fresh = crate::test_helpers::auth_cwt_aged(&h.state, r.user_id, 0);
    let compressed =
        URL_SAFE_NO_PAD.encode(device.key.verifying_key().to_encoded_point(true).as_bytes());
    for bad_key in [compressed, "BAAA".into(), URL_SAFE_NO_PAD.encode([4u8; 65])] {
        let (st, b) = h
            .post(
                "/session",
                Some(&fresh),
                json!({"publicKey": bad_key, "proof": proof_for(&fresh)}),
            )
            .await;
        assert_eq!(
            (st, b["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_public_key"))
        );
    }

    // A proof by another key, over another token, or DER-encoded.
    let other = Device::new();
    let c = claims_of(&h.state, &fresh);
    let elsewhere = crate::test_helpers::auth_cwt_aged(&h.state, r.user_id, 1);
    let der: Signature = device
        .key
        .sign(open_message(&c.sub, &c.cti, &pk).as_bytes());
    for bad_proof in [
        other.sign(&open_message(&c.sub, &c.cti, &pk)),
        proof_for(&elsewhere),
        URL_SAFE_NO_PAD.encode(der.to_der().as_bytes()),
    ] {
        let (st, b) = h
            .post(
                "/session",
                Some(&fresh),
                json!({"publicKey": pk, "proof": bad_proof}),
            )
            .await;
        assert_eq!(
            (st, b["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_proof"))
        );
    }
    let (st, b) = h.open(&fresh, &device).await;
    assert_eq!(st, StatusCode::CREATED, "{b}");
}

#[tokio::test]
async fn a_bad_proof_or_credential_keeps_the_session() {
    let Some(r) = registered_account(&unique_name()).await else {
        return;
    };
    let h = harness(&r);
    let device = Device::new();
    let now = Utc::now().timestamp();
    let (id, credential) = h.stored(&r, &device, now - 10, now - 10).await;

    let (st, b) = h.refresh(&Device::new(), &id, &credential).await;
    assert_eq!(
        (st, reason(&b)),
        (StatusCode::UNAUTHORIZED, Some("invalid_proof"))
    );
    // A caller without the key cannot end it with a spent-looking credential.
    let (st, b) = h.refresh(&Device::new(), &id, "0.x").await;
    assert_eq!(
        (st, reason(&b)),
        (StatusCode::UNAUTHORIZED, Some("invalid_proof"))
    );
    for wrong in ["1.d3Jvbmc", "2.c3RvcmVk", "c3RvcmVk", "+1.c3RvcmVk", "1."] {
        let (st, b) = h.refresh(&device, &id, wrong).await;
        assert_eq!(
            (st, reason(&b)),
            (StatusCode::UNAUTHORIZED, Some("invalid_credential")),
            "{wrong}"
        );
    }
    let (st, b) = h.refresh(&device, &id, &credential).await;
    assert_eq!(st, StatusCode::OK, "{b}");

    let (st, b) = h
        .refresh(&device, &Uuid::new_v4().to_string(), &credential)
        .await;
    assert_eq!(
        (st, reason(&b)),
        (StatusCode::UNAUTHORIZED, Some("not_found"))
    );
}

#[tokio::test]
async fn idle_and_absolute_timeouts_end_the_session() {
    let Some(r) = registered_account(&unique_name()).await else {
        return;
    };
    let h = harness(&r);
    let device = Device::new();
    let now = Utc::now().timestamp();

    // The last token expired and its skew passed: the renewal its 401
    // prompts still succeeds.
    let (id, credential) = h
        .stored(
            &r,
            &device,
            now - 7200,
            now - PASSKEY_SESSION_TOKEN_SECONDS - crate::cwt::DEFAULT_SKEW_SECS - 1,
        )
        .await;
    let (st, b) = h.refresh(&device, &id, &credential).await;
    assert_eq!(st, StatusCode::OK, "{b}");

    let (id, credential) = h
        .stored(&r, &device, now - 7200, now - SESSION_IDLE_LIMIT_SECONDS)
        .await;
    let (st, b) = h.refresh(&device, &id, &credential).await;
    assert_eq!((st, reason(&b)), (StatusCode::UNAUTHORIZED, Some("idle")));
    let (_, b) = h.refresh(&device, &id, &credential).await;
    assert_eq!(reason(&b), Some("not_found"), "ended, not just refused");

    let (id, credential) = h
        .stored(&r, &device, now - SESSION_MAX_SECONDS, now - 60)
        .await;
    let (st, b) = h.refresh(&device, &id, &credential).await;
    assert_eq!(
        (st, reason(&b)),
        (StatusCode::UNAUTHORIZED, Some("expired"))
    );

    // Near the deadline the token stops at it.
    let (id, credential) = h
        .stored(&r, &device, now - SESSION_MAX_SECONDS + 600, now - 60)
        .await;
    let (st, b) = h.refresh(&device, &id, &credential).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let deadline = now - SESSION_MAX_SECONDS + 600 + SESSION_MAX_SECONDS;
    assert_eq!(b["expiresAt"], deadline);
    assert_eq!(b["sessionExpiresAt"], deadline);
    assert_eq!(
        claims_of(&h.state, b["token"].as_str().unwrap()).exp,
        deadline
    );
}

#[tokio::test]
async fn signing_out_or_deleting_the_account_ends_the_session() {
    let Some(r) = registered_account(&unique_name()).await else {
        return;
    };
    let h = harness(&r);
    let device = Device::new();
    let now = Utc::now().timestamp();

    let (id, credential) = h.stored(&r, &device, now - 10, now - 10).await;
    let (st, b) = h.signout(&Device::new(), &id).await;
    assert_eq!(
        (st, reason(&b)),
        (StatusCode::UNAUTHORIZED, Some("invalid_proof"))
    );
    let (st, _) = h.signout(&device, &id).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, _) = h.signout(&device, &id).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "idempotent");
    let (_, b) = h.refresh(&device, &id, &credential).await;
    assert_eq!(reason(&b), Some("not_found"));

    let (id, credential) = h.stored(&r, &device, now - 10, now - 10).await;
    let fresh = crate::test_helpers::auth_cwt_aged(&h.state, r.user_id, 0);
    let (st, b) = h
        .send(
            Request::delete("/account")
                .header("X-Auth-Token", &fresh)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED, "{b}");
    let (st, b) = h.refresh(&device, &id, &credential).await;
    assert_eq!(
        (st, reason(&b)),
        (StatusCode::UNAUTHORIZED, Some("account_deleted"))
    );
}
