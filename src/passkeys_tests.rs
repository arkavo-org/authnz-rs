//! Passkey credential attestations (#104) through the real handlers, over an
//! account registered with a software passkey. Every test returns early
//! unless `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set, as CI's `test` job sets it.

use crate::AppState;
use crate::authentication_tests::{Registered, registered_account, unique_name};
use authnz_rs::credential_attestation;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Extension, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use tower::ServiceExt;
use webauthn_rs::prelude::{COSEKeyType, Passkey};

struct Harness {
    state: AppState,
    app: Router,
}

fn harness(r: &Registered) -> Harness {
    let state = crate::test_helpers::build_test_app_state_with_store(r.ceremony.store.clone());
    let app = Router::new()
        .route(
            "/passkeys/credential-attestation",
            post(crate::passkeys::issue_credential_attestation),
        )
        .route(
            "/passkeys/credentials/:credential_id/status",
            get(crate::passkeys::credential_status),
        )
        .route("/account", delete(crate::account::delete_account))
        .layer(Extension(state.clone()))
        .layer(Extension(crate::account_tests::patreon_off()))
        .layer(Extension(crate::apple_tokens::AppleTokens::disabled()));
    Harness { state, app }
}

impl Harness {
    fn auth_token(&self, r: &Registered) -> String {
        crate::test_helpers::auth_cwt_aged(&self.state, r.user_id, 0)
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, Option<String>, Value) {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let cache = resp
            .headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, cache, body)
    }

    async fn attest(&self, token: &str, credential_id: &str) -> (StatusCode, Value) {
        let (st, _, body) = self
            .send(
                Request::post("/passkeys/credential-attestation")
                    .header("X-Auth-Token", token)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "credentialId": credential_id }).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        (st, body)
    }

    async fn status(&self, credential_id: &str) -> (StatusCode, Option<String>, Value) {
        self.send(
            Request::get(format!("/passkeys/credentials/{credential_id}/status"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

fn cred_b64(r: &Registered) -> String {
    URL_SAFE_NO_PAD.encode(r.cred.as_ref())
}

fn coordinates(p: &Passkey) -> (Vec<u8>, Vec<u8>) {
    match &p.get_public_key().key {
        COSEKeyType::EC_EC2(ec2) => (ec2.x.as_ref().to_vec(), ec2.y.as_ref().to_vec()),
        other => panic!("soft passkey is not EC2: {other:?}"),
    }
}

#[tokio::test]
async fn an_account_gets_an_attestation_of_its_own_passkey() {
    let Some(r) = registered_account(&unique_name()).await else {
        return;
    };
    let h = harness(&r);
    let id = cred_b64(&r);

    let (st, body) = h.attest(&h.auth_token(&r), &id).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let bytes = URL_SAFE_NO_PAD
        .decode(body["attestation"].as_str().unwrap())
        .unwrap();
    let a = credential_attestation::verify(&bytes, &h.state.cwt_keys)
        .expect("the attestation verifies against the CWT signing key");
    assert_eq!(a.sub, r.user_id.to_string(), "sub is the passkey CWT's");
    assert_eq!(a.iss, "https://identity.arkavo.net");
    assert_eq!(a.rp_id, "identity.arkavo.net");
    assert_eq!(a.credential_id, r.cred.as_ref());
    let user = r
        .ceremony
        .store
        .get_user_by_id(&r.user_id)
        .await
        .unwrap()
        .unwrap();
    let (x, y) = coordinates(&user.credentials[0]);
    assert_eq!((a.x.to_vec(), a.y.to_vec()), (x, y), "the stored key");

    let (st, cache, body) = h.status(&id).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(cache.as_deref(), Some("no-store"));
    assert_eq!(
        body,
        json!({ "sub": r.user_id.to_string(), "revoked": false })
    );

    // On demand, as often as asked.
    let (st, _) = h.attest(&h.auth_token(&r), &id).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn only_a_passkey_auth_cwt_for_the_credential_s_own_account_is_accepted() {
    let Some(a) = registered_account(&unique_name()).await else {
        return;
    };
    let Some(b) = registered_account(&unique_name()).await else {
        return;
    };
    let h = harness(&a);

    // The ~99-year registration token is not a passkey auth CWT.
    let (st, _) = h.attest(&a.token, &cred_b64(&a)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Another account's passkey, and one nobody holds.
    let (st, body) = h.attest(&h.auth_token(&a), &cred_b64(&b)).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "unknown_credential");
    let nobody = URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes());
    let (st, _) = h.attest(&h.auth_token(&a), &nobody).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // Never attested: no status.
    let (st, _, body) = h.status(&nobody).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "unknown_credential");

    let (st, _, body) = h.status("AQIDBA==").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_credential_id");
}

#[tokio::test]
async fn deleting_the_account_revokes_its_passkeys_and_keeps_the_record() {
    let Some(r) = registered_account(&unique_name()).await else {
        return;
    };
    let h = harness(&r);
    let id = cred_b64(&r);
    assert_eq!(h.attest(&h.auth_token(&r), &id).await.0, StatusCode::OK);

    let (st, _, _) = h
        .send(
            Request::delete("/account")
                .header("X-Auth-Token", h.auth_token(&r))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let deleted_at = r
        .ceremony
        .store
        .get_account_deletion(&r.user_id)
        .await
        .unwrap()
        .unwrap()
        .deleted_at;

    // Revoked from the tombstone on, before the sweep.
    let revoked = json!({ "sub": r.user_id.to_string(), "revoked": true, "revokedAt": deleted_at });
    let (st, _, body) = h.status(&id).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, revoked);
    let (st, _) = h.attest(&h.auth_token(&r), &id).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // The sweep marks the row and does not delete it; same answer.
    crate::account::run_once(
        &r.ceremony.store,
        &crate::account_tests::patreon_off(),
        &crate::apple_tokens::AppleTokens::disabled(),
        &r.user_id,
    )
    .await
    .unwrap();
    let (st, _, body) = h.status(&id).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, revoked);
    let row = r
        .ceremony
        .store
        .passkey_status(&id, r.cred.as_ref())
        .await
        .unwrap()
        .expect("the index row is kept");
    assert_eq!(row.revoked_at, Some(deleted_at));
}
