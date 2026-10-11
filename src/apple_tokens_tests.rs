//! `POST /oauth/apple/link` with Apple token exchange, and (Task 7) the
//! deletion sweep's revocation, through the real handlers against DynamoDB
//! Local and a stub appleid.apple.com. Every test returns early unless
//! `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set, as CI's `test` job sets it.

use crate::AppState;
use crate::account::{run_once, schedule_sweep};
use crate::account_tests::patreon_off;
use crate::apple_signin::{AppleJwksCache, apple_link_handler, apple_nonce_handler};
use crate::apple_tokens::test_support::{self as ts, StubApple};
use crate::apple_tokens::{AppleTokenRow, AppleTokens, apple_link_key};
use crate::db::{DeletionState, DynamoDBStore};
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::AttributeValue;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Extension, Router};
use jsonwebtoken::EncodingKey;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use tower_sessions::{MemoryStore, SessionManagerLayer};
use uuid::Uuid;

pub(crate) fn new_sub() -> String {
    format!("001234.{}", Uuid::new_v4().simple())
}

pub(crate) struct Harness {
    pub app: Router,
    pub store: Arc<DynamoDBStore>,
    pub state: AppState,
    pub stub: StubApple,
    /// Signs id_tokens as Apple (its JWK is the stub's JWKS).
    apple_key: EncodingKey,
}

impl Harness {
    /// `None` without DynamoDB Local. `tokens_on`: revocation configured.
    pub(crate) async fn new(tokens_on: bool) -> Option<Self> {
        let store = crate::db::tests::local_store()?;
        Some(Self::build(store, tokens_on).await)
    }

    pub(crate) async fn build(store: DynamoDBStore, tokens_on: bool) -> Self {
        let store = Arc::new(store);
        let state = crate::test_helpers::build_test_app_state_with_store(store.clone());
        let (_, apple_key, apple_jwk) = ts::p256_key(ts::APPLE_KID);
        let stub = StubApple::start(vec![apple_jwk]).await;
        let cache = Arc::new(AppleJwksCache::for_tests(
            &[ts::CLIENT_ID],
            &stub.jwks_url(),
        ));
        let tokens = if tokens_on {
            ts::tokens(&stub)
        } else {
            AppleTokens::disabled()
        };
        let app = Router::new()
            .route("/oauth/apple/nonce", get(apple_nonce_handler))
            .route("/oauth/apple/link", post(apple_link_handler))
            .layer(Extension(state.clone()))
            .layer(Extension(cache))
            .layer(Extension(tokens))
            .layer(SessionManagerLayer::new(MemoryStore::default()).with_secure(false));
        Self {
            app,
            store,
            state,
            stub,
            apple_key,
        }
    }

    /// A live account and a passkey auth CWT for it.
    pub(crate) async fn user(&self) -> (Uuid, String) {
        let u = self
            .store
            .create_user(
                &format!("at-{}", &Uuid::new_v4().simple().to_string()[..12]),
                "did:key:z6Mkappletokens",
            )
            .await
            .unwrap();
        let cwt = crate::authn::mint_auth_token(&self.state, &u.user_id, None, None).unwrap();
        (u.user_id, cwt)
    }

    /// An id_token as Apple signs it, for our client.
    pub(crate) fn id_token(&self, sub: &str, nonce: Option<&str>) -> String {
        ts::sign_apple_id_token(
            &self.apple_key,
            &ts::apple_claims(sub, ts::CLIENT_ID, nonce),
        )
    }

    /// Make Apple's token endpoint answer the next exchange with
    /// `refresh_token` and an id_token for `sub` carrying `nonce`.
    pub(crate) fn apple_returns(&self, refresh_token: &str, sub: &str, nonce: Option<&str>) {
        self.stub.reply_token(
            200,
            json!({"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
                   "refresh_token": refresh_token, "id_token": self.id_token(sub, nonce)}),
        );
    }

    /// `GET /oauth/apple/nonce` → (session cookie, nonce).
    pub(crate) async fn nonce(&self) -> (String, String) {
        let resp = self
            .app
            .clone()
            .oneshot(
                Request::get("/oauth/apple/nonce")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cookie = resp
            .headers()
            .get("set-cookie")
            .expect("a session cookie")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        (cookie, v["nonce"].as_str().unwrap().to_string())
    }

    /// `POST /oauth/apple/link` on the session of `cookie`.
    pub(crate) async fn post_link(
        &self,
        cookie: &str,
        cwt: &str,
        id_token: &str,
        code: Option<&str>,
    ) -> (StatusCode, String) {
        let mut body = json!({ "id_token": id_token });
        if let Some(c) = code {
            body["authorization_code"] = c.into();
        }
        let resp = self
            .app
            .clone()
            .oneshot(
                Request::post("/oauth/apple/link")
                    .header("content-type", "application/json")
                    .header("cookie", cookie)
                    .header("X-Auth-Token", cwt)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// The whole ceremony: a nonce, Apple returning `refresh_token` for
    /// `sub` with that nonce, and the link.
    pub(crate) async fn link(
        &self,
        cwt: &str,
        sub: &str,
        code: Option<&str>,
        refresh_token: &str,
    ) -> (StatusCode, String) {
        let (cookie, nonce) = self.nonce().await;
        self.apple_returns(refresh_token, sub, Some(&nonce));
        self.post_link(&cookie, cwt, &self.id_token(sub, Some(&nonce)), code)
            .await
    }
}

#[tokio::test]
async fn a_link_with_a_code_stores_the_sealed_refresh_token() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (uid, cwt) = h.user().await;
    let sub = new_sub();

    let (st, body) = h.link(&cwt, &sub, Some("code-1"), "rt-1").await;
    assert_eq!(st, StatusCode::OK, "{body}");

    let calls = h.stub.calls("/auth/token");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["code"], "code-1");
    assert_eq!(calls[0]["client_id"], ts::CLIENT_ID);

    assert_eq!(
        h.store.get_identity_link("apple", &sub).await.unwrap(),
        Some(uid)
    );
    let row = h
        .store
        .get_apple_token(&apple_link_key(&sub))
        .await
        .expect("a token row");
    assert_eq!(row.user_id, uid);
    assert_eq!(row.client_id, ts::CLIENT_ID);
    assert_eq!(ts::tokens(&h.stub).open(&row.sealed).await.unwrap(), "rt-1");
    assert!(h.stub.revoked().is_empty());
}

/// Review Focus 3: `""` and whitespace count as no code.
#[tokio::test]
async fn without_a_code_the_link_is_refused_when_revocation_is_on() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (_, cwt) = h.user().await;
    for code in [None, Some(""), Some("   ")] {
        let sub = new_sub();
        let (cookie, nonce) = h.nonce().await;
        let (st, body) = h
            .post_link(&cookie, &cwt, &h.id_token(&sub, Some(&nonce)), code)
            .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{code:?}");
        assert_eq!(body, "authorization_code_required");
        assert_eq!(
            h.store.get_identity_link("apple", &sub).await.unwrap(),
            None
        );
        assert!(
            h.store
                .get_apple_token(&apple_link_key(&sub))
                .await
                .is_none()
        );
    }
    assert!(
        h.stub.calls("/auth/token").is_empty(),
        "Apple was called without a code"
    );
}

#[tokio::test]
async fn with_revocation_off_a_code_is_ignored() {
    let Some(h) = Harness::new(false).await else {
        return;
    };
    let (uid, cwt) = h.user().await;
    for code in [Some("code-1"), None] {
        let sub = new_sub();
        let (cookie, nonce) = h.nonce().await;
        let (st, body) = h
            .post_link(&cookie, &cwt, &h.id_token(&sub, Some(&nonce)), code)
            .await;
        assert_eq!(st, StatusCode::OK, "{code:?}: {body}");
        assert_eq!(
            h.store.get_identity_link("apple", &sub).await.unwrap(),
            Some(uid)
        );
        assert!(
            h.store
                .get_apple_token(&apple_link_key(&sub))
                .await
                .is_none()
        );
    }
    assert!(h.stub.calls("/auth/token").is_empty());
}

#[tokio::test]
async fn a_failed_exchange_stores_nothing() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (_, cwt) = h.user().await;
    for (status, reply) in [
        (400u16, json!({"error": "invalid_grant"})),
        (503, json!({})),
    ] {
        let sub = new_sub();
        let (cookie, nonce) = h.nonce().await;
        h.stub.reply_token(status, reply);
        let (st, body) = h
            .post_link(
                &cookie,
                &cwt,
                &h.id_token(&sub, Some(&nonce)),
                Some("used-code"),
            )
            .await;
        assert_eq!(st, StatusCode::BAD_GATEWAY, "{status}");
        assert_eq!(body, "apple_token_exchange_failed");
        assert_eq!(
            h.store.get_identity_link("apple", &sub).await.unwrap(),
            None
        );
        assert!(
            h.store
                .get_apple_token(&apple_link_key(&sub))
                .await
                .is_none()
        );
    }
    assert!(h.stub.revoked().is_empty());
}

#[tokio::test]
async fn a_code_for_another_identity_or_ceremony_is_revoked_and_refused() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (_, cwt) = h.user().await;
    let sub = new_sub();

    // Apple's id_token for the code names another Apple ID.
    let (cookie, nonce) = h.nonce().await;
    h.apple_returns("rt-other", &new_sub(), Some(&nonce));
    let (st, body) = h
        .post_link(
            &cookie,
            &cwt,
            &h.id_token(&sub, Some(&nonce)),
            Some("code-x"),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(body, "apple_token_binding_mismatch");
    assert_eq!(h.stub.revoked(), vec!["rt-other".to_string()]);

    // Same Apple ID, but the code came from another ceremony (its nonce).
    let (cookie, nonce) = h.nonce().await;
    h.apple_returns("rt-stale", &sub, Some("another-ceremony"));
    let (st, body) = h
        .post_link(
            &cookie,
            &cwt,
            &h.id_token(&sub, Some(&nonce)),
            Some("code-y"),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(body, "apple_token_binding_mismatch");
    assert!(h.stub.revoked().contains(&"rt-stale".to_string()));

    assert_eq!(
        h.store.get_identity_link("apple", &sub).await.unwrap(),
        None
    );
    assert!(
        h.store
            .get_apple_token(&apple_link_key(&sub))
            .await
            .is_none()
    );
}

#[tokio::test]
async fn a_returned_id_token_without_a_nonce_is_accepted() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (uid, cwt) = h.user().await;
    let sub = new_sub();
    let (cookie, nonce) = h.nonce().await;
    h.apple_returns("rt-1", &sub, None);
    let (st, body) = h
        .post_link(
            &cookie,
            &cwt,
            &h.id_token(&sub, Some(&nonce)),
            Some("code-1"),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(
        h.store
            .get_apple_token(&apple_link_key(&sub))
            .await
            .unwrap()
            .user_id,
        uid
    );
}

/// Apple's revoke is authorization-wide and the identity's authorization is
/// held by the account that owns the link, whose deletion revokes it.
#[tokio::test]
async fn a_link_conflict_revokes_nothing() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (owner, _) = h.user().await;
    let (requester, cwt) = h.user().await;
    let sub = new_sub();
    h.store.link_identity(owner, "apple", &sub).await.unwrap();

    let (st, _) = h.link(&cwt, &sub, Some("code-1"), "rt-1").await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(h.stub.revoked().is_empty(), "a conflict must not revoke");
    assert_eq!(
        h.store.get_identity_link("apple", &sub).await.unwrap(),
        Some(owner)
    );
    // No token row for this identity under the requesting user.
    let row = h.store.get_apple_token(&apple_link_key(&sub)).await;
    assert!(row.is_none_or(|r| r.user_id != requester));
}

/// Review Focus 5: no token table; the link fails closed.
#[tokio::test]
async fn a_failed_token_store_revokes_the_token_and_takes_back_a_new_link() {
    let Some(store) = crate::db::tests::local_store() else {
        return;
    };
    let h = Harness::build(
        store.with_apple_tokens_table(format!("missing-{}", Uuid::new_v4())),
        true,
    )
    .await;
    let (uid, cwt) = h.user().await;

    // A link this request created is taken back.
    let sub = new_sub();
    let (st, body) = h.link(&cwt, &sub, Some("code-1"), "rt-1").await;
    assert_eq!(st, StatusCode::BAD_GATEWAY);
    assert_eq!(body, "apple_token_store_failed");
    assert_eq!(h.stub.revoked(), vec!["rt-1".to_string()]);
    assert_eq!(
        h.store.get_identity_link("apple", &sub).await.unwrap(),
        None
    );

    // A link that was already there stays, and its new token is not revoked
    // (a re-link; the authorization is the existing link's).
    let sub2 = new_sub();
    h.store.link_identity(uid, "apple", &sub2).await.unwrap();
    let (st, _) = h.link(&cwt, &sub2, Some("code-2"), "rt-2").await;
    assert_eq!(st, StatusCode::BAD_GATEWAY);
    assert_eq!(h.stub.revoked(), vec!["rt-1".to_string()]);
    assert_eq!(
        h.store.get_identity_link("apple", &sub2).await.unwrap(),
        Some(uid)
    );
}

#[tokio::test]
async fn re_linking_the_same_identity_replaces_the_token_without_revoking() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (uid, cwt) = h.user().await;
    let sub = new_sub();
    assert_eq!(
        h.link(&cwt, &sub, Some("code-1"), "rt-1").await.0,
        StatusCode::OK
    );
    assert_eq!(
        h.link(&cwt, &sub, Some("code-2"), "rt-2").await.0,
        StatusCode::OK
    );

    assert!(
        h.stub.revoked().is_empty(),
        "a re-link must not revoke: Apple's revoke is authorization-wide"
    );
    let row = h
        .store
        .get_apple_token(&apple_link_key(&sub))
        .await
        .unwrap();
    assert_eq!(row.user_id, uid);
    assert_eq!(ts::tokens(&h.stub).open(&row.sealed).await.unwrap(), "rt-2");
}

/// A re-link's authorization is already held by the existing link and its
/// stored token; revoking the new token would end it.
#[tokio::test]
async fn a_failed_token_store_on_a_relink_revokes_nothing() {
    let Some(ok) = Harness::new(true).await else {
        return;
    };
    let (uid, cwt) = ok.user().await;
    let sub = new_sub();
    assert_eq!(
        ok.link(&cwt, &sub, Some("code-1"), "rt-1").await.0,
        StatusCode::OK
    );

    // Same account and identity, but the token table is gone.
    let Some(store) = crate::db::tests::local_store() else {
        return;
    };
    let bad = Harness::build(
        store.with_apple_tokens_table(format!("missing-{}", Uuid::new_v4())),
        true,
    )
    .await;
    let (st, body) = bad.link(&cwt, &sub, Some("code-2"), "rt-2").await;
    assert_eq!(st, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body, "apple_token_store_failed");
    assert!(bad.stub.revoked().is_empty(), "a re-link must not revoke");
    assert!(ok.stub.revoked().is_empty());
    assert_eq!(
        bad.store.get_identity_link("apple", &sub).await.unwrap(),
        Some(uid)
    );
    // The first link's token is untouched.
    let row = ok
        .store
        .get_apple_token(&apple_link_key(&sub))
        .await
        .unwrap();
    assert_eq!(
        ts::tokens(&ok.stub).open(&row.sealed).await.unwrap(),
        "rt-1"
    );
}

/// The returned id_token cannot be checked because Apple's JWKS is
/// unreachable: nothing says the code is foreign, and a revoke could end an
/// authorization that an existing link's token holds.
#[tokio::test]
async fn a_transient_jwks_failure_after_the_exchange_does_not_revoke() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (_, cwt) = h.user().await;
    let sub = new_sub();
    let (cookie, nonce) = h.nonce().await;

    // The returned id_token is signed with a kid the JWKS does not serve, so
    // verifying it refetches the JWKS; the stub serves the submitted token's
    // fetch and then fails.
    let (_, other_key, _) = ts::p256_key("rotated-kid");
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some("rotated-kid".into());
    let returned = jsonwebtoken::encode(
        &header,
        &ts::apple_claims(&sub, ts::CLIENT_ID, Some(&nonce)),
        &other_key,
    )
    .unwrap();
    h.stub.reply_token(
        200,
        json!({"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
               "refresh_token": "rt-1", "id_token": returned}),
    );
    h.stub.serve_keys_only(1);

    let (st, body) = h
        .post_link(
            &cookie,
            &cwt,
            &h.id_token(&sub, Some(&nonce)),
            Some("code-1"),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_GATEWAY, "{body}");
    assert!(
        h.stub.revoked().is_empty(),
        "a transient failure must not revoke"
    );
    assert_eq!(
        h.store.get_identity_link("apple", &sub).await.unwrap(),
        None
    );
    assert!(
        h.store
            .get_apple_token(&apple_link_key(&sub))
            .await
            .is_none()
    );
}

/// Tombstone `uid`, as `DELETE /account` does (the sweep is not run).
async fn tombstone(h: &Harness, uid: &Uuid) {
    h.store
        .tombstone_account(uid, &format!("{uid}.{}", "a".repeat(32)), None, 1)
        .await
        .unwrap();
}

/// Link `sub` to `uid` with Apple returning `refresh_token`, and delete the
/// account while the exchange is in flight: after the handler's account
/// check, before the token is stored.
async fn link_while_deleting(
    h: &Harness,
    uid: &Uuid,
    cwt: &str,
    sub: &str,
    refresh_token: &str,
) -> (StatusCode, String) {
    let (cookie, nonce) = h.nonce().await;
    h.apple_returns(refresh_token, sub, Some(&nonce));
    let id_token = h.id_token(sub, Some(&nonce));
    let exchanges = h.stub.calls("/auth/token").len();
    let gate = h.stub.hold_next_token_reply();
    let (reply, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(h.post_link(&cookie, cwt, &id_token, Some("code")), async {
            gate.wait().await; // the exchange is in flight
            tombstone(h, uid).await;
            gate.wait().await;
        })
    })
    .await
    .expect("the link request never reached Apple's token endpoint");
    assert_eq!(
        h.stub.calls("/auth/token").len(),
        exchanges + 1,
        "the account check at the start of the request passed"
    );
    reply
}

/// The deletion's sweep may already have passed the identity links and the
/// token rows: the link must neither keep a live token nor leave an identity
/// link that would 409 every other account.
#[tokio::test]
async fn an_account_deleted_during_the_link_keeps_no_link_and_its_token_is_revoked() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (uid, cwt) = h.user().await;
    let sub = new_sub();

    let (st, body) = link_while_deleting(&h, &uid, &cwt, &sub, "rt-1").await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(h.stub.revoked(), vec!["rt-1".to_string()]);
    assert!(
        h.store
            .get_apple_token(&apple_link_key(&sub))
            .await
            .is_none()
    );
    assert_eq!(
        h.store.get_identity_link("apple", &sub).await.unwrap(),
        None
    );
}

/// On a re-link the link is the deleted account's own, which the sweep
/// removes; the new token is revoked and its row removed all the same.
#[tokio::test]
async fn an_account_deleted_during_a_relink_has_the_new_token_revoked() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (uid, cwt) = h.user().await;
    let sub = new_sub();
    assert_eq!(
        h.link(&cwt, &sub, Some("code-1"), "rt-1").await.0,
        StatusCode::OK
    );

    let (st, body) = link_while_deleting(&h, &uid, &cwt, &sub, "rt-2").await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(h.stub.revoked(), vec!["rt-2".to_string()]);
    assert!(
        h.store
            .get_apple_token(&apple_link_key(&sub))
            .await
            .is_none()
    );
    assert_eq!(
        h.store.get_identity_link("apple", &sub).await.unwrap(),
        Some(uid),
        "a link this request did not create is left to the sweep"
    );
}

/// A token Apple did not revoke keeps its row, so that the sweep (or an
/// operator) can still revoke it; the link this request created goes.
#[tokio::test]
async fn an_account_deleted_during_the_link_keeps_a_token_apple_did_not_revoke() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (uid, cwt) = h.user().await;
    let sub = new_sub();
    h.stub.reply_revoke(503, json!({}));

    let (st, body) = link_while_deleting(&h, &uid, &cwt, &sub, "rt-1").await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(h.stub.revoked(), vec!["rt-1".to_string()]);
    let row = h
        .store
        .get_apple_token(&apple_link_key(&sub))
        .await
        .expect("the unrevoked token's row");
    assert_eq!(row.user_id, uid);
    assert_eq!(
        h.store.get_identity_link("apple", &sub).await.unwrap(),
        None
    );
}

/// A deleted account (tombstone in place, sweep not yet run) that linked one
/// Apple ID per token in `tokens`, each with its token stored.
async fn deleted_account_with_tokens(h: &Harness, tokens: &[&str]) -> (Uuid, Vec<String>) {
    let (uid, _) = h.user().await;
    let apple = ts::tokens(&h.stub);
    let mut subs = Vec::new();
    for t in tokens {
        let sub = new_sub();
        h.store.link_identity(uid, "apple", &sub).await.unwrap();
        h.store
            .put_apple_token(&AppleTokenRow {
                link_key: apple_link_key(&sub),
                user_id: uid,
                client_id: ts::CLIENT_ID.into(),
                sealed: apple.seal(t).await.unwrap(),
                stored_at: 1,
            })
            .await
            .unwrap();
        subs.push(sub);
    }
    h.store
        .tombstone_account(&uid, &format!("{uid}.{}", "a".repeat(32)), None, 1)
        .await
        .unwrap();
    (uid, subs)
}

async fn state_of(h: &Harness, uid: &Uuid) -> (DeletionState, u32) {
    let d = h.store.get_account_deletion(uid).await.unwrap().unwrap();
    (d.state, d.attempts)
}

#[tokio::test]
async fn the_sweep_revokes_every_apple_token_and_removes_the_rows() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (uid, subs) = deleted_account_with_tokens(&h, &["rt-a", "rt-b"]).await;
    h.stub.reply_revoke(200, json!(null));

    run_once(&h.store, &patreon_off(), &ts::tokens(&h.stub), &uid)
        .await
        .unwrap();

    let mut revoked = h.stub.revoked();
    revoked.sort();
    assert_eq!(revoked, vec!["rt-a".to_string(), "rt-b".to_string()]);
    for call in h.stub.calls("/auth/revoke") {
        assert_eq!(call["client_id"], ts::CLIENT_ID);
        assert_eq!(call["token_type_hint"], "refresh_token");
    }
    for sub in &subs {
        assert_eq!(h.store.get_identity_link("apple", sub).await.unwrap(), None);
        assert!(
            h.store
                .get_apple_token(&apple_link_key(sub))
                .await
                .is_none()
        );
    }
    assert_eq!(state_of(&h, &uid).await.0, DeletionState::Completed);
}

#[tokio::test]
async fn an_apple_refusal_keeps_the_token_and_fails_the_deletion_at_once() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (uid, subs) = deleted_account_with_tokens(&h, &["rt-a"]).await;
    let apple = ts::tokens(&h.stub);
    h.stub.reply_revoke(400, json!({"error": "invalid_client"}));

    let err = run_once(&h.store, &patreon_off(), &apple, &uid)
        .await
        .unwrap_err();
    assert!(err.is_permanent(), "{err}");
    assert_eq!(state_of(&h, &uid).await.0, DeletionState::Failed);
    // Everything else is gone; only the token still to revoke stays.
    assert_eq!(
        h.store.get_identity_link("apple", &subs[0]).await.unwrap(),
        None
    );
    assert!(
        h.store
            .get_apple_token(&apple_link_key(&subs[0]))
            .await
            .is_some()
    );

    // The scheduler does not wait for a retry: one attempt, then it ends.
    let before = h.stub.calls("/auth/revoke").len();
    let handle = schedule_sweep(h.store.clone(), patreon_off(), apple.clone(), uid, 0);
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("a refused revocation must not be retried on the schedule")
        .unwrap();
    assert_eq!(h.stub.calls("/auth/revoke").len(), before + 1);
    assert_eq!(state_of(&h, &uid).await.0, DeletionState::Failed);

    // Once the configuration is fixed, the startup resume (run_once) finishes it.
    h.stub.reply_revoke(200, json!(null));
    run_once(&h.store, &patreon_off(), &apple, &uid)
        .await
        .unwrap();
    assert_eq!(state_of(&h, &uid).await.0, DeletionState::Completed);
    assert!(
        h.store
            .get_apple_token(&apple_link_key(&subs[0]))
            .await
            .is_none()
    );
}

#[tokio::test]
async fn an_apple_outage_keeps_the_token_and_retries_on_the_schedule() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (uid, subs) = deleted_account_with_tokens(&h, &["rt-a"]).await;
    let apple = ts::tokens(&h.stub);
    h.stub.reply_revoke(503, json!({}));

    let err = run_once(&h.store, &patreon_off(), &apple, &uid)
        .await
        .unwrap_err();
    assert!(!err.is_permanent(), "{err}");
    assert_eq!(state_of(&h, &uid).await.0, DeletionState::Pending);
    // Revocation ran after every other step: the link is already gone.
    assert_eq!(
        h.store.get_identity_link("apple", &subs[0]).await.unwrap(),
        None
    );
    assert!(
        h.store
            .get_apple_token(&apple_link_key(&subs[0]))
            .await
            .is_some()
    );

    // The scheduler records the failure and waits to retry.
    let handle = schedule_sweep(h.store.clone(), patreon_off(), apple, uid, 0);
    let mut attempts = 0;
    for _ in 0..100 {
        attempts = state_of(&h, &uid).await.1;
        if attempts >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(attempts, 1);
    assert!(
        !handle.is_finished(),
        "a transient failure must be retried on the schedule"
    );
    handle.abort();
    assert_eq!(state_of(&h, &uid).await.0, DeletionState::Pending);
}

#[tokio::test]
async fn stored_tokens_without_revocation_configured_fail_the_deletion() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (uid, subs) = deleted_account_with_tokens(&h, &["rt-a"]).await;

    let err = run_once(&h.store, &patreon_off(), &AppleTokens::disabled(), &uid)
        .await
        .unwrap_err();
    assert!(err.is_permanent(), "{err}");
    assert_eq!(state_of(&h, &uid).await.0, DeletionState::Failed);
    assert!(
        h.store
            .get_apple_token(&apple_link_key(&subs[0]))
            .await
            .is_some()
    );
    assert!(h.stub.calls("/auth/revoke").is_empty());
}

/// A row that matches the account but cannot be read is a permanent failure,
/// reached after every readable row was revoked: retrying cannot repair it.
#[tokio::test]
async fn an_unreadable_apple_token_row_fails_the_deletion_at_once() {
    let Some(h) = Harness::new(true).await else {
        return;
    };
    let (uid, subs) = deleted_account_with_tokens(&h, &["rt-good"]).await;
    let apple = ts::tokens(&h.stub);
    // Right key and owner, but no `token_ct`: the row cannot be parsed.
    let bad_key = apple_link_key(&new_sub());
    h.store
        .raw_apple_tokens_put(
            [
                ("link_key", AttributeValue::S(bad_key.clone())),
                ("user_id", AttributeValue::S(uid.to_string())),
                ("client_id", AttributeValue::S(ts::CLIENT_ID.into())),
                ("wrapped_dek", AttributeValue::B(Blob::new(vec![1u8]))),
                ("token_nonce", AttributeValue::B(Blob::new(vec![2u8]))),
            ]
            .into_iter()
            .collect(),
        )
        .await;
    h.stub.reply_revoke(200, json!(null));

    let err = run_once(&h.store, &patreon_off(), &apple, &uid)
        .await
        .unwrap_err();
    assert!(err.is_permanent(), "{err}");
    assert!(
        !err.to_string().contains(&bad_key),
        "the error must not carry the link key"
    );
    assert_eq!(state_of(&h, &uid).await.0, DeletionState::Failed);
    // The readable row was revoked and removed; the unreadable one stays.
    assert_eq!(h.stub.revoked(), vec!["rt-good".to_string()]);
    assert!(
        h.store
            .get_apple_token(&apple_link_key(&subs[0]))
            .await
            .is_none()
    );
    assert_eq!(
        h.store.apple_tokens_of(&uid).await.unwrap().unreadable,
        vec![bad_key]
    );

    // The scheduler does not retry it: one attempt, then it ends.
    let handle = schedule_sweep(h.store.clone(), patreon_off(), apple, uid, 0);
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("an unreadable row must not be retried on the schedule")
        .unwrap();
    assert_eq!(state_of(&h, &uid).await.0, DeletionState::Failed);
}
