//! The agent plane — workloads, `agents:delegate`, and (in later tasks)
//! quarantine, recovery, Guardians and the status lease — driven through the
//! real handlers against DynamoDB Local. Every test returns early unless
//! `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set, as CI's `test` job sets it.
//!
//! Bin-local for the same reason as `registration_gate_tests.rs`: `AppState`
//! is not in the lib.

use crate::AppState;
use crate::db::{AgentDelegation, DynamoDBStore, WorkloadState, workload_id_for};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Extension, Router};
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

pub(crate) const READ: &str = "https://arkavo.ai/attr/action/value/read";
pub(crate) const DECRYPT: &str = "https://arkavo.ai/attr/tdf/value/decrypt";
/// Allowlisted for `agents:delegate` by `test_helpers`.
pub(crate) const DELEGATE_CLIENT: &str = "arkavo-edge";

pub(crate) struct Plane {
    pub app: Router,
    pub state: AppState,
    pub store: Arc<DynamoDBStore>,
}

pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/agents/authorize", post(crate::agent::authorize_agent))
        .route("/agents/delegations", get(crate::agent::list_delegations))
        .route(
            "/agents/delegations/:did",
            delete(crate::agent::revoke_delegation),
        )
        .route(
            "/agents/challenge",
            get(crate::agent::generate_agent_challenge),
        )
        .route("/agents/token", post(crate::agent::issue_agent_token))
        .layer(Extension(state))
}

impl Plane {
    pub async fn new() -> Option<Self> {
        let store = Arc::new(crate::db::tests::local_store()?);
        let state = crate::test_helpers::build_test_app_state_with_store(store.clone());
        Some(Self {
            app: router(state.clone()),
            state,
            store,
        })
    }

    /// A fresh user holding `entitlements`, and a passkey auth CWT for it.
    pub async fn user(&self, entitlements: &[&str]) -> (Uuid, String) {
        let user = self
            .store
            .create_user(
                &format!("ap-{}", &Uuid::new_v4().simple().to_string()[..12]),
                "did:key:z6Mkplane",
            )
            .await
            .unwrap();
        let ents: Vec<String> = entitlements.iter().map(|s| s.to_string()).collect();
        self.store
            .put_user_entitlements(&user.user_id, &ents)
            .await
            .unwrap();
        let token = crate::authn::mint_auth_token(&self.state, &user.user_id, None, None).unwrap();
        (user.user_id, token)
    }

    pub async fn send(&self, req: Request<Body>) -> (StatusCode, Value) {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, body)
    }

    pub async fn post_json(
        &self,
        path: &str,
        auth: (&str, &str),
        body: Value,
    ) -> (StatusCode, Value) {
        self.send(
            Request::post(path)
                .header(auth.0, auth.1)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    pub async fn authorize(&self, auth: (&str, &str), body: Value) -> (StatusCode, Value) {
        self.post_json("/agents/authorize", auth, body).await
    }

    /// Challenge → signed proof → token for `sk`'s did:key. Returns the first
    /// non-200 answer, so a refusal at the challenge step surfaces too.
    pub async fn mint(&self, sk: &SigningKey) -> (StatusCode, Value) {
        let did = did_key(sk);
        let (status, ch) = self
            .send(
                Request::get(format!("/agents/challenge?did={did}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        if status != StatusCode::OK {
            return (status, ch);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ch["challenge"].as_str().unwrap())
            .unwrap();
        let sig = base64::engine::general_purpose::STANDARD.encode(sk.sign(&bytes).to_bytes());
        self.send(
            Request::post("/agents/token")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"did": did, "challenge": ch["challenge"], "signature": sig, "nonce": ch["nonce"]})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
    }

    /// An `agents:delegate`-style OIDC access token for `owner`.
    pub fn delegate_token(
        &self,
        owner: Uuid,
        client: &str,
        scope: &str,
        idp: &str,
        auth_time: Option<i64>,
    ) -> String {
        crate::oidc::mint_access_token(
            &self.state,
            &format!("arkavo:{owner}"),
            client,
            Some(crate::oidc::AccessTokenExtras {
                idp: idp.into(),
                scope: Some(scope.into()),
                auth_time,
                ..Default::default()
            }),
            None,
        )
        .unwrap()
    }
}

pub(crate) fn did_key(sk: &SigningKey) -> String {
    let mut b = vec![0xed, 0x01];
    b.extend_from_slice(sk.verifying_key().as_bytes());
    format!("did:key:z{}", bs58::encode(b).into_string())
}

pub(crate) fn fresh_agent() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    SigningKey::from_bytes(&seed)
}

/// An authorize body; `swarm = ""` leaves the field out (no kit yet).
pub(crate) fn authorize_body(
    sk: &SigningKey,
    workload: &str,
    swarm: &str,
    short_lived: bool,
) -> Value {
    let mut body = json!({
        "agent_did": did_key(sk),
        "name": "plane-agent",
        "entitlements": [READ],
        "workload_name": workload,
        "short_lived": short_lived,
    });
    if !swarm.is_empty() {
        body["swarm"] = json!(swarm);
    }
    body
}

pub(crate) fn verify_token(p: &Plane, token: &str) -> crate::cwt::ArkavoClaims {
    let bytes = crate::cwt::decode_from_header(token).unwrap();
    crate::cwt::verify(
        &bytes,
        &p.state.cwt_verifying_key,
        &crate::cwt::VerifyOptions {
            expected_iss: Some(&p.state.issuer),
            expected_aud: Some("https://platform.arkavo.net"),
            now: Utc::now().timestamp(),
            skew_secs: crate::cwt::DEFAULT_SKEW_SECS,
        },
    )
    .unwrap()
}

#[tokio::test]
async fn authorize_creates_then_selects_the_owners_workload() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a1 = fresh_agent();
    let (st, body) = p
        .authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&a1, "fleet", "kit-1", false),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let wid = body["workload_id"].as_str().unwrap().to_string();
    assert_eq!(wid, workload_id_for(&owner, "fleet"));
    let w = p.store.get_workload(&wid).await.unwrap().unwrap();
    assert_eq!(w.owner, owner);
    assert_eq!(w.current_did, did_key(&a1));
    assert_eq!(w.swarm, "kit-1");
    assert_eq!(w.state, WorkloadState::Eligible);
    assert_eq!(w.generation, 1);
    let d = p
        .store
        .get_agent_delegation(&did_key(&a1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d.workload_id.as_deref(), Some(wid.as_str()));
    assert!(!d.short_lived);
}

#[tokio::test]
async fn authorize_rebinds_the_workload_and_revokes_the_previous_did() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let (a1, a2) = (fresh_agent(), fresh_agent());
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&a1, "fleet", "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let (st, body) = p
        .authorize(auth, authorize_body(&a2, "fleet", "kit-1", true))
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let w = p
        .store
        .get_workload(&workload_id_for(&owner, "fleet"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(w.current_did, did_key(&a2));
    assert_eq!(w.generation, 2);
    let old = p
        .store
        .get_agent_delegation(&did_key(&a1))
        .await
        .unwrap()
        .unwrap();
    assert!(
        old.revoked_at.is_some(),
        "rebinding must revoke the old DID"
    );
    let new = p
        .store
        .get_agent_delegation(&did_key(&a2))
        .await
        .unwrap()
        .unwrap();
    assert!(new.short_lived);
    let (st, body) = p.mint(&a1).await;
    assert_eq!(
        (st, body),
        (StatusCode::FORBIDDEN, json!("Delegation revoked"))
    );
    let (st, body) = p.mint(&a2).await;
    assert_eq!(st, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn the_same_workload_name_is_per_owner() {
    let Some(p) = Plane::new().await else { return };
    let (o1, c1) = p.user(&[READ]).await;
    let (o2, c2) = p.user(&[READ]).await;
    let (_, b1) = p
        .authorize(
            ("X-Auth-Token", &c1),
            authorize_body(&fresh_agent(), "fleet", "kit-1", false),
        )
        .await;
    let (_, b2) = p
        .authorize(
            ("X-Auth-Token", &c2),
            authorize_body(&fresh_agent(), "fleet", "kit-1", false),
        )
        .await;
    assert_eq!(b1["workload_id"], json!(workload_id_for(&o1, "fleet")));
    assert_eq!(b2["workload_id"], json!(workload_id_for(&o2, "fleet")));
    assert_ne!(b1["workload_id"], b2["workload_id"]);
}

#[tokio::test]
async fn authorize_refuses_an_entitlement_the_owner_does_not_hold() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let mut body = authorize_body(&fresh_agent(), "fleet", "kit-1", false);
    body["entitlements"] = json!([DECRYPT]);
    let (st, _) = p.authorize(("X-Auth-Token", &cwt), body).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(
        p.store
            .get_workload(&workload_id_for(&owner, "fleet"))
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn authorize_validates_the_workload_fields() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let (st, _) = p
        .authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&fresh_agent(), "", "kit-1", false),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = p
        .authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&fresh_agent(), "fleet", "kit\u{7}", false),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let mut empty_swarm = authorize_body(&fresh_agent(), "fleet", "", false);
    empty_swarm["swarm"] = json!("");
    let (st, _) = p.authorize(("X-Auth-Token", &cwt), empty_swarm).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "an empty swarm is invalid; omit it instead"
    );
    let mut missing = authorize_body(&fresh_agent(), "fleet", "kit-1", false);
    missing.as_object_mut().unwrap().remove("workload_name");
    let (st, _) = p.authorize(("X-Auth-Token", &cwt), missing).await;
    assert_eq!(
        st,
        StatusCode::UNPROCESSABLE_ENTITY,
        "workload_name is required"
    );
}

#[tokio::test]
async fn swarm_is_optional_and_set_by_a_later_authorize() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let auth = ("X-Auth-Token", cwt.as_str());
    let wid = workload_id_for(&owner, "onboarded");

    // Trust-QR onboarding: no kit yet.
    let (st, body) = p
        .authorize(auth, authorize_body(&a, "onboarded", "", false))
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let w = p.store.get_workload(&wid).await.unwrap().unwrap();
    assert_eq!((w.swarm.as_str(), w.generation), ("", 1));

    // Specialized into a kit: the same DID re-authorized with the swarm
    // replaces its own delegation (no 409) and sets the swarm.
    let (st, body) = p
        .authorize(auth, authorize_body(&a, "onboarded", "kit-7", false))
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let w = p.store.get_workload(&wid).await.unwrap().unwrap();
    assert_eq!(
        (w.swarm.as_str(), w.generation, w.current_did.clone()),
        ("kit-7", 2, did_key(&a))
    );
    let d = p
        .store
        .get_agent_delegation(&did_key(&a))
        .await
        .unwrap()
        .unwrap();
    assert!(d.revoked_at.is_none(), "same DID: nothing to revoke");

    // Omitting swarm later keeps it.
    let (st, _) = p
        .authorize(auth, authorize_body(&a, "onboarded", "", false))
        .await;
    assert_eq!(st, StatusCode::OK);
    let w = p.store.get_workload(&wid).await.unwrap().unwrap();
    assert_eq!((w.swarm.as_str(), w.generation), ("kit-7", 2));

    // The same DID under another workload is still a 409.
    let (st, _) = p
        .authorize(auth, authorize_body(&a, "elsewhere", "kit-7", false))
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_legacy_delegation_row_does_not_block_reauthorization() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let legacy = AgentDelegation {
        workload_id: None,
        ..crate::db::workloads_test_support::delegation(&did_key(&a), owner, None)
    };
    p.store.create_agent_delegation(&legacy).await.unwrap();
    let (st, body) = p
        .authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&a, "fleet", "kit-1", false),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let d = p
        .store
        .get_agent_delegation(&did_key(&a))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d.workload_id, Some(workload_id_for(&owner, "fleet")));
}

#[tokio::test]
async fn agents_delegate_access_token_authorizes() {
    let Some(p) = Plane::new().await else { return };
    let (owner, _) = p.user(&[READ]).await;
    let bearer = format!(
        "Bearer {}",
        p.delegate_token(
            owner,
            DELEGATE_CLIENT,
            "openid agents:delegate",
            "webauthn",
            Some(Utc::now().timestamp() - 120)
        )
    );
    let (st, body) = p
        .authorize(
            ("Authorization", &bearer),
            authorize_body(&fresh_agent(), "fleet", "kit-1", false),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["workload_id"], json!(workload_id_for(&owner, "fleet")));
}

#[tokio::test]
async fn access_tokens_without_delegate_rights_are_refused() {
    let Some(p) = Plane::new().await else { return };
    let (owner, _) = p.user(&[READ]).await;
    let now = Utc::now().timestamp();
    let cases = [
        // (client, scope, idp, auth_time, expected)
        (
            DELEGATE_CLIENT,
            "openid",
            "webauthn",
            Some(now),
            StatusCode::FORBIDDEN,
        ),
        (
            "some-other-rp",
            "openid agents:delegate",
            "webauthn",
            Some(now),
            StatusCode::FORBIDDEN,
        ),
        (
            DELEGATE_CLIENT,
            "openid agents:delegate",
            "google",
            Some(now),
            StatusCode::FORBIDDEN,
        ),
        (
            DELEGATE_CLIENT,
            "openid agents:delegate",
            "webauthn",
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            DELEGATE_CLIENT,
            "openid agents:delegate",
            "webauthn",
            Some(now - 3_700),
            StatusCode::UNAUTHORIZED,
        ),
    ];
    for (client, scope, idp, auth_time, expected) in cases {
        let bearer = format!(
            "Bearer {}",
            p.delegate_token(owner, client, scope, idp, auth_time)
        );
        let (st, body) = p
            .authorize(
                ("Authorization", &bearer),
                authorize_body(&fresh_agent(), "fleet", "kit-1", false),
            )
            .await;
        assert_eq!(st, expected, "{client} {scope} {idp} {auth_time:?}: {body}");
    }
    assert_eq!(
        p.store
            .get_workload(&workload_id_for(&owner, "fleet"))
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn another_owners_legacy_delegation_is_not_replaced() {
    let Some(p) = Plane::new().await else { return };
    let (first, _) = p.user(&[READ]).await;
    let (_, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let legacy = crate::db::workloads_test_support::delegation(&did_key(&a), first, None);
    p.store.create_agent_delegation(&legacy).await.unwrap();
    let (st, body) = p
        .authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&a, "fleet", "kit-1", false),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    let d = p
        .store
        .get_agent_delegation(&did_key(&a))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((d.root_user_id, d.workload_id), (first, None));
}

#[tokio::test]
async fn a_rebind_leaves_the_old_did_alone_once_it_is_authorized_elsewhere() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let (a1, a2) = (fresh_agent(), fresh_agent());
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&a1, "fleet", "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let (st, _) = p
        .send(
            Request::delete(format!("/agents/delegations/{}", did_key(&a1)))
                .header("X-Auth-Token", &cwt)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    // "fleet" is still bound to a1, but a1 now belongs to "other".
    assert_eq!(
        p.authorize(auth, authorize_body(&a1, "other", "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let (st, body) = p
        .authorize(auth, authorize_body(&a2, "fleet", "kit-1", false))
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let w = p
        .store
        .get_workload(&workload_id_for(&owner, "fleet"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((w.current_did, w.generation), (did_key(&a2), 2));
    let d1 = p
        .store
        .get_agent_delegation(&did_key(&a1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (d1.revoked_at, d1.workload_id),
        (None, Some(workload_id_for(&owner, "other"))),
        "rebinding fleet must not revoke a1's delegation for another workload"
    );
}

#[tokio::test]
async fn a_quarantined_workload_refuses_authorize_with_the_contract_body() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let q = crate::db::AgentWorkload {
        state: WorkloadState::Quarantined,
        incident: Some("inc-1".into()),
        ..crate::db::workloads_test_support::sample(owner, "fleet", &did_key(&a))
    };
    p.store.create_workload(&q).await.unwrap();
    for agent in [&a, &fresh_agent()] {
        let (st, body) = p
            .authorize(
                ("X-Auth-Token", &cwt),
                authorize_body(agent, "fleet", "kit-1", false),
            )
            .await;
        assert_eq!(
            (st, body),
            (StatusCode::FORBIDDEN, json!("Workload quarantined"))
        );
    }
    assert_eq!(p.store.get_workload(&q.workload_id).await.unwrap(), Some(q));
    assert!(
        p.store
            .get_agent_delegation(&did_key(&a))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_delegate_token_stops_working_once_its_client_is_delisted() {
    let Some(p) = Plane::new().await else { return };
    let (owner, _) = p.user(&[READ]).await;
    let bearer = format!(
        "Bearer {}",
        p.delegate_token(
            owner,
            DELEGATE_CLIENT,
            "openid agents:delegate",
            "webauthn",
            Some(Utc::now().timestamp())
        )
    );
    // The allowlist is read when the token is used, not when it was minted.
    let mut delisted = p.state.clone();
    delisted.agent_delegate_client_ids = Arc::new(vec!["some-other-rp".into()]);
    let resp = router(delisted)
        .oneshot(
            Request::post("/agents/authorize")
                .header("Authorization", &bearer)
                .header("content-type", "application/json")
                .body(Body::from(
                    authorize_body(&fresh_agent(), "fleet", "kit-1", false).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        p.store
            .get_workload(&workload_id_for(&owner, "fleet"))
            .await
            .unwrap(),
        None
    );
    let (st, body) = p
        .authorize(
            ("Authorization", &bearer),
            authorize_body(&fresh_agent(), "fleet", "kit-1", false),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "the same token while listed: {body}");
}

#[tokio::test]
async fn x_auth_token_wins_over_a_bearer_token() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let (st, body) = p
        .send(
            Request::post("/agents/authorize")
                .header("X-Auth-Token", &cwt)
                .header("Authorization", "Bearer not-a-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    authorize_body(&fresh_agent(), "fleet", "kit-1", false).to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["workload_id"], json!(workload_id_for(&owner, "fleet")));
}

#[tokio::test]
async fn a_rebind_revokes_the_previous_dids_expired_delegation_too() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let (a1, a2) = (fresh_agent(), fresh_agent());
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&a1, "fleet", "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    // a1's delegation ages out while "fleet" is still bound to it.
    let expired = AgentDelegation {
        expires_at: Some(Utc::now().timestamp() - 60),
        ..crate::db::workloads_test_support::delegation(
            &did_key(&a1),
            owner,
            Some(workload_id_for(&owner, "fleet")),
        )
    };
    p.store.create_agent_delegation(&expired).await.unwrap();
    let (st, body) = p
        .authorize(auth, authorize_body(&a2, "fleet", "kit-1", false))
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let d1 = p
        .store
        .get_agent_delegation(&did_key(&a1))
        .await
        .unwrap()
        .unwrap();
    assert!(d1.revoked_at.is_some(), "the previous DID reads as revoked");
    let (st, body) = p.mint(&a1).await;
    assert_eq!(
        (st, body),
        (StatusCode::FORBIDDEN, json!("Delegation revoked"))
    );
}

#[tokio::test]
async fn minted_tokens_carry_the_workload_swarm_and_short_lifetime() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let (short, long) = (fresh_agent(), fresh_agent());
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&short, "sealed", "kit-1", true))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        p.authorize(auth, authorize_body(&long, "chat", "kit-2", false))
            .await
            .0,
        StatusCode::OK
    );

    let (st, body) = p.mint(&short).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let claims = verify_token(&p, body["token"].as_str().unwrap());
    assert_eq!(
        claims.custom.arkavo_workload,
        Some(workload_id_for(&owner, "sealed"))
    );
    assert_eq!(claims.custom.arkavo_swarm.as_deref(), Some("kit-1"));
    assert_eq!(claims.exp - claims.iat, 300);
    assert!(body["expires_at"].as_i64().unwrap() - Utc::now().timestamp() <= 300);

    let (st, body) = p.mint(&long).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let claims = verify_token(&p, body["token"].as_str().unwrap());
    assert_eq!(claims.custom.arkavo_swarm.as_deref(), Some("kit-2"));
    assert_eq!(claims.exp - claims.iat, 900);
}

#[tokio::test]
async fn only_the_current_did_of_a_workload_can_mint() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let (a1, a2, a3) = (fresh_agent(), fresh_agent(), fresh_agent());
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&a1, "fleet", "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        p.authorize(auth, authorize_body(&a2, "fleet", "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        p.mint(&a1).await.0,
        StatusCode::FORBIDDEN,
        "rebound-away DID"
    );
    assert_eq!(p.mint(&a2).await.0, StatusCode::OK);

    // A delegation row naming the workload for a DID it is not bound to —
    // written straight to storage, bypassing authorize — is refused by the
    // issuance check itself, not only by revocation.
    let stray = crate::db::workloads_test_support::delegation(
        &did_key(&a3),
        owner,
        Some(workload_id_for(&owner, "fleet")),
    );
    p.store.create_agent_delegation(&stray).await.unwrap();
    assert_eq!(p.mint(&a3).await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_workload_without_a_swarm_mints_without_the_swarm_claim() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let auth = ("X-Auth-Token", cwt.as_str());
    let wid = workload_id_for(&owner, "onboarded");
    assert_eq!(
        p.authorize(auth, authorize_body(&a, "onboarded", "", false))
            .await
            .0,
        StatusCode::OK
    );
    let (st, body) = p.mint(&a).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let claims = verify_token(&p, body["token"].as_str().unwrap());
    assert_eq!(claims.custom.arkavo_workload, Some(wid.clone()));
    assert_eq!(claims.custom.arkavo_swarm, None);

    // Specialized: the same DID re-authorized with its kit.
    assert_eq!(
        p.authorize(auth, authorize_body(&a, "onboarded", "kit-7", false))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        p.store
            .get_workload(&wid)
            .await
            .unwrap()
            .unwrap()
            .generation,
        2
    );
    let (st, body) = p.mint(&a).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let claims = verify_token(&p, body["token"].as_str().unwrap());
    assert_eq!(claims.custom.arkavo_swarm.as_deref(), Some("kit-7"));
}

#[tokio::test]
async fn a_legacy_delegation_cannot_mint() {
    let Some(p) = Plane::new().await else { return };
    let (owner, _) = p.user(&[READ]).await;
    let a = fresh_agent();
    let legacy = crate::db::workloads_test_support::delegation(&did_key(&a), owner, None);
    p.store.create_agent_delegation(&legacy).await.unwrap();
    assert_eq!(p.mint(&a).await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_token_stage_also_refuses_a_did_that_is_not_current() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let (a1, a3) = (fresh_agent(), fresh_agent());
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&a1, "fleet", "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );

    // a3 holds a delegation naming "fleet", but the workload is bound to a1,
    // not a3. Write a challenge straight into storage — bypassing
    // GET /agents/challenge, whose own `eligible_workload` call would also
    // catch this — so only the token-stage check in `issue_agent_token` is
    // exercised.
    let stray = crate::db::workloads_test_support::delegation(
        &did_key(&a3),
        owner,
        Some(workload_id_for(&owner, "fleet")),
    );
    p.store.create_agent_delegation(&stray).await.unwrap();

    let mut challenge_bytes = [0u8; 32];
    getrandom::getrandom(&mut challenge_bytes).unwrap();
    let challenge = base64::engine::general_purpose::STANDARD.encode(challenge_bytes);
    let nonce = Uuid::new_v4().to_string();
    p.store
        .put_agent_challenge(&did_key(&a3), &challenge, &nonce, Utc::now().timestamp())
        .await
        .unwrap();
    let sig =
        base64::engine::general_purpose::STANDARD.encode(a3.sign(&challenge_bytes).to_bytes());

    let (st, body) = p
        .send(
            Request::post("/agents/token")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "did": did_key(&a3),
                        "challenge": challenge,
                        "signature": sig,
                        "nonce": nonce,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(
        (st, body),
        (
            StatusCode::FORBIDDEN,
            json!("Forbidden: agent DID is not the workload's current binding")
        )
    );
}
