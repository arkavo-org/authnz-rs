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
/// Allowlisted for the status endpoint by `test_helpers`.
pub(crate) const STATUS_CLIENT: &str = "platform-status";

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
        .route(
            "/agents/workloads/:workload_id/quarantine",
            post(crate::workload::quarantine_workload),
        )
        .route(
            "/agents/workloads/:workload_id/status",
            get(crate::workload::workload_status),
        )
        .route(
            "/agents/workloads/:workload_id/recover",
            post(crate::workload::recover_workload),
        )
        .route("/guardians", post(crate::guardian::enroll_guardian))
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

    pub async fn quarantine(&self, cwt: &str, wid: &str, incident: &str) -> (StatusCode, Value) {
        self.post_json(
            &format!("/agents/workloads/{wid}/quarantine"),
            ("X-Auth-Token", cwt),
            json!({"incident": incident, "evidence_ref": null}),
        )
        .await
    }

    pub async fn recover(
        &self,
        auth: (&str, &str),
        wid: &str,
        incident: &str,
    ) -> (StatusCode, Value) {
        self.post_json(
            &format!("/agents/workloads/{wid}/recover"),
            auth,
            json!({"incident": incident}),
        )
        .await
    }

    pub async fn status(&self, wid: &str, token: Option<&str>) -> axum::response::Response {
        let mut req = Request::get(format!("/agents/workloads/{wid}/status"));
        if let Some(t) = token {
            req = req.header("X-Auth-Token", t);
        }
        self.app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    pub async fn generation(&self, wid: &str) -> u64 {
        let resp = self
            .status(wid, Some(&service_cwt(self, STATUS_CLIENT)))
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        json_of(resp).await["generation"].as_u64().unwrap()
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

    pub async fn enroll_guardian(&self, cwt: &str, gsk: &SigningKey) -> String {
        let (st, body) = self
            .post_json(
                "/guardians",
                ("X-Auth-Token", cwt),
                json!({"public_key": b64url(gsk.verifying_key().as_bytes()), "name": "pager"}),
            )
            .await;
        assert_eq!(st, StatusCode::OK, "{body}");
        body["guardian_id"].as_str().unwrap().to_string()
    }

    /// A Guardian-signed request. `uri` may carry a query; the header was
    /// signed over its path alone.
    pub async fn signed(
        &self,
        method: &str,
        uri: &str,
        header: &str,
        body: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("X-Guardian-Signature", header);
        if body.is_some() {
            req = req.header("content-type", "application/json");
        }
        self.send(
            req.body(Body::from(body.unwrap_or("").to_string()))
                .unwrap(),
        )
        .await
    }
}

pub(crate) fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// `X-Guardian-Signature` for a request, per contract v1.
pub(crate) fn guardian_header(
    id: &str,
    sk: &SigningKey,
    method: &str,
    path: &str,
    ts: i64,
    body: &[u8],
) -> String {
    let sig = sk.sign(&crate::guardian::signing_input(method, path, ts, body));
    format!("{id}.{ts}.{}", b64url(&sig.to_bytes()))
}

/// A service CWT the way `client_credentials` shapes one for `client`.
pub(crate) fn service_cwt(p: &Plane, client: &str) -> String {
    let claims =
        crate::cwt::ArkavoClaims::auth(&p.state.issuer, &format!("client:{client}"), 1, None)
            .with_arkavo_roles(vec!["service-account".into()]);
    crate::cwt::encode_for_header(
        &crate::cwt::mint(&claims, &p.state.cwt_signing_key, &p.state.cwt_kid).unwrap(),
    )
}

pub(crate) async fn json_of(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
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

#[tokio::test]
async fn owner_quarantine_latches_once_per_incident() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&a, "fleet", "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    let wid = workload_id_for(&owner, "fleet");

    let (st, body) = p.quarantine(&cwt, &wid, "inc-1").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["workload"], json!(wid));
    assert_eq!(body["owner"], json!(owner.to_string()));
    assert_eq!(body["state"], "quarantined");
    assert_eq!(body["generation"], 2);
    assert_eq!(body["incident"], "inc-1");

    let (st, body) = p.quarantine(&cwt, &wid, "inc-1").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(
        body["generation"], 2,
        "a repeat of the same incident changes nothing"
    );

    let (st, body) = p.quarantine(&cwt, &wid, "inc-2").await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(body.as_str().unwrap().contains("inc-1"), "{body}");
    let stored = p.store.get_workload(&wid).await.unwrap().unwrap();
    assert_eq!(
        (stored.incident.as_deref(), stored.generation),
        (Some("inc-1"), 2)
    );
}

#[tokio::test]
async fn quarantine_needs_the_owner_and_a_valid_body() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let (_, stranger) = p.user(&[READ]).await;
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&fresh_agent(), "fleet", "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    let wid = workload_id_for(&owner, "fleet");
    assert_eq!(
        p.quarantine(&stranger, &wid, "inc-1").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        p.quarantine(&cwt, "wl-absent", "inc-1").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        p.quarantine(&cwt, &wid, "").await.0,
        StatusCode::BAD_REQUEST
    );
    let (st, _) = p
        .send(
            Request::post(format!("/agents/workloads/{wid}/quarantine"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"incident": "inc-1"}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(
        p.store.get_workload(&wid).await.unwrap().unwrap().state,
        WorkloadState::Eligible
    );
}

#[tokio::test]
async fn quarantined_workload_cannot_mint_even_under_a_rebound_did() {
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
    assert_eq!(
        p.authorize(auth, authorize_body(&a2, "fleet", "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(p.mint(&a2).await.0, StatusCode::OK);
    let wid = workload_id_for(&owner, "fleet");
    assert_eq!(p.quarantine(&cwt, &wid, "inc-1").await.0, StatusCode::OK);
    assert_eq!(
        p.mint(&a2).await.0,
        StatusCode::FORBIDDEN,
        "the rebound DID"
    );
    assert_eq!(
        p.mint(&a1).await.0,
        StatusCode::FORBIDDEN,
        "the original DID"
    );
}

#[tokio::test]
async fn rebinding_is_refused_while_quarantined() {
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
    let wid = workload_id_for(&owner, "fleet");
    assert_eq!(p.quarantine(&cwt, &wid, "inc-1").await.0, StatusCode::OK);

    let (st, body) = p
        .authorize(auth, authorize_body(&a3, "fleet", "kit-1", false))
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{body}");
    let w = p.store.get_workload(&wid).await.unwrap().unwrap();
    assert_eq!((w.current_did, w.generation), (did_key(&a1), 2));
    assert_eq!(
        p.store
            .get_agent_delegation(&did_key(&a3))
            .await
            .unwrap()
            .map(|d| d.agent_did),
        None
    );
    assert_eq!(
        p.mint(&a3).await.0,
        StatusCode::NOT_FOUND,
        "no delegation was written for the new DID"
    );
}

#[tokio::test]
async fn refusal_bodies_are_contract_v1() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let auth = ("X-Auth-Token", cwt.as_str());
    let (a1, a2, stray, legacy) = (fresh_agent(), fresh_agent(), fresh_agent(), fresh_agent());
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
    let wid = workload_id_for(&owner, "fleet");
    let support = |d: &SigningKey, w: Option<String>| {
        crate::db::workloads_test_support::delegation(&did_key(d), owner, w)
    };
    p.store
        .create_agent_delegation(&support(&stray, Some(wid.clone())))
        .await
        .unwrap();
    p.store
        .create_agent_delegation(&support(&legacy, None))
        .await
        .unwrap();

    // The texts are pinned in docs/agent-credentials-contract.md v1; edge
    // matches them byte for byte.
    let body = |v: Value| v.as_str().unwrap().to_string();
    let (st, b) = p.mint(&legacy).await;
    assert_eq!(
        (st, body(b)),
        (
            StatusCode::FORBIDDEN,
            "Forbidden: delegation predates workloads; authorize again with workload_name and swarm"
                .to_string()
        )
    );
    let (st, b) = p.mint(&stray).await;
    assert_eq!(
        (st, body(b)),
        (
            StatusCode::FORBIDDEN,
            "Forbidden: agent DID is not the workload's current binding".to_string()
        )
    );
    let (st, b) = p.mint(&a1).await;
    assert_eq!(
        (st, body(b)),
        (StatusCode::FORBIDDEN, "Delegation revoked".to_string())
    );
    assert_eq!(p.quarantine(&cwt, &wid, "inc-1").await.0, StatusCode::OK);
    let (st, b) = p.mint(&a2).await;
    assert_eq!(
        (st, body(b)),
        (StatusCode::FORBIDDEN, "Workload quarantined".to_string())
    );
    let (st, b) = p
        .authorize(
            auth,
            authorize_body(&fresh_agent(), "fleet", "kit-1", false),
        )
        .await;
    assert_eq!(
        (st, body(b)),
        (StatusCode::FORBIDDEN, "Workload quarantined".to_string())
    );
}

#[tokio::test]
async fn owner_quarantine_accepts_an_agents_delegate_token() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let (stranger, _) = p.user(&[READ]).await;
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&fresh_agent(), "fleet", "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    let wid = workload_id_for(&owner, "fleet");
    let path = format!("/agents/workloads/{wid}/quarantine");
    let now = Utc::now().timestamp();
    let bearer = |user: Uuid, client: &str, scope: &str, auth_time: i64| {
        format!(
            "Bearer {}",
            p.delegate_token(user, client, scope, "webauthn", Some(auth_time))
        )
    };
    let body = json!({"incident": "inc-1", "evidence_ref": null});
    let cases = [
        (
            "stale",
            bearer(
                owner,
                DELEGATE_CLIENT,
                "openid agents:delegate",
                now - 3_700,
            ),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "no scope",
            bearer(owner, DELEGATE_CLIENT, "openid", now),
            StatusCode::FORBIDDEN,
        ),
        (
            "wrong client",
            bearer(owner, "some-other-rp", "openid agents:delegate", now),
            StatusCode::FORBIDDEN,
        ),
        (
            "not the owner",
            bearer(stranger, DELEGATE_CLIENT, "openid agents:delegate", now),
            StatusCode::FORBIDDEN,
        ),
    ];
    for (what, token, expected) in cases {
        assert_eq!(
            p.post_json(&path, ("Authorization", &token), body.clone())
                .await
                .0,
            expected,
            "{what}"
        );
    }
    assert_eq!(
        p.store.get_workload(&wid).await.unwrap().unwrap().state,
        WorkloadState::Eligible
    );

    let ok = bearer(
        owner,
        DELEGATE_CLIENT,
        "openid agents:delegate",
        now - 3_000,
    );
    let (st, resp) = p.post_json(&path, ("Authorization", &ok), body).await;
    assert_eq!(st, StatusCode::OK, "{resp}");
    assert_eq!(resp["state"], "quarantined");
    assert_eq!(
        p.store
            .get_workload(&wid)
            .await
            .unwrap()
            .unwrap()
            .quarantined_by,
        Some(format!("owner:{owner}"))
    );
}

#[tokio::test]
async fn a_quarantined_workload_is_refused_at_both_challenge_and_token() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&a, "fleet", "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let wid = workload_id_for(&owner, "fleet");
    assert_eq!(p.quarantine(&cwt, &wid, "inc-1").await.0, StatusCode::OK);

    // The challenge step's own `eligible_workload` call refuses it.
    let (st, body) = p
        .send(
            Request::get(format!("/agents/challenge?did={}", did_key(&a)))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        (st, body),
        (StatusCode::FORBIDDEN, json!("Workload quarantined"))
    );

    // The token step is exercised on its own: write a challenge straight
    // into storage — bypassing GET /agents/challenge — so only the
    // token-stage `eligible_workload` check in `issue_agent_token` runs.
    let mut challenge_bytes = [0u8; 32];
    getrandom::getrandom(&mut challenge_bytes).unwrap();
    let challenge = base64::engine::general_purpose::STANDARD.encode(challenge_bytes);
    let nonce = Uuid::new_v4().to_string();
    p.store
        .put_agent_challenge(&did_key(&a), &challenge, &nonce, Utc::now().timestamp())
        .await
        .unwrap();
    let sig = base64::engine::general_purpose::STANDARD.encode(a.sign(&challenge_bytes).to_bytes());
    let (st, body) = p
        .send(
            Request::post("/agents/token")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "did": did_key(&a),
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
        (StatusCode::FORBIDDEN, json!("Workload quarantined"))
    );
}

#[tokio::test]
async fn status_requires_an_allowlisted_service_cwt_and_leases_five_seconds() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&a, "fleet", "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    let wid = workload_id_for(&owner, "fleet");

    assert_eq!(
        p.status(&wid, None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        p.status(&wid, Some(&cwt)).await.status(),
        StatusCode::FORBIDDEN,
        "a human CWT"
    );
    assert_eq!(
        p.status(&wid, Some(&service_cwt(&p, "it"))).await.status(),
        StatusCode::FORBIDDEN,
        "an admin client is not a status client"
    );

    let before = Utc::now().timestamp();
    let resp = p.status(&wid, Some(&service_cwt(&p, STATUS_CLIENT))).await;
    let after = Utc::now().timestamp();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    let body = json_of(resp).await;
    let valid_until = body["valid_until"].as_i64().unwrap();
    assert!(
        (before + 5..=after + 5).contains(&valid_until),
        "valid_until = now + 5"
    );
    assert_eq!(
        body,
        json!({
            "workload": wid, "owner": owner.to_string(), "current_did": did_key(&a),
            "swarm": "kit-1", "state": "eligible", "generation": 1, "incident": null,
            "valid_until": valid_until,
        })
    );
    assert_eq!(
        p.status("wl-absent", Some(&service_cwt(&p, STATUS_CLIENT)))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    // A workload authorized before its agent has a kit reports an empty swarm.
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&fresh_agent(), "bare", "", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    let bare = json_of(
        p.status(
            &workload_id_for(&owner, "bare"),
            Some(&service_cwt(&p, STATUS_CLIENT)),
        )
        .await,
    )
    .await;
    assert_eq!(bare["swarm"], "");
}

#[tokio::test]
async fn generation_increases_on_every_change_and_only_then() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let auth = ("X-Auth-Token", cwt.as_str());
    let wid = workload_id_for(&owner, "fleet");
    assert_eq!(
        p.authorize(
            auth,
            authorize_body(&fresh_agent(), "fleet", "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(p.generation(&wid).await, 1, "created");
    assert_eq!(
        p.authorize(
            auth,
            authorize_body(&fresh_agent(), "fleet", "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(p.generation(&wid).await, 2, "rebound");
    assert_eq!(p.quarantine(&cwt, &wid, "inc-1").await.0, StatusCode::OK);
    assert_eq!(p.generation(&wid).await, 3, "quarantined");
    assert_eq!(p.quarantine(&cwt, &wid, "inc-1").await.0, StatusCode::OK);
    assert_eq!(
        p.generation(&wid).await,
        3,
        "same incident again: unchanged"
    );
    assert_eq!(
        p.quarantine(&cwt, &wid, "inc-2").await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        p.generation(&wid).await,
        3,
        "refused second incident: unchanged"
    );
    assert_eq!(p.recover(auth, &wid, "inc-1").await.0, StatusCode::OK);
    assert_eq!(p.generation(&wid).await, 4, "recovered");
    assert_eq!(
        p.authorize(
            auth,
            authorize_body(&fresh_agent(), "fleet", "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(p.generation(&wid).await, 5, "bound again");
}

#[tokio::test]
async fn only_the_owner_with_a_fresh_passkey_recovers_citing_the_incident() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a1 = fresh_agent();
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&a1, "fleet", "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    let (st, tok) = p.mint(&a1).await;
    assert_eq!(st, StatusCode::OK, "{tok}");
    let agent_token = tok["token"].as_str().unwrap().to_string();
    let wid = workload_id_for(&owner, "fleet");
    assert_eq!(p.quarantine(&cwt, &wid, "inc-1").await.0, StatusCode::OK);
    let aged = |age: i64| crate::test_helpers::auth_cwt_aged(&p.state, owner, age);

    let (_, stranger) = p.user(&[READ]).await;
    assert_eq!(
        p.recover(("X-Auth-Token", &stranger), &wid, "inc-1")
            .await
            .0,
        StatusCode::FORBIDDEN,
        "not the owner"
    );
    assert_eq!(
        p.recover(("X-Auth-Token", &aged(301)), &wid, "inc-1")
            .await
            .0,
        StatusCode::UNAUTHORIZED,
        "a passkey assertion older than 300 s"
    );
    assert_eq!(
        p.recover(("X-Auth-Token", &aged(600)), &wid, "inc-1")
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        p.recover(("X-Auth-Token", &agent_token), &wid, "inc-1")
            .await
            .0,
        StatusCode::UNAUTHORIZED,
        "the agent cannot recover"
    );
    assert_eq!(
        p.recover(
            ("X-Auth-Token", &service_cwt(&p, STATUS_CLIENT)),
            &wid,
            "inc-1"
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED,
        "an orchestrator's service identity cannot recover"
    );
    let (st, _) = p
        .send(
            Request::post(format!("/agents/workloads/{wid}/recover"))
                .header("X-Auth-Token", &cwt)
                .header("X-Guardian-Signature", "g.1.sig")
                .header("content-type", "application/json")
                .body(Body::from(json!({"incident": "inc-1"}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "a Guardian can never recover");
    assert_eq!(
        p.recover(("X-Auth-Token", &cwt), &wid, "").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        p.recover(("X-Auth-Token", &cwt), "wl-unknown", "inc-1")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (st, body) = p.recover(("X-Auth-Token", &cwt), &wid, "inc-9").await;
    assert_eq!(
        st,
        StatusCode::CONFLICT,
        "recovery must cite the latched incident"
    );
    assert!(
        body.to_string()
            .contains("incident does not match the quarantine being cleared"),
        "{body}"
    );
    assert_eq!(
        p.store.get_workload(&wid).await.unwrap().unwrap().state,
        WorkloadState::Quarantined
    );

    let (st, body) = p.recover(("X-Auth-Token", &aged(299)), &wid, "inc-1").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "eligible");
    assert_eq!(body["current_did"], "");
    assert_eq!(body["generation"], 3);
    assert_eq!(body["incident"], Value::Null);
    let status = json_of(p.status(&wid, Some(&service_cwt(&p, STATUS_CLIENT))).await).await;
    assert_eq!(
        (
            &status["state"],
            &status["current_did"],
            &status["generation"]
        ),
        (&json!("eligible"), &json!(""), &json!(3))
    );

    let (st, b) = p.mint(&a1).await;
    assert_eq!(
        (st, b),
        (StatusCode::FORBIDDEN, json!("Delegation revoked")),
        "the old delegation is revoked"
    );
    assert_eq!(
        p.recover(("X-Auth-Token", &cwt), &wid, "inc-1").await.0,
        StatusCode::CONFLICT,
        "not quarantined"
    );
    // A replayed quarantine citing the cleared incident cannot re-latch.
    assert_eq!(
        p.quarantine(&cwt, &wid, "inc-1").await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(p.generation(&wid).await, 3);
    assert_eq!(p.quarantine(&cwt, &wid, "inc-2").await.0, StatusCode::OK);
}

#[tokio::test]
async fn owner_recovery_accepts_a_fresh_agents_delegate_token() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let (stranger, _) = p.user(&[READ]).await;
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&fresh_agent(), "fleet", "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    let wid = workload_id_for(&owner, "fleet");
    assert_eq!(p.quarantine(&cwt, &wid, "inc-1").await.0, StatusCode::OK);
    let now = Utc::now().timestamp();
    let bearer = |user: Uuid, client: &str, scope: &str, auth_time: i64| {
        format!(
            "Bearer {}",
            p.delegate_token(user, client, scope, "webauthn", Some(auth_time))
        )
    };
    let cases = [
        // Fine for authorize and quarantine (≤ 3600 s), not for recovery (≤ 300 s).
        (
            "stale for recovery",
            bearer(owner, DELEGATE_CLIENT, "openid agents:delegate", now - 400),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "just past the bound",
            bearer(owner, DELEGATE_CLIENT, "openid agents:delegate", now - 302),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "no scope",
            bearer(owner, DELEGATE_CLIENT, "openid", now),
            StatusCode::FORBIDDEN,
        ),
        (
            "wrong client",
            bearer(owner, "some-other-rp", "openid agents:delegate", now),
            StatusCode::FORBIDDEN,
        ),
        (
            "not the owner",
            bearer(stranger, DELEGATE_CLIENT, "openid agents:delegate", now),
            StatusCode::FORBIDDEN,
        ),
    ];
    for (what, token, expected) in cases {
        assert_eq!(
            p.recover(("Authorization", &token), &wid, "inc-1").await.0,
            expected,
            "{what}"
        );
    }
    assert_eq!(
        p.store.get_workload(&wid).await.unwrap().unwrap().state,
        WorkloadState::Quarantined
    );

    let ok = bearer(
        owner,
        DELEGATE_CLIENT,
        "openid agents:delegate",
        Utc::now().timestamp() - 299,
    );
    let (st, body) = p.recover(("Authorization", &ok), &wid, "inc-1").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "eligible");
}

#[tokio::test]
async fn recovery_needs_a_new_delegation() {
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
    let wid = workload_id_for(&owner, "fleet");
    assert_eq!(p.quarantine(&cwt, &wid, "inc-1").await.0, StatusCode::OK);
    assert_eq!(p.recover(auth, &wid, "inc-1").await.0, StatusCode::OK);
    assert_eq!(
        p.mint(&a2).await.0,
        StatusCode::NOT_FOUND,
        "nothing is authorized yet"
    );

    assert_eq!(
        p.authorize(auth, authorize_body(&a2, "fleet", "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let (st, body) = p.mint(&a2).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let claims = verify_token(&p, body["token"].as_str().unwrap());
    assert_eq!(claims.custom.arkavo_workload, Some(wid.clone()));
    let status = json_of(p.status(&wid, Some(&service_cwt(&p, STATUS_CLIENT))).await).await;
    assert_eq!(status["current_did"], json!(did_key(&a2)));
    assert_eq!(status["generation"], 4);
}

#[tokio::test]
async fn recovery_leaves_the_old_did_alone_once_it_is_authorized_elsewhere() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a1 = fresh_agent();
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
    let wid = workload_id_for(&owner, "fleet");
    assert_eq!(p.quarantine(&cwt, &wid, "inc-1").await.0, StatusCode::OK);
    let (st, body) = p.recover(auth, &wid, "inc-1").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["current_did"], "");
    let (st, body) = p.mint(&a1).await;
    assert_eq!(st, StatusCode::OK, "a1 still mints for \"other\": {body}");
    assert_eq!(
        verify_token(&p, body["token"].as_str().unwrap())
            .custom
            .arkavo_workload,
        Some(workload_id_for(&owner, "other"))
    );
}

/// An owner with one authorized agent in workload "fleet", and an enrolled
/// Guardian: (owner, owner CWT, workload id, guardian id, guardian key).
async fn guarded(p: &Plane) -> (Uuid, String, String, String, SigningKey) {
    let (owner, cwt) = p.user(&[READ]).await;
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&fresh_agent(), "fleet", "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    let gsk = fresh_agent();
    let gid = p.enroll_guardian(&cwt, &gsk).await;
    (owner, cwt, workload_id_for(&owner, "fleet"), gid, gsk)
}

fn quarantine_body(incident: &str) -> String {
    json!({"incident": incident, "evidence_ref": "s3://evidence/1"}).to_string()
}

#[tokio::test]
async fn enrolled_guardian_can_quarantine() {
    let Some(p) = Plane::new().await else { return };
    let (_, _, wid, gid, gsk) = guarded(&p).await;
    let path = format!("/agents/workloads/{wid}/quarantine");
    let body = quarantine_body("g-inc-1");
    let hdr = guardian_header(
        &gid,
        &gsk,
        "POST",
        &path,
        Utc::now().timestamp(),
        body.as_bytes(),
    );
    let (st, resp) = p.signed("POST", &path, &hdr, Some(&body)).await;
    assert_eq!(st, StatusCode::OK, "{resp}");
    assert_eq!(resp["state"], "quarantined");
    assert_eq!(resp["generation"], 2);
    let w = p.store.get_workload(&wid).await.unwrap().unwrap();
    assert_eq!(w.quarantined_by, Some(format!("guardian:{gid}")));
    assert_eq!(w.evidence_ref.as_deref(), Some("s3://evidence/1"));
}

#[tokio::test]
async fn guardian_signature_by_a_self_supplied_key_is_rejected() {
    let Some(p) = Plane::new().await else { return };
    let (_, _, wid, gid, _) = guarded(&p).await;
    let path = format!("/agents/workloads/{wid}/quarantine");
    let attacker = fresh_agent();
    // The body even names the attacker's key; nothing may read it.
    let body = json!({
        "incident": "forged",
        "evidence_ref": null,
        "public_key": b64url(attacker.verifying_key().as_bytes()),
    })
    .to_string();
    let now = Utc::now().timestamp();
    let hdr = guardian_header(&gid, &attacker, "POST", &path, now, body.as_bytes());
    assert_eq!(
        p.signed("POST", &path, &hdr, Some(&body)).await.0,
        StatusCode::UNAUTHORIZED
    );

    let with_key_header = p
        .send(
            Request::post(&path)
                .header("X-Guardian-Signature", &hdr)
                .header(
                    "X-Guardian-Public-Key",
                    b64url(attacker.verifying_key().as_bytes()),
                )
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await;
    assert_eq!(with_key_header.0, StatusCode::UNAUTHORIZED);

    let unknown = guardian_header(
        &Uuid::new_v4().to_string(),
        &attacker,
        "POST",
        &path,
        now,
        body.as_bytes(),
    );
    assert_eq!(
        p.signed("POST", &path, &unknown, Some(&body)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        p.store.get_workload(&wid).await.unwrap().unwrap().state,
        WorkloadState::Eligible
    );
}

#[tokio::test]
async fn guardian_signature_binds_body_path_and_time() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt, wid, gid, gsk) = guarded(&p).await;
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&fresh_agent(), "other", "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    let other_path = format!(
        "/agents/workloads/{}/quarantine",
        workload_id_for(&owner, "other")
    );
    let path = format!("/agents/workloads/{wid}/quarantine");
    let body = quarantine_body("g-inc-1");
    let now = Utc::now().timestamp();
    let sign = |method: &str, path: &str, ts: i64, body: &str| {
        guardian_header(&gid, &gsk, method, path, ts, body.as_bytes())
    };

    let cases = [
        (
            "another body",
            sign("POST", &path, now, &quarantine_body("g-inc-2")),
        ),
        ("another path", sign("POST", &other_path, now, &body)),
        ("another method", sign("GET", &path, now, &body)),
        ("two minutes old", sign("POST", &path, now - 120, &body)),
        ("two minutes ahead", sign("POST", &path, now + 120, &body)),
        ("malformed", "not-a-signature".to_string()),
    ];
    for (what, hdr) in cases {
        assert_eq!(
            p.signed("POST", &path, &hdr, Some(&body)).await.0,
            StatusCode::UNAUTHORIZED,
            "{what}"
        );
    }
    let good = sign("POST", &path, now, &body);
    assert_eq!(
        p.signed("POST", &path, &good, Some(&body)).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn guardian_cannot_quarantine_another_owners_workload() {
    let Some(p) = Plane::new().await else { return };
    let (_, _, _, gid, gsk) = guarded(&p).await;
    let (o2, c2) = p.user(&[READ]).await;
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &c2),
            authorize_body(&fresh_agent(), "fleet", "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    let wid2 = workload_id_for(&o2, "fleet");
    let path = format!("/agents/workloads/{wid2}/quarantine");
    let body = quarantine_body("g-inc-1");
    let hdr = guardian_header(
        &gid,
        &gsk,
        "POST",
        &path,
        Utc::now().timestamp(),
        body.as_bytes(),
    );
    assert_eq!(
        p.signed("POST", &path, &hdr, Some(&body)).await.0,
        StatusCode::FORBIDDEN
    );
    // Contract P7: the signature verified, so the clock advanced even though
    // the request was refused; the same header is now a replay.
    assert_eq!(
        p.signed("POST", &path, &hdr, Some(&body)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        p.store.get_workload(&wid2).await.unwrap().unwrap().state,
        WorkloadState::Eligible
    );
}

#[tokio::test]
async fn guardians_get_403_everywhere_but_quarantine() {
    let Some(p) = Plane::new().await else { return };
    let (_, _, wid, gid, gsk) = guarded(&p).await;
    let qpath = format!("/agents/workloads/{wid}/quarantine");
    let qbody = quarantine_body("g-inc-1");
    let now = Utc::now().timestamp();
    let hdr = guardian_header(&gid, &gsk, "POST", &qpath, now, qbody.as_bytes());
    assert_eq!(
        p.signed("POST", &qpath, &hdr, Some(&qbody)).await.0,
        StatusCode::OK
    );

    let a = fresh_agent();
    let did = did_key(&a);
    // (method, uri, signed path, body) — each validly signed for itself.
    let requests: Vec<(&str, String, String, Option<String>)> = vec![
        (
            "POST",
            "/agents/authorize".into(),
            "/agents/authorize".into(),
            Some(authorize_body(&a, "fleet2", "kit-1", false).to_string()),
        ),
        (
            "GET",
            "/agents/delegations".into(),
            "/agents/delegations".into(),
            None,
        ),
        (
            "DELETE",
            format!("/agents/delegations/{did}"),
            format!("/agents/delegations/{did}"),
            None,
        ),
        (
            "GET",
            format!("/agents/challenge?did={did}"),
            "/agents/challenge".into(),
            None,
        ),
        (
            "POST",
            "/agents/token".into(),
            "/agents/token".into(),
            Some(
                json!({"did": did, "challenge": "AA==", "signature": "AA==", "nonce": "n"})
                    .to_string(),
            ),
        ),
        (
            "POST",
            format!("/agents/workloads/{wid}/recover"),
            format!("/agents/workloads/{wid}/recover"),
            Some(json!({"incident": "g-inc-1"}).to_string()),
        ),
        (
            "GET",
            format!("/agents/workloads/{wid}/status"),
            format!("/agents/workloads/{wid}/status"),
            None,
        ),
        (
            "POST",
            "/guardians".into(),
            "/guardians".into(),
            Some(
                json!({"public_key": b64url(gsk.verifying_key().as_bytes()), "name": "again"})
                    .to_string(),
            ),
        ),
    ];
    for (method, uri, path, body) in requests {
        let bytes = body.as_deref().unwrap_or("").as_bytes().to_vec();
        let hdr = guardian_header(&gid, &gsk, method, &path, now, &bytes);
        let (st, resp) = p.signed(method, &uri, &hdr, body.as_deref()).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{method} {uri}: {resp}");
    }
    assert_eq!(
        p.store.get_workload(&wid).await.unwrap().unwrap().state,
        WorkloadState::Quarantined,
        "the reporting Guardian could not recover"
    );
}

#[tokio::test]
async fn a_replayed_guardian_request_is_rejected_even_inside_the_window() {
    let Some(p) = Plane::new().await else { return };
    let (_, _, wid, gid, gsk) = guarded(&p).await;
    let path = format!("/agents/workloads/{wid}/quarantine");
    let body = quarantine_body("g-inc-1");
    let now = Utc::now().timestamp();
    let hdr = guardian_header(&gid, &gsk, "POST", &path, now, body.as_bytes());
    assert_eq!(
        p.signed("POST", &path, &hdr, Some(&body)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        p.signed("POST", &path, &hdr, Some(&body)).await.0,
        StatusCode::UNAUTHORIZED,
        "same request again"
    );
    let older = guardian_header(&gid, &gsk, "POST", &path, now - 1, body.as_bytes());
    assert_eq!(
        p.signed("POST", &path, &older, Some(&body)).await.0,
        StatusCode::UNAUTHORIZED,
        "an older signature"
    );
    let newer = guardian_header(&gid, &gsk, "POST", &path, now + 1, body.as_bytes());
    assert_eq!(
        p.signed("POST", &path, &newer, Some(&body)).await.0,
        StatusCode::OK,
        "idempotent repeat, fresh signature"
    );
}

#[tokio::test]
async fn a_cleared_incident_cannot_re_quarantine_after_recovery() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt, wid, gid, gsk) = guarded(&p).await;
    let path = format!("/agents/workloads/{wid}/quarantine");
    let now = Utc::now().timestamp();
    let body = quarantine_body("g-inc-1");
    let first = guardian_header(&gid, &gsk, "POST", &path, now, body.as_bytes());
    assert_eq!(
        p.signed("POST", &path, &first, Some(&body)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        p.recover(("X-Auth-Token", &cwt), &wid, "g-inc-1").await.0,
        StatusCode::OK
    );

    // The exact request replayed after recovery: refused as a replay.
    assert_eq!(
        p.signed("POST", &path, &first, Some(&body)).await.0,
        StatusCode::UNAUTHORIZED
    );
    // Freshly signed but citing the cleared incident: refused, still eligible.
    let again = guardian_header(&gid, &gsk, "POST", &path, now + 1, body.as_bytes());
    let (st, resp) = p.signed("POST", &path, &again, Some(&body)).await;
    assert_eq!(st, StatusCode::CONFLICT, "{resp}");
    let w = p.store.get_workload(&wid).await.unwrap().unwrap();
    assert_eq!((w.state, w.generation), (WorkloadState::Eligible, 3));
    // A new incident latches.
    let new_body = quarantine_body("g-inc-2");
    let new = guardian_header(&gid, &gsk, "POST", &path, now + 2, new_body.as_bytes());
    assert_eq!(
        p.signed("POST", &path, &new, Some(&new_body)).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn guardian_enrollment_is_owner_only_and_validates_the_key() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let key = b64url(fresh_agent().verifying_key().as_bytes());
    let (st, _) = p
        .send(
            Request::post("/guardians")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"public_key": key, "name": "pager"}).to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _) = p
        .post_json(
            "/guardians",
            ("X-Auth-Token", &cwt),
            json!({"public_key": b64url(&[1u8; 31]), "name": "pager"}),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = p
        .post_json(
            "/guardians",
            ("X-Auth-Token", &cwt),
            json!({"public_key": key, "name": ""}),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}
