//! The agent plane — agent identities, `agents:delegate`, quarantine, recovery,
//! Guardians and the status lease — driven through the real handlers against DynamoDB Local. Every test returns early unless
//! `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set, as CI's `test` job sets it.
//!
//! Bin-local for the same reason as `registration_gate_tests.rs`: `AppState`
//! is not in the lib.

use crate::AppState;
use crate::db::{AgentState, AgentTrust, DynamoDBStore};
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
            "/agents/:did/quarantine",
            post(crate::agent_state::quarantine_agent),
        )
        .route("/agents/:did/status", get(crate::agent_state::agent_status))
        .route(
            "/agents/:did/recover",
            post(crate::agent_state::recover_agent),
        )
        .route(
            "/agents/:did/appraisal",
            post(crate::agent_state::appraise_agent),
        )
        .route("/guardians", post(crate::guardian::enroll_guardian))
        .route(
            "/guardians/:guardian_id",
            delete(crate::guardian::revoke_guardian),
        )
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

    pub async fn quarantine(&self, cwt: &str, did: &str, incident: &str) -> (StatusCode, Value) {
        self.post_json(
            &format!("/agents/{did}/quarantine"),
            ("X-Auth-Token", cwt),
            json!({"incident": incident, "evidence_ref": null}),
        )
        .await
    }

    pub async fn recover(
        &self,
        auth: (&str, &str),
        did: &str,
        incident: &str,
    ) -> (StatusCode, Value) {
        self.post_json(
            &format!("/agents/{did}/recover"),
            auth,
            json!({"incident": incident}),
        )
        .await
    }

    pub async fn status(&self, did: &str, token: Option<&str>) -> axum::response::Response {
        let mut req = Request::get(format!("/agents/{did}/status"));
        if let Some(t) = token {
            req = req.header("X-Auth-Token", t);
        }
        self.app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// The stored `state_version` of `did`'s row.
    pub async fn state_version(&self, did: &str) -> u64 {
        self.trust(did).await.state_version
    }

    /// The stored trust state of `did`'s row.
    pub async fn trust(&self, did: &str) -> AgentTrust {
        self.store
            .get_agent_delegation(did)
            .await
            .unwrap()
            .expect("agent row")
            .trust
    }

    /// Rewrite `did`'s appraisal expiry in storage, to make it lapse (or
    /// end soon) without waiting.
    pub async fn set_appraised_until(&self, did: &str, until: i64) {
        let mut row = self
            .store
            .get_agent_delegation(did)
            .await
            .unwrap()
            .expect("agent row");
        row.trust.appraised_until = Some(until);
        self.store.put_agent_row(&row).await.unwrap();
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

    pub async fn enroll_guardian(&self, owner: Uuid, cwt: &str, gsk: &SigningKey) -> String {
        let (st, body) = self
            .post_json(
                "/guardians",
                ("X-Auth-Token", cwt),
                enroll_body(owner, gsk, "pager"),
            )
            .await;
        assert_eq!(st, StatusCode::OK, "{body}");
        body["guardian_id"].as_str().unwrap().to_string()
    }

    pub async fn revoke_guardian(&self, cwt: &str, gid: &str) -> (StatusCode, Value) {
        self.send(
            Request::delete(format!("/guardians/{gid}"))
                .header("X-Auth-Token", cwt)
                .body(Body::empty())
                .unwrap(),
        )
        .await
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

/// Proof of possession for enrolling `gsk` as `owner`'s Guardian, per
/// contract v1 (spelled out here so the test pins the signed bytes).
pub(crate) fn enroll_proof(owner: Uuid, gsk: &SigningKey) -> String {
    let key = b64url(gsk.verifying_key().as_bytes());
    let msg = format!("arkavo-guardian-enroll\n{owner}\n{key}");
    b64url(&gsk.sign(msg.as_bytes()).to_bytes())
}

/// A `POST /guardians` body enrolling `gsk` for `owner`, with its proof.
pub(crate) fn enroll_body(owner: Uuid, gsk: &SigningKey, name: &str) -> Value {
    json!({
        "public_key": b64url(gsk.verifying_key().as_bytes()),
        "name": name,
        "proof": enroll_proof(owner, gsk),
    })
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
pub(crate) fn authorize_body(sk: &SigningKey, swarm: &str, short_lived: bool) -> Value {
    let mut body = json!({
        "agent_did": did_key(sk),
        "name": "plane-agent",
        "entitlements": [READ],
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
async fn authorize_makes_the_identity_eligible_under_an_owner_appraisal() {
    let Some(p) = Plane::new().await else { return };
    let (owner, _) = p.user(&[READ]).await;
    let a = fresh_agent();
    // A passkey assertion ten minutes old: the appraisal runs from it, not
    // from the request.
    let before = Utc::now().timestamp();
    let cwt = crate::test_helpers::auth_cwt_aged(&p.state, owner, 600);
    let (st, body) = p
        .authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["agent"], json!(did_key(&a)));
    assert_eq!(body["state"], "eligible");
    assert_eq!(body["state_version"], 1);
    let until = body["appraised_until"].as_i64().unwrap();
    assert!(
        (before - 600 + 43_200..=Utc::now().timestamp() - 600 + 43_200).contains(&until),
        "owner_appraisal_ttl (12 h by default) runs from the passkey assertion"
    );
    let d = p
        .store
        .get_agent_delegation(&did_key(&a))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d.root_user_id, owner);
    assert_eq!(d.swarm, "kit-1");
    assert!(!d.short_lived);
    assert_eq!(d.trust.state, AgentState::Eligible);
    assert_eq!(d.trust.state_version, 1);
    assert_eq!(d.trust.appraised_until, Some(until));
    assert_eq!(d.trust.appraised_by, Some(format!("owner:{owner}")));
}

#[tokio::test]
async fn the_owner_appraisal_runs_from_the_passkey_assertion() {
    let Some(p) = Plane::new().await else { return };
    let (owner, _) = p.user(&[READ]).await;

    // A passkey auth CWT whose assertion is half an hour old.
    let before = Utc::now().timestamp();
    let aged = crate::test_helpers::auth_cwt_aged(&p.state, owner, 1_800);
    let (st, body) = p
        .authorize(
            ("X-Auth-Token", &aged),
            authorize_body(&fresh_agent(), "kit-1", false),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let until = body["appraised_until"].as_i64().unwrap();
    assert!(
        (before - 1_800 + 43_200..=Utc::now().timestamp() - 1_800 + 43_200).contains(&until),
        "iat + 12 h, not now + 12 h: {until}"
    );

    // A refreshed agents:delegate token: minted now, its auth_time 50 minutes old.
    let auth_time = Utc::now().timestamp() - 3_000;
    let bearer = format!(
        "Bearer {}",
        p.delegate_token(
            owner,
            DELEGATE_CLIENT,
            "openid agents:delegate",
            "webauthn",
            Some(auth_time)
        )
    );
    let (st, body) = p
        .authorize(
            ("Authorization", &bearer),
            authorize_body(&fresh_agent(), "kit-1", false),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["appraised_until"], json!(auth_time + 43_200));

    // A configured lifetime shorter than the credential's age: refused with
    // the pinned body, and nothing is written.
    let mut short = p.state.clone();
    short.appraisal.owner_ttl_seconds = 600;
    let authorize_with = |auth_time: i64, a: &SigningKey| {
        let bearer = format!(
            "Bearer {}",
            p.delegate_token(
                owner,
                DELEGATE_CLIENT,
                "openid agents:delegate",
                "webauthn",
                Some(auth_time)
            )
        );
        Request::post("/agents/authorize")
            .header("Authorization", bearer)
            .header("content-type", "application/json")
            .body(Body::from(authorize_body(a, "kit-1", false).to_string()))
            .unwrap()
    };
    let a = fresh_agent();
    let resp = router(short.clone())
        .oneshot(authorize_with(Utc::now().timestamp() - 900, &a))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json_of(resp).await,
        json!(
            "Forbidden: passkey assertion is older than the owner appraisal lifetime; sign in again"
        )
    );
    assert!(
        p.store
            .get_agent_delegation(&did_key(&a))
            .await
            .unwrap()
            .is_none()
    );
    // Within that lifetime: the deadline is auth_time + 600.
    let recent = Utc::now().timestamp() - 300;
    let resp = router(short)
        .oneshot(authorize_with(recent, &a))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_of(resp).await["appraised_until"], json!(recent + 600));
}

#[tokio::test]
async fn authorize_refuses_an_entitlement_the_owner_does_not_hold() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let mut body = authorize_body(&a, "kit-1", false);
    body["entitlements"] = json!([DECRYPT]);
    let (st, _) = p.authorize(("X-Auth-Token", &cwt), body).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(
        p.store
            .get_agent_delegation(&did_key(&a))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn authorize_validates_the_swarm_and_ignores_a_v1_workload_name() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let auth = ("X-Auth-Token", cwt.as_str());
    let (st, _) = p
        .authorize(auth, authorize_body(&fresh_agent(), "kit\u{7}", false))
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let mut empty_swarm = authorize_body(&fresh_agent(), "", false);
    empty_swarm["swarm"] = json!("");
    let (st, _) = p.authorize(auth, empty_swarm).await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "an empty swarm is invalid; omit it instead"
    );
    let mut missing = authorize_body(&fresh_agent(), "kit-1", false);
    missing.as_object_mut().unwrap().remove("entitlements");
    let (st, _) = p.authorize(auth, missing).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    // A contract v1 client still sends workload_name: it is ignored.
    let mut v1 = authorize_body(&fresh_agent(), "kit-1", false);
    v1["workload_name"] = json!("fleet");
    let (st, body) = p.authorize(auth, v1).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(body.get("workload_id").is_none());
}

#[tokio::test]
async fn swarm_is_optional_and_set_by_a_later_authorize() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let did = did_key(&a);
    let auth = ("X-Auth-Token", cwt.as_str());

    // Trust-QR onboarding: no kit yet.
    let (st, body) = p.authorize(auth, authorize_body(&a, "", false)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let d = p.store.get_agent_delegation(&did).await.unwrap().unwrap();
    assert_eq!((d.swarm.as_str(), d.trust.state_version), ("", 1));

    // Specialized into a kit: the same DID re-authorized with the swarm
    // replaces its own delegation. A swarm change binds tokens to a new
    // authorization, so the version moves.
    let (st, body) = p.authorize(auth, authorize_body(&a, "kit-7", false)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let d = p.store.get_agent_delegation(&did).await.unwrap().unwrap();
    assert_eq!((d.swarm.as_str(), d.trust.state_version), ("kit-7", 2));
    assert!(d.revoked_at.is_none());

    // Omitting swarm later keeps it, and so does naming the same one: a
    // renewal, not a change.
    for swarm in ["", "kit-7"] {
        let (st, _) = p.authorize(auth, authorize_body(&a, swarm, false)).await;
        assert_eq!(st, StatusCode::OK);
        let d = p.store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!((d.swarm.as_str(), d.trust.state_version), ("kit-7", 2));
    }
}

#[tokio::test]
async fn a_swarm_change_and_back_leaves_the_first_token_behind() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let did = did_key(&a);
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&a, "kit-a", false))
            .await
            .0,
        StatusCode::OK
    );
    let (st, tok) = p.mint(&a).await;
    assert_eq!(st, StatusCode::OK, "{tok}");
    let first = verify_token(&p, tok["token"].as_str().unwrap());
    assert_eq!(first.custom.arkavo_state_version, Some(1));

    // A → B → A: each swarm change is an authorization-binding change.
    for (swarm, version) in [("kit-b", 2), ("kit-a", 3)] {
        let (st, body) = p.authorize(auth, authorize_body(&a, swarm, false)).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!(body["state_version"], version, "{swarm}");
    }
    assert_eq!(p.state_version(&did).await, 3);
    assert_ne!(
        first.custom.arkavo_state_version,
        Some(p.state_version(&did).await),
        "the token minted under the first kit-a never matches the platform's check again"
    );
    let (st, tok) = p.mint(&a).await;
    assert_eq!(st, StatusCode::OK, "{tok}");
    let now = verify_token(&p, tok["token"].as_str().unwrap());
    assert_eq!(
        (
            now.custom.arkavo_state_version,
            now.custom.arkavo_swarm.as_deref()
        ),
        (Some(3), Some("kit-a"))
    );
}

#[tokio::test]
async fn a_pre_v2_row_is_unassessed_until_its_owner_authorizes_again() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    // A track-1 (or contract v1) row: no state, no state_version.
    let legacy = crate::db::agent_state_test_support::delegation(&did_key(&a), owner);
    p.store.put_agent_row(&legacy).await.unwrap();
    let (st, body) = p.mint(&a).await;
    assert_eq!(
        (st, body),
        (
            StatusCode::FORBIDDEN,
            json!("Forbidden: agent is unassessed; it needs an appraisal")
        )
    );
    let (st, body) = p
        .authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["state_version"], 1);
    let (st, body) = p.mint(&a).await;
    assert_eq!(st, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_track_1_owner_at_capacity_can_still_re_authorize() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    // A track-1 owner already at MAX_AGENTS_PER_USER live, pre-v2
    // delegations, one of them for `a`.
    p.store
        .put_agent_row(&crate::db::agent_state_test_support::delegation(
            &did_key(&a),
            owner,
        ))
        .await
        .unwrap();
    for _ in 1..crate::constants::MAX_AGENTS_PER_USER {
        let did = crate::db::agent_state_test_support::unique_did("C");
        p.store
            .put_agent_row(&crate::db::agent_state_test_support::delegation(
                &did, owner,
            ))
            .await
            .unwrap();
    }
    let auth = ("X-Auth-Token", cwt.as_str());
    let (st, body) = p.authorize(auth, authorize_body(&a, "kit-1", false)).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "re-authorizing a delegation the owner already holds adds nothing: {body}"
    );
    assert_eq!(body["state_version"], 1);
    let (st, body) = p
        .authorize(auth, authorize_body(&fresh_agent(), "kit-1", false))
        .await;
    assert_eq!(
        (st, body),
        (
            StatusCode::BAD_REQUEST,
            json!("Maximum agents per user (640) exceeded")
        ),
        "a new delegation is still counted"
    );
}

#[tokio::test]
async fn agents_delegate_access_token_authorizes() {
    let Some(p) = Plane::new().await else { return };
    let (owner, _) = p.user(&[READ]).await;
    let a = fresh_agent();
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
            authorize_body(&a, "kit-1", false),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["agent"], json!(did_key(&a)));
    assert_eq!(
        p.trust(&did_key(&a)).await.appraised_by,
        Some(format!("owner:{owner}"))
    );
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
        let a = fresh_agent();
        let bearer = format!(
            "Bearer {}",
            p.delegate_token(owner, client, scope, idp, auth_time)
        );
        let (st, body) = p
            .authorize(
                ("Authorization", &bearer),
                authorize_body(&a, "kit-1", false),
            )
            .await;
        assert_eq!(st, expected, "{client} {scope} {idp} {auth_time:?}: {body}");
        assert!(
            p.store
                .get_agent_delegation(&did_key(&a))
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn another_owners_live_delegation_is_not_replaced() {
    let Some(p) = Plane::new().await else { return };
    let (first, first_cwt) = p.user(&[READ]).await;
    let (_, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    // A live pre-v2 row, and a live v2 identity, both owned by `first`.
    let legacy = crate::db::agent_state_test_support::delegation(&did_key(&a), first);
    p.store.put_agent_row(&legacy).await.unwrap();
    let (st, body) = p
        .authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
        .await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    let d = p
        .store
        .get_agent_delegation(&did_key(&a))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((d.root_user_id, d.trust.state_version), (first, 0));

    let b = fresh_agent();
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &first_cwt),
            authorize_body(&b, "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    let (st, _) = p
        .authorize(("X-Auth-Token", &cwt), authorize_body(&b, "kit-1", false))
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(
        p.trust(&did_key(&b)).await.appraised_by,
        Some(format!("owner:{first}"))
    );
}

#[tokio::test]
async fn a_quarantined_key_refuses_authorize_with_the_contract_body() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let q = crate::db::AgentDelegation {
        trust: AgentTrust {
            state: AgentState::Quarantined,
            state_version: 2,
            incident: Some("inc-1".into()),
            ..AgentTrust::default()
        },
        ..crate::db::agent_state_test_support::delegation(&did_key(&a), owner)
    };
    p.store.put_agent_row(&q).await.unwrap();
    let (st, body) = p
        .authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
        .await;
    assert_eq!(
        (st, body),
        (StatusCode::FORBIDDEN, json!("Workload quarantined"))
    );
    assert_eq!(
        p.store.get_agent_delegation(&q.agent_did).await.unwrap(),
        Some(q)
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
    let a = fresh_agent();
    let resp = router(delisted)
        .oneshot(
            Request::post("/agents/authorize")
                .header("Authorization", &bearer)
                .header("content-type", "application/json")
                .body(Body::from(authorize_body(&a, "kit-1", false).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        p.store
            .get_agent_delegation(&did_key(&a))
            .await
            .unwrap()
            .is_none()
    );
    let (st, body) = p
        .authorize(
            ("Authorization", &bearer),
            authorize_body(&a, "kit-1", false),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "the same token while listed: {body}");
}

#[tokio::test]
async fn x_auth_token_wins_over_a_bearer_token() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let (st, body) = p
        .send(
            Request::post("/agents/authorize")
                .header("X-Auth-Token", &cwt)
                .header("Authorization", "Bearer not-a-token")
                .header("content-type", "application/json")
                .body(Body::from(authorize_body(&a, "kit-1", false).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(
        p.trust(&did_key(&a)).await.appraised_by,
        Some(format!("owner:{owner}"))
    );
}

#[tokio::test]
async fn a_new_delegation_over_an_expired_one_bumps_the_version() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    // The delegation ages out while still eligible at version 1.
    let expired = crate::db::AgentDelegation {
        expires_at: Some(Utc::now().timestamp() - 60),
        ..p.store
            .get_agent_delegation(&did_key(&a))
            .await
            .unwrap()
            .unwrap()
    };
    p.store.put_agent_row(&expired).await.unwrap();
    assert_eq!(
        p.mint(&a).await,
        (StatusCode::FORBIDDEN, json!("Delegation expired"))
    );
    let (st, body) = p.authorize(auth, authorize_body(&a, "kit-1", false)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(
        body["state_version"], 2,
        "a token from the dead delegation must not pass the platform's version check"
    );
    let (st, body) = p.mint(&a).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let claims = verify_token(&p, body["token"].as_str().unwrap());
    assert_eq!(claims.custom.arkavo_state_version, Some(2));
    assert_eq!(
        p.trust(&did_key(&a)).await.appraised_by,
        Some(format!("owner:{owner}"))
    );
}

#[tokio::test]
async fn minted_tokens_carry_the_state_version_swarm_and_short_lifetime() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let (short, long) = (fresh_agent(), fresh_agent());
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&short, "kit-1", true))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        p.authorize(auth, authorize_body(&long, "kit-2", false))
            .await
            .0,
        StatusCode::OK
    );

    let (st, body) = p.mint(&short).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let claims = verify_token(&p, body["token"].as_str().unwrap());
    assert_eq!(claims.custom.arkavo_state_version, Some(1));
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
async fn a_token_ends_with_the_appraisal() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let until = Utc::now().timestamp() + 90;
    p.set_appraised_until(&did_key(&a), until).await;
    let (st, body) = p.mint(&a).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["expires_at"], json!(until));
    assert_eq!(verify_token(&p, body["token"].as_str().unwrap()).exp, until);
}

#[tokio::test]
async fn an_agent_without_a_swarm_mints_without_the_swarm_claim() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&a, "", false)).await.0,
        StatusCode::OK
    );
    let (st, body) = p.mint(&a).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let claims = verify_token(&p, body["token"].as_str().unwrap());
    assert_eq!(claims.custom.arkavo_state_version, Some(1));
    assert_eq!(claims.custom.arkavo_swarm, None);

    // Specialized: the same DID re-authorized with its kit, a swarm change.
    assert_eq!(
        p.authorize(auth, authorize_body(&a, "kit-7", false))
            .await
            .0,
        StatusCode::OK
    );
    let (st, body) = p.mint(&a).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let claims = verify_token(&p, body["token"].as_str().unwrap());
    assert_eq!(claims.custom.arkavo_swarm.as_deref(), Some("kit-7"));
    assert_eq!(claims.custom.arkavo_state_version, Some(2));
}

/// Write a challenge for `sk` straight into storage and redeem it at
/// `/agents/token`, so only the token-stage checks run.
async fn token_stage(p: &Plane, sk: &SigningKey) -> (StatusCode, Value) {
    let mut challenge_bytes = [0u8; 32];
    getrandom::getrandom(&mut challenge_bytes).unwrap();
    let challenge = base64::engine::general_purpose::STANDARD.encode(challenge_bytes);
    let nonce = Uuid::new_v4().to_string();
    p.store
        .put_agent_challenge(&did_key(sk), &challenge, &nonce, Utc::now().timestamp())
        .await
        .unwrap();
    let sig =
        base64::engine::general_purpose::STANDARD.encode(sk.sign(&challenge_bytes).to_bytes());
    p.send(
        Request::post("/agents/token")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "did": did_key(sk),
                    "challenge": challenge,
                    "signature": sig,
                    "nonce": nonce,
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn a_suspended_identity_is_refused_at_both_challenge_and_token() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    // The appraisal lapses: stored eligible, derived suspended.
    p.set_appraised_until(&did_key(&a), Utc::now().timestamp() - 1)
        .await;
    let suspended = json!("Forbidden: agent appraisal expired; it needs a fresh appraisal");
    assert_eq!(p.mint(&a).await, (StatusCode::FORBIDDEN, suspended.clone()));
    assert_eq!(
        token_stage(&p, &a).await,
        (StatusCode::FORBIDDEN, suspended)
    );
    // The owner re-appraises by authorizing again: no state change, same version.
    let (st, body) = p
        .authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
        .await;
    assert_eq!((st, &body["state_version"]), (StatusCode::OK, &json!(1)));
    assert_eq!(p.mint(&a).await.0, StatusCode::OK);
}
#[tokio::test]
async fn a_new_key_is_a_new_identity() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let (a1, a2) = (fresh_agent(), fresh_agent());
    let auth = ("X-Auth-Token", cwt.as_str());
    for a in [&a1, &a2] {
        assert_eq!(
            p.authorize(auth, authorize_body(a, "kit-1", false)).await.0,
            StatusCode::OK
        );
    }
    assert_eq!(
        p.quarantine(&cwt, &did_key(&a1), "inc-1").await.0,
        StatusCode::OK
    );
    assert_eq!(p.mint(&a1).await.0, StatusCode::FORBIDDEN);
    let (st, body) = p.mint(&a2).await;
    assert_eq!(st, StatusCode::OK, "another key is untouched: {body}");
    assert_eq!(p.trust(&did_key(&a2)).await.state_version, 1);
}

/// Present a signed challenge to `/agents/token` as given.
async fn present_token_proof(
    p: &Plane,
    did: &str,
    challenge: &str,
    signature: &[u8],
    nonce: &str,
) -> (StatusCode, Value) {
    p.send(
        Request::post("/agents/token")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "did": did,
                    "challenge": challenge,
                    "signature": base64::engine::general_purpose::STANDARD.encode(signature),
                    "nonce": nonce,
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn a_small_order_did_key_is_never_an_agent_identity() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    // did:key of the Ed25519 identity point (y = 1), a small-order key.
    let mut identity = vec![0xed, 0x01, 1];
    identity.extend_from_slice(&[0u8; 31]);
    let did = format!("did:key:z{}", bs58::encode(identity).into_string());

    // A row for it, as an earlier deploy could have written (the DID is
    // fixed, so this also resets whatever an earlier run left behind).
    let row = crate::db::AgentDelegation {
        trust: AgentTrust {
            state: AgentState::Eligible,
            state_version: 1,
            appraised_until: Some(Utc::now().timestamp() + 3_600),
            ..AgentTrust::default()
        },
        ..crate::db::agent_state_test_support::delegation(&did, owner)
    };
    p.store.put_agent_row(&row).await.unwrap();

    let (st, body) = p
        .authorize(
            ("X-Auth-Token", &cwt),
            json!({"agent_did": did, "name": "weak", "entitlements": [READ]}),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    let stored = p.store.get_agent_delegation(&did).await.unwrap().unwrap();
    assert_eq!(
        (stored.name.as_str(), stored.trust.state_version),
        ("agent", 1),
        "authorize wrote nothing"
    );

    // The row never mints, whatever signature is presented.
    let (st, body) = p
        .send(
            Request::get(format!("/agents/challenge?did={did}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");

    let challenge = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let nonce = Uuid::new_v4().to_string();
    p.store
        .plant_agent_challenge(&did, &challenge, &nonce, Utc::now().timestamp())
        .await
        .unwrap();
    // R = the identity point, s = 0: verifies for any message under the
    // lax check.
    let mut forged = [0u8; 64];
    forged[0] = 1;
    let (st, body) = present_token_proof(&p, &did, &challenge, &forged, &nonce).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.get("token").is_none());
}

/// A fresh `agents:delegate` access token whose audience is `"arkavo"`, as a
/// relying party registered under that client_id would receive one.
fn arkavo_audience_access_token(p: &Plane, owner: Uuid) -> String {
    let claims = crate::cwt::ArkavoClaims::oidc_access(
        &p.state.issuer,
        &format!("arkavo:{owner}"),
        "arkavo",
        1,
    )
    .with_idp("webauthn")
    .with_scope("openid agents:delegate")
    .with_auth_time(Utc::now().timestamp());
    crate::cwt::encode_for_header(
        &crate::cwt::mint(&claims, &p.state.cwt_signing_key, &p.state.cwt_kid).unwrap(),
    )
}

#[tokio::test]
async fn an_access_token_is_never_a_passkey_auth_cwt() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let did = did_key(&a);
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(p.quarantine(&cwt, &did, "inc-1").await.0, StatusCode::OK);
    let token = arkavo_audience_access_token(&p, owner);

    let (st, body) = p.recover(("X-Auth-Token", &token), &did, "inc-1").await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{body}");
    assert!(
        body.to_string()
            .contains("X-Auth-Token must be a passkey auth CWT"),
        "{body}"
    );
    assert_eq!(p.trust(&did).await.state, AgentState::Quarantined);

    let b = fresh_agent();
    let (st, body) = p
        .authorize(("X-Auth-Token", &token), authorize_body(&b, "kit-1", false))
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{body}");
    assert!(
        p.store
            .get_agent_delegation(&did_key(&b))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn owner_quarantine_latches_once_per_incident() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let did = did_key(&a);
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );

    let (st, body) = p.quarantine(&cwt, &did, "inc-1").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["agent"], json!(did));
    assert_eq!(body["owner"], json!(owner.to_string()));
    assert_eq!(body["state"], "quarantined");
    assert_eq!(body["state_version"], 2);
    assert_eq!(body["incident"], "inc-1");

    let (st, body) = p.quarantine(&cwt, &did, "inc-1").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(
        body["state_version"], 2,
        "a repeat of the same incident changes nothing"
    );

    let (st, body) = p.quarantine(&cwt, &did, "inc-2").await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(body.as_str().unwrap().contains("inc-1"), "{body}");
    let t = p.trust(&did).await;
    assert_eq!((t.incident.as_deref(), t.state_version), (Some("inc-1"), 2));
}

#[tokio::test]
async fn quarantine_needs_the_owner_and_a_valid_body() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let (_, stranger) = p.user(&[READ]).await;
    let a = fresh_agent();
    let did = did_key(&a);
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        p.quarantine(&stranger, &did, "inc-1").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        p.quarantine(&cwt, &did_key(&fresh_agent()), "inc-1")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        p.quarantine(&cwt, "wl-00112233445566778899aabbccddeeff", "inc-1")
            .await
            .0,
        StatusCode::BAD_REQUEST,
        "a v1 workload id is not a DID"
    );
    assert_eq!(
        p.quarantine(&cwt, &did, "").await.0,
        StatusCode::BAD_REQUEST
    );
    let (st, _) = p
        .send(
            Request::post(format!("/agents/{did}/quarantine"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"incident": "inc-1"}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(p.trust(&did).await.state, AgentState::Eligible);
}

#[tokio::test]
async fn a_quarantined_key_stays_latched_when_its_delegation_is_revoked() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let x = fresh_agent();
    let did = did_key(&x);
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&x, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(p.quarantine(&cwt, &did, "inc-1").await.0, StatusCode::OK);
    let (st, _) = p
        .send(
            Request::delete(format!("/agents/delegations/{did}"))
                .header("X-Auth-Token", &cwt)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    let (st, body) = p.authorize(auth, authorize_body(&x, "kit-1", false)).await;
    assert_eq!(
        (st, body),
        (StatusCode::FORBIDDEN, json!("Workload quarantined"))
    );
    assert_ne!(p.mint(&x).await.0, StatusCode::OK);
    let t = p.trust(&did).await;
    assert_eq!(
        (t.state, t.incident.as_deref()),
        (AgentState::Quarantined, Some("inc-1")),
        "the latch survives revocation"
    );
}

#[tokio::test]
async fn an_expired_delegation_does_not_clear_the_latch() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let x = fresh_agent();
    let did = did_key(&x);
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&x, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(p.quarantine(&cwt, &did, "inc-1").await.0, StatusCode::OK);
    let expired = crate::db::AgentDelegation {
        expires_at: Some(Utc::now().timestamp() - 60),
        ..p.store.get_agent_delegation(&did).await.unwrap().unwrap()
    };
    p.store.put_agent_row(&expired).await.unwrap();

    let (st, body) = p.authorize(auth, authorize_body(&x, "kit-1", false)).await;
    assert_eq!(
        (st, body),
        (StatusCode::FORBIDDEN, json!("Workload quarantined"))
    );
    assert_eq!(p.trust(&did).await.state, AgentState::Quarantined);
}

#[tokio::test]
async fn refusal_bodies_are_contract_v2() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let auth = ("X-Auth-Token", cwt.as_str());
    let (legacy, lapsed, revoked, latched) =
        (fresh_agent(), fresh_agent(), fresh_agent(), fresh_agent());
    p.store
        .put_agent_row(&crate::db::agent_state_test_support::delegation(
            &did_key(&legacy),
            owner,
        ))
        .await
        .unwrap();
    for a in [&lapsed, &revoked, &latched] {
        assert_eq!(
            p.authorize(auth, authorize_body(a, "kit-1", false)).await.0,
            StatusCode::OK
        );
    }
    p.set_appraised_until(&did_key(&lapsed), Utc::now().timestamp() - 1)
        .await;
    let (st, _) = p
        .send(
            Request::delete(format!("/agents/delegations/{}", did_key(&revoked)))
                .header("X-Auth-Token", &cwt)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(
        p.quarantine(&cwt, &did_key(&latched), "inc-1").await.0,
        StatusCode::OK
    );

    // The texts are pinned in docs/agent-credentials-contract.md v2; edge
    // matches them byte for byte.
    let refused = |text: &str| (StatusCode::FORBIDDEN, json!(text));
    assert_eq!(
        p.mint(&legacy).await,
        refused("Forbidden: agent is unassessed; it needs an appraisal")
    );
    assert_eq!(
        p.mint(&lapsed).await,
        refused("Forbidden: agent appraisal expired; it needs a fresh appraisal")
    );
    assert_eq!(p.mint(&revoked).await, refused("Delegation revoked"));
    assert_eq!(p.mint(&latched).await, refused("Workload quarantined"));
    assert_eq!(
        p.authorize(auth, authorize_body(&latched, "kit-1", false))
            .await,
        refused("Workload quarantined")
    );
    assert_eq!(
        p.recover(auth, &did_key(&latched), "inc-1").await.0,
        StatusCode::OK
    );
    assert_eq!(
        p.authorize(auth, authorize_body(&latched, "kit-1", false))
            .await,
        refused("Forbidden: agent was recovered; only a Guardian may appraise it")
    );
    assert_eq!(
        p.mint(&latched).await,
        refused("Forbidden: agent is unassessed; it needs an appraisal")
    );
    // An owner appraisal cannot start from an assertion
    // older than the configured lifetime.
    let mut short = p.state.clone();
    short.appraisal.owner_ttl_seconds = 60;
    let aged = crate::test_helpers::auth_cwt_aged(&p.state, owner, 120);
    let resp = router(short)
        .oneshot(
            Request::post("/agents/authorize")
                .header("X-Auth-Token", &aged)
                .header("content-type", "application/json")
                .body(Body::from(
                    authorize_body(&fresh_agent(), "kit-1", false).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let st = resp.status();
    assert_eq!(
        (st, json_of(resp).await),
        refused(
            "Forbidden: passkey assertion is older than the owner appraisal lifetime; sign in again"
        )
    );
}

#[tokio::test]
async fn owner_quarantine_accepts_an_agents_delegate_token() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let (stranger, _) = p.user(&[READ]).await;
    let a = fresh_agent();
    let did = did_key(&a);
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let path = format!("/agents/{did}/quarantine");
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
    assert_eq!(p.trust(&did).await.state, AgentState::Eligible);

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
        p.trust(&did).await.quarantined_by,
        Some(format!("owner:{owner}"))
    );
}

#[tokio::test]
async fn a_quarantined_identity_is_refused_at_both_challenge_and_token() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        p.quarantine(&cwt, &did_key(&a), "inc-1").await.0,
        StatusCode::OK
    );
    // The challenge step's own `issuable` call refuses it.
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
    // And the token step's, exercised on its own.
    assert_eq!(
        token_stage(&p, &a).await,
        (StatusCode::FORBIDDEN, json!("Workload quarantined"))
    );
}

#[tokio::test]
async fn state_version_increases_on_every_state_change_and_only_then() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let auth = ("X-Auth-Token", cwt.as_str());
    let a = fresh_agent();
    let did = did_key(&a);
    assert_eq!(
        p.authorize(auth, authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(p.state_version(&did).await, 1, "created");
    assert_eq!(
        p.authorize(auth, authorize_body(&a, "kit-2", true)).await.0,
        StatusCode::OK
    );
    assert_eq!(p.state_version(&did).await, 2, "a swarm change");
    assert_eq!(
        p.authorize(auth, authorize_body(&a, "kit-2", false))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        p.state_version(&did).await,
        2,
        "renewed in the same swarm: unchanged"
    );
    assert_eq!(p.quarantine(&cwt, &did, "inc-1").await.0, StatusCode::OK);
    assert_eq!(p.state_version(&did).await, 3, "quarantined");
    assert_eq!(p.quarantine(&cwt, &did, "inc-1").await.0, StatusCode::OK);
    assert_eq!(
        p.state_version(&did).await,
        3,
        "same incident again: unchanged"
    );
    assert_eq!(
        p.quarantine(&cwt, &did, "inc-2").await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        p.state_version(&did).await,
        3,
        "refused second incident: unchanged"
    );
    assert_eq!(p.recover(auth, &did, "inc-1").await.0, StatusCode::OK);
    assert_eq!(p.state_version(&did).await, 4, "recovered");
    assert_eq!(
        p.authorize(auth, authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::FORBIDDEN,
        "the owner cannot appraise a recovered key"
    );
    assert_eq!(p.state_version(&did).await, 4, "refused: unchanged");
}

#[tokio::test]
async fn only_the_owner_with_a_fresh_passkey_recovers_citing_the_incident() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a1 = fresh_agent();
    let did = did_key(&a1);
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a1, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let (st, tok) = p.mint(&a1).await;
    assert_eq!(st, StatusCode::OK, "{tok}");
    let agent_token = tok["token"].as_str().unwrap().to_string();
    assert_eq!(p.quarantine(&cwt, &did, "inc-1").await.0, StatusCode::OK);
    let aged = |age: i64| crate::test_helpers::auth_cwt_aged(&p.state, owner, age);

    let (_, stranger) = p.user(&[READ]).await;
    assert_eq!(
        p.recover(("X-Auth-Token", &stranger), &did, "inc-1")
            .await
            .0,
        StatusCode::FORBIDDEN,
        "not the owner"
    );
    assert_eq!(
        p.recover(("X-Auth-Token", &aged(301)), &did, "inc-1")
            .await
            .0,
        StatusCode::UNAUTHORIZED,
        "a passkey assertion older than 300 s"
    );
    assert_eq!(
        p.recover(("X-Auth-Token", &aged(600)), &did, "inc-1")
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        p.recover(("X-Auth-Token", &agent_token), &did, "inc-1")
            .await
            .0,
        StatusCode::UNAUTHORIZED,
        "the agent cannot recover"
    );
    assert_eq!(
        p.recover(
            ("X-Auth-Token", &service_cwt(&p, STATUS_CLIENT)),
            &did,
            "inc-1"
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED,
        "an orchestrator's service identity cannot recover"
    );
    let (st, _) = p
        .send(
            Request::post(format!("/agents/{did}/recover"))
                .header("X-Auth-Token", &cwt)
                .header("X-Guardian-Signature", "g.1.sig")
                .header("content-type", "application/json")
                .body(Body::from(json!({"incident": "inc-1"}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "a Guardian can never recover");
    assert_eq!(
        p.recover(("X-Auth-Token", &cwt), &did, "").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        p.recover(("X-Auth-Token", &cwt), &did_key(&fresh_agent()), "inc-1")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (st, body) = p.recover(("X-Auth-Token", &cwt), &did, "inc-9").await;
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
    assert_eq!(p.trust(&did).await.state, AgentState::Quarantined);

    let (st, body) = p.recover(("X-Auth-Token", &aged(299)), &did, "inc-1").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "unassessed");
    assert_eq!(body["state_version"], 3);
    assert_eq!(body["incident"], Value::Null);
    assert_eq!(body["appraised_until"], Value::Null);
    let t = p.trust(&did).await;
    assert_eq!((t.state, t.state_version), (AgentState::Unassessed, 3));

    assert_eq!(
        p.mint(&a1).await,
        (
            StatusCode::FORBIDDEN,
            json!("Forbidden: agent is unassessed; it needs an appraisal")
        ),
        "recovery does not make the key eligible"
    );
    assert_eq!(
        p.recover(("X-Auth-Token", &cwt), &did, "inc-1").await.0,
        StatusCode::CONFLICT,
        "not quarantined"
    );
    // A replayed quarantine citing the cleared incident cannot re-latch.
    assert_eq!(
        p.quarantine(&cwt, &did, "inc-1").await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(p.state_version(&did).await, 3);
    assert_eq!(p.quarantine(&cwt, &did, "inc-2").await.0, StatusCode::OK);
}

#[tokio::test]
async fn owner_recovery_accepts_a_fresh_agents_delegate_token() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let (stranger, _) = p.user(&[READ]).await;
    let a = fresh_agent();
    let did = did_key(&a);
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(p.quarantine(&cwt, &did, "inc-1").await.0, StatusCode::OK);
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
            p.recover(("Authorization", &token), &did, "inc-1").await.0,
            expected,
            "{what}"
        );
    }
    assert_eq!(p.trust(&did).await.state, AgentState::Quarantined);

    let ok = bearer(
        owner,
        DELEGATE_CLIENT,
        "openid agents:delegate",
        Utc::now().timestamp() - 299,
    );
    let (st, body) = p.recover(("Authorization", &ok), &did, "inc-1").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "unassessed");
}

#[tokio::test]
async fn after_recovery_the_owner_may_authorize_a_new_key_but_not_the_old_one() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let (a1, a2) = (fresh_agent(), fresh_agent());
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&a1, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        p.quarantine(&cwt, &did_key(&a1), "inc-1").await.0,
        StatusCode::OK
    );
    assert_eq!(
        p.recover(auth, &did_key(&a1), "inc-1").await.0,
        StatusCode::OK
    );
    assert_eq!(
        p.authorize(auth, authorize_body(&a1, "kit-1", false))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(p.trust(&did_key(&a1)).await.state, AgentState::Unassessed);

    let (st, body) = p.authorize(auth, authorize_body(&a2, "kit-1", false)).await;
    assert_eq!(st, StatusCode::OK, "a new key is a new identity: {body}");
    let (st, body) = p.mint(&a2).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(
        verify_token(&p, body["token"].as_str().unwrap())
            .custom
            .arkavo_state_version,
        Some(1)
    );
}

#[tokio::test]
async fn a_revoked_delegation_re_authorized_never_revives_its_tokens() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let did = did_key(&a);
    let auth = ("X-Auth-Token", cwt.as_str());
    assert_eq!(
        p.authorize(auth, authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let (st, tok) = p.mint(&a).await;
    assert_eq!(st, StatusCode::OK, "{tok}");
    let old = verify_token(&p, tok["token"].as_str().unwrap())
        .custom
        .arkavo_state_version;
    assert_eq!(old, Some(1));

    let (st, _) = p
        .send(
            Request::delete(format!("/agents/delegations/{did}"))
                .header("X-Auth-Token", &cwt)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(
        p.state_version(&did).await,
        2,
        "revocation bumps the version"
    );

    let (st, body) = p.authorize(auth, authorize_body(&a, "kit-1", false)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(
        body["state_version"], 3,
        "a new delegation over the revoked one"
    );
    assert_ne!(
        old,
        Some(p.state_version(&did).await),
        "the pre-revocation token no longer matches the platform's check"
    );
}

#[tokio::test]
async fn a_former_owner_cannot_quarantine_a_reassigned_key() {
    let Some(p) = Plane::new().await else { return };
    let (first, first_cwt) = p.user(&[READ]).await;
    let (second, second_cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let did = did_key(&a);
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &first_cwt),
            authorize_body(&a, "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    let gsk = fresh_agent();
    let gid = p.enroll_guardian(first, &first_cwt, &gsk).await;

    // The first owner's delegation ages out and the second owner takes the key.
    let expired = crate::db::AgentDelegation {
        expires_at: Some(Utc::now().timestamp() - 60),
        ..p.store.get_agent_delegation(&did).await.unwrap().unwrap()
    };
    p.store.put_agent_row(&expired).await.unwrap();
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &second_cwt),
            authorize_body(&a, "kit-2", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    let taken = p.store.get_agent_delegation(&did).await.unwrap().unwrap();
    assert_eq!((taken.root_user_id, taken.trust.state_version), (second, 2));

    assert_eq!(
        p.quarantine(&first_cwt, &did, "inc-1").await.0,
        StatusCode::FORBIDDEN,
        "the former owner"
    );
    let path = format!("/agents/{did}/quarantine");
    let body = quarantine_body("inc-1");
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
        StatusCode::FORBIDDEN,
        "the former owner's Guardian"
    );
    assert_eq!(
        p.store.get_agent_delegation(&did).await.unwrap(),
        Some(taken),
        "the new owner's row is untouched"
    );
}

#[tokio::test]
async fn status_requires_an_allowlisted_service_cwt_and_leases_five_seconds() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let did = did_key(&a);
    let (_, authorized) = p
        .authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
        .await;

    assert_eq!(
        p.status(&did, None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        p.status(&did, Some(&cwt)).await.status(),
        StatusCode::FORBIDDEN,
        "a human CWT"
    );
    assert_eq!(
        p.status(&did, Some(&service_cwt(&p, "it"))).await.status(),
        StatusCode::FORBIDDEN,
        "an admin client is not a status client"
    );

    let before = Utc::now().timestamp();
    let resp = p.status(&did, Some(&service_cwt(&p, STATUS_CLIENT))).await;
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
            "agent": did, "owner": owner.to_string(), "swarm": "kit-1",
            "state": "eligible", "state_version": 1,
            "appraised_until": authorized["appraised_until"], "appraised_by": "owner",
            "incident": null, "valid_until": valid_until,
        })
    );
    let status_client = service_cwt(&p, STATUS_CLIENT);
    assert_eq!(
        p.status(&did_key(&fresh_agent()), Some(&status_client))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        p.status("wl-00112233445566778899aabbccddeeff", Some(&status_client))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );

    // An agent authorized before it has a kit reports an empty swarm.
    let bare = fresh_agent();
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&bare, "", false))
            .await
            .0,
        StatusCode::OK
    );
    let body = json_of(p.status(&did_key(&bare), Some(&status_client)).await).await;
    assert_eq!(body["swarm"], "");

    // A revoked delegation that is not quarantined is gone to the platform.
    let (st, _) = p
        .send(
            Request::delete(format!("/agents/delegations/{did}"))
                .header("X-Auth-Token", &cwt)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(
        p.status(&did, Some(&status_client)).await.status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn status_reports_suspended_and_never_leases_past_the_appraisal() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let did = did_key(&a);
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let status_client = service_cwt(&p, STATUS_CLIENT);
    let soon = Utc::now().timestamp() + 4;
    p.set_appraised_until(&did, soon).await;
    let body = json_of(p.status(&did, Some(&status_client)).await).await;
    assert_eq!(body["state"], "eligible");
    assert_eq!(
        body["valid_until"],
        json!(soon),
        "capped at appraised_until"
    );

    p.set_appraised_until(&did, Utc::now().timestamp() - 1)
        .await;
    let body = json_of(p.status(&did, Some(&status_client)).await).await;
    assert_eq!(body["state"], "suspended");
    assert_eq!(
        body["state_version"], 1,
        "suspension is derived, never stored"
    );
}

#[tokio::test]
async fn status_reports_the_latch_after_revocation_and_unassessed_after_recovery() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt) = p.user(&[READ]).await;
    let (x, y) = (fresh_agent(), fresh_agent());
    let auth = ("X-Auth-Token", cwt.as_str());
    for a in [&x, &y] {
        assert_eq!(
            p.authorize(auth, authorize_body(a, "kit-1", false)).await.0,
            StatusCode::OK
        );
    }
    let status_client = service_cwt(&p, STATUS_CLIENT);

    // Quarantined, then revoked: the latch is still reported, and the
    // revocation moved the version.
    let did = did_key(&x);
    assert_eq!(p.quarantine(&cwt, &did, "inc-1").await.0, StatusCode::OK);
    let (st, _) = p
        .send(
            Request::delete(format!("/agents/delegations/{did}"))
                .header("X-Auth-Token", &cwt)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let body = json_of(p.status(&did, Some(&status_client)).await).await;
    assert_eq!(
        (&body["state"], &body["incident"], &body["state_version"]),
        (&json!("quarantined"), &json!("inc-1"), &json!(3)),
        "the latch is reported even after revocation"
    );

    // Recovered: unassessed, the appraisal gone, a new version.
    let did = did_key(&y);
    assert_eq!(p.quarantine(&cwt, &did, "inc-2").await.0, StatusCode::OK);
    assert_eq!(p.recover(auth, &did, "inc-2").await.0, StatusCode::OK);
    let body = json_of(p.status(&did, Some(&status_client)).await).await;
    assert_eq!(
        (
            &body["state"],
            &body["state_version"],
            &body["appraised_until"],
            &body["appraised_by"]
        ),
        (&json!("unassessed"), &json!(3), &Value::Null, &Value::Null)
    );
}

/// An owner with one authorized agent, and an enrolled Guardian:
/// (owner, owner CWT, agent DID, guardian id, guardian key).
async fn guarded(p: &Plane) -> (Uuid, String, String, String, SigningKey) {
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let gsk = fresh_agent();
    let gid = p.enroll_guardian(owner, &cwt, &gsk).await;
    (owner, cwt, did_key(&a), gid, gsk)
}

fn quarantine_body(incident: &str) -> String {
    json!({"incident": incident, "evidence_ref": "s3://evidence/1"}).to_string()
}

#[tokio::test]
async fn enrolled_guardian_can_quarantine() {
    let Some(p) = Plane::new().await else { return };
    let (_, _, agent, gid, gsk) = guarded(&p).await;
    let path = format!("/agents/{agent}/quarantine");
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
    assert_eq!(resp["state_version"], 2);
    let w = p.trust(&agent).await;
    assert_eq!(w.quarantined_by, Some(format!("guardian:{gid}")));
    assert_eq!(w.evidence_ref.as_deref(), Some("s3://evidence/1"));
}

#[tokio::test]
async fn guardian_signature_by_a_self_supplied_key_is_rejected() {
    let Some(p) = Plane::new().await else { return };
    let (_, _, agent, gid, _) = guarded(&p).await;
    let path = format!("/agents/{agent}/quarantine");
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
    assert_eq!(p.trust(&agent).await.state, AgentState::Eligible);
}

#[tokio::test]
async fn guardian_signature_binds_body_path_and_time() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt, agent, gid, gsk) = guarded(&p).await;
    let other = fresh_agent();
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&other, "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    let other_path = format!("/agents/{}/quarantine", did_key(&other));
    let path = format!("/agents/{agent}/quarantine");
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
async fn guardian_cannot_quarantine_another_owners_agent() {
    let Some(p) = Plane::new().await else { return };
    let (_, _, _, gid, gsk) = guarded(&p).await;
    let (_, c2) = p.user(&[READ]).await;
    let a2 = fresh_agent();
    assert_eq!(
        p.authorize(("X-Auth-Token", &c2), authorize_body(&a2, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let agent2 = did_key(&a2);
    let path = format!("/agents/{agent2}/quarantine");
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
    assert_eq!(p.trust(&agent2).await.state, AgentState::Eligible);
}

#[tokio::test]
async fn guardians_get_403_everywhere_but_quarantine_and_appraisal() {
    let Some(p) = Plane::new().await else { return };
    let (_, _, agent, gid, gsk) = guarded(&p).await;
    let qpath = format!("/agents/{agent}/quarantine");
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
            Some(authorize_body(&a, "kit-1", false).to_string()),
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
            format!("/agents/{agent}/recover"),
            format!("/agents/{agent}/recover"),
            Some(json!({"incident": "g-inc-1"}).to_string()),
        ),
        (
            "GET",
            format!("/agents/{agent}/status"),
            format!("/agents/{agent}/status"),
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
        (
            "DELETE",
            format!("/guardians/{gid}"),
            format!("/guardians/{gid}"),
            None,
        ),
    ];
    for (method, uri, path, body) in requests {
        let bytes = body.as_deref().unwrap_or("").as_bytes().to_vec();
        let hdr = guardian_header(&gid, &gsk, method, &path, now, &bytes);
        let (st, resp) = p.signed(method, &uri, &hdr, body.as_deref()).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{method} {uri}: {resp}");
    }
    assert_eq!(
        p.trust(&agent).await.state,
        AgentState::Quarantined,
        "the reporting Guardian could not recover"
    );
}

#[tokio::test]
async fn a_replayed_guardian_request_is_rejected_even_inside_the_window() {
    let Some(p) = Plane::new().await else { return };
    let (_, _, agent, gid, gsk) = guarded(&p).await;
    let path = format!("/agents/{agent}/quarantine");
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
    let (_, cwt, agent, gid, gsk) = guarded(&p).await;
    let path = format!("/agents/{agent}/quarantine");
    let now = Utc::now().timestamp();
    let body = quarantine_body("g-inc-1");
    let first = guardian_header(&gid, &gsk, "POST", &path, now, body.as_bytes());
    assert_eq!(
        p.signed("POST", &path, &first, Some(&body)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        p.recover(("X-Auth-Token", &cwt), &agent, "g-inc-1").await.0,
        StatusCode::OK
    );

    // The exact request replayed after recovery: refused as a replay.
    assert_eq!(
        p.signed("POST", &path, &first, Some(&body)).await.0,
        StatusCode::UNAUTHORIZED
    );
    // Freshly signed but citing the cleared incident: refused, still unassessed.
    let again = guardian_header(&gid, &gsk, "POST", &path, now + 1, body.as_bytes());
    let (st, resp) = p.signed("POST", &path, &again, Some(&body)).await;
    assert_eq!(st, StatusCode::CONFLICT, "{resp}");
    let w = p.trust(&agent).await;
    assert_eq!((w.state, w.state_version), (AgentState::Unassessed, 3));
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

#[tokio::test]
async fn a_bad_guardian_header_never_falls_back_to_the_owner_credential() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt, agent, gid, _) = guarded(&p).await;
    let path = format!("/agents/{agent}/quarantine");
    let body = quarantine_body("g-inc-1");
    let forged = guardian_header(
        &gid,
        &fresh_agent(),
        "POST",
        &path,
        Utc::now().timestamp(),
        body.as_bytes(),
    );
    for hdr in ["not-a-signature".to_string(), forged] {
        let (st, resp) = p
            .send(
                Request::post(&path)
                    .header("X-Auth-Token", &cwt)
                    .header("X-Guardian-Signature", &hdr)
                    .header("content-type", "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{hdr}: {resp}");
    }
    assert_eq!(p.trust(&agent).await.state, AgentState::Eligible);
}

#[tokio::test]
async fn a_guardian_header_takes_precedence_over_an_owner_credential() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt, agent, gid, gsk) = guarded(&p).await;
    let path = format!("/agents/{agent}/quarantine");
    let body = quarantine_body("g-inc-1");
    let hdr = guardian_header(
        &gid,
        &gsk,
        "POST",
        &path,
        Utc::now().timestamp(),
        body.as_bytes(),
    );
    let (st, resp) = p
        .send(
            Request::post(&path)
                .header("X-Auth-Token", &cwt)
                .header("X-Guardian-Signature", &hdr)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{resp}");
    let w = p.trust(&agent).await;
    assert_eq!(w.quarantined_by, Some(format!("guardian:{gid}")));
}

#[tokio::test]
async fn the_signed_path_excludes_the_query_string() {
    let Some(p) = Plane::new().await else { return };
    let (_, _, agent, gid, gsk) = guarded(&p).await;
    let path = format!("/agents/{agent}/quarantine");
    let uri = format!("{path}?x=1");
    let body = quarantine_body("g-inc-1");
    let now = Utc::now().timestamp();
    let over_query = guardian_header(&gid, &gsk, "POST", &uri, now, body.as_bytes());
    assert_eq!(
        p.signed("POST", &uri, &over_query, Some(&body)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let over_path = guardian_header(&gid, &gsk, "POST", &path, now, body.as_bytes());
    assert_eq!(
        p.signed("POST", &uri, &over_path, Some(&body)).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_public_key_enrolls_only_once_whoever_the_owner() {
    let Some(p) = Plane::new().await else { return };
    let (o1, c1) = p.user(&[READ]).await;
    let (o2, c2) = p.user(&[READ]).await;
    let gsk = fresh_agent();
    p.enroll_guardian(o1, &c1, &gsk).await;
    // Each with a valid proof for itself: the key holder cannot enroll twice.
    for (owner, cwt) in [(o1, &c1), (o2, &c2)] {
        let (st, body) = p
            .post_json(
                "/guardians",
                ("X-Auth-Token", cwt),
                enroll_body(owner, &gsk, "pager"),
            )
            .await;
        assert_eq!(st, StatusCode::CONFLICT, "{body}");
    }
}

#[tokio::test]
async fn owner_revokes_a_guardian_and_its_signatures_stop() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt, agent, gid, gsk) = guarded(&p).await;
    let (_, stranger) = p.user(&[READ]).await;
    let path = format!("/agents/{agent}/quarantine");
    let body = quarantine_body("g-inc-1");
    let now = Utc::now().timestamp();

    let (st, _) = p
        .send(
            Request::delete(format!("/guardians/{gid}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "no credential");
    assert_eq!(
        p.revoke_guardian(&stranger, &gid).await.0,
        StatusCode::FORBIDDEN
    );
    let signed_delete =
        guardian_header(&gid, &gsk, "DELETE", &format!("/guardians/{gid}"), now, b"");
    let (st, _) = p
        .send(
            Request::delete(format!("/guardians/{gid}"))
                .header("X-Auth-Token", &cwt)
                .header("X-Guardian-Signature", &signed_delete)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "a Guardian cannot revoke, even with the owner's token"
    );
    assert_eq!(
        p.revoke_guardian(&cwt, &Uuid::new_v4().to_string()).await.0,
        StatusCode::NOT_FOUND
    );

    assert_eq!(
        p.revoke_guardian(&cwt, &gid).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        p.revoke_guardian(&cwt, &gid).await.0,
        StatusCode::NO_CONTENT,
        "idempotent"
    );

    let hdr = guardian_header(&gid, &gsk, "POST", &path, now, body.as_bytes());
    let (st, revoked) = p.signed("POST", &path, &hdr, Some(&body)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let unknown = guardian_header(
        &Uuid::new_v4().to_string(),
        &gsk,
        "POST",
        &path,
        now,
        body.as_bytes(),
    );
    let (_, unknown) = p.signed("POST", &path, &unknown, Some(&body)).await;
    assert_eq!(
        revoked, unknown,
        "a revoked Guardian reads as an unknown one"
    );
    let w = p.trust(&agent).await;
    assert_eq!((w.state, w.state_version), (AgentState::Eligible, 1));

    let (st, _) = p
        .post_json(
            "/guardians",
            ("X-Auth-Token", &cwt),
            enroll_body(owner, &gsk, "pager"),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT, "a revoked key stays burned");
}

#[tokio::test]
async fn a_guardian_key_cannot_be_squatted_by_another_owner() {
    let Some(p) = Plane::new().await else { return };
    let (alice, alice_cwt) = p.user(&[READ]).await;
    let (mallory, mallory_cwt) = p.user(&[READ]).await;
    let gsk = fresh_agent();
    let key = b64url(gsk.verifying_key().as_bytes());
    let attempts = [
        ("no proof", json!({"public_key": key, "name": "squat"})),
        (
            "proof by another key",
            json!({"public_key": key, "name": "squat", "proof": enroll_proof(mallory, &fresh_agent())}),
        ),
        (
            "alice's captured proof",
            json!({"public_key": key, "name": "squat", "proof": enroll_proof(alice, &gsk)}),
        ),
        (
            "not base64url",
            json!({"public_key": key, "name": "squat", "proof": "not base64url!"}),
        ),
    ];
    for (what, body) in attempts {
        let (st, resp) = p
            .post_json("/guardians", ("X-Auth-Token", &mallory_cwt), body)
            .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{what}: {resp}");
    }
    // The key is still free for its holder.
    let gid = p.enroll_guardian(alice, &alice_cwt, &gsk).await;
    assert_eq!(
        p.store.get_guardian(&gid).await.unwrap().unwrap().owner,
        alice
    );
}

#[tokio::test]
async fn garbage_guardian_ids_are_refused_before_storage() {
    let Some(p) = Plane::new().await else { return };
    let (_, cwt, agent, _, gsk) = guarded(&p).await;
    let oversized = "a".repeat(3000);
    for id in ["not-a-uuid", oversized.as_str()] {
        assert_eq!(
            p.revoke_guardian(&cwt, id).await.0,
            StatusCode::NOT_FOUND,
            "DELETE {}",
            &id[..10]
        );
    }
    let path = format!("/agents/{agent}/quarantine");
    let body = quarantine_body("g-inc-1");
    let now = Utc::now().timestamp();
    let unknown = guardian_header(
        &Uuid::new_v4().to_string(),
        &gsk,
        "POST",
        &path,
        now,
        body.as_bytes(),
    );
    let (_, unknown) = p.signed("POST", &path, &unknown, Some(&body)).await;
    for id in ["not-a-uuid", oversized.as_str()] {
        let hdr = guardian_header(id, &gsk, "POST", &path, now, body.as_bytes());
        let (st, resp) = p.signed("POST", &path, &hdr, Some(&body)).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "header id {}", &id[..10]);
        assert_eq!(resp, unknown);
    }
    assert_eq!(p.trust(&agent).await.state, AgentState::Eligible);
}

/// A Guardian-signed appraisal of `did` with `body`, signed at `ts`.
async fn guardian_appraisal(
    p: &Plane,
    gid: &str,
    gsk: &SigningKey,
    did: &str,
    ts: i64,
    body: &Value,
) -> (StatusCode, Value) {
    let path = format!("/agents/{did}/appraisal");
    let body = body.to_string();
    let hdr = guardian_header(gid, gsk, "POST", &path, ts, body.as_bytes());
    p.signed("POST", &path, &hdr, Some(&body)).await
}

#[tokio::test]
async fn a_guardian_re_appraises_a_recovered_agent_within_its_cap() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let agent = did_key(&a);
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let gsk = fresh_agent();
    let gid = p.enroll_guardian(owner, &cwt, &gsk).await;
    assert_eq!(p.quarantine(&cwt, &agent, "inc-1").await.0, StatusCode::OK);
    assert_eq!(
        p.recover(("X-Auth-Token", &cwt), &agent, "inc-1").await.0,
        StatusCode::OK
    );
    let now = Utc::now().timestamp();
    let (st, body) = guardian_appraisal(
        &p,
        &gid,
        &gsk,
        &agent,
        now,
        &json!({"appraised_until": now + 3_600, "evidence_ref": "ev-1"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "eligible");
    assert_eq!(
        body["state_version"], 4,
        "unassessed → eligible is a state change"
    );
    assert_eq!(body["appraised_by"], "guardian");
    let until = body["appraised_until"].as_i64().unwrap();
    assert!(
        until <= Utc::now().timestamp() + 900,
        "clamped to 15 minutes"
    );
    assert_eq!(
        p.trust(&agent).await.appraised_by,
        Some(format!("guardian:{gid}"))
    );

    // The recovered key now mints, at the new version.
    let (st, tok) = p.mint(&a).await;
    assert_eq!(st, StatusCode::OK, "{tok}");
    let claims = verify_token(&p, tok["token"].as_str().unwrap());
    assert_eq!(claims.custom.arkavo_state_version, Some(4));
    assert!(claims.exp <= until, "the token ends with the appraisal");

    // A renewal keeps the version, so the token above stays good.
    let (st, body) = guardian_appraisal(&p, &gid, &gsk, &agent, now + 1, &json!({})).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["state_version"], 4);
    assert_eq!(p.state_version(&agent).await, 4);
}

#[tokio::test]
async fn the_owner_renews_by_appraisal_but_never_a_recovered_key() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let did = did_key(&a);
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    p.set_appraised_until(&did, Utc::now().timestamp() - 1)
        .await;
    assert_eq!(p.mint(&a).await.0, StatusCode::FORBIDDEN, "suspended");

    let path = format!("/agents/{did}/appraisal");
    // A passkey assertion ten minutes old: the renewal runs from it.
    let before = Utc::now().timestamp();
    let aged = crate::test_helpers::auth_cwt_aged(&p.state, owner, 600);
    let (st, body) = p.post_json(&path, ("X-Auth-Token", &aged), json!({})).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "eligible");
    assert_eq!(
        body["state_version"], 1,
        "suspended → eligible is a renewal"
    );
    assert_eq!(body["appraised_by"], "owner");
    let until = body["appraised_until"].as_i64().unwrap();
    assert!(
        (before - 600 + 43_200..=Utc::now().timestamp() - 600 + 43_200).contains(&until),
        "iat + 12 h: {until}"
    );
    assert_eq!(
        p.trust(&did).await.appraised_by,
        Some(format!("owner:{owner}"))
    );
    assert_eq!(p.mint(&a).await.0, StatusCode::OK);

    // An agents:delegate Bearer token works too, within an hour of the tap.
    let bearer = format!(
        "Bearer {}",
        p.delegate_token(
            owner,
            DELEGATE_CLIENT,
            "openid agents:delegate",
            "webauthn",
            Some(Utc::now().timestamp() - 600)
        )
    );
    assert_eq!(
        p.post_json(&path, ("Authorization", &bearer), json!({}))
            .await
            .0,
        StatusCode::OK
    );

    assert_eq!(p.quarantine(&cwt, &did, "inc-1").await.0, StatusCode::OK);
    assert_eq!(
        p.post_json(&path, ("X-Auth-Token", &cwt), json!({})).await,
        (StatusCode::FORBIDDEN, json!("Workload quarantined")),
        "an appraisal never clears quarantine"
    );
    assert_eq!(
        p.recover(("X-Auth-Token", &cwt), &did, "inc-1").await.0,
        StatusCode::OK
    );
    assert_eq!(
        p.post_json(&path, ("X-Auth-Token", &cwt), json!({})).await,
        (
            StatusCode::FORBIDDEN,
            json!("Forbidden: agent was recovered; only a Guardian may appraise it")
        )
    );
    assert_eq!(p.trust(&did).await.state, AgentState::Unassessed);
}

#[tokio::test]
async fn appraisal_is_refused_outside_the_callers_scope() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt, agent, gid, gsk) = guarded(&p).await;
    let now = Utc::now().timestamp();
    let ok = json!({});

    // Another owner's agent.
    let (_, c2) = p.user(&[READ]).await;
    let other = fresh_agent();
    assert_eq!(
        p.authorize(
            ("X-Auth-Token", &c2),
            authorize_body(&other, "kit-1", false)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        guardian_appraisal(&p, &gid, &gsk, &did_key(&other), now, &ok)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (st, _) = p
        .post_json(
            &format!("/agents/{}/appraisal", did_key(&other)),
            ("X-Auth-Token", &cwt),
            ok.clone(),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "nor its owner's appraisal");

    // Unknown, malformed and past.
    assert_eq!(
        guardian_appraisal(&p, &gid, &gsk, &did_key(&fresh_agent()), now + 1, &ok)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        guardian_appraisal(
            &p,
            &gid,
            &gsk,
            &agent,
            now + 2,
            &json!({"appraised_until": now})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        guardian_appraisal(
            &p,
            &gid,
            &gsk,
            &agent,
            now + 3,
            &json!({"evidence_ref": ""})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );

    // A revoked delegation.
    let (st, _) = p
        .send(
            Request::delete(format!("/agents/delegations/{agent}"))
                .header("X-Auth-Token", &cwt)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(
        guardian_appraisal(&p, &gid, &gsk, &agent, now + 4, &ok).await,
        (StatusCode::FORBIDDEN, json!("Delegation revoked"))
    );

    // The subject's own key, enrolled as a Guardian.
    let a = fresh_agent();
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let self_gid = p.enroll_guardian(owner, &cwt, &a).await;
    assert_eq!(
        guardian_appraisal(&p, &self_gid, &a, &did_key(&a), now, &ok).await,
        (
            StatusCode::FORBIDDEN,
            json!("Forbidden: an agent cannot appraise itself")
        )
    );

    // A revoked Guardian reads as unknown.
    assert_eq!(
        p.revoke_guardian(&cwt, &gid).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        guardian_appraisal(&p, &gid, &gsk, &did_key(&a), now + 5, &ok)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn an_owner_appraisal_runs_from_the_assertion_and_is_clamped_to_it() {
    let Some(p) = Plane::new().await else { return };
    let (owner, cwt) = p.user(&[READ]).await;
    let a = fresh_agent();
    let did = did_key(&a);
    assert_eq!(
        p.authorize(("X-Auth-Token", &cwt), authorize_body(&a, "kit-1", false))
            .await
            .0,
        StatusCode::OK
    );
    let path = format!("/agents/{did}/appraisal");
    // A refreshed agents:delegate token: minted now, its auth_time 50 minutes old.
    let auth_time = Utc::now().timestamp() - 3_000;
    let bearer = |auth_time: i64| {
        format!(
            "Bearer {}",
            p.delegate_token(
                owner,
                DELEGATE_CLIENT,
                "openid agents:delegate",
                "webauthn",
                Some(auth_time)
            )
        )
    };
    let deadline = auth_time + 43_200;
    let (st, body) = p
        .post_json(&path, ("Authorization", &bearer(auth_time)), json!({}))
        .await;
    assert_eq!(
        (st, &body["appraised_until"]),
        (StatusCode::OK, &json!(deadline))
    );
    let (st, body) = p
        .post_json(
            &path,
            ("Authorization", &bearer(auth_time)),
            json!({"appraised_until": deadline + 7_000}),
        )
        .await;
    assert_eq!(
        (st, &body["appraised_until"]),
        (StatusCode::OK, &json!(deadline)),
        "a later request is clamped to the deadline"
    );
    let sooner = Utc::now().timestamp() + 600;
    let (st, body) = p
        .post_json(
            &path,
            ("Authorization", &bearer(auth_time)),
            json!({"appraised_until": sooner}),
        )
        .await;
    assert_eq!(
        (st, &body["appraised_until"]),
        (StatusCode::OK, &json!(sooner))
    );

    // A configured lifetime shorter than the credential's age: refused.
    let mut short = p.state.clone();
    short.appraisal.owner_ttl_seconds = 600;
    let resp = router(short)
        .oneshot(
            Request::post(path.as_str())
                .header("Authorization", bearer(Utc::now().timestamp() - 900))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let st = resp.status();
    assert_eq!(
        (st, json_of(resp).await),
        (
            StatusCode::FORBIDDEN,
            json!(
                "Forbidden: passkey assertion is older than the owner appraisal lifetime; sign in again"
            )
        )
    );
    assert_eq!(p.trust(&did).await.appraised_until, Some(sooner));
}
