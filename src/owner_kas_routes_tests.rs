//! Owner-KAS routes (#148) through the real handlers. Refusals decided before
//! any read need no database; the rest register an account with a software
//! passkey and return early unless `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set, as
//! CI's `test` job sets it.

use super::*;
use crate::authentication_tests::{ORIGIN, Registered, registered_account, unique_name};
use crate::test_helpers::{auth_cwt_aged, build_test_app_state, build_test_app_state_with_store};
use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request};
use axum::routing::{delete, get, post, put};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::Value;
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

fn app(state: &AppState) -> Router {
    Router::new()
        .route(
            "/owner-kas/routes/:route_id",
            put(put_route).delete(delete_route),
        )
        .route(
            "/owner-kas/routes/:route_id/push",
            put(put_push).delete(delete_push),
        )
        .route("/owner-kas/routes/:route_id/relay", get(relay_read))
        .route(
            "/owner-kas/routes/:route_id/relay/push",
            delete(relay_delete_push),
        )
        .route("/owner-kas/token", post(crate::owner_kas::token_handler))
        .layer(Extension(state.clone()))
}

async fn send(
    state: &AppState,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        req = req.header("X-Auth-Token", t);
    }
    let body = match body {
        Some(b) => {
            req = req.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let resp = app(state).oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

use tower::ServiceExt;

fn service_cwt(state: &AppState, client: &str) -> String {
    let claims =
        authnz_rs::cwt::ArkavoClaims::auth(&state.issuer, &format!("client:{client}"), 1, None)
            .with_arkavo_roles(vec!["service-account".into()]);
    authnz_rs::cwt::encode_for_header(
        &authnz_rs::cwt::mint(&claims, &state.cwt_signing_key, &state.cwt_kid).unwrap(),
    )
}

/// A fresh canonical route id.
fn route_id() -> String {
    const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let bytes = Uuid::new_v4();
    let tail: String = bytes
        .as_bytes()
        .iter()
        .chain(Uuid::new_v4().as_bytes())
        .take(25)
        .map(|b| CROCKFORD[(*b as usize) % 32] as char)
        .collect();
    format!("0{tail}")
}

#[tokio::test]
async fn every_route_needs_its_credential() {
    let state = build_test_app_state().await;
    let r = route_id();
    let routes = [
        (Method::PUT, format!("/owner-kas/routes/{r}")),
        (Method::DELETE, format!("/owner-kas/routes/{r}")),
        (Method::PUT, format!("/owner-kas/routes/{r}/push")),
        (Method::DELETE, format!("/owner-kas/routes/{r}/push")),
        (Method::GET, format!("/owner-kas/routes/{r}/relay")),
        (Method::DELETE, format!("/owner-kas/routes/{r}/relay/push")),
    ];
    for (method, uri) in &routes {
        let (st, body) = send(&state, method.clone(), uri, None, Some(json!({}))).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{method} {uri}");
        assert_eq!(body, json!({ "error": "unauthorized" }), "{method} {uri}");
    }

    // The relay routes take only the relay's service client: not another
    // service, and not a person's passkey token.
    let other = service_cwt(&state, "arks-media");
    let person = auth_cwt_aged(&state, Uuid::new_v4(), 0);
    for (method, uri) in &routes[4..] {
        let (st, body) = send(&state, method.clone(), uri, Some(&other), Some(json!({}))).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{method} {uri}");
        assert_eq!(body, json!({ "error": "forbidden" }));
        let (st, _) = send(&state, method.clone(), uri, Some(&person), Some(json!({}))).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{method} {uri}");
    }

    // A malformed route id from the relay is 400, before any read.
    let relay = service_cwt(&state, "owner-kas-relay");
    let (st, body) = send(
        &state,
        Method::GET,
        &format!("/owner-kas/routes/{}/relay", r.to_lowercase()),
        Some(&relay),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({ "error": "invalid_route_id" }));
}

#[test]
fn apns_tokens_are_lowercase_hex_of_64_to_200() {
    assert!(is_apns_token(&"ab".repeat(32)));
    assert!(is_apns_token(&"0".repeat(200)));
    assert!(!is_apns_token(&"ab".repeat(31)));
    assert!(!is_apns_token(&"0".repeat(201)));
    assert!(!is_apns_token(&"AB".repeat(32)));
    assert!(!is_apns_token(&format!("{}g", "a".repeat(63))));
}

/// An owner with a software passkey, its token, and what it needs to sign
/// route records.
struct Owner {
    r: Registered,
    state: AppState,
    token: String,
    attestation: String,
}

impl Owner {
    async fn new() -> Option<Self> {
        let r = registered_account(&unique_name()).await?;
        let state = build_test_app_state_with_store(r.ceremony.store.clone());
        let token = auth_cwt_aged(&state, r.user_id, 0);
        let user = state
            .db_store
            .get_user_by_id(&r.user_id)
            .await
            .unwrap()
            .unwrap();
        let passkey = &user.credentials[0];
        let (x, y) = crate::passkeys::p256_coordinates(passkey).unwrap();
        let canonical = URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());
        state
            .db_store
            .link_passkey(&r.user_id, &canonical, Utc::now().timestamp())
            .await
            .unwrap();
        let attestation = authnz_rs::credential_attestation::mint(
            &authnz_rs::credential_attestation::CredentialAttestation {
                iss: state.issuer.to_string(),
                sub: r.user_id.to_string(),
                credential_id: passkey.cred_id().as_ref().to_vec(),
                x,
                y,
                rp_id: WEBAUTHN_RP_ID.into(),
                iat: Utc::now().timestamp(),
            },
            &state.cwt_signing_key,
            &state.cwt_kid,
        )
        .unwrap();
        Some(Owner {
            r,
            state,
            token,
            attestation: URL_SAFE_NO_PAD.encode(attestation),
        })
    }

    /// The deterministic CBOR record for `route` at `seq`, owned by `owner`.
    fn record(route: &str, owner: &str, seq: u64) -> Vec<u8> {
        let t = |s: &str| Value::Text(s.into());
        let point = || {
            p256::ecdsa::SigningKey::random(&mut OsRng)
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec()
        };
        let mut entries = vec![
            (t("v"), Value::Integer(1.into())),
            (t("route_id"), t(route)),
            (t("owner_sub"), t(owner)),
            (t("kas_key"), Value::Bytes(point())),
            (t("kas_kid"), t("owner-kas-1")),
            (t("service_key"), Value::Bytes(point())),
            (t("seq"), Value::Integer(seq.into())),
            (
                t("issued_at"),
                Value::Integer(Utc::now().timestamp().into()),
            ),
        ];
        let enc = |v: &Value| {
            let mut b = Vec::new();
            ciborium::ser::into_writer(v, &mut b).unwrap();
            b
        };
        entries.sort_by_key(|(k, _)| enc(k));
        enc(&Value::Map(entries))
    }

    /// The passkey's assertion over SHA-256(`signed`), as the phone sends it.
    fn assert_over(&mut self, signed: &[u8]) -> serde_json::Value {
        let options = serde_json::from_value(json!({
            "publicKey": {
                "challenge": URL_SAFE_NO_PAD.encode(Sha256::digest(signed)),
                "timeout": 60000,
                "rpId": WEBAUTHN_RP_ID,
                "allowCredentials": [{ "type": "public-key", "id": self.r.cred }],
                "userVerification": "required",
            }
        }))
        .unwrap();
        let credential = self
            .r
            .auth
            .do_authentication(Url::parse(ORIGIN).unwrap(), options)
            .expect("the soft authenticator signs");
        let b = |v: &[u8]| URL_SAFE_NO_PAD.encode(v);
        json!({
            "credentialId": b(credential.raw_id.as_ref()),
            "authenticatorData": b(credential.response.authenticator_data.as_ref()),
            "clientDataJSON": b(credential.response.client_data_json.as_ref()),
            "signature": b(credential.response.signature.as_ref()),
        })
    }

    /// A bundle for `route` at `seq`: the record, signed by the passkey.
    fn bundle(&mut self, route: &str, seq: u64) -> serde_json::Value {
        let record = Self::record(route, &self.r.user_id.to_string(), seq);
        let assertion = self.assert_over(&record);
        json!({
            "record": URL_SAFE_NO_PAD.encode(&record),
            "assertion": assertion,
            "credential": self.attestation,
        })
    }

    async fn put(
        &self,
        route: &str,
        bundle: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        send(
            &self.state,
            Method::PUT,
            &format!("/owner-kas/routes/{route}"),
            Some(&self.token),
            Some(bundle.clone()),
        )
        .await
    }
}

fn cnf_key() -> String {
    URL_SAFE_NO_PAD.encode(
        p256::ecdsa::SigningKey::random(&mut OsRng)
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    )
}

#[tokio::test]
async fn an_owner_puts_a_route_the_relay_reads_and_a_receiver_mints_for() {
    let Some(mut o) = Owner::new().await else {
        return;
    };
    let route = route_id();
    let relay = service_cwt(&o.state, "owner-kas-relay");
    let receiver = auth_cwt_aged(&o.state, o.r.user_id, 0);

    // Unknown until put.
    let (st, body) = send(
        &o.state,
        Method::POST,
        "/owner-kas/token",
        Some(&receiver),
        Some(json!({ "route_id": route, "cnf_key": cnf_key() })),
    )
    .await;
    assert_eq!(
        (st, body),
        (StatusCode::NOT_FOUND, json!({ "error": "unknown_route" }))
    );
    let (st, _) = send(
        &o.state,
        Method::GET,
        &format!("/owner-kas/routes/{route}/relay"),
        Some(&relay),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let bundle = o.bundle(&route, 1);
    let (st, body) = o.put(&route, &bundle).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body, json!({ "route_id": route, "seq": 1 }));

    // The same seq again is stale; a higher one replaces it.
    let (st, body) = o.put(&route, &bundle).await;
    assert_eq!(
        (st, body),
        (StatusCode::CONFLICT, json!({ "error": "stale_seq" }))
    );
    let bundle = o.bundle(&route, 2);
    assert_eq!(o.put(&route, &bundle).await.0, StatusCode::OK);

    // The receiver gets the bundle exactly as put.
    let (st, body) = send(
        &o.state,
        Method::POST,
        "/owner-kas/token",
        Some(&receiver),
        Some(json!({ "route_id": route, "cnf_key": cnf_key() })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["route"], bundle);

    // Push token: set, read by the relay, removed when APNs says so.
    let apns = "ab".repeat(32);
    let push = |env: &str| json!({ "apns_token": apns, "environment": env });
    let push_uri = format!("/owner-kas/routes/{route}/push");
    let (st, body) = send(
        &o.state,
        Method::PUT,
        &push_uri,
        Some(&o.token),
        Some(push("development")),
    )
    .await;
    assert_eq!(
        (st, body),
        (StatusCode::BAD_REQUEST, json!({ "error": "invalid_push" }))
    );
    let (st, _) = send(
        &o.state,
        Method::PUT,
        &push_uri,
        Some(&o.token),
        Some(push("production")),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    let relay_uri = format!("/owner-kas/routes/{route}/relay");
    let (st, body) = send(&o.state, Method::GET, &relay_uri, Some(&relay), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "owner_sub": o.r.user_id.to_string(), "apns_token": apns, "environment": "production" })
    );
    let unregistered = format!("/owner-kas/routes/{route}/relay/push");
    let (st, _) = send(
        &o.state,
        Method::DELETE,
        &unregistered,
        Some(&relay),
        Some(json!({ "apns_token": "cd".repeat(32) })),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(
        send(&o.state, Method::GET, &relay_uri, Some(&relay), None)
            .await
            .1["apns_token"],
        json!(apns)
    );
    let (st, _) = send(
        &o.state,
        Method::DELETE,
        &unregistered,
        Some(&relay),
        Some(json!({ "apns_token": apns })),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(
        send(&o.state, Method::GET, &relay_uri, Some(&relay), None)
            .await
            .1,
        json!({ "owner_sub": o.r.user_id.to_string() })
    );

    // Sharing off: retired for the mint, the relay and the owner alike.
    let route_uri = format!("/owner-kas/routes/{route}");
    let (st, _) = send(&o.state, Method::DELETE, &route_uri, Some(&o.token), None).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, body) = send(
        &o.state,
        Method::POST,
        "/owner-kas/token",
        Some(&receiver),
        Some(json!({ "route_id": route, "cnf_key": cnf_key() })),
    )
    .await;
    assert_eq!(
        (st, body),
        (StatusCode::GONE, json!({ "error": "route_retired" }))
    );
    assert_eq!(
        send(&o.state, Method::GET, &relay_uri, Some(&relay), None)
            .await
            .0,
        StatusCode::GONE
    );
    let bundle = o.bundle(&route, 3);
    assert_eq!(
        o.put(&route, &bundle).await,
        (StatusCode::GONE, json!({ "error": "route_retired" }))
    );
    let (st, _) = send(
        &o.state,
        Method::PUT,
        &push_uri,
        Some(&o.token),
        Some(push("production")),
    )
    .await;
    assert_eq!(st, StatusCode::GONE);
}

#[tokio::test]
async fn bundles_that_do_not_bind_the_owner_and_route_are_refused() {
    let Some(mut o) = Owner::new().await else {
        return;
    };
    let route = route_id();
    let invalid = |code: &str| (StatusCode::BAD_REQUEST, json!({ "error": code }));

    // A record for another route, or naming another owner.
    let other = o.bundle(&route_id(), 1);
    assert_eq!(o.put(&route, &other).await, invalid("invalid_record"));
    let record = Owner::record(&route, &Uuid::new_v4().to_string(), 1);
    let assertion = o.assert_over(&record);
    let foreign = json!({
        "record": URL_SAFE_NO_PAD.encode(&record), "assertion": assertion, "credential": o.attestation,
    });
    assert_eq!(o.put(&route, &foreign).await, invalid("invalid_record"));

    // An assertion over some other record.
    let mut swapped = o.bundle(&route, 1);
    swapped["assertion"] = o.assert_over(&Owner::record(&route, &o.r.user_id.to_string(), 1));
    assert_eq!(o.put(&route, &swapped).await, invalid("invalid_assertion"));

    // Another account's attestation of a different credential.
    let mut wrong_attestation = o.bundle(&route, 1);
    let Some(other_owner) = Owner::new().await else {
        return;
    };
    wrong_attestation["credential"] = other_owner.attestation.clone().into();
    assert_eq!(
        o.put(&route, &wrong_attestation).await,
        invalid("invalid_assertion")
    );

    // Unknown members, and an oversized body.
    let mut extra = o.bundle(&route, 1);
    extra["note"] = "x".into();
    assert_eq!(o.put(&route, &extra).await, invalid("invalid_request"));
    let mut big = o.bundle(&route, 1);
    big["record"] = "A".repeat(9000).into();
    assert_eq!(o.put(&route, &big).await, invalid("invalid_request"));

    // Another account cannot take over a route.
    let good = o.bundle(&route, 1);
    assert_eq!(o.put(&route, &good).await.0, StatusCode::OK);
    let mut thief = other_owner;
    let theirs = thief.bundle(&route, 9);
    assert_eq!(
        thief.put(&route, &theirs).await,
        (StatusCode::FORBIDDEN, json!({ "error": "not_route_owner" }))
    );
    let (st, _) = send(
        &thief.state,
        Method::DELETE,
        &format!("/owner-kas/routes/{route}"),
        Some(&thief.token),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_deleted_owners_route_is_retired_at_once() {
    let Some(mut o) = Owner::new().await else {
        return;
    };
    let route = route_id();
    let bundle = o.bundle(&route, 1);
    assert_eq!(o.put(&route, &bundle).await.0, StatusCode::OK);

    // The tombstone alone retires it for the mint and the relay, before the
    // sweep runs.
    o.state
        .db_store
        .tombstone_account(
            &o.r.user_id,
            &format!("{}.{}", o.r.user_id, Uuid::new_v4().simple()),
            None,
            Utc::now().timestamp(),
        )
        .await
        .unwrap();
    let relay = service_cwt(&o.state, "owner-kas-relay");
    let (st, _) = send(
        &o.state,
        Method::GET,
        &format!("/owner-kas/routes/{route}/relay"),
        Some(&relay),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::GONE);
    let receiver = registered_account(&unique_name()).await.unwrap();
    let (st, body) = send(
        &o.state,
        Method::POST,
        "/owner-kas/token",
        Some(&auth_cwt_aged(&o.state, receiver.user_id, 0)),
        Some(json!({ "route_id": route, "cnf_key": cnf_key() })),
    )
    .await;
    assert_eq!(
        (st, body),
        (StatusCode::GONE, json!({ "error": "route_retired" }))
    );

    // The sweep keeps the row and retires it: the id never frees up.
    assert_eq!(
        o.state
            .db_store
            .retire_owner_kas_routes_of(&o.r.user_id, Utc::now().timestamp())
            .await
            .unwrap(),
        1
    );
    let row = o
        .state
        .db_store
        .get_owner_kas_route(&route)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.user_id, o.r.user_id);
    assert!(row.retired_at.is_some() && row.bundle.is_none());
}
