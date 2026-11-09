//! `POST /owner-kas/token` (#146) through the real handler. Refusals decided
//! before the account read need no database; the rest return early unless
//! `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set, as CI's `test` job sets it.

use super::*;
use crate::test_helpers::{auth_cwt_aged, build_test_app_state, build_test_app_state_with_store};
use authnz_rs::constants::OWNER_KAS_MINTS_PER_MINUTE;
use authnz_rs::cwt::CwtError;
use axum::body::Body;
use axum::http::Request;
use axum::routing::post;
use axum::{Extension, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const ROUTE: &str = "01JC5Z8Q4M7N2P3R6S9T0V1W2X";

fn request_key() -> String {
    let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
    URL_SAFE_NO_PAD.encode(sk.verifying_key().to_encoded_point(false).as_bytes())
}

async fn post_token(
    state: &AppState,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, HeaderMap, Value) {
    let app = Router::new()
        .route("/owner-kas/token", post(token_handler))
        .layer(Extension(state.clone()));
    let mut req = Request::post("/owner-kas/token").header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("X-Auth-Token", t);
    }
    let resp = app
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, headers, serde_json::from_slice(&bytes).unwrap())
}

fn good_body() -> Value {
    json!({ "route_id": ROUTE, "cnf_key": request_key() })
}

#[tokio::test]
async fn only_a_passkey_auth_cwt_may_mint() {
    let state = build_test_app_state().await;
    let uid = Uuid::new_v4();

    let (st, h, body) = post_token(&state, None, good_body()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({ "error": "unauthorized" }));
    assert_eq!(h["cache-control"], "no-store");

    // An OIDC access token, even for the platform audience, is not one.
    let access =
        crate::oidc::mint_access_token(&state, &uid.to_string(), "rp", None, None).unwrap();
    let (st, _, _) = post_token(&state, Some(&access), good_body()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Nor is a owner-KAS token: its content type fails `cwt::verify`.
    let (x, y) = authnz_rs::owner_kas_token::parse_cnf_key(&request_key()).unwrap();
    let lk = authnz_rs::owner_kas_token::mint(
        &OwnerKasToken {
            iss: state.issuer.to_string(),
            sub: uid.to_string(),
            route_id: ROUTE.into(),
            iat: Utc::now().timestamp(),
            exp: Utc::now().timestamp() + LIFETIME_SECONDS,
            cti: [1; 16],
            x,
            y,
            handle: "alice.arkavo.social".into(),
        },
        &state.cwt_signing_key,
        &state.cwt_kid,
    )
    .unwrap();
    let lk = authnz_rs::cwt::encode_for_header(&lk);
    let (st, _, _) = post_token(&state, Some(&lk), good_body()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_requests_are_400_before_any_account_read() {
    // No database here: a 400 must be decided before the account read.
    let state = build_test_app_state().await;
    let cwt = auth_cwt_aged(&state, Uuid::new_v4(), 0);
    let key = request_key();
    let cases = [
        (json!({ "route_id": ROUTE }), "invalid_request"),
        (json!("not an object"), "invalid_request"),
        (
            json!({ "route_id": ROUTE.to_lowercase(), "cnf_key": key }),
            "invalid_route_id",
        ),
        (
            json!({ "route_id": "81JC5Z8Q4M7N2P3R6S9T0V1W2X", "cnf_key": key }),
            "invalid_route_id",
        ),
        (
            json!({ "route_id": ROUTE, "cnf_key": format!("{key}=") }),
            "invalid_cnf_key",
        ),
        (
            json!({ "route_id": ROUTE, "cnf_key": URL_SAFE_NO_PAD.encode([4u8; 65]) }),
            "invalid_cnf_key",
        ),
    ];
    for (body, error) in cases {
        let (st, _, got) = post_token(&state, Some(&cwt), body.clone()).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(got, json!({ "error": error }), "{body}");
    }
}

#[tokio::test]
async fn mints_past_the_limit_are_429_with_retry_after() {
    let state = build_test_app_state().await;
    let uid = Uuid::new_v4();
    let now = Utc::now().timestamp();
    for _ in 0..OWNER_KAS_MINTS_PER_MINUTE {
        state.owner_kas_mints.admit(&uid, now).unwrap();
    }
    let cwt = auth_cwt_aged(&state, uid, 0);
    let (st, h, body) = post_token(&state, Some(&cwt), good_body()).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body, json!({ "error": "rate_limited" }));
    let retry: u64 = h["retry-after"].to_str().unwrap().parse().unwrap();
    assert!((1..=60).contains(&retry), "{retry}");
}

#[test]
fn the_limit_is_per_account_and_per_minute() {
    let limiter = MintLimiter::default();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    for _ in 0..OWNER_KAS_MINTS_PER_MINUTE {
        limiter.admit(&a, 1_000).unwrap();
    }
    assert_eq!(limiter.admit(&a, 1_010), Err(50));
    assert!(limiter.admit(&b, 1_010).is_ok());
    assert!(limiter.admit(&a, 1_060).is_ok());
}

#[tokio::test]
async fn a_live_account_gets_a_token_for_the_route_and_key() {
    let Some(store) = crate::db::tests::local_store() else {
        return;
    };
    let store = Arc::new(store);
    let state = build_test_app_state_with_store(store.clone());
    let name = format!("lk-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let user = store
        .create_user(&name, "did:key:z6Mkownerkas")
        .await
        .unwrap();
    let key = request_key();
    // A route this account owns (#148), with a fresh id: CI shares one
    // database across runs of the suite.
    let route: String = format!(
        "0{}",
        &Uuid::new_v4().simple().to_string().to_uppercase()[..25]
    );
    let bundle = json!({ "record": "AA", "credential": "AA", "assertion": {
        "credentialId": "AA", "authenticatorData": "AA", "clientDataJSON": "AA", "signature": "AA" } });
    store
        .put_owner_kas_route(&user.user_id, &route, 1, &bundle.to_string(), 1)
        .await
        .unwrap();

    let before = Utc::now().timestamp();
    let (st, h, body) = post_token(
        &state,
        Some(&auth_cwt_aged(&state, user.user_id, 0)),
        json!({ "route_id": route, "cnf_key": key }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(body["route"], bundle);

    let bytes = authnz_rs::cwt::decode_from_header(body["token"].as_str().unwrap()).unwrap();
    let t = authnz_rs::owner_kas_token::verify(&bytes, &state.cwt_keys, before, 60).unwrap();
    assert_eq!(t.iss, *state.issuer);
    assert_eq!(t.sub, user.user_id.to_string());
    assert_eq!(t.route_id, route);
    assert_eq!(t.exp - t.iat, LIFETIME_SECONDS);
    assert_eq!(body["expires_at"], json!(t.exp));
    assert_eq!(t.handle, format!("{name}.arkavo.social"));
    assert_eq!(
        authnz_rs::owner_kas_token::parse_cnf_key(&key),
        Some((t.x, t.y))
    );

    // Identity itself never accepts it.
    let opts = authnz_rs::cwt::VerifyOptions {
        expected_iss: None,
        expected_aud: None,
        now: before,
        skew_secs: 60,
    };
    assert!(matches!(
        authnz_rs::cwt::verify(&bytes, &state.cwt_keys, &opts),
        Err(CwtError::Malformed)
    ));
}

#[tokio::test]
async fn an_account_without_a_live_row_is_refused() {
    let Some(store) = crate::db::tests::local_store() else {
        return;
    };
    let state = build_test_app_state_with_store(Arc::new(store));
    let cwt = auth_cwt_aged(&state, Uuid::new_v4(), 0);
    let (st, _, body) = post_token(&state, Some(&cwt), good_body()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({ "error": "unauthorized" }));
}

/// `GET /oauth/userinfo` takes only an access token for a registered client:
/// a passkey auth CWT verified there before #146.
#[tokio::test]
async fn userinfo_takes_only_access_tokens() {
    let state = build_test_app_state().await;
    let mut oidc = (*crate::oidc::tests::test_oidc_config()).clone();
    oidc.clients.insert(
        "rp".into(),
        crate::oidc::OidcClient {
            client_id: "rp".into(),
            client_secret: None,
            redirect_uris: vec!["https://rp.example/cb".into()],
        },
    );
    let oidc = Arc::new(oidc);
    let call = |token: String| {
        let (state, oidc) = (state.clone(), oidc.clone());
        async move {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            );
            crate::oidc::userinfo(Extension(state), Extension(oidc), headers)
                .await
                .status()
        }
    };
    let sub = format!("arkavo:{}", Uuid::new_v4());
    let access = crate::oidc::mint_access_token(&state, &sub, "rp", None, None).unwrap();
    assert_eq!(call(access).await, StatusCode::OK);

    let unregistered = crate::oidc::mint_access_token(&state, &sub, "gone", None, None).unwrap();
    assert_eq!(call(unregistered).await, StatusCode::UNAUTHORIZED);

    let passkey = auth_cwt_aged(&state, Uuid::new_v4(), 0);
    assert_eq!(call(passkey).await, StatusCode::UNAUTHORIZED);
}
