//! `POST /market/token` (#151) through the real handler. Refusals decided
//! before the account read need no database; the rest return early unless
//! `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set, as CI's `test` job sets it.

use super::*;
use crate::market::{MarketConfig, MarketSource};
use crate::test_helpers::{auth_cwt_aged, build_test_app_state, build_test_app_state_with_store};
use authnz_rs::cwt::CwtError;
use axum::Router;
use axum::body::Body;
use axum::http::Request;
use axum::routing::post;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const MARKET: &str = "https://market.example";

fn app_key() -> String {
    let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
    URL_SAFE_NO_PAD.encode(sk.verifying_key().to_encoded_point(false).as_bytes())
}

/// `state` with the market configured; its claim key is made here.
fn with_market(mut state: AppState) -> AppState {
    let key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let source = MarketSource::new(MarketConfig::for_tests(MARKET, &state.issuer, &key)).unwrap();
    state.market = Arc::new(Some(source));
    state
}

async fn post_token(
    state: &AppState,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, HeaderMap, Value) {
    let app = Router::new()
        .route("/market/token", post(token_handler))
        .layer(Extension(state.clone()));
    let mut req = Request::post("/market/token").header("content-type", "application/json");
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

#[tokio::test]
async fn unconfigured_is_503() {
    let state = build_test_app_state().await;
    let cwt = auth_cwt_aged(&state, Uuid::new_v4(), 0);
    let (st, h, body) = post_token(&state, Some(&cwt), json!({ "cnf_key": app_key() })).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({ "error": "market_unavailable" }));
    assert_eq!(h["cache-control"], "no-store");
}

#[tokio::test]
async fn only_a_passkey_auth_cwt_may_mint() {
    let state = with_market(build_test_app_state().await);
    let uid = Uuid::new_v4();
    let body = || json!({ "cnf_key": app_key() });

    let (st, h, got) = post_token(&state, None, body()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(got, json!({ "error": "unauthorized" }));
    assert_eq!(h["cache-control"], "no-store");

    // An OIDC access token is not one.
    let access =
        crate::oidc::mint_access_token(&state, &uid.to_string(), "rp", None, None).unwrap();
    let (st, _, _) = post_token(&state, Some(&access), body()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Nor is a market token: its content type fails `cwt::verify`, so one
    // can never be exchanged for another.
    let (x, y) = market_token::parse_cnf_key(&app_key()).unwrap();
    let now = Utc::now().timestamp();
    let own = market_token::mint(
        &MarketToken {
            iss: state.issuer.to_string(),
            account: uid.to_string(),
            aud: MARKET.into(),
            iat: now,
            exp: now + LIFETIME_SECONDS,
            cti: [1; 16],
            x,
            y,
        },
        &state.cwt_signing_key,
        &state.cwt_kid,
    )
    .unwrap();
    let own = authnz_rs::cwt::encode_for_header(&own);
    let (st, _, _) = post_token(&state, Some(&own), body()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_requests_are_400_before_any_account_read() {
    // No database here: a 400 must be decided before the account read.
    let state = with_market(build_test_app_state().await);
    let cwt = auth_cwt_aged(&state, Uuid::new_v4(), 0);
    let key = app_key();
    let cases = [
        (json!({}), "invalid_request"),
        (json!("not an object"), "invalid_request"),
        (
            json!({ "cnf_key": key, "audience": "https://elsewhere.example" }),
            "invalid_request",
        ),
        (json!({ "cnf_key": format!("{key}=") }), "invalid_cnf_key"),
        (
            json!({ "cnf_key": URL_SAFE_NO_PAD.encode([4u8; 65]) }),
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
    let state = with_market(build_test_app_state().await);
    let uid = Uuid::new_v4();
    let now = Utc::now().timestamp();
    for _ in 0..MARKET_TOKEN_MINTS_PER_MINUTE {
        state
            .market_token_mints
            .admit_within(&uid, now, MARKET_TOKEN_MINTS_PER_MINUTE)
            .unwrap();
    }
    let cwt = auth_cwt_aged(&state, uid, 0);
    let (st, h, body) = post_token(&state, Some(&cwt), json!({ "cnf_key": app_key() })).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body, json!({ "error": "rate_limited" }));
    let retry: u64 = h["retry-after"].to_str().unwrap().parse().unwrap();
    assert!((1..=60).contains(&retry), "{retry}");
    // The owner-KAS limiter is another count.
    assert!(state.owner_kas_mints.admit_within(&uid, now, 1).is_ok());
}

#[tokio::test]
async fn a_live_account_gets_a_token_for_the_market_and_key() {
    let Some(store) = crate::db::tests::local_store() else {
        return;
    };
    let store = Arc::new(store);
    let state = with_market(build_test_app_state_with_store(store.clone()));
    let name = format!("mt-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let user = store
        .create_user(&name, "did:key:z6Mkmarket")
        .await
        .unwrap();
    let key = app_key();

    let before = Utc::now().timestamp();
    let (st, h, body) = post_token(
        &state,
        Some(&auth_cwt_aged(&state, user.user_id, 0)),
        json!({ "cnf_key": key }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(body["audience"], json!(MARKET));

    let bytes = authnz_rs::cwt::decode_from_header(body["token"].as_str().unwrap()).unwrap();
    let t = market_token::verify(&bytes, &state.cwt_keys, MARKET, before, 60).unwrap();
    assert_eq!(t.iss, *state.issuer);
    assert_eq!(t.account, user.user_id.to_string());
    assert_eq!(t.exp - t.iat, LIFETIME_SECONDS);
    assert_eq!(body["expires_at"], json!(t.exp));
    assert_eq!(market_token::parse_cnf_key(&key), Some((t.x, t.y)));

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
    let state = with_market(build_test_app_state_with_store(Arc::new(store)));
    let cwt = auth_cwt_aged(&state, Uuid::new_v4(), 0);
    let (st, _, body) = post_token(&state, Some(&cwt), json!({ "cnf_key": app_key() })).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({ "error": "unauthorized" }));
}
