//! Account deletion (#88) through the real handlers against DynamoDB Local.
//! Every test returns early unless `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set, as
//! CI's `test` job sets it.

use crate::agent_plane_tests::{Plane, READ, authorize_body, enroll_body, fresh_agent};
use crate::db::DeletionState;
use crate::device_check::DeviceBinding;
use crate::patreon::PatreonState;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::{delete, get};
use axum::{Extension, Router};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

fn patreon_off() -> PatreonState {
    PatreonState::new(
        None,
        None,
        fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None),
    )
}

/// The agent plane's routes plus the deletion endpoints.
fn router(p: &Plane) -> Router {
    crate::agent_plane_tests::router(p.state.clone()).merge(
        Router::new()
            .route("/account", delete(crate::account::delete_account))
            .route(
                "/account/deletions/:id",
                get(crate::account::get_deletion_status),
            )
            .layer(Extension(p.state.clone()))
            .layer(Extension(patreon_off())),
    )
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

async fn delete_account(app: &Router, token: &str) -> (StatusCode, Value) {
    send(
        app,
        Request::delete("/account")
            .header("X-Auth-Token", token)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

async fn status(app: &Router, id: &str) -> (StatusCode, Value) {
    send(
        app,
        Request::get(format!("/account/deletions/{id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

fn binding(device_id: &str, user_id: Uuid) -> DeviceBinding {
    DeviceBinding {
        device_id: device_id.to_string(),
        user_id,
        public_key: vec![4; 65],
        counter: 0,
        app_id: "app".into(),
        created_at: 1,
        updated_at: 1,
    }
}

/// The whole lifecycle: accept, refuse the account's tokens, sweep, complete.
#[tokio::test]
async fn deletion_removes_the_account_then_everything_bound_to_it() {
    let Some(p) = Plane::new().await else { return };
    let app = router(&p);
    let (uid, cwt) = p.user(&[READ]).await;
    let username = p
        .store
        .get_user_by_id(&uid)
        .await
        .unwrap()
        .unwrap()
        .username;
    let handle = format!("{username}.arkavo.social");
    let suffix = Uuid::new_v4().simple().to_string();

    // Bind things to the account in every other table.
    p.store
        .put_handle(&handle, "did:webvh:x", &uid)
        .await
        .unwrap();
    p.store
        .link_identity(uid, "apple", &format!("apple-{suffix}"))
        .await
        .unwrap();
    p.store
        .link_identity(uid, "google", &format!("google-{suffix}"))
        .await
        .unwrap();
    let device = format!("dev-{suffix}");
    p.store
        .create_device_binding(&binding(&device, uid))
        .await
        .unwrap();
    let agent = fresh_agent();
    let did = crate::agent_plane_tests::did_key(&agent);
    let (st, body) = p
        .authorize(("X-Auth-Token", &cwt), authorize_body(&agent, "", false))
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let gsk = fresh_agent();
    let (st, body) = p
        .post_json(
            "/guardians",
            ("X-Auth-Token", &cwt),
            enroll_body(uid, &gsk, "pager"),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let gid = body["guardian_id"].as_str().unwrap().to_string();

    // Accept.
    let (st, body) = delete_account(&app, &cwt).await;
    assert_eq!(st, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "pending");
    let id = body["deletion_id"].as_str().unwrap().to_string();
    assert_eq!(
        body["completes_by"].as_i64().unwrap() - body["requested_at"].as_i64().unwrap(),
        crate::constants::ACCOUNT_DELETION_COMPLETES_WITHIN_SECONDS
    );

    // The account is gone at once, and its name and handle are free.
    assert!(p.store.get_user_by_id(&uid).await.unwrap().is_none());
    assert!(p.store.get_user_by_name(&username).await.unwrap().is_none());
    assert_eq!(p.store.handle_owner(&handle).await, None);
    let row = p.store.raw_credentials_item(&uid).await.unwrap();
    for gone in [
        "username",
        "credentials",
        "did",
        "entitlements",
        "webvh_log",
    ] {
        assert!(!row.contains_key(gone), "tombstone still has {gone}");
    }

    // A retry reports the same deletion.
    let (st, again) = delete_account(&app, &cwt).await;
    assert_eq!(st, StatusCode::ACCEPTED, "{again}");
    assert_eq!(again["deletion_id"], id.as_str());
    let (st, s) = status(&app, &id).await;
    assert_eq!(st, StatusCode::OK, "{s}");
    assert_eq!(s["status"], "pending");

    // The account's still-unexpired token acts for nothing.
    let (st, _) = p
        .authorize(
            ("X-Auth-Token", &cwt),
            authorize_body(&fresh_agent(), "", false),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _) = p
        .post_json(
            "/guardians",
            ("X-Auth-Token", &cwt),
            enroll_body(uid, &fresh_agent(), "late"),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Sweep (the handler schedules it after the grace; run it now).
    crate::account::run_once(&p.store, &patreon_off(), &uid)
        .await
        .unwrap();
    assert_eq!(
        p.store
            .get_identity_link("apple", &format!("apple-{suffix}"))
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        p.store
            .get_identity_link("google", &format!("google-{suffix}"))
            .await
            .unwrap(),
        None
    );
    assert!(p.store.get_device_binding(&device).await.unwrap().is_none());
    assert!(p.store.get_patreon_link(uid).await.unwrap().is_none());
    let d = p.store.get_agent_delegation(&did).await.unwrap().unwrap();
    assert!(d.revoked_at.is_some(), "delegation not revoked");
    assert_eq!(d.name, "");
    assert_eq!(d.delegator_username, None);
    let g = p.store.get_guardian(&gid).await.unwrap().unwrap();
    assert!(g.revoked_at.is_some(), "guardian not revoked");
    assert_eq!(g.name, "");

    let (st, s) = status(&app, &id).await;
    assert_eq!(st, StatusCode::OK, "{s}");
    assert_eq!(s["status"], "completed");
    assert!(s["completed_at"].as_i64().is_some());
    let row = p.store.raw_credentials_item(&uid).await.unwrap();
    assert!(
        !row.contains_key("deletion_handle"),
        "username kept past completion"
    );

    // A second sweep is a no-op.
    crate::account::run_once(&p.store, &patreon_off(), &uid)
        .await
        .unwrap();
    assert_eq!(
        p.store
            .get_account_deletion(&uid)
            .await
            .unwrap()
            .unwrap()
            .state,
        DeletionState::Completed
    );
}

#[tokio::test]
async fn deletion_needs_a_fresh_passkey_auth_token() {
    let Some(p) = Plane::new().await else { return };
    let app = router(&p);
    let (uid, _) = p.user(&[]).await;

    let stale = crate::test_helpers::auth_cwt_aged(&p.state, uid, 301);
    let (st, body) = delete_account(&app, &stale).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{body}");

    let registration = crate::authn::mint_registration_token(
        &p.state,
        &uid,
        None,
        crate::cwt::cnf_from_ed25519(&[7u8; 32], b"kid"),
    )
    .unwrap();
    let (st, body) = delete_account(&app, &registration).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{body}");

    let (st, _) = send(
        &app,
        Request::delete("/account").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // An account that never existed.
    let ghost = crate::authn::mint_auth_token(&p.state, &Uuid::new_v4(), None, None).unwrap();
    let (st, body) = delete_account(&app, &ghost).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{body}");

    // None of that deleted anything.
    assert!(p.store.get_user_by_id(&uid).await.unwrap().is_some());
}

#[tokio::test]
async fn the_status_endpoint_needs_the_whole_id() {
    let Some(p) = Plane::new().await else { return };
    let app = router(&p);
    let (uid, cwt) = p.user(&[]).await;
    let (_, body) = delete_account(&app, &cwt).await;
    let id = body["deletion_id"].as_str().unwrap();

    let forged = format!("{uid}.{}", "0".repeat(32));
    for bad in [forged.as_str(), &uid.to_string(), "nonsense"] {
        let (st, _) = status(&app, bad).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{bad}");
    }
    let (st, _) = status(&app, id).await;
    assert_eq!(st, StatusCode::OK);
}

/// Nothing written after the tombstone lands on it or recreates the account.
#[tokio::test]
async fn writes_after_deletion_are_refused() {
    let Some(p) = Plane::new().await else { return };
    let app = router(&p);
    let (uid, cwt) = p.user(&[READ]).await;
    let (st, _) = delete_account(&app, &cwt).await;
    assert_eq!(st, StatusCode::ACCEPTED);

    assert!(p.store.put_webvh_log(&uid, "{}").await.is_err());
    assert!(p.store.put_user_entitlements(&uid, &[]).await.is_err());
    let sus = crate::db::PublishingSuspension {
        reason: "r".into(),
        report_id: None,
        suspended_by: "client:mod".into(),
        suspended_at: 1,
    };
    assert_eq!(
        p.store.set_publishing_suspension(&uid, &sus).await.unwrap(),
        crate::db::SuspensionSet::UserNotFound
    );
    assert_eq!(p.store.get_publishing_suspension(&uid).await.unwrap(), None);
    // A webvh log for a user that never existed is not an upsert either.
    assert!(p.store.put_webvh_log(&Uuid::new_v4(), "{}").await.is_err());

    let row = p.store.raw_credentials_item(&uid).await.unwrap();
    assert!(!row.contains_key("webvh_log"));
    assert!(!row.contains_key("entitlements"));
    assert!(!row.contains_key("publishing_suspension"));
}

/// The name is free immediately; a new owner's handle is not swept away.
#[tokio::test]
async fn a_deleted_username_can_be_registered_again() {
    let Some(p) = Plane::new().await else { return };
    let app = router(&p);
    let (uid, cwt) = p.user(&[]).await;
    let username = p
        .store
        .get_user_by_id(&uid)
        .await
        .unwrap()
        .unwrap()
        .username;
    let handle = format!("{username}.arkavo.social");
    p.store
        .put_handle(&handle, "did:webvh:old", &uid)
        .await
        .unwrap();
    let (st, _) = delete_account(&app, &cwt).await;
    assert_eq!(st, StatusCode::ACCEPTED);

    let newcomer = p
        .store
        .create_user(&username, "did:key:z6Mknewcomer")
        .await
        .unwrap();
    assert_ne!(newcomer.user_id, uid);
    assert_eq!(
        p.store
            .get_user_by_name(&username)
            .await
            .unwrap()
            .unwrap()
            .user_id,
        newcomer.user_id
    );
    p.store
        .put_handle(&handle, "did:webvh:new", &newcomer.user_id)
        .await
        .unwrap();

    crate::account::run_once(&p.store, &patreon_off(), &uid)
        .await
        .unwrap();
    assert_eq!(
        p.store.handle_owner(&handle).await,
        Some(newcomer.user_id.to_string())
    );
}

/// Every OIDC path that trusts a token refuses a deleted account's.
#[tokio::test]
async fn oidc_refuses_a_deleted_accounts_tokens() {
    let Some(p) = Plane::new().await else { return };
    let app = router(&p);
    let (uid, cwt) = p.user(&[READ]).await;
    let oidc = crate::oidc::tests::test_oidc_config();
    let access = crate::oidc::mint_access_token(
        &p.state,
        &format!("arkavo:{uid}"),
        "test-client",
        Some(crate::oidc::AccessTokenExtras {
            idp: "webauthn".into(),
            arkavo_user: Some(crate::cwt::ArkavoUserClaims {
                account_id: uid.to_string(),
                roles: vec!["user".into()],
                entitlements: vec![READ.into()],
                derived_entitlements: vec![],
                patreon: None,
            }),
            ..Default::default()
        }),
        None,
    )
    .unwrap();
    let userinfo = |token: String| {
        let (state, oidc) = (p.state.clone(), oidc.clone());
        async move {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            );
            crate::oidc::userinfo(Extension(state), Extension(oidc), headers)
                .await
                .status()
        }
    };

    assert!(
        crate::oidc::resolve_from_arkavo_jwt(&p.state, &oidc, &cwt)
            .await
            .is_ok()
    );
    assert_eq!(userinfo(access.clone()).await, StatusCode::OK);

    let (st, _) = delete_account(&app, &cwt).await;
    assert_eq!(st, StatusCode::ACCEPTED);

    assert!(
        crate::oidc::resolve_from_arkavo_jwt(&p.state, &oidc, &cwt)
            .await
            .is_err()
    );
    assert_eq!(userinfo(access).await, StatusCode::UNAUTHORIZED);
}
