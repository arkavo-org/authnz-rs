//! Resolution and update regressions for #132. Database cases use DynamoDB Local.
use super::*;
use crate::agent_plane_tests::Plane;
use axum::{Router, body::Body, http::Request, routing::get as route_get};
use serde_json::Value;
use tower::ServiceExt;

fn router(p: &Plane) -> Router {
    Router::new()
        .route("/dids/:id/did.json", route_get(well_known_did_json))
        .route("/dids/:id/did.jsonl", route_get(well_known_did_jsonl))
        .route("/handles/:label/did.json", route_get(handle_did_json))
        .layer(Extension(p.state.clone()))
}

async fn get(app: &Router, path: &str) -> (StatusCode, String, String) {
    let response = app
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_type = response.headers()[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .to_string();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        content_type,
        String::from_utf8(body.to_vec()).unwrap(),
    )
}

fn fixture(id: &str, handle: &str) -> (String, String) {
    let did = format!("did:webvh:QmTest:identity.arkavo.net:dids:{id}");
    let mut doc = build_did_document(
        &did,
        "zDnOld",
        &[format!("https://{handle}"), format!("at://{handle}")],
    );
    let first = json!({"state": doc}).to_string();
    doc["verificationMethod"][0]["publicKeyMultibase"] = json!("zDnLatest");
    doc["service"] = json!([{"id": format!("{did}#service"), "type": "test", "serviceEndpoint": "https://example.com"}]);
    (did, format!("{first}\n{}\n", json!({"state": doc})))
}

#[test]
fn parallel_web_view_uses_latest_state_and_preserves_external_references() {
    let (did, log) = fixture("alice", "alice.arkavo.social");
    let mut doc = latest_document(&log).unwrap();
    doc["controller"] = json!("did:key:external");
    doc["service"][0]["serviceEndpoint"] = json!(format!("https://example.com/{did}"));
    let view = web_document(doc, "alice");
    assert_eq!(view["id"], "did:web:identity.arkavo.net:dids:alice");
    assert_eq!(
        view["verificationMethod"][0]["publicKeyMultibase"],
        "zDnLatest"
    );
    assert_eq!(view["verificationMethod"][0]["controller"], view["id"]);
    assert_eq!(
        view["authentication"][0],
        "did:web:identity.arkavo.net:dids:alice#auth-key-0"
    );
    assert_eq!(
        view["service"][0]["id"],
        "did:web:identity.arkavo.net:dids:alice#service"
    );
    assert_eq!(
        view["service"][0]["serviceEndpoint"],
        format!("https://example.com/{did}")
    );
    assert_eq!(view["controller"], "did:key:external");
    assert!(latest_document("").is_err());
    assert!(latest_document(&format!("{log}not json")).is_err());
}

#[tokio::test]
async fn uuid_resolution_and_handle_alias_agree_and_deletion_removes_both() {
    let Some(p) = Plane::new().await else { return };
    let (uid, _) = p.user(&[]).await;
    let user = p.store.get_user_by_id(&uid).await.unwrap().unwrap();
    let (did, log) = fixture(&uid.to_string(), &user.handle);
    p.store.put_webvh_log(&uid, &log).await.unwrap();
    p.store.put_handle(&user.handle, &did, &uid).await.unwrap();
    let app = router(&p);
    let alias_path = format!("/handles/{}/did.json", user.username);
    let (status, ct, body) = get(&app, &alias_path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ct, "application/did+json");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({
            "@context": "https://www.w3.org/ns/did/v1",
            "id": format!("did:web:{}", user.handle), "alsoKnownAs": [did]
        })
    );
    let log_path = format!("/dids/{uid}/did.jsonl");
    assert_eq!(
        get(&app, &log_path).await,
        (StatusCode::OK, "text/jsonl".into(), log)
    );
    let (_, _, body) = get(&app, &format!("/dids/{uid}/did.json")).await;
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["verificationMethod"][0]["publicKeyMultibase"],
        "zDnLatest"
    );
    assert_eq!(
        get(&app, &format!("/dids/{}/did.jsonl", user.username))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    for label in [
        "unknown",
        "bad.name",
        "Alice",
        "-alice",
        "alice-",
        "alice:bad",
    ] {
        assert_eq!(
            get(&app, &format!("/handles/{label}/did.json")).await.0,
            StatusCode::NOT_FOUND
        );
    }
    // A stale/mismatched pointer must never produce an alias.
    p.store
        .put_handle(&user.handle, "did:key:wrong", &uid)
        .await
        .unwrap();
    assert_eq!(get(&app, &alias_path).await.0, StatusCode::NOT_FOUND);
    p.store.put_handle(&user.handle, &did, &uid).await.unwrap();
    p.store
        .tombstone_account(&uid, "test", Some(&user.handle), 1)
        .await
        .unwrap();
    assert_eq!(get(&app, &alias_path).await.0, StatusCode::NOT_FOUND);
    assert_eq!(get(&app, &log_path).await.0, StatusCode::NOT_FOUND);
    p.store
        .retire_handle_if_owned(&user.handle, &uid, 1)
        .await
        .unwrap();
    assert!(
        p.store
            .get_handle_owner(&user.handle)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn legacy_path_survives_username_change_and_cannot_follow_a_reassigned_name() {
    let Some(p) = Plane::new().await else { return };
    let (uid, _) = p.user(&[]).await;
    let user = p.store.get_user_by_id(&uid).await.unwrap().unwrap();
    let (did, log) = fixture(&user.username, &user.handle);
    p.store.put_webvh_log(&uid, &log).await.unwrap();
    p.store.put_handle(&user.handle, &did, &uid).await.unwrap();
    // Simulate a future rename at the storage layer. The handle remains fixed.
    let config = aws_sdk_dynamodb::config::Builder::new()
        .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
        .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
            "local", "local", None, None, "tests",
        ))
        .endpoint_url(std::env::var("AUTHNZ_TEST_DYNAMODB_ENDPOINT").unwrap())
        .build();
    aws_sdk_dynamodb::Client::from_conf(config)
        .update_item()
        .table_name("credentials")
        .key(
            "user_id",
            aws_sdk_dynamodb::types::AttributeValue::S(uid.to_string()),
        )
        .update_expression("SET username = :name REMOVE handle")
        .expression_attribute_values(
            ":name",
            aws_sdk_dynamodb::types::AttributeValue::S(format!("renamed-{uid}")),
        )
        .send()
        .await
        .unwrap();
    let app = router(&p);
    let path = format!("/dids/{}/did.jsonl", user.username);
    assert_eq!(get(&app, &path).await.2, log);
    assert_eq!(
        get(&app, &format!("/handles/{}/did.json", user.username))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        get(&app, &format!("/dids/renamed-{uid}/did.jsonl")).await.0,
        StatusCode::NOT_FOUND
    );
    p.store
        .tombstone_account(&uid, "test", Some(&user.handle), 1)
        .await
        .unwrap();
    p.store
        .retire_handle_if_owned(&user.handle, &uid, 1)
        .await
        .unwrap();
    // Even a low-level insert reusing the old username cannot take over its DID path.
    let replacement = p
        .store
        .create_user(&user.username, "did:key:new")
        .await
        .unwrap();
    let (_, other_log) = fixture(&user.username, &user.handle);
    p.store
        .put_webvh_log(&replacement.user_id, &other_log)
        .await
        .unwrap();
    assert_eq!(get(&app, &path).await.0, StatusCode::NOT_FOUND);
    assert!(
        p.store
            .put_handle(&user.handle, &did, &replacement.user_id)
            .await
            .is_err()
    );
}

#[cfg(feature = "webvh")]
fn signing_key() -> String {
    let (_, key) =
        didwebvh_rs::did_key::generate_did_key(didwebvh_rs::prelude::KeyType::Ed25519).unwrap();
    serde_json::to_string(&key).unwrap()
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn signed_binding_update_preserves_identity_and_history_and_is_idempotent() {
    use didwebvh_rs::prelude::*;
    let key = signing_key();
    let original = build_did_document("{DID}", "zDnTest", &["at://arkavo.arkavo.social".into()]);
    let (did, log) =
        log_emit::create_passport_log(&key, "https://identity.arkavo.net/dids/arkavo", original)
            .await
            .unwrap();
    let updated = log_emit::add_handle_binding(&key, &log, "arkavo.arkavo.social")
        .await
        .unwrap()
        .unwrap();
    assert!(updated.starts_with(&format!("{log}\n")));
    assert_eq!(updated.lines().count(), 2);
    let before = latest_document(&log).unwrap();
    let after = latest_document(&updated).unwrap();
    assert_eq!(before["id"], after["id"]);
    assert_eq!(before["verificationMethod"], after["verificationMethod"]);
    assert!(
        after["alsoKnownAs"]
            .as_array()
            .unwrap()
            .contains(&json!("https://arkavo.arkavo.social"))
    );
    for alias in before["alsoKnownAs"].as_array().unwrap() {
        assert!(after["alsoKnownAs"].as_array().unwrap().contains(alias));
    }
    DIDWebVHState::default()
        .resolve_log(&did, &updated, None)
        .await
        .unwrap();
    assert!(
        log_emit::add_handle_binding(&key, &updated, "arkavo.arkavo.social")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        log_emit::add_handle_binding(&signing_key(), &log, "arkavo.arkavo.social")
            .await
            .is_err()
    );
    let tampered = log.replace("zDnTest", "zDnTampered");
    assert!(
        log_emit::add_handle_binding(&key, &tampered, "arkavo.arkavo.social")
            .await
            .is_err()
    );
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn log_compare_and_swap_rejects_races_and_deleted_accounts() {
    let Some(p) = Plane::new().await else { return };
    let (uid, _) = p.user(&[]).await;
    let (a, b) = tokio::join!(
        p.store.compare_and_swap_webvh_log(&uid, None, "first-a"),
        p.store.compare_and_swap_webvh_log(&uid, None, "first-b")
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let original = p.store.get_webvh_log(&uid).await.unwrap().unwrap();
    p.store
        .compare_and_swap_webvh_log(&uid, Some(&original), "second")
        .await
        .unwrap();
    assert!(
        p.store
            .compare_and_swap_webvh_log(&uid, Some(&original), "lost-update")
            .await
            .is_err()
    );
    assert_eq!(
        p.store.get_webvh_log(&uid).await.unwrap().as_deref(),
        Some("second")
    );
    p.store
        .tombstone_account(&uid, "test", None, 1)
        .await
        .unwrap();
    assert!(
        p.store
            .compare_and_swap_webvh_log(&uid, None, "resurrected")
            .await
            .is_err()
    );
    assert!(
        p.store
            .compare_and_swap_webvh_log(&Uuid::new_v4(), None, "missing")
            .await
            .is_err()
    );
}

/// A sign-in skips the chain check only when the log already names both.
#[cfg(feature = "webvh")]
#[test]
fn a_binding_needs_both_aliases() {
    let h = "alice.arkavo.social";
    let doc = |aliases: Value| json!({ "id": "did:webvh:x", "alsoKnownAs": aliases });
    let both = doc(json!([
        "at://alice.arkavo.social",
        "https://alice.arkavo.social"
    ]));
    assert!(log_emit::has_handle_aliases(&both, h));
    assert!(!log_emit::has_handle_aliases(
        &doc(json!(["at://alice.arkavo.social"])),
        h
    ));
    assert!(!log_emit::has_handle_aliases(
        &doc(json!(["https://alice.arkavo.social"])),
        h
    ));
    let other = doc(json!([
        "at://bob.arkavo.social",
        "https://bob.arkavo.social"
    ]));
    assert!(!log_emit::has_handle_aliases(&other, h));
    assert!(!log_emit::has_handle_aliases(
        &doc(json!("https://alice.arkavo.social")),
        h
    ));
    assert!(!log_emit::has_handle_aliases(
        &json!({ "id": "did:webvh:x" }),
        h
    ));
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn refresh_backfills_once_and_repairs_missing_handle_publication() {
    let Some(mut p) = Plane::new().await else {
        return;
    };
    let (uid, _) = p.user(&[]).await;
    let user = p.store.get_user_by_id(&uid).await.unwrap().unwrap();
    let key = signing_key();
    let (did, log) = log_emit::create_passport_log(
        &key,
        &format!("https://identity.arkavo.net/dids/{uid}"),
        build_did_document("{DID}", "zDnTest", &[format!("at://{}", user.handle)]),
    )
    .await
    .unwrap();
    p.store.put_webvh_log(&uid, &log).await.unwrap();
    p.state.webvh_sign_key = std::sync::Arc::new(Some(key));
    refresh_handle_binding(&p.state, &uid, &user.handle).await;
    let updated = p.store.get_webvh_log(&uid).await.unwrap().unwrap();
    assert_eq!(updated.lines().count(), 2);
    assert_eq!(
        p.store.get_handle_owner(&user.handle).await.unwrap(),
        Some((uid, did))
    );
    refresh_handle_binding(&p.state, &uid, &user.handle).await;
    assert_eq!(p.store.get_webvh_log(&uid).await.unwrap().unwrap(), updated);
}

#[cfg(feature = "webvh")]
#[tokio::test]
async fn new_passport_uses_uuid_and_both_handle_bindings_without_reminting() {
    let name = crate::authentication_tests::unique_name();
    let Some(registered) = crate::authentication_tests::registered_account(&name).await else {
        return;
    };
    let store = registered.ceremony.store.clone();
    let user = store
        .get_user_by_id(&registered.user_id)
        .await
        .unwrap()
        .unwrap();
    let mut app = crate::test_helpers::build_test_app_state_with_store(store.clone());
    app.webvh_sign_key = std::sync::Arc::new(Some(signing_key()));
    on_passkey_registered(
        &app,
        &user.user_id,
        &user.username,
        &user.handle,
        &user.credentials[0],
    )
    .await;
    let log = store.get_webvh_log(&user.user_id).await.unwrap().unwrap();
    let doc = latest_document(&log).unwrap();
    assert_eq!(did_path(&doc), Some(user.user_id.to_string().as_str()));
    let aliases = doc["alsoKnownAs"].as_array().unwrap();
    assert!(aliases.contains(&json!(format!("https://{}", user.handle))));
    assert!(aliases.contains(&json!(format!("at://{}", user.handle))));
    on_passkey_registered(
        &app,
        &user.user_id,
        "changed-name",
        &user.handle,
        &user.credentials[0],
    )
    .await;
    assert_eq!(
        store.get_webvh_log(&user.user_id).await.unwrap().unwrap(),
        log
    );
}
