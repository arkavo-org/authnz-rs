//! Passkey sign-in, end to end: `GET /authenticate` and `POST /authenticate`.
//!
//! Each test registers an account through the ticketed ceremony in
//! `registration_gate_tests`, with a software passkey, and then signs in on
//! the same session. They run against DynamoDB Local and return early unless
//! `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set, as CI's `test` job sets it.

use crate::registration_gate_tests::Ceremony;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use uuid::Uuid;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{Base64UrlSafeData, PublicKeyCredential, RequestChallengeResponse, Url};

/// The origin the test `Webauthn` is built for.
const ORIGIN: &str = "https://identity.arkavo.net";

/// A registered account, with the session that registered it and the
/// software passkey that holds its credential.
pub(crate) struct Registered {
    pub(crate) ceremony: Ceremony,
    auth: WebauthnAuthenticator<SoftPasskey>,
    pub(crate) user_id: Uuid,
    pub(crate) cred: Base64UrlSafeData,
    /// The `X-Auth-Token` its `POST /register` answered with.
    pub(crate) token: String,
}

/// A username no other run has used.
pub(crate) fn unique_name() -> String {
    format!("signin-{}", &Uuid::new_v4().simple().to_string()[..12])
}

/// Register `username` through the ticketed ceremony, or `None` without
/// DynamoDB Local.
pub(crate) async fn registered_account(username: &str) -> Option<Registered> {
    let mut ceremony = Ceremony::begin().await?;
    ceremony.username = username.to_string();
    let mut auth = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let registration = auth
        .do_registration(Url::parse(ORIGIN).unwrap(), ceremony.options().await)
        .expect("the soft authenticator must produce a registration");

    let response = ceremony.finish(&registration).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "registration must succeed"
    );
    let token = response
        .headers()
        .get("x-auth-token")
        .expect("registration answers with an account token")
        .to_str()
        .unwrap()
        .to_string();
    let user_id = ceremony
        .store
        .get_user_by_name(username)
        .await
        .unwrap()
        .expect("the registered account exists")
        .user_id;

    Some(Registered {
        ceremony,
        auth,
        user_id,
        cred: registration.raw_id,
        token,
    })
}

/// Answer `options` as a discoverable credential would.
///
/// `SoftPasskey` cannot answer an empty allow-list and never returns a user
/// handle. So this lists the one credential, signs, and then sets the user
/// handle. WebAuthn does not sign the user handle, so the result is the
/// assertion a platform passkey would send.
fn answer_discoverable(
    auth: &mut WebauthnAuthenticator<SoftPasskey>,
    mut options: RequestChallengeResponse,
    credential_id: &Base64UrlSafeData,
    user_handle: Option<Uuid>,
) -> PublicKeyCredential {
    // `AllowCredentials` is not re-exported by either webauthn crate.
    options.public_key.allow_credentials =
        serde_json::from_value(serde_json::json!([{ "type": "public-key", "id": credential_id }]))
            .unwrap();
    options.mediation = None;
    let mut assertion = auth
        .do_authentication(Url::parse(ORIGIN).unwrap(), options)
        .expect("the soft authenticator must sign the assertion");
    assertion.response.user_handle =
        user_handle.map(|id| Base64UrlSafeData::from(id.as_bytes().to_vec()));
    assertion
}

/// `GET {uri}` on `c`'s session, with `token` as `X-Auth-Token`: the status
/// and the body.
async fn start_raw(c: &Ceremony, uri: &str, token: Option<&str>) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder().uri(uri);
    if let Some(token) = token {
        request = request.header("X-Auth-Token", token);
    }
    let response = c.send(request, Body::empty()).await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, body.to_vec())
}

/// `GET /authenticate` on `c`'s session, with `token` as `X-Auth-Token`.
async fn start(c: &Ceremony, token: Option<&str>) -> RequestChallengeResponse {
    start_for(c, "/authenticate", token).await
}

/// `GET {uri}` on `c`'s session, which must start a ceremony.
async fn start_for(c: &Ceremony, uri: &str, token: Option<&str>) -> RequestChallengeResponse {
    let (status, body) = start_raw(c, uri, token).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "GET /authenticate must start a ceremony"
    );
    serde_json::from_slice(&body).expect("GET /authenticate returns WebAuthn request options")
}

/// `POST /authenticate` on `c`'s session: the status and the body.
async fn finish(c: &Ceremony, assertion: &PublicKeyCredential) -> (StatusCode, String) {
    let response = c
        .send(
            Request::builder()
                .method("POST")
                .uri("/authenticate")
                .header("content-type", "application/json"),
            Body::from(serde_json::to_vec(assertion).unwrap()),
        )
        .await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

/// The claims of an auth token the test server minted.
fn verified_claims(c: &Ceremony, token: &str) -> crate::cwt::ArkavoClaims {
    // The test AppState signs with a fixed key, so a fresh one verifies.
    let state = crate::test_helpers::build_test_app_state_with_store(c.store.clone());
    crate::cwt::verify(
        &crate::cwt::decode_from_header(token).expect("the token is base64url"),
        &state.cwt_verifying_key,
        &crate::cwt::VerifyOptions {
            expected_iss: Some(&state.issuer),
            expected_aud: Some("arkavo"),
            now: chrono::Utc::now().timestamp(),
            skew_secs: crate::cwt::DEFAULT_SKEW_SECS,
        },
    )
    .expect("the auth token must verify")
}

/// Tombstone `user_id`, as `DELETE /account` does (the sweep is not run).
async fn tombstone(c: &Ceremony, user_id: &Uuid) {
    c.store
        .tombstone_account(user_id, &format!("{user_id}.{}", "a".repeat(32)), None, 1)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_name_free_sign_in_returns_the_token_and_the_handle() {
    let Some(Registered {
        ceremony: c,
        mut auth,
        user_id,
        cred,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };

    let options = start(&c, None).await;
    assert!(
        options.public_key.allow_credentials.is_empty(),
        "a name-free start lists no credentials, so the sheet offers every passkey"
    );

    let (status, body) = finish(
        &c,
        &answer_discoverable(&mut auth, options, &cred, Some(user_id)),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let reply: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        reply.as_object().map(|o| o.len()),
        Some(2),
        "the reply is exactly {{token, handle}}"
    );
    assert_eq!(reply["handle"], c.username.as_str());
    let token = reply["token"].as_str().expect("the reply carries a token");
    assert_eq!(verified_claims(&c, token).sub, user_id.to_string());
}

#[tokio::test]
async fn a_passkey_of_a_deleted_account_is_an_unknown_passkey() {
    let Some(Registered {
        ceremony: c,
        mut auth,
        user_id,
        cred,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    let options = start(&c, None).await;
    tombstone(&c, &user_id).await;

    let (status, body) = finish(
        &c,
        &answer_discoverable(&mut auth, options, &cred, Some(user_id)),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, "Unknown Passkey");
}

#[tokio::test]
async fn a_credential_missing_from_the_account_is_an_unknown_passkey() {
    let Some(Registered {
        ceremony: c,
        user_id,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    let Some(Registered {
        auth: mut other_auth,
        cred: other_cred,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    let options = start(&c, None).await;

    // The right user handle, but a credential the account does not hold.
    let assertion = answer_discoverable(&mut other_auth, options, &other_cred, Some(user_id));
    let (status, body) = finish(&c, &assertion).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, "Unknown Passkey");
}

#[tokio::test]
async fn a_missing_user_handle_fails_the_ceremony() {
    let Some(Registered {
        ceremony: c,
        mut auth,
        cred,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    let options = start(&c, None).await;

    let (status, body) = finish(&c, &answer_discoverable(&mut auth, options, &cred, None)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, r#"{"token":""}"#);
}

#[tokio::test]
async fn an_inbound_token_for_another_account_is_refused_at_finish() {
    let Some(Registered {
        ceremony: c,
        token: a_token,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    let Some(Registered {
        auth: mut b_auth,
        user_id: b_id,
        cred: b_cred,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    let options = start(&c, Some(&a_token)).await;

    let (status, body) = finish(
        &c,
        &answer_discoverable(&mut b_auth, options, &b_cred, Some(b_id)),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "Passkey belongs to another account");
}

#[tokio::test]
async fn a_replayed_finish_mints_nothing() {
    let Some(Registered {
        ceremony: c,
        mut auth,
        user_id,
        cred,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    let options = start(&c, None).await;
    let assertion = answer_discoverable(&mut auth, options, &cred, Some(user_id));
    assert_eq!(finish(&c, &assertion).await.0, StatusCode::OK);

    let (status, body) = finish(&c, &assertion).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, "Corrupt Session");
}

#[tokio::test]
async fn a_forged_assertion_mints_nothing() {
    let Some(Registered {
        ceremony: c,
        mut auth,
        user_id,
        cred,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    // The second start replaces the first, so the session holds a challenge
    // the assertion below did not sign. Only the signature check catches it:
    // the user handle and the credential are the account's own.
    let first = start(&c, None).await;
    let _second = start(&c, None).await;

    let (status, body) = finish(
        &c,
        &answer_discoverable(&mut auth, first, &cred, Some(user_id)),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, r#"{"token":""}"#);
}

/// `GET /authenticate?account=<id>`.
fn scoped(account: &Uuid) -> String {
    format!("/authenticate?account={account}")
}

#[tokio::test]
async fn an_account_scoped_start_lists_only_that_accounts_passkeys() {
    let Some(Registered {
        ceremony: c,
        mut auth,
        user_id,
        cred,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    // A second account, so a bug that lists every credential shows.
    let Some(_other) = registered_account(&unique_name()).await else {
        return;
    };

    let options = start_for(&c, &scoped(&user_id), None).await;

    let listed: Vec<_> = options
        .public_key
        .allow_credentials
        .iter()
        .map(|allowed| allowed.id.clone())
        .collect();
    assert_eq!(listed, vec![cred.clone()], "only the account's own passkey");

    let (status, body) = finish(
        &c,
        &answer_discoverable(&mut auth, options, &cred, Some(user_id)),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let reply: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(reply["handle"], c.username.as_str());
    let token = reply["token"].as_str().expect("the reply carries a token");
    assert_eq!(verified_claims(&c, token).sub, user_id.to_string());
}

#[tokio::test]
async fn an_account_scoped_start_refuses_another_accounts_passkey() {
    let Some(Registered {
        ceremony: c,
        user_id: a_id,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    let Some(Registered {
        auth: mut b_auth,
        user_id: b_id,
        cred: b_cred,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    let options = start_for(&c, &scoped(&a_id), None).await;

    let (status, body) = finish(
        &c,
        &answer_discoverable(&mut b_auth, options, &b_cred, Some(b_id)),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, r#"{"token":""}"#);
}

#[tokio::test]
async fn an_account_scoped_start_for_a_deleted_account_is_user_not_found() {
    let Some(Registered {
        ceremony: c,
        user_id,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    tombstone(&c, &user_id).await;

    let (status, body) = start_raw(&c, &scoped(&user_id), None).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, b"User Not Found");
}

#[tokio::test]
async fn an_inbound_token_for_another_account_is_refused_at_an_account_scoped_start() {
    let Some(Registered {
        ceremony: c,
        user_id: a_id,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    let Some(Registered { token: b_token, .. }) = registered_account(&unique_name()).await else {
        return;
    };

    let (status, body) = start_raw(&c, &scoped(&a_id), Some(&b_token)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, b"User Not Found");
}

#[tokio::test]
async fn a_forged_assertion_at_an_account_scoped_start_mints_nothing() {
    let Some(Registered {
        ceremony: c,
        mut auth,
        user_id,
        cred,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    // As in the name-free case: the session holds the second challenge, and
    // the assertion signed the first.
    let first = start_for(&c, &scoped(&user_id), None).await;
    let _second = start_for(&c, &scoped(&user_id), None).await;

    let (status, body) = finish(
        &c,
        &answer_discoverable(&mut auth, first, &cred, Some(user_id)),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, r#"{"token":""}"#);
}

#[tokio::test]
async fn an_account_scoped_finish_refuses_a_mismatching_user_handle() {
    let Some(Registered {
        ceremony: c,
        mut auth,
        user_id: a_id,
        cred: a_cred,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    let Some(Registered { user_id: b_id, .. }) = registered_account(&unique_name()).await else {
        return;
    };
    let options = start_for(&c, &scoped(&a_id), None).await;

    // A's own credential, so its signature verifies; WebAuthn does not sign
    // the user handle, so only the server's own check refuses B's.
    let (status, body) = finish(
        &c,
        &answer_discoverable(&mut auth, options, &a_cred, Some(b_id)),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, r#"{"token":""}"#);
}

#[tokio::test]
async fn an_account_scoped_finish_accepts_an_absent_user_handle() {
    let Some(Registered {
        ceremony: c,
        mut auth,
        user_id,
        cred,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    let options = start_for(&c, &scoped(&user_id), None).await;

    // A user handle is optional when the start named the account.
    let (status, body) = finish(&c, &answer_discoverable(&mut auth, options, &cred, None)).await;

    assert_eq!(status, StatusCode::OK);
    let reply: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(reply["handle"], c.username.as_str());
    let token = reply["token"].as_str().expect("the reply carries a token");
    assert_eq!(verified_claims(&c, token).sub, user_id.to_string());
}

#[tokio::test]
async fn an_account_scoped_start_refuses_another_accounts_credential_without_a_handle() {
    let Some(Registered {
        ceremony: c,
        user_id: a_id,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    let Some(Registered {
        auth: mut b_auth,
        cred: b_cred,
        ..
    }) = registered_account(&unique_name()).await
    else {
        return;
    };
    let options = start_for(&c, &scoped(&a_id), None).await;

    // No user handle, so the handle check passes and only the start's list of
    // A's credentials refuses B's.
    let (status, body) = finish(
        &c,
        &answer_discoverable(&mut b_auth, options, &b_cred, None),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, r#"{"token":""}"#);
}
