//! Owner-KAS routes at identity (#148): the owner's passkey-signed route
//! record and APNs push token, and the relay's service read of them.
//!
//! Identity owns account deletion, so the route lives here: deletion (and
//! the owner turning sharing off) retires it, and the relay learns that on
//! its next read. A route id is retired, never deleted, so it can never pass
//! to another account (`db::owner_kas`). Contract:
//! [docs/owner-kas-routes.md](../docs/owner-kas-routes.md).

// The helpers return the refusal itself, a `Response`, as their error.
#![allow(clippy::result_large_err)]

use crate::AppState;
use crate::db::{RouteWrite, UserCredentials};
use crate::owner_kas::refuse;
use authnz_rs::constants::{WEBAUTHN_RP_ID, WEBAUTHN_RP_ORIGIN};
use authnz_rs::owner_kas_route::{self, MAX_BUNDLE_BYTES, RouteBundle, RouteError};
use authnz_rs::owner_kas_token::is_route_id;
use axum::Extension;
use axum::body::Bytes;
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use log::{error, info, warn};
use serde::Deserialize;

const ERR_UNAUTHORIZED: &str = "unauthorized";
const ERR_FORBIDDEN: &str = "forbidden";
const ERR_INVALID_REQUEST: &str = "invalid_request";
const ERR_INVALID_ROUTE_ID: &str = "invalid_route_id";
const ERR_INVALID_RECORD: &str = "invalid_record";
const ERR_INVALID_ASSERTION: &str = "invalid_assertion";
const ERR_INVALID_PUSH: &str = "invalid_push";
const ERR_NOT_ROUTE_OWNER: &str = "not_route_owner";
const ERR_STALE_SEQ: &str = "stale_seq";
pub(crate) const ERR_UNKNOWN_ROUTE: &str = "unknown_route";
pub(crate) const ERR_ROUTE_RETIRED: &str = "route_retired";
const ERR_SERVER: &str = "server_error";

/// The only APNs environment accepted: the APNs key is production-only.
const APNS_ENVIRONMENT: &str = "production";

fn server_error(what: &str, e: impl std::fmt::Display) -> Response {
    error!("owner-KAS route: {what} failed: {e}");
    refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER)
}

fn no_content() -> Response {
    (
        StatusCode::NO_CONTENT,
        [(header::CACHE_CONTROL, "no-store")],
    )
        .into_response()
}

/// The owner: a passkey auth CWT (original or renewed) for a live account.
async fn owner(app_state: &AppState, headers: &HeaderMap) -> Result<UserCredentials, Response> {
    let user_id = match crate::agent::verify_passkey_auth_token(app_state, headers) {
        Ok((user_id, _)) => user_id,
        Err(e) => {
            warn!("audit owner_kas_route outcome=unauthorized reason={e}");
            return Err(refuse(StatusCode::UNAUTHORIZED, ERR_UNAUTHORIZED));
        }
    };
    // Tokens outlive the account (#88): the row is the authority.
    match app_state.db_store.get_user_by_id(&user_id).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(refuse(StatusCode::UNAUTHORIZED, ERR_UNAUTHORIZED)),
        Err(e) => Err(server_error("account lookup", e)),
    }
}

/// The relay: a service CWT whose client is on `OWNER_KAS_RELAY_CLIENT_IDS`.
fn relay(app_state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    use crate::entitlements::EntitlementError as E;
    match crate::entitlements::require_service_cwt_for(
        app_state,
        headers,
        &app_state.owner_kas_relay_client_ids,
    ) {
        Ok(_) => Ok(()),
        Err(E::MissingToken | E::InvalidToken) => {
            Err(refuse(StatusCode::UNAUTHORIZED, ERR_UNAUTHORIZED))
        }
        Err(_) => Err(refuse(StatusCode::FORBIDDEN, ERR_FORBIDDEN)),
    }
}

fn check_route_id(route_id: &str) -> Result<(), Response> {
    if is_route_id(route_id) {
        Ok(())
    } else {
        Err(refuse(StatusCode::BAD_REQUEST, ERR_INVALID_ROUTE_ID))
    }
}

/// A refused owner write, as its response.
fn write_refused(outcome: RouteWrite) -> Response {
    match outcome {
        RouteWrite::Unknown => refuse(StatusCode::NOT_FOUND, ERR_UNKNOWN_ROUTE),
        RouteWrite::NotOwner => refuse(StatusCode::FORBIDDEN, ERR_NOT_ROUTE_OWNER),
        RouteWrite::Retired => refuse(StatusCode::GONE, ERR_ROUTE_RETIRED),
        RouteWrite::StaleSeq => refuse(StatusCode::CONFLICT, ERR_STALE_SEQ),
        RouteWrite::Done => no_content(),
    }
}

macro_rules! try_response {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(response) => return response,
        }
    };
}

/// Check `bundle` against the owner `user` and the path's `route_id`:
/// the record, the passkey assertion over it, and identity's attestation of
/// that passkey. Returns the record's `seq`.
async fn verify_bundle(
    app_state: &AppState,
    user: &UserCredentials,
    route_id: &str,
    bundle: &RouteBundle,
) -> Result<u64, Response> {
    let bad = |code| refuse(StatusCode::BAD_REQUEST, code);
    let record_bytes =
        owner_kas_route::b64(&bundle.record).map_err(|_| bad(ERR_INVALID_REQUEST))?;
    let record = owner_kas_route::parse_record(&record_bytes).map_err(|e| {
        info!("owner-KAS route refused: {e:?}");
        bad(ERR_INVALID_RECORD)
    })?;
    if record.route_id != route_id || record.owner_sub != user.user_id.to_string() {
        return Err(bad(ERR_INVALID_RECORD));
    }

    let (credential_id, canonical) =
        crate::passkeys::decode_credential_id(&bundle.assertion.credential_id)
            .map_err(|_| bad(ERR_INVALID_REQUEST))?;
    let Some(passkey) = user
        .credentials
        .iter()
        .find(|p| p.cred_id().as_ref() == credential_id.as_slice())
    else {
        return Err(bad(ERR_INVALID_ASSERTION));
    };
    let (x, y) =
        crate::passkeys::p256_coordinates(passkey).map_err(|_| bad(ERR_INVALID_ASSERTION))?;
    owner_kas_route::verify_assertion(
        &record_bytes,
        &bundle.assertion,
        WEBAUTHN_RP_ID,
        WEBAUTHN_RP_ORIGIN,
        &x,
        &y,
    )
    .map_err(|e| match e {
        RouteError::Malformed => bad(ERR_INVALID_REQUEST),
        e => {
            info!("owner-KAS route refused: {e:?}");
            bad(ERR_INVALID_ASSERTION)
        }
    })?;

    // Identity's own attestation of the same passkey, for the same account:
    // the receiver verifies the chain with it, offline.
    let attestation_bytes =
        owner_kas_route::b64(&bundle.credential).map_err(|_| bad(ERR_INVALID_REQUEST))?;
    let attestation =
        authnz_rs::credential_attestation::verify(&attestation_bytes, &app_state.cwt_keys)
            .map_err(|_| bad(ERR_INVALID_ASSERTION))?;
    if attestation.iss != *app_state.issuer
        || attestation.sub != user.user_id.to_string()
        || attestation.credential_id != credential_id
        || (attestation.x, attestation.y) != (x, y)
        || attestation.rp_id != WEBAUTHN_RP_ID
    {
        return Err(bad(ERR_INVALID_ASSERTION));
    }
    match app_state
        .db_store
        .passkey_status(&canonical, &credential_id)
        .await
    {
        Ok(Some(status)) if status.user_id == user.user_id && !status.revoked => {}
        Ok(_) => return Err(bad(ERR_INVALID_ASSERTION)),
        Err(e) => return Err(server_error("passkey status", e)),
    }
    Ok(record.seq)
}

/// `PUT /owner-kas/routes/:route_id`: create or replace the owner's route
/// record. 200 `{route_id, seq}`; 400 `invalid_request` / `invalid_route_id`
/// / `invalid_record` / `invalid_assertion`; 401; 403 `not_route_owner`; 409
/// `stale_seq`; 410 `route_retired`.
pub(crate) async fn put_route(
    Extension(app_state): Extension<AppState>,
    Path(route_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = try_response!(owner(&app_state, &headers).await);
    try_response!(check_route_id(&route_id));
    if body.len() > MAX_BUNDLE_BYTES {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_REQUEST);
    }
    let Ok(bundle) = serde_json::from_slice::<RouteBundle>(&body) else {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_REQUEST);
    };
    let seq = try_response!(verify_bundle(&app_state, &user, &route_id, &bundle).await);
    let stored = match serde_json::to_string(&bundle) {
        Ok(s) => s,
        Err(e) => return server_error("bundle encoding", e),
    };

    let db = &app_state.db_store;
    let now = Utc::now().timestamp();
    let uid = user.user_id;
    match db
        .put_owner_kas_route(&uid, &route_id, seq, &stored, now)
        .await
    {
        Ok(RouteWrite::Done) => {}
        Ok(refused) => {
            info!("audit owner_kas_route outcome={refused:?} user_id={uid} route_id={route_id}");
            return write_refused(refused);
        }
        Err(e) => return server_error("route write", e),
    }
    // The account may have been deleted while this request ran: retire what
    // was just written, so it cannot outlive the account.
    match db.is_account_live(&uid).await {
        Ok(true) => {}
        Ok(false) => {
            if let Err(e) = db.retire_owner_kas_route(&uid, &route_id, now).await {
                error!("owner-KAS route of deleted {uid} not retired: {e}");
            }
            return refuse(StatusCode::UNAUTHORIZED, ERR_UNAUTHORIZED);
        }
        // Stored: the sweep retires it if the account is gone.
        Err(e) => warn!("owner-KAS route liveness re-check failed for {uid}: {e}"),
    }
    info!("audit owner_kas_route outcome=stored user_id={uid} route_id={route_id} seq={seq}");
    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({ "route_id": route_id, "seq": seq })),
    )
        .into_response()
}

/// `DELETE /owner-kas/routes/:route_id`: the owner turns sharing off. The
/// route is retired, never deleted. 204 (also when already retired); 401;
/// 403 `not_route_owner`; 404 `unknown_route`.
pub(crate) async fn delete_route(
    Extension(app_state): Extension<AppState>,
    Path(route_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let user = try_response!(owner(&app_state, &headers).await);
    try_response!(check_route_id(&route_id));
    let uid = user.user_id;
    match app_state
        .db_store
        .retire_owner_kas_route(&uid, &route_id, Utc::now().timestamp())
        .await
    {
        Ok(outcome) => {
            info!(
                "audit owner_kas_route outcome=retire:{outcome:?} user_id={uid} route_id={route_id}"
            );
            write_refused(outcome)
        }
        Err(e) => server_error("route retirement", e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PushRequest {
    apns_token: String,
    environment: String,
}

fn is_apns_token(t: &str) -> bool {
    (64..=200).contains(&t.len()) && t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `PUT /owner-kas/routes/:route_id/push` `{apns_token, environment}`: the
/// owner's APNs token for the relay's alert. 204; 400 `invalid_request` /
/// `invalid_route_id` / `invalid_push`; 401; 403; 404; 410.
pub(crate) async fn put_push(
    Extension(app_state): Extension<AppState>,
    Path(route_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = try_response!(owner(&app_state, &headers).await);
    try_response!(check_route_id(&route_id));
    let Ok(push) = serde_json::from_slice::<PushRequest>(&body) else {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_REQUEST);
    };
    if !is_apns_token(&push.apns_token) || push.environment != APNS_ENVIRONMENT {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_PUSH);
    }
    match app_state
        .db_store
        .set_owner_kas_push(
            &user.user_id,
            &route_id,
            Some((&push.apns_token, APNS_ENVIRONMENT)),
            Utc::now().timestamp(),
        )
        .await
    {
        Ok(outcome) => write_refused(outcome),
        Err(e) => server_error("push token write", e),
    }
}

/// `DELETE /owner-kas/routes/:route_id/push`: the owner removes the token.
pub(crate) async fn delete_push(
    Extension(app_state): Extension<AppState>,
    Path(route_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let user = try_response!(owner(&app_state, &headers).await);
    try_response!(check_route_id(&route_id));
    match app_state
        .db_store
        .set_owner_kas_push(&user.user_id, &route_id, None, Utc::now().timestamp())
        .await
    {
        Ok(outcome) => write_refused(outcome),
        Err(e) => server_error("push token removal", e),
    }
}

/// Whether a stored route is in service: not retired, and its owner live.
/// Until the deletion sweep retires a deleted owner's routes, this is what
/// makes the deletion take effect at once.
pub(crate) async fn in_service(
    app_state: &AppState,
    route: &crate::db::OwnerKasRoute,
) -> Result<bool, crate::db::DynamoDBError> {
    if route.retired_at.is_some() || route.bundle.is_none() {
        return Ok(false);
    }
    app_state.db_store.is_account_live(&route.user_id).await
}

/// `GET /owner-kas/routes/:route_id/relay` (the relay's service client):
/// 200 `{owner_sub, apns_token?, environment?}`; 404 `unknown_route`; 410
/// `route_retired` (retired, or the owner is not live); 401; 403.
pub(crate) async fn relay_read(
    Extension(app_state): Extension<AppState>,
    Path(route_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    try_response!(relay(&app_state, &headers));
    try_response!(check_route_id(&route_id));
    let route = match app_state.db_store.get_owner_kas_route(&route_id).await {
        Ok(Some(route)) => route,
        Ok(None) => return refuse(StatusCode::NOT_FOUND, ERR_UNKNOWN_ROUTE),
        Err(e) => return server_error("route read", e),
    };
    match in_service(&app_state, &route).await {
        Ok(true) => {}
        Ok(false) => return refuse(StatusCode::GONE, ERR_ROUTE_RETIRED),
        Err(e) => return server_error("route owner lookup", e),
    }
    let mut body = serde_json::json!({ "owner_sub": route.user_id.to_string() });
    if let (Some(token), Some(environment)) = (route.apns_token, route.apns_environment) {
        body["apns_token"] = token.into();
        body["environment"] = environment.into();
    }
    ([(header::CACHE_CONTROL, "no-store")], axum::Json(body)).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnregisteredPush {
    apns_token: String,
}

/// `DELETE /owner-kas/routes/:route_id/relay/push` `{apns_token}` (the
/// relay's service client): APNs reported the token unregistered. Removed
/// only if it is still the stored token. 204 whether or not it was.
pub(crate) async fn relay_delete_push(
    Extension(app_state): Extension<AppState>,
    Path(route_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    try_response!(relay(&app_state, &headers));
    try_response!(check_route_id(&route_id));
    let Ok(push) = serde_json::from_slice::<UnregisteredPush>(&body) else {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_REQUEST);
    };
    match app_state
        .db_store
        .clear_owner_kas_push_if(&route_id, &push.apns_token)
        .await
    {
        Ok(removed) => {
            info!(
                "audit owner_kas_push outcome=unregistered removed={removed} route_id={route_id}"
            );
            no_content()
        }
        Err(e) => server_error("push token removal", e),
    }
}

#[cfg(test)]
#[path = "owner_kas_routes_tests.rs"]
mod tests;
