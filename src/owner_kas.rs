//! `POST /owner-kas/token` (#146): the token a receiver's request carries to
//! an owner's phone in arkavo-ios's owner KAS.
//!
//! The receiver's session token must never reach another user's device
//! (arkavo-ios ADR-0072), so identity mints a dedicated one: `aud`
//! `owner-kas:<route_id>`, `cnf` the receiver's per-attempt request key,
//! 900 s, and the receiver's handle so the owner can see who is asking. The
//! format is `authnz_rs::owner_kas_token`. Identity keeps nothing: the mint is
//! stateless and does not check that the route exists.

use crate::AppState;
use authnz_rs::owner_kas_token::{self, LIFETIME_SECONDS, OwnerKasToken};
use axum::Extension;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use log::{error, info, warn};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

use authnz_rs::constants::OWNER_KAS_MINTS_PER_MINUTE;

const ERR_UNAUTHORIZED: &str = "unauthorized";
const ERR_INVALID_REQUEST: &str = "invalid_request";
const ERR_INVALID_ROUTE_ID: &str = "invalid_route_id";
const ERR_INVALID_CNF_KEY: &str = "invalid_cnf_key";
const ERR_RATE_LIMITED: &str = "rate_limited";
const ERR_SERVER: &str = "server_error";

/// Mints per account in the current minute, in process. Only Open and "Try
/// again" mint on the app, so [`OWNER_KAS_MINTS_PER_MINUTE`] is ample; the
/// limit keeps one account from making identity sign without bound.
#[derive(Default)]
pub struct MintLimiter {
    windows: Mutex<HashMap<Uuid, (i64, u32)>>,
}

impl MintLimiter {
    /// Count a mint for `user_id` at `now`, or the seconds until it may
    /// mint again.
    fn admit(&self, user_id: &Uuid, now: i64) -> Result<(), u64> {
        self.admit_within(user_id, now, OWNER_KAS_MINTS_PER_MINUTE)
    }

    /// The same count against `limit` mints a minute, for another token's
    /// own limiter (`POST /market/token`).
    pub(crate) fn admit_within(&self, user_id: &Uuid, now: i64, limit: u32) -> Result<(), u64> {
        const WINDOW: i64 = 60;
        let mut map = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, (start, _)| now - *start < WINDOW);
        let (start, count) = map.entry(*user_id).or_insert((now, 0));
        if *count >= limit {
            return Err((*start + WINDOW - now).max(1) as u64);
        }
        *count += 1;
        Ok(())
    }
}

#[derive(Deserialize)]
struct TokenRequest {
    route_id: String,
    cnf_key: String,
}

pub(crate) fn refuse(status: StatusCode, error: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({ "error": error })),
    )
        .into_response()
}

/// `POST /owner-kas/token`, body `{"route_id", "cnf_key"}`.
///
/// The receiver's passkey auth CWT in `X-Auth-Token` (original or renewed),
/// for a live account: 401 `unauthorized` otherwise. Then 400
/// `invalid_request` (not that JSON object), `invalid_route_id` (not a
/// canonical ULID) or `invalid_cnf_key` (not an unpadded base64url P-256
/// point); 429 `rate_limited` with `Retry-After` past
/// [`OWNER_KAS_MINTS_PER_MINUTE`]; 404 `unknown_route` (never registered)
/// or 410 `route_retired` (turned off, or its owner is not live; #148); 200
/// `{token, expires_at, route}`, `route` the bundle as the owner put it.
pub(crate) async fn token_handler(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user_id = match crate::agent::verify_passkey_auth_token(&app_state, &headers) {
        Ok((user_id, _)) => user_id,
        Err(e) => {
            warn!("audit owner_kas_token outcome=unauthorized reason={e}");
            return refuse(StatusCode::UNAUTHORIZED, ERR_UNAUTHORIZED);
        }
    };
    let Ok(request) = serde_json::from_slice::<TokenRequest>(&body) else {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_REQUEST);
    };
    if !owner_kas_token::is_route_id(&request.route_id) {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_ROUTE_ID);
    }
    let Some((x, y)) = owner_kas_token::parse_cnf_key(&request.cnf_key) else {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_CNF_KEY);
    };

    let now = Utc::now().timestamp();
    if let Err(retry_after) = app_state.owner_kas_mints.admit(&user_id, now) {
        warn!("audit owner_kas_token outcome=rate_limited user_id={user_id}");
        let mut response = refuse(StatusCode::TOO_MANY_REQUESTS, ERR_RATE_LIMITED);
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, retry_after.into());
        return response;
    }

    // Tokens outlive the account (#88): the row is the authority, and it
    // holds the handle.
    let user = match app_state.db_store.get_user_by_id(&user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            warn!(
                "audit owner_kas_token outcome=unauthorized reason=account_gone user_id={user_id}"
            );
            return refuse(StatusCode::UNAUTHORIZED, ERR_UNAUTHORIZED);
        }
        Err(e) => {
            error!("owner-KAS token: account lookup failed for {user_id}: {e}");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        }
    };

    // The route the token is for, from the same read the receiver gets its
    // bundle from (#148).
    let route = match app_state
        .db_store
        .get_owner_kas_route(&request.route_id)
        .await
    {
        Ok(Some(route)) => route,
        Ok(None) => {
            return refuse(
                StatusCode::NOT_FOUND,
                crate::owner_kas_routes::ERR_UNKNOWN_ROUTE,
            );
        }
        Err(e) => {
            error!("owner-KAS token: route read failed: {e}");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        }
    };
    match crate::owner_kas_routes::in_service(&app_state, &route).await {
        Ok(true) => {}
        Ok(false) => {
            return refuse(StatusCode::GONE, crate::owner_kas_routes::ERR_ROUTE_RETIRED);
        }
        Err(e) => {
            error!("owner-KAS token: route owner lookup failed: {e}");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        }
    }
    let bundle = match route
        .bundle
        .as_deref()
        .map(serde_json::from_str::<serde_json::Value>)
    {
        Some(Ok(bundle)) => bundle,
        _ => {
            error!(
                "owner-KAS token: route {} has an unreadable bundle",
                request.route_id
            );
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        }
    };

    let token = OwnerKasToken {
        iss: app_state.issuer.to_string(),
        // Exactly the passkey auth CWT's `sub` (authn::mint_auth_token).
        sub: user_id.to_string(),
        route_id: request.route_id,
        iat: now,
        exp: now + LIFETIME_SECONDS,
        cti: *Uuid::new_v4().as_bytes(),
        x,
        y,
        handle: user.handle.to_lowercase(),
    };
    let bytes = match owner_kas_token::mint(&token, &app_state.cwt_signing_key, &app_state.cwt_kid)
    {
        Ok(b) => b,
        Err(e) => {
            error!("Signing an owner-KAS token failed: {e}");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        }
    };
    // The route id is routing data the relay sees too; the token is not
    // logged.
    info!(
        "audit owner_kas_token outcome=issued user_id={user_id} route_id={}",
        token.route_id
    );
    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({
            "token": authnz_rs::cwt::encode_for_header(&bytes),
            "expires_at": token.exp,
            "route": bundle,
        })),
    )
        .into_response()
}

#[cfg(test)]
#[path = "owner_kas_tests.rs"]
mod tests;
