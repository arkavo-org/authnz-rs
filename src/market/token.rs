//! `POST /market/token` (#151): the token an app presents to the market's
//! request API for the account signed in to it.
//!
//! Modelled on `POST /owner-kas/token`: the passkey auth CWT is exchanged for
//! a typed token for one audience (the market, `MARKET_ISSUER`), bound to a
//! key the app holds, for 900 s. The format is `authnz_rs::market_token`.
//! Identity keeps nothing: the mint is stateless.
//!
//! The app proves the key to the market on every request, not here. A stolen
//! auth CWT can therefore mint a market token for the thief's key; all that
//! buys is asking the market for a payment link in the account's name, which
//! someone still has to pay.

use crate::AppState;
use crate::owner_kas::refuse;
use authnz_rs::constants::MARKET_TOKEN_MINTS_PER_MINUTE;
use authnz_rs::market_token::{self, LIFETIME_SECONDS, MarketToken};
use axum::Extension;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use log::{error, info, warn};
use serde::Deserialize;
use uuid::Uuid;

const ERR_UNAUTHORIZED: &str = "unauthorized";
const ERR_INVALID_REQUEST: &str = "invalid_request";
const ERR_INVALID_CNF_KEY: &str = "invalid_cnf_key";
const ERR_RATE_LIMITED: &str = "rate_limited";
const ERR_UNAVAILABLE: &str = "market_unavailable";
const ERR_SERVER: &str = "server_error";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRequest {
    cnf_key: String,
}

/// `POST /market/token`, body `{"cnf_key"}`.
///
/// 503 `market_unavailable` while the market is not configured. Then the
/// passkey auth CWT in `X-Auth-Token` (original or renewed), for a live
/// account: 401 `unauthorized` otherwise. 400 `invalid_request` (not that
/// JSON object) or `invalid_cnf_key` (not an unpadded base64url P-256
/// point), decided before the account read; 429 `rate_limited` with
/// `Retry-After` past [`MARKET_TOKEN_MINTS_PER_MINUTE`]; 200
/// `{token, expires_at, audience}`.
pub(crate) async fn token_handler(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(market) = app_state.market.as_ref() else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, ERR_UNAVAILABLE);
    };
    let audience = market.config.issuer.clone();

    let user_id = match crate::agent::verify_passkey_auth_token(&app_state, &headers) {
        Ok((user_id, _)) => user_id,
        Err(e) => {
            warn!("audit market_token outcome=unauthorized reason={e}");
            return refuse(StatusCode::UNAUTHORIZED, ERR_UNAUTHORIZED);
        }
    };
    let Ok(request) = serde_json::from_slice::<TokenRequest>(&body) else {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_REQUEST);
    };
    let Some((x, y)) = market_token::parse_cnf_key(&request.cnf_key) else {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_CNF_KEY);
    };

    let now = Utc::now().timestamp();
    if let Err(retry_after) =
        app_state
            .market_token_mints
            .admit_within(&user_id, now, MARKET_TOKEN_MINTS_PER_MINUTE)
    {
        warn!("audit market_token outcome=rate_limited user_id={user_id}");
        let mut response = refuse(StatusCode::TOO_MANY_REQUESTS, ERR_RATE_LIMITED);
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, retry_after.into());
        return response;
    }

    // Tokens outlive the account (#88): the row is the authority.
    match app_state.db_store.is_account_live(&user_id).await {
        Ok(true) => {}
        Ok(false) => {
            warn!("audit market_token outcome=unauthorized reason=account_gone user_id={user_id}");
            return refuse(StatusCode::UNAUTHORIZED, ERR_UNAUTHORIZED);
        }
        Err(e) => {
            error!("market token: account lookup failed for {user_id}: {e}");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        }
    }

    let token = MarketToken {
        iss: app_state.issuer.to_string(),
        // The passkey auth CWT's `sub`: lowercase and hyphenated, as the
        // market requires of `arkavo_account_id`.
        account: user_id.to_string(),
        aud: audience,
        iat: now,
        exp: now + LIFETIME_SECONDS,
        cti: *Uuid::new_v4().as_bytes(),
        x,
        y,
    };
    let bytes = match market_token::mint(&token, &app_state.cwt_signing_key, &app_state.cwt_kid) {
        Ok(b) => b,
        Err(e) => {
            error!("Signing a market token failed: {e}");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        }
    };
    info!("audit market_token outcome=issued user_id={user_id}");
    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({
            "token": authnz_rs::cwt::encode_for_header(&bytes),
            "expires_at": token.exp,
            "audience": token.aud,
        })),
    )
        .into_response()
}

#[cfg(test)]
#[path = "token_tests.rs"]
mod tests;
