//! `POST /game/token` (#151): the token an app presents to a game server.
//!
//! Authenticated by the passkey session, not by a token: the caller proves
//! it holds the session's device key, and the token's `cnf` is that key as
//! identity stored it when the session opened. So a stolen auth CWT cannot
//! mint a game token, and a game token is useless without the device. The
//! format is `authnz_rs::game_token`; the contract is `docs/game-token.md`.
//!
//! The mint reads the session and never writes it: it is not a renewal, it
//! rotates nothing, and a 401 here never ends a session.
//!
//! **Game sessions.** A passkey session goes idle in about an hour and ends
//! in a day, which would put a passkey prompt before most play. So a live
//! passkey session can open a *game session* (`POST /game/session`): the
//! same account and device key, good for [`GAME_SESSION_SECONDS`] after the
//! passkey assertion, with no idle limit, and accepted by nothing but this
//! mint. `POST /game/session/end` and `POST /session/signout` end it; so
//! does the account's deletion.

use crate::AppState;
use crate::owner_kas::refuse;
use authnz_rs::constants::{
    ENTITLEMENT_ONLINE_PLAY, GAME_SESSION_SECONDS, GAME_TOKEN_MINTS_PER_MINUTE,
    GAME_TOKEN_PROOF_SKEW_SECONDS, SESSION_IDLE_LIMIT_SECONDS, SESSION_MAX_SECONDS,
};
use authnz_rs::game_token::{self, GameToken};
use axum::Extension;
use axum::body::Bytes;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use log::{error, info, warn};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

const ERR_UNAVAILABLE: &str = "game_tokens_unavailable";
const ERR_UNAUTHORIZED: &str = "unauthorized";
/// The game session is past its deadline. Answered only to a caller whose
/// proof verified.
const ERR_GAME_SESSION_ENDED: &str = "game_session_ended";
const ERR_INVALID_REQUEST: &str = "invalid_request";
const ERR_INVALID_AUDIENCE: &str = "invalid_audience";
const ERR_INVALID_ISSUED_AT: &str = "invalid_issued_at";
const ERR_RATE_LIMITED: &str = "rate_limited";
const ERR_SERVER: &str = "server_error";

/// Default and bounds of `GAME_TOKEN_SECONDS`.
const DEFAULT_LIFETIME_SECONDS: i64 = 900;
const MIN_LIFETIME_SECONDS: i64 = 60;

/// Game-server tokens: `GAME_TOKEN_AUDIENCES` and `GAME_TOKEN_SECONDS`, and
/// the per-account mint count.
#[derive(Debug, Default)]
pub struct GameTokens {
    /// The audiences a token may be minted for. Empty: the feature is off.
    pub audiences: Vec<String>,
    pub lifetime_seconds: i64,
    /// Mints per account in the current minute: (window start, count).
    mints: Mutex<HashMap<Uuid, (i64, u32)>>,
}

impl GameTokens {
    /// Parse the two values. An audience that is not shaped like one, or
    /// that another kind of token already carries, is an error: startup
    /// fails rather than mint a game token some other verifier would take.
    ///
    /// `taken` are the audiences of identity's other tokens: the passkey
    /// audience, the platform audience and the agent token audiences. OIDC
    /// client ids are checked once they are known
    /// ([`Self::refuse_client_ids`]).
    pub fn parse(
        audiences: Option<&str>,
        seconds: Option<&str>,
        taken: &[&str],
    ) -> Result<Self, String> {
        let audiences: Vec<String> = audiences
            .unwrap_or_default()
            .split(',')
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect();
        for aud in &audiences {
            if !game_token::is_audience(aud) {
                return Err(format!(
                    "GAME_TOKEN_AUDIENCES lists \"{aud}\": an audience is 1 to {} printable \
                     ASCII characters with no space",
                    game_token::MAX_AUDIENCE_LEN
                ));
            }
            let lower = aud.to_ascii_lowercase();
            if lower.starts_with("arkavo:") || lower.starts_with("owner-kas:") {
                return Err(format!(
                    "GAME_TOKEN_AUDIENCES lists \"{aud}\": that prefix belongs to another \
                     kind of token"
                ));
            }
            if conflicts(aud, taken.iter().copied()) {
                return Err(format!(
                    "GAME_TOKEN_AUDIENCES lists \"{aud}\", an audience another token carries; \
                     a game token must never pass for one"
                ));
            }
        }
        let lifetime_seconds = match seconds.map(str::trim).filter(|s| !s.is_empty()) {
            None => DEFAULT_LIFETIME_SECONDS,
            Some(raw) => {
                let value: i64 = raw
                    .parse()
                    .map_err(|_| format!("GAME_TOKEN_SECONDS is not an integer: {raw}"))?;
                if !(MIN_LIFETIME_SECONDS..=game_token::MAX_LIFETIME_SECONDS).contains(&value) {
                    return Err(format!(
                        "GAME_TOKEN_SECONDS must be {MIN_LIFETIME_SECONDS} to {} seconds, got \
                         {value}",
                        game_token::MAX_LIFETIME_SECONDS
                    ));
                }
                value
            }
        };
        Ok(Self {
            audiences,
            lifetime_seconds,
            mints: Mutex::default(),
        })
    }

    /// Refuse an audience that is an OIDC client id: every access token for
    /// that client carries it.
    pub fn refuse_client_ids<'a>(
        &self,
        client_ids: impl Iterator<Item = &'a str> + Clone,
    ) -> Result<(), String> {
        match self
            .audiences
            .iter()
            .find(|aud| conflicts(aud, client_ids.clone()))
        {
            Some(aud) => Err(format!(
                "GAME_TOKEN_AUDIENCES lists \"{aud}\", an OIDC client id; a game token must \
                 never pass for that client's access token"
            )),
            None => Ok(()),
        }
    }

    /// Log, once, which state the feature is in.
    pub fn log_state(&self) {
        if self.audiences.is_empty() {
            info!("Game tokens DISABLED: GAME_TOKEN_AUDIENCES unset");
        } else {
            info!(
                "Game tokens ENABLED: audiences={} lifetime={}s",
                self.audiences.join(","),
                self.lifetime_seconds
            );
        }
    }

    /// Count a mint for `user_id` at `now`, or the seconds until it may
    /// mint again.
    fn admit(&self, user_id: &Uuid, now: i64) -> Result<(), u64> {
        const WINDOW: i64 = 60;
        let mut map = self.mints.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, (start, _)| now - *start < WINDOW);
        let (start, count) = map.entry(*user_id).or_insert((now, 0));
        if *count >= GAME_TOKEN_MINTS_PER_MINUTE {
            return Err((*start + WINDOW - now).max(1) as u64);
        }
        *count += 1;
        Ok(())
    }
}

/// Whether `aud` is one of `others`, compared the way a verifier might
/// match it: letter case and a trailing slash do not make another audience.
fn conflicts<'a>(aud: &str, mut others: impl Iterator<Item = &'a str>) -> bool {
    let normal = |s: &str| s.trim().trim_end_matches('/').to_ascii_lowercase();
    let aud = normal(aud);
    others.any(|other| normal(other) == aud)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenRequest {
    /// Exactly one of the two: the passkey session, or its game session.
    #[serde(default)]
    session_id: Option<Uuid>,
    #[serde(default)]
    game_session_id: Option<Uuid>,
    audience: String,
    /// An integer: a fraction or an exponent does not deserialize.
    issued_at: i64,
    signature: String,
}

/// A refusal that also tells the caller identity's clock.
fn refuse_with_time(status: StatusCode, error: &str, now: i64) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({ "error": error, "serverTime": now })),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenSessionRequest {
    session_id: Uuid,
    issued_at: i64,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EndSessionRequest {
    game_session_id: Uuid,
    issued_at: i64,
    signature: String,
}

/// `POST /game/session`, body `{sessionId, issuedAt, signature}`: open the
/// game session of a passkey session.
///
/// The passkey session must be in service exactly as for a mint (it exists,
/// its device key signed the request, it is inside its 24 h deadline and
/// its idle limit, its account is live; each failure the same 401). The
/// game session takes that session's account, device key and assertion
/// time: the caller sends no key, and the deadline counts from the passkey
/// assertion. Its id is derived from the passkey session's, so a repeated
/// open answers the same game session and never extends it.
pub(crate) async fn open_session_handler(
    Extension(app_state): Extension<AppState>,
    body: Bytes,
) -> Response {
    let game = &app_state.game;
    if game.audiences.is_empty() {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, ERR_UNAVAILABLE);
    }
    let Ok(request) = serde_json::from_slice::<OpenSessionRequest>(&body) else {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_REQUEST);
    };
    let now = Utc::now().timestamp();
    if now.abs_diff(request.issued_at) > GAME_TOKEN_PROOF_SKEW_SECONDS.unsigned_abs() {
        return refuse_with_time(StatusCode::BAD_REQUEST, ERR_INVALID_ISSUED_AT, now);
    }
    let unauthorized = |why: &str| {
        warn!(
            "audit game_session_open outcome=unauthorized reason={why} session={}",
            request.session_id
        );
        refuse(StatusCode::UNAUTHORIZED, ERR_UNAUTHORIZED)
    };
    let session = match app_state.db_store.get_session(&request.session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => return unauthorized("no_session"),
        Err(e) => {
            error!("game session: session read failed: {e}");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        }
    };
    let Some((x, y)) = device_point(&session.public_key) else {
        error!(
            "game session: session {} holds an unreadable device key",
            session.session_id
        );
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
    };
    let message = game_token::session_open_message(&session.session_id, request.issued_at);
    if !game_token::signature_verifies(&x, &y, &message, &request.signature) {
        return unauthorized("invalid_proof");
    }
    if now >= session.assertion_at + SESSION_MAX_SECONDS {
        return unauthorized("session_expired");
    }
    if now >= session.last_renewed_at + SESSION_IDLE_LIMIT_SECONDS {
        return unauthorized("session_idle");
    }
    let user_id = session.user_id;
    if let Err(retry_after) = game.admit(&user_id, now) {
        warn!("audit game_session_open outcome=rate_limited user_id={user_id}");
        let mut response = refuse(StatusCode::TOO_MANY_REQUESTS, ERR_RATE_LIMITED);
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, retry_after.into());
        return response;
    }
    match app_state.db_store.get_user_by_id(&user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return unauthorized("account_gone"),
        Err(e) => {
            error!("game session: account lookup failed for {user_id}: {e}");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        }
    }
    let game_session = crate::db::GameSession {
        game_session_id: game_token::game_session_id_for(&session.session_id),
        user_id,
        public_key: session.public_key,
        assertion_at: session.assertion_at,
    };
    let wrote = match app_state
        .db_store
        .open_game_session(&game_session, now)
        .await
    {
        Ok(wrote) => wrote,
        Err(e) => {
            error!("game session: write failed for {user_id}: {e}");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        }
    };
    // Only for a row this request wrote: a game session that was already
    // open is in use, and nothing here may end it. A sign-out or an account
    // deletion that ran between the reads above and the write found no game
    // session to remove. So look again, and take the new row back unless
    // the passkey session and the account are both still there (a failed
    // read takes it back too; the client opens again).
    if wrote {
        let still = match app_state.db_store.get_session(&request.session_id).await {
            Ok(Some(_)) => app_state.db_store.is_account_live(&user_id).await,
            Ok(None) => Ok(false),
            Err(e) => Err(e),
        };
        if !matches!(still, Ok(true)) {
            if let Err(e) = app_state
                .db_store
                .delete_game_session(&game_session.game_session_id)
                .await
            {
                error!(
                    "game session: {} must not stay, and its delete failed: {e}",
                    game_session.game_session_id
                );
            }
            return match still {
                Err(e) => {
                    error!("game session: re-check failed for {user_id}: {e}");
                    refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER)
                }
                _ => unauthorized("ended_during_open"),
            };
        }
    }
    info!(
        "audit game_session_open outcome=opened user_id={user_id} game_session={}",
        game_session.game_session_id
    );
    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({
            "gameSessionId": game_session.game_session_id,
            "sub": user_id.to_string(),
            "expiresAt": game_session.assertion_at + GAME_SESSION_SECONDS,
            "serverTime": now,
        })),
    )
        .into_response()
}

/// `POST /game/session/end`, body `{gameSessionId, issuedAt, signature}`:
/// the device key ends its game session. 204, and 204 again for one that is
/// already gone. A session past its deadline can still be ended.
///
/// **A signature that is not the device key's is 204 too, and ends
/// nothing**: the route takes no token and no rate limit, so it must not
/// say whether an id names a game session (the mint does not either).
pub(crate) async fn end_session_handler(
    Extension(app_state): Extension<AppState>,
    body: Bytes,
) -> Response {
    if app_state.game.audiences.is_empty() {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, ERR_UNAVAILABLE);
    }
    let Ok(request) = serde_json::from_slice::<EndSessionRequest>(&body) else {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_REQUEST);
    };
    let now = Utc::now().timestamp();
    if now.abs_diff(request.issued_at) > GAME_TOKEN_PROOF_SKEW_SECONDS.unsigned_abs() {
        return refuse_with_time(StatusCode::BAD_REQUEST, ERR_INVALID_ISSUED_AT, now);
    }
    let id = request.game_session_id;
    let ended = || {
        (
            StatusCode::NO_CONTENT,
            [(header::CACHE_CONTROL, "no-store")],
        )
            .into_response()
    };
    let session = match app_state.db_store.get_game_session(&id).await {
        Ok(Some(session)) => session,
        Ok(None) => return ended(),
        Err(e) => {
            error!("game session end: read failed: {e}");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        }
    };
    let verified = device_point(&session.public_key).is_some_and(|(x, y)| {
        let message = game_token::session_end_message(&id, request.issued_at);
        game_token::signature_verifies(&x, &y, &message, &request.signature)
    });
    if !verified {
        warn!("audit game_session_end outcome=invalid_proof game_session={id}");
        return ended();
    }
    if let Err(e) = app_state.db_store.delete_game_session(&id).await {
        error!("game session end: delete failed: {e}");
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
    }
    info!(
        "audit game_session_end outcome=ended user_id={} game_session={id}",
        session.user_id
    );
    ended()
}

/// `POST /game/token`, body `{sessionId, audience, issuedAt, signature}`,
/// or `gameSessionId` in place of `sessionId` (exactly one of the two).
///
/// With a game session the checks are: it exists and its device key signed
/// the request (401 `unauthorized`), then its deadline (401
/// `game_session_ended`, told only to a caller whose proof verified). There
/// is no idle limit, and the passkey session is not read.
///
/// Order: the feature is configured (503); the body parses (400
/// `invalid_request`); the audience is listed (400 `invalid_audience`);
/// `issuedAt` is within the skew of now (400 `invalid_issued_at` with
/// `serverTime`: no secret is needed to decide it, and a wrong clock must
/// not look like a dead session). Then the session: it exists, the device
/// key signed the request, it is inside its deadline and its idle limit,
/// and its account is live, each failure the same 401. Then the rate limit
/// (429), the account's pass, and the mint.
pub(crate) async fn token_handler(
    Extension(app_state): Extension<AppState>,
    body: Bytes,
) -> Response {
    let game = &app_state.game;
    if game.audiences.is_empty() {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, ERR_UNAVAILABLE);
    }
    let Ok(request) = serde_json::from_slice::<TokenRequest>(&body) else {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_REQUEST);
    };
    let named = match (request.session_id, request.game_session_id) {
        (Some(id), None) => format!("session={id}"),
        (None, Some(id)) => format!("game_session={id}"),
        _ => return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_REQUEST),
    };
    if !game.audiences.contains(&request.audience) {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_AUDIENCE);
    }
    let now = Utc::now().timestamp();
    if now.abs_diff(request.issued_at) > GAME_TOKEN_PROOF_SKEW_SECONDS.unsigned_abs() {
        return refuse_with_time(StatusCode::BAD_REQUEST, ERR_INVALID_ISSUED_AT, now);
    }

    let unauthorized = |why: &str| {
        warn!("audit game_token outcome=unauthorized reason={why} {named}");
        refuse(StatusCode::UNAUTHORIZED, ERR_UNAUTHORIZED)
    };
    // The account, the device key as stored when the session opened (the
    // proof is checked against it and the token is bound to it; the caller
    // sends no key), and the deadline no token may outlive.
    let (user_id, x, y, deadline) = if let Some(id) = request.game_session_id {
        let session = match app_state.db_store.get_game_session(&id).await {
            Ok(Some(session)) => session,
            Ok(None) => return unauthorized("no_game_session"),
            Err(e) => {
                error!("game token: game session read failed: {e}");
                return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
            }
        };
        let Some((x, y)) = device_point(&session.public_key) else {
            error!("game token: game session {id} holds an unreadable device key");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        };
        let message = game_token::session_mint_message(&id, &request.audience, request.issued_at);
        if !game_token::signature_verifies(&x, &y, &message, &request.signature) {
            return unauthorized("invalid_proof");
        }
        // The deadline is decided below, after the rate limit and the
        // account: the row of an ended game session stays, so its mints
        // must be counted like any other, and a deleted account's is
        // `unauthorized` whatever its age.
        (
            session.user_id,
            x,
            y,
            session.assertion_at + GAME_SESSION_SECONDS,
        )
    } else {
        let Some(id) = request.session_id else {
            return refuse(StatusCode::BAD_REQUEST, ERR_INVALID_REQUEST);
        };
        let session = match app_state.db_store.get_session(&id).await {
            Ok(Some(session)) => session,
            Ok(None) => return unauthorized("no_session"),
            Err(e) => {
                error!("game token: session read failed: {e}");
                return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
            }
        };
        let Some((x, y)) = device_point(&session.public_key) else {
            error!("game token: session {id} holds an unreadable device key");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        };
        let message = game_token::mint_message(&id, &request.audience, request.issued_at);
        if !game_token::signature_verifies(&x, &y, &message, &request.signature) {
            return unauthorized("invalid_proof");
        }
        // Read-only: an over or idle session is refused, never ended here
        // (the renewal route ends it and says why).
        let deadline = session.assertion_at + SESSION_MAX_SECONDS;
        if now >= deadline {
            return unauthorized("session_expired");
        }
        if now >= session.last_renewed_at + SESSION_IDLE_LIMIT_SECONDS {
            return unauthorized("session_idle");
        }
        (session.user_id, x, y, deadline)
    };
    if let Err(retry_after) = game.admit(&user_id, now) {
        warn!("audit game_token outcome=rate_limited user_id={user_id}");
        let mut response = refuse(StatusCode::TOO_MANY_REQUESTS, ERR_RATE_LIMITED);
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, retry_after.into());
        return response;
    }
    // Sessions outlive the account until the sweep (#88): the row is the
    // authority, and it holds the handle.
    let user = match app_state.db_store.get_user_by_id(&user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return unauthorized("account_gone"),
        Err(e) => {
            error!("game token: account lookup failed for {user_id}: {e}");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        }
    };
    // A game session past its deadline. Read-only, and after the proof:
    // only the device learns that it is over, and the row is left for
    // sign-out to remove. (A passkey session's deadline was decided above.)
    if now >= deadline {
        warn!("audit game_token outcome=game_session_ended {named}");
        return refuse(StatusCode::UNAUTHORIZED, ERR_GAME_SESSION_ENDED);
    }

    let online_play = holds_online_play(&app_state, user_id).await;
    let token = GameToken {
        iss: app_state.issuer.to_string(),
        // Exactly the passkey auth CWT's `sub` (authn::mint_auth_token).
        sub: user_id.to_string(),
        aud: request.audience,
        iat: now,
        // Never past the session: the key the token is bound to ends with it.
        exp: (now + game.lifetime_seconds).min(deadline),
        cti: *Uuid::new_v4().as_bytes(),
        x,
        y,
        handle: user.handle.to_lowercase(),
        online_play,
    };
    let bytes = match game_token::mint(&token, &app_state.cwt_signing_key, &app_state.cwt_kid) {
        Ok(b) => b,
        Err(e) => {
            error!("Signing a game token failed: {e}");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, ERR_SERVER);
        }
    };
    info!(
        "audit game_token outcome=issued user_id={user_id} aud={} online_play={online_play} \
         {named}",
        token.aud
    );
    let mut answer = serde_json::json!({
        "token": authnz_rs::cwt::encode_for_header(&bytes),
        "expiresAt": token.exp,
        "onlinePlay": online_play,
        "serverTime": now,
    });
    if request.game_session_id.is_some() {
        answer["gameSessionExpiresAt"] = deadline.into();
    }
    ([(header::CACHE_CONTROL, "no-store")], axum::Json(answer)).into_response()
}

/// The coordinates of a stored device key (a 65-byte X9.63 point).
fn device_point(public_key: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if public_key.len() != 65 || public_key[0] != 0x04 {
        return None;
    }
    p256::PublicKey::from_sec1_bytes(public_key).ok()?;
    Some((
        public_key[1..33].try_into().ok()?,
        public_key[33..65].try_into().ok()?,
    ))
}

/// Whether the account holds the pass at this mint: derived as for any
/// token, asking the market again about a cached "none" (a client mints
/// right after a payment). No Patreon snapshot: no publishing source grants
/// online play. A failure withholds the pass and the mint goes on.
async fn holds_online_play(app_state: &AppState, user_id: Uuid) -> bool {
    let sources = match crate::publishing::load_sources(app_state, Some(user_id), true).await {
        Ok(sources) => sources,
        Err(e) => {
            warn!("game token: sources unreadable for {user_id}: {e}; no pass in this token");
            return false;
        }
    };
    match crate::publishing::derive(app_state, Some(user_id), None, sources).await {
        Ok(derived) => derived
            .entitlements
            .iter()
            .any(|e| e == ENTITLEMENT_ONLINE_PLAY),
        Err(e) => {
            warn!("game token: derivation failed for {user_id}: {e}; no pass in this token");
            false
        }
    }
}

#[cfg(test)]
#[path = "game_tests.rs"]
mod tests;
