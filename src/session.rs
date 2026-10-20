//! Passkey session renewal (#108).
//!
//! - `POST /session`: right after a passkey sign-in, the client registers the
//!   public half of a Secure Enclave key (the device key) and gets a session
//!   and its first single-use credential.
//! - `POST /session/refresh`: the device key signs the current credential;
//!   the answer is a fresh passkey auth CWT (entitlements and suspension read
//!   again) and the next credential. A spent credential ends the session
//!   (RFC 9700).
//! - `POST /session/signout`: the device key ends the session.
//!
//! A session lasts at most [`SESSION_MAX_SECONDS`] after its passkey
//! assertion and ends after [`SESSION_IDLE_SECONDS`] without a renewal. A
//! renewed token carries `auth_time` = that assertion, so it never passes
//! for a fresh sign-in ([`crate::cwt::passkey_assertion_time`]).
//!
//! Contract: [docs/session-renewal.md](../docs/session-renewal.md).

use crate::AppState;
use crate::constants::{
    SESSION_IDLE_SECONDS, SESSION_MAX_SECONDS, SESSION_OPEN_MAX_AUTH_AGE_SECONDS,
};
use crate::db::{DynamoDBError, Session, SessionOpened};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use log::{error, info, warn};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// First line of the message a device key signs to open a session.
pub(crate) const OPEN_CONTEXT: &str = "arkavo-session-open-v1";
/// First line of the message a device key signs to renew.
pub(crate) const REFRESH_CONTEXT: &str = "arkavo-session-refresh-v1";
/// First line of the message a device key signs to sign out.
pub(crate) const SIGNOUT_CONTEXT: &str = "arkavo-session-signout-v1";
/// Domain separator of the session id's hash of the opening token's `cti`.
const SESSION_ID_CONTEXT: &[u8] = b"arkavo-session-id-v1";

/// Why a renewal was refused. Each is `401 {"error": "session_ended",
/// "reason": …}`, and the client signs in with the passkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    NotFound,
    /// The signature does not verify against the session's device key. The
    /// session is kept: a caller without the key cannot end it.
    InvalidProof,
    /// Not the current credential, nor a spent one. The session is kept.
    InvalidCredential,
    /// A spent credential (RFC 9700 reuse). The session is ended.
    Reused,
    Idle,
    Expired,
    AccountDeleted,
}

impl Ended {
    pub fn reason(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::InvalidProof => "invalid_proof",
            Self::InvalidCredential => "invalid_credential",
            Self::Reused => "reused",
            Self::Idle => "idle",
            Self::Expired => "expired",
            Self::AccountDeleted => "account_deleted",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// `POST /session` needs an original passkey auth CWT minted at most
    /// [`SESSION_OPEN_MAX_AUTH_AGE_SECONDS`] ago, for a live account.
    #[error("{0}")]
    PasskeyAssertionRequired(String),
    #[error("publicKey must be a 65-byte uncompressed P-256 point")]
    InvalidPublicKey,
    #[error("proof must be a raw r||s ES256 signature by publicKey over the open message")]
    InvalidProof,
    #[error("this token already opened a session")]
    SessionExists,
    #[error("the session has ended; sign in with the passkey")]
    Ended(Ended),
    #[error("internal error")]
    Internal,
}

impl IntoResponse for SessionError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::PasskeyAssertionRequired(_) => {
                (StatusCode::UNAUTHORIZED, "passkey_assertion_required")
            }
            Self::InvalidPublicKey => (StatusCode::BAD_REQUEST, "invalid_public_key"),
            Self::InvalidProof => (StatusCode::BAD_REQUEST, "invalid_proof"),
            Self::SessionExists => (StatusCode::CONFLICT, "session_exists"),
            Self::Ended(_) => (StatusCode::UNAUTHORIZED, "session_ended"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        };
        let mut body = serde_json::json!({ "error": code, "error_description": self.to_string() });
        if let Self::Ended(why) = &self {
            body["reason"] = why.reason().into();
        }
        (status, [(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
    }
}

impl From<DynamoDBError> for SessionError {
    fn from(e: DynamoDBError) -> Self {
        error!("Session storage failure: {e}");
        Self::Internal
    }
}

/// The session a token opens: a UUID (version 8) from SHA-256 of its `cti`,
/// so one token opens at most one session.
pub(crate) fn session_id_for(cti: &[u8]) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_ID_CONTEXT);
    hasher.update(cti);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_custom_bytes(bytes).into_uuid()
}

pub(crate) fn open_message(sub: &str, cti: &[u8], public_key_b64: &str) -> String {
    format!(
        "{OPEN_CONTEXT}\n{sub}\n{}\n{public_key_b64}",
        URL_SAFE_NO_PAD.encode(cti)
    )
}

pub(crate) fn refresh_message(session_id: &Uuid, credential: &str) -> String {
    format!("{REFRESH_CONTEXT}\n{session_id}\n{credential}")
}

pub(crate) fn signout_message(session_id: &Uuid) -> String {
    format!("{SIGNOUT_CONTEXT}\n{session_id}")
}

/// A device public key: base64url of the 65-byte uncompressed X9.63 point.
fn parse_public_key(b64: &str) -> Result<(Vec<u8>, VerifyingKey), SessionError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| SessionError::InvalidPublicKey)?;
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(SessionError::InvalidPublicKey);
    }
    let key = VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| SessionError::InvalidPublicKey)?;
    Ok((bytes, key))
}

/// Whether `signature_b64` is a raw r||s ES256 signature by `key` over
/// `message`.
fn signature_verifies(key: &VerifyingKey, message: &str, signature_b64: &str) -> bool {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(signature_b64) else {
        return false;
    };
    if bytes.len() != 64 {
        return false;
    }
    let Ok(signature) = Signature::from_slice(&bytes) else {
        return false;
    };
    key.verify(message.as_bytes(), &signature).is_ok()
}

fn credential_hash(credential: &str) -> Vec<u8> {
    Sha256::digest(credential.as_bytes()).to_vec()
}

/// A fresh credential of `generation`: `<generation>.<base64url 32 random
/// bytes>`, and its hash.
fn new_credential(generation: u64) -> Result<(String, Vec<u8>), SessionError> {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).map_err(|e| {
        error!("Session credential RNG failure: {e}");
        SessionError::Internal
    })?;
    let credential = format!("{generation}.{}", URL_SAFE_NO_PAD.encode(secret));
    let hash = credential_hash(&credential);
    Ok((credential, hash))
}

/// The generation a credential names, if it is shaped like one.
fn credential_generation(credential: &str) -> Option<u64> {
    let (generation, secret) = credential.split_once('.')?;
    if secret.is_empty() || generation.starts_with('+') {
        return None;
    }
    generation.parse().ok()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenRequest {
    pub public_key: String,
    pub proof: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenResponse {
    pub session_id: Uuid,
    pub credential: String,
    pub session_expires_at: i64,
    pub idle_timeout_seconds: i64,
}

/// `POST /session`.
pub async fn open_session(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Json(req): Json<OpenRequest>,
) -> Result<(StatusCode, Json<OpenResponse>), SessionError> {
    let refuse = |why: &str| SessionError::PasskeyAssertionRequired(why.to_string());
    let (user_id, claims) = crate::agent::verify_passkey_auth_claims(&app_state, &headers)
        .map_err(|e| {
            warn!("Refused session open: {e}");
            refuse("X-Auth-Token must be a passkey auth CWT")
        })?;
    // A renewed token opening sessions would only multiply rows: its
    // assertion is no fresher than the session it came from.
    if claims.custom.auth_time.is_some() {
        return Err(refuse("a renewed token cannot open a session"));
    }
    let now = Utc::now().timestamp();
    let asserted_at = claims.iat;
    if !crate::oidc::within_age(asserted_at, now, SESSION_OPEN_MAX_AUTH_AGE_SECONDS) {
        return Err(refuse("the passkey sign-in is too old to open a session"));
    }
    if !app_state.db_store.is_account_live(&user_id).await? {
        return Err(refuse("account does not exist"));
    }

    let (public_key, key) = parse_public_key(&req.public_key)?;
    if !signature_verifies(
        &key,
        &open_message(&claims.sub, &claims.cti, &req.public_key),
        &req.proof,
    ) {
        return Err(SessionError::InvalidProof);
    }

    let session_id = session_id_for(&claims.cti);
    let (credential, hash) = new_credential(1)?;
    let session = Session {
        session_id,
        user_id,
        public_key,
        assertion_at: asserted_at,
        last_renewed_at: now,
        generation: 1,
        credential_hash: hash,
    };
    if app_state.db_store.open_session(&session, now).await? == SessionOpened::Exists {
        return Err(SessionError::SessionExists);
    }
    // The account may have been deleted while the row was written; the
    // sweep's link step may already have run (#88).
    if !app_state.db_store.is_account_live(&user_id).await? {
        app_state.db_store.delete_session(&session_id).await?;
        return Err(refuse("account does not exist"));
    }
    info!("Session {session_id} opened for {user_id}");
    Ok((
        StatusCode::CREATED,
        Json(OpenResponse {
            session_id,
            credential,
            session_expires_at: asserted_at + SESSION_MAX_SECONDS,
            idle_timeout_seconds: SESSION_IDLE_SECONDS,
        }),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub session_id: Uuid,
    pub credential: String,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub token: String,
    pub expires_at: i64,
    pub credential: String,
    pub session_expires_at: i64,
}

/// End `session` for `why`, and say so.
async fn end(
    app_state: &AppState,
    session: &Session,
    why: Ended,
) -> Result<SessionError, SessionError> {
    app_state
        .db_store
        .delete_session(&session.session_id)
        .await?;
    info!(
        "Session {} of {} ended: {}",
        session.session_id,
        session.user_id,
        why.reason()
    );
    Ok(SessionError::Ended(why))
}

/// The device key of a stored session.
fn device_key(session: &Session) -> Result<VerifyingKey, SessionError> {
    VerifyingKey::from_sec1_bytes(&session.public_key).map_err(|_| {
        error!(
            "Session {} holds an unreadable device key",
            session.session_id
        );
        SessionError::Internal
    })
}

/// `POST /session/refresh`.
pub async fn refresh_session(
    Extension(app_state): Extension<AppState>,
    Extension(patreon): Extension<crate::patreon::PatreonState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, SessionError> {
    let Some(session) = app_state.db_store.get_session(&req.session_id).await? else {
        return Err(SessionError::Ended(Ended::NotFound));
    };
    // The proof first: nothing below may end a session for a caller that
    // does not hold its device key.
    if !signature_verifies(
        &device_key(&session)?,
        &refresh_message(&session.session_id, &req.credential),
        &req.signature,
    ) {
        return Err(SessionError::Ended(Ended::InvalidProof));
    }
    let Some(generation) = credential_generation(&req.credential) else {
        return Err(SessionError::Ended(Ended::InvalidCredential));
    };
    if generation < session.generation {
        return Err(end(&app_state, &session, Ended::Reused).await?);
    }
    let presented = hex::encode(credential_hash(&req.credential));
    if generation > session.generation
        || !crate::oidc::constant_time_eq(&presented, &hex::encode(&session.credential_hash))
    {
        return Err(SessionError::Ended(Ended::InvalidCredential));
    }

    let now = Utc::now().timestamp();
    let deadline = session.assertion_at + SESSION_MAX_SECONDS;
    if now >= deadline {
        return Err(end(&app_state, &session, Ended::Expired).await?);
    }
    if now >= session.last_renewed_at + SESSION_IDLE_SECONDS {
        return Err(end(&app_state, &session, Ended::Idle).await?);
    }
    let Some(record) = app_state.db_store.get_user_by_id(&session.user_id).await? else {
        return Err(end(&app_state, &session, Ended::AccountDeleted).await?);
    };

    // Mint before rotating: a failure here leaves the credential unspent.
    let user = crate::oidc::AuthenticatedUser::webauthn(record.user_id, record.entitlements);
    let arkavo_user = crate::oidc::arkavo_user_claims(&app_state, &patreon, &user).await;
    let mut claims = crate::authn::passkey_auth_claims(&app_state, &session.user_id)
        .with_arkavo_user(&arkavo_user)
        .with_auth_time(session.assertion_at);
    claims.exp = claims.exp.min(deadline);
    let token =
        crate::cwt::mint(&claims, &app_state.cwt_signing_key, &app_state.cwt_kid).map_err(|e| {
            error!("Session {} renewal mint failed: {e}", session.session_id);
            SessionError::Internal
        })?;

    let (credential, hash) = new_credential(generation + 1)?;
    let rotated = app_state
        .db_store
        .rotate_session(
            &session.session_id,
            generation,
            &session.credential_hash,
            &hash,
            now,
        )
        .await?;
    if !rotated {
        // Renewed or ended meanwhile. A higher generation now means the
        // credential was spent by a concurrent renewal: reuse.
        return match app_state.db_store.get_session(&session.session_id).await? {
            Some(current) if current.generation > generation => {
                Err(end(&app_state, &current, Ended::Reused).await?)
            }
            _ => Err(SessionError::Ended(Ended::NotFound)),
        };
    }
    Ok(Json(RefreshResponse {
        token: crate::cwt::encode_for_header(&token),
        expires_at: claims.exp,
        credential,
        session_expires_at: deadline,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignoutRequest {
    pub session_id: Uuid,
    pub signature: String,
}

/// `POST /session/signout`. Idempotent: an unknown session is already gone.
pub async fn signout_session(
    Extension(app_state): Extension<AppState>,
    Json(req): Json<SignoutRequest>,
) -> Result<StatusCode, SessionError> {
    let Some(session) = app_state.db_store.get_session(&req.session_id).await? else {
        return Ok(StatusCode::NO_CONTENT);
    };
    if !signature_verifies(
        &device_key(&session)?,
        &signout_message(&session.session_id),
        &req.signature,
    ) {
        return Err(SessionError::Ended(Ended::InvalidProof));
    }
    app_state
        .db_store
        .delete_session(&session.session_id)
        .await?;
    info!(
        "Session {} of {} signed out",
        session.session_id, session.user_id
    );
    Ok(StatusCode::NO_CONTENT)
}
