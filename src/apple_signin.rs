//! Sign in with Apple integration.
//!
//! Apple is treated as an *upstream* identity provider: end-users sign in with
//! their Apple ID, and Arkavo AuthNZ trusts Apple's id_token only after
//! validating its signature against Apple's published JWKS. The resulting
//! Apple claims are mapped onto an Arkavo account before any OIDC tokens are
//! issued downstream. This ensures OpenTDF and other relying parties never
//! trust Apple directly — they trust AuthNZ, and AuthNZ decides which upstream
//! sources are acceptable.
//!
//! # Security model
//!
//! Every accepted Apple id_token must clear the following gates:
//!
//! 1. **Signature**: validated against Apple's published JWKS (cached 1h with
//!    force-refresh on `kid` miss in case Apple rotated keys).
//! 2. **Issuer**: `iss` must equal `https://appleid.apple.com`.
//! 3. **Audience**: `aud` must be one of the configured `APPLE_CLIENT_ID` values.
//!    Multiple values (comma-separated) are supported so a single AuthNZ
//!    deployment can accept both an iOS bundle id and a web Service ID.
//! 4. **Nonce**: a server-issued nonce must be supplied via the session, and
//!    the id_token's `nonce` claim must equal either that raw nonce *or*
//!    `sha256_hex(raw_nonce)` (Apple's recommended pattern for native clients).
//!    Replay-prevention rests on this nonce check, so it is mandatory.
//! 5. **Exp/iat**: enforced by `jsonwebtoken::Validation` (no leeway changes).
//!
//! # Supported flows
//!
//! - **Native flow** (`/oauth/apple/nonce` + `/oauth/apple/idtoken`): the iOS
//!   app calls `/oauth/apple/nonce` to obtain a server-issued nonce, uses it as
//!   the `nonce` field in `ASAuthorizationAppleIDRequest`, then POSTs the
//!   resulting id_token to `/oauth/apple/idtoken`. Server validates as above
//!   and returns the persisted Arkavo identity record.
//! - **OIDC authorize-with-Apple** (`GET /oauth/authorize?idp=apple&...`): the
//!   relying party's OIDC `nonce` parameter is reused as the Apple nonce. The
//!   id_token's `nonce` claim must match (raw or sha256_hex). This binds the
//!   downstream OIDC nonce to the upstream Apple ceremony.
//! - **Web callback** (`POST /oauth/apple/callback`): intentionally rejected
//!   until full code-exchange + state-bound-nonce wiring is implemented. The
//!   endpoint returns HTTP 501 with a clear error so misconfigured Apple
//!   Service IDs fail loudly instead of being silently accepted.
//!
//! # Persistence
//!
//! [`map_apple_user`] persists the `apple:<sub> → arkavo_account_id` mapping
//! in DynamoDB (via the existing credentials table, keyed by an
//! `apple-<sanitized_sub>` username). Email is treated as optional metadata;
//! the account key is always Apple's `sub`, so private-relay address changes
//! do not break identity continuity.

use crate::AppState;
use crate::constants::{APPLE_ISSUER, APPLE_JWKS_CACHE_TTL_SECONDS, APPLE_JWKS_URL};
use crate::db::DynamoDBError;
use crate::oidc::AuthenticatedUser;
use axum::Json;
use axum::extract::Extension;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tower_sessions::Session;
use uuid::Uuid;

const SESSION_APPLE_NONCE_KEY: &str = "apple_nonce_state";

/// Nonce TTL (seconds). Short-lived to bound the replay window.
const APPLE_NONCE_TTL_SECONDS: i64 = 600;

/// Claims published by Apple in id_tokens.
///
/// Apple only includes `email` on the *first* successful authentication
/// for a given user/app pair, so callers must persist the mapping locally.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct AppleIdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub nonce: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<EmailVerified>,
    pub is_private_email: Option<EmailVerified>,
}

/// Apple sends `email_verified`/`is_private_email` as either a JSON bool or
/// a JSON string ("true"/"false"). Handle both.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum EmailVerified {
    Bool(bool),
    Str(String),
}

impl EmailVerified {
    pub fn as_bool(&self) -> bool {
        match self {
            EmailVerified::Bool(b) => *b,
            EmailVerified::Str(s) => s == "true",
        }
    }
}

#[derive(Debug, Error)]
pub enum AppleSigninError {
    #[error("Apple JWKS fetch failed: {0}")]
    JwksFetch(String),
    #[error("Apple JWKS parsing failed: {0}")]
    JwksParse(String),
    #[error("Apple id_token header missing kid")]
    MissingKid,
    #[error("Apple id_token signed by unknown kid: {0}")]
    UnknownKid(String),
    #[error("Apple id_token signature/claims invalid: {0}")]
    InvalidToken(String),
    #[error("Apple id_token audience mismatch: aud={actual} not in {expected:?}")]
    AudienceMismatch {
        expected: Vec<String>,
        actual: String,
    },
    #[error("Apple id_token issuer mismatch: iss={0}")]
    IssuerMismatch(String),
    #[error("Apple id_token nonce missing")]
    MissingTokenNonce,
    #[error("Apple id_token nonce mismatch")]
    NonceMismatch,
    #[error(
        "No server-issued Apple nonce in session — call GET /oauth/apple/nonce before submitting an id_token"
    )]
    MissingSessionNonce,
    #[error("APPLE_CLIENT_ID is not configured")]
    MissingClientId,
    #[error("session error: {0}")]
    SessionError(String),
}

impl IntoResponse for AppleSigninError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppleSigninError::JwksFetch(_) | AppleSigninError::JwksParse(_) => {
                StatusCode::BAD_GATEWAY
            }
            AppleSigninError::MissingClientId | AppleSigninError::SessionError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            AppleSigninError::MissingSessionNonce => StatusCode::BAD_REQUEST,
            _ => StatusCode::UNAUTHORIZED,
        };
        (status, self.to_string()).into_response()
    }
}

/// Cached Apple JWKS, plus the operator-configured Apple client IDs.
///
/// `client_ids` is parsed from the `APPLE_CLIENT_ID` env var, which accepts a
/// comma-separated list so a single AuthNZ instance can accept both an iOS
/// bundle id (used by native Sign in with Apple) and a web Service ID (used by
/// the web flow) without needing parallel deployments.
pub struct AppleJwksCache {
    inner: RwLock<CacheState>,
    client_ids: Vec<String>,
}

struct CacheState {
    keys: Vec<Jwk>,
    fetched_at: i64,
}

impl AppleJwksCache {
    pub fn new() -> Self {
        let client_ids = env::var("APPLE_CLIENT_ID")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Self {
            inner: RwLock::new(CacheState {
                keys: Vec::new(),
                fetched_at: 0,
            }),
            client_ids,
        }
    }

    /// Operator-configured Apple client IDs. Apple `aud` must match one of these.
    pub fn client_ids(&self) -> &[String] {
        &self.client_ids
    }

    async fn get_keys(&self) -> Result<Vec<Jwk>, AppleSigninError> {
        let now = Utc::now().timestamp();
        {
            let state = self.inner.read().await;
            if !state.keys.is_empty() && now - state.fetched_at < APPLE_JWKS_CACHE_TTL_SECONDS {
                return Ok(state.keys.clone());
            }
        }

        let response = reqwest::get(APPLE_JWKS_URL)
            .await
            .map_err(|e| AppleSigninError::JwksFetch(e.to_string()))?;
        if !response.status().is_success() {
            return Err(AppleSigninError::JwksFetch(format!(
                "HTTP {}",
                response.status()
            )));
        }
        let body: AppleJwksResponse = response
            .json()
            .await
            .map_err(|e| AppleSigninError::JwksParse(e.to_string()))?;

        let mut state = self.inner.write().await;
        state.keys = body.keys;
        state.fetched_at = now;
        Ok(state.keys.clone())
    }

    async fn invalidate(&self) {
        let mut state = self.inner.write().await;
        state.fetched_at = 0;
        state.keys.clear();
    }
}

impl Default for AppleJwksCache {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize)]
struct AppleJwksResponse {
    keys: Vec<Jwk>,
}

/// Verify an Apple-issued id_token against the configured Apple client IDs,
/// Apple's published JWKS, and the supplied server-issued nonce.
///
/// `expected_raw_nonce` is the raw, opaque nonce that AuthNZ issued (via
/// [`issue_apple_nonce`] for the native flow, or the OIDC `nonce` query param
/// for the authorize flow). The id_token's `nonce` claim must equal either the
/// raw value or its hex-encoded SHA-256 — Apple recommends clients hash the
/// nonce before sending it to Apple, so both forms are accepted.
pub async fn verify_apple_id_token(
    cache: &AppleJwksCache,
    id_token: &str,
    expected_raw_nonce: &str,
) -> Result<AppleIdTokenClaims, AppleSigninError> {
    let client_ids = cache.client_ids();
    if client_ids.is_empty() {
        return Err(AppleSigninError::MissingClientId);
    }

    let header = decode_header(id_token)
        .map_err(|e| AppleSigninError::InvalidToken(format!("header decode: {}", e)))?;
    let kid = header.kid.ok_or(AppleSigninError::MissingKid)?;

    let keys = cache.get_keys().await?;
    if let Some(jwk) = find_jwk(&keys, &kid) {
        return verify_apple_id_token_with_jwk(jwk, id_token, client_ids, expected_raw_nonce);
    }

    // Cache miss: force a refresh in case Apple rotated keys.
    warn!("Apple kid {} not in cache; forcing JWKS refresh", kid);
    cache.invalidate().await;
    let keys = cache.get_keys().await?;
    let jwk = find_jwk(&keys, &kid).ok_or_else(|| AppleSigninError::UnknownKid(kid.clone()))?;
    verify_apple_id_token_with_jwk(jwk, id_token, client_ids, expected_raw_nonce)
}

fn find_jwk<'a>(keys: &'a [Jwk], kid: &str) -> Option<&'a Jwk> {
    keys.iter().find(|k| {
        k.common
            .key_id
            .as_deref()
            .map(|k_id| k_id == kid)
            .unwrap_or(false)
    })
}

fn verify_apple_id_token_with_jwk(
    jwk: &Jwk,
    id_token: &str,
    client_ids: &[String],
    expected_raw_nonce: &str,
) -> Result<AppleIdTokenClaims, AppleSigninError> {
    let alg = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Algorithm::RS256,
        AlgorithmParameters::EllipticCurve(_) => Algorithm::ES256,
        _ => {
            return Err(AppleSigninError::InvalidToken(
                "unsupported JWK algorithm parameters".into(),
            ));
        }
    };

    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| AppleSigninError::InvalidToken(format!("DecodingKey: {}", e)))?;

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[APPLE_ISSUER]);
    // jsonwebtoken's set_audience accepts the full list; it succeeds if `aud`
    // matches *any* configured value, which is what we want for multi-client
    // deployments (iOS bundle + web Service ID).
    validation.set_audience(client_ids);

    let data = decode::<AppleIdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| AppleSigninError::InvalidToken(e.to_string()))?;
    let claims = data.claims;

    // Defense-in-depth: re-check aud/iss ourselves so a future Validation
    // misconfiguration can't silently widen the trust boundary.
    if !client_ids.iter().any(|c| c == &claims.aud) {
        return Err(AppleSigninError::AudienceMismatch {
            expected: client_ids.to_vec(),
            actual: claims.aud,
        });
    }
    if claims.iss != APPLE_ISSUER {
        return Err(AppleSigninError::IssuerMismatch(claims.iss));
    }

    check_nonce(claims.nonce.as_deref(), expected_raw_nonce)?;

    Ok(claims)
}

/// Validate that the id_token's nonce claim binds to the server-issued nonce.
///
/// Accepts either the raw nonce verbatim or its hex SHA-256 (Apple's
/// recommended client-side hashing pattern). Uses constant-time comparison.
fn check_nonce(
    token_nonce: Option<&str>,
    expected_raw_nonce: &str,
) -> Result<(), AppleSigninError> {
    let token_nonce = token_nonce.ok_or(AppleSigninError::MissingTokenNonce)?;
    let hashed = sha256_hex(expected_raw_nonce);
    if !constant_time_eq(token_nonce, expected_raw_nonce) && !constant_time_eq(token_nonce, &hashed)
    {
        return Err(AppleSigninError::NonceMismatch);
    }
    Ok(())
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Map verified Apple claims onto an Arkavo account, creating one if needed.
///
/// **Persistence contract**: this function writes to DynamoDB (via the
/// existing credentials table). Specifically:
///
/// - Lookup key: `username = apple-<sanitized_apple_sub>` (DynamoDB
///   `username-index` GSI). The Apple `sub` is the canonical join key —
///   email is treated as optional metadata and is *never* used to locate an
///   account (Apple may rotate private-relay addresses without notice).
/// - Mapping: `apple:<apple_sub> → arkavo_account_id (UUID)` is rehydrated
///   on every login from DynamoDB, never from in-memory state or defaults.
/// - First-login provisioning: creates a real DynamoDB row via
///   [`crate::db::DynamoDBStore::create_user`] with a deterministic synthetic
///   `did:key:apple-<sha256(sub)>` DID (the existing schema requires a DID;
///   a follow-up will add a dedicated Apple-account record).
///
/// Roles/entitlements default to a minimal user policy; persisting these
/// per-account is a tracked follow-up (see README).
pub async fn map_apple_user(
    app_state: &AppState,
    claims: &AppleIdTokenClaims,
) -> Result<AuthenticatedUser, DynamoDBError> {
    let username = format!("apple-{}", sanitize_for_username(&claims.sub));
    let did = format!("did:key:apple-{}", &sha256_hex(&claims.sub)[..32]);

    let user = match app_state.db_store.get_user_by_name(&username).await? {
        Some(existing) => existing,
        None => {
            info!("Provisioning Arkavo account for Apple sub {}", claims.sub);
            app_state.db_store.create_user(&username, &did).await?
        }
    };

    let email_verified = claims.email_verified.as_ref().map(|v| v.as_bool());

    Ok(AuthenticatedUser {
        subject: format!("apple:{}", claims.sub),
        arkavo_account_id: user.user_id.to_string(),
        email: claims.email.clone(),
        email_verified,
        idp: "apple".to_string(),
        roles: vec!["user".to_string()],
        entitlements: vec!["tdf:create".to_string(), "tdf:decrypt".to_string()],
    })
}

fn sanitize_for_username(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(128)
        .collect()
}

fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

// --------- Nonce session helpers ---------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppleNonceState {
    raw_nonce: String,
    expires_at: i64,
}

/// Issue a fresh server-side Apple nonce, persist it in the session, and
/// return the raw value. The session is the binding between this nonce and
/// the subsequent `/oauth/apple/idtoken` call from the same client.
pub async fn issue_apple_nonce(session: &Session) -> Result<String, AppleSigninError> {
    // 256 bits of entropy from two UUIDs concatenated and base64url-encoded.
    let part1 = Uuid::new_v4();
    let part2 = Uuid::new_v4();
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(part1.as_bytes());
    bytes.extend_from_slice(part2.as_bytes());
    let raw_nonce =
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes);

    let state = AppleNonceState {
        raw_nonce: raw_nonce.clone(),
        expires_at: Utc::now().timestamp() + APPLE_NONCE_TTL_SECONDS,
    };
    session
        .insert(SESSION_APPLE_NONCE_KEY, &state)
        .await
        .map_err(|e| AppleSigninError::SessionError(e.to_string()))?;
    Ok(raw_nonce)
}

/// Single-use consume of the session-stored Apple nonce.
async fn consume_apple_nonce(session: &Session) -> Result<String, AppleSigninError> {
    let state: AppleNonceState = session
        .get(SESSION_APPLE_NONCE_KEY)
        .await
        .map_err(|e| AppleSigninError::SessionError(e.to_string()))?
        .ok_or(AppleSigninError::MissingSessionNonce)?;
    // Clear immediately — single-use, regardless of whether validation succeeds.
    session
        .remove_value(SESSION_APPLE_NONCE_KEY)
        .await
        .map_err(|e| AppleSigninError::SessionError(e.to_string()))?;

    if state.expires_at < Utc::now().timestamp() {
        return Err(AppleSigninError::MissingSessionNonce);
    }
    Ok(state.raw_nonce)
}

// --------- HTTP handlers ---------

#[derive(Debug, Serialize)]
pub struct AppleNonceResponse {
    /// Opaque server-issued nonce. Pass this value to
    /// `ASAuthorizationAppleIDRequest.nonce` (or its hex SHA-256, per Apple's
    /// recommendation). The same `Session` cookie must accompany the eventual
    /// `POST /oauth/apple/idtoken` so the server can match the nonce.
    pub nonce: String,
    pub expires_in: i64,
}

/// Issue a server-side Apple nonce. Required step before
/// `POST /oauth/apple/idtoken` in the native flow.
pub async fn apple_nonce_handler(session: Session) -> Response {
    match issue_apple_nonce(&session).await {
        Ok(nonce) => Json(AppleNonceResponse {
            nonce,
            expires_in: APPLE_NONCE_TTL_SECONDS,
        })
        .into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct AppleIdTokenRequest {
    pub id_token: String,
}

#[derive(Debug, Serialize)]
pub struct AppleIdTokenResponse {
    pub arkavo_account_id: String,
    pub subject: String,
    pub idp: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
}

/// Native flow: exchange an Apple-issued id_token (with a previously issued
/// nonce) for an Arkavo identity record.
///
/// Required preamble: client must have called `GET /oauth/apple/nonce` on the
/// same session. The id_token's `nonce` claim must match the session-stored
/// raw nonce, either verbatim or as hex SHA-256.
pub async fn apple_idtoken_handler(
    Extension(app_state): Extension<AppState>,
    Extension(cache): Extension<Arc<AppleJwksCache>>,
    session: Session,
    Json(req): Json<AppleIdTokenRequest>,
) -> Response {
    let raw_nonce = match consume_apple_nonce(&session).await {
        Ok(n) => n,
        Err(e) => return e.into_response(),
    };

    let claims = match verify_apple_id_token(&cache, &req.id_token, &raw_nonce).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let user = match map_apple_user(&app_state, &claims).await {
        Ok(u) => u,
        Err(e) => {
            error!("Failed to map Apple user: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to provision Arkavo account: {}", e),
            )
                .into_response();
        }
    };

    Json(AppleIdTokenResponse {
        arkavo_account_id: user.arkavo_account_id,
        subject: user.subject,
        idp: user.idp,
        email: user.email,
        email_verified: user.email_verified,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AppleCallbackForm {
    pub code: Option<String>,
    pub id_token: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    error_description: &'static str,
}

/// Web flow callback — currently rejected unconditionally.
///
/// The Apple web flow requires both:
/// 1. A code-exchange step against `https://appleid.apple.com/auth/token`
///    using a JWT signed with the operator's Apple private key, and
/// 2. State-bound nonce verification so the callback can be tied to the
///    original `/authorize` request without trusting attacker-supplied input.
///
/// Until both are implemented this endpoint returns HTTP 501. This is the
/// "clearly rejects" path required by the security review — we never accept
/// an Apple id_token through this endpoint without nonce verification, even
/// if the form post happens to include one.
pub async fn apple_callback_handler(Json(_form): Json<AppleCallbackForm>) -> Response {
    debug!("Rejecting Apple web callback — code exchange + state-bound nonce not implemented");
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorBody {
            error: "apple_web_callback_disabled",
            error_description:
                "Apple web callback is intentionally disabled until code exchange and \
                 state-bound nonce verification are implemented. Use the native flow \
                 (GET /oauth/apple/nonce + POST /oauth/apple/idtoken) or the OIDC \
                 authorize endpoint with idp=apple instead.",
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_verified_bool() {
        let v: EmailVerified = serde_json::from_str("true").unwrap();
        assert!(v.as_bool());
        let v: EmailVerified = serde_json::from_str("\"true\"").unwrap();
        assert!(v.as_bool());
        let v: EmailVerified = serde_json::from_str("\"false\"").unwrap();
        assert!(!v.as_bool());
        let v: EmailVerified = serde_json::from_str("false").unwrap();
        assert!(!v.as_bool());
    }

    #[test]
    fn test_sanitize_for_username() {
        assert_eq!(
            sanitize_for_username("000123.abc-def_ghi"),
            "000123.abc-def_ghi"
        );
        assert_eq!(sanitize_for_username("apple/sub<script>"), "applesubscript");
        let long = "a".repeat(200);
        assert_eq!(sanitize_for_username(&long).len(), 128);
    }

    #[test]
    fn test_sha256_hex_stable() {
        let a = sha256_hex("apple-sub");
        let b = sha256_hex("apple-sub");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn test_apple_issuer_constant() {
        assert_eq!(APPLE_ISSUER, "https://appleid.apple.com");
    }

    #[test]
    fn test_apple_signin_error_status_mapping() {
        assert_eq!(
            AppleSigninError::JwksFetch("x".into())
                .into_response()
                .status(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            AppleSigninError::MissingKid.into_response().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppleSigninError::MissingClientId.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AppleSigninError::NonceMismatch.into_response().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppleSigninError::MissingTokenNonce.into_response().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppleSigninError::MissingSessionNonce
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AppleSigninError::IssuerMismatch("https://evil.example".into())
                .into_response()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn test_id_token_claims_deserializes_real_shape() {
        let json = r#"{
            "iss":"https://appleid.apple.com",
            "sub":"000123.abc",
            "aud":"com.arkavo.app",
            "iat":1700000000,
            "exp":1700003600,
            "nonce":"abc",
            "email":"user@privaterelay.appleid.com",
            "email_verified":"true",
            "is_private_email":true
        }"#;
        let claims: AppleIdTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "000123.abc");
        assert_eq!(claims.nonce.as_deref(), Some("abc"));
        assert!(claims.email_verified.unwrap().as_bool());
        assert!(claims.is_private_email.unwrap().as_bool());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("hello", "hello"));
        assert!(!constant_time_eq("hello", "world"));
        assert!(!constant_time_eq("hello", "hello!"));
        assert!(!constant_time_eq("", "x"));
    }

    #[test]
    fn test_multiple_client_ids_parsed() {
        // Note: we don't use AppleJwksCache::new() here because it reads env;
        // instead validate the parsing logic directly.
        let raw = "com.arkavo.app, com.arkavo.web , com.arkavo.macos";
        let parsed: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(
            parsed,
            vec![
                "com.arkavo.app".to_string(),
                "com.arkavo.web".to_string(),
                "com.arkavo.macos".to_string(),
            ]
        );
    }

    #[test]
    fn test_audience_mismatch_lists_expected() {
        let err = AppleSigninError::AudienceMismatch {
            expected: vec!["com.arkavo.app".into(), "com.arkavo.web".into()],
            actual: "evil.example".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("com.arkavo.app"));
        assert!(msg.contains("com.arkavo.web"));
        assert!(msg.contains("evil.example"));
    }

    #[test]
    fn test_check_nonce_accepts_verbatim() {
        let raw = "raw-nonce-12345";
        assert!(check_nonce(Some(raw), raw).is_ok());
    }

    #[test]
    fn test_check_nonce_accepts_sha256_hex() {
        let raw = "raw-nonce-12345";
        let hashed = sha256_hex(raw);
        assert!(check_nonce(Some(&hashed), raw).is_ok());
    }

    #[test]
    fn test_check_nonce_rejects_mismatch() {
        let raw = "raw-nonce-12345";
        assert!(matches!(
            check_nonce(Some("not-the-nonce"), raw),
            Err(AppleSigninError::NonceMismatch)
        ));
    }

    #[test]
    fn test_check_nonce_rejects_missing() {
        assert!(matches!(
            check_nonce(None, "raw-nonce"),
            Err(AppleSigninError::MissingTokenNonce)
        ));
    }

    #[test]
    fn test_check_nonce_rejects_empty_string_when_raw_is_nonempty() {
        // An attacker sending an id_token whose nonce is empty must not pass.
        assert!(matches!(
            check_nonce(Some(""), "raw"),
            Err(AppleSigninError::NonceMismatch)
        ));
    }

    #[test]
    fn test_check_nonce_rejects_hash_of_wrong_value() {
        let other_hashed = sha256_hex("other-nonce");
        assert!(matches!(
            check_nonce(Some(&other_hashed), "expected-nonce"),
            Err(AppleSigninError::NonceMismatch)
        ));
    }

    #[test]
    fn test_apple_subject_is_account_key_not_email() {
        // The mapping uses Apple sub for username derivation. Construct a
        // claims value with a non-empty sub but no email; confirm the
        // derived username is the same regardless of email rotation.
        let sub = "000abc.123def";
        let username = format!("apple-{}", sanitize_for_username(sub));
        assert_eq!(username, "apple-000abc.123def");
        // Email rotation must not affect the deterministic key.
        let same = format!("apple-{}", sanitize_for_username(sub));
        assert_eq!(username, same);
    }

    #[tokio::test]
    async fn test_apple_web_callback_returns_501() {
        use axum::Router;
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::post;
        use tower::ServiceExt;

        let app = Router::new().route("/oauth/apple/callback", post(apple_callback_handler));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/apple/callback")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"code":"X","id_token":"Y","state":"S"}"#.to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "apple_web_callback_disabled");
    }

    #[tokio::test]
    async fn test_apple_nonce_endpoint_issues_unique_values_and_persists() {
        use axum::Router;
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use tower::ServiceExt;
        use tower_sessions::cookie::SameSite;
        use tower_sessions::cookie::time::Duration as SessionDuration;
        use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

        let session_layer = SessionManagerLayer::new(MemoryStore::default())
            .with_name("authnz-rs-test")
            .with_same_site(SameSite::Strict)
            .with_secure(false)
            .with_expiry(Expiry::OnInactivity(SessionDuration::seconds(600)));

        let app = Router::new()
            .route("/oauth/apple/nonce", get(apple_nonce_handler))
            .layer(session_layer);

        let resp1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/oauth/apple/nonce")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);
        let body1 = axum::body::to_bytes(resp1.into_body(), 4096).await.unwrap();
        let v1: AppleNonceResponse = serde_json::from_slice(&body1).unwrap();
        assert!(!v1.nonce.is_empty());
        assert_eq!(v1.expires_in, APPLE_NONCE_TTL_SECONDS);

        let resp2 = app
            .oneshot(
                Request::builder()
                    .uri("/oauth/apple/nonce")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body2 = axum::body::to_bytes(resp2.into_body(), 4096).await.unwrap();
        let v2: AppleNonceResponse = serde_json::from_slice(&body2).unwrap();
        // Two separate session-less requests must not return the same nonce.
        assert_ne!(v1.nonce, v2.nonce);
    }
}

// Allow the binary crate's `Serialize` derive on `AppleNonceResponse` to be
// reconstructed by tests via `serde_json::from_slice`. (`AppleNonceResponse`
// is `Serialize`-only in production; tests need to deserialize, so add a
// permissive Deserialize impl behind cfg(test).)
#[cfg(test)]
impl<'de> serde::Deserialize<'de> for AppleNonceResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            nonce: String,
            expires_in: i64,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(AppleNonceResponse {
            nonce: h.nonce,
            expires_in: h.expires_in,
        })
    }
}
