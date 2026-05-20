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
//! Supported flows:
//!
//! - Native flow (`/oauth/apple/idtoken`): the iOS app uses
//!   `ASAuthorizationAppleIDProvider` to obtain an id_token, then POSTs it to
//!   this server. We validate the signature, map to an Arkavo account, and
//!   return an Arkavo JWT (or, when called from `/oauth/authorize`, an OIDC
//!   authorization code).
//! - Web flow (`/oauth/apple/callback`): scaffolded for completeness. Apple's
//!   web flow requires a client secret JWT signed by the operator's Apple
//!   private key. Operators must set `APPLE_TEAM_ID`, `APPLE_KEY_ID`,
//!   `APPLE_PRIVATE_KEY_PATH`, `APPLE_CLIENT_ID`, and `APPLE_REDIRECT_URI`.
//!   The code-exchange step against Apple is intentionally left as a TODO in
//!   the initial OIDC provider PR.

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
use std::env;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

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
    #[error("Apple id_token audience mismatch: expected {expected}, got {actual}")]
    AudienceMismatch { expected: String, actual: String },
    #[error("APPLE_CLIENT_ID is not configured")]
    MissingClientId,
}

impl IntoResponse for AppleSigninError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppleSigninError::JwksFetch(_) | AppleSigninError::JwksParse(_) => {
                StatusCode::BAD_GATEWAY
            }
            AppleSigninError::MissingClientId => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNAUTHORIZED,
        };
        (status, self.to_string()).into_response()
    }
}

/// Cached Apple JWKS. Refreshes lazily on cache miss / expiry.
pub struct AppleJwksCache {
    inner: RwLock<CacheState>,
    client_id: Option<String>,
}

struct CacheState {
    keys: Vec<Jwk>,
    fetched_at: i64,
}

impl AppleJwksCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(CacheState {
                keys: Vec::new(),
                fetched_at: 0,
            }),
            client_id: env::var("APPLE_CLIENT_ID").ok(),
        }
    }

    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
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

/// Verify an Apple-issued id_token. Returns the verified claims on success.
pub async fn verify_apple_id_token(
    cache: &AppleJwksCache,
    id_token: &str,
) -> Result<AppleIdTokenClaims, AppleSigninError> {
    let client_id = cache
        .client_id()
        .ok_or(AppleSigninError::MissingClientId)?
        .to_string();

    let header = decode_header(id_token)
        .map_err(|e| AppleSigninError::InvalidToken(format!("header decode: {}", e)))?;
    let kid = header.kid.ok_or(AppleSigninError::MissingKid)?;

    let keys = cache.get_keys().await?;
    if let Some(jwk) = find_jwk(&keys, &kid) {
        return verify_apple_id_token_with_jwk(jwk, id_token, &client_id);
    }

    // Cache miss: force a refresh in case Apple rotated keys.
    warn!("Apple kid {} not in cache; forcing JWKS refresh", kid);
    cache.invalidate().await;
    let keys = cache.get_keys().await?;
    let jwk = find_jwk(&keys, &kid).ok_or_else(|| AppleSigninError::UnknownKid(kid.clone()))?;
    verify_apple_id_token_with_jwk(jwk, id_token, &client_id)
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
    client_id: &str,
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
    validation.set_audience(&[client_id]);

    let data = decode::<AppleIdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| AppleSigninError::InvalidToken(e.to_string()))?;
    let claims = data.claims;

    if claims.aud != client_id {
        return Err(AppleSigninError::AudienceMismatch {
            expected: client_id.to_string(),
            actual: claims.aud,
        });
    }
    if claims.iss != APPLE_ISSUER {
        return Err(AppleSigninError::InvalidToken(format!(
            "iss mismatch: {}",
            claims.iss
        )));
    }

    Ok(claims)
}

/// Map verified Apple claims onto an Arkavo account, creating one if needed.
///
/// The mapping uses Apple's stable `sub` claim as the join key. For the first
/// PR we mint a synthetic DID (`did:key:apple-<sub-hash>`) so the existing
/// DynamoDB `create_user` path (which requires a `did:key:` DID) keeps working.
/// A follow-up PR can replace this with a richer Apple-account record.
pub async fn map_apple_user(
    app_state: &AppState,
    claims: &AppleIdTokenClaims,
) -> Result<AuthenticatedUser, DynamoDBError> {
    // Use the Apple sub as a deterministic username so we can locate the user
    // on subsequent logins. The leading `apple-` prefix avoids collisions with
    // WebAuthn-registered usernames.
    let username = format!("apple-{}", sanitize_for_username(&claims.sub));
    let did = format!(
        "did:key:apple-{}",
        // Truncate to keep DID a sensible length; collisions on the truncated
        // hash are not relevant because lookups go through `username`.
        &sha256_hex(&claims.sub)[..32]
    );

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
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

// --------- HTTP handlers ---------

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

/// Native flow: exchange an Apple-issued id_token for an Arkavo identity record.
///
/// This endpoint is primarily intended for native iOS clients that have
/// already completed the Sign in with Apple ceremony on-device. The response
/// is informational; to obtain OIDC tokens for downstream relying parties,
/// the client should call `/oauth/authorize` with `idp=apple` and the same
/// id_token in either the `id_token` query param or the `X-Apple-Id-Token`
/// header.
pub async fn apple_idtoken_handler(
    Extension(app_state): Extension<AppState>,
    Extension(cache): Extension<Arc<AppleJwksCache>>,
    Json(req): Json<AppleIdTokenRequest>,
) -> Response {
    let claims = match verify_apple_id_token(&cache, &req.id_token).await {
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

/// Web flow callback. Apple POSTs (`response_mode=form_post`) the code and
/// id_token to this endpoint after the user authenticates on appleid.apple.com.
///
/// For now we only support the path where Apple includes the id_token directly
/// (which it does when `response_mode=form_post` + `scope=name email` are set).
/// Exchanging `code` for tokens against Apple's `/auth/token` endpoint
/// requires signing a client secret JWT with the operator's Apple private key
/// — left as a follow-up.
pub async fn apple_callback_handler(
    Extension(app_state): Extension<AppState>,
    Extension(cache): Extension<Arc<AppleJwksCache>>,
    Json(form): Json<AppleCallbackForm>,
) -> Response {
    if let Some(err) = form.error {
        return (StatusCode::BAD_REQUEST, format!("apple_error: {}", err)).into_response();
    }
    let id_token = match form.id_token {
        Some(t) => t,
        None => {
            debug!(
                "Apple callback received code but no id_token; code exchange not yet implemented"
            );
            return (
                StatusCode::NOT_IMPLEMENTED,
                "Apple callback requires id_token in form post. \
                 Apple code-exchange flow is not yet implemented; configure your \
                 Apple Service ID with response_mode=form_post and scope=name+email \
                 so id_token is delivered directly.",
            )
                .into_response();
        }
    };

    let claims = match verify_apple_id_token(&cache, &id_token).await {
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
    }

    #[test]
    fn test_id_token_claims_deserializes_real_shape() {
        let json = r#"{
            "iss":"https://appleid.apple.com",
            "sub":"000123.abc",
            "aud":"com.arkavo.app",
            "iat":1700000000,
            "exp":1700003600,
            "email":"user@privaterelay.appleid.com",
            "email_verified":"true",
            "is_private_email":true
        }"#;
        let claims: AppleIdTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "000123.abc");
        assert!(claims.email_verified.unwrap().as_bool());
        assert!(claims.is_private_email.unwrap().as_bool());
    }
}
