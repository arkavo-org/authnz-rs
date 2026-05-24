//! OpenID Connect (OIDC) Provider endpoints
//!
//! Implements the OIDC endpoints required to act as an Identity Provider for
//! OpenTDF and other OIDC relying parties:
//!
//! - `GET /.well-known/openid-configuration` - OIDC discovery document
//! - `GET /.well-known/jwks.json`            - JWKS (public signing keys)
//! - `GET /oauth/authorize`                  - Authorization endpoint (code flow)
//! - `POST /oauth/token`                     - Token endpoint
//! - `GET /oauth/userinfo`                   - UserInfo endpoint
//!
//! Token claims include OpenTDF-compatible attributes:
//! `iss`, `sub`, `aud`, `email`, `email_verified`, `idp`,
//! `arkavo_account_id`, `arkavo_roles`, `arkavo_entitlements`.
//!
//! Authentication during the authorize step is delegated to an upstream
//! identity source (WebAuthn-issued Arkavo JWT, Apple Sign In, etc.).
//! Operators MUST configure allowed clients/redirect URIs via environment
//! variables (see [`OidcConfig`]).

use crate::AppState;
use crate::apple_signin;
use crate::constants::{
    ACCESS_TOKEN_LIFETIME_SECONDS, AUTHORIZATION_CODE_LIFETIME_SECONDS, DEFAULT_OIDC_ISSUER,
    ID_TOKEN_LIFETIME_SECONDS,
};
use axum::Json;
use axum::extract::{Extension, Form, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use chrono::Utc;
use fred::interfaces::{ClientLike, KeysInterface};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, encode};
use log::{debug, error, info, warn};
use p256::PublicKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

/// OIDC provider runtime configuration.
///
/// Loaded once at startup from environment variables.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub clients: HashMap<String, OidcClient>,
    /// `kid` to advertise in JWKS and embed in JWT headers.
    pub signing_kid: String,
    /// JWK representation of the public signing key.
    pub jwk: Jwk,
}

#[derive(Debug, Clone)]
pub struct OidcClient {
    pub client_id: String,
    /// Optional client secret. If `None`, the client is public and must use PKCE.
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
    pub kid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub scopes_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub claims_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
}

/// OIDC claims issued in ID/access tokens.
///
/// Fields are serialized into JWT payloads. The `arkavo_*` claims are
/// OpenTDF-compatible attributes that are mapped from internal Arkavo state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    pub idp: String,
    pub arkavo_account_id: String,
    pub arkavo_roles: Vec<String>,
    pub arkavo_entitlements: Vec<String>,
}

/// Information about an authenticated user used to mint OIDC tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    /// Stable subject identifier used in the `sub` claim.
    /// Format: `apple:<apple_sub>` or `arkavo:<uuid>` so it's clear which IdP issued.
    pub subject: String,
    /// Internal Arkavo account id (UUID), mapped into `arkavo_account_id`.
    pub arkavo_account_id: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    /// Upstream identity provider (`apple`, `webauthn`, ...).
    pub idp: String,
    pub roles: Vec<String>,
    pub entitlements: Vec<String>,
}

/// Stored authorization code metadata, keyed by the random code value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct AuthorizationCodeRecord {
    client_id: String,
    redirect_uri: String,
    scope: String,
    nonce: Option<String>,
    code_challenge: Option<String>,
    // Only S256 is supported (validated at the authorize endpoint), so the method
    // is stored for diagnostics/audit but not read during verification.
    code_challenge_method: Option<String>,
    user: AuthenticatedUser,
    expires_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RefreshTokenRecord {
    pub subject: String,
    pub client_id: String,
    pub scopes: String,
    pub expires_at: i64,
    pub created_at: i64,
}

/// Redis-backed (with local in-memory fallback) authorization code store.
///
/// Authorization codes are short-lived (10 minutes) and single-use.
#[derive(Clone)]
pub struct AuthorizationCodeStore {
    redis: fred::clients::RedisClient,
    local_fallback: Arc<Mutex<HashMap<String, AuthorizationCodeRecord>>>,
}

impl AuthorizationCodeStore {
    pub fn new(redis: fred::clients::RedisClient) -> Self {
        Self {
            redis,
            local_fallback: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn insert(
        &self,
        code: String,
        record: AuthorizationCodeRecord,
    ) -> Result<(), String> {
        let key = format!("oidc:code:{}", code);
        if self.redis.is_connected() {
            let value = serde_json::to_string(&record)
                .map_err(|e| format!("Serialization failed: {}", e))?;
            let _: () = self
                .redis
                .set(
                    &key,
                    value,
                    Some(fred::types::Expiration::EX(600)),
                    None,
                    false,
                )
                .await
                .map_err(|e| format!("Redis set failed: {}", e))?;
            Ok(())
        } else {
            log::warn!("Redis is offline; falling back to in-memory AuthorizationCodeStore");
            let mut map = self.local_fallback.lock().unwrap();
            let now = Utc::now().timestamp();
            map.retain(|_, v| v.expires_at > now);
            map.insert(code, record);
            Ok(())
        }
    }

    pub async fn take(&self, code: &str) -> Result<Option<AuthorizationCodeRecord>, String> {
        let key = format!("oidc:code:{}", code);
        if self.redis.is_connected() {
            let val: Option<String> = self
                .redis
                .get(&key)
                .await
                .map_err(|e| format!("Redis get failed: {}", e))?;
            if let Some(json_str) = val {
                // Delete immediately on retrieval (single-use)
                let _: () = self
                    .redis
                    .del(&key)
                    .await
                    .map_err(|e| format!("Redis del failed: {}", e))?;
                let record: AuthorizationCodeRecord = serde_json::from_str(&json_str)
                    .map_err(|e| format!("Deserialization failed: {}", e))?;
                if record.expires_at < Utc::now().timestamp() {
                    return Ok(None);
                }
                Ok(Some(record))
            } else {
                Ok(None)
            }
        } else {
            log::warn!("Redis is offline; falling back to in-memory AuthorizationCodeStore");
            let mut map = self.local_fallback.lock().unwrap();
            if let Some(record) = map.remove(code) {
                if record.expires_at < Utc::now().timestamp() {
                    return Ok(None);
                }
                Ok(Some(record))
            } else {
                Ok(None)
            }
        }
    }
}

/// Redis-backed (with local in-memory fallback) refresh token store.
///
/// Stores SHA-256 hash of refresh tokens with 30-day automatic expiration.
#[derive(Clone)]
pub struct RefreshTokenStore {
    redis: fred::clients::RedisClient,
    local_fallback: Arc<Mutex<HashMap<String, RefreshTokenRecord>>>,
}

impl RefreshTokenStore {
    pub fn new(redis: fred::clients::RedisClient) -> Self {
        Self {
            redis,
            local_fallback: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub async fn insert(&self, token: &str, record: RefreshTokenRecord) -> Result<(), String> {
        let token_hash = self.hash_token(token);
        let key = format!("oidc:refresh:{}", token_hash);
        let ttl_seconds = crate::constants::REFRESH_TOKEN_LIFETIME_SECONDS;

        if self.redis.is_connected() {
            let value = serde_json::to_string(&record)
                .map_err(|e| format!("Serialization failed: {}", e))?;
            let _: () = self
                .redis
                .set(
                    &key,
                    value,
                    Some(fred::types::Expiration::EX(ttl_seconds)),
                    None,
                    false,
                )
                .await
                .map_err(|e| format!("Redis set failed: {}", e))?;
            Ok(())
        } else {
            log::warn!("Redis is offline; falling back to in-memory RefreshTokenStore");
            let mut map = self.local_fallback.lock().unwrap();
            let now = Utc::now().timestamp();
            map.retain(|_, v| v.expires_at > now);
            map.insert(token_hash, record);
            Ok(())
        }
    }

    pub async fn take(&self, token: &str) -> Result<Option<RefreshTokenRecord>, String> {
        let token_hash = self.hash_token(token);
        let key = format!("oidc:refresh:{}", token_hash);

        if self.redis.is_connected() {
            let val: Option<String> = self
                .redis
                .get(&key)
                .await
                .map_err(|e| format!("Redis get failed: {}", e))?;
            if let Some(json_str) = val {
                // Delete immediately on retrieval (Refresh Token Rotation)
                let _: () = self
                    .redis
                    .del(&key)
                    .await
                    .map_err(|e| format!("Redis del failed: {}", e))?;
                let record: RefreshTokenRecord = serde_json::from_str(&json_str)
                    .map_err(|e| format!("Deserialization failed: {}", e))?;
                if record.expires_at < Utc::now().timestamp() {
                    return Ok(None);
                }
                Ok(Some(record))
            } else {
                Ok(None)
            }
        } else {
            log::warn!("Redis is offline; falling back to in-memory RefreshTokenStore");
            let mut map = self.local_fallback.lock().unwrap();
            if let Some(record) = map.remove(&token_hash) {
                if record.expires_at < Utc::now().timestamp() {
                    return Ok(None);
                }
                Ok(Some(record))
            } else {
                Ok(None)
            }
        }
    }
}

impl OidcConfig {
    pub fn from_env(decoding_key_path: &str) -> Result<Self, String> {
        let issuer = env::var("OIDC_ISSUER").unwrap_or_else(|_| DEFAULT_OIDC_ISSUER.to_string());

        // Build the JWK from the configured public decoding key.
        let pem = std::fs::read_to_string(decoding_key_path)
            .map_err(|e| format!("Failed to read decoding key for JWKS: {}", e))?;
        let pub_key = PublicKey::from_public_key_pem(&pem)
            .map_err(|e| format!("Failed to parse decoding key for JWKS: {}", e))?;
        let jwk = ec_public_key_to_jwk(&pub_key)?;
        let signing_kid = jwk.kid.clone();

        let clients = load_clients_from_env()?;

        Ok(Self {
            issuer,
            clients,
            signing_kid,
            jwk,
        })
    }
}

fn load_clients_from_env() -> Result<HashMap<String, OidcClient>, String> {
    parse_clients_from_env_vars(env::vars())
}

/// Parse RP registrations from a `(key, value)` env iterator.
///
/// Each registered relying party is configured by a triple of env vars keyed
/// by an operator-chosen `<TAG>` (typically matching the RP's `client_id`,
/// upper-cased):
///
/// ```text
///   OIDC_CLIENT_<TAG>_ID             = the RP's client_id
///   OIDC_CLIENT_<TAG>_SECRET         = optional; omit for public PKCE-only RPs
///   OIDC_CLIENT_<TAG>_REDIRECT_URIS  = comma-separated registered redirect URIs
/// ```
///
/// Returns an empty map (with a warning) when no tags are configured. Errors
/// when a tag has `_ID` but no `_REDIRECT_URIS`, when `_REDIRECT_URIS` is
/// empty after trimming, or when two tags resolve to the same `client_id`.
fn parse_clients_from_env_vars<I>(vars: I) -> Result<HashMap<String, OidcClient>, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let env_map: HashMap<String, String> = vars.into_iter().collect();

    let tags: Vec<String> = env_map
        .keys()
        .filter_map(|k| {
            k.strip_prefix("OIDC_CLIENT_")
                .and_then(|rest| rest.strip_suffix("_ID"))
                .filter(|tag| !tag.is_empty())
                .map(|s| s.to_string())
        })
        .collect();

    let mut clients: HashMap<String, OidcClient> = HashMap::new();
    for tag in tags {
        let client_id = env_map[&format!("OIDC_CLIENT_{}_ID", tag)].clone();
        let client_secret = env_map
            .get(&format!("OIDC_CLIENT_{}_SECRET", tag))
            .filter(|s| !s.is_empty())
            .cloned();
        let redirects_key = format!("OIDC_CLIENT_{}_REDIRECT_URIS", tag);
        let redirect_uris: Vec<String> = env_map
            .get(&redirects_key)
            .ok_or_else(|| {
                format!(
                    "OIDC_CLIENT_{}_ID is set but {} is missing",
                    tag, redirects_key
                )
            })?
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if redirect_uris.is_empty() {
            return Err(format!("{} has no values", redirects_key));
        }

        if let Some(existing) = clients.get(&client_id) {
            return Err(format!(
                "Duplicate OIDC client_id `{}` configured under multiple tags",
                existing.client_id
            ));
        }

        clients.insert(
            client_id.clone(),
            OidcClient {
                client_id,
                client_secret,
                redirect_uris,
            },
        );
    }

    if clients.is_empty() {
        warn!(
            "No OIDC relying parties configured; /oauth/authorize and /oauth/token will reject all clients. \
             Register at least one RP via OIDC_CLIENT_<TAG>_ID, optional OIDC_CLIENT_<TAG>_SECRET, \
             and OIDC_CLIENT_<TAG>_REDIRECT_URIS."
        );
    }

    Ok(clients)
}

/// Convert a P-256 public key to a JWK (kty=EC, crv=P-256, alg=ES256).
///
/// The `kid` is the SHA-256 thumbprint per RFC 7638, base64url-encoded.
pub fn ec_public_key_to_jwk(pub_key: &PublicKey) -> Result<Jwk, String> {
    let encoded = pub_key.to_encoded_point(false);
    let x_bytes = encoded
        .x()
        .ok_or_else(|| "EC public key missing x coordinate".to_string())?;
    let y_bytes = encoded
        .y()
        .ok_or_else(|| "EC public key missing y coordinate".to_string())?;

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let x = b64.encode(x_bytes);
    let y = b64.encode(y_bytes);

    // RFC 7638 thumbprint: SHA-256 over canonical JSON of required JWK members.
    let thumb_input = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        x, y
    );
    let mut hasher = Sha256::new();
    hasher.update(thumb_input.as_bytes());
    let kid = b64.encode(hasher.finalize());

    Ok(Jwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x,
        y,
        use_: "sig".to_string(),
        alg: "ES256".to_string(),
        kid,
    })
}

// --------- Endpoint handlers ---------

pub async fn discovery(Extension(oidc): Extension<Arc<OidcConfig>>) -> impl IntoResponse {
    let issuer = oidc.issuer.trim_end_matches('/').to_string();
    let doc = DiscoveryDocument {
        authorization_endpoint: format!("{}/oauth/authorize", issuer),
        token_endpoint: format!("{}/oauth/token", issuer),
        userinfo_endpoint: format!("{}/oauth/userinfo", issuer),
        jwks_uri: format!("{}/.well-known/jwks.json", issuer),
        issuer,
        response_types_supported: vec!["code"],
        subject_types_supported: vec!["public"],
        id_token_signing_alg_values_supported: vec!["ES256"],
        scopes_supported: vec!["openid", "email", "profile", "offline_access"],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_post",
            "client_secret_basic",
            "none",
        ],
        claims_supported: vec![
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "nonce",
            "email",
            "email_verified",
            "idp",
            "arkavo_account_id",
            "arkavo_roles",
            "arkavo_entitlements",
        ],
        grant_types_supported: vec!["authorization_code", "client_credentials", "refresh_token"],
        code_challenge_methods_supported: vec!["S256"],
    };
    Json(doc)
}

pub async fn jwks(Extension(oidc): Extension<Arc<OidcConfig>>) -> impl IntoResponse {
    Json(Jwks {
        keys: vec![oidc.jwk.clone()],
    })
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// Identity-source hint. Currently supported: `apple` (with `id_token`),
    /// `webauthn` (Arkavo JWT in `X-Auth-Token` header).
    pub idp: Option<String>,
    /// Apple id_token, when `idp=apple`. Alternatively pass `X-Apple-Id-Token` header.
    pub id_token: Option<String>,
}

/// Authorization endpoint.
///
/// Accepts standard OIDC authorize parameters. The end-user must already be
/// authenticated via one of the supported upstream identity sources:
///
/// 1. `idp=apple` + `id_token` (or `X-Apple-Id-Token` header): validates the
///    Apple-issued id_token, maps to an Arkavo account, and issues an
///    authorization code.
/// 2. `X-Auth-Token` header with a valid Arkavo JWT (from WebAuthn flow):
///    upgrades the WebAuthn session into an OIDC authorization code.
///
/// If no upstream credential is presented, returns 401 with a JSON body
/// explaining how to authenticate. (A future enhancement is a login HTML page
/// that walks the user through these flows; for now this endpoint is intended
/// to be driven by an SPA or native client that has already authenticated the
/// user via one of the supported flows.)
pub async fn authorize(
    Extension(app_state): Extension<AppState>,
    Extension(oidc): Extension<Arc<OidcConfig>>,
    Extension(apple): Extension<Arc<apple_signin::AppleJwksCache>>,
    Extension(code_store): Extension<AuthorizationCodeStore>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeQuery>,
) -> Response {
    if params.response_type != "code" {
        return oidc_error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "Only response_type=code is supported",
        );
    }

    let client = match oidc.clients.get(&params.client_id) {
        Some(client) => client.clone(),
        None => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "Unknown client_id",
            );
        }
    };

    if !client
        .redirect_uris
        .iter()
        .any(|u| u == &params.redirect_uri)
    {
        return oidc_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uri is not registered for this client",
        );
    }

    // PKCE: if a code_challenge is supplied, the method must be S256.
    if let Some(method) = &params.code_challenge_method
        && method != "S256"
    {
        return oidc_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge_method must be S256",
        );
    }

    let scope = params.scope.clone().unwrap_or_else(|| "openid".to_string());
    if !scope.split_whitespace().any(|s| s == "openid") {
        return oidc_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "scope must include openid",
        );
    }

    // Resolve the authenticated user from one of the supported upstream sources.
    let user = match resolve_user(&app_state, &oidc, &apple, &headers, &params).await {
        Ok(user) => user,
        Err(e) => return e.into_response(),
    };

    // Mint an authorization code.
    let code = generate_authz_code();
    let expires_at = Utc::now().timestamp() + AUTHORIZATION_CODE_LIFETIME_SECONDS;
    if let Err(err) = code_store
        .insert(
            code.clone(),
            AuthorizationCodeRecord {
                client_id: client.client_id.clone(),
                redirect_uri: params.redirect_uri.clone(),
                scope,
                nonce: params.nonce.clone(),
                code_challenge: params.code_challenge.clone(),
                code_challenge_method: params.code_challenge_method.clone(),
                user,
                expires_at,
            },
        )
        .await
    {
        error!("Failed to store authorization code: {}", err);
        return oidc_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Internal server error",
        );
    }

    // Redirect back to the relying party with code + state.
    let mut redirect = format!("{}?code={}", params.redirect_uri, code);
    if let Some(state) = params.state.as_deref() {
        redirect.push_str("&state=");
        redirect
            .push_str(&url::form_urlencoded::byte_serialize(state.as_bytes()).collect::<String>());
    }
    Redirect::temporary(&redirect).into_response()
}

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub id_token: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// Token endpoint: exchanges an authorization code, client credentials, or refresh token for tokens.
pub async fn token(
    Extension(app_state): Extension<AppState>,
    Extension(oidc): Extension<Arc<OidcConfig>>,
    Extension(code_store): Extension<AuthorizationCodeStore>,
    Extension(refresh_store): Extension<RefreshTokenStore>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    match form.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(
                app_state,
                oidc,
                code_store,
                refresh_store,
                headers,
                form,
            )
            .await
        }
        "client_credentials" => {
            handle_client_credentials_grant(app_state, oidc, headers, form).await
        }
        "refresh_token" => {
            handle_refresh_token_grant(app_state, oidc, refresh_store, headers, form).await
        }
        _ => oidc_error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Unsupported grant_type. Supported: authorization_code, client_credentials, refresh_token",
        ),
    }
}

async fn handle_authorization_code_grant(
    app_state: AppState,
    oidc: Arc<OidcConfig>,
    code_store: AuthorizationCodeStore,
    refresh_store: RefreshTokenStore,
    headers: HeaderMap,
    form: TokenForm,
) -> Response {
    let code = match form.code.as_deref() {
        Some(c) if !c.is_empty() => c,
        _ => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "code is required",
            );
        }
    };

    let record = match code_store.take(code).await {
        Ok(Some(r)) => r,
        _ => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Authorization code is invalid, expired, or already redeemed",
            );
        }
    };

    // Authenticate the client. Support either form params or HTTP Basic.
    let (presented_client_id, presented_client_secret) =
        extract_client_credentials(&headers, &form);
    let presented_client_id = match presented_client_id {
        Some(id) => id,
        None => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id is required",
            );
        }
    };

    if presented_client_id != record.client_id {
        return oidc_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "client_id mismatch",
        );
    }

    let client = match oidc.clients.get(&presented_client_id) {
        Some(c) => c,
        None => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "Unknown client_id",
            );
        }
    };

    match (&client.client_secret, &presented_client_secret) {
        (Some(expected), Some(given)) if constant_time_eq(expected, given) => {}
        (Some(_), _) => {
            return oidc_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Invalid client secret",
            );
        }
        (None, _) => {
            // Public client: require PKCE.
            let challenge = match record.code_challenge.as_deref() {
                Some(c) => c,
                None => {
                    return oidc_error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "Public clients must use PKCE (code_challenge)",
                    );
                }
            };
            let verifier = match form.code_verifier.as_deref() {
                Some(v) => v,
                None => {
                    return oidc_error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "code_verifier is required for public clients",
                    );
                }
            };
            if !verify_pkce_s256(verifier, challenge) {
                return oidc_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "PKCE verification failed",
                );
            }
        }
    }

    if let Some(redirect_uri) = form.redirect_uri.as_deref()
        && redirect_uri != record.redirect_uri
    {
        return oidc_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri mismatch",
        );
    }

    let now = Utc::now().timestamp();
    let id_exp = now + ID_TOKEN_LIFETIME_SECONDS;
    let at_exp = now + ACCESS_TOKEN_LIFETIME_SECONDS;

    let id_claims = OidcClaims {
        iss: oidc.issuer.clone(),
        sub: record.user.subject.clone(),
        aud: record.client_id.clone(),
        exp: id_exp,
        iat: now,
        nonce: record.nonce.clone(),
        email: record.user.email.clone(),
        email_verified: record.user.email_verified,
        idp: record.user.idp.clone(),
        arkavo_account_id: record.user.arkavo_account_id.clone(),
        arkavo_roles: record.user.roles.clone(),
        arkavo_entitlements: record.user.entitlements.clone(),
    };
    let mut access_claims = id_claims.clone();
    access_claims.exp = at_exp;
    access_claims.nonce = None;

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(oidc.signing_kid.clone());

    let id_token = match encode(&header, &id_claims, &app_state.encoding_key) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to encode id_token: {}", e);
            return oidc_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to issue id_token",
            );
        }
    };
    let access_token = {
        let extras = AccessTokenExtras {
            idp: record.user.idp.clone(),
            email: record.user.email.clone(),
            email_verified: record.user.email_verified,
            arkavo_account_id: Some(record.user.arkavo_account_id.clone()),
            arkavo_roles: Some(record.user.roles.clone()),
            arkavo_entitlements: Some(record.user.entitlements.clone()),
        };
        match mint_access_token(
            &app_state,
            &record.user.subject,
            &record.client_id,
            Some(extras),
            // TODO: thread cnf through. The WebAuthn passkey's COSE_Key is in
            // DynamoDB at this point, not on the request. Storing it on the
            // AuthorizationCodeRecord at /authorize time (or looking it up via
            // sub here) would let us bind the access token to the credential.
            // Deferred from JWT->CWT migration; access token is currently
            // unbound for WebAuthn flow, same security posture as today's JWT.
            None,
        ) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to mint access_token CWT: {}", e);
                return oidc_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Failed to issue access_token",
                );
            }
        }
    };

    // Issue standard refresh token if offline_access is requested
    let mut refresh_token = None;
    if record
        .scope
        .split_whitespace()
        .any(|s| s == "offline_access")
    {
        let r_token = generate_refresh_token();
        let expires_at = now + crate::constants::REFRESH_TOKEN_LIFETIME_SECONDS;
        let refresh_record = RefreshTokenRecord {
            subject: record.user.subject.clone(),
            client_id: record.client_id.clone(),
            scopes: record.scope.clone(),
            expires_at,
            created_at: now,
        };
        if let Err(err) = refresh_store.insert(&r_token, refresh_record).await {
            error!("Failed to store refresh token: {}", err);
            return oidc_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to issue refresh token",
            );
        }
        refresh_token = Some(r_token);
    }

    info!(
        "Issued OIDC tokens for client={} sub={} idp={} (refresh={})",
        record.client_id,
        record.user.subject,
        record.user.idp,
        refresh_token.is_some()
    );

    let mut response = Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_LIFETIME_SECONDS,
        id_token,
        scope: record.scope,
        refresh_token,
    })
    .into_response();
    // OAuth2 requires Cache-Control: no-store and Pragma: no-cache on token responses.
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    response
}

async fn handle_client_credentials_grant(
    app_state: AppState,
    oidc: Arc<OidcConfig>,
    headers: HeaderMap,
    form: TokenForm,
) -> Response {
    let (presented_client_id, presented_client_secret) =
        extract_client_credentials(&headers, &form);
    let presented_client_id = match presented_client_id {
        Some(id) => id,
        None => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id is required",
            );
        }
    };

    let client = match oidc.clients.get(&presented_client_id) {
        Some(c) => c,
        None => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "Unknown client_id",
            );
        }
    };

    match (&client.client_secret, &presented_client_secret) {
        (Some(expected), Some(given)) if constant_time_eq(expected, given) => {}
        _ => {
            return oidc_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Invalid client credentials",
            );
        }
    }

    let now = Utc::now().timestamp();
    let exp = now + ACCESS_TOKEN_LIFETIME_SECONDS;
    let client_subject = format!("client:{}", client.client_id);
    let scope = form.scope.unwrap_or_else(|| "openid".to_string());

    let id_claims = OidcClaims {
        iss: oidc.issuer.clone(),
        sub: client_subject.clone(),
        aud: client.client_id.clone(),
        exp,
        iat: now,
        nonce: None,
        email: None,
        email_verified: None,
        idp: "client_credentials".to_string(),
        arkavo_account_id: client_subject.clone(),
        arkavo_roles: vec!["service-account".to_string()],
        // Grant standard entitlements so service accounts can encrypt/decrypt OpenTDF payloads
        arkavo_entitlements: vec!["tdf:create".to_string(), "tdf:decrypt".to_string()],
    };

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(oidc.signing_kid.clone());

    let id_token = match encode(&header, &id_claims, &app_state.encoding_key) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to encode id_token: {}", e);
            return oidc_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to issue id_token",
            );
        }
    };
    let access_token = {
        let extras = AccessTokenExtras {
            idp: id_claims.idp.clone(),
            email: id_claims.email.clone(),
            email_verified: id_claims.email_verified,
            arkavo_account_id: Some(id_claims.arkavo_account_id.clone()),
            arkavo_roles: Some(id_claims.arkavo_roles.clone()),
            arkavo_entitlements: Some(id_claims.arkavo_entitlements.clone()),
        };
        match mint_access_token(&app_state, &client_subject, &client.client_id, Some(extras), None) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to mint access_token CWT: {}", e);
                return oidc_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Failed to issue access_token",
                );
            }
        }
    };

    info!(
        "Issued OIDC client credentials tokens for client_id={}",
        client.client_id
    );

    let mut response = Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_LIFETIME_SECONDS,
        id_token,
        scope,
        refresh_token: None,
    })
    .into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    response
}

async fn handle_refresh_token_grant(
    app_state: AppState,
    oidc: Arc<OidcConfig>,
    refresh_store: RefreshTokenStore,
    headers: HeaderMap,
    form: TokenForm,
) -> Response {
    let r_token = match form.refresh_token.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "refresh_token is required",
            );
        }
    };

    // Authenticate the client (if client_secret exists, must authenticate)
    let (presented_client_id, presented_client_secret) =
        extract_client_credentials(&headers, &form);
    let presented_client_id = match presented_client_id {
        Some(id) => id,
        None => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id is required",
            );
        }
    };

    let client = match oidc.clients.get(&presented_client_id) {
        Some(c) => c,
        None => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "Unknown client_id",
            );
        }
    };

    if let Some(expected_secret) = &client.client_secret {
        match &presented_client_secret {
            Some(given) if constant_time_eq(expected_secret, given) => {}
            _ => {
                return oidc_error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "Invalid client credentials",
                );
            }
        }
    }

    // Retrieve and rotate (delete) token from Redis
    let record = match refresh_store.take(r_token).await {
        Ok(Some(rec)) => rec,
        _ => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Invalid, expired, or rotated refresh token",
            );
        }
    };

    if record.client_id != presented_client_id {
        return oidc_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Client ID mismatch",
        );
    }

    let now = Utc::now().timestamp();
    if record.expires_at < now {
        return oidc_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Refresh token has expired",
        );
    }

    // Resolve standard roles and entitlements based on subject pattern
    let (roles, entitlements, idp) = if record.subject.starts_with("client:") {
        (
            vec!["service-account".to_string()],
            vec!["tdf:create".to_string(), "tdf:decrypt".to_string()],
            "client_credentials".to_string(),
        )
    } else {
        let auth_idp = if record.subject.starts_with("apple:") {
            "apple"
        } else {
            "webauthn"
        };
        (
            vec!["user".to_string()],
            vec!["tdf:create".to_string(), "tdf:decrypt".to_string()],
            auth_idp.to_string(),
        )
    };

    let id_exp = now + ID_TOKEN_LIFETIME_SECONDS;
    let at_exp = now + ACCESS_TOKEN_LIFETIME_SECONDS;

    let id_claims = OidcClaims {
        iss: oidc.issuer.clone(),
        sub: record.subject.clone(),
        aud: record.client_id.clone(),
        exp: id_exp,
        iat: now,
        nonce: None,
        email: None,
        email_verified: None,
        idp,
        arkavo_account_id: record.subject.clone(),
        arkavo_roles: roles,
        arkavo_entitlements: entitlements,
    };
    let mut access_claims = id_claims.clone();
    access_claims.exp = at_exp;

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(oidc.signing_kid.clone());

    let id_token = match encode(&header, &id_claims, &app_state.encoding_key) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to encode id_token: {}", e);
            return oidc_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to issue id_token",
            );
        }
    };
    let access_token = {
        let extras = AccessTokenExtras {
            idp: access_claims.idp.clone(),
            email: access_claims.email.clone(),
            email_verified: access_claims.email_verified,
            arkavo_account_id: Some(access_claims.arkavo_account_id.clone()),
            arkavo_roles: Some(access_claims.arkavo_roles.clone()),
            arkavo_entitlements: Some(access_claims.arkavo_entitlements.clone()),
        };
        match mint_access_token(&app_state, &record.subject, &record.client_id, Some(extras), None) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to mint access_token CWT: {}", e);
                return oidc_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Failed to issue access_token",
                );
            }
        }
    };

    // Rotate refresh token (issue a brand new one)
    let new_refresh_token = generate_refresh_token();
    let expires_at = now + crate::constants::REFRESH_TOKEN_LIFETIME_SECONDS;
    let new_refresh_record = RefreshTokenRecord {
        subject: record.subject.clone(),
        client_id: record.client_id.clone(),
        scopes: record.scopes.clone(),
        expires_at,
        created_at: now,
    };
    if let Err(err) = refresh_store
        .insert(&new_refresh_token, new_refresh_record)
        .await
    {
        error!("Failed to store rotated refresh token: {}", err);
        return oidc_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Failed to issue rotated refresh token",
        );
    }

    info!(
        "Rotated OIDC refresh tokens for client_id={} sub={}",
        record.client_id, record.subject
    );

    let mut response = Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_LIFETIME_SECONDS,
        id_token,
        scope: record.scopes,
        refresh_token: Some(new_refresh_token),
    })
    .into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    response
}

fn generate_refresh_token() -> String {
    let part1 = Uuid::new_v4();
    let part2 = Uuid::new_v4();
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(part1.as_bytes());
    bytes.extend_from_slice(part2.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Debug, Serialize)]
struct UserInfoResponse<'a> {
    sub: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    idp: &'a str,
    arkavo_account_id: &'a str,
    arkavo_roles: &'a [String],
    arkavo_entitlements: &'a [String],
}

pub async fn userinfo(
    Extension(app_state): Extension<AppState>,
    Extension(oidc): Extension<Arc<OidcConfig>>,
    headers: HeaderMap,
) -> Response {
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => {
            return oidc_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Bearer token required",
            );
        }
    };

    // Access tokens are now CWT (COSE_Sign1). Decode from base64url and verify.
    let raw = match crate::cwt::decode_from_header(&token) {
        Ok(b) => b,
        Err(e) => {
            debug!("UserInfo token base64url decode failed: {}", e);
            return oidc_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Access token is invalid or expired",
            );
        }
    };
    let opts = crate::cwt::VerifyOptions {
        expected_iss: Some(oidc.issuer.as_str()),
        // aud is the client_id; we don't know it here, so skip the check.
        expected_aud: None,
        now: chrono::Utc::now().timestamp(),
        skew_secs: crate::cwt::DEFAULT_SKEW_SECS,
    };
    let claims = match crate::cwt::verify(&raw, &app_state.cwt_verifying_key, &opts) {
        Ok(c) => c,
        Err(e) => {
            debug!("UserInfo CWT verification failed: {}", e);
            return oidc_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Access token is invalid or expired",
            );
        }
    };

    let sub = claims.sub.clone();
    let email = claims.custom.email.clone();
    let email_verified = claims.custom.email_verified;
    let idp = claims.custom.idp.clone().unwrap_or_default();
    let arkavo_account_id = claims.custom.arkavo_account_id.clone().unwrap_or_default();
    let arkavo_roles = claims.custom.arkavo_roles.clone().unwrap_or_default();
    let arkavo_entitlements = claims.custom.arkavo_entitlements.clone().unwrap_or_default();

    Json(UserInfoResponse {
        sub: &sub,
        email: email.as_deref(),
        email_verified,
        idp: &idp,
        arkavo_account_id: &arkavo_account_id,
        arkavo_roles: &arkavo_roles,
        arkavo_entitlements: &arkavo_entitlements,
    })
    .into_response()
}

// --------- Helpers ---------

#[derive(Debug, Error)]
pub enum AuthorizeError {
    #[error("login_required: no upstream credential supplied")]
    LoginRequired,
    #[error("invalid Arkavo JWT: {0}")]
    InvalidArkavoJwt(String),
    #[error("invalid Apple id_token: {0}")]
    InvalidAppleIdToken(String),
    #[error(
        "idp=apple requires the OIDC `nonce` query parameter (used as the Apple nonce). \
         No nonce was supplied — refusing to validate Apple id_token."
    )]
    AppleNonceRequired,
    #[error("apple_signin error: {0}")]
    AppleSigninError(#[from] apple_signin::AppleSigninError),
    #[error("database error: {0}")]
    Database(String),
}

impl IntoResponse for AuthorizeError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            AuthorizeError::LoginRequired => (StatusCode::UNAUTHORIZED, "login_required"),
            AuthorizeError::InvalidArkavoJwt(_) | AuthorizeError::InvalidAppleIdToken(_) => {
                (StatusCode::UNAUTHORIZED, "invalid_token")
            }
            AuthorizeError::AppleNonceRequired => (StatusCode::BAD_REQUEST, "invalid_request"),
            AuthorizeError::AppleSigninError(_) => (StatusCode::UNAUTHORIZED, "invalid_token"),
            AuthorizeError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        };
        oidc_error_response(status, code, &self.to_string())
    }
}

async fn resolve_user(
    app_state: &AppState,
    oidc: &OidcConfig,
    apple: &apple_signin::AppleJwksCache,
    headers: &HeaderMap,
    params: &AuthorizeQuery,
) -> Result<AuthenticatedUser, AuthorizeError> {
    // Prefer explicit idp hint.
    if params.idp.as_deref() == Some("apple")
        || params.id_token.is_some()
        || headers.get("X-Apple-Id-Token").is_some()
    {
        let token = params
            .id_token
            .clone()
            .or_else(|| {
                headers
                    .get("X-Apple-Id-Token")
                    .and_then(|h| h.to_str().ok().map(|s| s.to_string()))
            })
            .ok_or_else(|| {
                AuthorizeError::InvalidAppleIdToken("id_token is required for idp=apple".into())
            })?;

        // For the authorize flow the OIDC `nonce` query parameter doubles as
        // the Apple nonce: the client uses the same value when invoking Apple
        // Sign In, Apple echoes it in the id_token, and we verify the match.
        // We refuse to validate Apple tokens without a nonce — this is the
        // mandatory anti-replay binding for the upstream Apple ceremony.
        let nonce = params
            .nonce
            .as_deref()
            .ok_or(AuthorizeError::AppleNonceRequired)?;
        if nonce.is_empty() {
            return Err(AuthorizeError::AppleNonceRequired);
        }

        let apple_claims = apple_signin::verify_apple_id_token(apple, &token, nonce).await?;
        return apple_signin::map_apple_user(app_state, &apple_claims)
            .await
            .map_err(|e| AuthorizeError::Database(e.to_string()));
    }

    // Otherwise expect an Arkavo JWT (from WebAuthn flow).
    if let Some(arkavo_jwt) = headers.get("X-Auth-Token").and_then(|h| h.to_str().ok()) {
        return resolve_from_arkavo_jwt(app_state, oidc, arkavo_jwt).await;
    }

    Err(AuthorizeError::LoginRequired)
}

async fn resolve_from_arkavo_jwt(
    app_state: &AppState,
    _oidc: &OidcConfig,
    token: &str,
) -> Result<AuthenticatedUser, AuthorizeError> {
    // The legacy Arkavo JWTs do not yet include OIDC claims. Decode without
    // strict exp/nbf validation to stay consistent with start_authentication
    // (see authn.rs for the security rationale).
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_nbf = false;
    validation.validate_exp = false;
    validation.validate_aud = false;
    let decoding_key: &DecodingKey = &app_state.decoding_key;

    #[derive(Deserialize)]
    struct LegacyClaims {
        sub: String,
    }
    let data = decode::<LegacyClaims>(token, decoding_key, &validation)
        .map_err(|e| AuthorizeError::InvalidArkavoJwt(e.to_string()))?;

    let account_id = data.claims.sub;
    // Best-effort role/entitlement defaults. Future work: persist these on the user.
    Ok(AuthenticatedUser {
        subject: format!("arkavo:{}", account_id),
        arkavo_account_id: account_id,
        email: None,
        email_verified: None,
        idp: "webauthn".to_string(),
        roles: vec!["user".to_string()],
        entitlements: vec!["tdf:create".to_string(), "tdf:decrypt".to_string()],
    })
}

fn extract_client_credentials(
    headers: &HeaderMap,
    form: &TokenForm,
) -> (Option<String>, Option<String>) {
    if let Some(basic) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Basic "))
        && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(basic)
        && let Ok(s) = std::str::from_utf8(&decoded)
        && let Some((id, secret)) = s.split_once(':')
    {
        return (Some(id.to_string()), Some(secret.to_string()));
    }
    (form.client_id.clone(), form.client_secret.clone())
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
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

pub fn verify_pkce_s256(verifier: &str, challenge: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
    constant_time_eq(&expected, challenge)
}

fn generate_authz_code() -> String {
    // 256 bits of randomness, base64url-encoded. UUID v4 supplies 122 bits;
    // combine two for ~244 bits and append a nanosecond-based salt to make
    // collisions practically impossible without pulling in `rand`.
    let part1 = Uuid::new_v4();
    let part2 = Uuid::new_v4();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(part1.as_bytes());
    bytes.extend_from_slice(part2.as_bytes());
    bytes.extend_from_slice(&nanos.to_be_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Serialize)]
struct OidcErrorBody {
    error: String,
    error_description: String,
}

fn oidc_error_response(status: StatusCode, code: &str, description: &str) -> Response {
    (
        status,
        Json(OidcErrorBody {
            error: code.to_string(),
            error_description: description.to_string(),
        }),
    )
        .into_response()
}

/// Additional claims attached to a minted OIDC access token.
#[derive(Debug, Clone, Default)]
pub struct AccessTokenExtras {
    pub idp: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub arkavo_account_id: Option<String>,
    pub arkavo_roles: Option<Vec<String>>,
    pub arkavo_entitlements: Option<Vec<String>>,
}

impl AccessTokenExtras {
    pub fn with_idp(mut self, idp: &str) -> Self {
        self.idp = idp.into();
        self
    }
}

/// Mint an OIDC access token as a CWT (COSE_Sign1, ES256).
///
/// Returns a base64url-encoded CWT suitable for use as a Bearer token in the
/// `access_token` field of an OAuth2 token response.
pub fn mint_access_token(
    app_state: &AppState,
    sub: &str,
    audience: &str,
    extras: Option<AccessTokenExtras>,
    cnf: Option<crate::cwt::Cnf>,
) -> Result<String, crate::cwt::CwtError> {
    let issuer = std::env::var("OIDC_ISSUER")
        .unwrap_or_else(|_| DEFAULT_OIDC_ISSUER.to_string());
    let mut claims = crate::cwt::ArkavoClaims::oidc_access(&issuer, sub, audience, 1);

    if let Some(e) = extras {
        if !e.idp.is_empty() {
            claims = claims.with_idp(&e.idp);
        }
        if let Some(email) = e.email {
            claims = claims.with_email(&email, e.email_verified.unwrap_or(false));
        }
        if let Some(id) = e.arkavo_account_id {
            claims = claims.with_arkavo_account_id(&id);
        }
        if let Some(roles) = e.arkavo_roles {
            claims = claims.with_arkavo_roles(roles);
        }
        if let Some(ents) = e.arkavo_entitlements {
            claims = claims.with_arkavo_entitlements(ents);
        }
    }
    if let Some(c) = cnf {
        claims = claims.with_cnf(c);
    }
    let bytes = crate::cwt::mint(&claims, &app_state.cwt_signing_key, &app_state.cwt_kid)?;
    Ok(crate::cwt::encode_for_header(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use p256::SecretKey;
    use tower::ServiceExt;

    fn test_jwk() -> Jwk {
        // Deterministic test key derived from a fixed seed.
        let scalar = p256::elliptic_curve::ScalarPrimitive::from_slice(&[0x42u8; 32]).unwrap();
        let secret = SecretKey::new(scalar);
        let pub_key = secret.public_key();
        ec_public_key_to_jwk(&pub_key).unwrap()
    }

    fn test_oidc_config() -> Arc<OidcConfig> {
        let jwk = test_jwk();
        let signing_kid = jwk.kid.clone();
        Arc::new(OidcConfig {
            issuer: "https://identity.arkavo.net".to_string(),
            clients: HashMap::new(),
            signing_kid,
            jwk,
        })
    }

    #[test]
    fn test_jwk_serialization_shape() {
        let jwk = test_jwk();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(jwk.alg, "ES256");
        assert_eq!(jwk.use_, "sig");
        assert!(!jwk.x.is_empty());
        assert!(!jwk.y.is_empty());
        assert!(!jwk.kid.is_empty());

        let json = serde_json::to_string(&jwk).unwrap();
        assert!(json.contains("\"use\":\"sig\""));
        assert!(json.contains("\"kty\":\"EC\""));
        assert!(json.contains("\"crv\":\"P-256\""));
    }

    #[test]
    fn test_jwk_thumbprint_stable() {
        let a = test_jwk();
        let b = test_jwk();
        assert_eq!(a.kid, b.kid);
    }

    #[test]
    fn test_authorize_error_apple_nonce_required_is_400() {
        let resp = AuthorizeError::AppleNonceRequired.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    fn env_vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn test_parse_clients_multiple_rps() {
        let vars = env_vars(&[
            ("OIDC_CLIENT_OPENTDF_ID", "opentdf"),
            ("OIDC_CLIENT_OPENTDF_SECRET", "shh"),
            ("OIDC_CLIENT_OPENTDF_REDIRECT_URIS", "https://a/cb,https://b/cb"),
            ("OIDC_CLIENT_NATIVEAPP_ID", "arkavo-ios"),
            ("OIDC_CLIENT_NATIVEAPP_REDIRECT_URIS", "arkavo://oauth/cb"),
            // Unrelated env var must be ignored.
            ("SOME_OTHER_VAR", "ignored"),
        ]);
        let clients = parse_clients_from_env_vars(vars).unwrap();
        assert_eq!(clients.len(), 2);

        let opentdf = clients.get("opentdf").unwrap();
        assert_eq!(opentdf.client_secret.as_deref(), Some("shh"));
        assert_eq!(
            opentdf.redirect_uris,
            vec!["https://a/cb".to_string(), "https://b/cb".to_string()]
        );

        let native = clients.get("arkavo-ios").unwrap();
        // Empty/missing secret → public PKCE-only client.
        assert!(native.client_secret.is_none());
        assert_eq!(native.redirect_uris, vec!["arkavo://oauth/cb".to_string()]);
    }

    #[test]
    fn test_parse_clients_empty_secret_treated_as_public() {
        let vars = env_vars(&[
            ("OIDC_CLIENT_FOO_ID", "foo"),
            ("OIDC_CLIENT_FOO_SECRET", ""),
            ("OIDC_CLIENT_FOO_REDIRECT_URIS", "https://x/cb"),
        ]);
        let clients = parse_clients_from_env_vars(vars).unwrap();
        assert!(clients["foo"].client_secret.is_none());
    }

    #[test]
    fn test_parse_clients_missing_redirects_errors() {
        let vars = env_vars(&[("OIDC_CLIENT_FOO_ID", "foo")]);
        let err = parse_clients_from_env_vars(vars).unwrap_err();
        assert!(err.contains("OIDC_CLIENT_FOO_REDIRECT_URIS"));
    }

    #[test]
    fn test_parse_clients_empty_redirects_errors() {
        let vars = env_vars(&[
            ("OIDC_CLIENT_FOO_ID", "foo"),
            ("OIDC_CLIENT_FOO_REDIRECT_URIS", " , , "),
        ]);
        let err = parse_clients_from_env_vars(vars).unwrap_err();
        assert!(err.contains("has no values"));
    }

    #[test]
    fn test_parse_clients_duplicate_client_id_errors() {
        let vars = env_vars(&[
            ("OIDC_CLIENT_A_ID", "same"),
            ("OIDC_CLIENT_A_REDIRECT_URIS", "https://x/cb"),
            ("OIDC_CLIENT_B_ID", "same"),
            ("OIDC_CLIENT_B_REDIRECT_URIS", "https://y/cb"),
        ]);
        let err = parse_clients_from_env_vars(vars).unwrap_err();
        assert!(err.contains("Duplicate OIDC client_id"));
    }

    #[test]
    fn test_parse_clients_empty_env_returns_empty_map() {
        let clients = parse_clients_from_env_vars(env_vars(&[])).unwrap();
        assert!(clients.is_empty());
    }

    #[test]
    fn test_pkce_s256_verifier_matches_challenge() {
        let verifier = "verifier-string-with-enough-entropy-1234567890";
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert!(verify_pkce_s256(verifier, &challenge));
        assert!(!verify_pkce_s256("wrong", &challenge));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("hello", "hello"));
        assert!(!constant_time_eq("hello", "world"));
        assert!(!constant_time_eq("hello", "hello!"));
    }

    #[test]
    fn test_generate_authz_code_unique() {
        let a = generate_authz_code();
        let b = generate_authz_code();
        assert_ne!(a, b);
        assert!(a.len() >= 40, "authz code too short: {}", a.len());
    }

    fn test_redis() -> fred::clients::RedisClient {
        let config = fred::types::RedisConfig::default();
        fred::clients::RedisClient::new(config, None, None, None)
    }

    #[tokio::test]
    async fn test_authorization_code_store_roundtrip() {
        let store = AuthorizationCodeStore::new(test_redis());
        let code = "abc".to_string();
        let user = AuthenticatedUser {
            subject: "apple:123".into(),
            arkavo_account_id: "uuid".into(),
            email: Some("a@b".into()),
            email_verified: Some(true),
            idp: "apple".into(),
            roles: vec!["user".into()],
            entitlements: vec!["tdf:create".into()],
        };
        let record = AuthorizationCodeRecord {
            client_id: "opentdf".into(),
            redirect_uri: "https://opentdf/cb".into(),
            scope: "openid".into(),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            user,
            expires_at: Utc::now().timestamp() + 60,
        };
        store.insert(code.clone(), record).await.unwrap();
        assert!(store.take(&code).await.unwrap().is_some());
        // single-use: second take returns None
        assert!(store.take(&code).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_authorization_code_store_expired_take_returns_none() {
        let store = AuthorizationCodeStore::new(test_redis());
        let code = "expired".to_string();
        let user = AuthenticatedUser {
            subject: "apple:123".into(),
            arkavo_account_id: "uuid".into(),
            email: None,
            email_verified: None,
            idp: "apple".into(),
            roles: vec![],
            entitlements: vec![],
        };
        let record = AuthorizationCodeRecord {
            client_id: "opentdf".into(),
            redirect_uri: "https://opentdf/cb".into(),
            scope: "openid".into(),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            user,
            expires_at: Utc::now().timestamp() - 1,
        };
        store.insert(code.clone(), record).await.unwrap();
        assert!(store.take(&code).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_refresh_token_store_roundtrip() {
        let store = RefreshTokenStore::new(test_redis());
        let token = "some-secure-token-value-123456789";
        let record = RefreshTokenRecord {
            subject: "client:opentdf".into(),
            client_id: "opentdf".into(),
            scopes: "openid offline_access".into(),
            expires_at: Utc::now().timestamp() + 600,
            created_at: Utc::now().timestamp(),
        };
        store.insert(token, record).await.unwrap();
        let taken = store.take(token).await.unwrap();
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().client_id, "opentdf");
        // rotated/single-use: second take returns None
        assert!(store.take(token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_discovery_endpoint_returns_expected_shape() {
        let oidc = test_oidc_config();
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .layer(Extension(oidc));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["issuer"], "https://identity.arkavo.net");
        assert_eq!(
            v["authorization_endpoint"],
            "https://identity.arkavo.net/oauth/authorize"
        );
        assert_eq!(
            v["token_endpoint"],
            "https://identity.arkavo.net/oauth/token"
        );
        assert_eq!(
            v["userinfo_endpoint"],
            "https://identity.arkavo.net/oauth/userinfo"
        );
        assert_eq!(
            v["jwks_uri"],
            "https://identity.arkavo.net/.well-known/jwks.json"
        );
        assert_eq!(v["id_token_signing_alg_values_supported"][0], "ES256");
        assert!(
            v["claims_supported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c == "arkavo_account_id")
        );
        assert!(
            v["claims_supported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c == "arkavo_roles")
        );
        assert!(
            v["claims_supported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c == "arkavo_entitlements")
        );
    }

    #[tokio::test]
    async fn test_jwks_endpoint_returns_single_key() {
        let oidc = test_oidc_config();
        let app = Router::new()
            .route("/.well-known/jwks.json", get(jwks))
            .layer(Extension(oidc.clone()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["keys"].as_array().unwrap().len(), 1);
        assert_eq!(v["keys"][0]["kty"], "EC");
        assert_eq!(v["keys"][0]["crv"], "P-256");
        assert_eq!(v["keys"][0]["alg"], "ES256");
        assert_eq!(v["keys"][0]["use"], "sig");
        assert_eq!(v["keys"][0]["kid"], oidc.jwk.kid);
    }

    #[test]
    fn test_oidc_claims_serialization_omits_none() {
        let claims = OidcClaims {
            iss: "https://identity.arkavo.net".into(),
            sub: "apple:SUB".into(),
            aud: "opentdf".into(),
            exp: 0,
            iat: 0,
            nonce: None,
            email: None,
            email_verified: None,
            idp: "apple".into(),
            arkavo_account_id: "uuid".into(),
            arkavo_roles: vec!["user".into()],
            arkavo_entitlements: vec!["tdf:create".into(), "tdf:decrypt".into()],
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("nonce"));
        assert!(!json.contains("\"email\""));
        assert!(json.contains("arkavo_account_id"));
        assert!(json.contains("arkavo_roles"));
        assert!(json.contains("arkavo_entitlements"));
    }

    #[tokio::test]
    async fn test_client_credentials_grant() {
        use p256::pkcs8::EncodePrivateKey;
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
            std::env::set_var("AWS_ACCESS_KEY_ID", "fake_access_key");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "fake_secret_key");
        }
        let scalar = p256::elliptic_curve::ScalarPrimitive::from_slice(&[0x42u8; 32]).unwrap();
        let secret = SecretKey::new(scalar);
        let der = secret.to_pkcs8_der().unwrap();
        let encoding_key = jsonwebtoken::EncodingKey::from_ec_der(der.as_bytes());

        let cwt_signing_key = p256::ecdsa::SigningKey::from(&secret);
        let cwt_verifying_key = *cwt_signing_key.verifying_key();
        let cwt_kid: Vec<u8> = {
            use base64::Engine;
            let encoded = cwt_verifying_key.to_encoded_point(false);
            let x = encoded.x().unwrap();
            let y = encoded.y().unwrap();
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let thumb_input = format!(
                "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
                b64.encode(x),
                b64.encode(y)
            );
            let mut hasher = Sha256::new();
            hasher.update(thumb_input.as_bytes());
            hasher.finalize().to_vec()
        };

        let app_state = AppState {
            webauthn: Arc::new(
                webauthn_rs::WebauthnBuilder::new(
                    "identity.arkavo.net",
                    &url::Url::parse("https://identity.arkavo.net").unwrap(),
                )
                .unwrap()
                .build()
                .unwrap(),
            ),
            db_store: Arc::new(
                crate::db::DynamoDBStore::new(
                    "credentials".to_string(),
                    "handles".to_string(),
                    "device_bindings".to_string(),
                )
                .await
                .unwrap(),
            ),
            signing_key: Arc::new(p256::ecdsa::SigningKey::from(&secret)),
            encoding_key: Arc::new(encoding_key),
            decoding_key: Arc::new(jsonwebtoken::DecodingKey::from_secret(&[])),
            cwt_signing_key: Arc::new(cwt_signing_key),
            cwt_verifying_key: Arc::new(cwt_verifying_key),
            cwt_kid: Arc::new(cwt_kid),
        };

        let mut oidc = (*test_oidc_config()).clone();
        oidc.clients.insert(
            "test-client".to_string(),
            OidcClient {
                client_id: "test-client".to_string(),
                client_secret: Some("test-secret".to_string()),
                redirect_uris: vec![],
            },
        );
        let oidc = Arc::new(oidc);

        let form = TokenForm {
            grant_type: "client_credentials".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("test-client".to_string()),
            client_secret: Some("test-secret".to_string()),
            code_verifier: None,
            refresh_token: None,
            scope: None,
        };

        let headers = HeaderMap::new();
        let resp = handle_client_credentials_grant(app_state, oidc, headers, form).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(!body["access_token"].as_str().unwrap().is_empty());
        assert!(!body["id_token"].as_str().unwrap().is_empty());
        assert_eq!(body["scope"].as_str().unwrap(), "openid");
    }

    #[tokio::test]
    async fn test_refresh_token_grant() {
        use p256::pkcs8::EncodePrivateKey;
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
            std::env::set_var("AWS_ACCESS_KEY_ID", "fake_access_key");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "fake_secret_key");
        }
        let scalar = p256::elliptic_curve::ScalarPrimitive::from_slice(&[0x42u8; 32]).unwrap();
        let secret = SecretKey::new(scalar);
        let der = secret.to_pkcs8_der().unwrap();
        let encoding_key = jsonwebtoken::EncodingKey::from_ec_der(der.as_bytes());

        let cwt_signing_key = p256::ecdsa::SigningKey::from(&secret);
        let cwt_verifying_key = *cwt_signing_key.verifying_key();
        let cwt_kid: Vec<u8> = {
            use base64::Engine;
            let encoded = cwt_verifying_key.to_encoded_point(false);
            let x = encoded.x().unwrap();
            let y = encoded.y().unwrap();
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let thumb_input = format!(
                "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
                b64.encode(x),
                b64.encode(y)
            );
            let mut hasher = Sha256::new();
            hasher.update(thumb_input.as_bytes());
            hasher.finalize().to_vec()
        };

        let app_state = AppState {
            webauthn: Arc::new(
                webauthn_rs::WebauthnBuilder::new(
                    "identity.arkavo.net",
                    &url::Url::parse("https://identity.arkavo.net").unwrap(),
                )
                .unwrap()
                .build()
                .unwrap(),
            ),
            db_store: Arc::new(
                crate::db::DynamoDBStore::new(
                    "credentials".to_string(),
                    "handles".to_string(),
                    "device_bindings".to_string(),
                )
                .await
                .unwrap(),
            ),
            signing_key: Arc::new(p256::ecdsa::SigningKey::from(&secret)),
            encoding_key: Arc::new(encoding_key),
            decoding_key: Arc::new(jsonwebtoken::DecodingKey::from_secret(&[])),
            cwt_signing_key: Arc::new(cwt_signing_key),
            cwt_verifying_key: Arc::new(cwt_verifying_key),
            cwt_kid: Arc::new(cwt_kid),
        };

        let mut oidc = (*test_oidc_config()).clone();
        oidc.clients.insert(
            "test-client".to_string(),
            OidcClient {
                client_id: "test-client".to_string(),
                client_secret: Some("test-secret".to_string()),
                redirect_uris: vec![],
            },
        );
        let oidc = Arc::new(oidc);

        let refresh_store = RefreshTokenStore::new(test_redis());
        let token = "my-refresh-token-123";
        let record = RefreshTokenRecord {
            subject: "apple:123".into(),
            client_id: "test-client".into(),
            scopes: "openid offline_access".into(),
            expires_at: Utc::now().timestamp() + 3600,
            created_at: Utc::now().timestamp(),
        };
        refresh_store.insert(token, record).await.unwrap();

        let form = TokenForm {
            grant_type: "refresh_token".to_string(),
            code: None,
            redirect_uri: None,
            client_id: Some("test-client".to_string()),
            client_secret: Some("test-secret".to_string()),
            code_verifier: None,
            refresh_token: Some(token.to_string()),
            scope: None,
        };

        let headers = HeaderMap::new();
        let resp =
            handle_refresh_token_grant(app_state, oidc, refresh_store.clone(), headers, form).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(!body["access_token"].as_str().unwrap().is_empty());
        assert!(!body["id_token"].as_str().unwrap().is_empty());
        assert!(!body["refresh_token"].as_str().unwrap().is_empty());

        // Verification of rotation: original token must be gone
        assert!(refresh_store.take(token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn access_token_is_cwt_not_jwt() {
        use coset::CborSerializable;
        unsafe { std::env::set_var("AWS_REGION", "us-east-1"); }
        unsafe { std::env::set_var("AWS_ACCESS_KEY_ID", "test"); }
        unsafe { std::env::set_var("AWS_SECRET_ACCESS_KEY", "test"); }

        let app_state = crate::test_helpers::build_test_app_state().await;
        let extras = crate::oidc::AccessTokenExtras::default().with_idp("arkavo");
        let token = crate::oidc::mint_access_token(
            &app_state, "arkavo:test", "opentdf", Some(extras), None,
        ).expect("mint");

        // CWT bytes start as base64url-encoded CBOR; the COSE_Sign1 parses cleanly.
        let raw = crate::cwt::decode_from_header(&token).unwrap();
        let sign1 = coset::CoseSign1::from_slice(&raw).unwrap();
        let claims = crate::cwt::claims_from_cbor(sign1.payload.as_ref().unwrap()).unwrap();
        assert_eq!(claims.aud, crate::cwt::Audience::Single("opentdf".into()));
        assert_eq!(claims.custom.idp.as_deref(), Some("arkavo"));
    }

    #[tokio::test]
    async fn access_token_apple_omits_cnf() {
        use coset::CborSerializable;
        unsafe { std::env::set_var("AWS_REGION", "us-east-1"); }
        unsafe { std::env::set_var("AWS_ACCESS_KEY_ID", "test"); }
        unsafe { std::env::set_var("AWS_SECRET_ACCESS_KEY", "test"); }

        let app_state = crate::test_helpers::build_test_app_state().await;
        let token = crate::oidc::mint_access_token(
            &app_state, "apple:abc", "opentdf",
            Some(crate::oidc::AccessTokenExtras::default().with_idp("apple")),
            None,
        ).expect("mint");
        let raw = crate::cwt::decode_from_header(&token).unwrap();
        let sign1 = coset::CoseSign1::from_slice(&raw).unwrap();
        let claims = crate::cwt::claims_from_cbor(sign1.payload.as_ref().unwrap()).unwrap();
        assert!(claims.cnf.is_none());
    }
}
