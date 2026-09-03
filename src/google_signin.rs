//! Sign in with Google as an upstream identity provider for the OIDC
//! authorize endpoint.
//!
//! Unlike the Apple path (where the native client presents an Apple
//! `id_token` it already obtained), Google is driven **server-side** as a
//! browser redirect: a relying party sends the user-agent to
//! `/oauth/authorize?...&idp=google`, this server parks the validated OIDC
//! request, bounces the browser to Google, and finishes the OIDC code grant
//! when Google redirects back to `/oauth/google/callback`.
//!
//! ```text
//!   RP ──► /oauth/authorize?idp=google&client_id=…&redirect_uri=…&state=S
//!            │  validate RP params; store PendingAuthorize under G (random)
//!            └─► 302 accounts.google.com/o/oauth2/v2/auth?state=G&nonce=N…
//!   Google ─► /oauth/google/callback?state=G&code=C
//!            │  take PendingAuthorize(G); POST code C to Google's token endpoint
//!            │  verify id_token (JWKS sig, iss, aud, nonce N, exp)
//!            │  map google:<sub> → Arkavo account (credentials table)
//!            └─► 302 <RP redirect_uri>?code=<authz code>&state=S
//! ```
//!
//! # Security model
//! - The Google `state` is a fresh 256-bit random value that is the *only*
//!   key to the parked OIDC request, and it is single-use. The RP's own
//!   `state` is stored inside the record and echoed back untouched.
//! - The Google `nonce` is likewise random per request and must appear
//!   verbatim in the returned id_token (constant-time compare).
//! - Every accepted id_token must pass signature verification against
//!   Google's JWKS, `iss` ∈ [`GOOGLE_ISSUERS`], `aud` = the configured
//!   `GOOGLE_CLIENT_ID`, and `exp`/`iat` checks.
//! - The parked request is stored in Redis (in-memory fallback), not in the
//!   cookie session: the session cookie is `SameSite=Strict`, so it would not
//!   be sent on the cross-site top-level navigation back from Google.
//!
//! # Persistence
//! [`map_google_user`] mirrors [`crate::apple_signin::map_apple_user`]: the
//! Arkavo account is keyed by a `google-<sub>` username in the credentials
//! table. Google's `sub` is the canonical join key; email is carried as a
//! claim but never used to locate accounts.
//!
//! # Configuration
//! `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` enable the path;
//! `GOOGLE_REDIRECT_URI` defaults to `<OIDC_ISSUER>/oauth/google/callback`
//! and must be registered on the Google OAuth client. With either credential
//! unset, `idp=google` fails closed with `temporarily_unavailable`.

use crate::AppState;
use crate::apple_signin::EmailVerified;
use crate::constants::{
    GOOGLE_AUTHORIZE_URL, GOOGLE_HTTP_TIMEOUT_SECS, GOOGLE_ISSUERS, GOOGLE_JWKS_CACHE_TTL_SECONDS,
    GOOGLE_JWKS_URL, GOOGLE_PENDING_AUTHORIZE_TTL_SECONDS, GOOGLE_TOKEN_URL,
};
use crate::db::DynamoDBError;
use crate::oidc::{
    AuthenticatedUser, AuthorizationCodeStore, AuthorizeRequest, complete_authorization,
    oidc_error_response, redirect_error_to_client,
};
use axum::extract::{Extension, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use chrono::Utc;
use fred::interfaces::{ClientLike, KeysInterface};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::sync::RwLock;

/// Scopes requested from Google. `email` + `profile` yield the
/// `email`/`email_verified`/`name` claims surfaced on the Arkavo id_token.
const GOOGLE_SCOPES: &str = "openid email profile";

/// Operator configuration for the Google OAuth client.
#[derive(Debug, Clone)]
pub struct GoogleConfig {
    pub client_id: String,
    pub client_secret: String,
    /// Must match a redirect URI registered on the Google OAuth client.
    pub redirect_uri: String,
    pub authorize_url: String,
    pub token_url: String,
    pub jwks_url: String,
}

/// Claims we read from a Google id_token.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GoogleIdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub nonce: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<EmailVerified>,
    pub name: Option<String>,
    /// Google Workspace hosted domain, when the account belongs to one.
    pub hd: Option<String>,
}

#[derive(Debug, Error)]
pub enum GoogleSigninError {
    #[error("Google sign-in is not configured (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET)")]
    NotConfigured,
    #[error("Google JWKS fetch failed: {0}")]
    JwksFetch(String),
    #[error("Google JWKS parsing failed: {0}")]
    JwksParse(String),
    #[error("Google id_token header missing kid")]
    MissingKid,
    #[error("Google id_token signed by unknown kid: {0}")]
    UnknownKid(String),
    #[error("Google id_token signature/claims invalid: {0}")]
    InvalidToken(String),
    #[error("Google id_token audience mismatch: aud={0}")]
    AudienceMismatch(String),
    #[error("Google id_token issuer mismatch: iss={0}")]
    IssuerMismatch(String),
    #[error("Google id_token nonce missing")]
    MissingTokenNonce,
    #[error("Google id_token nonce mismatch")]
    NonceMismatch,
    #[error("Google code exchange failed: {0}")]
    CodeExchange(String),
}

/// A validated OIDC authorize request parked while the browser is at Google.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAuthorize {
    pub request: AuthorizeRequest,
    /// Nonce we sent to Google; must come back verbatim in the id_token.
    pub google_nonce: String,
    pub expires_at: i64,
}

/// Redis-backed (in-memory fallback) single-use store for parked requests,
/// keyed by the random Google `state`.
#[derive(Clone)]
pub struct PendingAuthorizeStore {
    redis: fred::clients::RedisClient,
    local_fallback: Arc<Mutex<HashMap<String, PendingAuthorize>>>,
}

impl PendingAuthorizeStore {
    pub fn new(redis: fred::clients::RedisClient) -> Self {
        Self {
            redis,
            local_fallback: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn key(state: &str) -> String {
        format!("oidc:google:pending:{}", state)
    }

    pub async fn insert(&self, state: &str, record: PendingAuthorize) -> Result<(), String> {
        if self.redis.is_connected() {
            let value = serde_json::to_string(&record)
                .map_err(|e| format!("Serialization failed: {}", e))?;
            let _: () = self
                .redis
                .set(
                    Self::key(state),
                    value,
                    Some(fred::types::Expiration::EX(
                        GOOGLE_PENDING_AUTHORIZE_TTL_SECONDS,
                    )),
                    None,
                    false,
                )
                .await
                .map_err(|e| format!("Redis set failed: {}", e))?;
            Ok(())
        } else {
            warn!("Redis is offline; falling back to in-memory PendingAuthorizeStore");
            let mut map = self.local_fallback.lock().unwrap();
            let now = Utc::now().timestamp();
            map.retain(|_, v| v.expires_at > now);
            map.insert(state.to_string(), record);
            Ok(())
        }
    }

    /// Fetch and delete (single-use). Expired records read as absent.
    pub async fn take(&self, state: &str) -> Result<Option<PendingAuthorize>, String> {
        let record = if self.redis.is_connected() {
            // GETDEL so two concurrent callbacks presenting the same state
            // cannot both win the race between a GET and a DEL.
            let val: Option<String> = self
                .redis
                .getdel(Self::key(state))
                .await
                .map_err(|e| format!("Redis getdel failed: {}", e))?;
            match val {
                Some(json) => Some(
                    serde_json::from_str::<PendingAuthorize>(&json)
                        .map_err(|e| format!("Deserialization failed: {}", e))?,
                ),
                None => None,
            }
        } else {
            warn!("Redis is offline; falling back to in-memory PendingAuthorizeStore");
            self.local_fallback.lock().unwrap().remove(state)
        };
        Ok(record.filter(|r| r.expires_at >= Utc::now().timestamp()))
    }
}

struct JwksState {
    keys: Vec<Jwk>,
    fetched_at: i64,
}

/// Process-wide Google sign-in state: config, JWKS cache, HTTP client, and
/// the parked-request store. `config == None` means the path is disabled.
pub struct GoogleSignin {
    config: Option<GoogleConfig>,
    jwks: RwLock<JwksState>,
    client: reqwest::Client,
    pending: PendingAuthorizeStore,
}

impl GoogleSignin {
    /// Build from `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` /
    /// `GOOGLE_REDIRECT_URI` (default `<issuer>/oauth/google/callback`).
    pub fn from_env(issuer: &str, redis: fred::clients::RedisClient) -> Self {
        let non_empty = |k: &str| env::var(k).ok().filter(|v| !v.trim().is_empty());
        let config = match (
            non_empty("GOOGLE_CLIENT_ID"),
            non_empty("GOOGLE_CLIENT_SECRET"),
        ) {
            (Some(client_id), Some(client_secret)) => {
                let redirect_uri = non_empty("GOOGLE_REDIRECT_URI").unwrap_or_else(|| {
                    format!("{}/oauth/google/callback", issuer.trim_end_matches('/'))
                });
                info!(
                    "Google sign-in enabled (client_id={}, redirect_uri={})",
                    client_id, redirect_uri
                );
                Some(GoogleConfig {
                    client_id,
                    client_secret,
                    redirect_uri,
                    authorize_url: GOOGLE_AUTHORIZE_URL.to_string(),
                    token_url: GOOGLE_TOKEN_URL.to_string(),
                    jwks_url: GOOGLE_JWKS_URL.to_string(),
                })
            }
            (Some(_), None) | (None, Some(_)) => {
                warn!(
                    "Google sign-in disabled: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must both be set"
                );
                None
            }
            (None, None) => None,
        };
        let timeout_secs = env::var("GOOGLE_HTTP_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&s| s > 0)
            .unwrap_or(GOOGLE_HTTP_TIMEOUT_SECS);
        Self::new(config, redis, std::time::Duration::from_secs(timeout_secs))
    }

    pub fn new(
        config: Option<GoogleConfig>,
        redis: fred::clients::RedisClient,
        timeout: std::time::Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            // TLS backend failing to initialize is a fatal startup condition.
            .expect("failed to build Google HTTP client");
        Self {
            config,
            jwks: RwLock::new(JwksState {
                keys: Vec::new(),
                fetched_at: 0,
            }),
            client,
            pending: PendingAuthorizeStore::new(redis),
        }
    }

    #[cfg(test)]
    pub fn is_enabled(&self) -> bool {
        self.config.is_some()
    }

    #[cfg(test)]
    pub fn pending_store(&self) -> &PendingAuthorizeStore {
        &self.pending
    }

    /// Park the validated OIDC request and redirect the browser to Google.
    ///
    /// The RP's `client_id`/`redirect_uri` have already been validated by the
    /// authorize endpoint, so failures here are reported to the RP on its
    /// redirect URI per RFC 6749 §4.1.2.1.
    pub async fn begin_authorize(&self, request: AuthorizeRequest) -> Response {
        let Some(config) = &self.config else {
            warn!(
                "idp=google requested by client_id={} but Google sign-in is not configured",
                request.client_id
            );
            return redirect_error_to_client(
                &request.redirect_uri,
                request.state.as_deref(),
                "temporarily_unavailable",
                "Google sign-in is not configured on this server",
            );
        };

        let google_state = random_token();
        let google_nonce = random_token();
        let record = PendingAuthorize {
            request: request.clone(),
            google_nonce: google_nonce.clone(),
            expires_at: Utc::now().timestamp() + GOOGLE_PENDING_AUTHORIZE_TTL_SECONDS,
        };
        if let Err(e) = self.pending.insert(&google_state, record).await {
            error!("Failed to park Google authorize request: {}", e);
            return redirect_error_to_client(
                &request.redirect_uri,
                request.state.as_deref(),
                "server_error",
                "Could not start Google sign-in",
            );
        }

        let mut url = match url::Url::parse(&config.authorize_url) {
            Ok(u) => u,
            Err(e) => {
                error!(
                    "Invalid Google authorize URL {:?}: {}",
                    config.authorize_url, e
                );
                return redirect_error_to_client(
                    &request.redirect_uri,
                    request.state.as_deref(),
                    "server_error",
                    "Google sign-in is misconfigured",
                );
            }
        };
        url.query_pairs_mut()
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &config.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", GOOGLE_SCOPES)
            .append_pair("state", &google_state)
            .append_pair("nonce", &google_nonce)
            // Let users with several Google sessions pick the account they
            // want linked, instead of silently reusing the last one.
            .append_pair("prompt", "select_account");

        info!(
            "Redirecting client_id={} to Google for sign-in",
            request.client_id
        );
        Redirect::temporary(url.as_str()).into_response()
    }

    async fn get_keys(&self, jwks_url: &str) -> Result<Vec<Jwk>, GoogleSigninError> {
        let now = Utc::now().timestamp();
        {
            let state = self.jwks.read().await;
            if !state.keys.is_empty() && now - state.fetched_at < GOOGLE_JWKS_CACHE_TTL_SECONDS {
                return Ok(state.keys.clone());
            }
        }
        let keys = fetch_jwks(&self.client, jwks_url).await?;
        let mut state = self.jwks.write().await;
        state.keys = keys;
        state.fetched_at = now;
        Ok(state.keys.clone())
    }

    async fn invalidate_keys(&self) {
        let mut state = self.jwks.write().await;
        state.fetched_at = 0;
        state.keys.clear();
    }

    /// Exchange the Google authorization code for an id_token.
    async fn exchange_code(
        &self,
        config: &GoogleConfig,
        code: &str,
    ) -> Result<String, GoogleSigninError> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("redirect_uri", config.redirect_uri.as_str()),
        ];
        let response = self
            .client
            .post(&config.token_url)
            .form(&form)
            .send()
            .await
            .map_err(|e| GoogleSigninError::CodeExchange(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            // Google's error body is `{error, error_description}`; log it but
            // never forward it to the RP verbatim.
            let body = response.text().await.unwrap_or_default();
            warn!("Google token endpoint returned {}: {}", status, body);
            return Err(GoogleSigninError::CodeExchange(format!("HTTP {}", status)));
        }
        let body: GoogleTokenResponse = response
            .json()
            .await
            .map_err(|e| GoogleSigninError::CodeExchange(format!("body: {}", e)))?;
        body.id_token
            .filter(|t| !t.is_empty())
            .ok_or_else(|| GoogleSigninError::CodeExchange("response lacks id_token".into()))
    }

    /// Verify a Google id_token against the configured client id, Google's
    /// JWKS, and the nonce we sent on the authorize redirect.
    pub async fn verify_id_token(
        &self,
        id_token: &str,
        expected_nonce: &str,
    ) -> Result<GoogleIdTokenClaims, GoogleSigninError> {
        let config = self
            .config
            .as_ref()
            .ok_or(GoogleSigninError::NotConfigured)?;
        let header = decode_header(id_token)
            .map_err(|e| GoogleSigninError::InvalidToken(format!("header decode: {}", e)))?;
        let kid = header.kid.ok_or(GoogleSigninError::MissingKid)?;

        let keys = self.get_keys(&config.jwks_url).await?;
        if let Some(jwk) = find_jwk(&keys, &kid) {
            return verify_id_token_with_jwk(jwk, id_token, &config.client_id, expected_nonce);
        }
        warn!("Google kid {} not in cache; forcing JWKS refresh", kid);
        self.invalidate_keys().await;
        let keys = self.get_keys(&config.jwks_url).await?;
        let jwk =
            find_jwk(&keys, &kid).ok_or_else(|| GoogleSigninError::UnknownKid(kid.clone()))?;
        verify_id_token_with_jwk(jwk, id_token, &config.client_id, expected_nonce)
    }
}

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

async fn fetch_jwks(client: &reqwest::Client, url: &str) -> Result<Vec<Jwk>, GoogleSigninError> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| GoogleSigninError::JwksFetch(e.to_string()))?;
    if !response.status().is_success() {
        return Err(GoogleSigninError::JwksFetch(format!(
            "HTTP {}",
            response.status()
        )));
    }
    let body: JwksResponse = response
        .json()
        .await
        .map_err(|e| GoogleSigninError::JwksParse(e.to_string()))?;
    Ok(body.keys)
}

fn find_jwk<'a>(keys: &'a [Jwk], kid: &str) -> Option<&'a Jwk> {
    keys.iter()
        .find(|k| k.common.key_id.as_deref() == Some(kid))
}

fn verify_id_token_with_jwk(
    jwk: &Jwk,
    id_token: &str,
    client_id: &str,
    expected_nonce: &str,
) -> Result<GoogleIdTokenClaims, GoogleSigninError> {
    let alg = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Algorithm::RS256,
        AlgorithmParameters::EllipticCurve(_) => Algorithm::ES256,
        _ => {
            return Err(GoogleSigninError::InvalidToken(
                "unsupported JWK algorithm parameters".into(),
            ));
        }
    };
    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| GoogleSigninError::InvalidToken(format!("DecodingKey: {}", e)))?;

    let mut validation = Validation::new(alg);
    validation.set_issuer(&GOOGLE_ISSUERS);
    validation.set_audience(&[client_id]);

    let claims = decode::<GoogleIdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| GoogleSigninError::InvalidToken(e.to_string()))?
        .claims;

    // Defense-in-depth: re-check iss/aud so a future Validation change can't
    // silently widen the trust boundary.
    if claims.aud != client_id {
        return Err(GoogleSigninError::AudienceMismatch(claims.aud));
    }
    if !GOOGLE_ISSUERS.contains(&claims.iss.as_str()) {
        return Err(GoogleSigninError::IssuerMismatch(claims.iss));
    }
    let token_nonce = claims
        .nonce
        .as_deref()
        .ok_or(GoogleSigninError::MissingTokenNonce)?;
    if !constant_time_eq(token_nonce, expected_nonce) {
        return Err(GoogleSigninError::NonceMismatch);
    }
    Ok(claims)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

/// Lower-case and trim an email address. Google addresses are
/// case-insensitive, and downstream policy (the OpenTDF platform's recipient
/// mapping) hashes the lower-cased address, so the CWT must carry the
/// canonical form regardless of how the user typed it at Google.
fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn sanitize_for_username(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(128)
        .collect()
}

/// Map verified Google claims to an Arkavo account, provisioning one on
/// first sight. Keyed by Google `sub` (never by email).
pub async fn map_google_user(
    app_state: &AppState,
    claims: &GoogleIdTokenClaims,
) -> Result<AuthenticatedUser, DynamoDBError> {
    let username = format!("google-{}", sanitize_for_username(&claims.sub));
    let did = format!("did:key:google-{}", &sha256_hex(&claims.sub)[..32]);

    let user = match app_state.db_store.get_user_by_name(&username).await? {
        Some(existing) => existing,
        None => {
            info!("Provisioning Arkavo account for Google sub {}", claims.sub);
            app_state.db_store.create_user(&username, &did).await?
        }
    };

    Ok(AuthenticatedUser {
        subject: format!("google:{}", claims.sub),
        arkavo_account_id: user.user_id.to_string(),
        email: claims.email.as_deref().map(normalize_email),
        email_verified: claims.email_verified.as_ref().map(|v| v.as_bool()),
        name: claims.name.clone(),
        idp: "google".to_string(),
        roles: vec!["user".to_string()],
        entitlements: user.entitlements.clone(),
    })
}

/// Query parameters Google sends to the redirect URI.
#[derive(Debug, Deserialize)]
pub struct GoogleCallbackQuery {
    pub state: Option<String>,
    pub code: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// `GET /oauth/google/callback` — Google redirects here after the user signs
/// in. Completes the parked OIDC authorize request for the relying party.
pub async fn google_callback_handler(
    Extension(app_state): Extension<AppState>,
    Extension(google): Extension<Arc<GoogleSignin>>,
    Extension(code_store): Extension<AuthorizationCodeStore>,
    Query(params): Query<GoogleCallbackQuery>,
) -> Response {
    // Without a parked request there is no RP to report to, so this is the
    // one failure that stays on this origin.
    let pending = match params.state.as_deref() {
        Some(state) if !state.is_empty() => match google.pending.take(state).await {
            Ok(Some(p)) => p,
            Ok(None) => {
                return oidc_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Unknown or expired Google sign-in state",
                );
            }
            Err(e) => {
                error!("Pending authorize lookup failed: {}", e);
                return oidc_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Internal server error",
                );
            }
        },
        _ => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "state is required",
            );
        }
    };
    let request = pending.request;
    let rp_state = request.state.as_deref();

    if let Some(err) = params.error.as_deref() {
        info!(
            "Google sign-in for client_id={} failed upstream: {} ({})",
            request.client_id,
            err,
            params.error_description.as_deref().unwrap_or("")
        );
        let code = if err == "access_denied" {
            "access_denied"
        } else {
            "server_error"
        };
        return redirect_error_to_client(
            &request.redirect_uri,
            rp_state,
            code,
            &format!("Google sign-in failed: {}", sanitize_error(err)),
        );
    }

    let Some(config) = google.config.as_ref() else {
        return redirect_error_to_client(
            &request.redirect_uri,
            rp_state,
            "temporarily_unavailable",
            "Google sign-in is not configured on this server",
        );
    };

    let code = match params.code.as_deref() {
        Some(c) if !c.is_empty() => c,
        _ => {
            return redirect_error_to_client(
                &request.redirect_uri,
                rp_state,
                "invalid_request",
                "Google callback lacked an authorization code",
            );
        }
    };

    let id_token = match google.exchange_code(config, code).await {
        Ok(t) => t,
        Err(e) => {
            error!("Google code exchange failed: {}", e);
            return redirect_error_to_client(
                &request.redirect_uri,
                rp_state,
                "server_error",
                "Google code exchange failed",
            );
        }
    };

    let claims = match google
        .verify_id_token(&id_token, &pending.google_nonce)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Google id_token rejected: {}", e);
            return redirect_error_to_client(
                &request.redirect_uri,
                rp_state,
                "access_denied",
                "Google id_token could not be verified",
            );
        }
    };

    let user = match map_google_user(&app_state, &claims).await {
        Ok(u) => u,
        Err(e) => {
            error!("Google user mapping failed: {}", e);
            return redirect_error_to_client(
                &request.redirect_uri,
                rp_state,
                "server_error",
                "Account lookup failed",
            );
        }
    };

    complete_authorization(&code_store, request, user).await
}

/// Keep upstream error codes to the RFC 6749 token character set before
/// echoing them into an RP redirect.
fn sanitize_error(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(64)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::LOCATION;
    use jsonwebtoken::jwk::{CommonParameters, EllipticCurveKeyParameters, EllipticCurveKeyType};
    use jsonwebtoken::{EncodingKey, Header};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::EncodePrivateKey;

    fn test_redis() -> fred::clients::RedisClient {
        fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None)
    }

    fn test_config(base: &str) -> GoogleConfig {
        GoogleConfig {
            client_id: "google-client-id.apps.googleusercontent.com".into(),
            client_secret: "shh".into(),
            redirect_uri: "https://identity.arkavo.net/oauth/google/callback".into(),
            authorize_url: format!("{base}/o/oauth2/v2/auth"),
            token_url: format!("{base}/token"),
            jwks_url: format!("{base}/certs"),
        }
    }

    fn test_request() -> AuthorizeRequest {
        AuthorizeRequest {
            client_id: "closurekb-android".into(),
            redirect_uri: "com.closurekb:/oauth2redirect".into(),
            scope: "openid email profile offline_access".into(),
            state: Some("rp-state-123".into()),
            nonce: Some("rp-nonce".into()),
            code_challenge: Some("chal".into()),
            code_challenge_method: Some("S256".into()),
        }
    }

    /// Ephemeral P-256 key as (EncodingKey, JWK with kid).
    fn test_keypair(kid: &str) -> (EncodingKey, Jwk) {
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).unwrap();
        let secret = p256::SecretKey::from_slice(&raw).unwrap();
        let der = secret.to_pkcs8_der().unwrap();
        let encoding_key = EncodingKey::from_ec_der(der.as_bytes());
        let point = secret.public_key().to_encoded_point(false);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwk = Jwk {
            common: CommonParameters {
                key_id: Some(kid.into()),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: jsonwebtoken::jwk::EllipticCurve::P256,
                x: b64.encode(point.x().unwrap()),
                y: b64.encode(point.y().unwrap()),
            }),
        };
        (encoding_key, jwk)
    }

    fn sign_google_token(key: &EncodingKey, kid: &str, claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.into());
        jsonwebtoken::encode(&header, claims, key).unwrap()
    }

    fn google_claims(client_id: &str, nonce: &str) -> serde_json::Value {
        let now = Utc::now().timestamp();
        serde_json::json!({
            "iss": "https://accounts.google.com",
            "sub": "110169484474386276334",
            "aud": client_id,
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
            "email": "Someone@Example.com",
            "email_verified": true,
            "name": "Some One",
        })
    }

    fn location(resp: &Response) -> String {
        resp.headers()[LOCATION].to_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn pending_store_is_single_use_and_expires() {
        let store = PendingAuthorizeStore::new(test_redis());
        let rec = PendingAuthorize {
            request: test_request(),
            google_nonce: "n".into(),
            expires_at: Utc::now().timestamp() + 60,
        };
        store.insert("s1", rec.clone()).await.unwrap();
        let got = store.take("s1").await.unwrap().expect("first take");
        assert_eq!(got.request.client_id, "closurekb-android");
        assert!(store.take("s1").await.unwrap().is_none(), "single use");

        let expired = PendingAuthorize {
            expires_at: Utc::now().timestamp() - 1,
            ..rec
        };
        store.insert("s2", expired).await.unwrap();
        assert!(store.take("s2").await.unwrap().is_none(), "expired");
    }

    #[tokio::test]
    async fn begin_authorize_redirects_to_google_and_parks_request() {
        let google = GoogleSignin::new(
            Some(test_config("https://google.test")),
            test_redis(),
            std::time::Duration::from_secs(1),
        );
        let resp = google.begin_authorize(test_request()).await;
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        let loc = url::Url::parse(&location(&resp)).unwrap();
        assert_eq!(loc.host_str(), Some("google.test"));
        let q: HashMap<_, _> = loc.query_pairs().into_owned().collect();
        assert_eq!(
            q["client_id"],
            "google-client-id.apps.googleusercontent.com"
        );
        assert_eq!(
            q["redirect_uri"],
            "https://identity.arkavo.net/oauth/google/callback"
        );
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["scope"], "openid email profile");
        assert_eq!(q["prompt"], "select_account");
        // Google state/nonce are fresh values, never the RP's.
        assert_ne!(q["state"], "rp-state-123");
        assert_ne!(q["nonce"], "rp-nonce");

        let parked = google
            .pending_store()
            .take(&q["state"])
            .await
            .unwrap()
            .expect("parked under google state");
        assert_eq!(parked.google_nonce, q["nonce"]);
        assert_eq!(parked.request.state.as_deref(), Some("rp-state-123"));
        assert_eq!(parked.request.redirect_uri, "com.closurekb:/oauth2redirect");
    }

    #[tokio::test]
    async fn begin_authorize_when_disabled_reports_to_rp() {
        let google = GoogleSignin::new(None, test_redis(), std::time::Duration::from_secs(1));
        assert!(!google.is_enabled());
        let resp = google.begin_authorize(test_request()).await;
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        let loc = location(&resp);
        assert!(loc.starts_with("com.closurekb:/oauth2redirect?"), "{loc}");
        assert!(loc.contains("error=temporarily_unavailable"), "{loc}");
        assert!(loc.contains("state=rp-state-123"), "{loc}");
    }

    #[test]
    fn verify_accepts_valid_token_and_rejects_tampering() {
        let (key, jwk) = test_keypair("kid-1");
        let cid = "google-client-id.apps.googleusercontent.com";

        let ok = sign_google_token(&key, "kid-1", &google_claims(cid, "nonce-1"));
        let claims = verify_id_token_with_jwk(&jwk, &ok, cid, "nonce-1").unwrap();
        assert_eq!(claims.sub, "110169484474386276334");
        assert_eq!(claims.email.as_deref(), Some("Someone@Example.com"));
        assert!(claims.email_verified.unwrap().as_bool());
        assert_eq!(claims.name.as_deref(), Some("Some One"));

        // Wrong nonce.
        assert!(matches!(
            verify_id_token_with_jwk(&jwk, &ok, cid, "nonce-2"),
            Err(GoogleSigninError::NonceMismatch)
        ));
        // Wrong audience.
        let other = sign_google_token(&key, "kid-1", &google_claims("someone-else", "nonce-1"));
        assert!(verify_id_token_with_jwk(&jwk, &other, cid, "nonce-1").is_err());
        // Wrong issuer.
        let mut c = google_claims(cid, "nonce-1");
        c["iss"] = serde_json::json!("https://evil.example");
        let bad_iss = sign_google_token(&key, "kid-1", &c);
        assert!(verify_id_token_with_jwk(&jwk, &bad_iss, cid, "nonce-1").is_err());
        // Bare-host issuer form is accepted.
        let mut c = google_claims(cid, "nonce-1");
        c["iss"] = serde_json::json!("accounts.google.com");
        let bare = sign_google_token(&key, "kid-1", &c);
        assert!(verify_id_token_with_jwk(&jwk, &bare, cid, "nonce-1").is_ok());
        // Expired.
        let mut c = google_claims(cid, "nonce-1");
        c["exp"] = serde_json::json!(Utc::now().timestamp() - 3600);
        let expired = sign_google_token(&key, "kid-1", &c);
        assert!(verify_id_token_with_jwk(&jwk, &expired, cid, "nonce-1").is_err());
        // Wrong key.
        let (other_key, _) = test_keypair("kid-1");
        let forged = sign_google_token(&other_key, "kid-1", &google_claims(cid, "nonce-1"));
        assert!(verify_id_token_with_jwk(&jwk, &forged, cid, "nonce-1").is_err());
    }

    #[test]
    fn normalize_email_lowercases_and_trims() {
        assert_eq!(
            normalize_email("  Someone@Example.com "),
            "someone@example.com"
        );
        assert_eq!(normalize_email("plain@example.com"), "plain@example.com");
    }

    #[test]
    fn email_verified_accepts_string_form() {
        let v: GoogleIdTokenClaims = serde_json::from_value(serde_json::json!({
            "iss": "accounts.google.com", "sub": "1", "aud": "a", "iat": 1, "exp": 2,
            "email_verified": "true"
        }))
        .unwrap();
        assert!(v.email_verified.unwrap().as_bool());
    }

    /// Minimal stand-in for Google's token + JWKS endpoints.
    async fn mock_google(jwk: Jwk, id_token: String) -> String {
        use axum::routing::{get, post};
        let jwks = serde_json::json!({ "keys": [jwk] });
        let app = axum::Router::new()
            .route(
                "/token",
                post(move |body: String| async move {
                    assert!(body.contains("grant_type=authorization_code"), "{body}");
                    assert!(body.contains("code=gcode"), "{body}");
                    axum::Json(serde_json::json!({
                        "access_token": "ya29.x", "expires_in": 3599,
                        "token_type": "Bearer", "id_token": id_token
                    }))
                }),
            )
            .route("/certs", get(move || async move { axum::Json(jwks) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    async fn test_app_state() -> AppState {
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
            std::env::set_var("AWS_ACCESS_KEY_ID", "fake_access_key");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "fake_secret_key");
            // Closed local port so the account lookup fails fast.
            std::env::set_var("AWS_ENDPOINT_URL_DYNAMODB", "http://127.0.0.1:1");
        }
        crate::test_helpers::build_test_app_state().await
    }

    #[tokio::test]
    async fn callback_unknown_state_is_400() {
        let google = Arc::new(GoogleSignin::new(
            Some(test_config("https://google.test")),
            test_redis(),
            std::time::Duration::from_secs(1),
        ));
        let resp = google_callback_handler(
            Extension(test_app_state().await),
            Extension(google),
            Extension(AuthorizationCodeStore::new(test_redis())),
            Query(GoogleCallbackQuery {
                state: Some("nope".into()),
                code: Some("gcode".into()),
                error: None,
                error_description: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn callback_upstream_denial_is_reported_to_rp() {
        let google = Arc::new(GoogleSignin::new(
            Some(test_config("https://google.test")),
            test_redis(),
            std::time::Duration::from_secs(1),
        ));
        google
            .pending_store()
            .insert(
                "gstate",
                PendingAuthorize {
                    request: test_request(),
                    google_nonce: "gn".into(),
                    expires_at: Utc::now().timestamp() + 60,
                },
            )
            .await
            .unwrap();
        let resp = google_callback_handler(
            Extension(test_app_state().await),
            Extension(google),
            Extension(AuthorizationCodeStore::new(test_redis())),
            Query(GoogleCallbackQuery {
                state: Some("gstate".into()),
                code: None,
                error: Some("access_denied".into()),
                error_description: Some("user said no".into()),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        let loc = location(&resp);
        assert!(loc.starts_with("com.closurekb:/oauth2redirect?"), "{loc}");
        assert!(loc.contains("error=access_denied"), "{loc}");
        assert!(loc.contains("state=rp-state-123"), "{loc}");
    }

    #[tokio::test]
    async fn callback_exchanges_code_and_verifies_id_token() {
        let (key, jwk) = test_keypair("kid-live");
        let cid = "google-client-id.apps.googleusercontent.com";
        let id_token = sign_google_token(&key, "kid-live", &google_claims(cid, "gn"));
        let base = mock_google(jwk, id_token).await;

        let google = Arc::new(GoogleSignin::new(
            Some(test_config(&base)),
            test_redis(),
            std::time::Duration::from_secs(5),
        ));
        google
            .pending_store()
            .insert(
                "gstate",
                PendingAuthorize {
                    request: test_request(),
                    google_nonce: "gn".into(),
                    expires_at: Utc::now().timestamp() + 60,
                },
            )
            .await
            .unwrap();

        let resp = google_callback_handler(
            Extension(test_app_state().await),
            Extension(google.clone()),
            Extension(AuthorizationCodeStore::new(test_redis())),
            Query(GoogleCallbackQuery {
                state: Some("gstate".into()),
                code: Some("gcode".into()),
                error: None,
                error_description: None,
            }),
        )
        .await;
        // Code exchange + id_token verification succeeded; the only thing
        // standing between us and an authorization code is DynamoDB, which
        // is deliberately unreachable here, so the RP gets server_error
        // (not access_denied, which is what a rejected id_token yields).
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        let loc = location(&resp);
        assert!(loc.starts_with("com.closurekb:/oauth2redirect?"), "{loc}");
        assert!(loc.contains("error=server_error"), "{loc}");
        assert!(loc.contains("state=rp-state-123"), "{loc}");
        // Parked request was consumed.
        assert!(
            google
                .pending_store()
                .take("gstate")
                .await
                .unwrap()
                .is_none()
        );

        // A wrong nonce on the parked request must be refused as access_denied.
        google
            .pending_store()
            .insert(
                "gstate2",
                PendingAuthorize {
                    request: test_request(),
                    google_nonce: "different".into(),
                    expires_at: Utc::now().timestamp() + 60,
                },
            )
            .await
            .unwrap();
        let resp = google_callback_handler(
            Extension(test_app_state().await),
            Extension(google),
            Extension(AuthorizationCodeStore::new(test_redis())),
            Query(GoogleCallbackQuery {
                state: Some("gstate2".into()),
                code: Some("gcode".into()),
                error: None,
                error_description: None,
            }),
        )
        .await;
        assert!(location(&resp).contains("error=access_denied"));
    }
}
