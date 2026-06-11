// `Key::<Aes256Gcm>::from_slice` is the documented constructor on the
// aes-gcm 0.10.x release line but fires a transitive deprecation warning
// from generic-array 0.x. Tracked upstream; until aes-gcm rolls forward to
// generic-array 1.x we suppress at the module level instead of polluting
// each call site.
#![allow(deprecated)]

//! Patreon identity linking + membership materialization.
//!
//! This module mirrors the [`apple_signin`](crate::apple_signin) linking
//! pattern for Patreon as an upstream identity / entitlement source. Unlike
//! Apple, Patreon does not issue an id_token; it uses OAuth2 authorization
//! code flow. The end result is the same shape: the verified Patreon
//! identifier is bound to an arkavo user in the `identity_links` table
//! (per the Apple linking contract — minimum-PII, one-Patreon-account-to-one
//! arkavo-user enforced by a conditional put).
//!
//! # Architecture
//!
//! - **Linking** (`POST /oauth/patreon/link`): auth-required handler that
//!   accepts an OAuth `code` returned from `www.patreon.com/oauth2/authorize`,
//!   exchanges it for Patreon access/refresh tokens server-side, fetches
//!   `/api/oauth2/v2/identity` to discover the Patreon user id (and, for
//!   creators, their campaign id), then persists two rows:
//!
//!   1. `identity_links`: `patreon#<patreon_user_id> → arkavo_user_id`
//!      conditional put — provides per-Patreon-account uniqueness and an
//!      audit-traceable join key. Same shape as Apple linking.
//!   2. `patreon_tokens`: the encrypted access + refresh tokens keyed by
//!      arkavo `user_id`, plus the discovered `patreon_user_id` and (creator
//!      only) `campaign_id`.
//!
//! - **Token sealing**: KMS envelope encryption. Tokens are AES-256-GCM
//!   encrypted under a fresh per-row 256-bit DEK; the DEK itself is wrapped
//!   by an operator-configured KMS key. This means a DynamoDB compromise
//!   alone is insufficient to recover the Patreon tokens — an attacker also
//!   needs `kms:Decrypt` permission on the key.
//!
//! - **Membership materialization**: there is no separate
//!   `/entitlements/...` endpoint surface. Patreon membership and tier
//!   claims are emitted *only* inside the OIDC access_token CWT, via
//!   [`materialize_for_user`]. The materialization is cached in Redis (with
//!   a fallback in-memory map) for [`crate::constants::PATREON_CACHE_TTL_SECONDS`]
//!   so we don't hammer Patreon on every token mint; the cached snapshot
//!   carries `verified_at` / `cache_expires_at` so RPs can detect stale data.
//!
//! # Failure posture
//!
//! Fail-closed for membership: when Patreon is unreachable, the linked-user
//! lookup fails, or the cached snapshot is past `cache_expires_at`, the
//! mint path omits the `arkavo_patreon` claim entirely. Downstream KAS /
//! policy enforcers must treat absence of the claim as "no entitlement",
//! per the architecture statement "Patreon proves membership."
//!
//! # No new endpoint surface beyond linking
//!
//! The deliberate design constraint here is that the *only* new external
//! endpoint is `POST /oauth/patreon/link` (mirroring `POST /oauth/apple/link`).
//! Status, entitlement, and membership-check endpoints are intentionally
//! omitted — relying parties read everything they need from the
//! access_token CWT.

use crate::AppState;
use crate::constants::{
    PATREON_CACHE_TTL_SECONDS, PATREON_CAMPAIGN_MEMBERS_URL_TEMPLATE, PATREON_IDENTITY_URL,
    PATREON_TOKEN_URL,
};
use crate::cwt::{ArkavoPatreon, ArkavoPatreonMembership};
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aws_sdk_kms::primitives::Blob;
use axum::Json;
use axum::extract::Extension;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use fred::interfaces::{ClientLike, KeysInterface};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use uuid::Uuid;

/// One registered Patreon OAuth client (Patreon issues one client per app,
/// so multi-app deployments carry several).
#[derive(Debug, Clone)]
pub struct PatreonClient {
    pub client_id: String,
    pub client_secret: String,
    /// Allow-list of permitted redirect URIs for *this* client. Must contain
    /// whatever the app used at `https://www.patreon.com/oauth2/authorize`.
    pub redirect_uris: Vec<String>,
}

/// Patreon OAuth configuration. Loaded once at startup from env vars.
///
/// Empty/missing config disables every Patreon code path silently — link
/// handler returns 503, membership materialization is skipped. This lets
/// non-Patreon deployments run without forcing operators to set Patreon
/// credentials.
///
/// Two env forms, combinable (mirrors the `OIDC_CLIENT_<TAG>_*` pattern):
///
/// ```text
///   # Legacy single client:
///   PATREON_CLIENT_ID / PATREON_CLIENT_SECRET / PATREON_REDIRECT_URIS
///
///   # Tagged clients (one Patreon client per app):
///   PATREON_CLIENT_<TAG>_ID            = the Patreon client id
///   PATREON_CLIENT_<TAG>_SECRET        = the Patreon client secret
///   PATREON_CLIENT_<TAG>_REDIRECT_URIS = comma-separated redirect URIs
/// ```
///
/// The link request's `redirect_uri` selects which client's credentials are
/// used for the code exchange, so a redirect URI may belong to only one
/// client. Any malformed tag, duplicate client_id, or redirect URI claimed
/// by two clients disables Patreon entirely (loud warn, fail-closed) rather
/// than guessing which credentials to use.
#[derive(Debug, Clone)]
pub struct PatreonOAuthConfig {
    pub clients: Vec<PatreonClient>,
}

impl PatreonOAuthConfig {
    pub fn from_env() -> Option<Self> {
        Self::from_env_vars(env::vars())
    }

    /// Parse from a `(key, value)` iterator (testable without process env).
    fn from_env_vars<I>(vars: I) -> Option<Self>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let env_map: std::collections::HashMap<String, String> =
            vars.into_iter().filter(|(_, v)| !v.is_empty()).collect();
        let mut clients: Vec<PatreonClient> = Vec::new();

        // Legacy untagged trio. (`PATREON_CLIENT_ID` cannot collide with the
        // tag scan below: its post-prefix remainder `ID` has no `_ID` suffix.)
        if let Some(client_id) = env_map.get("PATREON_CLIENT_ID") {
            let Some(client_secret) = env_map.get("PATREON_CLIENT_SECRET") else {
                warn!(
                    "PATREON_CLIENT_ID is set but PATREON_CLIENT_SECRET is missing — Patreon disabled"
                );
                return None;
            };
            let redirect_uris = split_uris(env_map.get("PATREON_REDIRECT_URIS"));
            if redirect_uris.is_empty() {
                warn!(
                    "PATREON_CLIENT_ID is set but PATREON_REDIRECT_URIS is empty — \
                     /oauth/patreon/link would reject all callbacks; Patreon disabled"
                );
                return None;
            }
            clients.push(PatreonClient {
                client_id: client_id.clone(),
                client_secret: client_secret.clone(),
                redirect_uris,
            });
        }

        // Tagged clients: PATREON_CLIENT_<TAG>_ID anchors each registration.
        let mut tags: Vec<String> = env_map
            .keys()
            .filter_map(|k| {
                k.strip_prefix("PATREON_CLIENT_")
                    .and_then(|rest| rest.strip_suffix("_ID"))
                    .filter(|tag| !tag.is_empty())
                    .map(|s| s.to_string())
            })
            .collect();
        tags.sort(); // deterministic order regardless of env iteration
        for tag in tags {
            let client_id = env_map[&format!("PATREON_CLIENT_{}_ID", tag)].clone();
            let Some(client_secret) = env_map
                .get(&format!("PATREON_CLIENT_{}_SECRET", tag))
                .cloned()
            else {
                warn!(
                    "PATREON_CLIENT_{}_ID is set but PATREON_CLIENT_{}_SECRET is missing — Patreon disabled",
                    tag, tag
                );
                return None;
            };
            let redirect_uris =
                split_uris(env_map.get(&format!("PATREON_CLIENT_{}_REDIRECT_URIS", tag)));
            if redirect_uris.is_empty() {
                warn!(
                    "PATREON_CLIENT_{}_ID is set but PATREON_CLIENT_{}_REDIRECT_URIS is empty — Patreon disabled",
                    tag, tag
                );
                return None;
            }
            clients.push(PatreonClient {
                client_id,
                client_secret,
                redirect_uris,
            });
        }

        if clients.is_empty() {
            return None;
        }

        // Reject ambiguity rather than guessing: duplicate client_ids and
        // redirect URIs shared across clients both make credential selection
        // ill-defined.
        let mut seen_ids = std::collections::HashSet::new();
        let mut seen_uris = std::collections::HashSet::new();
        for c in &clients {
            if !seen_ids.insert(c.client_id.clone()) {
                warn!(
                    "Duplicate Patreon client_id configured under multiple tags — Patreon disabled"
                );
                return None;
            }
            for u in &c.redirect_uris {
                if !seen_uris.insert(u.clone()) {
                    warn!(
                        "Patreon redirect URI {} is claimed by more than one client — Patreon disabled",
                        u
                    );
                    return None;
                }
            }
        }

        Some(Self { clients })
    }

    /// The client registered for this redirect URI, if any. Used by the link
    /// endpoint to pick which credentials perform the code exchange.
    pub fn client_for_redirect(&self, redirect_uri: &str) -> Option<&PatreonClient> {
        self.clients
            .iter()
            .find(|c| c.redirect_uris.iter().any(|u| u == redirect_uri))
    }

    /// The client that issued a stored token bundle (refresh needs the same
    /// client's secret). Rows written before multi-client support carry no
    /// client_id; tolerate that only while a single client is configured.
    pub fn client_by_id(&self, client_id: &str) -> Option<&PatreonClient> {
        if client_id.is_empty() && self.clients.len() == 1 {
            return self.clients.first();
        }
        self.clients.iter().find(|c| c.client_id == client_id)
    }
}

fn split_uris(raw: Option<&String>) -> Vec<String> {
    raw.map(|raw| {
        raw.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

/// KMS envelope sealer for Patreon access/refresh tokens.
///
/// `Kms` is the production variant. In tests we substitute a plaintext sealer
/// that still produces valid-shape `wrapped_dek` / `nonce` / `ct` bytes so
/// the surrounding DynamoDB CRUD can be exercised without a real KMS call.
#[derive(Clone)]
pub enum TokenSealer {
    Kms {
        client: aws_sdk_kms::Client,
        key_id: String,
    },
    #[cfg(test)]
    Plaintext, // ONLY for tests; stores DEK alongside ciphertext, no wrapping.
}

impl std::fmt::Debug for TokenSealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kms { key_id, .. } => f.debug_struct("Kms").field("key_id", key_id).finish(),
            #[cfg(test)]
            Self::Plaintext => write!(f, "Plaintext"),
        }
    }
}

/// One sealed plaintext: (wrapped DEK, nonce, ciphertext).
#[derive(Debug, Clone)]
pub struct SealedToken {
    pub wrapped_dek: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl TokenSealer {
    /// Seal a single plaintext token. Generates a fresh DEK so multiple
    /// tokens stored together don't share a DEK + nonce reuse risk.
    pub async fn seal(&self, plaintext: &[u8]) -> Result<SealedToken, PatreonError> {
        match self {
            TokenSealer::Kms { client, key_id } => {
                let mut dek = [0u8; 32];
                use aes_gcm::aead::rand_core::RngCore;
                OsRng.fill_bytes(&mut dek);

                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
                let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
                let ciphertext = cipher
                    .encrypt(&nonce_bytes, plaintext)
                    .map_err(|_| PatreonError::Crypto("AES-256-GCM encrypt failed".into()))?;

                let wrap_resp = client
                    .encrypt()
                    .key_id(key_id)
                    .plaintext(Blob::new(dek.to_vec()))
                    .send()
                    .await
                    .map_err(|e| PatreonError::Kms(format!("Encrypt: {}", e)))?;
                let wrapped_dek = wrap_resp
                    .ciphertext_blob
                    .ok_or_else(|| PatreonError::Kms("missing ciphertext_blob".into()))?
                    .into_inner();

                // Zeroize the DEK eagerly; it has done its job. (Best-effort
                // overwrite — `dek` is a stack array, no allocation tracking.)
                for b in dek.iter_mut() {
                    *b = 0;
                }

                Ok(SealedToken {
                    wrapped_dek,
                    nonce: nonce_bytes.to_vec(),
                    ciphertext,
                })
            }
            #[cfg(test)]
            TokenSealer::Plaintext => {
                let dek = [0u8; 32];
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
                let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
                let ciphertext = cipher
                    .encrypt(&nonce_bytes, plaintext)
                    .map_err(|_| PatreonError::Crypto("test sealer encrypt".into()))?;
                // "Wrapped" DEK is the zero key itself so open() can recover it.
                Ok(SealedToken {
                    wrapped_dek: dek.to_vec(),
                    nonce: nonce_bytes.to_vec(),
                    ciphertext,
                })
            }
        }
    }

    pub async fn open(&self, sealed: &SealedToken) -> Result<Vec<u8>, PatreonError> {
        let dek = match self {
            TokenSealer::Kms { client, .. } => {
                let resp = client
                    .decrypt()
                    .ciphertext_blob(Blob::new(sealed.wrapped_dek.clone()))
                    .send()
                    .await
                    .map_err(|e| PatreonError::Kms(format!("Decrypt: {}", e)))?;
                let bytes = resp
                    .plaintext
                    .ok_or_else(|| PatreonError::Kms("missing plaintext".into()))?
                    .into_inner();
                if bytes.len() != 32 {
                    return Err(PatreonError::Crypto(format!(
                        "DEK length {} != 32",
                        bytes.len()
                    )));
                }
                let mut dek = [0u8; 32];
                dek.copy_from_slice(&bytes);
                dek
            }
            #[cfg(test)]
            TokenSealer::Plaintext => {
                if sealed.wrapped_dek.len() != 32 {
                    return Err(PatreonError::Crypto("test DEK len".into()));
                }
                let mut dek = [0u8; 32];
                dek.copy_from_slice(&sealed.wrapped_dek);
                dek
            }
        };
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
        if sealed.nonce.len() != 12 {
            return Err(PatreonError::Crypto("nonce length != 12".into()));
        }
        let nonce = Nonce::from_slice(&sealed.nonce);
        cipher
            .decrypt(nonce, sealed.ciphertext.as_slice())
            .map_err(|_| PatreonError::Crypto("AES-256-GCM decrypt failed".into()))
    }
}

/// Build the [`TokenSealer`] from env (`PATREON_KMS_KEY_ID`) + an existing
/// AWS SDK shared config. Returns `None` if Patreon support is disabled
/// (no `PATREON_KMS_KEY_ID`).
pub async fn build_kms_sealer() -> Option<TokenSealer> {
    let key_id = env::var("PATREON_KMS_KEY_ID")
        .ok()
        .filter(|s| !s.is_empty())?;
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_kms::Client::new(&config);
    Some(TokenSealer::Kms { client, key_id })
}

/// Holder for Patreon runtime state. Carried as an Axum `Extension` so all
/// patreon handlers + the OIDC mint enrichment can find it.
#[derive(Clone)]
pub struct PatreonState {
    pub oauth: Option<PatreonOAuthConfig>,
    pub sealer: Option<TokenSealer>,
    pub http: reqwest::Client,
    pub cache: MembershipCache,
    /// Patreon OAuth2 token endpoint. Defaults to the production constant;
    /// overridable so tests (and staging) can point at a local/sandbox server.
    pub token_url: String,
    /// Patreon API v2 identity endpoint (base, without query). See `token_url`.
    pub identity_url: String,
}

impl PatreonState {
    pub fn new(
        oauth: Option<PatreonOAuthConfig>,
        sealer: Option<TokenSealer>,
        redis: fred::clients::RedisClient,
    ) -> Self {
        Self {
            oauth,
            sealer,
            http: reqwest::Client::builder()
                .user_agent("authnz-rs/0.6")
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            cache: MembershipCache::new(redis),
            token_url: PATREON_TOKEN_URL.to_string(),
            identity_url: PATREON_IDENTITY_URL.to_string(),
        }
    }

    fn is_enabled(&self) -> bool {
        self.oauth.is_some() && self.sealer.is_some()
    }
}

#[derive(Debug, Error)]
pub enum PatreonError {
    #[error("Patreon integration is not configured on this server")]
    NotConfigured,
    #[error("redirect_uri is not in the operator-configured allow list")]
    InvalidRedirectUri,
    #[error("role must be \"creator\" or \"consumer\"")]
    InvalidRole,
    #[error("role=creator but no Patreon campaign is owned by this account")]
    NoCampaign,
    #[error("Patreon rejected the authorization code (expired, replayed, or invalid)")]
    InvalidGrant,
    #[error("missing or invalid X-Auth-Token")]
    MissingAuth,
    #[error("Patreon API error: {0}")]
    Api(String),
    #[error("Patreon rejected the access token (expired or revoked)")]
    Unauthorized,
    #[error("KMS error: {0}")]
    Kms(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("DynamoDB error: {0}")]
    Db(String),
    #[error("Patreon identity already linked to a different arkavo user")]
    LinkConflict,
    #[allow(dead_code)]
    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for PatreonError {
    fn into_response(self) -> Response {
        let status = match &self {
            PatreonError::NotConfigured => StatusCode::SERVICE_UNAVAILABLE,
            PatreonError::InvalidRedirectUri
            | PatreonError::InvalidRole
            | PatreonError::NoCampaign
            | PatreonError::InvalidGrant => StatusCode::BAD_REQUEST,
            PatreonError::MissingAuth => StatusCode::UNAUTHORIZED,
            // A Patreon-side 401 is an upstream/token problem, not a problem
            // with the *caller's* request to us → surface as BAD_GATEWAY. In
            // the materialization path this is caught and triggers a refresh
            // before it can become a response.
            PatreonError::Api(_) | PatreonError::Unauthorized => StatusCode::BAD_GATEWAY,
            PatreonError::LinkConflict => StatusCode::CONFLICT,
            PatreonError::Kms(_)
            | PatreonError::Crypto(_)
            | PatreonError::Db(_)
            | PatreonError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        // Only expose safe, pre-defined messages to clients. The `Api`, `Kms`,
        // `Crypto`, and `Db` variants embed raw upstream diagnostics (KMS ARNs,
        // DynamoDB internals, Patreon response bodies) — those stay in the
        // server logs (already emitted via error!/warn! at the call sites) and
        // must never reach the wire.
        let body: &str = match &self {
            PatreonError::NotConfigured => "Patreon integration is not configured",
            PatreonError::InvalidRedirectUri => "redirect_uri is not in the allow list",
            PatreonError::InvalidRole => "role must be \"creator\" or \"consumer\"",
            PatreonError::NoCampaign => {
                "role=creator but no Patreon campaign is owned by this account"
            }
            PatreonError::InvalidGrant => {
                "Patreon rejected the authorization code (expired, replayed, or invalid)"
            }
            PatreonError::MissingAuth => "missing or invalid X-Auth-Token",
            PatreonError::LinkConflict => {
                "Patreon identity already linked to a different arkavo user"
            }
            PatreonError::Api(_) => "upstream Patreon request failed",
            PatreonError::Unauthorized => "Patreon rejected the access token",
            PatreonError::Kms(_) | PatreonError::Crypto(_) | PatreonError::Db(_) => {
                "internal error"
            }
            PatreonError::Internal(_) => "internal error",
        };
        (status, body.to_string()).into_response()
    }
}

/// Persisted Patreon token bundle for an arkavo user.
///
/// Keyed by `user_id` in DynamoDB (`patreon_tokens` table). The token bytes
/// are KMS-envelope-encrypted; the same `wrapped_dek` is reused for both
/// access and refresh tokens (one DEK per row, distinct GCM nonces per
/// token — never reuse nonce + key).
#[derive(Debug, Clone)]
pub struct PatreonLink {
    pub user_id: Uuid,
    /// `creator` or `consumer`.
    pub role: String,
    /// The Patreon client_id whose code exchange produced this token bundle.
    /// Refresh must present the same client's secret. Empty on rows written
    /// before multi-client support.
    pub client_id: String,
    pub patreon_user_id: String,
    pub campaign_id: Option<String>,
    pub scopes: String,
    pub access_token_ct: Vec<u8>,
    pub access_token_nonce: Vec<u8>,
    pub refresh_token_ct: Vec<u8>,
    pub refresh_token_nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub token_expires_at: i64,
    pub linked_at: i64,
}

// --------- Linking endpoint ---------

#[derive(Debug, Deserialize)]
pub struct LinkRequest {
    /// OAuth authorization code returned by Patreon to the client's redirect
    /// URI.
    pub code: String,
    /// Redirect URI used during the authorize step. Must match an entry in
    /// `PATREON_REDIRECT_URIS`.
    pub redirect_uri: String,
    /// `creator` or `consumer`. Determines which scopes are persisted and
    /// whether `campaign_id` discovery runs.
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct LinkResponse {
    pub patreon_user_id: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub campaign_id: Option<String>,
}

/// `POST /oauth/patreon/link`
///
/// Auth-required. Mirrors `POST /oauth/apple/link`:
/// - Caller must present a valid Arkavo CWT in `X-Auth-Token` (this is the
///   arkavo user_id that the Patreon identity will be bound to).
/// - On success, writes both `identity_links` (patreon#sub → user_id,
///   conditional put for uniqueness) and `patreon_tokens` (encrypted tokens
///   keyed by user_id).
/// - 200 on success (or idempotent re-link to the same user).
/// - 409 if this Patreon account is already linked to a *different* arkavo
///   user (cross-account-hijack guard).
/// - 502 if Patreon's token / identity endpoint rejects the exchange.
/// - 503 if Patreon support is not configured on this deployment.
pub async fn patreon_link_handler(
    Extension(app_state): Extension<AppState>,
    Extension(state): Extension<PatreonState>,
    headers: HeaderMap,
    Json(req): Json<LinkRequest>,
) -> Response {
    let client_ip = client_ip_from_headers(&headers);

    let user_id = match extract_authenticated_user_id(&app_state, &headers) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    if !state.is_enabled() {
        return PatreonError::NotConfigured.into_response();
    }
    let oauth = state.oauth.as_ref().unwrap();
    let sealer = state.sealer.as_ref().unwrap();

    let role = match req.role.as_str() {
        "creator" | "consumer" => req.role.clone(),
        _ => return PatreonError::InvalidRole.into_response(),
    };

    // The redirect_uri selects which registered Patreon client's credentials
    // perform the exchange (Patreon issues one client per app).
    let Some(client) = oauth.client_for_redirect(&req.redirect_uri) else {
        return PatreonError::InvalidRedirectUri.into_response();
    };

    // 1. Exchange the code for tokens.
    let tokens = match exchange_code_for_tokens(
        &state.http,
        client,
        &req.code,
        &req.redirect_uri,
        &state.token_url,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            warn!("Patreon code exchange failed: {}", e);
            return e.into_response();
        }
    };

    // 2. Discover patreon_user_id (+ campaign_id for creators).
    let (patreon_user_id, campaign_id) = match fetch_identity(
        &state.http,
        &tokens.access_token,
        role.as_str() == "creator",
        &state.identity_url,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("Patreon identity fetch failed: {}", e);
            return e.into_response();
        }
    };

    // role is client-asserted; refuse to persist a creator link with no owned
    // campaign (it would materialize empty entitlements forever).
    if let Err(e) = validate_creator_campaign(&role, &campaign_id) {
        warn!(
            "Patreon link rejected: role=creator but no campaign for subject_prefix={}",
            subject_prefix(&patreon_user_id)
        );
        return e.into_response();
    }

    // 3. Persist the link. identity_links first (uniqueness check), then
    //    patreon_tokens. Order matters: identity_links is the per-Patreon-
    //    account guard; only after we know we own the binding do we encrypt
    //    and store the tokens.
    let sub_prefix = subject_prefix(&patreon_user_id);
    match app_state
        .db_store
        .link_identity(user_id, "patreon", &patreon_user_id)
        .await
    {
        Ok(()) => info!(
            "audit identity_link outcome=linked user_id={} provider=patreon role={} subject_prefix={} client_ip={}",
            user_id, role, sub_prefix, client_ip
        ),
        Err(crate::db::DynamoDBError::LinkConflict) => {
            warn!(
                "audit identity_link outcome=conflict user_id={} provider=patreon role={} subject_prefix={} client_ip={}",
                user_id, role, sub_prefix, client_ip
            );
            return PatreonError::LinkConflict.into_response();
        }
        Err(e) => {
            error!("Failed to write identity_link for Patreon: {}", e);
            return PatreonError::Db("identity_link_write_failed".into()).into_response();
        }
    }

    // Encrypt both tokens. Per the design note above, the access and refresh
    // ciphertexts get their own nonces but share a DEK to keep storage small.
    let now = Utc::now().timestamp();
    let token_expires_at = now + tokens.expires_in;

    let sealed_access = match sealer.seal(tokens.access_token.as_bytes()).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let sealed_refresh = match seal_under_existing_dek(
        sealer,
        &sealed_access.wrapped_dek,
        tokens.refresh_token.as_bytes(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };

    let link = PatreonLink {
        user_id,
        role: role.clone(),
        client_id: client.client_id.clone(),
        patreon_user_id: patreon_user_id.clone(),
        campaign_id: campaign_id.clone(),
        scopes: tokens.scope.clone(),
        access_token_ct: sealed_access.ciphertext,
        access_token_nonce: sealed_access.nonce,
        refresh_token_ct: sealed_refresh.ciphertext,
        refresh_token_nonce: sealed_refresh.nonce,
        wrapped_dek: sealed_access.wrapped_dek,
        token_expires_at,
        linked_at: now,
    };

    if let Err(e) = app_state.db_store.put_patreon_link(&link).await {
        error!("Failed to persist patreon_tokens row: {}", e);
        return PatreonError::Db("patreon_tokens_write_failed".into()).into_response();
    }

    // Invalidate any cached materialization so the next access-token mint
    // picks up the freshly-linked memberships.
    state.cache.invalidate(user_id).await;

    Json(LinkResponse {
        patreon_user_id,
        role,
        campaign_id,
    })
    .into_response()
}

/// Seal a second plaintext under the same DEK as a previously-sealed token.
///
/// Used so the access + refresh tokens in a row share one wrapped DEK
/// (saving a second KMS round-trip per link). Distinct GCM nonces are
/// generated per call, so the (key, nonce) pair is never reused.
async fn seal_under_existing_dek(
    sealer: &TokenSealer,
    wrapped_dek: &[u8],
    plaintext: &[u8],
) -> Result<SealedToken, PatreonError> {
    // Recover the DEK by asking the sealer to open just the wrapped DEK
    // (using an empty ciphertext is not portable; instead we round-trip a
    // throwaway plaintext to get back the DEK).
    //
    // Implementation: re-decrypt the wrapped_dek directly.
    let dek = match sealer {
        TokenSealer::Kms { client, .. } => {
            let resp = client
                .decrypt()
                .ciphertext_blob(Blob::new(wrapped_dek.to_vec()))
                .send()
                .await
                .map_err(|e| PatreonError::Kms(format!("Decrypt: {}", e)))?;
            resp.plaintext
                .ok_or_else(|| PatreonError::Kms("missing plaintext".into()))?
                .into_inner()
        }
        #[cfg(test)]
        TokenSealer::Plaintext => wrapped_dek.to_vec(),
    };
    if dek.len() != 32 {
        return Err(PatreonError::Crypto("recovered DEK len != 32".into()));
    }
    let key = Key::<Aes256Gcm>::from_slice(&dek);
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce_bytes, plaintext)
        .map_err(|_| PatreonError::Crypto("AES-256-GCM encrypt failed".into()))?;
    Ok(SealedToken {
        wrapped_dek: wrapped_dek.to_vec(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

// --------- Patreon HTTP client ---------

#[derive(Debug, Clone, Deserialize)]
struct PatreonTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub token_type: String,
}

/// Classify a non-success Patreon token-endpoint response. Only a 400 reflects
/// a bad `code`/`redirect_uri` (the caller's fault) → InvalidGrant. Other 4xx
/// are *not* the caller's problem — 429 means Patreon is rate-limiting us,
/// 401/403 mean our client credentials are misconfigured — so they route
/// through `Api` (502) with diagnostics preserved for the logs.
fn token_exchange_error(status: reqwest::StatusCode, body: &str) -> PatreonError {
    if status == reqwest::StatusCode::BAD_REQUEST {
        PatreonError::InvalidGrant
    } else {
        PatreonError::Api(format!(
            "token endpoint returned {}: {}",
            status,
            truncate(body, 256)
        ))
    }
}

/// Build the updated [`PatreonLink`] after a successful token refresh. Keeps
/// the immutable identity fields (user, Patreon user/campaign, role,
/// `linked_at`) and swaps in the freshly-sealed access/refresh ciphertexts,
/// new scopes, and recomputed expiry. Patreon rotates the refresh token on
/// every refresh, so both ciphertexts are replaced.
fn merge_refreshed_link(
    old: &PatreonLink,
    new_tokens: &PatreonTokenResponse,
    sealed_access: SealedToken,
    sealed_refresh: SealedToken,
    now: i64,
) -> PatreonLink {
    PatreonLink {
        user_id: old.user_id,
        role: old.role.clone(),
        client_id: old.client_id.clone(),
        patreon_user_id: old.patreon_user_id.clone(),
        campaign_id: old.campaign_id.clone(),
        scopes: new_tokens.scope.clone(),
        access_token_ct: sealed_access.ciphertext,
        access_token_nonce: sealed_access.nonce,
        refresh_token_ct: sealed_refresh.ciphertext,
        refresh_token_nonce: sealed_refresh.nonce,
        wrapped_dek: sealed_access.wrapped_dek,
        token_expires_at: now + new_tokens.expires_in,
        linked_at: old.linked_at,
    }
}

/// Classify a non-success Patreon `/identity` (or membership) response. A 401
/// means our stored access token is stale/revoked and the caller may refresh;
/// everything else is an opaque upstream failure.
fn identity_fetch_error(status: reqwest::StatusCode, body: &str) -> PatreonError {
    if status == reqwest::StatusCode::UNAUTHORIZED {
        PatreonError::Unauthorized
    } else {
        PatreonError::Api(format!(
            "identity endpoint returned {}: {}",
            status,
            truncate(body, 256)
        ))
    }
}

async fn exchange_code_for_tokens(
    http: &reqwest::Client,
    client: &PatreonClient,
    code: &str,
    redirect_uri: &str,
    token_url: &str,
) -> Result<PatreonTokenResponse, PatreonError> {
    let form = [
        ("code", code),
        ("grant_type", "authorization_code"),
        ("client_id", client.client_id.as_str()),
        ("client_secret", client.client_secret.as_str()),
        ("redirect_uri", redirect_uri),
    ];
    let resp = http
        .post(token_url)
        .form(&form)
        .send()
        .await
        .map_err(|e| PatreonError::Api(format!("token POST: {}", e)))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(token_exchange_error(status, &body));
    }
    resp.json::<PatreonTokenResponse>()
        .await
        .map_err(|e| PatreonError::Api(format!("token JSON parse: {}", e)))
}

/// Refresh a Patreon access token using its refresh token. Wired into
/// `materialize_from_link`: a consumer membership fetch that returns 401
/// triggers refresh-and-retry, and the caller persists the rotated tokens.
async fn refresh_access_token(
    http: &reqwest::Client,
    client: &PatreonClient,
    refresh_token: &str,
    token_url: &str,
) -> Result<PatreonTokenResponse, PatreonError> {
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client.client_id.as_str()),
        ("client_secret", client.client_secret.as_str()),
    ];
    let resp = http
        .post(token_url)
        .form(&form)
        .send()
        .await
        .map_err(|e| PatreonError::Api(format!("refresh POST: {}", e)))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(PatreonError::Api(format!(
            "refresh endpoint returned {}: {}",
            status,
            truncate(&body, 256)
        )));
    }
    resp.json::<PatreonTokenResponse>()
        .await
        .map_err(|e| PatreonError::Api(format!("refresh JSON parse: {}", e)))
}

/// Build the `/identity` URL from a base. Creators add the `campaign`
/// relationship so we can discover the owned campaign id; consumers need none
/// of it. We never request the `email` field — minimum-PII, never read.
fn build_identity_url(base: &str, is_creator: bool) -> String {
    if is_creator {
        format!("{}?include=campaign", base)
    } else {
        base.to_string()
    }
}

/// Fetch the current user's Patreon identity, returning
/// `(patreon_user_id, Option<campaign_id>)`. Campaign discovery only runs
/// for creators (and only the first campaign is captured — multi-campaign
/// creators must explicitly select; out of scope for MVP).
async fn fetch_identity(
    http: &reqwest::Client,
    access_token: &str,
    is_creator: bool,
    identity_url: &str,
) -> Result<(String, Option<String>), PatreonError> {
    let url = build_identity_url(identity_url, is_creator);
    let resp = http
        .get(&url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| PatreonError::Api(format!("identity GET: {}", e)))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(identity_fetch_error(status, &body));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| PatreonError::Api(format!("identity JSON parse: {}", e)))?;
    let patreon_user_id = body
        .get("data")
        .and_then(|d| d.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| PatreonError::Api("identity response missing data.id".into()))?
        .to_string();

    let campaign_id = if is_creator {
        find_campaign_id(&body)
    } else {
        None
    };

    Ok((patreon_user_id, campaign_id))
}

/// Locate the creator's owned campaign id in a Patreon `/identity` response.
///
/// Patreon's JSON:API response stores relationships under
/// `data.relationships.campaign.data.id`. When the user owns no campaign
/// the field is absent (consumer with creator role-claim → returns None
/// rather than failing; caller can decide whether to error).
fn find_campaign_id(body: &serde_json::Value) -> Option<String> {
    body.get("data")?
        .get("relationships")?
        .get("campaign")?
        .get("data")?
        .get("id")?
        .as_str()
        .map(|s| s.to_string())
}

/// Guard against persisting a contradictory creator link. `role` is asserted
/// by the client; if it claims `creator` but Patreon reports no owned campaign,
/// the row would materialize empty entitlements forever — reject up front.
fn validate_creator_campaign(role: &str, campaign_id: &Option<String>) -> Result<(), PatreonError> {
    if role == "creator" && campaign_id.is_none() {
        return Err(PatreonError::NoCampaign);
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

// --------- Membership materialization (used by OIDC access_token mint) ---------

/// Hard cap on the in-memory fallback map (used only while Redis is down).
/// Bounds memory if Redis stays unreachable under sustained load; once the cap
/// is hit, new users simply re-materialize on each mint instead of being
/// cached. Redis remains the unbounded-by-TTL primary store.
const MAX_LOCAL_CACHE_ENTRIES: usize = 10_000;

#[derive(Clone)]
pub struct MembershipCache {
    redis: fred::clients::RedisClient,
    local: Arc<Mutex<HashMap<String, (ArkavoPatreon, i64)>>>,
}

impl MembershipCache {
    pub fn new(redis: fred::clients::RedisClient) -> Self {
        Self {
            redis,
            local: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn key(user_id: Uuid) -> String {
        format!("patreon:materialized:{}", user_id)
    }

    pub async fn get(&self, user_id: Uuid) -> Option<ArkavoPatreon> {
        let key = Self::key(user_id);
        if self.redis.is_connected() {
            match self.redis.get::<Option<String>, _>(&key).await {
                Ok(Some(s)) => match serde_json::from_str::<SerializableMaterialized>(&s) {
                    Ok(m) => {
                        let now = Utc::now().timestamp();
                        if m.cache_expires_at < now {
                            None
                        } else {
                            Some(m.into())
                        }
                    }
                    Err(_) => None,
                },
                _ => None,
            }
        } else {
            let mut map = self.local.lock().unwrap();
            let now = Utc::now().timestamp();
            map.retain(|_, (_, exp)| *exp > now);
            map.get(&key).map(|(m, _)| m.clone())
        }
    }

    pub async fn put(&self, user_id: Uuid, snap: &ArkavoPatreon) {
        let key = Self::key(user_id);
        let ser: SerializableMaterialized = snap.into();
        if self.redis.is_connected() {
            if let Ok(json) = serde_json::to_string(&ser) {
                let ttl = (snap.cache_expires_at - Utc::now().timestamp()).max(1);
                let _: Result<(), _> = self
                    .redis
                    .set(
                        &key,
                        json,
                        Some(fred::types::Expiration::EX(ttl)),
                        None,
                        false,
                    )
                    .await;
            }
        } else {
            let mut map = self.local.lock().unwrap();
            // Reclaim expired entries first, then enforce the cap. We still
            // refresh an existing key even at capacity (it's not net growth);
            // only brand-new keys are dropped once full.
            let now = Utc::now().timestamp();
            map.retain(|_, (_, exp)| *exp > now);
            if map.len() < MAX_LOCAL_CACHE_ENTRIES || map.contains_key(&key) {
                map.insert(key, (snap.clone(), snap.cache_expires_at));
            }
        }
    }

    pub async fn invalidate(&self, user_id: Uuid) {
        let key = Self::key(user_id);
        if self.redis.is_connected() {
            let _: Result<(), _> = self.redis.del(&key).await;
        } else {
            let mut map = self.local.lock().unwrap();
            map.remove(&key);
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SerializableMaterialized {
    role: String,
    patreon_user_id: String,
    campaign_id: Option<String>,
    memberships: Vec<SerializableMembership>,
    verified_at: i64,
    cache_expires_at: i64,
}

#[derive(Serialize, Deserialize)]
struct SerializableMembership {
    campaign_id: String,
    patron_status: Option<String>,
    tier_ids: Vec<String>,
}

impl From<&ArkavoPatreon> for SerializableMaterialized {
    fn from(p: &ArkavoPatreon) -> Self {
        Self {
            role: p.role.clone(),
            patreon_user_id: p.patreon_user_id.clone(),
            campaign_id: p.campaign_id.clone(),
            memberships: p
                .memberships
                .iter()
                .map(|m| SerializableMembership {
                    campaign_id: m.campaign_id.clone(),
                    patron_status: m.patron_status.clone(),
                    tier_ids: m.tier_ids.clone(),
                })
                .collect(),
            verified_at: p.verified_at,
            cache_expires_at: p.cache_expires_at,
        }
    }
}

impl From<SerializableMaterialized> for ArkavoPatreon {
    fn from(s: SerializableMaterialized) -> Self {
        Self {
            role: s.role,
            patreon_user_id: s.patreon_user_id,
            campaign_id: s.campaign_id,
            memberships: s
                .memberships
                .into_iter()
                .map(|m| ArkavoPatreonMembership {
                    campaign_id: m.campaign_id,
                    patron_status: m.patron_status,
                    tier_ids: m.tier_ids,
                })
                .collect(),
            verified_at: s.verified_at,
            cache_expires_at: s.cache_expires_at,
        }
    }
}

/// Materialize an [`ArkavoPatreon`] snapshot for the given arkavo user, for
/// embedding in an OIDC access_token. Returns `None` if the user has no
/// Patreon link or Patreon support is disabled; returns `None` (with a
/// warning) if Patreon is unreachable — per the fail-closed posture, the
/// caller must treat absence of the claim as "no entitlement".
pub async fn materialize_for_user(
    app_state: &AppState,
    state: &PatreonState,
    user_id: Uuid,
) -> Option<ArkavoPatreon> {
    if !state.is_enabled() {
        return None;
    }

    if let Some(cached) = state.cache.get(user_id).await {
        debug!("Patreon materialization cache HIT for user {}", user_id);
        return Some(cached);
    }

    let link = match app_state.db_store.get_patreon_link(user_id).await {
        Ok(Some(link)) => link,
        Ok(None) => return None,
        Err(e) => {
            warn!(
                "Patreon link lookup failed for user {}: {} — failing closed (no claim)",
                user_id, e
            );
            return None;
        }
    };

    let (snap, refreshed) = match materialize_from_link(state, &link).await {
        Ok(v) => v,
        Err(failure) => {
            warn!(
                "Patreon materialization failed for user {}: {} — failing closed (no claim)",
                user_id, failure.error
            );
            // Even on failure, a refresh may have succeeded before the retry
            // fetch broke. Patreon consumed the old refresh token the moment
            // the refresh went through — persisting the rotated link is the
            // only way the next mint can refresh at all.
            persist_rotated_tokens(app_state, user_id, failure.refreshed).await;
            return None;
        }
    };

    persist_rotated_tokens(app_state, user_id, refreshed).await;

    state.cache.put(user_id, &snap).await;
    Some(snap)
}

/// Persist a rotated Patreon token bundle, if one was produced. Best-effort:
/// a persist failure doesn't fail the mint, but it does mean the DB still
/// holds the already-consumed refresh token — the next refresh attempt will
/// be rejected by Patreon and the user fails closed until they re-link, so
/// the failure is logged loudly.
async fn persist_rotated_tokens(
    app_state: &AppState,
    user_id: Uuid,
    refreshed: Option<PatreonLink>,
) {
    let Some(new_link) = refreshed else { return };
    match app_state.db_store.put_patreon_link(&new_link).await {
        Ok(()) => debug!("Persisted refreshed Patreon tokens for user {}", user_id),
        Err(e) => warn!(
            "Failed to persist refreshed Patreon tokens for user {}: {} — stored refresh token is \
             already consumed; subsequent refreshes will fail until the user re-links",
            user_id, e
        ),
    }
}

/// A materialization failure that may still carry a successfully rotated
/// token bundle. Patreon consumes the old refresh token the moment a refresh
/// succeeds, so if the post-refresh retry fetch then fails, the rotated link
/// MUST still reach the caller for persistence — otherwise the DB keeps the
/// dead refresh token and the user is stuck fail-closed until they re-link.
#[derive(Debug)]
struct MaterializeFailure {
    error: PatreonError,
    refreshed: Option<PatreonLink>,
}

impl From<PatreonError> for MaterializeFailure {
    fn from(error: PatreonError) -> Self {
        Self {
            error,
            refreshed: None,
        }
    }
}

/// Produce the membership snapshot for a link. The returned `Option<PatreonLink>`
/// is `Some` iff a token refresh happened and the caller should persist the
/// rotated tokens. Any unrecoverable failure propagates — the caller fails
/// closed (omits the claim, doesn't cache) — but the failure still carries a
/// rotated link when the refresh itself succeeded.
async fn materialize_from_link(
    state: &PatreonState,
    link: &PatreonLink,
) -> Result<(ArkavoPatreon, Option<PatreonLink>), MaterializeFailure> {
    let sealer = state.sealer.as_ref().ok_or(PatreonError::NotConfigured)?;

    let access_plain = sealer
        .open(&SealedToken {
            wrapped_dek: link.wrapped_dek.clone(),
            nonce: link.access_token_nonce.clone(),
            ciphertext: link.access_token_ct.clone(),
        })
        .await?;
    let access_token = String::from_utf8(access_plain)
        .map_err(|_| PatreonError::Crypto("access token not UTF-8 after decrypt".into()))?;

    let now = Utc::now().timestamp();

    match link.role.as_str() {
        "creator" => {
            // For creators, the snapshot is informational — the relevant
            // membership data is the consumer's, not the creator's. Embed the
            // campaign id so RPs can look up "which creator does this user own".
            // No Patreon call is made, so no refresh is possible or needed.
            let snap = ArkavoPatreon {
                role: "creator".into(),
                patreon_user_id: link.patreon_user_id.clone(),
                campaign_id: link.campaign_id.clone(),
                memberships: Vec::new(),
                verified_at: now,
                cache_expires_at: now + PATREON_CACHE_TTL_SECONDS,
            };
            Ok((snap, None))
        }
        _ => {
            // Consumer: query Patreon for memberships, refreshing the access
            // token once on a 401. A genuine HTTP 200 with no memberships
            // yields an empty list (cached as a real snapshot); any
            // unrecoverable failure propagates so the caller fails closed.
            let (memberships, refreshed) =
                fetch_memberships_with_refresh(state, link, &access_token).await?;
            let snap = ArkavoPatreon {
                role: "consumer".into(),
                patreon_user_id: link.patreon_user_id.clone(),
                campaign_id: None,
                memberships,
                verified_at: now,
                cache_expires_at: now + PATREON_CACHE_TTL_SECONDS,
            };
            Ok((snap, refreshed))
        }
    }
}

/// Fetch consumer memberships, transparently refreshing the access token once
/// if Patreon returns 401 (token expired/revoked). On refresh, returns the
/// rotated [`PatreonLink`] so the caller can persist it; the retry fetch is
/// authoritative (a second 401 propagates rather than looping). If the retry
/// fails after a successful refresh, the error carries the rotated link — the
/// old refresh token is already consumed, so the caller must still persist.
///
/// Concurrency note: two simultaneous mints for the same user can both refresh.
/// Patreon rotates the refresh token on use, so the slower refresh may fail (it
/// reused an already-consumed refresh token) — that mint just fails closed for
/// that request, and persistence is last-writer-wins. Acceptable for the read
/// path; fully serializing refreshes (distributed lock / conditional update) is
/// intentionally out of scope here (tracked in #36).
async fn fetch_memberships_with_refresh(
    state: &PatreonState,
    link: &PatreonLink,
    access_token: &str,
) -> Result<(Vec<ArkavoPatreonMembership>, Option<PatreonLink>), MaterializeFailure> {
    match fetch_consumer_memberships(&state.http, access_token, &state.identity_url).await {
        Ok(m) => Ok((m, None)),
        Err(PatreonError::Unauthorized) => {
            let sealer = state.sealer.as_ref().ok_or(PatreonError::NotConfigured)?;
            let oauth = state.oauth.as_ref().ok_or(PatreonError::NotConfigured)?;
            // Refresh must use the same client that minted the bundle —
            // Patreon rejects a refresh token presented with another
            // client's credentials. Unknown client_id (e.g. the operator
            // dropped a client from env) fails closed: claim omitted.
            let Some(client) = oauth.client_by_id(&link.client_id) else {
                warn!(
                    "Patreon link for patreon_user_id_prefix={} was issued by client_id no longer configured; cannot refresh",
                    subject_prefix(&link.patreon_user_id)
                );
                return Err(PatreonError::NotConfigured.into());
            };
            info!(
                "Patreon access token rejected (401) for patreon_user_id_prefix={}; refreshing",
                subject_prefix(&link.patreon_user_id)
            );

            let refresh_plain = sealer
                .open(&SealedToken {
                    wrapped_dek: link.wrapped_dek.clone(),
                    nonce: link.refresh_token_nonce.clone(),
                    ciphertext: link.refresh_token_ct.clone(),
                })
                .await?;
            let refresh_token = String::from_utf8(refresh_plain).map_err(|_| {
                PatreonError::Crypto("refresh token not UTF-8 after decrypt".into())
            })?;

            let new_tokens =
                refresh_access_token(&state.http, client, &refresh_token, &state.token_url).await?;

            // Re-seal both rotated tokens under a fresh per-row DEK (distinct
            // GCM nonces; one wrapped DEK per row).
            let sealed_access = sealer.seal(new_tokens.access_token.as_bytes()).await?;
            let sealed_refresh = seal_under_existing_dek(
                sealer,
                &sealed_access.wrapped_dek,
                new_tokens.refresh_token.as_bytes(),
            )
            .await?;
            let now = Utc::now().timestamp();
            let refreshed_link =
                merge_refreshed_link(link, &new_tokens, sealed_access, sealed_refresh, now);

            // Retry once with the new access token. A failure here propagates
            // (fail-closed) rather than triggering a second refresh — but it
            // carries the rotated link: the refresh already consumed the old
            // refresh token, so dropping the new one would strand the user.
            match fetch_consumer_memberships(
                &state.http,
                &new_tokens.access_token,
                &state.identity_url,
            )
            .await
            {
                Ok(memberships) => Ok((memberships, Some(refreshed_link))),
                Err(error) => Err(MaterializeFailure {
                    error,
                    refreshed: Some(refreshed_link),
                }),
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// Pull the consumer's memberships from Patreon's `/identity` endpoint.
///
/// We request `include=memberships,memberships.currently_entitled_tiers,memberships.campaign`
/// so a single round-trip returns campaign id + patron_status + tier ids.
async fn fetch_consumer_memberships(
    http: &reqwest::Client,
    access_token: &str,
    identity_url: &str,
) -> Result<Vec<ArkavoPatreonMembership>, PatreonError> {
    let url = format!(
        "{}?include=memberships,memberships.currently_entitled_tiers,memberships.campaign\
        &fields%5Bmember%5D=patron_status",
        identity_url
    );
    let resp = http
        .get(&url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| PatreonError::Api(format!("identity GET: {}", e)))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(identity_fetch_error(status, &body));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| PatreonError::Api(format!("identity JSON parse: {}", e)))?;
    Ok(parse_memberships_from_identity(&body))
}

/// Parse the Patreon JSON:API document into our membership shape.
///
/// JSON:API stores memberships in the `included` array (type=`member`), with
/// each member's relationships pointing at its `campaign` and
/// `currently_entitled_tiers`. We walk the `included` array twice: first to
/// index tiers by id (no embedded attributes we need; tier presence is the
/// signal), then to build the member rows.
pub(crate) fn parse_memberships_from_identity(
    body: &serde_json::Value,
) -> Vec<ArkavoPatreonMembership> {
    let Some(included) = body.get("included").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in included {
        if entry.get("type").and_then(|v| v.as_str()) != Some("member") {
            continue;
        }
        let campaign_id = entry
            .get("relationships")
            .and_then(|r| r.get("campaign"))
            .and_then(|c| c.get("data"))
            .and_then(|d| d.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let Some(campaign_id) = campaign_id else {
            continue;
        };
        let patron_status = entry
            .get("attributes")
            .and_then(|a| a.get("patron_status"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let tier_ids: Vec<String> = entry
            .get("relationships")
            .and_then(|r| r.get("currently_entitled_tiers"))
            .and_then(|t| t.get("data"))
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| t.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        out.push(ArkavoPatreonMembership {
            campaign_id,
            patron_status,
            tier_ids,
        });
    }
    out
}

// --------- Helpers (copied from apple_signin to avoid cross-module coupling) ---------

fn subject_prefix(sub: &str) -> &str {
    match sub.char_indices().nth(8) {
        Some((byte_idx, _)) => &sub[..byte_idx],
        None => sub,
    }
}

fn client_ip_from_headers(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn extract_authenticated_user_id(
    app_state: &AppState,
    headers: &HeaderMap,
) -> Result<Uuid, PatreonError> {
    let token_header = headers
        .get("X-Auth-Token")
        .ok_or(PatreonError::MissingAuth)?;
    let token_str = token_header
        .to_str()
        .map_err(|_| PatreonError::MissingAuth)?;
    let claims = crate::authn::verify_inbound_account_token(app_state, token_str)
        .map_err(|_| PatreonError::MissingAuth)?;
    Uuid::parse_str(&claims.sub).map_err(|_| PatreonError::MissingAuth)
}

// Avoid a "PATREON_CAMPAIGN_MEMBERS_URL_TEMPLATE unused" warning: the
// constant is exported for the future creator-side roster query path
// (planned: webhook-driven cache warm-up), and tests reference it.
#[allow(dead_code)]
fn _campaign_members_url_used() -> &'static str {
    PATREON_CAMPAIGN_MEMBERS_URL_TEMPLATE
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_memberships_extracts_active_patron_with_tiers() {
        let body = json!({
            "data": {"id": "user-1", "type": "user"},
            "included": [
                {
                    "type": "member",
                    "id": "m1",
                    "attributes": {"patron_status": "active_patron"},
                    "relationships": {
                        "campaign": {"data": {"id": "camp-gold", "type": "campaign"}},
                        "currently_entitled_tiers": {
                            "data": [
                                {"id": "tier-1", "type": "tier"},
                                {"id": "tier-2", "type": "tier"}
                            ]
                        }
                    }
                }
            ]
        });
        let parsed = parse_memberships_from_identity(&body);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].campaign_id, "camp-gold");
        assert_eq!(parsed[0].patron_status.as_deref(), Some("active_patron"));
        assert_eq!(parsed[0].tier_ids, vec!["tier-1", "tier-2"]);
    }

    #[test]
    fn parse_memberships_ignores_non_member_includes() {
        let body = json!({
            "data": {"id": "user-1"},
            "included": [
                {"type": "campaign", "id": "camp-x"},
                {"type": "tier", "id": "tier-x"},
            ]
        });
        let parsed = parse_memberships_from_identity(&body);
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_memberships_skips_members_without_campaign_link() {
        let body = json!({
            "data": {"id": "user-1"},
            "included": [
                {
                    "type": "member",
                    "id": "m1",
                    "attributes": {"patron_status": "active_patron"},
                    "relationships": {
                        "currently_entitled_tiers": {"data": []}
                    }
                }
            ]
        });
        let parsed = parse_memberships_from_identity(&body);
        assert!(
            parsed.is_empty(),
            "member without campaign should be skipped"
        );
    }

    #[test]
    fn parse_memberships_handles_no_included() {
        let body = json!({"data": {"id": "user-1"}});
        assert!(parse_memberships_from_identity(&body).is_empty());
    }

    #[test]
    fn find_campaign_id_extracts_creator_campaign() {
        let body = json!({
            "data": {
                "id": "user-1",
                "relationships": {
                    "campaign": {"data": {"id": "camp-z", "type": "campaign"}}
                }
            }
        });
        assert_eq!(find_campaign_id(&body).as_deref(), Some("camp-z"));
    }

    #[test]
    fn find_campaign_id_returns_none_when_no_campaign() {
        let body = json!({"data": {"id": "user-1"}});
        assert!(find_campaign_id(&body).is_none());
    }

    #[test]
    fn identity_url_creator_includes_campaign_but_not_email() {
        // Minimum-PII: we only need data.id + campaign relationship; never
        // request the user's email from Patreon.
        let url = build_identity_url(PATREON_IDENTITY_URL, true);
        assert!(url.contains("include=campaign"), "creator url: {url}");
        assert!(
            !url.to_lowercase().contains("email"),
            "creator url must not request email: {url}"
        );
    }

    #[test]
    fn identity_url_consumer_has_no_query() {
        assert_eq!(
            build_identity_url(PATREON_IDENTITY_URL, false),
            PATREON_IDENTITY_URL
        );
    }

    #[test]
    fn identity_fetch_401_classifies_as_unauthorized() {
        // A 401 on a membership/identity fetch means our access token is
        // stale/revoked → caller can trigger a refresh. Other failures stay Api.
        assert!(matches!(
            identity_fetch_error(reqwest::StatusCode::UNAUTHORIZED, "expired"),
            PatreonError::Unauthorized
        ));
        assert!(matches!(
            identity_fetch_error(reqwest::StatusCode::INTERNAL_SERVER_ERROR, "boom"),
            PatreonError::Api(_)
        ));
    }

    #[test]
    fn token_exchange_client_error_maps_to_invalid_grant() {
        // A bad/expired/replayed auth code is the *client's* fault — surface a
        // 400, not a 502 that implies Patreon is down.
        let err = token_exchange_error(reqwest::StatusCode::BAD_REQUEST, "invalid_grant");
        assert!(matches!(err, PatreonError::InvalidGrant));
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn token_exchange_server_error_maps_to_bad_gateway() {
        let err = token_exchange_error(reqwest::StatusCode::INTERNAL_SERVER_ERROR, "boom");
        assert!(matches!(err, PatreonError::Api(_)));
        assert_eq!(err.into_response().status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn token_exchange_non_400_client_errors_are_upstream_failures() {
        // 429 = Patreon rate-limiting *us*; 401/403 = our client credentials
        // are misconfigured. None of these are the caller's fault — they must
        // not masquerade as InvalidGrant (which invites the client to retry
        // with a fresh code, amplifying load) and must keep diagnostics.
        for status in [
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            reqwest::StatusCode::UNAUTHORIZED,
            reqwest::StatusCode::FORBIDDEN,
        ] {
            let err = token_exchange_error(status, "details");
            assert!(
                matches!(err, PatreonError::Api(ref m) if m.contains(status.as_str())),
                "{status} should map to Api with diagnostics, got: {err:?}"
            );
            assert_eq!(err.into_response().status(), StatusCode::BAD_GATEWAY);
        }
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        let s = "αβγδ"; // 4 chars, 8 bytes
        assert_eq!(truncate(s, 100), s);
        let truncated = truncate(s, 3);
        // 3 bytes lands mid-codepoint; should back off to 2.
        assert!(truncated.len() <= 3);
        assert!(s.starts_with(&truncated));
    }

    #[test]
    fn patreon_error_status_codes() {
        assert_eq!(
            PatreonError::NotConfigured.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            PatreonError::InvalidRedirectUri.into_response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            PatreonError::InvalidRole.into_response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            PatreonError::MissingAuth.into_response().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            PatreonError::Api("x".into()).into_response().status(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            PatreonError::LinkConflict.into_response().status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            PatreonError::Kms("x".into()).into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn into_response_redacts_server_side_error_details() {
        use axum::body::to_bytes;
        // Server-side (5xx) variants must never echo raw upstream diagnostics
        // (KMS ARNs, DynamoDB internals, Patreon bodies) to the client.
        let cases = [
            PatreonError::Kms("arn:aws:kms:us-east-1:123456789012:key/SECRET-KMS-DETAIL".into()),
            PatreonError::Crypto("SECRET-KMS-DETAIL nonce internals".into()),
            PatreonError::Db("SECRET-KMS-DETAIL table scan".into()),
            PatreonError::Internal("SECRET-KMS-DETAIL stack".into()),
        ];
        for err in cases {
            let resp = err.into_response();
            assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
            let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains("SECRET-KMS-DETAIL"),
                "5xx body leaked internal detail: {text}"
            );
        }
    }

    #[tokio::test]
    async fn into_response_keeps_safe_client_facing_messages() {
        use axum::body::to_bytes;
        // 4xx variants carry no sensitive data and may keep their descriptive
        // body so the caller can correct the request.
        let resp = PatreonError::InvalidRole.into_response();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("creator"), "client-facing 4xx body: {text}");
    }

    #[tokio::test]
    async fn plaintext_sealer_roundtrips_long_token() {
        let sealer = TokenSealer::Plaintext;
        let plaintext = b"patreon-access-token-".repeat(100);
        let sealed = sealer.seal(&plaintext).await.expect("seal");
        assert_ne!(sealed.ciphertext, plaintext);
        let opened = sealer.open(&sealed).await.expect("open");
        assert_eq!(opened, plaintext);
    }

    #[tokio::test]
    async fn plaintext_sealer_seal_under_existing_dek_distinct_nonces() {
        let sealer = TokenSealer::Plaintext;
        let access = sealer.seal(b"access-token").await.expect("seal access");
        let refresh = seal_under_existing_dek(&sealer, &access.wrapped_dek, b"refresh-token")
            .await
            .expect("seal refresh");
        assert_eq!(refresh.wrapped_dek, access.wrapped_dek);
        assert_ne!(refresh.nonce, access.nonce, "nonces must differ");
        let opened_access = sealer.open(&access).await.expect("open access");
        let opened_refresh = sealer.open(&refresh).await.expect("open refresh");
        assert_eq!(opened_access, b"access-token");
        assert_eq!(opened_refresh, b"refresh-token");
    }

    #[tokio::test]
    async fn plaintext_sealer_rejects_tampered_ciphertext() {
        let sealer = TokenSealer::Plaintext;
        let mut sealed = sealer.seal(b"hello").await.expect("seal");
        sealed.ciphertext[0] ^= 0x01;
        let result = sealer.open(&sealed).await;
        assert!(matches!(result, Err(PatreonError::Crypto(_))));
    }

    #[tokio::test]
    async fn membership_cache_in_memory_roundtrip() {
        // Redis isn't connected in unit tests, so we exercise the in-memory
        // fallback path. This is the same code that runs in production when
        // the Redis connection drops mid-session.
        let redis =
            fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None);
        let cache = MembershipCache::new(redis);
        let user_id = Uuid::new_v4();
        let now = Utc::now().timestamp();
        let snap = ArkavoPatreon {
            role: "consumer".into(),
            patreon_user_id: "p-1".into(),
            campaign_id: None,
            memberships: vec![ArkavoPatreonMembership {
                campaign_id: "camp-1".into(),
                patron_status: Some("active_patron".into()),
                tier_ids: vec!["tier-1".into()],
            }],
            verified_at: now,
            cache_expires_at: now + 300,
        };
        cache.put(user_id, &snap).await;
        let got = cache.get(user_id).await.expect("cache hit");
        assert_eq!(got, snap);
        cache.invalidate(user_id).await;
        assert!(cache.get(user_id).await.is_none(), "invalidate clears");
    }

    /// reqwest client whose DNS for the Patreon host resolves to a dead local
    /// port, so any outbound Patreon call fails fast and offline.
    fn unreachable_patreon_http() -> reqwest::Client {
        reqwest::Client::builder()
            .resolve(
                "www.patreon.com",
                "127.0.0.1:1".parse::<std::net::SocketAddr>().unwrap(),
            )
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap()
    }

    async fn consumer_link_with_token(sealer: &TokenSealer, token: &[u8]) -> PatreonLink {
        let access = sealer.seal(token).await.expect("seal access");
        let refresh = seal_under_existing_dek(sealer, &access.wrapped_dek, b"refresh")
            .await
            .expect("seal refresh");
        let now = Utc::now().timestamp();
        PatreonLink {
            user_id: Uuid::new_v4(),
            role: "consumer".into(),
            client_id: "c".into(),
            patreon_user_id: "p-1".into(),
            campaign_id: None,
            scopes: String::new(),
            access_token_ct: access.ciphertext,
            access_token_nonce: access.nonce,
            refresh_token_ct: refresh.ciphertext,
            refresh_token_nonce: refresh.nonce,
            wrapped_dek: access.wrapped_dek,
            token_expires_at: now + 3600,
            linked_at: now,
        }
    }

    #[tokio::test]
    async fn merge_refreshed_link_preserves_identity_and_updates_tokens() {
        let sealer = TokenSealer::Plaintext;
        let old = consumer_link_with_token(&sealer, b"old-access").await;
        let new_tokens = PatreonTokenResponse {
            access_token: "new-access".into(),
            refresh_token: "new-refresh".into(),
            expires_in: 2_592_000,
            scope: "identity campaigns.members".into(),
            token_type: "Bearer".into(),
        };
        let sealed_access = sealer
            .seal(new_tokens.access_token.as_bytes())
            .await
            .unwrap();
        let sealed_refresh = seal_under_existing_dek(
            &sealer,
            &sealed_access.wrapped_dek,
            new_tokens.refresh_token.as_bytes(),
        )
        .await
        .unwrap();
        let now = 1_000_000;
        let merged = merge_refreshed_link(&old, &new_tokens, sealed_access, sealed_refresh, now);

        // Identity, role, and link timestamp are preserved.
        assert_eq!(merged.user_id, old.user_id);
        assert_eq!(merged.patreon_user_id, old.patreon_user_id);
        assert_eq!(merged.role, old.role);
        assert_eq!(merged.campaign_id, old.campaign_id);
        assert_eq!(merged.linked_at, old.linked_at);
        // Token material + expiry + scopes are refreshed.
        assert_eq!(merged.scopes, "identity campaigns.members");
        assert_eq!(merged.token_expires_at, now + 2_592_000);
        let opened_access = sealer
            .open(&SealedToken {
                wrapped_dek: merged.wrapped_dek.clone(),
                nonce: merged.access_token_nonce.clone(),
                ciphertext: merged.access_token_ct.clone(),
            })
            .await
            .unwrap();
        assert_eq!(opened_access, b"new-access");
        let opened_refresh = sealer
            .open(&SealedToken {
                wrapped_dek: merged.wrapped_dek.clone(),
                nonce: merged.refresh_token_nonce.clone(),
                ciphertext: merged.refresh_token_ct.clone(),
            })
            .await
            .unwrap();
        assert_eq!(opened_refresh, b"new-refresh");
    }

    #[tokio::test]
    async fn consumer_fetch_failure_propagates_does_not_yield_empty_snapshot() {
        // Fail-closed contract: when Patreon is unreachable, materialization
        // must return Err (so materialize_for_user omits the claim and does NOT
        // cache), NOT Ok with an empty membership list that would be cached for
        // the full TTL and read downstream as "no entitlement".
        let sealer = TokenSealer::Plaintext;
        let link = consumer_link_with_token(&sealer, b"access-token").await;
        let redis =
            fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None);
        let state = PatreonState {
            oauth: Some(PatreonOAuthConfig {
                clients: vec![PatreonClient {
                    client_id: "c".into(),
                    client_secret: "s".into(),
                    redirect_uris: vec!["https://x/cb".into()],
                }],
            }),
            sealer: Some(sealer),
            http: unreachable_patreon_http(),
            cache: MembershipCache::new(redis),
            token_url: PATREON_TOKEN_URL.to_string(),
            identity_url: PATREON_IDENTITY_URL.to_string(),
        };
        let result = materialize_from_link(&state, &link).await;
        assert!(
            result.is_err(),
            "unreachable Patreon must propagate an error, got: {result:?}"
        );
    }

    /// Minimal localhost Patreon stand-in. Dispatches on method + bearer token:
    /// - POST (token endpoint)            → 200, rotated tokens (new-access/new-refresh)
    /// - GET  with `Bearer old-access`    → 401 (token expired)
    /// - GET  with `Bearer new-access`    → 200, one active membership when
    ///   `retry_ok`, else 500 (post-refresh retry fetch fails)
    ///
    /// Returns `(token_url, identity_url)` pointing at the spawned server.
    async fn spawn_patreon_mock(retry_ok: bool) -> (String, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    // Small localhost requests arrive whole in one read; the
                    // request line + headers are all we dispatch on.
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let is_post = req.starts_with("POST");
                    let has_old = req.contains("Bearer old-access");

                    let (status_line, body) = if is_post {
                        (
                            "HTTP/1.1 200 OK",
                            r#"{"access_token":"new-access","refresh_token":"new-refresh","expires_in":2592000,"scope":"identity","token_type":"Bearer"}"#.to_string(),
                        )
                    } else if has_old {
                        ("HTTP/1.1 401 Unauthorized", String::new())
                    } else if retry_ok {
                        (
                            "HTTP/1.1 200 OK",
                            r#"{"data":{"id":"p-1"},"included":[{"type":"member","id":"m1","attributes":{"patron_status":"active_patron"},"relationships":{"campaign":{"data":{"id":"camp-1"}},"currently_entitled_tiers":{"data":[{"id":"tier-gold"}]}}}]}"#.to_string(),
                        )
                    } else {
                        ("HTTP/1.1 500 Internal Server Error", String::new())
                    };
                    let resp = format!(
                        "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });
        let base = format!("http://{addr}");
        (format!("{base}/token"), format!("{base}/v2/identity"))
    }

    #[tokio::test]
    async fn consumer_membership_refreshes_on_401_and_retries() {
        // End-to-end: stale access token → 401 → refresh → retry → memberships.
        let (token_url, identity_url) = spawn_patreon_mock(true).await;
        let sealer = TokenSealer::Plaintext;
        let link = consumer_link_with_token(&sealer, b"old-access").await;
        let redis =
            fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None);
        let state = PatreonState {
            oauth: Some(PatreonOAuthConfig {
                clients: vec![PatreonClient {
                    client_id: "c".into(),
                    client_secret: "s".into(),
                    redirect_uris: vec!["https://x/cb".into()],
                }],
            }),
            sealer: Some(sealer.clone()),
            http: reqwest::Client::new(),
            cache: MembershipCache::new(redis),
            token_url,
            identity_url,
        };

        let (snap, refreshed) = materialize_from_link(&state, &link)
            .await
            .expect("materialization should succeed after refresh");

        // The retried fetch (with new-access) returned the active membership.
        assert_eq!(snap.memberships.len(), 1, "expected one membership");
        assert_eq!(
            snap.memberships[0].patron_status.as_deref(),
            Some("active_patron")
        );
        assert_eq!(snap.memberships[0].tier_ids, vec!["tier-gold"]);

        // A refresh occurred, so a rotated link is handed back for persistence,
        // and its access ciphertext decrypts to the new token.
        let new_link = refreshed.expect("a refresh should have produced a new link");
        assert_eq!(new_link.user_id, link.user_id);
        assert_eq!(new_link.patreon_user_id, link.patreon_user_id);
        let opened = sealer
            .open(&SealedToken {
                wrapped_dek: new_link.wrapped_dek.clone(),
                nonce: new_link.access_token_nonce.clone(),
                ciphertext: new_link.access_token_ct.clone(),
            })
            .await
            .unwrap();
        assert_eq!(opened, b"new-access");
    }

    #[tokio::test]
    async fn refresh_survives_failed_retry_fetch() {
        // 401 → refresh succeeds (old refresh token now consumed by Patreon)
        // → retry fetch 500s. The materialization must fail closed AND hand
        // back the rotated link for persistence — dropping it would leave the
        // dead refresh token in the DB and strand the user until re-link.
        let (token_url, identity_url) = spawn_patreon_mock(false).await;
        let sealer = TokenSealer::Plaintext;
        let link = consumer_link_with_token(&sealer, b"old-access").await;
        let redis =
            fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None);
        let state = PatreonState {
            oauth: Some(PatreonOAuthConfig {
                clients: vec![PatreonClient {
                    client_id: "c".into(),
                    client_secret: "s".into(),
                    redirect_uris: vec!["https://x/cb".into()],
                }],
            }),
            sealer: Some(sealer.clone()),
            http: reqwest::Client::new(),
            cache: MembershipCache::new(redis),
            token_url,
            identity_url,
        };

        let failure = materialize_from_link(&state, &link)
            .await
            .expect_err("retry 500 must fail the materialization");
        assert!(
            matches!(failure.error, PatreonError::Api(_)),
            "expected Api error from the failed retry, got: {:?}",
            failure.error
        );

        let new_link = failure
            .refreshed
            .expect("rotated link must survive the failed retry fetch");
        let opened = sealer
            .open(&SealedToken {
                wrapped_dek: new_link.wrapped_dek.clone(),
                nonce: new_link.refresh_token_nonce.clone(),
                ciphertext: new_link.refresh_token_ct.clone(),
            })
            .await
            .unwrap();
        assert_eq!(opened, b"new-refresh");
    }

    #[tokio::test]
    async fn in_memory_cache_fallback_is_bounded() {
        // Redis disconnected → local fallback. Inserting more distinct,
        // non-expired users than the cap must not grow the map past the cap.
        let redis =
            fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None);
        let cache = MembershipCache::new(redis);
        let now = Utc::now().timestamp();
        let snap = ArkavoPatreon {
            role: "consumer".into(),
            patreon_user_id: "p".into(),
            campaign_id: None,
            memberships: vec![],
            verified_at: now,
            cache_expires_at: now + 3600, // not expired, so retain can't reclaim
        };
        for _ in 0..(MAX_LOCAL_CACHE_ENTRIES + 25) {
            cache.put(Uuid::new_v4(), &snap).await;
        }
        let len = cache.local.lock().unwrap().len();
        assert!(
            len <= MAX_LOCAL_CACHE_ENTRIES,
            "local cache grew to {len}, exceeding cap {MAX_LOCAL_CACHE_ENTRIES}"
        );
    }

    #[tokio::test]
    async fn membership_cache_drops_expired_entries() {
        let redis =
            fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None);
        let cache = MembershipCache::new(redis);
        let user_id = Uuid::new_v4();
        let snap = ArkavoPatreon {
            role: "consumer".into(),
            patreon_user_id: "p-1".into(),
            campaign_id: None,
            memberships: vec![],
            verified_at: 0,
            cache_expires_at: 1, // already expired
        };
        cache.put(user_id, &snap).await;
        // The retain-on-read sweep should drop the expired row.
        assert!(cache.get(user_id).await.is_none());
    }

    #[test]
    fn subject_prefix_caps_at_eight_chars() {
        assert_eq!(subject_prefix("0123456789abc"), "01234567");
        assert_eq!(subject_prefix("short"), "short");
        assert_eq!(subject_prefix(""), "");
    }

    #[test]
    fn creator_without_campaign_is_rejected() {
        // A creator link with no discoverable campaign would persist a
        // contradictory row (role=creator, campaign_id=None) that materializes
        // empty entitlements forever. Reject it at link time instead.
        assert!(matches!(
            validate_creator_campaign("creator", &None),
            Err(PatreonError::NoCampaign)
        ));
        // Creator with a campaign is fine.
        assert!(validate_creator_campaign("creator", &Some("camp-1".into())).is_ok());
        // Consumers never require a campaign.
        assert!(validate_creator_campaign("consumer", &None).is_ok());
    }

    #[test]
    fn no_campaign_error_maps_to_400() {
        assert_eq!(
            PatreonError::NoCampaign.into_response().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn link_request_deserializes_minimal_shape() {
        let body = serde_json::json!({
            "code": "abc123",
            "redirect_uri": "https://identity.arkavo.net/oauth/patreon/cb",
            "role": "consumer",
        });
        let req: LinkRequest = serde_json::from_value(body).expect("parse");
        assert_eq!(req.code, "abc123");
        assert_eq!(req.role, "consumer");
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn patreon_oauth_config_requires_redirect_uris() {
        assert!(
            PatreonOAuthConfig::from_env_vars(env(&[
                ("PATREON_CLIENT_ID", "test-client"),
                ("PATREON_CLIENT_SECRET", "test-secret"),
            ]))
            .is_none()
        );

        let cfg = PatreonOAuthConfig::from_env_vars(env(&[
            ("PATREON_CLIENT_ID", "test-client"),
            ("PATREON_CLIENT_SECRET", "test-secret"),
            ("PATREON_REDIRECT_URIS", "https://a/cb, https://b/cb"),
        ]))
        .expect("config builds");
        assert_eq!(cfg.clients.len(), 1);
        assert_eq!(cfg.clients[0].client_id, "test-client");
        assert_eq!(cfg.clients[0].client_secret, "test-secret");
        assert_eq!(
            cfg.clients[0].redirect_uris,
            vec!["https://a/cb".to_string(), "https://b/cb".to_string()]
        );
    }

    #[test]
    fn patreon_oauth_config_parses_tagged_clients() {
        let cfg = PatreonOAuthConfig::from_env_vars(env(&[
            ("PATREON_CLIENT_ARKAVO_ID", "id-arkavo"),
            ("PATREON_CLIENT_ARKAVO_SECRET", "sec-arkavo"),
            (
                "PATREON_CLIENT_ARKAVO_REDIRECT_URIS",
                "https://identity.arkavo.net/oauth/arkavo/patreon",
            ),
            ("PATREON_CLIENT_CREATOR_ID", "id-creator"),
            ("PATREON_CLIENT_CREATOR_SECRET", "sec-creator"),
            (
                "PATREON_CLIENT_CREATOR_REDIRECT_URIS",
                "https://identity.arkavo.net/oauth/arkavocreator/patreon, https://webauthn.arkavo.net/oauth/arkavocreator/patreon",
            ),
        ]))
        .expect("config builds");
        assert_eq!(cfg.clients.len(), 2);

        // redirect_uri → the client registered for it.
        let by_redirect = cfg
            .client_for_redirect("https://webauthn.arkavo.net/oauth/arkavocreator/patreon")
            .expect("creator client");
        assert_eq!(by_redirect.client_id, "id-creator");
        assert!(cfg.client_for_redirect("https://evil.example/cb").is_none());

        // client_id → stored-bundle lookup for refresh.
        assert_eq!(
            cfg.client_by_id("id-arkavo").expect("arkavo").client_secret,
            "sec-arkavo"
        );
        assert!(cfg.client_by_id("unknown").is_none());
        // Empty client_id (pre-multi-client row) is ambiguous with 2 clients.
        assert!(cfg.client_by_id("").is_none());
    }

    #[test]
    fn patreon_oauth_config_combines_legacy_and_tagged() {
        let cfg = PatreonOAuthConfig::from_env_vars(env(&[
            ("PATREON_CLIENT_ID", "legacy-id"),
            ("PATREON_CLIENT_SECRET", "legacy-sec"),
            ("PATREON_REDIRECT_URIS", "https://legacy/cb"),
            ("PATREON_CLIENT_ARKAVO_ID", "id-arkavo"),
            ("PATREON_CLIENT_ARKAVO_SECRET", "sec-arkavo"),
            ("PATREON_CLIENT_ARKAVO_REDIRECT_URIS", "https://arkavo/cb"),
        ]))
        .expect("config builds");
        assert_eq!(cfg.clients.len(), 2);
        assert_eq!(
            cfg.client_for_redirect("https://legacy/cb")
                .expect("legacy")
                .client_id,
            "legacy-id"
        );
    }

    #[test]
    fn patreon_oauth_config_single_client_tolerates_empty_client_id() {
        let cfg = PatreonOAuthConfig::from_env_vars(env(&[
            ("PATREON_CLIENT_ID", "only-id"),
            ("PATREON_CLIENT_SECRET", "only-sec"),
            ("PATREON_REDIRECT_URIS", "https://only/cb"),
        ]))
        .expect("config builds");
        // Rows written before multi-client support carry client_id="".
        assert_eq!(cfg.client_by_id("").expect("fallback").client_id, "only-id");
    }

    #[test]
    fn patreon_oauth_config_rejects_ambiguity() {
        // Same redirect URI claimed by two clients → disabled.
        assert!(
            PatreonOAuthConfig::from_env_vars(env(&[
                ("PATREON_CLIENT_A_ID", "id-a"),
                ("PATREON_CLIENT_A_SECRET", "sec-a"),
                ("PATREON_CLIENT_A_REDIRECT_URIS", "https://shared/cb"),
                ("PATREON_CLIENT_B_ID", "id-b"),
                ("PATREON_CLIENT_B_SECRET", "sec-b"),
                ("PATREON_CLIENT_B_REDIRECT_URIS", "https://shared/cb"),
            ]))
            .is_none()
        );
        // Duplicate client_id across tags → disabled.
        assert!(
            PatreonOAuthConfig::from_env_vars(env(&[
                ("PATREON_CLIENT_A_ID", "same"),
                ("PATREON_CLIENT_A_SECRET", "sec-a"),
                ("PATREON_CLIENT_A_REDIRECT_URIS", "https://a/cb"),
                ("PATREON_CLIENT_B_ID", "same"),
                ("PATREON_CLIENT_B_SECRET", "sec-b"),
                ("PATREON_CLIENT_B_REDIRECT_URIS", "https://b/cb"),
            ]))
            .is_none()
        );
        // Tag missing its secret → disabled (not silently skipped).
        assert!(
            PatreonOAuthConfig::from_env_vars(env(&[
                ("PATREON_CLIENT_A_ID", "id-a"),
                ("PATREON_CLIENT_A_REDIRECT_URIS", "https://a/cb"),
            ]))
            .is_none()
        );
    }
}
