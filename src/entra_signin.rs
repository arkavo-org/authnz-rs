//! Microsoft Entra ID (Azure AD) upstream federation.
//!
//! Entra is treated as an *upstream* identity provider, exactly like
//! [`crate::apple_signin`]: end-users sign in with their Microsoft 365
//! identity, and Arkavo AuthNZ trusts Entra's `id_token` only after validating
//! its signature against the tenant's published JWKS. The resulting directory
//! object is mapped onto an Arkavo account before any OIDC/CWT tokens are
//! issued downstream. OpenTDF and other relying parties never trust Entra
//! directly — they trust AuthNZ, and AuthNZ decides which upstream sources are
//! acceptable.
//!
//! # Security model
//!
//! Every accepted Entra `id_token` must clear the following gates:
//!
//! 1. **Signature**: validated against the tenant's published JWKS
//!    (`https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys`),
//!    cached 1h with force-refresh on `kid` miss in case Entra rotated keys.
//!    Entra signs with RSA, so the accepted algorithm is `RS256`.
//! 2. **Issuer**: `iss` must equal the v2.0 issuer for the configured tenant,
//!    `https://login.microsoftonline.com/{tenant}/v2.0`. This is a *single
//!    tenant* (one org) deployment, so the issuer is pinned exactly.
//! 3. **Tenant**: the `tid` claim must equal the configured `ENTRA_TENANT_ID`.
//!    This is defence-in-depth on top of the issuer check.
//! 4. **Audience**: `aud` must be one of the configured `ENTRA_CLIENT_ID`
//!    values (comma-separated list supported, mirroring the Apple module).
//! 5. **Nonce**: a server-issued / OIDC nonce must be supplied, and the
//!    id_token's `nonce` claim must equal either that raw nonce *or*
//!    `sha256_hex(raw_nonce)`. Replay-prevention rests on this check, so it is
//!    mandatory — identical contract to the Apple flow.
//! 6. **Exp/iat**: enforced by `jsonwebtoken::Validation`.
//!
//! # Identity key
//!
//! The canonical join key is the Entra **`oid`** (directory object id), *not*
//! `sub`. Entra's `sub` is pairwise/per-application, whereas `oid` is stable
//! for the user across every app in the tenant — so `oid` (scoped by `tid`) is
//! what survives app re-registration and is what we key the Arkavo account on.
//! Email / UPN are treated as optional metadata and are never used to locate an
//! account (they can be reassigned by a tenant admin).
//!
//! Wired into `oidc::resolve_user` via the `idp=entra` authorize branch.

use crate::AppState;
use crate::db::DynamoDBError;
use crate::oidc::AuthenticatedUser;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use log::{info, warn};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;
use thiserror::Error;
use tokio::sync::RwLock;

/// Entra JWKS cache TTL (seconds). Entra rotates signing keys infrequently;
/// a `kid` miss force-refreshes regardless, so an hour is comfortable.
const ENTRA_JWKS_CACHE_TTL_SECONDS: i64 = 3600;

/// Total timeout for a JWKS fetch. The fetch runs inline on the unauthenticated
/// `/oauth/authorize` path (any `idp=entra` token can trigger a cold or
/// `kid`-miss refresh), so a bounded timeout is required to keep a slow or
/// blackholed `login.microsoftonline.com` from pinning an inbound task.
const ENTRA_JWKS_HTTP_TIMEOUT_SECS: u64 = 10;

/// Claims published by Entra in v2.0 `id_token`s.
///
/// Requires the app registration to use `accessTokenAcceptedVersion: 2` so the
/// claim shapes below are stable (the v1.0 endpoint emits different `iss`/`ver`
/// values and is intentionally not supported).
/// `allow(dead_code)`: serde populates every field, but some (`sub`, `iat`,
/// `groups`) are retained for completeness / future use and not read today.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct EntraIdTokenClaims {
    pub iss: String,
    pub aud: String,
    /// Pairwise per-app subject. Present, but NOT used as the account key.
    pub sub: String,
    /// Directory object id — the stable, canonical join key.
    pub oid: String,
    /// Tenant id — must equal the configured tenant.
    pub tid: String,
    pub iat: i64,
    pub exp: i64,
    pub nonce: Option<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    /// Application roles assigned to the user (preferred for authorization —
    /// app roles never overflow, unlike the `groups` claim).
    #[serde(default)]
    pub roles: Vec<String>,
    /// Group object GUIDs. Subject to Entra's "groups overage" (omitted and
    /// replaced by a Graph API link once the user is in too many groups), so
    /// these are best-effort and should not be the sole authorization source.
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Error)]
pub enum EntraSigninError {
    #[error("Entra JWKS fetch failed: {0}")]
    JwksFetch(String),
    #[error("Entra JWKS parsing failed: {0}")]
    JwksParse(String),
    #[error("Entra id_token header missing kid")]
    MissingKid,
    #[error("Entra id_token signed by unknown kid: {0}")]
    UnknownKid(String),
    #[error("Entra id_token signature/claims invalid: {0}")]
    InvalidToken(String),
    #[error("Entra id_token audience mismatch: aud={actual} not in {expected:?}")]
    AudienceMismatch {
        expected: Vec<String>,
        actual: String,
    },
    #[error("Entra id_token issuer mismatch: iss={0}")]
    IssuerMismatch(String),
    #[error("Entra id_token tenant mismatch: tid={actual} (expected {expected})")]
    TenantMismatch { expected: String, actual: String },
    #[error("Entra id_token nonce missing")]
    MissingTokenNonce,
    #[error("Entra id_token nonce mismatch")]
    NonceMismatch,
    #[error("Entra federation is not configured (set ENTRA_TENANT_ID and ENTRA_CLIENT_ID)")]
    NotConfigured,
}

impl IntoResponse for EntraSigninError {
    fn into_response(self) -> Response {
        let status = match &self {
            EntraSigninError::JwksFetch(_) | EntraSigninError::JwksParse(_) => {
                StatusCode::BAD_GATEWAY
            }
            EntraSigninError::NotConfigured => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNAUTHORIZED,
        };
        (status, self.to_string()).into_response()
    }
}

/// Operator-configured Entra tenant settings, derived once at construction.
///
/// `issuer` and `jwks_url` are *computed* from the tenant id rather than
/// supplied directly, so an operator can only ever point AuthNZ at a
/// well-formed Microsoft endpoint for the tenant they configured.
#[derive(Debug, Clone)]
pub struct EntraConfig {
    pub tenant_id: String,
    pub issuer: String,
    pub jwks_url: String,
    /// Accepted `aud` values (the app registration client id, and optionally
    /// an `api://{client_id}` form), parsed from `ENTRA_CLIENT_ID`.
    pub audiences: Vec<String>,
}

impl EntraConfig {
    /// Build a config from a tenant id and the accepted audience list.
    pub fn new(tenant_id: impl Into<String>, audiences: Vec<String>) -> Self {
        let tenant_id = tenant_id.into();
        Self {
            issuer: build_issuer(&tenant_id),
            jwks_url: build_jwks_url(&tenant_id),
            tenant_id,
            audiences,
        }
    }

    /// Read config from the environment (`ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`).
    /// Returns a config even when unset — emptiness is reported by
    /// [`EntraConfig::is_configured`] and rejected at verification time.
    pub fn from_env() -> Self {
        let tenant_id = env::var("ENTRA_TENANT_ID").unwrap_or_default();
        let audiences = parse_audiences(env::var("ENTRA_CLIENT_ID").ok());
        Self::new(tenant_id, audiences)
    }

    pub fn is_configured(&self) -> bool {
        !self.tenant_id.is_empty() && !self.audiences.is_empty()
    }
}

/// The v2.0 issuer for a tenant. `iss` on a v2.0 id_token equals this exactly.
fn build_issuer(tenant_id: &str) -> String {
    format!("https://login.microsoftonline.com/{tenant_id}/v2.0")
}

/// The tenant-scoped JWKS (signing key) endpoint.
fn build_jwks_url(tenant_id: &str) -> String {
    format!("https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys")
}

/// Parse a comma-separated `ENTRA_CLIENT_ID` into a trimmed, non-empty list.
fn parse_audiences(raw: Option<String>) -> Vec<String> {
    raw.map(|raw| {
        raw.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
    })
    .unwrap_or_default()
}

/// Cached Entra JWKS plus the resolved tenant config.
///
/// Mirrors [`crate::apple_signin::AppleJwksCache`]; the difference is that the
/// keys URL is tenant-specific (held in `cfg`) and Entra signs `RS256`.
pub struct EntraJwksCache {
    inner: RwLock<CacheState>,
    cfg: EntraConfig,
    /// Reused HTTP client carrying an explicit total timeout (see
    /// [`ENTRA_JWKS_HTTP_TIMEOUT_SECS`]). Reused so the connection pool survives
    /// across refreshes rather than reconnecting on every cold fetch.
    http_client: reqwest::Client,
}

struct CacheState {
    keys: Vec<Jwk>,
    fetched_at: i64,
}

#[derive(Debug, Deserialize)]
struct EntraJwksResponse {
    keys: Vec<Jwk>,
}

impl EntraJwksCache {
    /// Construct from the environment. Use [`EntraJwksCache::with_config`] in
    /// tests to avoid touching env / the network.
    pub fn new() -> Self {
        Self::with_config(EntraConfig::from_env())
    }

    pub fn with_config(cfg: EntraConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(ENTRA_JWKS_HTTP_TIMEOUT_SECS))
            .build()
            .expect("build reqwest client for Entra JWKS");
        Self {
            inner: RwLock::new(CacheState {
                keys: Vec::new(),
                fetched_at: 0,
            }),
            cfg,
            http_client,
        }
    }

    async fn get_keys(&self) -> Result<Vec<Jwk>, EntraSigninError> {
        let now = Utc::now().timestamp();
        {
            let state = self.inner.read().await;
            if !state.keys.is_empty() && now - state.fetched_at < ENTRA_JWKS_CACHE_TTL_SECONDS {
                return Ok(state.keys.clone());
            }
        }

        let response = self
            .http_client
            .get(&self.cfg.jwks_url)
            .send()
            .await
            .map_err(|e| EntraSigninError::JwksFetch(e.to_string()))?;
        if !response.status().is_success() {
            return Err(EntraSigninError::JwksFetch(format!(
                "HTTP {}",
                response.status()
            )));
        }
        let body: EntraJwksResponse = response
            .json()
            .await
            .map_err(|e| EntraSigninError::JwksParse(e.to_string()))?;

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

impl Default for EntraJwksCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify an Entra-issued `id_token` against the tenant JWKS, issuer, tenant,
/// audience, and the supplied server-issued nonce.
///
/// `expected_raw_nonce` is the nonce AuthNZ bound to the ceremony (the OIDC
/// `nonce` query parameter in the authorize flow). The id_token's `nonce` claim
/// must equal that value or its hex SHA-256.
pub async fn verify_entra_id_token(
    cache: &EntraJwksCache,
    id_token: &str,
    expected_raw_nonce: &str,
) -> Result<EntraIdTokenClaims, EntraSigninError> {
    if !cache.cfg.is_configured() {
        return Err(EntraSigninError::NotConfigured);
    }

    let header = decode_header(id_token)
        .map_err(|e| EntraSigninError::InvalidToken(format!("header decode: {}", e)))?;
    let kid = header.kid.ok_or(EntraSigninError::MissingKid)?;

    let keys = cache.get_keys().await?;
    if let Some(jwk) = find_jwk(&keys, &kid) {
        return verify_with_jwk(jwk, id_token, &cache.cfg, expected_raw_nonce);
    }

    // Cache miss: force a refresh in case Entra rotated keys.
    warn!("Entra kid {} not in cache; forcing JWKS refresh", kid);
    cache.invalidate().await;
    let keys = cache.get_keys().await?;
    let jwk = find_jwk(&keys, &kid).ok_or_else(|| EntraSigninError::UnknownKid(kid.clone()))?;
    verify_with_jwk(jwk, id_token, &cache.cfg, expected_raw_nonce)
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

fn verify_with_jwk(
    jwk: &Jwk,
    id_token: &str,
    cfg: &EntraConfig,
    expected_raw_nonce: &str,
) -> Result<EntraIdTokenClaims, EntraSigninError> {
    // Entra signs id_tokens with RSA. Reject anything else outright rather than
    // silently widening the accepted algorithm set.
    let alg = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Algorithm::RS256,
        _ => {
            return Err(EntraSigninError::InvalidToken(
                "unsupported JWK algorithm parameters (expected RSA)".into(),
            ));
        }
    };

    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| EntraSigninError::InvalidToken(format!("DecodingKey: {}", e)))?;

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[&cfg.issuer]);
    validation.set_audience(&cfg.audiences);

    let data = decode::<EntraIdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| EntraSigninError::InvalidToken(e.to_string()))?;
    let claims = data.claims;

    // Defence-in-depth: re-check iss/aud/tid/nonce ourselves so a future
    // `Validation` misconfiguration can't silently widen the trust boundary.
    validate_entra_claims(&claims, cfg, expected_raw_nonce)?;
    Ok(claims)
}

/// Pure claim-validation: issuer, tenant, audience, and nonce binding.
///
/// Separated from signature verification so the full security contract is unit
/// testable without a network round-trip to the JWKS endpoint.
fn validate_entra_claims(
    claims: &EntraIdTokenClaims,
    cfg: &EntraConfig,
    expected_raw_nonce: &str,
) -> Result<(), EntraSigninError> {
    if claims.tid != cfg.tenant_id {
        return Err(EntraSigninError::TenantMismatch {
            expected: cfg.tenant_id.clone(),
            actual: claims.tid.clone(),
        });
    }
    if claims.iss != cfg.issuer {
        return Err(EntraSigninError::IssuerMismatch(claims.iss.clone()));
    }
    if !cfg.audiences.iter().any(|a| a == &claims.aud) {
        return Err(EntraSigninError::AudienceMismatch {
            expected: cfg.audiences.clone(),
            actual: claims.aud.clone(),
        });
    }
    check_nonce(claims.nonce.as_deref(), expected_raw_nonce)
}

/// Validate that the id_token's nonce claim binds to the server-issued nonce.
/// Accepts the raw value or its hex SHA-256. Constant-time comparison.
fn check_nonce(
    token_nonce: Option<&str>,
    expected_raw_nonce: &str,
) -> Result<(), EntraSigninError> {
    let token_nonce = token_nonce.ok_or(EntraSigninError::MissingTokenNonce)?;
    let hashed = sha256_hex(expected_raw_nonce);
    if !constant_time_eq(token_nonce, expected_raw_nonce) && !constant_time_eq(token_nonce, &hashed)
    {
        return Err(EntraSigninError::NonceMismatch);
    }
    Ok(())
}

/// Constant-time byte comparison **for equal-length inputs**. The early
/// length-mismatch return leaks the length of `b` (the expected nonce / its
/// 64-char hex hash) via timing. That is acceptable here: the nonce is the
/// client-supplied, single-use OIDC `nonce`, not a long-lived secret, so its
/// length is not sensitive. A vetted crate (`subtle`) would be required if a
/// stronger guarantee were ever needed.
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

/// Map verified Entra claims onto an Arkavo account, creating one if needed.
///
/// Join key is the Entra `oid` (directory object id), never email/UPN. Mirrors
/// [`crate::apple_signin::map_apple_user`]: first login provisions a real
/// DynamoDB row via [`crate::db::DynamoDBStore::create_user`] with a synthetic
/// `did:key:entra-<sha256(oid)>` DID.
pub async fn map_entra_user(
    app_state: &AppState,
    claims: &EntraIdTokenClaims,
) -> Result<AuthenticatedUser, DynamoDBError> {
    let username = format!("entra-{}", sanitize_for_username(&claims.oid));
    let did = format!("did:key:entra-{}", &sha256_hex(&claims.oid)[..32]);

    // NOTE: read-then-create is not atomic — two concurrent *first* logins for
    // the same `oid` can both observe `None` and provision duplicate accounts.
    // This is inherited from the shared `create_user` path (WebAuthn + Apple
    // have the same shape); making provisioning idempotent (conditional put on
    // `username`, re-read on conflict) is a db-layer follow-up tracked in #34,
    // not specific to Entra.
    let user = match app_state.db_store.get_user_by_name(&username).await? {
        Some(existing) => existing,
        None => {
            info!("Provisioning Arkavo account for Entra oid {}", claims.oid);
            app_state.db_store.create_user(&username, &did).await?
        }
    };

    // Org identities are managed by the tenant; treat them as verified. Prefer
    // `email`, fall back to UPN (`preferred_username`) for display only.
    let email = claims
        .email
        .clone()
        .or_else(|| claims.preferred_username.clone());

    Ok(AuthenticatedUser {
        subject: format!("entra:{}", claims.oid),
        arkavo_account_id: user.user_id.to_string(),
        email,
        email_verified: Some(true),
        idp: "entra".to_string(),
        roles: map_roles(&claims.roles),
        entitlements: map_entitlements(&claims.roles),
    })
}

/// Map Entra app roles → Arkavo roles. Defaults to `["user"]` when the token
/// carries no app roles (e.g. the app registration has none defined yet).
fn map_roles(app_roles: &[String]) -> Vec<String> {
    if app_roles.is_empty() {
        return vec!["user".to_string()];
    }
    app_roles.iter().map(|r| r.to_ascii_lowercase()).collect()
}

/// Derive OpenTDF entitlements from Entra app roles. Everyone authenticated may
/// create/decrypt; the `Admin` app role additionally grants `tdf:admin`.
fn map_entitlements(app_roles: &[String]) -> Vec<String> {
    let mut entitlements = vec!["tdf:create".to_string(), "tdf:decrypt".to_string()];
    if app_roles.iter().any(|r| r.eq_ignore_ascii_case("admin")) {
        entitlements.push("tdf:admin".to_string());
    }
    entitlements
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

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "11111111-2222-3333-4444-555555555555";
    const CLIENT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    fn test_cfg() -> EntraConfig {
        EntraConfig::new(TENANT, vec![CLIENT.to_string()])
    }

    fn valid_claims(nonce: &str) -> EntraIdTokenClaims {
        EntraIdTokenClaims {
            iss: build_issuer(TENANT),
            aud: CLIENT.to_string(),
            sub: "pairwise-subject-not-the-key".to_string(),
            oid: "00000000-1111-2222-3333-444444444444".to_string(),
            tid: TENANT.to_string(),
            iat: 1_700_000_000,
            exp: 1_700_003_600,
            nonce: Some(nonce.to_string()),
            preferred_username: Some("user@contoso.com".to_string()),
            email: Some("user@contoso.com".to_string()),
            roles: vec![],
            groups: vec![],
        }
    }

    #[test]
    fn test_build_issuer_is_v2_endpoint() {
        assert_eq!(
            build_issuer(TENANT),
            "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
        );
    }

    #[test]
    fn test_build_jwks_url() {
        assert_eq!(
            build_jwks_url(TENANT),
            "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/discovery/v2.0/keys"
        );
    }

    #[test]
    fn test_config_derives_endpoints_from_tenant() {
        let cfg = test_cfg();
        assert_eq!(cfg.issuer, build_issuer(TENANT));
        assert_eq!(cfg.jwks_url, build_jwks_url(TENANT));
        assert!(cfg.is_configured());
    }

    #[test]
    fn test_config_not_configured_when_empty() {
        assert!(!EntraConfig::new("", vec![]).is_configured());
        assert!(!EntraConfig::new(TENANT, vec![]).is_configured());
        assert!(!EntraConfig::new("", vec![CLIENT.to_string()]).is_configured());
    }

    #[test]
    fn test_parse_audiences_comma_separated() {
        let parsed = parse_audiences(Some(format!(" {CLIENT} , api://{CLIENT} ,")));
        assert_eq!(parsed, vec![CLIENT.to_string(), format!("api://{CLIENT}")]);
    }

    #[test]
    fn test_parse_audiences_none_is_empty() {
        assert!(parse_audiences(None).is_empty());
        assert!(parse_audiences(Some("   ".to_string())).is_empty());
    }

    #[test]
    fn test_validate_claims_ok() {
        let cfg = test_cfg();
        assert!(validate_entra_claims(&valid_claims("the-nonce"), &cfg, "the-nonce").is_ok());
    }

    #[test]
    fn test_validate_claims_accepts_sha256_nonce() {
        let cfg = test_cfg();
        let raw = "the-raw-nonce";
        let hashed = sha256_hex(raw);
        let claims = valid_claims(&hashed);
        assert!(validate_entra_claims(&claims, &cfg, raw).is_ok());
    }

    #[test]
    fn test_validate_claims_rejects_tenant_mismatch() {
        let cfg = test_cfg();
        let mut claims = valid_claims("n");
        claims.tid = "99999999-9999-9999-9999-999999999999".to_string();
        assert!(matches!(
            validate_entra_claims(&claims, &cfg, "n"),
            Err(EntraSigninError::TenantMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_claims_rejects_issuer_mismatch() {
        let cfg = test_cfg();
        let mut claims = valid_claims("n");
        claims.iss = "https://login.microsoftonline.com/other/v2.0".to_string();
        assert!(matches!(
            validate_entra_claims(&claims, &cfg, "n"),
            Err(EntraSigninError::IssuerMismatch(_))
        ));
    }

    #[test]
    fn test_validate_claims_rejects_audience_mismatch() {
        let cfg = test_cfg();
        let mut claims = valid_claims("n");
        claims.aud = "some-other-app".to_string();
        assert!(matches!(
            validate_entra_claims(&claims, &cfg, "n"),
            Err(EntraSigninError::AudienceMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_claims_rejects_nonce_mismatch() {
        let cfg = test_cfg();
        let claims = valid_claims("not-the-nonce");
        assert!(matches!(
            validate_entra_claims(&claims, &cfg, "expected-nonce"),
            Err(EntraSigninError::NonceMismatch)
        ));
    }

    #[test]
    fn test_validate_claims_rejects_missing_nonce() {
        let cfg = test_cfg();
        let mut claims = valid_claims("ignored");
        claims.nonce = None;
        assert!(matches!(
            validate_entra_claims(&claims, &cfg, "expected"),
            Err(EntraSigninError::MissingTokenNonce)
        ));
    }

    #[test]
    fn test_check_nonce_accepts_verbatim_and_hash() {
        let raw = "raw-nonce-12345";
        assert!(check_nonce(Some(raw), raw).is_ok());
        assert!(check_nonce(Some(&sha256_hex(raw)), raw).is_ok());
    }

    #[test]
    fn test_check_nonce_rejects_empty_when_raw_nonempty() {
        assert!(matches!(
            check_nonce(Some(""), "raw"),
            Err(EntraSigninError::NonceMismatch)
        ));
    }

    #[test]
    fn test_check_nonce_rejects_hash_of_wrong_value() {
        let other = sha256_hex("other-nonce");
        assert!(matches!(
            check_nonce(Some(&other), "expected-nonce"),
            Err(EntraSigninError::NonceMismatch)
        ));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("hello", "hello"));
        assert!(!constant_time_eq("hello", "world"));
        assert!(!constant_time_eq("hello", "hello!"));
        assert!(!constant_time_eq("", "x"));
    }

    #[test]
    fn test_map_roles_defaults_to_user() {
        assert_eq!(map_roles(&[]), vec!["user".to_string()]);
    }

    #[test]
    fn test_map_roles_lowercases_app_roles() {
        let roles = vec!["Admin".to_string(), "Standard".to_string()];
        assert_eq!(
            map_roles(&roles),
            vec!["admin".to_string(), "standard".to_string()]
        );
    }

    #[test]
    fn test_map_entitlements_non_admin() {
        assert_eq!(
            map_entitlements(&["Standard".to_string()]),
            vec!["tdf:create".to_string(), "tdf:decrypt".to_string()]
        );
    }

    #[test]
    fn test_map_entitlements_admin_gets_tdf_admin() {
        let e = map_entitlements(&["admin".to_string()]);
        assert!(e.contains(&"tdf:admin".to_string()));
        // Case-insensitive on the role name.
        assert!(map_entitlements(&["ADMIN".to_string()]).contains(&"tdf:admin".to_string()));
    }

    #[test]
    fn test_sanitize_for_username() {
        assert_eq!(
            sanitize_for_username("00000000-1111-2222"),
            "00000000-1111-2222"
        );
        assert_eq!(
            sanitize_for_username("oid/with<bad>chars"),
            "oidwithbadchars"
        );
        assert_eq!(sanitize_for_username(&"a".repeat(200)).len(), 128);
    }

    #[test]
    fn test_sha256_hex_stable() {
        let a = sha256_hex("entra-oid");
        assert_eq!(a, sha256_hex("entra-oid"));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn test_oid_is_account_key_not_email() {
        // The derived username must depend only on `oid`, so a UPN/email change
        // does not fork the account.
        let mut c1 = valid_claims("n");
        c1.email = Some("before@contoso.com".to_string());
        let mut c2 = valid_claims("n");
        c2.email = Some("after@contoso.com".to_string());
        assert_eq!(c1.oid, c2.oid);
        let u1 = format!("entra-{}", sanitize_for_username(&c1.oid));
        let u2 = format!("entra-{}", sanitize_for_username(&c2.oid));
        assert_eq!(u1, u2);
    }

    #[test]
    fn test_claims_deserialize_real_shape_with_defaults() {
        // A token without `roles`/`groups` must still deserialize (serde default).
        let json = format!(
            r#"{{
                "iss":"{iss}",
                "aud":"{CLIENT}",
                "sub":"pair-wise",
                "oid":"00000000-1111-2222-3333-444444444444",
                "tid":"{TENANT}",
                "iat":1700000000,
                "exp":1700003600,
                "nonce":"abc",
                "preferred_username":"user@contoso.com"
            }}"#,
            iss = build_issuer(TENANT),
        );
        let claims: EntraIdTokenClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims.oid, "00000000-1111-2222-3333-444444444444");
        assert_eq!(claims.tid, TENANT);
        assert!(claims.roles.is_empty());
        assert!(claims.groups.is_empty());
        assert_eq!(claims.email, None);
    }

    #[test]
    fn test_claims_deserialize_with_roles_and_groups() {
        let json = format!(
            r#"{{
                "iss":"{iss}","aud":"{CLIENT}","sub":"s",
                "oid":"o","tid":"{TENANT}","iat":1,"exp":2,
                "roles":["Admin","Reader"],
                "groups":["group-guid-1","group-guid-2"]
            }}"#,
            iss = build_issuer(TENANT),
        );
        let claims: EntraIdTokenClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims.roles, vec!["Admin", "Reader"]);
        assert_eq!(claims.groups.len(), 2);
    }

    #[test]
    fn test_error_status_mapping() {
        assert_eq!(
            EntraSigninError::JwksFetch("x".into())
                .into_response()
                .status(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            EntraSigninError::NotConfigured.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        for unauthorized in [
            EntraSigninError::MissingKid,
            EntraSigninError::UnknownKid("k".into()),
            EntraSigninError::InvalidToken("t".into()),
            EntraSigninError::IssuerMismatch("i".into()),
            EntraSigninError::TenantMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            EntraSigninError::AudienceMismatch {
                expected: vec!["a".into()],
                actual: "b".into(),
            },
            EntraSigninError::MissingTokenNonce,
            EntraSigninError::NonceMismatch,
        ] {
            assert_eq!(
                unauthorized.into_response().status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }

    #[test]
    fn test_audience_mismatch_message_lists_expected() {
        let err = EntraSigninError::AudienceMismatch {
            expected: vec![CLIENT.to_string()],
            actual: "evil-app".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains(CLIENT));
        assert!(msg.contains("evil-app"));
    }
}

/// Network-path integration tests for [`verify_entra_id_token`].
///
/// These exercise the *full* verification pipeline that the pure unit tests
/// above deliberately skip: a real RS256-signed id_token is decoded against a
/// JWKS served over HTTP by an ephemeral local server, so signature
/// verification, `kid` lookup (incl. force-refresh on miss), and the
/// `jsonwebtoken` exp/iss/aud checks are all genuinely executed.
///
/// No key material is committed: a throwaway RSA-2048 keypair is generated once
/// per test run (see [`TEST_KEY`]). Its PKCS#8 PEM signs the test id_tokens, and
/// its public modulus/exponent are served in the mock JWKS so
/// `DecodingKey::from_jwk` reconstructs the matching public key.
#[cfg(test)]
mod jwks_network_tests {
    use super::*;
    use axum::{Json, Router, routing::get};
    use base64::Engine as _;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::traits::PublicKeyParts;
    use serde::Serialize;
    use std::sync::LazyLock;
    use tokio::net::TcpListener;

    const TENANT: &str = "11111111-2222-3333-4444-555555555555";
    const CLIENT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const TEST_KID: &str = "test-kid-1";

    /// An ephemeral RSA keypair, generated once and shared across the tests.
    /// Nothing here is a real credential — it exists only to produce a valid
    /// RS256 signature and the matching JWKS within a single test process.
    struct TestKey {
        /// PKCS#8 PEM of the private key, fed to `EncodingKey::from_rsa_pem`.
        signing_pem: String,
        /// base64url public modulus / exponent for the served JWK.
        jwk_n: String,
        jwk_e: String,
    }

    static TEST_KEY: LazyLock<TestKey> = LazyLock::new(|| {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("generate test RSA key");
        let public = private.to_public_key();
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        TestKey {
            signing_pem: private
                .to_pkcs8_pem(LineEnding::LF)
                .expect("encode pkcs8 pem")
                .as_str()
                .to_owned(),
            jwk_n: b64(&public.n().to_bytes_be()),
            jwk_e: b64(&public.e().to_bytes_be()),
        }
    });

    #[derive(Serialize)]
    struct SignedClaims {
        iss: String,
        aud: String,
        sub: String,
        oid: String,
        tid: String,
        iat: i64,
        exp: i64,
        nonce: String,
    }

    fn valid_signed_claims(nonce: &str) -> SignedClaims {
        let now = Utc::now().timestamp();
        SignedClaims {
            iss: build_issuer(TENANT),
            aud: CLIENT.to_string(),
            sub: "pairwise-subject".to_string(),
            oid: "00000000-1111-2222-3333-444444444444".to_string(),
            tid: TENANT.to_string(),
            iat: now,
            exp: now + 3600,
            nonce: nonce.to_string(),
        }
    }

    /// Sign `claims` into an RS256 JWT with the given `kid`, using the test key.
    fn sign(claims: &SignedClaims, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let key = EncodingKey::from_rsa_pem(TEST_KEY.signing_pem.as_bytes())
            .expect("test RSA PEM parses");
        encode(&header, claims, &key).expect("sign id_token")
    }

    /// Spin up an ephemeral local HTTP server that serves a JWKS containing a
    /// single RSA key with the given `kid`. Returns the `/keys` URL.
    async fn spawn_jwks_server(kid: &str) -> String {
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": TEST_KEY.jwk_n,
                "e": TEST_KEY.jwk_e,
            }]
        });
        let app = Router::new().route(
            "/keys",
            get(move || {
                let jwks = jwks.clone();
                async move { Json(jwks) }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/keys")
    }

    /// Build a cache whose JWKS endpoint points at `jwks_url` instead of the
    /// real Microsoft endpoint, while keeping the real tenant-derived issuer.
    fn cache_for(jwks_url: String) -> EntraJwksCache {
        let mut cfg = EntraConfig::new(TENANT, vec![CLIENT.to_string()]);
        cfg.jwks_url = jwks_url;
        EntraJwksCache::with_config(cfg)
    }

    #[tokio::test]
    async fn accepts_valid_signed_token() {
        let nonce = "the-nonce";
        let token = sign(&valid_signed_claims(nonce), TEST_KID);
        let cache = cache_for(spawn_jwks_server(TEST_KID).await);

        let claims = verify_entra_id_token(&cache, &token, nonce)
            .await
            .expect("valid token should verify");
        assert_eq!(claims.oid, "00000000-1111-2222-3333-444444444444");
        assert_eq!(claims.tid, TENANT);
        assert_eq!(claims.aud, CLIENT);
    }

    #[tokio::test]
    async fn accepts_sha256_hashed_nonce() {
        let raw = "raw-nonce-value";
        let token = sign(&valid_signed_claims(&sha256_hex(raw)), TEST_KID);
        let cache = cache_for(spawn_jwks_server(TEST_KID).await);

        assert!(verify_entra_id_token(&cache, &token, raw).await.is_ok());
    }

    #[tokio::test]
    async fn rejects_wrong_nonce() {
        let token = sign(&valid_signed_claims("issued-nonce"), TEST_KID);
        let cache = cache_for(spawn_jwks_server(TEST_KID).await);

        assert!(matches!(
            verify_entra_id_token(&cache, &token, "different-nonce").await,
            Err(EntraSigninError::NonceMismatch)
        ));
    }

    #[tokio::test]
    async fn rejects_tampered_signature() {
        // Flip the last char of the signature segment — proves the signature is
        // actually checked against the JWKS, not merely decoded.
        let token = sign(&valid_signed_claims("n"), TEST_KID);
        let mut bytes = token.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        let cache = cache_for(spawn_jwks_server(TEST_KID).await);

        assert!(matches!(
            verify_entra_id_token(&cache, &tampered, "n").await,
            Err(EntraSigninError::InvalidToken(_))
        ));
    }

    #[tokio::test]
    async fn rejects_unknown_kid_after_refresh() {
        // Token is signed with TEST_KID, but the JWKS only publishes a different
        // kid — exercises the cache-miss → force-refresh → still-missing path.
        let token = sign(&valid_signed_claims("n"), TEST_KID);
        let cache = cache_for(spawn_jwks_server("some-other-kid").await);

        assert!(matches!(
            verify_entra_id_token(&cache, &token, "n").await,
            Err(EntraSigninError::UnknownKid(_))
        ));
    }

    #[tokio::test]
    async fn rejects_expired_token() {
        let mut claims = valid_signed_claims("n");
        let now = Utc::now().timestamp();
        claims.iat = now - 7200;
        claims.exp = now - 3600; // expired an hour ago
        let token = sign(&claims, TEST_KID);
        let cache = cache_for(spawn_jwks_server(TEST_KID).await);

        // jsonwebtoken enforces exp during decode → surfaced as InvalidToken.
        assert!(matches!(
            verify_entra_id_token(&cache, &token, "n").await,
            Err(EntraSigninError::InvalidToken(_))
        ));
    }

    #[tokio::test]
    async fn rejects_wrong_issuer() {
        let mut claims = valid_signed_claims("n");
        claims.iss = "https://login.microsoftonline.com/99999999/v2.0".to_string();
        let token = sign(&claims, TEST_KID);
        let cache = cache_for(spawn_jwks_server(TEST_KID).await);

        assert!(verify_entra_id_token(&cache, &token, "n").await.is_err());
    }

    #[tokio::test]
    async fn unconfigured_cache_rejects_before_network() {
        // Empty tenant/audience → NotConfigured, without ever hitting the net.
        let cache = EntraJwksCache::with_config(EntraConfig::new("", vec![]));
        let token = sign(&valid_signed_claims("n"), TEST_KID);
        assert!(matches!(
            verify_entra_id_token(&cache, &token, "n").await,
            Err(EntraSigninError::NotConfigured)
        ));
    }
}
