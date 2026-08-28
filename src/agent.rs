//! Agent delegation: a human (PE) authorizes an agent (NPE, identified by
//! `did:key`) to act on their behalf; the agent then proves key possession
//! and receives an agent access token plus a signed delegation JWT.
//!
//! Extracted from PR #23 onto the CWT-based `main`. Wire contract follows
//! `arkavo-edge/crates/arkavo-agent-auth` (issue #54):
//!
//! ```text
//! Terminal (arkavo agent run --trust)          Arkavo iOS app
//! ───────────────────────────────────────────────────────────────────
//! QR: arkavo://agent/authorize?did=…  ──scan──►  POST /agents/authorize
//!                                                X-Auth-Token: <human CWT>
//!                                                {agent_did, name, entitlements}
//! GET  /agents/challenge?did=…   ──►  {challenge: b64(32 bytes), nonce}
//! POST /agents/token             ──►  {token, expires_at, entitlements, delegation_jwt}
//!      {did, challenge, signature: b64(Ed25519 over challenge bytes), nonce}
//! ```
//!
//! - `token` is a CWT access token (`sub` = agent DID, `arkavo_roles = ["agent"]`,
//!   `arkavo_entitlements` = delegated set, `arkavo_account_id` = root user).
//! - `delegation_jwt` is ES256 under the OIDC signing key (`kid` matches the
//!   JWKS): `sub` = agent DID, `act` = root user, `scope` = entitlement array.
//!   `arkavo-protocol/src/registration` already parses this shape.
//! - The pending challenge lives on the delegation row and is removed
//!   atomically when taken — no cookie session, so headless CLIs work.
//!
//! Not in this module (tracked separately): agent→agent delegation
//! (delegator must be a human CWT today), per-agent OAuth clients (#50),
//! the ERS resolution surface (#48), per-user entitlement storage (#53).

use crate::AppState;
use crate::constants::{
    AGENT_CHALLENGE_TTL_SECONDS, AGENT_DELEGATION_DAYS, AGENT_TOKEN_HOURS,
    DEFAULT_USER_ENTITLEMENTS, MAX_AGENTS_PER_USER, MAX_DELEGATION_DEPTH,
};
use crate::cwt;
use crate::db::{AgentDelegation, DynamoDBError};
use axum::http::HeaderMap;
use axum::{
    extract::{Extension, Json, Path, Query},
    http::StatusCode,
    response::IntoResponse,
};
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jsonwebtoken::{Algorithm, Header, encode};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

// ============================================================================
// Discovery
// ============================================================================

/// Metadata served at `/.well-known/agent-configuration`.
#[derive(Debug, Clone, Serialize)]
pub struct AgentConfiguration {
    pub issuer: String,
    pub agent_authorization_endpoint: String,
    pub agent_delegations_endpoint: String,
    pub agent_revocation_endpoint: String,
    pub agent_challenge_endpoint: String,
    pub agent_token_endpoint: String,
    pub entitlements_supported: Vec<&'static str>,
    pub max_delegation_depth: u8,
    pub max_agents_per_user: u32,
    pub delegation_lifetime_seconds: i64,
    pub agent_token_lifetime_seconds: i64,
    pub challenge_ttl_seconds: i64,
    pub did_methods_supported: Vec<&'static str>,
    pub proof_signing_alg_values_supported: Vec<&'static str>,
    pub delegation_jwt_signing_alg: &'static str,
    pub authorization_deep_link_scheme: String,
}

impl AgentConfiguration {
    pub fn new(issuer: &str) -> Self {
        let base = issuer.trim_end_matches('/');
        Self {
            issuer: base.to_string(),
            agent_authorization_endpoint: format!("{}/agents/authorize", base),
            agent_delegations_endpoint: format!("{}/agents/delegations", base),
            agent_revocation_endpoint: format!("{}/agents/delegations", base),
            agent_challenge_endpoint: format!("{}/agents/challenge", base),
            agent_token_endpoint: format!("{}/agents/token", base),
            entitlements_supported: DEFAULT_USER_ENTITLEMENTS.to_vec(),
            max_delegation_depth: MAX_DELEGATION_DEPTH,
            max_agents_per_user: MAX_AGENTS_PER_USER,
            delegation_lifetime_seconds: AGENT_DELEGATION_DAYS * 24 * 60 * 60,
            agent_token_lifetime_seconds: AGENT_TOKEN_HOURS * 60 * 60,
            challenge_ttl_seconds: AGENT_CHALLENGE_TTL_SECONDS,
            did_methods_supported: vec!["did:key"],
            proof_signing_alg_values_supported: vec!["EdDSA"],
            delegation_jwt_signing_alg: "ES256",
            authorization_deep_link_scheme: "arkavo://agent/authorize".to_string(),
        }
    }
}

/// GET /.well-known/agent-configuration
pub async fn serve_agent_configuration(
    Extension(app_state): Extension<AppState>,
) -> impl IntoResponse {
    Json(AgentConfiguration::new(&app_state.issuer))
}

// ============================================================================
// Wire types (contract: arkavo-agent-auth)
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AuthorizeAgentRequest {
    pub agent_did: String,
    pub name: String,
    pub entitlements: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeAgentResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeQueryParams {
    pub did: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// Base64 (standard) of 32 random bytes. The agent signs the decoded bytes.
    pub challenge: String,
    /// Opaque nonce that must be echoed back on `/agents/token`.
    pub nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub did: String,
    pub challenge: String,
    /// Base64 (standard) Ed25519 signature over the decoded challenge bytes.
    pub signature: String,
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    /// CWT access token (header encoding), see [`crate::cwt::encode_for_header`].
    pub token: String,
    /// Unix epoch seconds.
    pub expires_at: i64,
    pub entitlements: Vec<String>,
    /// ES256 JWT binding the root user to this agent DID.
    pub delegation_jwt: String,
}

#[derive(Debug, Serialize)]
pub struct DelegationListResponse {
    pub delegations: Vec<DelegationInfo>,
}

#[derive(Debug, Serialize)]
pub struct DelegationInfo {
    pub agent_did: String,
    pub name: String,
    pub entitlements: Vec<String>,
    pub depth: u8,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked: bool,
}

/// Claims of the delegation JWT. `scope` is a JSON array (not a space-joined
/// string) because that is what the arkavo-edge registration path parses.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationJwtClaims {
    pub iss: String,
    /// Agent did:key
    pub sub: String,
    /// Root user id (the PE the agent acts for)
    pub act: String,
    pub scope: Vec<String>,
    pub iat: i64,
    pub exp: i64,
    /// Delegation id (agent DID is the row key; jti is per-mint)
    pub jti: String,
    pub depth: u8,
}

// ============================================================================
// did:key utilities
// ============================================================================

/// Extract the Ed25519 public key from `did:key:z6Mk…` (multicodec 0xed01,
/// base58btc).
pub fn extract_ed25519_pubkey(did: &str) -> Result<[u8; 32], AgentError> {
    let key_part = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| AgentError::InvalidDID("Must start with did:key:z".into()))?;

    let decoded = bs58::decode(key_part)
        .into_vec()
        .map_err(|e| AgentError::InvalidDID(format!("Invalid base58: {}", e)))?;

    if decoded.len() != 34 {
        return Err(AgentError::InvalidDID(format!(
            "Invalid length: expected 34 bytes, got {}",
            decoded.len()
        )));
    }
    if decoded[0..2] != [0xed, 0x01] {
        return Err(AgentError::InvalidDID(format!(
            "Invalid Ed25519 multicodec prefix: expected 0xed01, got 0x{:02x}{:02x}",
            decoded[0], decoded[1]
        )));
    }
    decoded[2..34]
        .try_into()
        .map_err(|_| AgentError::InvalidDID("Invalid key length".into()))
}

pub fn validate_did_key(did: &str) -> Result<(), AgentError> {
    extract_ed25519_pubkey(did).map(|_| ())
}

// ============================================================================
// Human (PE) authentication
// ============================================================================

struct HumanDelegator {
    user_id: Uuid,
    username: Option<String>,
}

/// Authenticate the human delegator from `X-Auth-Token` (Arkavo CWT, `aud = "arkavo"`).
///
/// Only WebAuthn-derived subjects (`arkavo:<uuid>`) may delegate; Apple-only
/// and service-account subjects are rejected. Agent-to-agent delegation is
/// not supported yet (the delegator must be a human CWT).
async fn authenticate_human(
    app_state: &AppState,
    headers: &HeaderMap,
) -> Result<HumanDelegator, AgentError> {
    let token = headers
        .get("X-Auth-Token")
        .ok_or(AgentError::MissingToken)?
        .to_str()
        .map_err(|_| AgentError::InvalidToken)?;

    let bytes = cwt::decode_from_header(token).map_err(|_| AgentError::InvalidToken)?;
    let opts = cwt::VerifyOptions {
        expected_iss: Some(&app_state.issuer),
        expected_aud: Some("arkavo"),
        now: Utc::now().timestamp(),
        skew_secs: cwt::DEFAULT_SKEW_SECS,
    };
    let claims = cwt::verify(&bytes, &app_state.cwt_verifying_key, &opts).map_err(|e| {
        warn!("Rejected delegator token: {}", e);
        AgentError::InvalidToken
    })?;

    let user_id = user_id_from_claims(&claims)?;
    let username = app_state
        .db_store
        .get_user_by_id(&user_id)
        .await
        .ok()
        .flatten()
        .map(|u| u.username);

    Ok(HumanDelegator { user_id, username })
}

/// Root user id from a verified CWT: `arkavo_account_id` when present, else
/// the `arkavo:<uuid>` subject. Other subject namespaces cannot delegate.
fn user_id_from_claims(claims: &cwt::ArkavoClaims) -> Result<Uuid, AgentError> {
    let raw = claims
        .custom
        .arkavo_account_id
        .as_deref()
        .or_else(|| claims.sub.strip_prefix("arkavo:"))
        .ok_or_else(|| {
            AgentError::Unauthorized(format!(
                "subject '{}' is not a WebAuthn-registered user",
                claims.sub
            ))
        })?;
    Uuid::parse_str(raw).map_err(|_| {
        AgentError::Unauthorized(format!("subject '{}' has no valid account id", claims.sub))
    })
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /agents/authorize — human (PE) delegates to an agent (NPE).
pub async fn authorize_agent(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Json(request): Json<AuthorizeAgentRequest>,
) -> Result<impl IntoResponse, AgentError> {
    info!(
        "Authorizing agent: {} with name: {}",
        request.agent_did, request.name
    );
    validate_did_key(&request.agent_did)?;
    if request.entitlements.is_empty() {
        return Err(AgentError::InsufficientEntitlements(
            "At least one entitlement is required".into(),
        ));
    }

    let human = authenticate_human(&app_state, &headers).await?;

    // Subset check against the delegable set for humans (per-user storage: #53).
    for entitlement in &request.entitlements {
        if !DEFAULT_USER_ENTITLEMENTS.contains(&entitlement.as_str()) {
            return Err(AgentError::InsufficientEntitlements(format!(
                "Entitlement '{}' is not delegable",
                entitlement
            )));
        }
    }

    let depth: u8 = 0;
    if depth >= MAX_DELEGATION_DEPTH {
        return Err(AgentError::MaxDepthExceeded(depth));
    }

    let current_count = app_state
        .db_store
        .count_delegations_by_root_user(human.user_id)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;
    if current_count >= MAX_AGENTS_PER_USER {
        return Err(AgentError::MaxAgentsExceeded(current_count));
    }

    if let Some(existing) = app_state
        .db_store
        .get_agent_delegation(&request.agent_did)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?
        && existing.revoked_at.is_none()
    {
        return Err(AgentError::DelegationAlreadyExists);
    }

    let now = Utc::now().timestamp();
    let delegation = AgentDelegation {
        agent_did: request.agent_did.clone(),
        delegator_type: "human".to_string(),
        delegator_id: human.user_id.to_string(),
        delegator_username: human.username,
        entitlements: request.entitlements,
        name: request.name,
        depth,
        root_user_id: human.user_id,
        chain: vec![],
        created_at: now,
        expires_at: Some(now + AGENT_DELEGATION_DAYS * 24 * 60 * 60),
        revoked_at: None,
    };

    app_state
        .db_store
        .create_agent_delegation(&delegation)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;

    info!("Agent delegation created for: {}", request.agent_did);
    Ok(Json(AuthorizeAgentResponse {
        success: true,
        message: "Agent authorized successfully".to_string(),
    }))
}

/// GET /agents/delegations — list the caller's delegations.
pub async fn list_delegations(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AgentError> {
    let human = authenticate_human(&app_state, &headers).await?;

    let delegations = app_state
        .db_store
        .list_delegations_by_root_user(human.user_id)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;

    Ok(Json(DelegationListResponse {
        delegations: delegations
            .into_iter()
            .map(|d| DelegationInfo {
                agent_did: d.agent_did,
                name: d.name,
                entitlements: d.entitlements,
                depth: d.depth,
                created_at: d.created_at,
                expires_at: d.expires_at,
                revoked: d.revoked_at.is_some(),
            })
            .collect(),
    }))
}

/// DELETE /agents/delegations/:did — revoke, cascading to child delegations.
pub async fn revoke_delegation(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Path(agent_did): Path<String>,
) -> Result<impl IntoResponse, AgentError> {
    let human = authenticate_human(&app_state, &headers).await?;

    let delegation = app_state
        .db_store
        .get_agent_delegation(&agent_did)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?
        .ok_or(AgentError::DelegationNotFound)?;
    if delegation.root_user_id != human.user_id {
        return Err(AgentError::Unauthorized(
            "delegation belongs to a different user".into(),
        ));
    }

    app_state
        .db_store
        .revoke_delegation(&agent_did)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;
    let cascaded = app_state
        .db_store
        .revoke_delegations_with_chain(&agent_did)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;

    info!(
        "Revoked delegation {} and {} child delegations",
        agent_did, cascaded
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Load a delegation and check it is active (not revoked/expired, chain intact).
async fn active_delegation(
    app_state: &AppState,
    agent_did: &str,
) -> Result<AgentDelegation, AgentError> {
    let delegation = app_state
        .db_store
        .get_agent_delegation(agent_did)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?
        .ok_or(AgentError::DelegationNotFound)?;

    if delegation.revoked_at.is_some() {
        return Err(AgentError::DelegationRevoked);
    }
    if let Some(expires_at) = delegation.expires_at
        && Utc::now().timestamp() > expires_at
    {
        return Err(AgentError::DelegationExpired);
    }
    for ancestor_did in &delegation.chain {
        if let Some(ancestor) = app_state
            .db_store
            .get_agent_delegation(ancestor_did)
            .await
            .map_err(|e| AgentError::DatabaseError(Box::new(e)))?
            && ancestor.revoked_at.is_some()
        {
            return Err(AgentError::ChainRevoked(ancestor_did.clone()));
        }
    }
    Ok(delegation)
}

fn random_challenge_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

/// GET /agents/challenge?did=… — issue a challenge for an active delegation.
pub async fn generate_agent_challenge(
    Extension(app_state): Extension<AppState>,
    Query(params): Query<ChallengeQueryParams>,
) -> Result<impl IntoResponse, AgentError> {
    validate_did_key(&params.did)?;
    active_delegation(&app_state, &params.did).await?;

    let challenge = base64::engine::general_purpose::STANDARD.encode(random_challenge_bytes());
    let nonce = Uuid::new_v4().to_string();

    app_state
        .db_store
        .put_agent_challenge(&params.did, &challenge, &nonce, Utc::now().timestamp())
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;

    info!("Challenge issued for agent: {}", params.did);
    Ok(Json(ChallengeResponse { challenge, nonce }))
}

/// POST /agents/token — verify the signed challenge, mint agent token + delegation JWT.
pub async fn issue_agent_token(
    Extension(app_state): Extension<AppState>,
    Json(request): Json<TokenRequest>,
) -> Result<impl IntoResponse, AgentError> {
    info!("Issuing agent token for DID: {}", request.did);
    validate_did_key(&request.did)?;

    // Take the challenge first so a bad proof still burns it (no retries on
    // the same challenge), then check TTL.
    let taken = app_state
        .db_store
        .take_agent_challenge(&request.did, &request.challenge, &request.nonce)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?
        .ok_or(AgentError::ChallengeMismatch)?;
    if Utc::now().timestamp() - taken.issued_at > AGENT_CHALLENGE_TTL_SECONDS {
        return Err(AgentError::ChallengeExpired);
    }

    let delegation = active_delegation(&app_state, &request.did).await?;

    let challenge_bytes = base64::engine::general_purpose::STANDARD
        .decode(&request.challenge)
        .map_err(|e| AgentError::InvalidProof(format!("Invalid challenge base64: {}", e)))?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&request.signature)
        .map_err(|e| AgentError::InvalidProof(format!("Invalid signature base64: {}", e)))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| AgentError::InvalidProof(format!("Invalid signature format: {}", e)))?;
    let verifying_key = VerifyingKey::from_bytes(&extract_ed25519_pubkey(&request.did)?)
        .map_err(|e| AgentError::InvalidDID(format!("Invalid public key: {}", e)))?;
    verifying_key
        .verify(&challenge_bytes, &signature)
        .map_err(|_| AgentError::InvalidProof("Signature verification failed".into()))?;

    let (token, expires_at) = mint_agent_cwt(&app_state, &delegation)?;
    let delegation_jwt = mint_delegation_jwt(&app_state, &delegation)?;

    info!(
        "Agent token issued for {} (depth {})",
        request.did, delegation.depth
    );
    Ok(Json(TokenResponse {
        token,
        expires_at,
        entitlements: delegation.entitlements,
        delegation_jwt,
    }))
}

// ============================================================================
// Token minting
// ============================================================================

/// CWT access token for the agent NPE. Audience is the platform audience when
/// configured (so the OpenTDF verifier accepts it), else `"arkavo"`.
fn mint_agent_cwt(
    app_state: &AppState,
    delegation: &AgentDelegation,
) -> Result<(String, i64), AgentError> {
    let audience = app_state.platform_audience.as_deref().unwrap_or("arkavo");
    let claims = cwt::ArkavoClaims::oidc_access(
        &app_state.issuer,
        &delegation.agent_did,
        audience,
        AGENT_TOKEN_HOURS,
    )
    .with_arkavo_account_id(&delegation.root_user_id.to_string())
    .with_arkavo_roles(vec!["agent".to_string()])
    .with_arkavo_entitlements(delegation.entitlements.clone());
    let expires_at = claims.exp;
    let bytes = cwt::mint(&claims, &app_state.cwt_signing_key, &app_state.cwt_kid)
        .map_err(|e| AgentError::TokenGenerationError(e.to_string()))?;
    Ok((cwt::encode_for_header(&bytes), expires_at))
}

pub fn delegation_jwt_claims(
    issuer: &str,
    delegation: &AgentDelegation,
    now: i64,
) -> DelegationJwtClaims {
    DelegationJwtClaims {
        iss: issuer.to_string(),
        sub: delegation.agent_did.clone(),
        act: delegation.root_user_id.to_string(),
        scope: delegation.entitlements.clone(),
        iat: now,
        exp: delegation
            .expires_at
            .unwrap_or(now + AGENT_DELEGATION_DAYS * 24 * 60 * 60),
        jti: Uuid::new_v4().to_string(),
        depth: delegation.depth,
    }
}

fn mint_delegation_jwt(
    app_state: &AppState,
    delegation: &AgentDelegation,
) -> Result<String, AgentError> {
    let claims = delegation_jwt_claims(&app_state.issuer, delegation, Utc::now().timestamp());
    let mut header = Header::new(Algorithm::ES256);
    // Same kid the JWKS advertises (base64url of the CWT kid bytes).
    header.kid = Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*app_state.cwt_kid));
    encode(&header, &claims, &app_state.encoding_key)
        .map_err(|e| AgentError::TokenGenerationError(format!("delegation_jwt: {}", e)))
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Error, Debug)]
pub enum AgentError {
    #[error("Invalid DID format: {0}")]
    InvalidDID(String),
    #[error("Delegation not found")]
    DelegationNotFound,
    #[error("Delegation already exists")]
    DelegationAlreadyExists,
    #[error("Delegation revoked")]
    DelegationRevoked,
    #[error("Delegation expired")]
    DelegationExpired,
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    #[error("Maximum delegation depth ({0}) exceeded")]
    MaxDepthExceeded(u8),
    #[error("Maximum agents per user ({0}) exceeded")]
    MaxAgentsExceeded(u32),
    #[error("Insufficient entitlements: {0}")]
    InsufficientEntitlements(String),
    #[error("Invalid token")]
    InvalidToken,
    #[error("Missing token")]
    MissingToken,
    #[error("Token generation error: {0}")]
    TokenGenerationError(String),
    #[error("Chain revoked at: {0}")]
    ChainRevoked(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Challenge mismatch")]
    ChallengeMismatch,
    #[error("Database error: {0}")]
    DatabaseError(#[from] Box<DynamoDBError>),
}

impl IntoResponse for AgentError {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = match &self {
            AgentError::InvalidDID(msg) => {
                (StatusCode::BAD_REQUEST, format!("Invalid DID: {}", msg))
            }
            AgentError::DelegationNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AgentError::DelegationAlreadyExists => (StatusCode::CONFLICT, self.to_string()),
            AgentError::DelegationRevoked
            | AgentError::DelegationExpired
            | AgentError::ChainRevoked(_)
            | AgentError::InsufficientEntitlements(_) => (StatusCode::FORBIDDEN, self.to_string()),
            AgentError::InvalidProof(_)
            | AgentError::InvalidToken
            | AgentError::MissingToken
            | AgentError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            AgentError::MaxDepthExceeded(_)
            | AgentError::MaxAgentsExceeded(_)
            | AgentError::ChallengeExpired
            | AgentError::ChallengeMismatch => (StatusCode::BAD_REQUEST, self.to_string()),
            AgentError::TokenGenerationError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            AgentError::DatabaseError(e) => match e.as_ref() {
                DynamoDBError::TableNotExists(table) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Service setup incomplete: {} table not configured", table),
                ),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            },
        };
        if status.is_server_error() {
            error!("{}", self);
        }
        (status, body).into_response()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const TEST_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    fn did_key_for(pk: &VerifyingKey) -> String {
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(pk.as_bytes());
        format!("did:key:z{}", bs58::encode(bytes).into_string())
    }

    fn sample_delegation(agent_did: &str) -> AgentDelegation {
        AgentDelegation {
            agent_did: agent_did.to_string(),
            delegator_type: "human".into(),
            delegator_id: "00000000-0000-0000-0000-000000000001".into(),
            delegator_username: Some("alice".into()),
            entitlements: vec![DEFAULT_USER_ENTITLEMENTS[0].to_string()],
            name: "CLI Agent".into(),
            depth: 0,
            root_user_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            chain: vec![],
            created_at: 1_700_000_000,
            expires_at: Some(1_700_000_000 + 30 * 86_400),
            revoked_at: None,
        }
    }

    #[test]
    fn extract_pubkey_valid() {
        assert_eq!(extract_ed25519_pubkey(TEST_DID).unwrap().len(), 32);
    }

    #[test]
    fn extract_pubkey_rejects_other_methods_and_bad_base58() {
        assert!(
            extract_ed25519_pubkey("did:web:example.com")
                .unwrap_err()
                .to_string()
                .contains("Must start with")
        );
        assert!(extract_ed25519_pubkey("did:key:z0Oilegal").is_err());
        assert!(validate_did_key("invalid").is_err());
    }

    #[test]
    fn did_key_round_trips_generated_key() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let did = did_key_for(&sk.verifying_key());
        assert_eq!(
            extract_ed25519_pubkey(&did).unwrap(),
            sk.verifying_key().to_bytes()
        );
    }

    #[test]
    fn proof_verifies_over_decoded_challenge_bytes() {
        // Mirrors the arkavo-agent-auth client: decode base64, sign bytes.
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let challenge = base64::engine::general_purpose::STANDARD.encode(random_challenge_bytes());
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&challenge)
            .unwrap();
        assert_eq!(bytes.len(), 32);
        let sig = sk.sign(&bytes);
        let vk = VerifyingKey::from_bytes(
            &extract_ed25519_pubkey(&did_key_for(&sk.verifying_key())).unwrap(),
        )
        .unwrap();
        assert!(vk.verify(&bytes, &sig).is_ok());
        // Signing the base64 *string* (the PR #23 behaviour) must NOT verify.
        let wrong = sk.sign(challenge.as_bytes());
        assert!(vk.verify(&bytes, &wrong).is_err());
    }

    #[test]
    fn delegation_jwt_claims_shape_matches_edge_parser() {
        let d = sample_delegation(TEST_DID);
        let c = delegation_jwt_claims("https://identity.arkavo.net", &d, 1_700_000_100);
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["sub"], TEST_DID);
        assert_eq!(json["act"], "00000000-0000-0000-0000-000000000001");
        assert!(json["scope"].is_array(), "scope must be a JSON array");
        assert_eq!(json["exp"], 1_700_000_000 + 30 * 86_400);
        assert_eq!(json["depth"], 0);
    }

    #[test]
    fn delegation_jwt_signs_and_verifies_es256() {
        use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
        let scalar = p256::elliptic_curve::ScalarPrimitive::from_slice(&[0x42u8; 32]).unwrap();
        let secret = p256::SecretKey::new(scalar);
        let enc = jsonwebtoken::EncodingKey::from_ec_der(secret.to_pkcs8_der().unwrap().as_bytes());
        let pem = secret
            .public_key()
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();
        let dec = jsonwebtoken::DecodingKey::from_ec_pem(pem.as_bytes()).unwrap();

        let mut d = sample_delegation(TEST_DID);
        let now = Utc::now().timestamp();
        d.expires_at = Some(now + AGENT_DELEGATION_DAYS * 86_400);
        let claims = delegation_jwt_claims("https://identity.arkavo.net", &d, now);
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("test-kid".into());
        let jwt = encode(&header, &claims, &enc).unwrap();

        let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
        validation.validate_aud = false;
        validation.set_issuer(&["https://identity.arkavo.net"]);
        let decoded = jsonwebtoken::decode::<DelegationJwtClaims>(&jwt, &dec, &validation).unwrap();
        assert_eq!(decoded.header.kid.as_deref(), Some("test-kid"));
        assert_eq!(decoded.claims.sub, TEST_DID);
        assert_eq!(decoded.claims.scope, d.entitlements);
    }

    #[test]
    fn user_id_from_claims_prefers_account_id_then_arkavo_subject() {
        let mut c = cwt::ArkavoClaims::auth(
            "https://identity.arkavo.net",
            "arkavo:00000000-0000-0000-0000-000000000002",
            1,
        );
        assert_eq!(
            user_id_from_claims(&c).unwrap().to_string(),
            "00000000-0000-0000-0000-000000000002"
        );
        c = c.with_arkavo_account_id("00000000-0000-0000-0000-000000000003");
        assert_eq!(
            user_id_from_claims(&c).unwrap().to_string(),
            "00000000-0000-0000-0000-000000000003"
        );
        let apple = cwt::ArkavoClaims::auth("https://identity.arkavo.net", "apple:001234.abc", 1);
        assert!(matches!(
            user_id_from_claims(&apple),
            Err(AgentError::Unauthorized(_))
        ));
        let svc = cwt::ArkavoClaims::auth("https://identity.arkavo.net", "client:mcp-edge", 1);
        assert!(matches!(
            user_id_from_claims(&svc),
            Err(AgentError::Unauthorized(_))
        ));
    }

    #[test]
    fn error_status_codes() {
        let cases = vec![
            (AgentError::InvalidDID("x".into()), StatusCode::BAD_REQUEST),
            (AgentError::DelegationNotFound, StatusCode::NOT_FOUND),
            (AgentError::DelegationAlreadyExists, StatusCode::CONFLICT),
            (AgentError::DelegationRevoked, StatusCode::FORBIDDEN),
            (
                AgentError::InvalidProof("x".into()),
                StatusCode::UNAUTHORIZED,
            ),
            (AgentError::MissingToken, StatusCode::UNAUTHORIZED),
            (
                AgentError::Unauthorized("x".into()),
                StatusCode::UNAUTHORIZED,
            ),
            (AgentError::ChallengeMismatch, StatusCode::BAD_REQUEST),
            (AgentError::ChallengeExpired, StatusCode::BAD_REQUEST),
            (
                AgentError::DatabaseError(Box::new(DynamoDBError::TableNotExists(
                    "agent_delegations".into(),
                ))),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ];
        for (err, status) in cases {
            assert_eq!(err.into_response().status(), status);
        }
    }

    #[test]
    fn agent_configuration_endpoints_and_limits() {
        let c = AgentConfiguration::new("https://identity.arkavo.net/");
        assert_eq!(c.issuer, "https://identity.arkavo.net");
        assert_eq!(
            c.agent_token_endpoint,
            "https://identity.arkavo.net/agents/token"
        );
        assert!(!c.agent_authorization_endpoint.contains("//agents"));
        assert_eq!(c.max_delegation_depth, MAX_DELEGATION_DEPTH);
        assert_eq!(c.agent_token_lifetime_seconds, AGENT_TOKEN_HOURS * 3600);
        assert_eq!(
            c.delegation_lifetime_seconds,
            AGENT_DELEGATION_DAYS * 86_400
        );
        assert!(
            c.entitlements_supported
                .contains(&DEFAULT_USER_ENTITLEMENTS[5])
        );
        assert_eq!(c.delegation_jwt_signing_alg, "ES256");
    }
}
