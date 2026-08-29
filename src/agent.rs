//! Agent delegation: a human (PE) authorizes an agent (NPE, identified by
//! `did:key`) to act on their behalf; the agent then proves key possession
//! and receives a short-lived, multi-audience agent access token.
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
//! POST /agents/token             ──►  {token, expires_at, entitlements}
//!      {did, challenge, signature: b64(Ed25519 over challenge bytes), nonce}
//! ```
//!
//! - `token` is a CWT access token (`sub` = agent DID, `aud` = the configured
//!   `AGENT_TOKEN_AUDIENCES` list, `act` = `AGENT_AUTHORIZED_ACTORS`,
//!   `arkavo_roles = ["agent"]`, `arkavo_entitlements` = delegated set,
//!   `arkavo_account_id` = root user, `arkavo_npe` describing the agent,
//!   `cnf` bound to the agent's Ed25519 `did:key`) with `exp - iat` capped at
//!   [`crate::constants::AGENT_TOKEN_MINUTES_MAX`] minutes.
//! - The pending challenge lives on the delegation row and is removed
//!   atomically when taken — no cookie session, so headless CLIs work.
//! - There is no refresh token: the agent re-runs the challenge/token
//!   exchange to mint a fresh token.
//!
//! Not in this module (tracked separately): agent→agent delegation
//! (delegator must be a human CWT today), per-agent OAuth clients (#50),
//! the ERS resolution surface (#48).

use crate::AppState;
use crate::constants::{
    AGENT_CHALLENGE_TTL_SECONDS, AGENT_DELEGATION_DAYS, MAX_AGENTS_PER_USER, MAX_DELEGATION_DEPTH,
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
    pub max_delegation_depth: u8,
    pub max_agents_per_user: u32,
    pub delegation_lifetime_seconds: i64,
    pub agent_token_lifetime_seconds: i64,
    pub challenge_ttl_seconds: i64,
    pub did_methods_supported: Vec<&'static str>,
    pub proof_signing_alg_values_supported: Vec<&'static str>,
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
            max_delegation_depth: MAX_DELEGATION_DEPTH,
            max_agents_per_user: MAX_AGENTS_PER_USER,
            delegation_lifetime_seconds: AGENT_DELEGATION_DAYS * 24 * 60 * 60,
            agent_token_lifetime_seconds: crate::constants::AGENT_TOKEN_MINUTES_MAX * 60,
            challenge_ttl_seconds: AGENT_CHALLENGE_TTL_SECONDS,
            did_methods_supported: vec!["did:key"],
            proof_signing_alg_values_supported: vec!["EdDSA"],
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
/// Only WebAuthn-derived subjects (a bare UUID — the shape `authn::mint_auth_token`
/// mints — or the `arkavo:<uuid>` prefixed form some other issuers use) may
/// delegate; Apple-only and service-account subjects are rejected, as are any
/// claims describing an agent or device NPE (`arkavo_npe` set, or `arkavo_roles`
/// containing `"agent"`). Agent-to-agent delegation is not supported yet (the
/// delegator must be a human CWT).
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

/// Root user id from a verified CWT: `claims.sub` parsed as a bare UUID (the
/// shape `authn::mint_auth_token` mints) or an `arkavo:<uuid>`-prefixed UUID.
/// `arkavo_account_id` is deliberately NOT consulted — the real WebAuthn auth
/// CWT never sets it, so trusting it would accept a shape no genuine human
/// token has. Other subject namespaces (`apple:`, `client:`, …) cannot
/// delegate. Claims describing an agent or device NPE (`arkavo_npe` set, or
/// `arkavo_roles` containing `"agent"`) are rejected outright — only a human
/// may delegate.
fn user_id_from_claims(claims: &cwt::ArkavoClaims) -> Result<Uuid, AgentError> {
    if claims.custom.arkavo_npe.is_some() {
        return Err(AgentError::Unauthorized(
            "delegator must be a human; token describes an agent/device NPE".into(),
        ));
    }
    if claims
        .custom
        .arkavo_roles
        .as_ref()
        .is_some_and(|roles| roles.iter().any(|r| r == "agent"))
    {
        return Err(AgentError::Unauthorized(
            "delegator must be a human; token carries the 'agent' role".into(),
        ));
    }
    let raw = claims.sub.strip_prefix("arkavo:").unwrap_or(&claims.sub);
    Uuid::parse_str(raw).map_err(|_| {
        AgentError::Unauthorized(format!(
            "subject '{}' is not a WebAuthn-registered user",
            claims.sub
        ))
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

    // Subset check against the delegator's own stored entitlements.
    let delegable = app_state
        .db_store
        .get_user_entitlements(&human.user_id)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;
    for entitlement in &request.entitlements {
        if !delegable.contains(entitlement) {
            return Err(AgentError::InsufficientEntitlements(format!(
                "Entitlement '{}' is not held by the delegator",
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
        .map_err(map_create_delegation_error)?;

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

/// POST /agents/token — verify the signed challenge, mint the agent CWT.
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

    let mut delegation = active_delegation(&app_state, &request.did).await?;

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

    // Agents keep stale entitlements for the whole delegation lifetime
    // otherwise: mint against what the delegator currently holds, not what
    // was captured at authorize time.
    let stored = app_state
        .db_store
        .get_user_entitlements(&delegation.root_user_id)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;
    let effective = intersect_entitlements(&delegation.entitlements, &stored);
    if effective.is_empty() {
        return Err(AgentError::InsufficientEntitlements(
            "delegated entitlements no longer held by delegator".into(),
        ));
    }
    delegation.entitlements = effective;

    let (token, expires_at) = mint_agent_cwt(&app_state, &delegation)?;

    info!(
        "Agent token issued for {} (depth {})",
        request.did, delegation.depth
    );
    Ok(Json(TokenResponse {
        token,
        expires_at,
        entitlements: delegation.entitlements,
    }))
}

/// Entitlements a delegation may actually exercise right now: the delegated
/// set filtered to what the delegator (`root_user_id`) currently holds in
/// storage, preserving the delegation's own entitlement order.
fn intersect_entitlements(delegated: &[String], stored: &[String]) -> Vec<String> {
    delegated
        .iter()
        .filter(|e| stored.contains(e))
        .cloned()
        .collect()
}

// ============================================================================
// Token minting
// ============================================================================

/// Agent token issuance config (spec §1). Parsed once at startup.
#[derive(Debug, Clone)]
pub struct AgentTokenConfig {
    pub audiences: Vec<String>,
    pub authorized_actors: Vec<String>,
    pub minutes: i64,
}

impl AgentTokenConfig {
    /// `AGENT_TOKEN_AUDIENCES` (required, comma-separated), `AGENT_AUTHORIZED_ACTORS`
    /// (optional, comma-separated), `AGENT_TOKEN_MINUTES` (optional, default 15, cap 15).
    pub fn parse(
        audiences: Option<String>,
        actors: Option<String>,
        minutes: Option<String>,
    ) -> Result<Self, String> {
        fn split(s: Option<String>) -> Vec<String> {
            s.unwrap_or_default()
                .split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        }
        let audiences = split(audiences);
        if audiences.is_empty() {
            return Err("AGENT_TOKEN_AUDIENCES must list at least one audience".into());
        }
        let authorized_actors = split(actors);
        if authorized_actors.is_empty() {
            warn!("AGENT_AUTHORIZED_ACTORS is empty: agent tokens will carry no act claim");
        }
        let requested = minutes
            .as_deref()
            .map(|m| {
                m.trim()
                    .parse::<i64>()
                    .map_err(|_| format!("AGENT_TOKEN_MINUTES not an integer: {m}"))
            })
            .transpose()?
            .unwrap_or(crate::constants::AGENT_TOKEN_MINUTES_MAX);
        let minutes = requested.clamp(1, crate::constants::AGENT_TOKEN_MINUTES_MAX);
        if minutes != requested {
            warn!("AGENT_TOKEN_MINUTES={requested} clamped to {minutes}");
        }
        Ok(Self {
            audiences,
            authorized_actors,
            minutes,
        })
    }
}

pub(crate) fn agent_cwt_claims(
    issuer: &str,
    cfg: &AgentTokenConfig,
    delegation: &AgentDelegation,
) -> Result<cwt::ArkavoClaims, AgentError> {
    let pubkey = extract_ed25519_pubkey(&delegation.agent_did)?;
    let mut claims = cwt::ArkavoClaims::agent(
        issuer,
        &delegation.agent_did,
        cfg.audiences.clone(),
        cfg.minutes,
    );
    if !cfg.authorized_actors.is_empty() {
        claims = claims.with_act(
            cfg.authorized_actors
                .iter()
                .map(|s| cwt::Actor { sub: s.clone() })
                .collect(),
        );
    }
    Ok(claims
        .with_arkavo_account_id(&delegation.root_user_id.to_string())
        .with_arkavo_roles(vec!["agent".to_string()])
        .with_arkavo_entitlements(delegation.entitlements.clone())
        .with_arkavo_npe(cwt::ArkavoNpe {
            npe_type: "agent".into(),
            class: None,
            attestation_expiry: None,
            device_id: None,
            delegation_id: Some(delegation.agent_did.clone()),
            depth: Some(delegation.depth),
            chain: Some(delegation.chain.clone()),
        })
        .with_cnf(cwt::cnf_from_ed25519(
            &pubkey,
            delegation.agent_did.as_bytes(),
        )))
}

fn map_create_delegation_error(e: DynamoDBError) -> AgentError {
    match e {
        DynamoDBError::ConditionalConflict => AgentError::DelegationAlreadyExists,
        other => AgentError::DatabaseError(Box::new(other)),
    }
}

fn mint_agent_cwt(
    app_state: &AppState,
    delegation: &AgentDelegation,
) -> Result<(String, i64), AgentError> {
    let claims = agent_cwt_claims(&app_state.issuer, &app_state.agent_tokens, delegation)?;
    let expires_at = claims.exp;
    let bytes = cwt::mint(&claims, &app_state.cwt_signing_key, &app_state.cwt_kid)
        .map_err(|e| AgentError::TokenGenerationError(e.to_string()))?;
    Ok((cwt::encode_for_header(&bytes), expires_at))
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
    use crate::constants::DEFAULT_USER_ENTITLEMENTS;
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
    fn agent_token_config_from_env_strings() {
        let cfg = AgentTokenConfig::parse(
            Some("https://platform.arkavo.net, https://kas.arkavo.net".into()),
            Some("https://kg.arkavo.net".into()),
            Some("60".into()),
        )
        .unwrap();
        assert_eq!(
            cfg.audiences,
            vec!["https://platform.arkavo.net", "https://kas.arkavo.net"]
        );
        assert_eq!(cfg.authorized_actors, vec!["https://kg.arkavo.net"]);
        assert_eq!(cfg.minutes, 15, "values above the cap clamp to 15");
        assert!(
            AgentTokenConfig::parse(None, None, None).is_err(),
            "audiences are required"
        );
        assert!(AgentTokenConfig::parse(Some("".into()), None, None).is_err());
    }

    #[test]
    fn agent_cwt_claims_have_required_shape() {
        let cfg = AgentTokenConfig {
            audiences: vec!["https://platform.arkavo.net".into()],
            authorized_actors: vec!["https://kg.arkavo.net".into()],
            minutes: 15,
        };
        let d = sample_delegation(TEST_DID);
        let claims = agent_cwt_claims("https://identity.arkavo.net", &cfg, &d).unwrap();
        assert_eq!(claims.sub, TEST_DID);
        assert_eq!(
            claims.aud,
            cwt::Audience::Multiple(vec!["https://platform.arkavo.net".into()])
        );
        assert_eq!(claims.exp - claims.iat, 900);
        assert_eq!(
            claims.custom.act.as_ref().unwrap()[0].sub,
            "https://kg.arkavo.net"
        );
        assert_eq!(
            claims.custom.arkavo_roles.as_deref(),
            Some(&["agent".to_string()][..])
        );
        assert_eq!(
            claims.custom.arkavo_account_id.as_deref(),
            Some("00000000-0000-0000-0000-000000000001")
        );
        let npe = claims.custom.arkavo_npe.as_ref().unwrap();
        assert_eq!(npe.npe_type, "agent");
        assert_eq!(npe.delegation_id.as_deref(), Some(TEST_DID));
        assert!(claims.cnf.is_some());
    }

    #[test]
    fn agent_cwt_claims_omit_act_when_no_authorized_actors() {
        let cfg = AgentTokenConfig {
            audiences: vec!["https://platform.arkavo.net".into()],
            authorized_actors: vec![],
            minutes: 15,
        };
        let d = sample_delegation(TEST_DID);
        let claims = agent_cwt_claims("https://identity.arkavo.net", &cfg, &d).unwrap();
        assert_eq!(claims.custom.act, None);
    }

    #[test]
    fn user_id_from_claims_accepts_bare_uuid_and_arkavo_prefixed_subjects() {
        // The real WebAuthn auth CWT (authn::mint_auth_token) has a bare-UUID
        // `sub` and no `arkavo_account_id` — this is the shape C1 fixes.
        let bare = cwt::ArkavoClaims::auth(
            "https://identity.arkavo.net",
            "00000000-0000-0000-0000-000000000002",
            1,
            None,
        );
        assert_eq!(
            user_id_from_claims(&bare).unwrap().to_string(),
            "00000000-0000-0000-0000-000000000002"
        );

        let prefixed = cwt::ArkavoClaims::auth(
            "https://identity.arkavo.net",
            "arkavo:00000000-0000-0000-0000-000000000003",
            1,
            None,
        );
        assert_eq!(
            user_id_from_claims(&prefixed).unwrap().to_string(),
            "00000000-0000-0000-0000-000000000003"
        );
    }

    #[test]
    fn user_id_from_claims_does_not_consult_arkavo_account_id() {
        // arkavo_account_id must never be trusted on its own — the real auth
        // CWT never sets it, so honoring it would accept a shape no genuine
        // human token has.
        let c = cwt::ArkavoClaims::auth("https://identity.arkavo.net", "apple:001234.abc", 1, None)
            .with_arkavo_account_id("00000000-0000-0000-0000-000000000099");
        assert!(matches!(
            user_id_from_claims(&c),
            Err(AgentError::Unauthorized(_))
        ));
    }

    #[test]
    fn user_id_from_claims_rejects_apple_and_service_subjects() {
        let apple =
            cwt::ArkavoClaims::auth("https://identity.arkavo.net", "apple:001234.abc", 1, None);
        assert!(matches!(
            user_id_from_claims(&apple),
            Err(AgentError::Unauthorized(_))
        ));
        let svc =
            cwt::ArkavoClaims::auth("https://identity.arkavo.net", "client:mcp-edge", 1, None);
        assert!(matches!(
            user_id_from_claims(&svc),
            Err(AgentError::Unauthorized(_))
        ));
    }

    #[test]
    fn user_id_from_claims_rejects_agent_npe_and_agent_role() {
        let by_npe = cwt::ArkavoClaims::agent(
            "https://identity.arkavo.net",
            TEST_DID,
            vec!["arkavo".into()],
            15,
        )
        .with_arkavo_npe(cwt::ArkavoNpe {
            npe_type: "agent".into(),
            class: None,
            attestation_expiry: None,
            device_id: None,
            delegation_id: None,
            depth: None,
            chain: None,
        });
        assert!(matches!(
            user_id_from_claims(&by_npe),
            Err(AgentError::Unauthorized(_))
        ));

        // Load-bearing: a bare-UUID `sub` that would otherwise parse fine,
        // but carries the "agent" role, must still be rejected.
        let by_role = cwt::ArkavoClaims::auth(
            "https://identity.arkavo.net",
            "00000000-0000-0000-0000-000000000004",
            1,
            None,
        )
        .with_arkavo_roles(vec!["agent".to_string()]);
        assert!(matches!(
            user_id_from_claims(&by_role),
            Err(AgentError::Unauthorized(_))
        ));
    }

    #[tokio::test]
    async fn authenticate_human_accepts_real_webauthn_auth_token() {
        // End-to-end: a token minted the way the real WebAuthn flow mints it
        // (authn::mint_auth_token — bare-UUID sub, aud = "arkavo") must be
        // accepted by authenticate_human.
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
            std::env::set_var("AWS_ACCESS_KEY_ID", "fake_access_key");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "fake_secret_key");
        }
        let app_state = crate::test_helpers::build_test_app_state().await;
        let user_id = Uuid::new_v4();
        let token = crate::authn::mint_auth_token(&app_state, &user_id, None).expect("mint");
        let mut headers = HeaderMap::new();
        headers.insert("X-Auth-Token", token.parse().unwrap());
        let human = authenticate_human(&app_state, &headers)
            .await
            .expect("a real WebAuthn auth CWT must be accepted");
        assert_eq!(human.user_id, user_id);
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
    fn create_delegation_conditional_conflict_is_already_exists() {
        assert!(matches!(
            map_create_delegation_error(DynamoDBError::ConditionalConflict),
            AgentError::DelegationAlreadyExists
        ));
        let mapped =
            map_create_delegation_error(DynamoDBError::TableNotExists("agent_delegations".into()));
        assert!(matches!(mapped, AgentError::DatabaseError(_)));
        assert_eq!(
            mapped.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn intersect_entitlements_filters_to_stored_preserving_delegation_order() {
        let delegated = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let stored = vec!["c".to_string(), "a".to_string()];
        assert_eq!(
            intersect_entitlements(&delegated, &stored),
            vec!["a".to_string(), "c".to_string()]
        );
        assert!(intersect_entitlements(&delegated, &[]).is_empty());
        assert_eq!(intersect_entitlements(&[], &stored), Vec::<String>::new());
        assert_eq!(intersect_entitlements(&delegated, &delegated), delegated);
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
        assert_eq!(
            c.agent_token_lifetime_seconds,
            crate::constants::AGENT_TOKEN_MINUTES_MAX * 60
        );
        assert_eq!(
            c.delegation_lifetime_seconds,
            AGENT_DELEGATION_DAYS * 86_400
        );
    }
}
