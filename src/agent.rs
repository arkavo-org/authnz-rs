//! Agent Delegation Module
//!
//! Implements agent delegation flow where humans authorize agents (via QR code
//! scanned by Arkavo iOS app) to act on their behalf, receiving NTDF tokens
//! with delegated entitlements.
//!
//! # User Flow
//!
//! ```text
//! Terminal                          Arkavo iOS App
//! ─────────────────────────────────────────────────────────
//! $ arkavo agent run --verbose
//!                                   (authenticated via DeviceCheck)
//! ┌─────────────┐
//! │  QR Code    │    ──scan──►     "Authorize agent?"
//! │  did:key:.. │                   Name: CLI Agent
//! └─────────────┘                   Entitlements: [read, execute]
//!                    ◄─────────
//! ✓ Authorized                      POST /agents/authorize
//!                                   X-Auth-Token: <jwt>
//! Agent requests token:
//! GET /agents/challenge?did=...
//! POST /agents/token (signed proof)
//!
//! ✓ NTDF Token received
//! ```
//!
//! # Deep Link Format
//!
//! ```text
//! arkavo://agent/authorize?did=did:key:z6Mk...&name=CLI%20Agent&entitlements=read,execute
//! ```
//!
//! # Security Features
//!
//! - **DID-based identity**: Agents identified by did:key (Ed25519 multicodec)
//! - **Delegation chains**: Supports agent-to-agent delegation up to depth 5
//! - **Entitlement subset**: Agents can only delegate entitlements they possess
//! - **Cascade revocation**: Revoking a delegation revokes all child delegations
//! - **Challenge-response**: Agents prove key ownership via Ed25519 signatures

use crate::constants::{
    AGENT_CHALLENGE_TTL_SECONDS, AGENT_TOKEN_DAYS, MAX_AGENTS_PER_USER, MAX_DELEGATION_DEPTH,
};
use crate::db::{AgentDelegation, DynamoDBError};
use crate::ntdf_token::{CapabilityFlag, NtdfTokenPayload};
use crate::AppState;
use axum::http::HeaderMap;
use axum::{
    extract::{Extension, Json, Path, Query},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jsonwebtoken::{decode, Algorithm, Validation};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tower_sessions::Session;
use uuid::Uuid;

const SESSION_AGENT_CHALLENGE_KEY: &str = "agent_challenge_state";

/// Entitlement URIs for agent delegation
pub mod entitlements {
    pub const ACTION_READ: &str = "https://arkavo.ai/attr/action/value/read";
    pub const ACTION_WRITE: &str = "https://arkavo.ai/attr/action/value/write";
    pub const ACTION_EXECUTE: &str = "https://arkavo.ai/attr/action/value/execute";
    pub const ACTION_DELEGATE: &str = "https://arkavo.ai/attr/action/value/delegate";
    pub const ACTION_ADMIN: &str = "https://arkavo.ai/attr/action/value/admin";
    pub const MESH_ORCHESTRATOR: &str = "https://arkavo.ai/attr/mesh/value/orchestrator";
    pub const MESH_WORKER: &str = "https://arkavo.ai/attr/mesh/value/worker";
}

// ============================================================================
// Agent Configuration Discovery (OpenID-style)
// ============================================================================

/// Agent configuration metadata returned at /.well-known/agent-configuration
///
/// Follows the pattern of OpenID Connect Discovery but for agent delegation.
/// See: https://openid.net/specs/openid-connect-discovery-1_0.html
#[derive(Debug, Clone, Serialize)]
pub struct AgentConfiguration {
    /// URL of the agent delegation service
    pub issuer: String,

    /// Endpoint for authorizing new agent delegations
    pub agent_authorization_endpoint: String,

    /// Endpoint for listing delegations
    pub agent_delegations_endpoint: String,

    /// Endpoint for revoking delegations (base path, append /:did)
    pub agent_revocation_endpoint: String,

    /// Endpoint for requesting a challenge for token issuance
    pub agent_challenge_endpoint: String,

    /// Endpoint for exchanging signed proof for token
    pub agent_token_endpoint: String,

    /// Supported entitlement URIs that can be delegated
    pub entitlements_supported: Vec<&'static str>,

    /// Maximum depth of delegation chain (human -> agent1 -> agent2 -> ...)
    pub max_delegation_depth: u8,

    /// Maximum number of agents a single user can delegate to
    pub max_agents_per_user: u32,

    /// Lifetime of issued agent tokens in seconds
    pub agent_token_lifetime_seconds: i64,

    /// Time-to-live for challenge in seconds
    pub challenge_ttl_seconds: i64,

    /// Supported DID methods for agent identity
    pub did_methods_supported: Vec<&'static str>,

    /// Supported proof signing algorithms
    pub proof_signing_alg_values_supported: Vec<&'static str>,

    /// Deep link URI scheme for mobile authorization
    pub authorization_deep_link_scheme: String,
}

impl AgentConfiguration {
    /// Build configuration for the given issuer URL
    pub fn new(issuer: &str) -> Self {
        let base = issuer.trim_end_matches('/');
        Self {
            issuer: base.to_string(),
            agent_authorization_endpoint: format!("{}/agents/authorize", base),
            agent_delegations_endpoint: format!("{}/agents/delegations", base),
            agent_revocation_endpoint: format!("{}/agents/delegations", base),
            agent_challenge_endpoint: format!("{}/agents/challenge", base),
            agent_token_endpoint: format!("{}/agents/token", base),
            entitlements_supported: vec![
                entitlements::ACTION_READ,
                entitlements::ACTION_WRITE,
                entitlements::ACTION_EXECUTE,
                entitlements::ACTION_DELEGATE,
                entitlements::ACTION_ADMIN,
                entitlements::MESH_ORCHESTRATOR,
                entitlements::MESH_WORKER,
            ],
            max_delegation_depth: MAX_DELEGATION_DEPTH,
            max_agents_per_user: MAX_AGENTS_PER_USER,
            agent_token_lifetime_seconds: AGENT_TOKEN_DAYS * 24 * 60 * 60,
            challenge_ttl_seconds: AGENT_CHALLENGE_TTL_SECONDS,
            did_methods_supported: vec!["did:key"],
            proof_signing_alg_values_supported: vec!["EdDSA"],
            authorization_deep_link_scheme: "arkavo://agent/authorize".to_string(),
        }
    }
}

/// GET /.well-known/agent-configuration
///
/// Returns agent delegation service metadata for discovery.
/// Similar to OpenID Connect Discovery's /.well-known/openid-configuration
pub async fn serve_agent_configuration() -> impl IntoResponse {
    let config = AgentConfiguration::new("https://identity.arkavo.net");
    Json(config)
}

// ============================================================================
// Request/Response Types
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

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub agent_did: String,
    pub challenge: String,
    pub proof: String, // Base64-encoded Ed25519 signature
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
// DID Key Utilities
// ============================================================================

/// Extract Ed25519 public key from did:key:z6Mk... format
///
/// The did:key format encodes the public key using multicodec:
/// - "z" prefix indicates base58btc encoding
/// - First 2 bytes after decode are multicodec prefix: 0xed01 for Ed25519
/// - Remaining 32 bytes are the raw public key
pub fn extract_ed25519_pubkey(did: &str) -> Result<[u8; 32], AgentError> {
    // did:key:z6Mk...
    let key_part = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| AgentError::InvalidDID("Must start with did:key:z".into()))?;

    let decoded = bs58::decode(key_part)
        .into_vec()
        .map_err(|e| AgentError::InvalidDID(format!("Invalid base58: {}", e)))?;

    // First 2 bytes are multicodec prefix 0xed01 for Ed25519
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

/// Derive deterministic UUID from agent DID for sub_id
///
/// Uses first 16 bytes of SHA256(pubkey) as UUID
pub fn uuid_from_did(did: &str) -> Result<Uuid, AgentError> {
    let pubkey = extract_ed25519_pubkey(did)?;
    let hash = Sha256::digest(pubkey);
    Ok(Uuid::from_bytes(
        hash[0..16].try_into().expect("SHA256 is 32 bytes"),
    ))
}

/// Validate did:key format without extracting the key
pub fn validate_did_key(did: &str) -> Result<(), AgentError> {
    extract_ed25519_pubkey(did).map(|_| ())
}

// ============================================================================
// Endpoint Handlers
// ============================================================================

/// POST /agents/authorize
///
/// Authorize an agent to act on behalf of a human or another agent.
/// Requires either:
/// - Human JWT in X-Auth-Token header (creates depth 0 delegation)
/// - Agent NTDF token (creates depth N+1 delegation, requires `delegate` entitlement)
pub async fn authorize_agent(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Json(request): Json<AuthorizeAgentRequest>,
) -> Result<impl IntoResponse, AgentError> {
    info!(
        "Authorizing agent: {} with name: {}",
        request.agent_did, request.name
    );

    // Validate agent DID format
    validate_did_key(&request.agent_did)?;

    // Validate entitlements are not empty
    if request.entitlements.is_empty() {
        return Err(AgentError::InsufficientEntitlements(
            "At least one entitlement is required".into(),
        ));
    }

    // Parse authorization header to determine delegator type
    let (delegator_type, delegator_id, delegator_username, root_user_id, depth, parent_entitlements, chain) =
        parse_auth_header(&app_state, &headers).await?;

    // Verify entitlements are a subset of delegator's entitlements
    for entitlement in &request.entitlements {
        if !parent_entitlements.contains(entitlement) {
            return Err(AgentError::InsufficientEntitlements(format!(
                "Cannot delegate entitlement '{}' that delegator does not possess",
                entitlement
            )));
        }
    }

    // For agent delegators, verify they have the delegate entitlement
    if delegator_type == "agent" && !parent_entitlements.contains(&entitlements::ACTION_DELEGATE.to_string()) {
        return Err(AgentError::InsufficientEntitlements(
            "Delegator must have 'delegate' entitlement to authorize sub-agents".into(),
        ));
    }

    // Check delegation depth
    if depth >= MAX_DELEGATION_DEPTH {
        return Err(AgentError::MaxDepthExceeded(depth));
    }

    // Check max agents per user
    let current_count = app_state
        .db_store
        .count_delegations_by_root_user(root_user_id)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;

    if current_count >= MAX_AGENTS_PER_USER {
        return Err(AgentError::MaxAgentsExceeded(current_count));
    }

    // Check if delegation already exists
    if let Some(existing) = app_state
        .db_store
        .get_agent_delegation(&request.agent_did)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?
        && existing.revoked_at.is_none()
    {
        return Err(AgentError::DelegationAlreadyExists);
    }
    // If revoked, we'll create a new one (overwrite)

    // Build the delegation chain
    let mut new_chain = chain;
    if delegator_type == "agent" {
        // Add the delegator's DID to the chain
        new_chain.push(delegator_id.clone());
    }

    // Create delegation record
    let delegation = AgentDelegation {
        agent_did: request.agent_did.clone(),
        delegator_type,
        delegator_id,
        delegator_username,
        entitlements: request.entitlements,
        name: request.name,
        depth,
        root_user_id,
        chain: new_chain,
        created_at: Utc::now().timestamp(),
        expires_at: Some(Utc::now().timestamp() + (AGENT_TOKEN_DAYS * 24 * 60 * 60)),
        revoked_at: None,
    };

    app_state
        .db_store
        .create_agent_delegation(&delegation)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;

    info!(
        "Agent delegation created successfully for: {}",
        request.agent_did
    );

    Ok(Json(AuthorizeAgentResponse {
        success: true,
        message: "Agent authorized successfully".to_string(),
    }))
}

/// GET /agents/delegations
///
/// List all delegations for the authenticated human user.
/// Requires human JWT in X-Auth-Token header.
pub async fn list_delegations(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AgentError> {
    info!("Listing agent delegations");

    // Parse JWT to get user_id
    let jwt = headers
        .get("X-Auth-Token")
        .ok_or(AgentError::MissingToken)?
        .to_str()
        .map_err(|_| AgentError::InvalidToken)?;

    let decoding_key = (*app_state.decoding_key).clone();
    let mut token_validation = Validation::new(Algorithm::ES256);
    token_validation.validate_nbf = false;
    token_validation.validate_exp = false;

    let token_data = decode::<crate::authn::Claims>(jwt, &decoding_key, &token_validation)
        .map_err(|e| AgentError::TokenDecodingError(format!("Error decoding token: {}", e)))?;

    let user_id = Uuid::parse_str(&token_data.claims.sub)
        .map_err(|e| AgentError::TokenDecodingError(format!("Invalid user_id in token: {}", e)))?;

    // List delegations
    let delegations = app_state
        .db_store
        .list_delegations_by_root_user(user_id)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;

    let delegation_infos: Vec<DelegationInfo> = delegations
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
        .collect();

    Ok(Json(DelegationListResponse {
        delegations: delegation_infos,
    }))
}

/// DELETE /agents/delegations/:did
///
/// Revoke an agent delegation and cascade to child delegations.
/// Requires human JWT in X-Auth-Token header.
pub async fn revoke_delegation(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Path(agent_did): Path<String>,
) -> Result<impl IntoResponse, AgentError> {
    info!("Revoking agent delegation: {}", agent_did);

    // Parse JWT to get user_id
    let jwt = headers
        .get("X-Auth-Token")
        .ok_or(AgentError::MissingToken)?
        .to_str()
        .map_err(|_| AgentError::InvalidToken)?;

    let decoding_key = (*app_state.decoding_key).clone();
    let mut token_validation = Validation::new(Algorithm::ES256);
    token_validation.validate_nbf = false;
    token_validation.validate_exp = false;

    let token_data = decode::<crate::authn::Claims>(jwt, &decoding_key, &token_validation)
        .map_err(|e| AgentError::TokenDecodingError(format!("Error decoding token: {}", e)))?;

    let user_id = Uuid::parse_str(&token_data.claims.sub)
        .map_err(|e| AgentError::TokenDecodingError(format!("Invalid user_id in token: {}", e)))?;

    // Verify the delegation exists and belongs to this user
    let delegation = app_state
        .db_store
        .get_agent_delegation(&agent_did)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?
        .ok_or(AgentError::DelegationNotFound)?;

    if delegation.root_user_id != user_id {
        return Err(AgentError::Unauthorized);
    }

    // Revoke the delegation
    app_state
        .db_store
        .revoke_delegation(&agent_did)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;

    // Cascade revocation to child delegations
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

/// GET /agents/challenge
///
/// Generate a challenge for agent token issuance.
/// The agent must have an active (non-revoked) delegation.
pub async fn generate_agent_challenge(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Query(params): Query<ChallengeQueryParams>,
) -> Result<impl IntoResponse, AgentError> {
    info!("Generating agent challenge for DID: {}", params.did);

    // Validate DID format
    validate_did_key(&params.did)?;

    // Verify delegation exists and is active
    let delegation = app_state
        .db_store
        .get_agent_delegation(&params.did)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?
        .ok_or(AgentError::DelegationNotFound)?;

    // Check if delegation is revoked
    if delegation.revoked_at.is_some() {
        return Err(AgentError::DelegationRevoked);
    }

    // Check if delegation is expired
    if let Some(expires_at) = delegation.expires_at
        && Utc::now().timestamp() > expires_at
    {
        return Err(AgentError::DelegationExpired);
    }

    // Verify chain is valid (no revoked ancestors)
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

    // Generate challenge
    let challenge = Uuid::new_v4().to_string();

    // Store challenge in session with expiry
    let challenge_state = (params.did.clone(), challenge.clone(), Utc::now().timestamp());
    if let Err(err) = session.insert(SESSION_AGENT_CHALLENGE_KEY, challenge_state).await {
        error!("Failed to save agent challenge state: {:?}", err);
        return Err(AgentError::SessionError(err.to_string()));
    }

    info!("Challenge generated for agent: {}", params.did);
    Ok(Json(ChallengeResponse { challenge }))
}

/// POST /agents/token
///
/// Issue an NTDF token to an authorized agent.
/// The agent must prove key ownership by signing the challenge.
pub async fn issue_agent_token(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(request): Json<TokenRequest>,
) -> Result<impl IntoResponse, AgentError> {
    info!("Issuing agent token for DID: {}", request.agent_did);

    // Retrieve and clear challenge from session
    let (stored_did, stored_challenge, challenge_time): (String, String, i64) = session
        .get(SESSION_AGENT_CHALLENGE_KEY)
        .await
        .map_err(|e| AgentError::SessionError(e.to_string()))?
        .ok_or(AgentError::ChallengeNotFound)?;

    // Clear session immediately
    if let Err(e) = session.remove_value(SESSION_AGENT_CHALLENGE_KEY).await {
        warn!("Failed to remove challenge from session: {}", e);
    }

    // Verify challenge hasn't expired
    let elapsed = Utc::now().timestamp() - challenge_time;
    if elapsed > AGENT_CHALLENGE_TTL_SECONDS {
        return Err(AgentError::ChallengeExpired);
    }

    // Verify DID matches
    if stored_did != request.agent_did {
        return Err(AgentError::ChallengeMismatch);
    }

    // Verify challenge matches
    if stored_challenge != request.challenge {
        return Err(AgentError::ChallengeMismatch);
    }

    // Get delegation
    let delegation = app_state
        .db_store
        .get_agent_delegation(&request.agent_did)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?
        .ok_or(AgentError::DelegationNotFound)?;

    // Double-check delegation is still valid
    if delegation.revoked_at.is_some() {
        return Err(AgentError::DelegationRevoked);
    }

    // Verify chain is still valid
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

    // Extract public key and verify signature
    let pubkey_bytes = extract_ed25519_pubkey(&request.agent_did)?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| AgentError::InvalidDID(format!("Invalid public key: {}", e)))?;

    let signature_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &request.proof,
    )
    .map_err(|e| AgentError::InvalidProof(format!("Invalid base64: {}", e)))?;

    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| AgentError::InvalidProof(format!("Invalid signature format: {}", e)))?;

    // Verify signature over the challenge
    verifying_key
        .verify(request.challenge.as_bytes(), &signature)
        .map_err(|e| {
            error!("Signature verification failed: {}", e);
            AgentError::InvalidProof("Signature verification failed".into())
        })?;

    info!("Signature verified for agent: {}", request.agent_did);

    // Build NTDF token if builder is available
    let ntdf_builder = app_state
        .ntdf_builder
        .as_ref()
        .ok_or(AgentError::NtdfNotConfigured)?;

    // Derive sub_id from agent DID
    let agent_uuid = uuid_from_did(&request.agent_did)?;
    let sub_id: [u8; 16] = *agent_uuid.as_bytes();

    // Build flags
    let flags = CapabilityFlag::AgentDelegated as u64;

    // Build delegation chain for token
    let mut token_chain = delegation.chain.clone();
    if delegation.delegator_type == "agent" {
        token_chain.push(delegation.delegator_id.clone());
    }

    // Parse delegator_id as UUID if human
    let delegator_id_bytes: Option<[u8; 16]> = if delegation.delegator_type == "human" {
        Uuid::parse_str(&delegation.delegator_id)
            .ok()
            .map(|u| *u.as_bytes())
    } else {
        // For agent delegator, derive from DID
        uuid_from_did(&delegation.delegator_id)
            .ok()
            .map(|u| *u.as_bytes())
    };

    let root_user_id_bytes: [u8; 16] = *delegation.root_user_id.as_bytes();

    // Build payload
    let now = Utc::now().timestamp();
    let exp = now + (AGENT_TOKEN_DAYS * 24 * 60 * 60);

    let payload = NtdfTokenPayload {
        sub_id,
        flags,
        scopes: delegation.entitlements.clone(),
        attrs: vec![],
        dpop_jti: None,
        iat: now,
        exp,
        aud: "https://kas.arkavo.net".to_string(),
        session_id: None,
        device_id: None,
        did: Some(request.agent_did.clone()),
        delegator_id: delegator_id_bytes,
        root_user_id: Some(root_user_id_bytes),
        delegation_depth: Some(delegation.depth),
        delegation_chain: Some(token_chain),
    };

    let token = ntdf_builder
        .build(&payload)
        .map_err(|e| AgentError::TokenGenerationError(e.to_string()))?;

    info!(
        "NTDF token generated for agent: {} (depth: {})",
        request.agent_did, delegation.depth
    );

    // Return token in header
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-NTDF-Token",
        token.parse().map_err(|_| {
            AgentError::TokenGenerationError("Failed to create header value".into())
        })?,
    );

    Ok((headers, StatusCode::OK))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse authorization header and return delegator info
///
/// Returns: (delegator_type, delegator_id, delegator_username, root_user_id, depth, entitlements, chain)
async fn parse_auth_header(
    app_state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, String, Option<String>, Uuid, u8, Vec<String>, Vec<String>), AgentError> {
    // Try JWT first (human delegator)
    if let Some(jwt_header) = headers.get("X-Auth-Token") {
        let jwt = jwt_header
            .to_str()
            .map_err(|_| AgentError::InvalidToken)?;

        let decoding_key = (*app_state.decoding_key).clone();
        let mut token_validation = Validation::new(Algorithm::ES256);
        token_validation.validate_nbf = false;
        token_validation.validate_exp = false;

        let token_data = decode::<crate::authn::Claims>(jwt, &decoding_key, &token_validation)
            .map_err(|e| AgentError::TokenDecodingError(format!("Error decoding token: {}", e)))?;

        let user_id = Uuid::parse_str(&token_data.claims.sub)
            .map_err(|e| {
                AgentError::TokenDecodingError(format!("Invalid user_id in token: {}", e))
            })?;

        // Get user to retrieve username
        let user = app_state
            .db_store
            .get_user_by_name(&token_data.claims.sub)
            .await
            .ok()
            .flatten();

        let username = user.map(|u| u.username);

        // Humans have all entitlements by default
        let human_entitlements = vec![
            entitlements::ACTION_READ.to_string(),
            entitlements::ACTION_WRITE.to_string(),
            entitlements::ACTION_EXECUTE.to_string(),
            entitlements::ACTION_DELEGATE.to_string(),
            entitlements::ACTION_ADMIN.to_string(),
            entitlements::MESH_ORCHESTRATOR.to_string(),
            entitlements::MESH_WORKER.to_string(),
        ];

        return Ok((
            "human".to_string(),
            user_id.to_string(),
            username,
            user_id, // root_user_id is same as delegator for human
            0,       // depth 0 for human delegator
            human_entitlements,
            vec![], // empty chain for human
        ));
    }

    // Try NTDF token (agent delegator) - for now return error
    // TODO: Implement NTDF token decoding for agent-to-agent delegation
    // This would require the KAS to decode the token, or local decoding capability

    Err(AgentError::MissingToken)
}

// ============================================================================
// Error Types
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

    #[error("Token decoding error: {0}")]
    TokenDecodingError(String),

    #[error("Token generation error: {0}")]
    TokenGenerationError(String),

    #[error("Chain revoked at: {0}")]
    ChainRevoked(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Challenge not found")]
    ChallengeNotFound,

    #[error("Challenge expired")]
    ChallengeExpired,

    #[error("Challenge mismatch")]
    ChallengeMismatch,

    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] Box<DynamoDBError>),

    #[error("NTDF token builder not configured")]
    NtdfNotConfigured,
}

impl IntoResponse for AgentError {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = match &self {
            AgentError::InvalidDID(msg) => (StatusCode::BAD_REQUEST, format!("Invalid DID: {}", msg)),
            AgentError::DelegationNotFound => {
                (StatusCode::NOT_FOUND, "Delegation not found".to_string())
            }
            AgentError::DelegationAlreadyExists => (
                StatusCode::CONFLICT,
                "Delegation already exists".to_string(),
            ),
            AgentError::DelegationRevoked => {
                (StatusCode::FORBIDDEN, "Delegation revoked".to_string())
            }
            AgentError::DelegationExpired => {
                (StatusCode::FORBIDDEN, "Delegation expired".to_string())
            }
            AgentError::InvalidProof(msg) => {
                (StatusCode::UNAUTHORIZED, format!("Invalid proof: {}", msg))
            }
            AgentError::MaxDepthExceeded(depth) => (
                StatusCode::BAD_REQUEST,
                format!("Maximum delegation depth ({}) exceeded", depth),
            ),
            AgentError::MaxAgentsExceeded(count) => (
                StatusCode::BAD_REQUEST,
                format!("Maximum agents per user ({}) exceeded", count),
            ),
            AgentError::InsufficientEntitlements(msg) => {
                (StatusCode::FORBIDDEN, format!("Insufficient entitlements: {}", msg))
            }
            AgentError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            AgentError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing token".to_string()),
            AgentError::TokenDecodingError(msg) => {
                (StatusCode::UNAUTHORIZED, format!("Token error: {}", msg))
            }
            AgentError::TokenGenerationError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Token generation failed: {}", msg),
            ),
            AgentError::ChainRevoked(did) => (
                StatusCode::FORBIDDEN,
                format!("Delegation chain revoked at: {}", did),
            ),
            AgentError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            AgentError::ChallengeNotFound => {
                (StatusCode::BAD_REQUEST, "Challenge not found".to_string())
            }
            AgentError::ChallengeExpired => {
                (StatusCode::BAD_REQUEST, "Challenge expired".to_string())
            }
            AgentError::ChallengeMismatch => {
                (StatusCode::BAD_REQUEST, "Challenge mismatch".to_string())
            }
            AgentError::SessionError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Session error: {}", msg),
            ),
            AgentError::DatabaseError(e) => match e.as_ref() {
                DynamoDBError::TableNotExists(table) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Service setup incomplete: {} table not configured", table),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database error: {}", e),
                ),
            },
            AgentError::NtdfNotConfigured => (
                StatusCode::SERVICE_UNAVAILABLE,
                "NTDF token generation not configured".to_string(),
            ),
        };

        (status, body).into_response()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ed25519_pubkey_valid() {
        // Example did:key for Ed25519 (from did-key spec)
        // This is a test vector - the actual key bytes don't matter for format testing
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let result = extract_ed25519_pubkey(did);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_extract_ed25519_pubkey_invalid_prefix() {
        let did = "did:web:example.com";
        let result = extract_ed25519_pubkey(did);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Must start with"));
    }

    #[test]
    fn test_extract_ed25519_pubkey_invalid_base58() {
        let did = "did:key:z0Oilegal";
        let result = extract_ed25519_pubkey(did);
        assert!(result.is_err());
    }

    #[test]
    fn test_uuid_from_did_deterministic() {
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let uuid1 = uuid_from_did(did).unwrap();
        let uuid2 = uuid_from_did(did).unwrap();
        assert_eq!(uuid1, uuid2);
    }

    #[test]
    fn test_validate_did_key() {
        assert!(validate_did_key("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").is_ok());
        assert!(validate_did_key("did:web:example.com").is_err());
        assert!(validate_did_key("invalid").is_err());
    }

    #[test]
    fn test_agent_error_response_codes() {
        let test_cases = vec![
            (AgentError::InvalidDID("test".into()), StatusCode::BAD_REQUEST),
            (AgentError::DelegationNotFound, StatusCode::NOT_FOUND),
            (AgentError::DelegationAlreadyExists, StatusCode::CONFLICT),
            (AgentError::DelegationRevoked, StatusCode::FORBIDDEN),
            (AgentError::InvalidProof("test".into()), StatusCode::UNAUTHORIZED),
            (AgentError::MissingToken, StatusCode::UNAUTHORIZED),
            (AgentError::Unauthorized, StatusCode::UNAUTHORIZED),
        ];

        for (error, expected_status) in test_cases {
            let response = error.into_response();
            assert_eq!(response.status(), expected_status);
        }
    }

    #[test]
    fn test_entitlement_uris() {
        assert!(entitlements::ACTION_READ.starts_with("https://arkavo.ai/"));
        assert!(entitlements::ACTION_WRITE.starts_with("https://arkavo.ai/"));
        assert!(entitlements::ACTION_DELEGATE.contains("delegate"));
        assert!(entitlements::MESH_ORCHESTRATOR.contains("mesh"));
    }

    #[test]
    fn test_agent_configuration() {
        let config = AgentConfiguration::new("https://identity.arkavo.net");

        // Verify issuer
        assert_eq!(config.issuer, "https://identity.arkavo.net");

        // Verify endpoints
        assert_eq!(
            config.agent_authorization_endpoint,
            "https://identity.arkavo.net/agents/authorize"
        );
        assert_eq!(
            config.agent_challenge_endpoint,
            "https://identity.arkavo.net/agents/challenge"
        );
        assert_eq!(
            config.agent_token_endpoint,
            "https://identity.arkavo.net/agents/token"
        );

        // Verify supported entitlements include all defined entitlements
        assert!(config.entitlements_supported.contains(&entitlements::ACTION_READ));
        assert!(config.entitlements_supported.contains(&entitlements::ACTION_DELEGATE));

        // Verify limits match constants
        assert_eq!(config.max_delegation_depth, MAX_DELEGATION_DEPTH);
        assert_eq!(config.max_agents_per_user, MAX_AGENTS_PER_USER);

        // Verify supported methods
        assert!(config.did_methods_supported.contains(&"did:key"));
        assert!(config.proof_signing_alg_values_supported.contains(&"EdDSA"));
    }

    #[test]
    fn test_agent_configuration_trailing_slash() {
        let config = AgentConfiguration::new("https://identity.arkavo.net/");

        // Should strip trailing slash
        assert_eq!(config.issuer, "https://identity.arkavo.net");
        assert!(!config.agent_authorization_endpoint.contains("//agents"));
    }
}
