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
use crate::agent_state::{AppraisalConfig, owner_appraisal_deadline, validate_label};
use crate::constants::{
    AGENT_CHALLENGE_TTL_SECONDS, AGENT_DELEGATION_DAYS, AGENT_NAME_MAX_LEN,
    AGENT_SHORT_LIVED_TOKEN_MINUTES, AGENT_STATUS_LEASE_SECONDS, AGENT_TOKEN_MINUTES_MAX,
    AGENTS_DELEGATE_MAX_AUTH_AGE_SECONDS, AGENTS_DELEGATE_SCOPE, AUTH_TOKEN_HOURS,
    MAX_AGENTS_PER_USER, MAX_DELEGATION_DEPTH, SWARM_ID_MAX_LEN,
};
use crate::cwt;
use crate::db::{
    AgentDelegation, AgentState, AuthorizeOver, AuthorizeWrite, DynamoDBError, EffectiveState,
    SwarmWrite,
};
use crate::guardian::refuse_guardian;
use axum::http::HeaderMap;
use axum::{
    extract::{Extension, Json, Path, Query},
    http::StatusCode,
    response::IntoResponse,
};
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
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
    /// URI template of an agent identity's state endpoints: append
    /// `/quarantine`, `/recover`, `/appraisal` or `/status` after replacing
    /// `{did}` with the agent's `did:key`.
    pub agent_state_endpoint: String,
    pub guardian_registration_endpoint: String,
    pub short_lived_token_lifetime_seconds: i64,
    pub agent_status_lease_seconds: i64,
    pub owner_appraisal_ttl_seconds: i64,
    pub guardian_appraisal_max_seconds: i64,
    /// Version of docs/agent-credentials-contract.md this server implements.
    pub contract_version: &'static str,
}

impl AgentConfiguration {
    pub fn new(issuer: &str, token_minutes: i64, appraisal: AppraisalConfig) -> Self {
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
            agent_token_lifetime_seconds: token_minutes.clamp(1, AGENT_TOKEN_MINUTES_MAX) * 60,
            challenge_ttl_seconds: AGENT_CHALLENGE_TTL_SECONDS,
            did_methods_supported: vec!["did:key"],
            proof_signing_alg_values_supported: vec!["EdDSA"],
            authorization_deep_link_scheme: "arkavo://agent/authorize".to_string(),
            agent_state_endpoint: format!("{}/agents/{{did}}", base),
            guardian_registration_endpoint: format!("{}/guardians", base),
            short_lived_token_lifetime_seconds: token_minutes
                .clamp(1, AGENT_TOKEN_MINUTES_MAX)
                .min(AGENT_SHORT_LIVED_TOKEN_MINUTES)
                * 60,
            agent_status_lease_seconds: AGENT_STATUS_LEASE_SECONDS,
            owner_appraisal_ttl_seconds: appraisal.owner_ttl_seconds,
            guardian_appraisal_max_seconds: appraisal.guardian_max_seconds,
            contract_version: "v2",
        }
    }
}

/// GET /.well-known/agent-configuration
pub async fn serve_agent_configuration(
    Extension(app_state): Extension<AppState>,
) -> impl IntoResponse {
    Json(AgentConfiguration::new(
        &app_state.issuer,
        app_state.agent_tokens.minutes,
        app_state.appraisal,
    ))
}

// ============================================================================
// Wire types (contract: arkavo-agent-auth)
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AuthorizeAgentRequest {
    pub agent_did: String,
    pub name: String,
    pub entitlements: Vec<String>,
    /// SwarmKit `kit_id` the delegation is bound to. Absent for an agent
    /// onboarded before it has a kit (trust QR); its tokens then carry no
    /// `arkavo_swarm` and the platform will not release sealed keys to it.
    #[serde(default)]
    pub swarm: Option<String>,
    /// Tokens for this delegation live at most
    /// [`crate::constants::AGENT_SHORT_LIVED_TOKEN_MINUTES`].
    #[serde(default)]
    pub short_lived: bool,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeAgentResponse {
    pub success: bool,
    pub message: String,
    /// The agent identity (its DID).
    pub agent: String,
    /// Always `eligible`: authorize is the owner's bootstrap appraisal.
    pub state: &'static str,
    pub state_version: u64,
    pub appraised_until: i64,
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
    pub short_lived: bool,
    /// `""` while the agent has no kit.
    pub swarm: String,
    /// `unassessed`, `eligible`, `suspended` or `quarantined`.
    pub state: &'static str,
    pub state_version: u64,
    pub appraised_until: Option<i64>,
}

// ============================================================================
// did:key utilities
// ============================================================================

/// Extract the Ed25519 public key from `did:key:z6Mk…` (multicodec 0xed01,
/// base58btc). The key must decode to a curve point of large order: a
/// small-order ("weak") key, such as the identity point, would let a
/// non-strict verifier accept signatures nobody made, so such a DID is not
/// an agent identity at all.
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
    let key: [u8; 32] = decoded[2..34]
        .try_into()
        .map_err(|_| AgentError::InvalidDID("Invalid key length".into()))?;
    let point = VerifyingKey::from_bytes(&key)
        .map_err(|_| AgentError::InvalidDID("Key is not an Ed25519 point".into()))?;
    if point.is_weak() {
        return Err(AgentError::InvalidDID(
            "Key is a small-order Ed25519 point".into(),
        ));
    }
    Ok(key)
}

pub fn validate_did_key(did: &str) -> Result<(), AgentError> {
    extract_ed25519_pubkey(did).map(|_| ())
}

// ============================================================================
// Human (PE) authentication
// ============================================================================

#[derive(Debug)]
pub(crate) struct HumanDelegator {
    pub(crate) user_id: Uuid,
    pub(crate) username: Option<String>,
    /// When the passkey assertion behind the credential happened: the passkey
    /// auth CWT's `iat` (only the WebAuthn ceremony mints one), or a Bearer
    /// token's `auth_time`. Recovery requires it to be recent.
    pub(crate) issued_at: i64,
}

/// Authenticate the human delegator from `X-Auth-Token` (Arkavo CWT, `aud = "arkavo"`).
///
/// Only WebAuthn-derived subjects (a bare UUID — the shape `authn::mint_auth_token`
/// mints — or the `arkavo:<uuid>` prefixed form some other issuers use) may
/// delegate; Apple-only and service-account subjects are rejected, as are any
/// claims describing an agent or device NPE (`arkavo_npe` set, or `arkavo_roles`
/// containing `"agent"`). Agent-to-agent delegation is not supported yet (the
/// delegator must be a human CWT). Claims carrying `scope` or `auth_time` are
/// OIDC access tokens, never a passkey auth CWT, and are refused (401).
pub(crate) async fn authenticate_human(
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
    // `aud = "arkavo"` alone does not identify a passkey auth CWT: an OIDC
    // access token for a client (or platform audience) named "arkavo" carries
    // it too, and would otherwise act as the owner here with a refreshable,
    // never-renewed `auth_time`. `authn::mint_auth_token` never sets `scope`
    // or `auth_time`; every access token carries `scope`.
    if claims.custom.scope.is_some() || claims.custom.auth_time.is_some() {
        return Err(AgentError::Unauthorized(
            "X-Auth-Token must be a passkey auth CWT".into(),
        ));
    }

    let lifetime = claims.exp.saturating_sub(claims.iat);
    let max_auth = AUTH_TOKEN_HOURS * 3600 + cwt::DEFAULT_SKEW_SECS;
    if lifetime > max_auth {
        return Err(AgentError::Unauthorized(
            "delegator token is not a short-lived auth CWT".into(),
        ));
    }

    let user_id = user_id_from_claims(&claims)?;
    let username = app_state
        .db_store
        .get_user_by_id(&user_id)
        .await
        .ok()
        .flatten()
        .map(|u| u.username);

    Ok(HumanDelegator {
        user_id,
        username,
        issued_at: claims.iat,
    })
}

/// The operator authorizing an agent: a passkey auth CWT in `X-Auth-Token`
/// (checked first, unchanged), or else an OIDC access token in
/// `Authorization: Bearer` carrying `agents:delegate`, so `arkavo agent
/// authorize` (and the owner's quarantine/recover) can use the operator's
/// `arkavo-identity` session. `max_auth_age` bounds how old the WebAuthn
/// assertion behind a Bearer token may be for the calling endpoint.
pub(crate) async fn authenticate_operator(
    app_state: &AppState,
    headers: &HeaderMap,
    max_auth_age: i64,
) -> Result<HumanDelegator, AgentError> {
    if headers.contains_key("X-Auth-Token") {
        return authenticate_human(app_state, headers).await;
    }
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(AgentError::MissingToken)?;
    let bytes = cwt::decode_from_header(token).map_err(|_| AgentError::InvalidToken)?;
    let now = Utc::now().timestamp();
    let opts = cwt::VerifyOptions {
        expected_iss: Some(&app_state.issuer),
        // Checked below against the delegate allowlist: an OIDC access token
        // carries aud = [client_id, platform audience?].
        expected_aud: None,
        now,
        skew_secs: cwt::DEFAULT_SKEW_SECS,
    };
    let claims = cwt::verify(&bytes, &app_state.cwt_verifying_key, &opts).map_err(|e| {
        warn!("Rejected agents:delegate token: {}", e);
        AgentError::InvalidToken
    })?;
    let auth_time = check_delegate_claims(
        &claims,
        &app_state.agent_delegate_client_ids,
        now,
        max_auth_age,
    )?;
    let user_id = user_id_from_claims(&claims)?;
    let username = app_state
        .db_store
        .get_user_by_id(&user_id)
        .await
        .ok()
        .flatten()
        .map(|u| u.username);
    Ok(HumanDelegator {
        user_id,
        username,
        issued_at: auth_time,
    })
}

/// What a verified OIDC access token must carry to act as the owner on the
/// agent plane: `agents:delegate`, a client in `aud` that is on the delegate
/// allowlist *now* (a refresh token keeps minting the scope after its client
/// is delisted, so issuance-time checks are not enough), a passkey sign-in,
/// and a WebAuthn assertion no older than `max_auth_age` seconds. Returns
/// that assertion time.
fn check_delegate_claims(
    claims: &cwt::ArkavoClaims,
    delegate_clients: &[String],
    now: i64,
    max_auth_age: i64,
) -> Result<i64, AgentError> {
    let scoped = claims
        .custom
        .scope
        .as_deref()
        .is_some_and(|s| crate::oidc::has_scope(s, AGENTS_DELEGATE_SCOPE));
    if !scoped {
        return Err(AgentError::Forbidden(
            "access token lacks the agents:delegate scope".into(),
        ));
    }
    let audiences: Vec<&String> = match &claims.aud {
        cwt::Audience::Single(a) => vec![a],
        cwt::Audience::Multiple(v) => v.iter().collect(),
    };
    if !audiences
        .iter()
        .any(|a| delegate_clients.iter().any(|c| c == *a))
    {
        return Err(AgentError::Forbidden(
            "access token was not issued to a delegating client".into(),
        ));
    }
    if claims.custom.idp.as_deref() != Some("webauthn") {
        return Err(AgentError::Forbidden(
            "agents:delegate requires a passkey sign-in".into(),
        ));
    }
    let auth_time = claims
        .custom
        .auth_time
        .ok_or_else(|| AgentError::Unauthorized("access token carries no auth_time".into()))?;
    if !crate::oidc::within_age(auth_time, now, max_auth_age) {
        return Err(AgentError::Unauthorized(format!(
            "passkey assertion is older than {max_auth_age} s; sign in again"
        )));
    }
    Ok(auth_time)
}

/// Root user id from a verified CWT: `claims.sub` parsed as a bare UUID (the
/// shape `authn::mint_auth_token` mints) or an `arkavo:<uuid>`-prefixed UUID.
/// `arkavo_account_id` is deliberately NOT consulted — on the real WebAuthn
/// auth CWT it is only a copy of `sub`, so honoring it on its own would
/// accept a shape (non-UUID `sub` plus an account id) no genuine human token
/// has. Other subject namespaces (`apple:`, `client:`, …) cannot delegate.
/// Claims describing an agent or device NPE (`arkavo_npe` set, or
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

/// POST /agents/authorize — human (PE) delegates to an agent (NPE). This is
/// also the owner's bootstrap appraisal: the identity becomes `eligible`
/// until `owner_appraisal_ttl` after the passkey assertion behind the
/// owner's credential. One identity is one key; a new key
/// is a new identity.
pub async fn authorize_agent(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Json(request): Json<AuthorizeAgentRequest>,
) -> Result<impl IntoResponse, AgentError> {
    refuse_guardian(&headers)?;
    validate_did_key(&request.agent_did)?;
    validate_label("name", &request.name, AGENT_NAME_MAX_LEN)?;
    if let Some(swarm) = &request.swarm {
        validate_label("swarm", swarm, SWARM_ID_MAX_LEN)?;
    }
    info!(
        "Authorizing agent: {} with name: {}",
        request.agent_did, request.name
    );
    if request.entitlements.is_empty() {
        return Err(AgentError::InsufficientEntitlements(
            "At least one entitlement is required".into(),
        ));
    }

    let human =
        authenticate_operator(&app_state, &headers, AGENTS_DELEGATE_MAX_AUTH_AGE_SECONDS).await?;

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

    // v1 only mints depth-0 delegations (the delegator is always a human, see
    // `authenticate_human`), so this bound cannot trip yet. It stays as the
    // guard sub-delegation will need, next to the constant it enforces,
    // rather than being reintroduced from scratch later.
    let depth: u8 = 0;
    if depth >= MAX_DELEGATION_DEPTH {
        return Err(AgentError::MaxDepthExceeded(depth));
    }

    let now = Utc::now().timestamp();
    // The appraisal runs from the passkey assertion behind
    // the credential (auth CWT `iat`, or the Bearer token's `auth_time`), not
    // from this request; an assertion older than the lifetime is refused.
    let appraised_until =
        owner_appraisal_deadline(human.issued_at, app_state.appraisal.owner_ttl_seconds, now)?;

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
        short_lived: request.short_lived,
        swarm: String::new(),
        trust: Default::default(),
    };
    let appraised_by = format!("owner:{}", human.user_id);
    // The write is conditioned on the version read; on a conflict (a
    // concurrent quarantine, revocation, authorize or recovery), re-read and
    // decide again.
    for _ in 0..3 {
        let existing = app_state
            .db_store
            .get_agent_delegation(&request.agent_did)
            .await
            .map_err(db_err)?;
        let plan = plan_authorize(
            existing.as_ref(),
            human.user_id,
            request.swarm.as_deref(),
            now,
        )?;
        // The quota counts live delegations, so only an authorize that adds
        // one is checked: renewing a delegation the owner already holds
        // (including a track-1 row) is never refused for quota.
        if !plan.keeps_delegation() {
            let current_count = app_state
                .db_store
                .count_delegations_by_root_user(human.user_id)
                .await
                .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;
            if current_count >= MAX_AGENTS_PER_USER {
                return Err(AgentError::MaxAgentsExceeded(current_count));
            }
        }
        let swarm = match (&request.swarm, plan.keeps_delegation()) {
            (Some(swarm), _) => SwarmWrite::Set(swarm),
            (None, true) => SwarmWrite::Keep,
            (None, false) => SwarmWrite::Clear,
        };
        match app_state
            .db_store
            .authorize_agent(AuthorizeWrite {
                delegation: &delegation,
                swarm,
                over: plan.over,
                read_version: plan.read_version,
                new_version: plan.new_version,
                appraised_until,
                appraised_by: &appraised_by,
                now,
            })
            .await
        {
            Ok(()) => {
                info!(
                    "Agent {} authorized and appraised by owner {} until {} (state_version {})",
                    request.agent_did, human.user_id, appraised_until, plan.new_version
                );
                return Ok(Json(AuthorizeAgentResponse {
                    success: true,
                    message: "Agent authorized successfully".to_string(),
                    agent: request.agent_did,
                    state: AgentState::Eligible.as_str(),
                    state_version: plan.new_version,
                    appraised_until,
                }));
            }
            Err(DynamoDBError::ConditionalConflict) => continue,
            Err(e) => return Err(db_err(e)),
        }
    }
    Err(AgentError::Conflict(
        "agent changed concurrently; retry".into(),
    ))
}

/// What an authorize by `owner` writes over `existing`, the row read for the
/// DID: the version to condition on, the version to store, and what the row
/// must still be when the write lands (`over`: absent, the owner's live
/// delegation, which stays the same delegation so an omitted swarm keeps its
/// value, or a dead one replaced by a new delegation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorizePlan {
    pub read_version: u64,
    pub new_version: u64,
    pub over: AuthorizeOver,
}

impl AuthorizePlan {
    /// Whether the row stays the same delegation (a renewal or amendment).
    pub(crate) fn keeps_delegation(&self) -> bool {
        self.over == AuthorizeOver::Live
    }
}

/// Refused while the key's quarantine latch is set (whatever the
/// delegation's liveness: moving or re-authorizing the key is no way out),
/// once the key has been recovered (only a Guardian may appraise it), and
/// while another owner's delegation of the key is live. The version bumps
/// unless the row is a live, eligible delegation of the same owner whose
/// swarm stays as it is (`swarm` is the request's, `None` keeping it), so a
/// token from a revoked or expired delegation, or one minted in an earlier
/// swarm, never revives (A → B → A would otherwise match).
pub(crate) fn plan_authorize(
    existing: Option<&AgentDelegation>,
    owner: Uuid,
    swarm: Option<&str>,
    now: i64,
) -> Result<AuthorizePlan, AgentError> {
    let Some(d) = existing else {
        return Ok(AuthorizePlan {
            read_version: 0,
            new_version: 1,
            over: AuthorizeOver::Absent,
        });
    };
    if d.trust.state == AgentState::Quarantined {
        return Err(AgentError::WorkloadQuarantined);
    }
    if d.trust.recovered() {
        return Err(AgentError::Forbidden(REFUSE_RECOVERED.into()));
    }
    let live = is_live(d, now);
    if live && d.root_user_id != owner {
        return Err(AgentError::DelegationAlreadyExists);
    }
    let keeps_delegation = live && d.root_user_id == owner;
    let swarm_changes = swarm.is_some_and(|s| s != d.swarm);
    let read_version = d.trust.state_version;
    let new_version = if keeps_delegation && d.trust.state == AgentState::Eligible && !swarm_changes
    {
        read_version
    } else {
        read_version + 1
    };
    Ok(AuthorizePlan {
        read_version,
        new_version,
        over: if keeps_delegation {
            AuthorizeOver::Live
        } else {
            AuthorizeOver::Dead {
                owner: d.root_user_id,
            }
        },
    })
}

/// GET /agents/delegations — list the caller's delegations.
pub async fn list_delegations(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AgentError> {
    refuse_guardian(&headers)?;
    let human = authenticate_human(&app_state, &headers).await?;

    let delegations = app_state
        .db_store
        .list_delegations_by_root_user(human.user_id)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;
    let now = Utc::now().timestamp();

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
                short_lived: d.short_lived,
                state: d.trust.effective(now).as_str(),
                state_version: d.trust.state_version,
                appraised_until: d.trust.appraised_until,
                swarm: d.swarm,
            })
            .collect(),
    }))
}

/// DELETE /agents/delegations/:did — revoke, cascading to child delegations.
/// The write bumps `state_version` and is conditioned on the owner and the
/// version read: it never lands on a key reassigned
/// since the read, and no renewal or appraisal that read the live row can
/// clear it and keep the version its tokens carry.
pub async fn revoke_delegation(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Path(agent_did): Path<String>,
) -> Result<impl IntoResponse, AgentError> {
    refuse_guardian(&headers)?;
    let human = authenticate_human(&app_state, &headers).await?;
    let now = Utc::now().timestamp();

    let mut revoked = None;
    for _ in 0..3 {
        let delegation = app_state
            .db_store
            .get_agent_delegation(&agent_did)
            .await
            .map_err(|e| AgentError::DatabaseError(Box::new(e)))?
            .ok_or(AgentError::DelegationNotFound)?;
        // Checked on every read, so a key reassigned between a read and the
        // write gets the same answer as one that was never the caller's.
        if delegation.root_user_id != human.user_id {
            return Err(AgentError::Unauthorized(
                "delegation belongs to a different user".into(),
            ));
        }
        match app_state
            .db_store
            .revoke_agent(
                &agent_did,
                human.user_id,
                delegation.trust.state_version,
                now,
            )
            .await
        {
            Ok(d) => {
                revoked = Some(d);
                break;
            }
            Err(DynamoDBError::ConditionalConflict) => continue,
            Err(e) => return Err(AgentError::DatabaseError(Box::new(e))),
        }
    }
    let Some(revoked) = revoked else {
        return Err(AgentError::Conflict(
            "agent changed concurrently; retry".into(),
        ));
    };
    let cascaded = app_state
        .db_store
        .revoke_delegations_with_chain(&agent_did)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;

    info!(
        "Revoked delegation {} (state_version {}) and {} child delegations",
        agent_did, revoked.trust.state_version, cascaded
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Load a delegation and check it is active (not revoked/expired, chain
/// intact). The quarantine latch is checked first: a latched key answers
/// `Workload quarantined` whatever its delegation's liveness, as it does at
/// authorize, so revoking it or letting it expire never changes the answer.
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

    if delegation.trust.state == AgentState::Quarantined {
        return Err(AgentError::WorkloadQuarantined);
    }
    if delegation.revoked_at.is_some() {
        return Err(AgentError::DelegationRevoked);
    }
    if let Some(expires_at) = delegation.expires_at
        && Utc::now().timestamp() > expires_at
    {
        return Err(AgentError::DelegationExpired);
    }
    for ancestor_did in &delegation.chain {
        // Every chain entry is an agent DID with its own delegation row
        // (that is what `revoke_delegations_with_chain` cascades over), so a
        // missing ancestor means the chain cannot be shown intact. Treat it
        // as broken rather than skipping it — skipping would let a delegation
        // whose parent row is gone keep minting tokens.
        let ancestor = app_state
            .db_store
            .get_agent_delegation(ancestor_did)
            .await
            .map_err(|e| AgentError::DatabaseError(Box::new(e)))?
            .ok_or_else(|| AgentError::ChainRevoked(ancestor_did.clone()))?;
        if ancestor.revoked_at.is_some() {
            return Err(AgentError::ChainRevoked(ancestor_did.clone()));
        }
    }
    Ok(delegation)
}

/// Whether the identity may be issued a token now: only while `eligible`.
/// Enforced here, at issuance, as well as by the platform through the status
/// lease: every `AGENT_TOKEN_AUDIENCES` verifier accepts the token, and only
/// the platform asks for status.
pub(crate) fn issuable(d: &AgentDelegation, now: i64) -> Result<(), AgentError> {
    match d.trust.effective(now) {
        EffectiveState::Eligible => Ok(()),
        EffectiveState::Quarantined => Err(AgentError::WorkloadQuarantined),
        EffectiveState::Unassessed => Err(AgentError::Forbidden(REFUSE_UNASSESSED.into())),
        EffectiveState::Suspended => Err(AgentError::Forbidden(REFUSE_SUSPENDED.into())),
    }
}

/// Contract v2 refusal texts (docs/agent-credentials-contract.md, "Refusal
/// bodies"), each after the `Forbidden: ` prefix. arkavo-edge sorts 403s by
/// these; changing one is a contract change. The other two pinned bodies are
/// the `Display` of `AgentError::WorkloadQuarantined` and
/// `AgentError::DelegationRevoked`.
pub(crate) const REFUSE_UNASSESSED: &str = "agent is unassessed; it needs an appraisal";
pub(crate) const REFUSE_SUSPENDED: &str = "agent appraisal expired; it needs a fresh appraisal";
pub(crate) const REFUSE_RECOVERED: &str = "agent was recovered; only a Guardian may appraise it";
pub(crate) const REFUSE_STALE_ASSERTION: &str =
    "passkey assertion is older than the owner appraisal lifetime; sign in again";

/// Whether a delegation can still mint: not revoked, not expired at `now`.
/// The one liveness test: authorize asks it whether a DID is already taken.
pub(crate) fn is_live(d: &AgentDelegation, now: i64) -> bool {
    d.revoked_at.is_none() && d.expires_at.is_none_or(|e| now <= e)
}

fn random_challenge_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    getrandom::getrandom(&mut out).expect("OS RNG");
    out
}

/// GET /agents/challenge?did=… — issue a challenge for an active delegation.
pub async fn generate_agent_challenge(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Query(params): Query<ChallengeQueryParams>,
) -> Result<impl IntoResponse, AgentError> {
    refuse_guardian(&headers)?;
    validate_did_key(&params.did)?;
    // The write is conditioned on the identity being issuable when it
    // lands; when it is not, re-read so the caller gets the refusal that
    // applies now (quarantined, revoked, expired, suspended).
    for _ in 0..3 {
        let delegation = active_delegation(&app_state, &params.did).await?;
        issuable(&delegation, Utc::now().timestamp())?;

        let challenge = base64::engine::general_purpose::STANDARD.encode(random_challenge_bytes());
        let nonce = Uuid::new_v4().to_string();

        match app_state
            .db_store
            .put_agent_challenge(&params.did, &challenge, &nonce, Utc::now().timestamp())
            .await
        {
            Ok(()) => {
                info!("Challenge issued for agent: {}", params.did);
                return Ok(Json(ChallengeResponse { challenge, nonce }));
            }
            Err(DynamoDBError::ConditionalConflict) => continue,
            Err(e) => return Err(db_err(e)),
        }
    }
    Err(AgentError::Conflict(
        "agent changed concurrently; retry".into(),
    ))
}

/// POST /agents/token — verify the signed challenge, mint the agent CWT.
pub async fn issue_agent_token(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Json(request): Json<TokenRequest>,
) -> Result<impl IntoResponse, AgentError> {
    refuse_guardian(&headers)?;
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
        .verify_strict(&challenge_bytes, &signature)
        .map_err(|_| AgentError::InvalidProof("Signature verification failed".into()))?;

    issuable(&delegation, Utc::now().timestamp())?;

    // Agents keep stale entitlements for the whole delegation lifetime
    // otherwise: mint against what the delegator currently holds, not what
    // was captured at authorize time.
    let held = app_state
        .db_store
        .get_user_entitlements(&delegation.root_user_id)
        .await
        .map_err(|e| AgentError::DatabaseError(Box::new(e)))?;
    let minted = mint_from_current(&app_state, &delegation, &held).await?;

    info!(
        "Agent token issued for {} at state_version {}",
        request.did, minted.state_version
    );
    Ok(Json(minted.response))
}

/// A token minted by [`mint_from_current`], and the version it carries.
#[derive(Debug)]
pub(crate) struct Minted {
    pub response: TokenResponse,
    pub state_version: u64,
}

/// Mint the agent token from a strongly consistent read of the identity
/// taken after every other lookup of the token request, so a quarantine,
/// revocation, expiry, shortened appraisal or re-authorize (fewer
/// entitlements, `short_lived`, another swarm) that lands while the request
/// is in flight is honoured: the token carries the current row's
/// entitlements (∩ `held`, what the owner holds now), lifetime,
/// `state_version` and swarm. `read` is the row the proof was checked
/// against; a row that has since changed hands is refused like a
/// challenge that no longer matches (its owner's entitlements were not the
/// ones looked up).
pub(crate) async fn mint_from_current(
    app_state: &AppState,
    read: &AgentDelegation,
    held: &[String],
) -> Result<Minted, AgentError> {
    let current = active_delegation(app_state, &read.agent_did).await?;
    if current.root_user_id != read.root_user_id {
        return Err(AgentError::ChallengeMismatch);
    }
    issuable(&current, Utc::now().timestamp())?;
    let effective = intersect_entitlements(&current.entitlements, held);
    if effective.is_empty() {
        return Err(AgentError::InsufficientEntitlements(
            "delegated entitlements no longer held by delegator".into(),
        ));
    }
    let delegation = AgentDelegation {
        entitlements: effective,
        ..current
    };
    let (token, expires_at) = mint_agent_cwt(app_state, &delegation)?;
    Ok(Minted {
        response: TokenResponse {
            token,
            expires_at,
            entitlements: delegation.entitlements,
        },
        state_version: delegation.trust.state_version,
    })
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

/// The Arkavo KAS audience. Agent status is checked by the platform's entity
/// resolver, not by the KAS, so an agent token the KAS accepted would be a
/// live bearer there with no status lease: refused at startup.
const AGENT_TOKEN_REFUSED_KAS_AUDIENCE: &str = "https://kas.arkavo.net";

/// Agent token issuance config (spec §1). Parsed once at startup.
#[derive(Debug, Clone)]
pub struct AgentTokenConfig {
    pub audiences: Vec<String>,
    pub authorized_actors: Vec<String>,
    pub minutes: i64,
}

impl AgentTokenConfig {
    /// `AGENT_TOKEN_AUDIENCES` (required, comma-separated; never the passkey
    /// CWT audience `arkavo` nor the KAS), `AGENT_AUTHORIZED_ACTORS`
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
        for aud in &audiences {
            if aud == crate::constants::ARKAVO_CWT_AUDIENCE {
                return Err(format!(
                    "AGENT_TOKEN_AUDIENCES lists \"{aud}\", the audience of passkey auth CWTs; \
                     an agent token must never pass for one"
                ));
            }
            if aud == AGENT_TOKEN_REFUSED_KAS_AUDIENCE {
                return Err(format!(
                    "AGENT_TOKEN_AUDIENCES lists \"{aud}\": the KAS never asks for agent \
                     status, so it must not accept agent tokens; remove it"
                ));
            }
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
    // The 15-minute cap is applied in `ArkavoClaims::agent` itself, on every
    // mint; this code only adds the 5-minute cap for short_lived, so it never
    // outlives AGENT_SHORT_LIVED_TOKEN_MINUTES whatever the configured
    // minutes are.
    let minutes = if delegation.short_lived {
        cfg.minutes.min(AGENT_SHORT_LIVED_TOKEN_MINUTES)
    } else {
        cfg.minutes
    };
    let mut claims = cwt::ArkavoClaims::agent(
        issuer,
        &delegation.agent_did,
        cfg.audiences.clone(),
        minutes,
    );
    if !cfg.authorized_actors.is_empty() {
        claims = claims.with_act(
            cfg.authorized_actors
                .iter()
                .map(|s| cwt::Actor { sub: s.clone() })
                .collect(),
        );
    }
    claims = claims
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
        .with_arkavo_state_version(delegation.trust.state_version)
        .with_cnf(cwt::cnf_from_ed25519(
            &pubkey,
            delegation.agent_did.as_bytes(),
        ));
    // No kit yet: omit the claim rather than send an empty one, so the
    // platform's "token lacks arkavo_swarm" denial applies.
    if !delegation.swarm.is_empty() {
        claims = claims.with_arkavo_swarm(&delegation.swarm);
    }
    // Every token's lifetime is covered by a current appraisal and by the
    // delegation itself; one that would end before it starts is refused, never
    // minted with `exp <= iat`.
    if let Some(until) = delegation.trust.appraised_until {
        if until <= claims.iat {
            return Err(AgentError::Forbidden(REFUSE_SUSPENDED.into()));
        }
        claims.exp = claims.exp.min(until);
    }
    if let Some(end) = delegation.expires_at {
        if end <= claims.iat {
            return Err(AgentError::DelegationExpired);
        }
        claims.exp = claims.exp.min(end);
    }
    Ok(claims)
}

pub(crate) fn db_err(e: DynamoDBError) -> AgentError {
    AgentError::DatabaseError(Box::new(e))
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
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Guardian not found")]
    GuardianNotFound,
    /// Body is contract v1 text (docs/agent-credentials-contract.md).
    #[error("Workload quarantined")]
    WorkloadQuarantined,
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
            AgentError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AgentError::Forbidden(_) | AgentError::WorkloadQuarantined => {
                (StatusCode::FORBIDDEN, self.to_string())
            }
            AgentError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            AgentError::GuardianNotFound => (StatusCode::NOT_FOUND, self.to_string()),
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
    use crate::db::AgentTrust;
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    const TEST_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    fn did_key_for(pk: &VerifyingKey) -> String {
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(pk.as_bytes());
        format!("did:key:z{}", bs58::encode(bytes).into_string())
    }

    /// An eligible delegation, appraised far into the future, in "kit-alpha".
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
            // 2100-01-01: never the bound on a token's lifetime.
            expires_at: Some(4_102_444_800),
            revoked_at: None,
            short_lived: false,
            swarm: "kit-alpha".into(),
            trust: AgentTrust {
                state: AgentState::Eligible,
                state_version: 3,
                appraised_until: Some(i64::MAX),
                appraised_by: Some("owner:00000000-0000-0000-0000-000000000001".into()),
                ..AgentTrust::default()
            },
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

    /// The did:key naming raw key bytes, whether or not they are a usable key.
    fn did_key_of_bytes(key: &[u8; 32]) -> String {
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(key);
        format!("did:key:z{}", bs58::encode(bytes).into_string())
    }

    #[test]
    fn small_order_and_off_curve_keys_are_not_agent_identities() {
        // The identity point: a small-order key.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let err = extract_ed25519_pubkey(&did_key_of_bytes(&identity)).unwrap_err();
        assert!(err.to_string().contains("small-order"), "{err}");
        assert!(validate_did_key(&did_key_of_bytes(&identity)).is_err());
        // Bytes that decode to no curve point at all.
        let off_curve = (2u8..=255)
            .map(|b| {
                let mut k = [0u8; 32];
                k[0] = b;
                k
            })
            .find(|k| VerifyingKey::from_bytes(k).is_err())
            .expect("some y has no x");
        let err = extract_ed25519_pubkey(&did_key_of_bytes(&off_curve)).unwrap_err();
        assert!(err.to_string().contains("not an Ed25519 point"), "{err}");
    }

    #[test]
    fn a_forged_signature_under_a_small_order_key_never_verifies_strictly() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let vk = VerifyingKey::from_bytes(&identity).unwrap();
        // R = the identity point, s = 0: [s]B = R + [k]A holds for any message.
        let mut forged = [0u8; 64];
        forged[0] = 1;
        let forged = Signature::from_bytes(&forged);
        assert!(
            vk.verify(b"any challenge", &forged).is_ok(),
            "the lax check accepts it"
        );
        assert!(vk.verify_strict(b"any challenge", &forged).is_err());
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
            Some("https://platform.arkavo.net, https://kg.arkavo.net".into()),
            Some("https://kg.arkavo.net".into()),
            Some("60".into()),
        )
        .unwrap();
        assert_eq!(
            cfg.audiences,
            vec!["https://platform.arkavo.net", "https://kg.arkavo.net"]
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
    fn agent_claims_carry_the_state_version_and_swarm() {
        let cfg = AgentTokenConfig {
            audiences: vec!["https://platform.arkavo.net".into()],
            authorized_actors: vec![],
            minutes: 15,
        };
        let claims = agent_cwt_claims(
            "https://identity.arkavo.net",
            &cfg,
            &sample_delegation(TEST_DID),
        )
        .unwrap();
        assert_eq!(claims.custom.arkavo_state_version, Some(3));
        assert_eq!(claims.custom.arkavo_swarm.as_deref(), Some("kit-alpha"));

        let no_kit = AgentDelegation {
            swarm: String::new(),
            ..sample_delegation(TEST_DID)
        };
        let claims = agent_cwt_claims("https://identity.arkavo.net", &cfg, &no_kit).unwrap();
        assert_eq!(claims.custom.arkavo_state_version, Some(3));
        assert_eq!(claims.custom.arkavo_swarm, None, "omitted, not empty");
    }

    #[test]
    fn a_token_never_outlives_the_appraisal() {
        let cfg = AgentTokenConfig {
            audiences: vec!["https://platform.arkavo.net".into()],
            authorized_actors: vec![],
            minutes: 15,
        };
        let mut d = sample_delegation(TEST_DID);
        let now = Utc::now().timestamp();
        d.trust.appraised_until = Some(now + 60);
        let claims = agent_cwt_claims("https://identity.arkavo.net", &cfg, &d).unwrap();
        assert_eq!(claims.exp, now + 60, "capped at appraised_until");
        d.trust.appraised_until = Some(now + 3_600);
        let claims = agent_cwt_claims("https://identity.arkavo.net", &cfg, &d).unwrap();
        assert_eq!(
            claims.exp - claims.iat,
            900,
            "the lifetime cap still applies"
        );
    }

    #[test]
    fn a_token_never_outlives_the_delegation_nor_ends_before_it_starts() {
        let cfg = AgentTokenConfig {
            audiences: vec!["https://platform.arkavo.net".into()],
            authorized_actors: vec![],
            minutes: 15,
        };
        let claims_for = |appraised_until: i64, expires_at: i64| {
            let mut d = sample_delegation(TEST_DID);
            d.trust.appraised_until = Some(appraised_until);
            d.expires_at = Some(expires_at);
            agent_cwt_claims("https://identity.arkavo.net", &cfg, &d)
        };
        let now = Utc::now().timestamp();
        let claims = claims_for(now + 3_600, now + 60).unwrap();
        assert_eq!(claims.exp, now + 60, "capped at the delegation's expiry");
        // An appraisal that has ended by the time the claims are built.
        assert_eq!(
            claims_for(now, now + 3_600).unwrap_err().to_string(),
            "Forbidden: agent appraisal expired; it needs a fresh appraisal"
        );
        assert_eq!(
            claims_for(now - 1, now + 3_600).unwrap_err().to_string(),
            "Forbidden: agent appraisal expired; it needs a fresh appraisal"
        );
        // A delegation that has ended by then.
        assert!(matches!(
            claims_for(now + 3_600, now),
            Err(AgentError::DelegationExpired)
        ));
    }

    #[test]
    fn only_an_eligible_identity_is_issuable() {
        let now = 1_790_000_000;
        let mut d = sample_delegation(TEST_DID);
        d.trust.appraised_until = Some(now + 1);
        assert!(issuable(&d, now).is_ok());
        d.trust.appraised_until = Some(now);
        assert_eq!(
            issuable(&d, now).unwrap_err().to_string(),
            "Forbidden: agent appraisal expired; it needs a fresh appraisal"
        );
        d.trust.state = AgentState::Unassessed;
        assert_eq!(
            issuable(&d, now).unwrap_err().to_string(),
            "Forbidden: agent is unassessed; it needs an appraisal"
        );
        d.trust.state = AgentState::Quarantined;
        assert_eq!(
            issuable(&d, now).unwrap_err().to_string(),
            "Workload quarantined"
        );
    }

    #[test]
    fn authorize_plans_the_version_and_refuses_latched_recovered_or_foreign_keys() {
        let owner = Uuid::from_u128(1);
        let now = 1_790_000_000;
        let mut d = sample_delegation(TEST_DID);
        d.root_user_id = owner;
        d.expires_at = Some(now + 86_400);
        let plan = |d: Option<&AgentDelegation>| plan_authorize(d, owner, None, now);
        assert_eq!(
            plan(None).unwrap(),
            AuthorizePlan {
                read_version: 0,
                new_version: 1,
                over: AuthorizeOver::Absent
            }
        );
        assert_eq!(
            plan(Some(&d)).unwrap(),
            AuthorizePlan {
                read_version: 3,
                new_version: 3,
                over: AuthorizeOver::Live
            },
            "renewing a live eligible delegation keeps the version"
        );
        // A swarm change is an authorization-binding change.
        assert_eq!(
            plan_authorize(Some(&d), owner, Some("kit-alpha"), now)
                .unwrap()
                .new_version,
            3,
            "naming the current swarm is a renewal"
        );
        assert_eq!(
            plan_authorize(Some(&d), owner, Some("kit-beta"), now)
                .unwrap()
                .new_version,
            4,
            "a swarm change bumps"
        );
        let suspended = AgentDelegation {
            trust: AgentTrust {
                appraised_until: Some(now),
                ..d.trust.clone()
            },
            ..d.clone()
        };
        assert_eq!(
            plan(Some(&suspended)).unwrap().new_version,
            3,
            "stored state is eligible"
        );
        let legacy = AgentDelegation {
            trust: AgentTrust::default(),
            ..d.clone()
        };
        assert_eq!(
            plan(Some(&legacy)).unwrap(),
            AuthorizePlan {
                read_version: 0,
                new_version: 1,
                over: AuthorizeOver::Live
            }
        );
        let revoked = AgentDelegation {
            revoked_at: Some(now - 1),
            ..d.clone()
        };
        assert_eq!(
            plan(Some(&revoked)).unwrap(),
            AuthorizePlan {
                read_version: 3,
                new_version: 4,
                over: AuthorizeOver::Dead { owner }
            },
            "a new delegation over a revoked one bumps the version"
        );
        let expired = AgentDelegation {
            expires_at: Some(now - 1),
            ..d.clone()
        };
        assert_eq!(plan(Some(&expired)).unwrap().new_version, 4);
        let foreign = AgentDelegation {
            root_user_id: Uuid::from_u128(2),
            ..d.clone()
        };
        assert!(matches!(
            plan(Some(&foreign)),
            Err(AgentError::DelegationAlreadyExists)
        ));
        let foreign_expired = AgentDelegation {
            expires_at: Some(now - 1),
            ..foreign
        };
        assert_eq!(
            plan(Some(&foreign_expired)).unwrap(),
            AuthorizePlan {
                read_version: 3,
                new_version: 4,
                over: AuthorizeOver::Dead {
                    owner: Uuid::from_u128(2)
                }
            },
            "taken over only while still the former owner's and still dead"
        );
        let latched = AgentDelegation {
            trust: AgentTrust {
                state: AgentState::Quarantined,
                ..d.trust.clone()
            },
            revoked_at: Some(now - 1),
            ..d.clone()
        };
        assert!(matches!(
            plan(Some(&latched)),
            Err(AgentError::WorkloadQuarantined)
        ));
        let recovered = AgentDelegation {
            trust: AgentTrust {
                state: AgentState::Unassessed,
                recovered_at: Some(now - 10),
                ..d.trust.clone()
            },
            ..d.clone()
        };
        assert_eq!(
            plan(Some(&recovered)).unwrap_err().to_string(),
            "Forbidden: agent was recovered; only a Guardian may appraise it"
        );
    }

    #[test]
    fn short_lived_delegations_mint_tokens_of_at_most_five_minutes() {
        let cfg = |minutes| AgentTokenConfig {
            audiences: vec!["https://platform.arkavo.net".into()],
            authorized_actors: vec![],
            minutes,
        };
        let mut d = sample_delegation(TEST_DID);
        let life = |c: &AgentTokenConfig, d: &AgentDelegation| {
            let claims = agent_cwt_claims("https://identity.arkavo.net", c, d).unwrap();
            claims.exp - claims.iat
        };
        assert_eq!(life(&cfg(15), &d), 900);
        d.short_lived = true;
        assert_eq!(life(&cfg(15), &d), 300);
        assert_eq!(
            life(&cfg(3), &d),
            180,
            "a shorter configured lifetime still wins"
        );
        // `cfg(60)` is built directly, bypassing `AgentTokenConfig::parse`'s
        // own clamp to AGENT_TOKEN_MINUTES_MAX: this exercises the cap that
        // `cwt::ArkavoClaims::agent` applies on every mint, not the one
        // `parse` applies to config at startup.
        assert_eq!(
            life(&cfg(60), &sample_delegation(TEST_DID)),
            900,
            "the mint path itself caps at 15 minutes, not just config parsing"
        );
        assert_eq!(
            life(&cfg(60), &d),
            300,
            "short_lived still wins over an oversized config minutes"
        );
    }

    #[test]
    fn user_id_from_claims_accepts_bare_uuid_and_arkavo_prefixed_subjects() {
        // The real WebAuthn auth CWT (authn::mint_auth_token) has a bare-UUID
        // `sub` (and, since the claims fix, an `arkavo_account_id` equal to
        // it) — `sub` alone is what identifies the delegator.
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
        // arkavo_account_id must never be trusted on its own — on the real
        // auth CWT it only mirrors `sub`, so honoring it with a non-UUID `sub`
        // would accept a shape no genuine human token has.
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
        // The real flow passes the Arkavo custom claims for the user record
        // (`arkavo_account_id` == sub, roles ["user"]) — they must not trip
        // the agent/NPE rejection in user_id_from_claims.
        let user = cwt::ArkavoUserClaims {
            account_id: user_id.to_string(),
            roles: vec!["user".into()],
            entitlements: vec![],
            patreon: None,
        };
        let token =
            crate::authn::mint_auth_token(&app_state, &user_id, Some(&user), None).expect("mint");
        let mut headers = HeaderMap::new();
        headers.insert("X-Auth-Token", token.parse().unwrap());
        let human = authenticate_human(&app_state, &headers)
            .await
            .expect("a real WebAuthn auth CWT must be accepted");
        assert_eq!(human.user_id, user_id);
    }

    #[tokio::test]
    async fn authenticate_human_rejects_registration_cwt() {
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
            std::env::set_var("AWS_ACCESS_KEY_ID", "fake_access_key");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "fake_secret_key");
        }
        let app_state = crate::test_helpers::build_test_app_state().await;
        let user_id = Uuid::new_v4();
        let cnf = cwt::cnf_from_ed25519(&[7u8; 32], b"kid");
        // Mint it the way `POST /register` does — with the Arkavo custom
        // claims — so the rejection is proven against the production shape.
        let user = cwt::ArkavoUserClaims {
            account_id: user_id.to_string(),
            roles: vec!["user".into()],
            entitlements: vec![],
            patreon: None,
        };
        let token = crate::authn::mint_registration_token(&app_state, &user_id, Some(&user), cnf)
            .expect("mint");
        let mut headers = HeaderMap::new();
        headers.insert("X-Auth-Token", token.parse().unwrap());
        let err = authenticate_human(&app_state, &headers)
            .await
            .expect_err("99-year registration CWT must not authorize agents");
        assert!(matches!(err, AgentError::Unauthorized(_)));
    }

    #[test]
    fn agent_token_config_refuses_the_passkey_and_kas_audiences() {
        for listed in [
            "arkavo",
            "https://platform.arkavo.net,arkavo",
            "https://kas.arkavo.net",
            "https://platform.arkavo.net, https://kas.arkavo.net",
        ] {
            let err = AgentTokenConfig::parse(Some(listed.into()), None, None).unwrap_err();
            assert!(
                err.contains("AGENT_TOKEN_AUDIENCES lists"),
                "{listed}: {err}"
            );
        }
        assert!(
            AgentTokenConfig::parse(
                Some("https://platform.arkavo.net,https://kg.arkavo.net".into()),
                None,
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn agent_token_config_rejects_non_integer_minutes() {
        let err = AgentTokenConfig::parse(
            Some("https://platform.test".into()),
            None,
            Some("fifteen".into()),
        )
        .unwrap_err();
        assert!(err.contains("not an integer"), "{err}");
        let ok =
            AgentTokenConfig::parse(Some("https://platform.test".into()), None, Some("7".into()))
                .unwrap();
        assert_eq!(ok.minutes, 7);
        let clamped = AgentTokenConfig::parse(
            Some("https://platform.test".into()),
            None,
            Some("99".into()),
        )
        .unwrap();
        assert_eq!(clamped.minutes, AGENT_TOKEN_MINUTES_MAX);
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
                AgentError::InvalidRequest("x".into()),
                StatusCode::BAD_REQUEST,
            ),
            (AgentError::Forbidden("x".into()), StatusCode::FORBIDDEN),
            (AgentError::Conflict("x".into()), StatusCode::CONFLICT),
            (AgentError::GuardianNotFound, StatusCode::NOT_FOUND),
            (AgentError::WorkloadQuarantined, StatusCode::FORBIDDEN),
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
    fn db_err_keeps_a_missing_table_a_503() {
        let mapped = db_err(DynamoDBError::TableNotExists("agent_delegations".into()));
        assert!(matches!(mapped, AgentError::DatabaseError(_)));
        assert_eq!(
            mapped.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn the_quarantine_refusal_body_is_contract_text() {
        let resp = AgentError::WorkloadQuarantined.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"Workload quarantined");
    }

    #[test]
    fn check_delegate_claims_needs_scope_client_passkey_and_a_recent_assertion() {
        let now = 1_790_000_000;
        let clients = vec!["arkavo-edge".to_string()];
        let good = || {
            cwt::ArkavoClaims::oidc_access(
                "https://identity.arkavo.net",
                "arkavo:u",
                "arkavo-edge",
                1,
            )
            .with_idp("webauthn")
            .with_scope("openid agents:delegate")
            .with_auth_time(now - 3_600)
        };
        let hour = AGENTS_DELEGATE_MAX_AUTH_AGE_SECONDS;
        assert_eq!(
            check_delegate_claims(&good(), &clients, now, hour).unwrap(),
            now - 3_600
        );
        assert!(
            matches!(
                check_delegate_claims(&good(), &clients, now, 300),
                Err(AgentError::Unauthorized(_))
            ),
            "the recover limit is five minutes"
        );
        assert!(matches!(
            check_delegate_claims(&good().with_scope("openid"), &clients, now, hour),
            Err(AgentError::Forbidden(_))
        ));
        assert!(matches!(
            check_delegate_claims(&good(), &["other".to_string()], now, hour),
            Err(AgentError::Forbidden(_))
        ));
        assert!(matches!(
            check_delegate_claims(&good().with_idp("google"), &clients, now, hour),
            Err(AgentError::Forbidden(_))
        ));
        assert!(matches!(
            check_delegate_claims(&good().with_auth_time(now - 3_601), &clients, now, hour),
            Err(AgentError::Unauthorized(_))
        ));
        let mut no_time = good();
        no_time.custom.auth_time = None;
        assert!(matches!(
            check_delegate_claims(&no_time, &clients, now, hour),
            Err(AgentError::Unauthorized(_))
        ));
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
        let c = AgentConfiguration::new(
            "https://identity.arkavo.net/",
            15,
            AppraisalConfig::default(),
        );
        assert_eq!(c.issuer, "https://identity.arkavo.net");
        assert_eq!(
            c.agent_token_endpoint,
            "https://identity.arkavo.net/agents/token"
        );
        assert!(!c.agent_authorization_endpoint.contains("//agents"));
        assert_eq!(c.max_delegation_depth, MAX_DELEGATION_DEPTH);
        assert_eq!(c.agent_token_lifetime_seconds, 15 * 60);
        assert_eq!(
            AgentConfiguration::new(
                "https://identity.arkavo.net/",
                7,
                AppraisalConfig::default()
            )
            .agent_token_lifetime_seconds,
            7 * 60
        );
        assert_eq!(
            c.delegation_lifetime_seconds,
            AGENT_DELEGATION_DAYS * 86_400
        );
        assert_eq!(
            c.agent_state_endpoint,
            "https://identity.arkavo.net/agents/{did}"
        );
        assert_eq!(
            c.guardian_registration_endpoint,
            "https://identity.arkavo.net/guardians"
        );
        assert_eq!(c.short_lived_token_lifetime_seconds, 300);
        assert_eq!(
            AgentConfiguration::new("https://identity.arkavo.net", 3, AppraisalConfig::default())
                .short_lived_token_lifetime_seconds,
            180
        );
        assert_eq!(c.agent_status_lease_seconds, 5);
        assert_eq!(
            (
                c.owner_appraisal_ttl_seconds,
                c.guardian_appraisal_max_seconds
            ),
            (43_200, 900)
        );
        let tuned = AgentConfiguration::new(
            "https://identity.arkavo.net",
            15,
            AppraisalConfig {
                owner_ttl_seconds: 3_600,
                guardian_max_seconds: 300,
            },
        );
        assert_eq!(
            (
                tuned.owner_appraisal_ttl_seconds,
                tuned.guardian_appraisal_max_seconds
            ),
            (3_600, 300)
        );
        assert_eq!(c.contract_version, "v2");
    }
}
