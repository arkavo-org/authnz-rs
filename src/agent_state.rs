//! The agent identity's trust state over HTTP. Contract:
//! docs/agent-credentials-contract.md (v2).

use crate::AppState;
use crate::agent::{
    AgentError, REFUSE_RECOVERED, REFUSE_STALE_ASSERTION, db_err, extract_ed25519_pubkey, is_live,
    validate_did_key,
};
use crate::constants::{
    AGENT_STATUS_LEASE_SECONDS, AGENTS_DELEGATE_MAX_AUTH_AGE_SECONDS, EVIDENCE_REF_MAX_LEN,
    GUARDIAN_APPRAISAL_MAX_SECONDS, INCIDENT_MAX_LEN, OWNER_APPRAISAL_TTL_DEFAULT_SECONDS,
    OWNER_APPRAISAL_TTL_MAX_SECONDS, RECOVERY_TOKEN_MAX_AGE_SECONDS,
};
use crate::db::{AgentDelegation, AgentState, DynamoDBError, EffectiveState, QuarantineOutcome};
use crate::entitlements::EntitlementError;
use crate::guardian::{GUARDIAN_SIGNATURE_HEADER, refuse_guardian, verify_guardian_request};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, OriginalUri, Path};
use axum::http::{HeaderMap, Method};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How long an appraisal lasts, parsed once at startup. Either value may be
/// configured below its ceiling, never above it: an out-of-range value
/// fails startup rather than being clamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppraisalConfig {
    /// An owner appraisal's `appraised_until` is this long after the owner's
    /// passkey assertion (`auth_time`), never after the request.
    pub owner_ttl_seconds: i64,
    /// The latest `appraised_until` a Guardian may set, from now.
    pub guardian_max_seconds: i64,
}

impl Default for AppraisalConfig {
    fn default() -> Self {
        Self {
            owner_ttl_seconds: OWNER_APPRAISAL_TTL_DEFAULT_SECONDS,
            guardian_max_seconds: GUARDIAN_APPRAISAL_MAX_SECONDS,
        }
    }
}

impl AppraisalConfig {
    /// `AGENT_OWNER_APPRAISAL_TTL_SECONDS` (default 12 h, 1 s to 24 h) and
    /// `AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS` (default 15 min, 1 s to 15 min).
    pub fn parse(owner_ttl: Option<String>, guardian_max: Option<String>) -> Result<Self, String> {
        fn bounded(name: &str, raw: Option<String>, default: i64, max: i64) -> Result<i64, String> {
            let Some(raw) = raw.filter(|v| !v.trim().is_empty()) else {
                return Ok(default);
            };
            let value: i64 = raw
                .trim()
                .parse()
                .map_err(|_| format!("{name} is not an integer: {raw}"))?;
            if !(1..=max).contains(&value) {
                return Err(format!("{name} must be 1 to {max} seconds, got {value}"));
            }
            Ok(value)
        }
        Ok(Self {
            owner_ttl_seconds: bounded(
                "AGENT_OWNER_APPRAISAL_TTL_SECONDS",
                owner_ttl,
                OWNER_APPRAISAL_TTL_DEFAULT_SECONDS,
                OWNER_APPRAISAL_TTL_MAX_SECONDS,
            )?,
            guardian_max_seconds: bounded(
                "AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS",
                guardian_max,
                GUARDIAN_APPRAISAL_MAX_SECONDS,
                GUARDIAN_APPRAISAL_MAX_SECONDS,
            )?,
        })
    }
}

/// Refuse an empty, oversized or control-character label before it reaches
/// storage or a token claim.
pub(crate) fn validate_label(field: &str, value: &str, max: usize) -> Result<(), AgentError> {
    if value.is_empty() || value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(AgentError::InvalidRequest(format!(
            "{field} must be 1 to {max} characters with no control characters"
        )));
    }
    Ok(())
}

/// When an owner appraisal ends: `owner_ttl` after the
/// passkey assertion behind the owner's credential (a passkey auth CWT's
/// `iat`, or an `agents:delegate` token's `auth_time`), never after the
/// request, and never later than `now + owner_ttl`, so a clock-skewed `iat`
/// gains nothing. Refused once that moment has passed: the owner signs in
/// again.
pub(crate) fn owner_appraisal_deadline(
    issued_at: i64,
    owner_ttl: i64,
    now: i64,
) -> Result<i64, AgentError> {
    let deadline = issued_at
        .saturating_add(owner_ttl)
        .min(now.saturating_add(owner_ttl));
    if deadline <= now {
        return Err(AgentError::Forbidden(REFUSE_STALE_ASSERTION.into()));
    }
    Ok(deadline)
}

/// Contract v2 status body; quarantine, recover and appraisal answer with
/// it too.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentStatus {
    pub agent: String,
    pub owner: String,
    /// `""` while the agent has no kit.
    pub swarm: String,
    /// `unassessed`, `eligible`, `suspended` or `quarantined`.
    pub state: String,
    pub state_version: u64,
    pub appraised_until: Option<i64>,
    /// `owner` or `guardian`.
    pub appraised_by: Option<String>,
    pub incident: Option<String>,
    pub valid_until: i64,
}

impl AgentStatus {
    /// `valid_until` is `now + 5`, and no later than `appraised_until` while
    /// eligible, so a cached answer never outlives the appraisal.
    pub(crate) fn of(d: &AgentDelegation, now: i64) -> Self {
        let state = d.trust.effective(now);
        let mut valid_until = now + AGENT_STATUS_LEASE_SECONDS;
        if state == EffectiveState::Eligible
            && let Some(until) = d.trust.appraised_until
        {
            valid_until = valid_until.min(until);
        }
        Self {
            agent: d.agent_did.clone(),
            owner: d.root_user_id.to_string(),
            swarm: d.swarm.clone(),
            state: state.as_str().to_string(),
            state_version: d.trust.state_version,
            appraised_until: d.trust.appraised_until,
            appraised_by: d
                .trust
                .appraised_by
                .as_deref()
                .and_then(|by| by.split_once(':'))
                .map(|(kind, _)| kind.to_string()),
            incident: d.trust.incident.clone(),
            valid_until,
        }
    }
}

/// Who is changing an identity's state.
pub(crate) enum StateCaller {
    Owner {
        user_id: Uuid,
        /// The passkey assertion behind the credential (auth CWT `iat`, or
        /// Bearer `auth_time`): an owner appraisal runs from it.
        issued_at: i64,
    },
    Guardian {
        guardian_id: String,
        owner: Uuid,
        public_key: [u8; 32],
    },
}

impl StateCaller {
    pub(crate) fn owner(&self) -> Uuid {
        match self {
            Self::Owner { user_id, .. } => *user_id,
            Self::Guardian { owner, .. } => *owner,
        }
    }

    /// `owner:<uuid>` or `guardian:<guardian_id>`, stored as who latched or
    /// appraised.
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Owner { user_id, .. } => format!("owner:{user_id}"),
            Self::Guardian { guardian_id, .. } => format!("guardian:{guardian_id}"),
        }
    }
}

/// A Guardian when the request carries `X-Guardian-Signature` (checked
/// before either owner credential, so a signed request never falls back to
/// one); otherwise the owner by passkey auth CWT or, when `X-Auth-Token` is
/// absent, by an `agents:delegate` Bearer token whose assertion is at most
/// an hour old.
pub(crate) async fn state_caller(
    app_state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    body: &[u8],
    now: i64,
) -> Result<StateCaller, AgentError> {
    if headers.contains_key(GUARDIAN_SIGNATURE_HEADER) {
        let g = verify_guardian_request(app_state, headers, method, path, body, now).await?;
        return Ok(StateCaller::Guardian {
            guardian_id: g.guardian_id,
            owner: g.owner,
            public_key: g.public_key,
        });
    }
    let owner = crate::agent::authenticate_operator(
        app_state,
        headers,
        AGENTS_DELEGATE_MAX_AUTH_AGE_SECONDS,
    )
    .await?;
    Ok(StateCaller::Owner {
        user_id: owner.user_id,
        issued_at: owner.issued_at,
    })
}

/// The identity at `did`, which must belong to `owner`.
async fn owned_agent(
    app_state: &AppState,
    did: &str,
    owner: Uuid,
) -> Result<AgentDelegation, AgentError> {
    let d = app_state
        .db_store
        .get_agent_delegation(did)
        .await
        .map_err(db_err)?
        .ok_or(AgentError::DelegationNotFound)?;
    if d.root_user_id != owner {
        return Err(AgentError::Forbidden(
            "agent belongs to a different owner".into(),
        ));
    }
    Ok(d)
}

#[derive(Debug, Deserialize)]
pub struct QuarantineRequest {
    pub incident: String,
    #[serde(default)]
    pub evidence_ref: Option<String>,
}

/// POST /agents/:did/quarantine — latch a quarantine on the identity.
/// Idempotent per incident; a different incident while latched is 409, so
/// the incident a recovery must cite stays unambiguous. Latches whatever the
/// delegation's liveness: the latch is on the key. The write is conditioned
/// on the owner and the `state_version` read: a key
/// reassigned to another owner since the read is refused (403), and a
/// concurrent state change is re-read and decided again.
pub async fn quarantine_agent(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    Path(did): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AgentError> {
    let now = Utc::now().timestamp();
    // The signed PATH is the path as sent, without the query string.
    let caller = state_caller(&app_state, &headers, &method, uri.path(), &body, now).await?;
    validate_did_key(&did)?;
    // Parsed from raw bytes: a Guardian signs the exact body.
    let req: QuarantineRequest = serde_json::from_slice(&body)
        .map_err(|e| AgentError::InvalidRequest(format!("quarantine body: {e}")))?;
    validate_label("incident", &req.incident, INCIDENT_MAX_LEN)?;
    if let Some(ev) = &req.evidence_ref {
        validate_label("evidence_ref", ev, EVIDENCE_REF_MAX_LEN)?;
    }
    for _ in 0..3 {
        let read = owned_agent(&app_state, &did, caller.owner()).await?;
        match app_state
            .db_store
            .quarantine_agent(
                &did,
                caller.owner(),
                read.trust.state_version,
                &req.incident,
                req.evidence_ref.as_deref(),
                &caller.label(),
                now,
            )
            .await
            .map_err(db_err)?
        {
            QuarantineOutcome::Latched(d) => {
                warn!(
                    "Agent {} quarantined by {} (incident {}, state_version {})",
                    did,
                    caller.label(),
                    req.incident,
                    d.trust.state_version
                );
                return Ok(Json(AgentStatus::of(&d, now)));
            }
            QuarantineOutcome::AlreadyLatched(d) => return Ok(Json(AgentStatus::of(&d, now))),
            QuarantineOutcome::OtherIncident(d) => {
                return Err(AgentError::Conflict(format!(
                    "agent already quarantined under incident {}",
                    d.trust.incident.unwrap_or_default()
                )));
            }
            QuarantineOutcome::ClearedIncident(_) => {
                return Err(AgentError::Conflict(format!(
                    "incident {} was already cleared by recovery; report a new incident",
                    req.incident
                )));
            }
            // Reassigned to another owner after the ownership read.
            QuarantineOutcome::NotOwner => {
                return Err(AgentError::Forbidden(
                    "agent belongs to a different owner".into(),
                ));
            }
            QuarantineOutcome::NotFound => return Err(AgentError::DelegationNotFound),
            // The version moved (an appraisal, authorize, revocation or
            // recovery landed in between): read again and decide again.
            QuarantineOutcome::Raced => continue,
        }
    }
    Err(AgentError::Conflict(
        "agent changed concurrently; retry".into(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct RecoverRequest {
    pub incident: String,
}

/// POST /agents/:did/recover — the only way out of a quarantine: the owner
/// alone, with a passkey assertion from the last five minutes, citing the
/// incident being cleared. The identity becomes `unassessed`, and from then
/// on only a Guardian may appraise it. Guardians, agents and services
/// cannot call it.
pub async fn recover_agent(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Path(did): Path<String>,
    Json(req): Json<RecoverRequest>,
) -> Result<impl IntoResponse, AgentError> {
    // Verified or not, and even alongside a valid owner credential.
    refuse_guardian(&headers)?;
    // The passkey CWT is aged by its `iat` here; the Bearer path already
    // bounded `auth_time` inside, and reports it as `issued_at` too.
    let owner =
        crate::agent::authenticate_operator(&app_state, &headers, RECOVERY_TOKEN_MAX_AGE_SECONDS)
            .await?;
    let now = Utc::now().timestamp();
    if !crate::oidc::within_age(owner.issued_at, now, RECOVERY_TOKEN_MAX_AGE_SECONDS) {
        return Err(AgentError::Unauthorized(format!(
            "recovery needs a passkey assertion from the last \
             {RECOVERY_TOKEN_MAX_AGE_SECONDS} s; sign in again"
        )));
    }
    validate_did_key(&did)?;
    validate_label("incident", &req.incident, INCIDENT_MAX_LEN)?;
    // The write is conditioned on the version read; on a conflict, re-read
    // and decide again (a concurrent recovery then reads as not quarantined).
    for _ in 0..3 {
        let d = owned_agent(&app_state, &did, owner.user_id).await?;
        if d.trust.state != AgentState::Quarantined {
            return Err(AgentError::Conflict("agent is not quarantined".into()));
        }
        if d.trust.incident.as_deref() != Some(req.incident.as_str()) {
            return Err(AgentError::Conflict(
                "incident does not match the quarantine being cleared".into(),
            ));
        }
        match app_state
            .db_store
            .recover_agent(&did, &req.incident, d.trust.state_version, now)
            .await
        {
            Ok(recovered) => {
                info!(
                    "Agent {} recovered by owner {} (cleared incident {}, state_version {})",
                    did, owner.user_id, req.incident, recovered.trust.state_version
                );
                return Ok(Json(AgentStatus::of(&recovered, now)));
            }
            Err(DynamoDBError::ConditionalConflict) => continue,
            Err(e) => return Err(db_err(e)),
        }
    }
    Err(AgentError::Conflict(
        "agent changed concurrently; read its status and retry".into(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct AppraisalRequest {
    /// Unix seconds. Omitted: the caller's latest (see `appraisal_until`).
    #[serde(default)]
    pub appraised_until: Option<i64>,
    /// Opaque reference to the evidence behind the appraisal (audit only).
    #[serde(default)]
    pub evidence_ref: Option<String>,
}

/// The `appraised_until` to store: the request's value, which must be in the
/// future, clamped to `latest`; or `latest` when it names none. `latest` is
/// the owner's deadline (`owner_appraisal_deadline`: the passkey assertion
/// plus `owner_appraisal_ttl`) or a Guardian's `now + guardian_appraisal_max`.
/// Clamping rather than refusing keeps a Guardian whose clock runs slightly
/// ahead working; the answer reports the value stored.
pub(crate) fn appraisal_until(
    requested: Option<i64>,
    now: i64,
    latest: i64,
) -> Result<i64, AgentError> {
    match requested {
        None => Ok(latest),
        Some(t) if t <= now => Err(AgentError::InvalidRequest(
            "appraised_until must be in the future".into(),
        )),
        Some(t) => Ok(t.min(latest)),
    }
}

/// POST /agents/:did/appraisal — record a current appraisal: the identity
/// becomes (or stays) `eligible` until `appraised_until`. An enrolled
/// Guardian of the agent's owner may appraise for up to
/// `guardian_appraisal_max` from now; the owner, for up to
/// `owner_appraisal_ttl` from its passkey assertion, but
/// never a key that has been recovered. Never clears a quarantine, and
/// never appraises a revoked or expired delegation. Renewing an eligible
/// identity keeps its `state_version`; making an unassessed one eligible
/// bumps it.
pub async fn appraise_agent(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    Path(did): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AgentError> {
    let now = Utc::now().timestamp();
    let caller = state_caller(&app_state, &headers, &method, uri.path(), &body, now).await?;
    validate_did_key(&did)?;
    let req: AppraisalRequest = serde_json::from_slice(&body)
        .map_err(|e| AgentError::InvalidRequest(format!("appraisal body: {e}")))?;
    if let Some(ev) = &req.evidence_ref {
        validate_label("evidence_ref", ev, EVIDENCE_REF_MAX_LEN)?;
    }
    let latest = match &caller {
        StateCaller::Owner { issued_at, .. } => {
            owner_appraisal_deadline(*issued_at, app_state.appraisal.owner_ttl_seconds, now)?
        }
        StateCaller::Guardian { .. } => now + app_state.appraisal.guardian_max_seconds,
    };
    let until = appraisal_until(req.appraised_until, now, latest)?;
    if let StateCaller::Guardian { public_key, .. } = &caller
        && *public_key == extract_ed25519_pubkey(&did)?
    {
        return Err(AgentError::Forbidden(
            "an agent cannot appraise itself".into(),
        ));
    }
    for _ in 0..3 {
        let d = owned_agent(&app_state, &did, caller.owner()).await?;
        if d.trust.state == AgentState::Quarantined {
            return Err(AgentError::WorkloadQuarantined);
        }
        if d.revoked_at.is_some() {
            return Err(AgentError::DelegationRevoked);
        }
        if !is_live(&d, now) {
            return Err(AgentError::DelegationExpired);
        }
        if matches!(caller, StateCaller::Owner { .. }) && d.trust.recovered() {
            return Err(AgentError::Forbidden(REFUSE_RECOVERED.into()));
        }
        let read = d.trust.state_version;
        let new_version = if d.trust.state == AgentState::Eligible {
            read
        } else {
            read + 1
        };
        match app_state
            .db_store
            .appraise_agent(
                &did,
                read,
                new_version,
                until,
                &caller.label(),
                req.evidence_ref.as_deref(),
                now,
            )
            .await
        {
            Ok(appraised) => {
                info!(
                    "Agent {} appraised by {} until {} (state_version {})",
                    did,
                    caller.label(),
                    until,
                    appraised.trust.state_version
                );
                return Ok(Json(AgentStatus::of(&appraised, now)));
            }
            Err(DynamoDBError::ConditionalConflict) => continue,
            Err(e) => return Err(db_err(e)),
        }
    }
    Err(AgentError::Conflict(
        "agent changed concurrently; read its status and retry".into(),
    ))
}

/// GET /agents/:did/status — what the platform checks before it lets an
/// agent token's entitlements through. Served from a strongly consistent
/// read with a 5-second lease, never from a cache. A revoked or expired
/// delegation is 404 unless the quarantine latch is set, which is reported
/// whatever the delegation's liveness.
pub async fn agent_status(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Path(did): Path<String>,
) -> Result<Response, AgentError> {
    refuse_guardian(&headers)?;
    crate::entitlements::require_service_cwt_for(
        &app_state,
        &headers,
        &app_state.agent_status_client_ids,
    )
    .map_err(|e| match e {
        EntitlementError::MissingToken => AgentError::MissingToken,
        EntitlementError::InvalidToken => AgentError::InvalidToken,
        _ => AgentError::Forbidden("client may not read agent status".into()),
    })?;
    validate_did_key(&did)?;
    let now = Utc::now().timestamp();
    let d = app_state
        .db_store
        .get_agent_delegation(&did)
        .await
        .map_err(db_err)?
        .filter(|d| d.trust.state == AgentState::Quarantined || is_live(d, now))
        .ok_or(AgentError::DelegationNotFound)?;
    // An agent of a deleted account is gone with it, whether or not the
    // deletion has revoked its row yet (#88). A quarantine is still reported:
    // the platform refuses it either way.
    if d.trust.state != AgentState::Quarantined
        && !app_state
            .db_store
            .is_account_live(&d.root_user_id)
            .await
            .map_err(db_err)?
    {
        return Err(AgentError::DelegationNotFound);
    }
    let mut resp = Json(AgentStatus::of(&d, now)).into_response();
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appraisal_config_defaults_to_twelve_hours_and_fifteen_minutes() {
        let c = AppraisalConfig::parse(None, None).unwrap();
        assert_eq!((c.owner_ttl_seconds, c.guardian_max_seconds), (43_200, 900));
        assert_eq!(c, AppraisalConfig::default());
        assert_eq!(
            AppraisalConfig::parse(Some(" ".into()), Some("".into())).unwrap(),
            c,
            "blank means unset"
        );
    }

    #[test]
    fn appraisal_config_accepts_values_up_to_the_nist_ceilings() {
        let c = AppraisalConfig::parse(Some("86400".into()), Some("900".into())).unwrap();
        assert_eq!((c.owner_ttl_seconds, c.guardian_max_seconds), (86_400, 900));
        let c = AppraisalConfig::parse(Some("3600".into()), Some("60".into())).unwrap();
        assert_eq!((c.owner_ttl_seconds, c.guardian_max_seconds), (3_600, 60));
    }

    #[test]
    fn appraisal_config_refuses_out_of_range_values_instead_of_clamping() {
        for (owner, guardian, needle) in [
            (
                Some("86401"),
                None,
                "AGENT_OWNER_APPRAISAL_TTL_SECONDS must be 1 to 86400",
            ),
            (
                Some("0"),
                None,
                "AGENT_OWNER_APPRAISAL_TTL_SECONDS must be 1 to 86400",
            ),
            (
                Some("-5"),
                None,
                "AGENT_OWNER_APPRAISAL_TTL_SECONDS must be 1 to 86400",
            ),
            (
                Some("12h"),
                None,
                "AGENT_OWNER_APPRAISAL_TTL_SECONDS is not an integer",
            ),
            (
                None,
                Some("901"),
                "AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS must be 1 to 900",
            ),
            (
                None,
                Some("0"),
                "AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS must be 1 to 900",
            ),
        ] {
            let err = AppraisalConfig::parse(owner.map(Into::into), guardian.map(Into::into))
                .unwrap_err();
            assert!(err.contains(needle), "{err}");
        }
    }

    #[test]
    fn appraisal_until_defaults_to_the_deadline_clamps_to_it_and_refuses_the_past() {
        assert_eq!(appraisal_until(None, 1_000, 1_900).unwrap(), 1_900);
        assert_eq!(appraisal_until(Some(1_300), 1_000, 1_900).unwrap(), 1_300);
        assert_eq!(appraisal_until(Some(5_000), 1_000, 1_900).unwrap(), 1_900);
        for past in [1_000, 999] {
            assert!(matches!(
                appraisal_until(Some(past), 1_000, 1_900),
                Err(AgentError::InvalidRequest(_))
            ));
        }
    }

    #[test]
    fn an_owner_appraisal_runs_from_the_assertion_and_is_refused_once_past() {
        assert_eq!(
            owner_appraisal_deadline(1_000, 43_200, 1_600).unwrap(),
            44_200
        );
        assert_eq!(
            owner_appraisal_deadline(1_700, 43_200, 1_600).unwrap(),
            44_800,
            "an iat ahead of the clock gains nothing"
        );
        assert_eq!(owner_appraisal_deadline(1_000, 600, 1_599).unwrap(), 1_600);
        for now in [1_600, 5_000] {
            let err = owner_appraisal_deadline(1_000, 600, now).unwrap_err();
            assert_eq!(
                err.to_string(),
                "Forbidden: passkey assertion is older than the owner appraisal lifetime; sign in again"
            );
        }
    }
}
