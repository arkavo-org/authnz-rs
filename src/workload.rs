//! Agent workloads over HTTP: binding at authorize time, quarantine,
//! recovery and the status lease. Contract:
//! docs/agent-credentials-contract.md (v1).

use crate::AppState;
use crate::agent::{AgentError, db_err, live_delegation};
use crate::constants::{
    AGENTS_DELEGATE_MAX_AUTH_AGE_SECONDS, EVIDENCE_REF_MAX_LEN, INCIDENT_MAX_LEN,
    RECOVERY_TOKEN_MAX_AGE_SECONDS, WORKLOAD_STATUS_LEASE_SECONDS,
};
use crate::db::{
    AgentDelegation, AgentWorkload, Binding, DynamoDBError, QuarantineOutcome, WorkloadState,
};
use crate::entitlements::EntitlementError;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// Whether `owner` may overwrite `existing`, a live delegation of the DID
/// being authorized into workload `workload_id`: only the DID's own
/// delegation for that workload, or a row from before workloads that the
/// same owner wrote. Mirrors the condition on the delegation put
/// (`DynamoDBStore::agent_delegation_put`).
fn replaceable(existing: &AgentDelegation, owner: Uuid, workload_id: &str) -> bool {
    match &existing.workload_id {
        Some(bound) => bound == workload_id,
        None => existing.root_user_id == owner,
    }
}

/// Select (or create) `owner`'s workload `name`, bind it to the DID of
/// `delegation` and `swarm`, and write `delegation`, all in one transaction.
///
/// `delegation.workload_id` must already name the workload
/// (`workload_id_for(owner, name)`). `swarm = None` means no swarm for a new
/// workload and the current one for an existing workload. A different DID or
/// swarm rebinds the workload (generation + 1); a different DID also revokes
/// the previously bound DID's delegation for this workload. Refused while
/// quarantined, so a new key is never a way out of a quarantine.
pub(crate) async fn bind_workload(
    app_state: &AppState,
    owner: Uuid,
    name: &str,
    swarm: Option<&str>,
    delegation: &AgentDelegation,
    now: i64,
) -> Result<AgentWorkload, AgentError> {
    let db = &app_state.db_store;
    let did = delegation.agent_did.as_str();
    let workload_id = delegation
        .workload_id
        .as_deref()
        .ok_or_else(|| db_err(DynamoDBError::Internal("delegation has no workload".into())))?;
    // Every condition sits in one transaction, whose failure does not say
    // which condition tripped: on a conflict, re-read and decide again.
    for _ in 0..3 {
        if let Some(existing) = live_delegation(app_state, did, now).await?
            && !replaceable(&existing, owner, workload_id)
        {
            return Err(AgentError::DelegationAlreadyExists);
        }
        let current = db.get_workload(workload_id).await.map_err(db_err)?;
        let (bound, outcome) = match &current {
            None => {
                let created = AgentWorkload {
                    workload_id: workload_id.to_string(),
                    owner,
                    name: name.to_string(),
                    current_did: did.to_string(),
                    swarm: swarm.unwrap_or_default().to_string(),
                    state: WorkloadState::Eligible,
                    generation: 1,
                    incident: None,
                    evidence_ref: None,
                    quarantined_by: None,
                    quarantined_at: None,
                    last_cleared_incident: None,
                    created_at: now,
                    updated_at: now,
                };
                let outcome = db
                    .commit_binding(Binding::Create(&created), delegation, now)
                    .await;
                (created, outcome)
            }
            Some(w) => {
                if w.owner != owner {
                    return Err(AgentError::Forbidden(
                        "workload belongs to a different owner".into(),
                    ));
                }
                if w.state == WorkloadState::Quarantined {
                    return Err(AgentError::WorkloadQuarantined);
                }
                // Omitting the swarm keeps the workload's current one.
                let swarm = swarm.unwrap_or(w.swarm.as_str());
                if w.current_did == did && w.swarm == swarm {
                    let outcome = db.commit_binding(Binding::Keep(w), delegation, now).await;
                    (w.clone(), outcome)
                } else {
                    // Not a liveness question: an expired delegation of the
                    // previous DID is revoked too, so it reads (and is
                    // refused) as revoked rather than merely expired.
                    let revoke_previous = !w.current_did.is_empty()
                        && w.current_did != did
                        && db
                            .get_agent_delegation(&w.current_did)
                            .await
                            .map_err(db_err)?
                            .is_some_and(|d| {
                                d.revoked_at.is_none()
                                    && d.workload_id.as_deref() == Some(workload_id)
                            });
                    let binding = Binding::Rebind {
                        from: w,
                        did,
                        swarm,
                        revoke_previous,
                    };
                    let outcome = db.commit_binding(binding, delegation, now).await;
                    let rebound = AgentWorkload {
                        current_did: did.to_string(),
                        swarm: swarm.to_string(),
                        generation: w.generation + 1,
                        updated_at: now,
                        ..w.clone()
                    };
                    (rebound, outcome)
                }
            }
        };
        match outcome {
            Ok(()) => return Ok(bound),
            Err(DynamoDBError::ConditionalConflict) => continue,
            Err(e) => return Err(db_err(e)),
        }
    }
    Err(AgentError::Conflict(
        "workload changed concurrently; retry".into(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct QuarantineRequest {
    pub incident: String,
    #[serde(default)]
    pub evidence_ref: Option<String>,
}

/// Contract v1 status body; quarantine and recover answer with it too.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadStatus {
    pub workload: String,
    pub owner: String,
    pub current_did: String,
    pub swarm: String,
    pub state: String,
    pub generation: u64,
    pub incident: Option<String>,
    pub valid_until: i64,
}

impl WorkloadStatus {
    pub(crate) fn of(w: &AgentWorkload, now: i64) -> Self {
        Self {
            workload: w.workload_id.clone(),
            owner: w.owner.to_string(),
            current_did: w.current_did.clone(),
            swarm: w.swarm.clone(),
            state: w.state.as_str().to_string(),
            generation: w.generation,
            incident: w.incident.clone(),
            valid_until: now + WORKLOAD_STATUS_LEASE_SECONDS,
        }
    }
}

/// Who is latching a quarantine.
enum QuarantineCaller {
    Owner(Uuid),
}

impl QuarantineCaller {
    fn owner(&self) -> Uuid {
        match self {
            Self::Owner(u) => *u,
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Owner(u) => format!("owner:{u}"),
        }
    }
}

/// The owner by passkey auth CWT or, when `X-Auth-Token` is absent, by an
/// `agents:delegate` Bearer token whose assertion is at most an hour old.
async fn quarantine_caller(
    app_state: &AppState,
    headers: &HeaderMap,
) -> Result<QuarantineCaller, AgentError> {
    let owner = crate::agent::authenticate_operator(
        app_state,
        headers,
        AGENTS_DELEGATE_MAX_AUTH_AGE_SECONDS,
    )
    .await?;
    Ok(QuarantineCaller::Owner(owner.user_id))
}

/// POST /agents/workloads/:workload_id/quarantine — latch a quarantine.
/// Idempotent per incident; a different incident while latched is 409, so
/// the incident a recovery must cite stays unambiguous.
pub async fn quarantine_workload(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Path(workload_id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AgentError> {
    let caller = quarantine_caller(&app_state, &headers).await?;
    // Parsed from raw bytes: a Guardian signs the exact body.
    let req: QuarantineRequest = serde_json::from_slice(&body)
        .map_err(|e| AgentError::InvalidRequest(format!("quarantine body: {e}")))?;
    validate_label("incident", &req.incident, INCIDENT_MAX_LEN)?;
    if let Some(ev) = &req.evidence_ref {
        validate_label("evidence_ref", ev, EVIDENCE_REF_MAX_LEN)?;
    }
    let w = app_state
        .db_store
        .get_workload(&workload_id)
        .await
        .map_err(db_err)?
        .ok_or(AgentError::WorkloadNotFound)?;
    if w.owner != caller.owner() {
        return Err(AgentError::Forbidden(
            "workload belongs to a different owner".into(),
        ));
    }
    let now = Utc::now().timestamp();
    match app_state
        .db_store
        .quarantine_workload(
            &workload_id,
            &req.incident,
            req.evidence_ref.as_deref(),
            &caller.label(),
            now,
        )
        .await
        .map_err(db_err)?
    {
        QuarantineOutcome::Latched(q) => {
            warn!(
                "Workload {} quarantined by {} (incident {}, generation {})",
                q.workload_id,
                caller.label(),
                req.incident,
                q.generation
            );
            Ok(Json(WorkloadStatus::of(&q, now)))
        }
        QuarantineOutcome::AlreadyLatched(q) => Ok(Json(WorkloadStatus::of(&q, now))),
        QuarantineOutcome::OtherIncident(q) => Err(AgentError::Conflict(format!(
            "workload already quarantined under incident {}",
            q.incident.unwrap_or_default()
        ))),
        QuarantineOutcome::ClearedIncident(_) => Err(AgentError::Conflict(format!(
            "incident {} was already cleared by recovery; report a new incident",
            req.incident
        ))),
        QuarantineOutcome::Raced => Err(AgentError::Conflict(
            "workload changed concurrently; retry".into(),
        )),
        QuarantineOutcome::NotFound => Err(AgentError::WorkloadNotFound),
    }
}

#[derive(Debug, Deserialize)]
pub struct RecoverRequest {
    pub incident: String,
}

/// POST /agents/workloads/:workload_id/recover — the only way out of a
/// quarantine: the owner alone, with a passkey assertion from the last five
/// minutes, citing the incident being cleared. Unbinds the DID and revokes
/// its delegation, so nothing mints until the owner authorizes again.
/// Guardians, agents and services cannot call it.
pub async fn recover_workload(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Path(workload_id): Path<String>,
    Json(req): Json<RecoverRequest>,
) -> Result<impl IntoResponse, AgentError> {
    // Contract v1: any request carrying a Guardian signature is refused here,
    // verified or not, even alongside a valid owner credential.
    if headers.contains_key("X-Guardian-Signature") {
        return Err(AgentError::Forbidden(
            "a Guardian may only quarantine".into(),
        ));
    }
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
    validate_label("incident", &req.incident, INCIDENT_MAX_LEN)?;
    let db = &app_state.db_store;
    // The write is conditioned on everything decided here; on a conflict,
    // re-read and decide again (a concurrent recovery then reads as "not
    // quarantined", a DID authorized elsewhere as nothing to revoke).
    for _ in 0..3 {
        let w = db
            .get_workload(&workload_id)
            .await
            .map_err(db_err)?
            .ok_or(AgentError::WorkloadNotFound)?;
        if w.owner != owner.user_id {
            return Err(AgentError::Forbidden(
                "workload belongs to a different owner".into(),
            ));
        }
        if w.state != WorkloadState::Quarantined {
            return Err(AgentError::Conflict("workload is not quarantined".into()));
        }
        if w.incident.as_deref() != Some(req.incident.as_str()) {
            return Err(AgentError::Conflict(
                "incident does not match the quarantine being cleared".into(),
            ));
        }
        // Not a liveness question: an expired delegation naming the workload
        // is revoked too, so the old DID reads (and is refused) as revoked.
        let revoke_old = !w.current_did.is_empty()
            && db
                .get_agent_delegation(&w.current_did)
                .await
                .map_err(db_err)?
                .is_some_and(|d| {
                    d.revoked_at.is_none() && d.workload_id.as_deref() == Some(&w.workload_id)
                });
        match db
            .recover_workload(&w, &req.incident, revoke_old, now)
            .await
        {
            Ok(()) => {}
            Err(DynamoDBError::ConditionalConflict) => continue,
            Err(e) => return Err(db_err(e)),
        }
        let recovered = AgentWorkload {
            state: WorkloadState::Eligible,
            current_did: String::new(),
            generation: w.generation + 1,
            incident: None,
            evidence_ref: None,
            quarantined_by: None,
            quarantined_at: None,
            last_cleared_incident: Some(req.incident.clone()),
            updated_at: now,
            ..w
        };
        info!(
            "Workload {} recovered by owner {} (cleared incident {}, generation {})",
            recovered.workload_id, owner.user_id, req.incident, recovered.generation
        );
        return Ok(Json(WorkloadStatus::of(&recovered, now)));
    }
    Err(AgentError::Conflict(
        "workload changed concurrently; read its status and retry".into(),
    ))
}

/// GET /agents/workloads/:workload_id/status — what the KAS checks before
/// releasing a key to an agent token. Served from a strongly consistent read
/// of the latch with a 5-second lease, never from a cache.
pub async fn workload_status(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Path(workload_id): Path<String>,
) -> Result<Response, AgentError> {
    crate::entitlements::require_service_cwt_for(
        &app_state,
        &headers,
        &app_state.agent_status_client_ids,
    )
    .map_err(|e| match e {
        EntitlementError::MissingToken => AgentError::MissingToken,
        EntitlementError::InvalidToken => AgentError::InvalidToken,
        _ => AgentError::Forbidden("client may not read workload status".into()),
    })?;
    let w = app_state
        .db_store
        .get_workload(&workload_id)
        .await
        .map_err(db_err)?
        .ok_or(AgentError::WorkloadNotFound)?;
    let mut resp = Json(WorkloadStatus::of(&w, Utc::now().timestamp())).into_response();
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_workload_revokes_a_previous_did_that_became_live_again() {
        let Some(store) = crate::db::tests::local_store() else {
            return;
        };
        let store = std::sync::Arc::new(store);
        let app_state = crate::test_helpers::build_test_app_state_with_store(store.clone());
        let owner = Uuid::new_v4();
        let wid = crate::db::workload_id_for(&owner, "fleet");
        let x = format!("did:key:z6MkX{}", Uuid::new_v4().simple());
        let y = format!("did:key:z6MkY{}", Uuid::new_v4().simple());
        let for_did = |did: &str| {
            crate::db::workloads_test_support::delegation(did, owner, Some(wid.clone()))
        };
        bind_workload(&app_state, owner, "fleet", Some("kit-1"), &for_did(&x), 1)
            .await
            .unwrap();
        store.revoke_delegation(&x).await.unwrap();
        // X is re-authorized into the same workload: live again, same generation.
        let w = bind_workload(&app_state, owner, "fleet", None, &for_did(&x), 2)
            .await
            .unwrap();
        assert_eq!(w.generation, 1);
        let w = bind_workload(&app_state, owner, "fleet", None, &for_did(&y), 3)
            .await
            .unwrap();
        assert_eq!((w.current_did.as_str(), w.generation), (y.as_str(), 2));
        let old = store.get_agent_delegation(&x).await.unwrap().unwrap();
        assert!(old.revoked_at.is_some(), "the rebind must revoke X");
    }

    #[test]
    fn validate_label_bounds_and_control_characters() {
        assert!(validate_label("swarm", "kit-1", 128).is_ok());
        assert!(validate_label("swarm", &"k".repeat(128), 128).is_ok());
        assert!(matches!(
            validate_label("swarm", "", 128),
            Err(AgentError::InvalidRequest(_))
        ));
        assert!(validate_label("swarm", &"k".repeat(129), 128).is_err());
        assert!(validate_label("swarm", "kit\n1", 128).is_err());
    }

    #[test]
    fn only_the_dids_own_workload_or_its_owners_legacy_row_is_replaceable() {
        let (owner, stranger) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let wid = crate::db::workload_id_for(&owner, "fleet");
        let row = |workload_id: Option<String>, root: Uuid| {
            crate::db::workloads_test_support::delegation("did:key:z6MkA", root, workload_id)
        };
        assert!(replaceable(&row(Some(wid.clone()), owner), owner, &wid));
        assert!(!replaceable(
            &row(Some("wl-other".into()), owner),
            owner,
            &wid
        ));
        assert!(replaceable(&row(None, owner), owner, &wid));
        assert!(!replaceable(&row(None, stranger), owner, &wid));
    }
}
