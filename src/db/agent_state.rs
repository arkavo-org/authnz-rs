//! The trust state of an agent identity, stored on its `agent_delegations`
//! row (keyed by the agent DID). One identity is one key: a new key is a new
//! identity and starts `unassessed`.
//!
//! Every write here is a single conditional `UpdateItem` on that row, read
//! strongly consistent, so there is no cross-item transaction left.

use super::{AgentDelegation, DynamoDBError, DynamoDBStore};
use aws_sdk_dynamodb::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_dynamodb::types::{AttributeValue, ReturnValue};
use log::error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

pub(super) type Item = HashMap<String, AttributeValue>;

/// The stored state. `suspended` is never stored: it is `Eligible` whose
/// `appraised_until` has passed (see [`AgentTrust::effective`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentState {
    /// No current appraisal: a new identity before one, a recovered identity,
    /// and every row written before the state existed.
    #[default]
    Unassessed,
    Eligible,
    Quarantined,
}

impl AgentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unassessed => "unassessed",
            Self::Eligible => "eligible",
            Self::Quarantined => "quarantined",
        }
    }

    fn parse(s: &str) -> Result<Self, DynamoDBError> {
        match s {
            "unassessed" => Ok(Self::Unassessed),
            "eligible" => Ok(Self::Eligible),
            "quarantined" => Ok(Self::Quarantined),
            other => Err(DynamoDBError::Internal(format!(
                "unknown agent state {other:?}"
            ))),
        }
    }
}

/// What issuance and the status endpoint decide on at a given instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveState {
    Unassessed,
    Eligible,
    Suspended,
    Quarantined,
}

impl EffectiveState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unassessed => "unassessed",
            Self::Eligible => "eligible",
            Self::Suspended => "suspended",
            Self::Quarantined => "quarantined",
        }
    }
}

/// The trust half of an agent's row.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AgentTrust {
    pub state: AgentState,
    /// Server-assigned and monotonic: +1 on every change of the stored
    /// state, on a swarm change, on a revocation (and its cascade), and on
    /// an authorize that starts a new delegation over a revoked, expired or
    /// pre-v2 row; never on a renewal. Never reset. 0 only on a row written
    /// before the state existed (the attribute is absent).
    pub state_version: u64,
    /// Present once appraised; the identity is eligible while `now` is before it.
    pub appraised_until: Option<i64>,
    /// `owner:<uuid>` or `guardian:<guardian_id>`.
    pub appraised_by: Option<String>,
    /// The latched incident; present only while quarantined.
    pub incident: Option<String>,
    pub evidence_ref: Option<String>,
    /// `owner:<uuid>` or `guardian:<guardian_id>`.
    pub quarantined_by: Option<String>,
    pub quarantined_at: Option<i64>,
    /// The incident the most recent recovery cleared.
    pub last_cleared_incident: Option<String>,
    /// When the owner last recovered this identity. Never removed: the owner
    /// may not appraise a key that has been quarantined and recovered.
    pub recovered_at: Option<i64>,
}

impl AgentTrust {
    pub fn effective(&self, now: i64) -> EffectiveState {
        match self.state {
            AgentState::Quarantined => EffectiveState::Quarantined,
            AgentState::Unassessed => EffectiveState::Unassessed,
            AgentState::Eligible if self.appraised_until.is_some_and(|t| now < t) => {
                EffectiveState::Eligible
            }
            AgentState::Eligible => EffectiveState::Suspended,
        }
    }

    pub fn recovered(&self) -> bool {
        self.recovered_at.is_some()
    }
}

/// Result of a quarantine request against the stored latch.
#[derive(Debug, Clone, PartialEq)]
pub enum QuarantineOutcome {
    /// This call latched it; the row carries the new `state_version`.
    Latched(AgentDelegation),
    /// Already latched under the same incident: nothing changed.
    AlreadyLatched(AgentDelegation),
    /// Already latched under a different incident: nothing changed.
    OtherIncident(AgentDelegation),
    /// Not latched, and the incident is the one the last recovery cleared:
    /// refused so a replayed or stale report cannot re-latch it.
    ClearedIncident(AgentDelegation),
    /// The row now belongs to another owner: the key was reassigned after
    /// the caller's ownership read. Nothing changed.
    NotOwner,
    /// The condition failed but the re-read shows it unlatched and still the
    /// caller's: the version moved (a recovery, appraisal, authorize or
    /// revocation landed in between). The caller re-reads and retries.
    Raced,
    NotFound,
}

/// How an authorize writes the swarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwarmWrite<'a> {
    Set(&'a str),
    /// The request named no swarm and the row stays the same delegation.
    Keep,
    /// The request named no swarm and the row starts a new delegation.
    Clear,
}

/// What an authorize found for the DID, and so what its write requires the
/// row still to be. The version alone is not enough: a renewal keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeOver {
    /// No row: the write creates it.
    Absent,
    /// The authorizing owner's own live delegation, renewed or amended: the
    /// row must still be that owner's, unrevoked and unexpired.
    Live,
    /// A revoked or expired delegation of `owner` (the authorizing owner or
    /// another), replaced by a new one: the row must still be that owner's
    /// and still dead, so a renewal that landed after the read (keeping the
    /// version) is never taken over.
    Dead { owner: Uuid },
}

/// An authorize: the owner's bootstrap appraisal written over the row read
/// at `read_version` (0 when absent or pre-state).
#[derive(Debug, Clone, Copy)]
pub struct AuthorizeWrite<'a> {
    /// Delegation fields to write; its `swarm` and `trust` are ignored.
    pub delegation: &'a AgentDelegation,
    pub swarm: SwarmWrite<'a>,
    pub over: AuthorizeOver,
    pub read_version: u64,
    pub new_version: u64,
    pub appraised_until: i64,
    pub appraised_by: &'a str,
    pub now: i64,
}

pub(crate) fn s(v: &str) -> AttributeValue {
    AttributeValue::S(v.to_string())
}

pub(crate) fn n(v: impl ToString) -> AttributeValue {
    AttributeValue::N(v.to_string())
}

/// Map a DynamoDB call failure onto the store's error type. A failed
/// condition is a `ConditionalConflict` the caller resolves by re-reading.
pub(super) fn classify<E, R>(err: SdkError<E, R>, table: &str) -> DynamoDBError
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
    R: std::fmt::Debug,
{
    let code = match &err {
        SdkError::ServiceError(se) => se.err().code().map(str::to_owned),
        _ => None,
    };
    match code.as_deref() {
        Some("ConditionalCheckFailedException") => DynamoDBError::ConditionalConflict,
        Some("ResourceNotFoundException") => DynamoDBError::TableNotExists(table.to_string()),
        _ => {
            error!("DynamoDB call on {table} failed: {err:?}");
            DynamoDBError::SdkError(err.to_string())
        }
    }
}

/// The condition that the row still carries the version the caller read.
/// Version 0 is a row without the attribute (absent or pre-state).
fn version_condition(read_version: u64) -> &'static str {
    if read_version == 0 {
        "attribute_not_exists(state_version)"
    } else {
        "state_version = :rv"
    }
}

pub(super) fn trust_from_item(item: &Item) -> Result<AgentTrust, DynamoDBError> {
    let text = |k: &str| item.get(k).and_then(|v| v.as_s().ok()).cloned();
    let int = |k: &str| {
        item.get(k)
            .and_then(|v| v.as_n().ok())
            .and_then(|v| v.parse::<i64>().ok())
    };
    Ok(AgentTrust {
        state: match text("state") {
            Some(st) => AgentState::parse(&st)?,
            None => AgentState::Unassessed,
        },
        state_version: match item.get("state_version") {
            None => 0,
            Some(v) => v
                .as_n()
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or_else(|| DynamoDBError::Internal("state_version is not a number".into()))?,
        },
        appraised_until: int("appraised_until"),
        appraised_by: text("appraised_by"),
        incident: text("incident"),
        evidence_ref: text("evidence_ref"),
        quarantined_by: text("quarantined_by"),
        quarantined_at: int("quarantined_at"),
        last_cleared_incident: text("last_cleared_incident"),
        recovered_at: int("recovered_at"),
    })
}

/// The stored attributes of `t` (absent fields omitted, never empty strings).
#[cfg(test)]
fn trust_item(t: &AgentTrust) -> Item {
    let mut item = Item::new();
    if t.state_version > 0 {
        item.insert("state".into(), s(t.state.as_str()));
        item.insert("state_version".into(), n(t.state_version));
    }
    for (key, value) in [
        ("appraised_by", &t.appraised_by),
        ("incident", &t.incident),
        ("evidence_ref", &t.evidence_ref),
        ("quarantined_by", &t.quarantined_by),
        ("last_cleared_incident", &t.last_cleared_incident),
    ] {
        if let Some(v) = value {
            item.insert(key.into(), s(v));
        }
    }
    for (key, value) in [
        ("appraised_until", t.appraised_until),
        ("quarantined_at", t.quarantined_at),
        ("recovered_at", t.recovered_at),
    ] {
        if let Some(v) = value {
            item.insert(key.into(), n(v));
        }
    }
    item
}

impl DynamoDBStore {
    /// Write an authorize: the delegation fields, the swarm, and the owner's
    /// appraisal (`eligible` until `appraised_until`), conditional on the row
    /// still carrying `read_version`, not being quarantined, and still being
    /// what the caller found (`w.over`, judged at `w.now`). Clears
    /// `revoked_at`, a pending challenge and the pre-v2 `workload_id`.
    /// `ConditionalConflict` when the row changed since it was read.
    pub async fn authorize_agent(&self, w: AuthorizeWrite<'_>) -> Result<(), DynamoDBError> {
        let d = w.delegation;
        let list =
            |v: &[String]| AttributeValue::L(v.iter().cloned().map(AttributeValue::S).collect());
        let mut set = vec![
            "delegator_type = :dt",
            "delegator_id = :di",
            "entitlements = :ents",
            "#name = :name",
            "#depth = :depth",
            "root_user_id = :root",
            "#chain = :chain",
            "created_at = :created",
            "short_lived = :sl",
            "#st = :eligible",
            "state_version = :nv",
            "appraised_until = :au",
            "appraised_by = :ab",
            "updated_at = :now",
        ];
        let mut remove = vec![
            "revoked_at",
            "workload_id",
            "challenge",
            "challenge_nonce",
            "challenge_issued_at",
        ];
        let mut req = self
            .client
            .update_item()
            .table_name(&self.agent_delegations_table)
            .key("agent_did", s(&d.agent_did))
            .expression_attribute_names("#name", "name")
            .expression_attribute_names("#chain", "chain")
            .expression_attribute_names("#depth", "depth")
            .expression_attribute_names("#st", "state")
            .expression_attribute_values(":dt", s(&d.delegator_type))
            .expression_attribute_values(":di", s(&d.delegator_id))
            .expression_attribute_values(":ents", list(&d.entitlements))
            .expression_attribute_values(":name", s(&d.name))
            .expression_attribute_values(":depth", n(d.depth))
            .expression_attribute_values(":root", s(&d.root_user_id.to_string()))
            .expression_attribute_values(":chain", list(&d.chain))
            .expression_attribute_values(":created", n(d.created_at))
            .expression_attribute_values(":sl", AttributeValue::Bool(d.short_lived))
            .expression_attribute_values(":eligible", s(AgentState::Eligible.as_str()))
            .expression_attribute_values(":nv", n(w.new_version))
            .expression_attribute_values(":au", n(w.appraised_until))
            .expression_attribute_values(":ab", s(w.appraised_by))
            .expression_attribute_values(":now", n(w.now));
        match &d.delegator_username {
            Some(u) => {
                set.push("delegator_username = :du");
                req = req.expression_attribute_values(":du", s(u));
            }
            None => remove.push("delegator_username"),
        }
        match d.expires_at {
            Some(e) => {
                set.push("expires_at = :exp");
                req = req.expression_attribute_values(":exp", n(e));
            }
            None => remove.push("expires_at"),
        }
        match w.swarm {
            SwarmWrite::Set(swarm) => {
                set.push("swarm = :swarm");
                req = req.expression_attribute_values(":swarm", s(swarm));
            }
            SwarmWrite::Keep => {}
            SwarmWrite::Clear => remove.push("swarm"),
        }
        if w.read_version > 0 {
            req = req.expression_attribute_values(":rv", n(w.read_version));
        }
        let unlatched = "(attribute_not_exists(#st) OR #st <> :q)";
        if w.over != AuthorizeOver::Absent {
            req = req.expression_attribute_values(":q", s(AgentState::Quarantined.as_str()));
        }
        // Liveness as `agent::is_live` judges it: live through `expires_at`.
        let condition = match w.over {
            AuthorizeOver::Absent => "attribute_not_exists(agent_did)".to_string(),
            // A renewal (which may keep the version) lands only on the
            // caller's row while it is still live: never on one revoked
            // (by any path) or expired since the read.
            AuthorizeOver::Live => format!(
                "{} AND {unlatched} AND root_user_id = :root \
                 AND attribute_not_exists(revoked_at) \
                 AND (attribute_not_exists(expires_at) OR expires_at >= :now)",
                version_condition(w.read_version)
            ),
            // A new delegation replaces only the dead row it read. Renewals
            // keep `state_version`, so without this a renewal landing after
            // the read would be taken over with its live identity.
            AuthorizeOver::Dead { owner } => {
                req = req.expression_attribute_values(":old", s(&owner.to_string()));
                format!(
                    "{} AND {unlatched} AND root_user_id = :old \
                     AND (attribute_exists(revoked_at) OR expires_at < :now)",
                    version_condition(w.read_version)
                )
            }
        };
        req.update_expression(format!(
            "SET {} REMOVE {}",
            set.join(", "),
            remove.join(", ")
        ))
        .condition_expression(condition)
        .send()
        .await
        .map_err(|e| classify(e, &self.agent_delegations_table))?;
        Ok(())
    }

    /// Latch a quarantine: any unlatched state → `quarantined`,
    /// `state_version + 1`, in one conditional update, conditioned on the
    /// row still belonging to `owner` at `read_version` (the caller's
    /// ownership read), so a key reassigned in between is never latched on
    /// its new owner's behalf. A latched row is never re-latched; the
    /// re-read tells an idempotent repeat from a second incident, a changed
    /// owner and a moved version.
    #[allow(clippy::too_many_arguments)]
    pub async fn quarantine_agent(
        &self,
        agent_did: &str,
        owner: Uuid,
        read_version: u64,
        incident: &str,
        evidence_ref: Option<&str>,
        by: &str,
        now: i64,
    ) -> Result<QuarantineOutcome, DynamoDBError> {
        let set = "SET #st = :q, incident = :inc, quarantined_by = :by, \
                   quarantined_at = :now, updated_at = :now, \
                   state_version = if_not_exists(state_version, :zero) + :one";
        let mut req = self
            .client
            .update_item()
            .table_name(&self.agent_delegations_table)
            .key("agent_did", s(agent_did))
            .condition_expression(format!(
                "attribute_exists(agent_did) AND root_user_id = :owner AND {} \
                 AND (attribute_not_exists(#st) OR #st <> :q) \
                 AND (attribute_not_exists(last_cleared_incident) OR last_cleared_incident <> :inc)",
                version_condition(read_version)
            ))
            .expression_attribute_names("#st", "state")
            .expression_attribute_values(":owner", s(&owner.to_string()))
            .expression_attribute_values(":q", s(AgentState::Quarantined.as_str()))
            .expression_attribute_values(":inc", s(incident))
            .expression_attribute_values(":by", s(by))
            .expression_attribute_values(":now", n(now))
            .expression_attribute_values(":zero", n(0))
            .expression_attribute_values(":one", n(1))
            .return_values(ReturnValue::AllNew);
        if read_version > 0 {
            req = req.expression_attribute_values(":rv", n(read_version));
        }
        let expression = match evidence_ref {
            Some(e) => {
                req = req.expression_attribute_values(":ev", s(e));
                format!("{set}, evidence_ref = :ev")
            }
            None => format!("{set} REMOVE evidence_ref"),
        };
        match req.update_expression(expression).send().await {
            Ok(out) => {
                let item = out.attributes.ok_or_else(|| {
                    DynamoDBError::Internal("quarantine returned no attributes".into())
                })?;
                Ok(QuarantineOutcome::Latched(
                    DynamoDBStore::item_to_agent_delegation(&item)?,
                ))
            }
            Err(err) => match classify(err, &self.agent_delegations_table) {
                DynamoDBError::ConditionalConflict => {
                    Ok(match self.get_agent_delegation(agent_did).await? {
                        None => QuarantineOutcome::NotFound,
                        Some(d) if d.root_user_id != owner => QuarantineOutcome::NotOwner,
                        Some(d) if d.trust.state != AgentState::Quarantined => {
                            if d.trust.last_cleared_incident.as_deref() == Some(incident) {
                                QuarantineOutcome::ClearedIncident(d)
                            } else {
                                QuarantineOutcome::Raced
                            }
                        }
                        Some(d) if d.trust.incident.as_deref() == Some(incident) => {
                            QuarantineOutcome::AlreadyLatched(d)
                        }
                        Some(d) => QuarantineOutcome::OtherIncident(d),
                    })
                }
                other => Err(other),
            },
        }
    }

    /// Clear a quarantine, conditional on it still being latched under
    /// `incident` at the version the caller read: `unassessed`,
    /// `state_version + 1`, the incident recorded as cleared, `recovered_at`
    /// set, the appraisal removed. The delegation itself stays; only a
    /// Guardian appraisal makes the identity eligible again.
    pub async fn recover_agent(
        &self,
        agent_did: &str,
        incident: &str,
        read_version: u64,
        now: i64,
    ) -> Result<AgentDelegation, DynamoDBError> {
        let out = self
            .client
            .update_item()
            .table_name(&self.agent_delegations_table)
            .key("agent_did", s(agent_did))
            .condition_expression("#st = :q AND incident = :inc AND state_version = :rv")
            .update_expression(
                "SET #st = :unassessed, last_cleared_incident = :inc, recovered_at = :now, \
                 updated_at = :now, state_version = state_version + :one \
                 REMOVE incident, evidence_ref, quarantined_by, quarantined_at, \
                 appraised_until, appraised_by",
            )
            .expression_attribute_names("#st", "state")
            .expression_attribute_values(":q", s(AgentState::Quarantined.as_str()))
            .expression_attribute_values(":unassessed", s(AgentState::Unassessed.as_str()))
            .expression_attribute_values(":inc", s(incident))
            .expression_attribute_values(":rv", n(read_version))
            .expression_attribute_values(":now", n(now))
            .expression_attribute_values(":one", n(1))
            .return_values(ReturnValue::AllNew)
            .send()
            .await
            .map_err(|e| classify(e, &self.agent_delegations_table))?;
        let item = out
            .attributes
            .ok_or_else(|| DynamoDBError::Internal("recover returned no attributes".into()))?;
        DynamoDBStore::item_to_agent_delegation(&item)
    }

    /// Record an appraisal: `eligible` until `appraised_until`, conditional
    /// on the row still carrying `read_version`, not being quarantined, and
    /// its delegation being live (not revoked, not past `expires_at`, as
    /// `agent::is_live` judges it at `now`).
    /// `new_version` is `read_version + 1` when the stored state changes
    /// (unassessed → eligible) and `read_version` for a renewal, so renewing
    /// never invalidates the tokens the identity already holds.
    #[allow(clippy::too_many_arguments)]
    pub async fn appraise_agent(
        &self,
        agent_did: &str,
        read_version: u64,
        new_version: u64,
        appraised_until: i64,
        by: &str,
        evidence_ref: Option<&str>,
        now: i64,
    ) -> Result<AgentDelegation, DynamoDBError> {
        let set = "SET #st = :eligible, appraised_until = :au, appraised_by = :by, \
                   updated_at = :now, state_version = :nv";
        let mut req = self
            .client
            .update_item()
            .table_name(&self.agent_delegations_table)
            .key("agent_did", s(agent_did))
            .condition_expression(format!(
                "attribute_exists(agent_did) AND {} AND (attribute_not_exists(#st) OR #st <> :q) \
                 AND attribute_not_exists(revoked_at) \
                 AND (attribute_not_exists(expires_at) OR expires_at >= :now)",
                version_condition(read_version)
            ))
            .expression_attribute_names("#st", "state")
            .expression_attribute_values(":eligible", s(AgentState::Eligible.as_str()))
            .expression_attribute_values(":q", s(AgentState::Quarantined.as_str()))
            .expression_attribute_values(":au", n(appraised_until))
            .expression_attribute_values(":by", s(by))
            .expression_attribute_values(":now", n(now))
            .expression_attribute_values(":nv", n(new_version))
            .return_values(ReturnValue::AllNew);
        if read_version > 0 {
            req = req.expression_attribute_values(":rv", n(read_version));
        }
        let expression = match evidence_ref {
            Some(e) => {
                req = req.expression_attribute_values(":ev", s(e));
                format!("{set}, appraisal_evidence_ref = :ev")
            }
            None => format!("{set} REMOVE appraisal_evidence_ref"),
        };
        let out = req
            .update_expression(expression)
            .send()
            .await
            .map_err(|e| classify(e, &self.agent_delegations_table))?;
        let item = out
            .attributes
            .ok_or_else(|| DynamoDBError::Internal("appraisal returned no attributes".into()))?;
        DynamoDBStore::item_to_agent_delegation(&item)
    }

    /// Revoke the delegation (`DELETE /agents/delegations/{did}`):
    /// `revoked_at` set (a repeat keeps the first time), `state_version + 1`,
    /// conditional on the row still belonging to `owner` at `read_version`.
    /// Every write that sets `revoked_at` moves the version, so a renewal or
    /// appraisal that read the live row fails its own version condition
    /// instead of clearing the revocation and keeping the version its tokens
    /// carry. `ConditionalConflict` when the row changed or changed hands.
    pub async fn revoke_agent(
        &self,
        agent_did: &str,
        owner: Uuid,
        read_version: u64,
        now: i64,
    ) -> Result<AgentDelegation, DynamoDBError> {
        let mut req = self
            .client
            .update_item()
            .table_name(&self.agent_delegations_table)
            .key("agent_did", s(agent_did))
            .condition_expression(format!(
                "attribute_exists(agent_did) AND root_user_id = :owner AND {}",
                version_condition(read_version)
            ))
            .update_expression(
                "SET revoked_at = if_not_exists(revoked_at, :now), updated_at = :now, \
                 state_version = if_not_exists(state_version, :zero) + :one",
            )
            .expression_attribute_values(":owner", s(&owner.to_string()))
            .expression_attribute_values(":now", n(now))
            .expression_attribute_values(":zero", n(0))
            .expression_attribute_values(":one", n(1))
            .return_values(ReturnValue::AllNew);
        if read_version > 0 {
            req = req.expression_attribute_values(":rv", n(read_version));
        }
        let out = req
            .send()
            .await
            .map_err(|e| classify(e, &self.agent_delegations_table))?;
        let item = out
            .attributes
            .ok_or_else(|| DynamoDBError::Internal("revoke returned no attributes".into()))?;
        DynamoDBStore::item_to_agent_delegation(&item)
    }

    /// Plant a row as given, unconditionally: tests use it to write rows
    /// (pre-state, quarantined, expired) that the handlers never would.
    #[cfg(test)]
    pub async fn put_agent_row(&self, d: &AgentDelegation) -> Result<(), DynamoDBError> {
        let list =
            |v: &[String]| AttributeValue::L(v.iter().cloned().map(AttributeValue::S).collect());
        let mut item = trust_item(&d.trust);
        item.insert("agent_did".into(), s(&d.agent_did));
        item.insert("delegator_type".into(), s(&d.delegator_type));
        item.insert("delegator_id".into(), s(&d.delegator_id));
        item.insert("entitlements".into(), list(&d.entitlements));
        item.insert("name".into(), s(&d.name));
        item.insert("depth".into(), n(d.depth));
        item.insert("root_user_id".into(), s(&d.root_user_id.to_string()));
        item.insert("chain".into(), list(&d.chain));
        item.insert("created_at".into(), n(d.created_at));
        item.insert("short_lived".into(), AttributeValue::Bool(d.short_lived));
        if let Some(u) = &d.delegator_username {
            item.insert("delegator_username".into(), s(u));
        }
        if let Some(e) = d.expires_at {
            item.insert("expires_at".into(), n(e));
        }
        if let Some(r) = d.revoked_at {
            item.insert("revoked_at".into(), n(r));
        }
        if !d.swarm.is_empty() {
            item.insert("swarm".into(), s(&d.swarm));
        }
        self.client
            .put_item()
            .table_name(&self.agent_delegations_table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| classify(e, &self.agent_delegations_table))?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::tests::local_store;
    use uuid::Uuid;

    /// A live depth-0 delegation of `did` owned by `owner`, pre-state
    /// (unassessed, version 0) unless the caller sets `trust`.
    pub(crate) fn delegation(did: &str, owner: Uuid) -> AgentDelegation {
        let now = chrono::Utc::now().timestamp();
        AgentDelegation {
            agent_did: did.into(),
            delegator_type: "human".into(),
            delegator_id: owner.to_string(),
            delegator_username: None,
            entitlements: vec!["https://arkavo.ai/attr/action/value/read".into()],
            name: "agent".into(),
            depth: 0,
            root_user_id: owner,
            chain: vec![],
            created_at: now,
            expires_at: Some(now + 86_400),
            revoked_at: None,
            short_lived: false,
            swarm: String::new(),
            trust: AgentTrust::default(),
        }
    }

    pub(crate) fn unique_did(tag: &str) -> String {
        format!("did:key:z6Mk{tag}{}", Uuid::new_v4().simple())
    }

    /// An authorize at the fixed clock `now = 1_790_000_000`, before the
    /// `expires_at` [`delegation`] gives a row.
    fn write<'a>(
        d: &'a AgentDelegation,
        read: u64,
        new: u64,
        swarm: SwarmWrite<'a>,
        over: AuthorizeOver,
    ) -> AuthorizeWrite<'a> {
        AuthorizeWrite {
            delegation: d,
            swarm,
            over,
            read_version: read,
            new_version: new,
            appraised_until: 1_790_043_200,
            appraised_by: "owner:x",
            now: 1_790_000_000,
        }
    }

    /// A new delegation over `d`'s owner's dead row.
    fn dead(d: &AgentDelegation) -> AuthorizeOver {
        AuthorizeOver::Dead {
            owner: d.root_user_id,
        }
    }

    fn conflict<T>(r: Result<T, DynamoDBError>) -> bool {
        matches!(r, Err(DynamoDBError::ConditionalConflict))
    }

    #[test]
    fn effective_state_derives_suspended_from_an_expired_appraisal() {
        let mut t = AgentTrust::default();
        assert_eq!(t.effective(100), EffectiveState::Unassessed);
        t.state = AgentState::Eligible;
        assert_eq!(
            t.effective(100),
            EffectiveState::Suspended,
            "never appraised"
        );
        t.appraised_until = Some(101);
        assert_eq!(t.effective(100), EffectiveState::Eligible);
        assert_eq!(
            t.effective(101),
            EffectiveState::Suspended,
            "until is exclusive"
        );
        t.state = AgentState::Quarantined;
        assert_eq!(t.effective(100), EffectiveState::Quarantined);
    }

    #[test]
    fn trust_round_trips_and_a_pre_state_row_reads_unassessed_at_version_zero() {
        let t = AgentTrust {
            state: AgentState::Quarantined,
            state_version: 7,
            appraised_until: Some(1_790_000_900),
            appraised_by: Some("guardian:g".into()),
            incident: Some("inc-1".into()),
            evidence_ref: Some("s3://e/1".into()),
            quarantined_by: Some("owner:o".into()),
            quarantined_at: Some(1_790_000_100),
            last_cleared_incident: Some("inc-0".into()),
            recovered_at: Some(1_789_000_000),
        };
        assert_eq!(trust_from_item(&trust_item(&t)).unwrap(), t);
        assert_eq!(
            trust_from_item(&Item::new()).unwrap(),
            AgentTrust::default()
        );
        let mut bad = Item::new();
        bad.insert("state".into(), s("revoked"));
        assert!(
            trust_from_item(&bad).is_err(),
            "an unknown state never parses"
        );
    }

    #[tokio::test]
    async fn authorize_creates_a_row_eligible_at_version_one() {
        let Some(store) = local_store() else { return };
        let owner = Uuid::new_v4();
        let did = unique_did("A");
        let d = delegation(&did, owner);
        store
            .authorize_agent(write(
                &d,
                0,
                1,
                SwarmWrite::Set("kit-1"),
                AuthorizeOver::Absent,
            ))
            .await
            .unwrap();
        let got = store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!(got.trust.state, AgentState::Eligible);
        assert_eq!(got.trust.state_version, 1);
        assert_eq!(got.trust.appraised_until, Some(1_790_043_200));
        assert_eq!(got.trust.appraised_by.as_deref(), Some("owner:x"));
        assert_eq!(got.swarm, "kit-1");
        assert_eq!(got.root_user_id, owner);
        assert!(
            conflict(
                store
                    .authorize_agent(write(&d, 0, 1, SwarmWrite::Keep, AuthorizeOver::Absent))
                    .await
            ),
            "a second create at version 0 loses"
        );
    }

    #[tokio::test]
    async fn authorize_keeps_or_clears_the_swarm_and_clears_revocation_and_workload_id() {
        let Some(store) = local_store() else { return };
        let did = unique_did("S");
        let d = delegation(&did, Uuid::new_v4());
        store
            .authorize_agent(write(
                &d,
                0,
                1,
                SwarmWrite::Set("kit-1"),
                AuthorizeOver::Absent,
            ))
            .await
            .unwrap();
        store
            .authorize_agent(write(&d, 1, 1, SwarmWrite::Keep, AuthorizeOver::Live))
            .await
            .unwrap();
        let got = store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!(got.swarm, "kit-1");
        // A pre-v2 attribute and a revocation are cleared by the next authorize.
        store
            .client
            .update_item()
            .table_name(&store.agent_delegations_table)
            .key("agent_did", s(&did))
            .update_expression("SET workload_id = :w, revoked_at = :r")
            .expression_attribute_values(":w", s("wl-00112233445566778899aabbccddeeff"))
            .expression_attribute_values(":r", n(1))
            .send()
            .await
            .unwrap();
        store
            .authorize_agent(write(&d, 1, 2, SwarmWrite::Clear, dead(&d)))
            .await
            .unwrap();
        let got = store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!(
            (got.swarm.as_str(), got.revoked_at, got.trust.state_version),
            ("", None, 2)
        );
        let raw = store
            .client
            .get_item()
            .table_name(&store.agent_delegations_table)
            .key("agent_did", s(&did))
            .consistent_read(true)
            .send()
            .await
            .unwrap()
            .item
            .unwrap();
        assert!(!raw.contains_key("workload_id"));
    }

    #[tokio::test]
    async fn authorize_upgrades_a_pre_state_row_and_refuses_a_stale_or_quarantined_one() {
        let Some(store) = local_store() else { return };
        let owner = Uuid::new_v4();
        let did = unique_did("L");
        let legacy = delegation(&did, owner);
        store.put_agent_row(&legacy).await.unwrap();
        let read = store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!(
            (read.trust.state, read.trust.state_version),
            (AgentState::Unassessed, 0)
        );
        store
            .authorize_agent(write(&legacy, 0, 1, SwarmWrite::Keep, AuthorizeOver::Live))
            .await
            .unwrap();
        assert!(
            conflict(
                store
                    .authorize_agent(write(&legacy, 0, 1, SwarmWrite::Keep, AuthorizeOver::Live))
                    .await
            ),
            "stale read version"
        );
        let q = AgentDelegation {
            trust: AgentTrust {
                state: AgentState::Quarantined,
                state_version: 4,
                incident: Some("inc-1".into()),
                ..AgentTrust::default()
            },
            ..delegation(&unique_did("Q"), owner)
        };
        store.put_agent_row(&q).await.unwrap();
        assert!(
            conflict(
                store
                    .authorize_agent(write(&q, 4, 4, SwarmWrite::Keep, AuthorizeOver::Live))
                    .await
            ),
            "a quarantined row is never overwritten, even at the version read"
        );
    }

    #[tokio::test]
    async fn quarantine_latches_once_per_incident_and_bumps_the_version() {
        let Some(store) = local_store() else { return };
        let did = unique_did("Q");
        let owner = Uuid::new_v4();
        let d = delegation(&did, owner);
        store
            .authorize_agent(write(&d, 0, 1, SwarmWrite::Keep, AuthorizeOver::Absent))
            .await
            .unwrap();
        let QuarantineOutcome::Latched(q) = store
            .quarantine_agent(&did, owner, 1, "inc-1", Some("s3://e"), "owner:o", 5)
            .await
            .unwrap()
        else {
            panic!("expected a latch")
        };
        assert_eq!(
            (
                q.trust.state,
                q.trust.state_version,
                q.trust.incident.as_deref()
            ),
            (AgentState::Quarantined, 2, Some("inc-1"))
        );
        assert!(matches!(
            store.quarantine_agent(&did, owner, 2, "inc-1", None, "owner:o", 6).await.unwrap(),
            QuarantineOutcome::AlreadyLatched(d) if d.trust.state_version == 2
        ));
        assert!(matches!(
            store
                .quarantine_agent(&did, owner, 2, "inc-2", None, "owner:o", 6)
                .await
                .unwrap(),
            QuarantineOutcome::OtherIncident(_)
        ));
        assert_eq!(
            store
                .quarantine_agent(&unique_did("none"), owner, 0, "inc-1", None, "owner:o", 6)
                .await
                .unwrap(),
            QuarantineOutcome::NotFound
        );
        // A pre-state row (no state_version attribute) latches at version 1.
        let legacy = unique_did("LQ");
        let legacy_owner = Uuid::new_v4();
        store
            .put_agent_row(&delegation(&legacy, legacy_owner))
            .await
            .unwrap();
        assert!(matches!(
            store.quarantine_agent(&legacy, legacy_owner, 0, "inc-1", None, "owner:o", 6).await.unwrap(),
            QuarantineOutcome::Latched(d) if d.trust.state_version == 1
        ));
    }

    #[tokio::test]
    async fn recovery_leaves_the_identity_unassessed_and_a_cleared_incident_cannot_relatch() {
        let Some(store) = local_store() else { return };
        let did = unique_did("R");
        let owner = Uuid::new_v4();
        let d = delegation(&did, owner);
        store
            .authorize_agent(write(&d, 0, 1, SwarmWrite::Keep, AuthorizeOver::Absent))
            .await
            .unwrap();
        store
            .quarantine_agent(&did, owner, 1, "inc-1", Some("s3://e"), "owner:o", 5)
            .await
            .unwrap();
        assert!(
            conflict(store.recover_agent(&did, "inc-9", 2, 6).await),
            "wrong incident"
        );
        assert!(
            conflict(store.recover_agent(&did, "inc-1", 1, 6).await),
            "stale version"
        );
        let r = store.recover_agent(&did, "inc-1", 2, 6).await.unwrap();
        assert_eq!(r.trust.state, AgentState::Unassessed);
        assert_eq!(r.trust.state_version, 3);
        assert_eq!(r.trust.recovered_at, Some(6));
        assert_eq!(r.trust.last_cleared_incident.as_deref(), Some("inc-1"));
        assert_eq!(
            (
                r.trust.incident,
                r.trust.evidence_ref,
                r.trust.appraised_until,
                r.trust.appraised_by
            ),
            (None, None, None, None)
        );
        assert!(r.revoked_at.is_none(), "recovery keeps the delegation");
        assert!(matches!(
            store
                .quarantine_agent(&did, owner, 3, "inc-1", None, "owner:o", 7)
                .await
                .unwrap(),
            QuarantineOutcome::ClearedIncident(_)
        ));
        assert!(matches!(
            store.quarantine_agent(&did, owner, 3, "inc-2", None, "owner:o", 7).await.unwrap(),
            QuarantineOutcome::Latched(d) if d.trust.state_version == 4
        ));
    }

    #[tokio::test]
    async fn appraisal_bumps_only_on_a_state_change_and_never_clears_quarantine() {
        let Some(store) = local_store() else { return };
        let did = unique_did("P");
        let owner = Uuid::new_v4();
        store.put_agent_row(&delegation(&did, owner)).await.unwrap(); // unassessed, version 0
        let a = store
            .appraise_agent(&did, 0, 1, 1_000, "guardian:g", Some("ev-1"), 10)
            .await
            .unwrap();
        assert_eq!(
            (
                a.trust.state,
                a.trust.state_version,
                a.trust.appraised_until
            ),
            (AgentState::Eligible, 1, Some(1_000))
        );
        // Renewal: eligible → eligible keeps the version.
        let b = store
            .appraise_agent(&did, 1, 1, 2_000, "guardian:g", None, 20)
            .await
            .unwrap();
        assert_eq!(
            (b.trust.state_version, b.trust.appraised_until),
            (1, Some(2_000))
        );
        store
            .quarantine_agent(&did, owner, 1, "inc-1", None, "guardian:g", 30)
            .await
            .unwrap();
        assert!(
            conflict(
                store
                    .appraise_agent(&did, 2, 2, 3_000, "guardian:g", None, 40)
                    .await
            ),
            "an appraisal never clears quarantine"
        );
        assert!(
            conflict(
                store
                    .appraise_agent(&unique_did("none"), 0, 1, 3_000, "guardian:g", None, 40)
                    .await
            ),
            "an appraisal never creates a row"
        );
    }

    #[tokio::test]
    async fn a_revocation_bumps_the_version_so_a_stale_renewal_or_appraisal_cannot_clear_it() {
        let Some(store) = local_store() else { return };
        let owner = Uuid::new_v4();
        let did = unique_did("V");
        let d = delegation(&did, owner);
        store
            .authorize_agent(write(&d, 0, 1, SwarmWrite::Keep, AuthorizeOver::Absent))
            .await
            .unwrap();
        // A renewal and an appraisal both read the live row at version 1 ...
        let read = store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!((read.trust.state_version, read.revoked_at), (1, None));
        // ... then the owner revokes it.
        let revoked = store.revoke_agent(&did, owner, 1, 50).await.unwrap();
        assert_eq!(
            (revoked.revoked_at, revoked.trust.state_version),
            (Some(50), 2)
        );
        assert!(
            conflict(
                store
                    .authorize_agent(write(&d, 1, 1, SwarmWrite::Keep, AuthorizeOver::Live))
                    .await
            ),
            "the stale renewal cannot clear the revocation and keep version 1"
        );
        assert!(
            conflict(
                store
                    .appraise_agent(&did, 1, 1, 2_000, "guardian:g", None, 60)
                    .await
            ),
            "nor can the stale appraisal"
        );
        assert!(
            conflict(
                store
                    .appraise_agent(&did, 2, 2, 2_000, "guardian:g", None, 60)
                    .await
            ),
            "an appraisal never lands on a revoked delegation"
        );
        let got = store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!((got.revoked_at, got.trust.state_version), (Some(50), 2));
        // Read again, the owner's authorize starts a new delegation.
        store
            .authorize_agent(write(&d, 2, 3, SwarmWrite::Keep, dead(&d)))
            .await
            .unwrap();
        let got = store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!((got.revoked_at, got.trust.state_version), (None, 3));
        // A repeated revocation keeps the first timestamp and still moves the version.
        store.revoke_agent(&did, owner, 3, 70).await.unwrap();
        let again = store.revoke_agent(&did, owner, 4, 80).await.unwrap();
        assert_eq!((again.revoked_at, again.trust.state_version), (Some(70), 5));

        // An expired delegation is not appraised either (live through
        // expires_at itself, as `agent::is_live` says).
        let e = AgentDelegation {
            expires_at: Some(100),
            trust: AgentTrust {
                state: AgentState::Eligible,
                state_version: 1,
                appraised_until: Some(1_000),
                ..AgentTrust::default()
            },
            ..delegation(&unique_did("E"), owner)
        };
        store.put_agent_row(&e).await.unwrap();
        assert!(conflict(
            store
                .appraise_agent(&e.agent_did, 1, 1, 2_000, "guardian:g", None, 101)
                .await
        ));
        assert!(
            store
                .appraise_agent(&e.agent_did, 1, 1, 2_000, "guardian:g", None, 100)
                .await
                .is_ok()
        );

        // A row revoked without a version bump (planted: no write path does
        // this) is still never revived at the version read.
        let planted = AgentDelegation {
            revoked_at: Some(40),
            trust: AgentTrust {
                state: AgentState::Eligible,
                state_version: 1,
                ..AgentTrust::default()
            },
            ..delegation(&unique_did("G"), owner)
        };
        store.put_agent_row(&planted).await.unwrap();
        assert!(conflict(
            store
                .authorize_agent(write(&planted, 1, 1, SwarmWrite::Keep, AuthorizeOver::Live))
                .await
        ));
        store
            .authorize_agent(write(&planted, 1, 2, SwarmWrite::Keep, dead(&planted)))
            .await
            .unwrap();
    }

    fn eligible_at(version: u64) -> AgentTrust {
        AgentTrust {
            state: AgentState::Eligible,
            state_version: version,
            appraised_until: Some(1_790_043_200),
            ..AgentTrust::default()
        }
    }

    /// Owner A reads its eligible row just before it expires and plans a
    /// renewal, which keeps the version; after the expiry owner B reads the
    /// same version and plans a takeover. A's renewal lands first: B's write
    /// must not take over the identity A has just renewed.
    #[tokio::test]
    async fn a_takeover_never_lands_on_a_row_renewed_after_its_read() {
        let Some(store) = local_store() else { return };
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let did = unique_did("T");
        let t = 1_790_000_000;
        let expiring = AgentDelegation {
            expires_at: Some(t),
            trust: eligible_at(7),
            ..delegation(&did, a)
        };
        store.put_agent_row(&expiring).await.unwrap();
        let renewed = AgentDelegation {
            expires_at: Some(t - 1 + 30 * 86_400),
            ..delegation(&did, a)
        };
        let renewal = AuthorizeWrite {
            now: t - 1,
            ..write(&renewed, 7, 7, SwarmWrite::Keep, AuthorizeOver::Live)
        };
        let theirs = delegation(&did, b);
        let takeover = AuthorizeWrite {
            now: t + 1,
            ..write(
                &theirs,
                7,
                8,
                SwarmWrite::Clear,
                AuthorizeOver::Dead { owner: a },
            )
        };
        store.authorize_agent(renewal).await.unwrap();
        assert!(
            conflict(store.authorize_agent(takeover).await),
            "the renewed row is live again: it is not taken over"
        );
        let got = store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!(
            (got.root_user_id, got.trust.state_version, got.expires_at),
            (a, 7, renewed.expires_at),
            "still A's renewed identity"
        );

        // Had the row stayed dead, the same takeover lands.
        store.put_agent_row(&expiring).await.unwrap();
        store.authorize_agent(takeover).await.unwrap();
        let got = store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!((got.root_user_id, got.trust.state_version), (b, 8));
    }

    #[tokio::test]
    async fn an_authorize_lands_only_on_the_row_it_read() {
        let Some(store) = local_store() else { return };
        let (owner, other) = (Uuid::new_v4(), Uuid::new_v4());
        // A renewal (keeping the version) of a row that expired since the read.
        let expired = AgentDelegation {
            expires_at: Some(100),
            trust: eligible_at(1),
            ..delegation(&unique_did("X"), owner)
        };
        store.put_agent_row(&expired).await.unwrap();
        assert!(
            conflict(
                store
                    .authorize_agent(write(&expired, 1, 1, SwarmWrite::Keep, AuthorizeOver::Live))
                    .await
            ),
            "a renewal never lands on an expired row"
        );
        // A renewal of a row that is another owner's.
        let foreign = AgentDelegation {
            trust: eligible_at(1),
            ..delegation(&unique_did("F"), other)
        };
        store.put_agent_row(&foreign).await.unwrap();
        let mine = delegation(&foreign.agent_did, owner);
        assert!(
            conflict(
                store
                    .authorize_agent(write(&mine, 1, 1, SwarmWrite::Keep, AuthorizeOver::Live))
                    .await
            ),
            "a renewal never lands on another owner's row"
        );
        // A new delegation over a row that is live ...
        assert!(
            conflict(
                store
                    .authorize_agent(write(
                        &mine,
                        1,
                        2,
                        SwarmWrite::Clear,
                        AuthorizeOver::Dead { owner: other }
                    ))
                    .await
            ),
            "a live row is never replaced"
        );
        // ... or dead but not the owner's it read.
        let lapsed = AgentDelegation {
            expires_at: Some(100),
            ..foreign.clone()
        };
        store.put_agent_row(&lapsed).await.unwrap();
        assert!(conflict(
            store
                .authorize_agent(write(
                    &mine,
                    1,
                    2,
                    SwarmWrite::Clear,
                    AuthorizeOver::Dead { owner }
                ))
                .await
        ));
        store
            .authorize_agent(write(
                &mine,
                1,
                2,
                SwarmWrite::Clear,
                AuthorizeOver::Dead { owner: other },
            ))
            .await
            .unwrap();
        // A create never lands on an existing row, even one without a version.
        let legacy = delegation(&unique_did("C"), owner);
        store.put_agent_row(&legacy).await.unwrap();
        assert!(conflict(
            store
                .authorize_agent(write(
                    &legacy,
                    0,
                    1,
                    SwarmWrite::Keep,
                    AuthorizeOver::Absent
                ))
                .await
        ));
    }

    #[tokio::test]
    async fn quarantine_and_revocation_are_bound_to_the_owner_and_version_read() {
        let Some(store) = local_store() else { return };
        let (first, second) = (Uuid::new_v4(), Uuid::new_v4());
        let did = unique_did("O");
        // The first owner's delegation, already expired at the clock the
        // reassignment below runs at.
        let lapsed = AgentDelegation {
            expires_at: Some(1_000),
            ..delegation(&did, first)
        };
        store
            .authorize_agent(write(
                &lapsed,
                0,
                1,
                SwarmWrite::Keep,
                AuthorizeOver::Absent,
            ))
            .await
            .unwrap();
        // The former owner (or its Guardian) reads the row at version 1 ...
        let read = store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!((read.root_user_id, read.trust.state_version), (first, 1));
        // ... the lapsed key is reassigned to another owner in between ...
        store
            .authorize_agent(write(
                &delegation(&did, second),
                1,
                2,
                SwarmWrite::Keep,
                AuthorizeOver::Dead { owner: first },
            ))
            .await
            .unwrap();
        let reassigned = store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!(reassigned.root_user_id, second);
        // ... and neither write lands.
        for by in ["owner:first", "guardian:g-first"] {
            assert_eq!(
                store
                    .quarantine_agent(&did, first, 1, "inc-1", None, by, 60)
                    .await
                    .unwrap(),
                QuarantineOutcome::NotOwner,
                "{by}"
            );
        }
        assert!(conflict(store.revoke_agent(&did, first, 1, 60).await));
        assert_eq!(
            store.get_agent_delegation(&did).await.unwrap(),
            Some(reassigned),
            "the new owner's row is untouched"
        );
        // The new owner at a stale version races; at the version it reads, it latches.
        assert_eq!(
            store
                .quarantine_agent(&did, second, 1, "inc-1", None, "owner:second", 61)
                .await
                .unwrap(),
            QuarantineOutcome::Raced
        );
        assert!(matches!(
            store.quarantine_agent(&did, second, 2, "inc-1", None, "owner:second", 62).await.unwrap(),
            QuarantineOutcome::Latched(d) if d.trust.state_version == 3
        ));
    }

    /// The owner clause refuses both writes on its own, independent of the
    /// version: `first` reads the version the row actually carries (1) but
    /// is not the owner, so neither write can be attributed to a stale
    /// version read.
    #[tokio::test]
    async fn quarantine_and_revocation_refuse_the_wrong_owner_at_the_stored_version() {
        let Some(store) = local_store() else { return };
        let (first, second) = (Uuid::new_v4(), Uuid::new_v4());
        let did = unique_did("W");
        let d = AgentDelegation {
            trust: AgentTrust {
                state: AgentState::Eligible,
                state_version: 1,
                appraised_until: Some(1_790_043_200),
                appraised_by: Some("owner:second".into()),
                ..AgentTrust::default()
            },
            ..delegation(&did, second)
        };
        store.put_agent_row(&d).await.unwrap();
        assert_eq!(
            store
                .quarantine_agent(&did, first, 1, "inc-1", None, "owner:first", 60)
                .await
                .unwrap(),
            QuarantineOutcome::NotOwner
        );
        assert!(conflict(store.revoke_agent(&did, first, 1, 60).await));
        let got = store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!(got.root_user_id, second);
        assert_eq!(got.trust.state_version, 1);
        assert_eq!(got.trust.state, AgentState::Eligible);
        assert_eq!(got.revoked_at, None);
    }
}
