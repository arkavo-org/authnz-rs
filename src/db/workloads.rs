//! Agent workloads (`agent_workloads` table): the owner-scoped record that
//! binds one agent DID and one swarm and carries the quarantine latch.
//!
//! The primary key is derived from `(owner, name)`, so one conditional put
//! enforces name uniqueness and every read — the KAS status check included —
//! is a strongly consistent `GetItem`, never an eventually consistent index.

use super::{AgentDelegation, DynamoDBError, DynamoDBStore};
use aws_sdk_dynamodb::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_dynamodb::types::{
    AttributeValue, ConditionCheck, Put, ReturnValue, TransactWriteItem, Update,
};
use log::{error, info};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

type Item = HashMap<String, AttributeValue>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadState {
    Eligible,
    Quarantined,
}

impl WorkloadState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::Quarantined => "quarantined",
        }
    }

    fn parse(s: &str) -> Result<Self, DynamoDBError> {
        match s {
            "eligible" => Ok(Self::Eligible),
            "quarantined" => Ok(Self::Quarantined),
            other => Err(DynamoDBError::Internal(format!(
                "unknown workload state {other:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWorkload {
    pub workload_id: String,
    pub owner: Uuid,
    pub name: String,
    /// The one agent DID that may mint for this workload; empty after a
    /// recovery until the owner authorizes again.
    pub current_did: String,
    /// SwarmKit `kit_id`; empty while the agent has no kit.
    pub swarm: String,
    pub state: WorkloadState,
    /// Server-assigned; +1 on every change to `current_did`, `swarm` or
    /// `state`, so the KAS can refuse a status answer older than one it has
    /// already seen.
    pub generation: u64,
    /// Incident that latched the quarantine; `None` while eligible.
    pub incident: Option<String>,
    pub evidence_ref: Option<String>,
    /// `owner:<uuid>` or `guardian:<id>`.
    pub quarantined_by: Option<String>,
    pub quarantined_at: Option<i64>,
    /// The incident the most recent recovery cleared.
    pub last_cleared_incident: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Result of a quarantine request against the stored latch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineOutcome {
    /// This call latched it; the record carries the new generation.
    Latched(AgentWorkload),
    /// Already latched under the same incident: nothing changed.
    AlreadyLatched(AgentWorkload),
    /// Already latched under a different incident: nothing changed.
    OtherIncident(AgentWorkload),
    /// Eligible, and the incident is the one the last recovery cleared:
    /// refused so a replayed or stale report cannot re-latch it.
    ClearedIncident(AgentWorkload),
    /// The condition failed but the re-read shows the workload eligible:
    /// a recovery landed in between. The caller retries.
    Raced,
    NotFound,
}

/// What an authorize does to the workload row, decided from the row as the
/// caller read it. Every variant is written in one transaction with the
/// agent's delegation, so a workload is never bound to a DID whose
/// delegation failed to land, nor a delegation written into a workload that
/// was quarantined or rebound in between.
#[derive(Debug, Clone, Copy)]
pub enum Binding<'a> {
    /// No row yet: create this one (conditional on the id being free).
    Create(&'a AgentWorkload),
    /// Bind the row read at `from.generation` to `did` and `swarm`
    /// (`""` = no swarm), generation + 1. With `revoke_previous`, also revoke
    /// the delegation of `from.current_did` — only while that row still
    /// names this workload, so a DID since authorized elsewhere keeps it.
    /// Without it, the write instead requires that DID to hold no unrevoked
    /// delegation for this workload, so a stale "nothing to revoke" fails.
    Rebind {
        from: &'a AgentWorkload,
        did: &'a str,
        swarm: &'a str,
        revoke_previous: bool,
    },
    /// DID and swarm unchanged: the row is left as is (no generation bump)
    /// but must still be eligible at the generation read.
    Keep(&'a AgentWorkload),
}

impl Binding<'_> {
    fn workload(&self) -> &AgentWorkload {
        match self {
            Self::Create(w) | Self::Keep(w) | Self::Rebind { from: w, .. } => w,
        }
    }

    fn did(&self) -> &str {
        match self {
            Self::Create(w) | Self::Keep(w) => &w.current_did,
            Self::Rebind { did, .. } => did,
        }
    }
}

/// Server-derived workload id for `(owner, name)`: `wl-` and the first 16
/// bytes of a domain-separated SHA-256, hex. Deterministic so the same
/// owner and name always select the same workload without an index.
pub fn workload_id_for(owner: &Uuid, name: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"arkavo-workload-v1\0");
    h.update(owner.as_bytes());
    h.update(b"\0");
    h.update(name.as_bytes());
    format!("wl-{}", hex::encode(&h.finalize()[..16]))
}

pub(super) fn s(v: &str) -> AttributeValue {
    AttributeValue::S(v.to_string())
}

pub(super) fn n(v: impl ToString) -> AttributeValue {
    AttributeValue::N(v.to_string())
}

/// Map a DynamoDB call failure onto the store's error type. A failed
/// condition — on a single write or inside a transaction — is a
/// `ConditionalConflict` the caller resolves by re-reading.
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
        Some("ConditionalCheckFailedException") | Some("TransactionCanceledException") => {
            DynamoDBError::ConditionalConflict
        }
        Some("ResourceNotFoundException") => DynamoDBError::TableNotExists(table.to_string()),
        _ => {
            error!("DynamoDB call on {table} failed: {err:?}");
            DynamoDBError::SdkError(err.to_string())
        }
    }
}

fn workload_item(w: &AgentWorkload) -> Item {
    let mut item = Item::new();
    item.insert("workload_id".into(), s(&w.workload_id));
    item.insert("owner".into(), s(&w.owner.to_string()));
    item.insert("name".into(), s(&w.name));
    if !w.current_did.is_empty() {
        item.insert("current_did".into(), s(&w.current_did));
    }
    if !w.swarm.is_empty() {
        item.insert("swarm".into(), s(&w.swarm));
    }
    item.insert("state".into(), s(w.state.as_str()));
    item.insert("generation".into(), n(w.generation));
    item.insert("created_at".into(), n(w.created_at));
    item.insert("updated_at".into(), n(w.updated_at));
    for (key, value) in [
        ("incident", &w.incident),
        ("evidence_ref", &w.evidence_ref),
        ("quarantined_by", &w.quarantined_by),
        ("last_cleared_incident", &w.last_cleared_incident),
    ] {
        if let Some(v) = value {
            item.insert(key.into(), s(v));
        }
    }
    if let Some(t) = w.quarantined_at {
        item.insert("quarantined_at".into(), n(t));
    }
    item
}

fn item_to_workload(item: &Item) -> Result<AgentWorkload, DynamoDBError> {
    let text = |k: &str| item.get(k).and_then(|v| v.as_s().ok()).cloned();
    let req = |k: &str| {
        text(k).ok_or_else(|| DynamoDBError::Internal(format!("workload row missing {k}")))
    };
    let int = |k: &str| {
        item.get(k)
            .and_then(|v| v.as_n().ok())
            .and_then(|v| v.parse::<i64>().ok())
    };
    Ok(AgentWorkload {
        workload_id: req("workload_id")?,
        owner: Uuid::parse_str(&req("owner")?)?,
        name: req("name")?,
        current_did: text("current_did").unwrap_or_default(),
        swarm: text("swarm").unwrap_or_default(),
        state: WorkloadState::parse(&req("state")?)?,
        generation: item
            .get("generation")
            .and_then(|v| v.as_n().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| DynamoDBError::Internal("workload row missing generation".into()))?,
        incident: text("incident"),
        evidence_ref: text("evidence_ref"),
        quarantined_by: text("quarantined_by"),
        quarantined_at: int("quarantined_at"),
        last_cleared_incident: text("last_cleared_incident"),
        created_at: int("created_at")
            .ok_or_else(|| DynamoDBError::Internal("workload row missing created_at".into()))?,
        updated_at: int("updated_at")
            .ok_or_else(|| DynamoDBError::Internal("workload row missing updated_at".into()))?,
    })
}

fn built<T, E: std::fmt::Display>(r: Result<T, E>) -> Result<T, DynamoDBError> {
    r.map_err(|e| DynamoDBError::Internal(e.to_string()))
}

impl DynamoDBStore {
    /// Strongly consistent read: issuance, quarantine, recovery and the
    /// status lease all decide on what this returns.
    pub async fn get_workload(
        &self,
        workload_id: &str,
    ) -> Result<Option<AgentWorkload>, DynamoDBError> {
        let out = self
            .client
            .get_item()
            .table_name(&self.agent_workloads_table)
            .key("workload_id", s(workload_id))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| classify(e, &self.agent_workloads_table))?;
        out.item.as_ref().map(item_to_workload).transpose()
    }

    /// Latch a quarantine: eligible → quarantined with `generation + 1`, in
    /// one conditional update. A latched workload is never re-latched; the
    /// re-read tells an idempotent repeat from a second incident.
    pub async fn quarantine_workload(
        &self,
        workload_id: &str,
        incident: &str,
        evidence_ref: Option<&str>,
        by: &str,
        now: i64,
    ) -> Result<QuarantineOutcome, DynamoDBError> {
        let set = "SET #st = :q, incident = :inc, quarantined_by = :by, \
                   quarantined_at = :now, updated_at = :now, #g = #g + :one";
        let mut req = self
            .client
            .update_item()
            .table_name(&self.agent_workloads_table)
            .key("workload_id", s(workload_id))
            .condition_expression(
                "attribute_exists(workload_id) AND #st = :eligible \
                 AND (attribute_not_exists(last_cleared_incident) OR last_cleared_incident <> :inc)",
            )
            .expression_attribute_names("#st", "state")
            .expression_attribute_names("#g", "generation")
            .expression_attribute_values(":q", s(WorkloadState::Quarantined.as_str()))
            .expression_attribute_values(":eligible", s(WorkloadState::Eligible.as_str()))
            .expression_attribute_values(":inc", s(incident))
            .expression_attribute_values(":by", s(by))
            .expression_attribute_values(":now", n(now))
            .expression_attribute_values(":one", n(1))
            .return_values(ReturnValue::AllNew);
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
                Ok(QuarantineOutcome::Latched(item_to_workload(&item)?))
            }
            Err(err) => match classify(err, &self.agent_workloads_table) {
                DynamoDBError::ConditionalConflict => {
                    Ok(match self.get_workload(workload_id).await? {
                        None => QuarantineOutcome::NotFound,
                        Some(w)
                            if w.state == WorkloadState::Eligible
                                && w.last_cleared_incident.as_deref() == Some(incident) =>
                        {
                            QuarantineOutcome::ClearedIncident(w)
                        }
                        Some(w) if w.state == WorkloadState::Eligible => QuarantineOutcome::Raced,
                        Some(w) if w.incident.as_deref() == Some(incident) => {
                            QuarantineOutcome::AlreadyLatched(w)
                        }
                        Some(w) => QuarantineOutcome::OtherIncident(w),
                    })
                }
                other => Err(other),
            },
        }
    }

    /// Clear a quarantine, conditional on it still being latched under
    /// `incident` at the generation the caller read (so a concurrent rebind,
    /// re-latch or second recovery fails it): eligible, `generation + 1`,
    /// `incident` recorded as cleared, DID unbound. In the same transaction
    /// the unbound DID's delegation is revoked when `revoke_old_delegation`
    /// — only while it still names this workload (P4) — or else must hold no
    /// unrevoked delegation for it, so a stale "nothing to revoke" fails.
    /// Nothing mints for the workload until the owner authorizes again.
    pub async fn recover_workload(
        &self,
        w: &AgentWorkload,
        incident: &str,
        revoke_old_delegation: bool,
        now: i64,
    ) -> Result<(), DynamoDBError> {
        let clear = built(
            Update::builder()
                .table_name(&self.agent_workloads_table)
                .key("workload_id", s(&w.workload_id))
                .condition_expression("#st = :q AND incident = :inc AND #g = :g")
                .update_expression(
                    "SET #st = :eligible, last_cleared_incident = :inc, updated_at = :now, \
                     #g = #g + :one REMOVE current_did, incident, evidence_ref, \
                     quarantined_by, quarantined_at",
                )
                .expression_attribute_names("#st", "state")
                .expression_attribute_names("#g", "generation")
                .expression_attribute_values(":q", s(WorkloadState::Quarantined.as_str()))
                .expression_attribute_values(":eligible", s(WorkloadState::Eligible.as_str()))
                .expression_attribute_values(":inc", s(incident))
                .expression_attribute_values(":g", n(w.generation))
                .expression_attribute_values(":now", n(now))
                .expression_attribute_values(":one", n(1))
                .build(),
        )?;
        let mut items = vec![TransactWriteItem::builder().update(clear).build()];
        if !w.current_did.is_empty() {
            items.push(if revoke_old_delegation {
                self.revoke_delegation_item(&w.current_did, &w.workload_id, now)?
            } else {
                self.nothing_to_revoke_item(&w.current_did, &w.workload_id)?
            });
        }
        self.transact(items).await?;
        info!(
            "Recovered workload {} (cleared incident {}, generation {})",
            w.workload_id,
            incident,
            w.generation + 1
        );
        Ok(())
    }

    /// Plant a workload row on its own; `ConditionalConflict` if the id
    /// already exists. Production creates workloads only through
    /// [`Self::commit_binding`], together with the delegation.
    #[cfg(test)]
    pub async fn create_workload(&self, w: &AgentWorkload) -> Result<(), DynamoDBError> {
        self.transact(vec![self.create_workload_item(w)?]).await
    }

    fn create_workload_item(&self, w: &AgentWorkload) -> Result<TransactWriteItem, DynamoDBError> {
        let put = built(
            Put::builder()
                .table_name(&self.agent_workloads_table)
                .set_item(Some(workload_item(w)))
                .condition_expression("attribute_not_exists(workload_id)")
                .build(),
        )?;
        Ok(TransactWriteItem::builder().put(put).build())
    }

    /// Apply `binding` and write `delegation` — the bound DID's delegation for
    /// this workload — in one transaction. `ConditionalConflict` when any
    /// condition fails (the workload changed or was quarantined since it was
    /// read, or the DID holds a delegation this one may not replace); the
    /// caller re-reads to learn which.
    pub async fn commit_binding(
        &self,
        binding: Binding<'_>,
        delegation: &AgentDelegation,
        now: i64,
    ) -> Result<(), DynamoDBError> {
        let w = binding.workload();
        if delegation.agent_did != binding.did()
            || delegation.workload_id.as_deref() != Some(w.workload_id.as_str())
        {
            return Err(DynamoDBError::Internal(format!(
                "delegation for {} does not match the binding of workload {}",
                delegation.agent_did, w.workload_id
            )));
        }
        let mut items = vec![match binding {
            Binding::Create(w) => self.create_workload_item(w)?,
            Binding::Keep(w) => self.workload_unchanged_item(w)?,
            Binding::Rebind {
                from, did, swarm, ..
            } => self.rebind_item(from, did, swarm, now)?,
        }];
        items.push(
            TransactWriteItem::builder()
                .put(self.agent_delegation_put(delegation, now)?)
                .build(),
        );
        if let Binding::Rebind {
            from,
            did,
            revoke_previous,
            ..
        } = binding
            && !from.current_did.is_empty()
            && from.current_did != did
        {
            items.push(if revoke_previous {
                self.revoke_delegation_item(&from.current_did, &from.workload_id, now)?
            } else {
                self.nothing_to_revoke_item(&from.current_did, &from.workload_id)?
            });
        }
        self.transact(items).await?;
        info!(
            "Bound workload {} to {} in {:?} (generation {})",
            w.workload_id,
            binding.did(),
            match binding {
                Binding::Rebind { swarm, .. } => swarm,
                _ => w.swarm.as_str(),
            },
            match binding {
                Binding::Rebind { .. } => w.generation + 1,
                _ => w.generation,
            }
        );
        Ok(())
    }

    /// The row must still be eligible at the generation the caller read.
    fn workload_unchanged_item(
        &self,
        w: &AgentWorkload,
    ) -> Result<TransactWriteItem, DynamoDBError> {
        let check = built(
            ConditionCheck::builder()
                .table_name(&self.agent_workloads_table)
                .key("workload_id", s(&w.workload_id))
                .condition_expression("#st = :eligible AND #g = :g")
                .expression_attribute_names("#st", "state")
                .expression_attribute_names("#g", "generation")
                .expression_attribute_values(":eligible", s(WorkloadState::Eligible.as_str()))
                .expression_attribute_values(":g", n(w.generation))
                .build(),
        )?;
        Ok(TransactWriteItem::builder().condition_check(check).build())
    }

    /// Bind `w` to `did` and `swarm`, conditional on it still being eligible
    /// at the generation the caller read.
    fn rebind_item(
        &self,
        w: &AgentWorkload,
        did: &str,
        swarm: &str,
        now: i64,
    ) -> Result<TransactWriteItem, DynamoDBError> {
        // No swarm yet is an absent attribute, never an empty string.
        let expression = if swarm.is_empty() {
            "SET current_did = :did, #g = #g + :one, updated_at = :now REMOVE swarm"
        } else {
            "SET current_did = :did, swarm = :swarm, #g = #g + :one, updated_at = :now"
        };
        let mut bind = Update::builder()
            .table_name(&self.agent_workloads_table)
            .key("workload_id", s(&w.workload_id))
            .condition_expression("#st = :eligible AND #g = :g")
            .update_expression(expression)
            .expression_attribute_names("#st", "state")
            .expression_attribute_names("#g", "generation")
            .expression_attribute_values(":eligible", s(WorkloadState::Eligible.as_str()))
            .expression_attribute_values(":g", n(w.generation))
            .expression_attribute_values(":did", s(did))
            .expression_attribute_values(":one", n(1))
            .expression_attribute_values(":now", n(now));
        if !swarm.is_empty() {
            bind = bind.expression_attribute_values(":swarm", s(swarm));
        }
        Ok(TransactWriteItem::builder()
            .update(built(bind.build())?)
            .build())
    }

    /// The negation of [`Self::revoke_delegation_item`]'s precondition: a
    /// rebind that decided not to revoke the previous DID commits only while
    /// that DID still holds no unrevoked delegation for `workload_id`. A
    /// re-authorization of it for the same workload leaves the generation
    /// alone, so the workload's own condition cannot catch it.
    /// `attribute_not_exists(workload_id)` is needed because a comparison on a
    /// missing attribute is false.
    fn nothing_to_revoke_item(
        &self,
        agent_did: &str,
        workload_id: &str,
    ) -> Result<TransactWriteItem, DynamoDBError> {
        let check = built(
            ConditionCheck::builder()
                .table_name(&self.agent_delegations_table)
                .key("agent_did", s(agent_did))
                .condition_expression(
                    "attribute_not_exists(agent_did) OR attribute_exists(revoked_at) \
                     OR attribute_not_exists(workload_id) OR workload_id <> :wid",
                )
                .expression_attribute_values(":wid", s(workload_id))
                .build(),
        )?;
        Ok(TransactWriteItem::builder().condition_check(check).build())
    }

    /// Revoke `agent_did`'s delegation inside a transaction, conditional on
    /// the row existing (an update must never create a stub delegation row)
    /// and still naming `workload_id`: a DID re-authorized under another
    /// workload since keeps that delegation.
    pub(crate) fn revoke_delegation_item(
        &self,
        agent_did: &str,
        workload_id: &str,
        now: i64,
    ) -> Result<TransactWriteItem, DynamoDBError> {
        let update = built(
            Update::builder()
                .table_name(&self.agent_delegations_table)
                .key("agent_did", s(agent_did))
                .condition_expression("attribute_exists(agent_did) AND workload_id = :wid")
                .update_expression("SET revoked_at = if_not_exists(revoked_at, :now)")
                .expression_attribute_values(":wid", s(workload_id))
                .expression_attribute_values(":now", n(now))
                .build(),
        )?;
        Ok(TransactWriteItem::builder().update(update).build())
    }

    pub(crate) async fn transact(
        &self,
        items: Vec<TransactWriteItem>,
    ) -> Result<(), DynamoDBError> {
        self.client
            .transact_write_items()
            .set_transact_items(Some(items))
            .send()
            .await
            .map_err(|e| classify(e, &self.agent_workloads_table))?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::tests::local_store;

    pub(crate) fn sample(owner: Uuid, name: &str, did: &str) -> AgentWorkload {
        AgentWorkload {
            workload_id: workload_id_for(&owner, name),
            owner,
            name: name.into(),
            current_did: did.into(),
            swarm: "kit-1".into(),
            state: WorkloadState::Eligible,
            generation: 1,
            incident: None,
            evidence_ref: None,
            quarantined_by: None,
            quarantined_at: None,
            last_cleared_incident: None,
            created_at: 1_790_000_000,
            updated_at: 1_790_000_000,
        }
    }

    pub(crate) fn delegation(
        did: &str,
        owner: Uuid,
        workload_id: Option<String>,
    ) -> AgentDelegation {
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
            created_at: chrono::Utc::now().timestamp(),
            expires_at: Some(chrono::Utc::now().timestamp() + 86_400),
            revoked_at: None,
            workload_id,
            short_lived: false,
        }
    }

    fn unique_did(tag: &str) -> String {
        format!("did:key:z6Mk{tag}{}", Uuid::new_v4().simple())
    }

    /// Rebind `w` (as read) to `did`/`swarm`, writing `did`'s delegation in
    /// the same transaction, as authorize does.
    async fn rebind(
        store: &DynamoDBStore,
        w: &AgentWorkload,
        did: &str,
        swarm: &str,
        revoke_previous: bool,
        now: i64,
    ) -> Result<(), DynamoDBError> {
        let d = delegation(did, w.owner, Some(w.workload_id.clone()));
        store
            .commit_binding(
                Binding::Rebind {
                    from: w,
                    did,
                    swarm,
                    revoke_previous,
                },
                &d,
                now,
            )
            .await
    }

    #[test]
    fn workload_id_is_stable_per_owner_and_name() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        assert_eq!(workload_id_for(&a, "fleet"), workload_id_for(&a, "fleet"));
        assert_ne!(workload_id_for(&a, "fleet"), workload_id_for(&b, "fleet"));
        assert_ne!(workload_id_for(&a, "fleet"), workload_id_for(&a, "fleet2"));
        let id = workload_id_for(&a, "fleet");
        assert_eq!(id.len(), 35);
        assert!(id.starts_with("wl-"));
        assert!(
            id[3..]
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
    }

    #[test]
    fn workload_item_round_trips_including_an_unbound_did() {
        let mut w = sample(Uuid::from_u128(3), "fleet", "did:key:z6MkA");
        w.state = WorkloadState::Quarantined;
        w.incident = Some("inc-1".into());
        w.evidence_ref = Some("s3://evidence/1".into());
        w.quarantined_by = Some("owner:x".into());
        w.quarantined_at = Some(1_790_000_050);
        assert_eq!(item_to_workload(&workload_item(&w)).unwrap(), w);
        let unbound = AgentWorkload {
            current_did: String::new(),
            last_cleared_incident: Some("inc-0".into()),
            ..sample(Uuid::from_u128(3), "fleet", "")
        };
        assert_eq!(item_to_workload(&workload_item(&unbound)).unwrap(), unbound);
    }

    #[test]
    fn a_delegation_that_does_not_match_the_binding_is_refused_before_writing() {
        // Pure: the mismatch is caught before any DynamoDB call.
        let store = crate::db::DynamoDBStore::with_client(
            aws_sdk_dynamodb::Client::from_conf(
                aws_sdk_dynamodb::config::Builder::new()
                    .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
                    .build(),
            ),
            "c".into(),
            "h".into(),
            "d".into(),
            "i".into(),
            "p".into(),
            "a".into(),
            "k".into(),
            "w".into(),
            vec![],
        );
        let owner = Uuid::from_u128(4);
        let w = sample(owner, "fleet", "did:key:z6MkA");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for d in [
            delegation("did:key:z6MkOther", owner, Some(w.workload_id.clone())),
            delegation("did:key:z6MkA", owner, Some(workload_id_for(&owner, "x"))),
            delegation("did:key:z6MkA", owner, None),
        ] {
            assert!(matches!(
                rt.block_on(store.commit_binding(Binding::Create(&w), &d, 1)),
                Err(DynamoDBError::Internal(_))
            ));
        }
    }

    #[tokio::test]
    async fn create_is_conditional_and_get_reads_it_back() {
        let Some(store) = local_store() else {
            return;
        };
        let w = sample(Uuid::new_v4(), "fleet", "did:key:z6MkA");
        store.create_workload(&w).await.unwrap();
        assert_eq!(
            store.get_workload(&w.workload_id).await.unwrap(),
            Some(w.clone())
        );
        assert!(matches!(
            store.create_workload(&w).await,
            Err(DynamoDBError::ConditionalConflict)
        ));
        assert_eq!(store.get_workload("wl-absent").await.unwrap(), None);
    }

    #[tokio::test]
    async fn create_binding_writes_the_workload_and_delegation_together() {
        let Some(store) = local_store() else {
            return;
        };
        let owner = Uuid::new_v4();
        let did = unique_did("Create");
        let w = sample(owner, "fleet", &did);
        let d = delegation(&did, owner, Some(w.workload_id.clone()));
        store
            .commit_binding(Binding::Create(&w), &d, 1_790_000_000)
            .await
            .unwrap();
        assert_eq!(store.get_workload(&w.workload_id).await.unwrap(), Some(w));
        let got = store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!(got.workload_id, d.workload_id);

        // The DID now holds a live delegation for "fleet": creating another
        // workload bound to it fails as a whole — no half-created workload.
        let other = sample(owner, "other", &did);
        let d2 = delegation(&did, owner, Some(other.workload_id.clone()));
        assert!(matches!(
            store
                .commit_binding(Binding::Create(&other), &d2, 1_790_000_000)
                .await,
            Err(DynamoDBError::ConditionalConflict)
        ));
        assert_eq!(store.get_workload(&other.workload_id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn rebind_refuses_quarantined_or_stale_generation() {
        let Some(store) = local_store() else {
            return;
        };
        let owner = Uuid::new_v4();
        let w = sample(owner, "fleet", "did:key:z6MkOld");
        store.create_workload(&w).await.unwrap();
        let new_did = unique_did("New");
        rebind(&store, &w, &new_did, "kit-2", false, 1_790_000_100)
            .await
            .unwrap();
        let after = store.get_workload(&w.workload_id).await.unwrap().unwrap();
        assert_eq!(after.current_did, new_did);
        assert_eq!(after.swarm, "kit-2");
        assert_eq!(after.generation, 2);

        // The snapshot at generation 1 is stale now.
        assert!(matches!(
            rebind(&store, &w, &unique_did("X"), "kit-2", false, 1_790_000_200).await,
            Err(DynamoDBError::ConditionalConflict)
        ));

        // A quarantined row cannot be rebound even at its current generation.
        let q = AgentWorkload {
            state: WorkloadState::Quarantined,
            incident: Some("inc".into()),
            ..sample(owner, "q", "did:key:z6MkQ")
        };
        store.create_workload(&q).await.unwrap();
        let y = unique_did("Y");
        assert!(matches!(
            rebind(&store, &q, &y, "kit-1", false, 1_790_000_300).await,
            Err(DynamoDBError::ConditionalConflict)
        ));
        let still = store.get_workload(&q.workload_id).await.unwrap().unwrap();
        assert_eq!(
            (still.current_did.as_str(), still.generation),
            ("did:key:z6MkQ", 1)
        );
        assert!(
            store.get_agent_delegation(&y).await.unwrap().is_none(),
            "the delegation is written only with the binding"
        );
    }

    #[tokio::test]
    async fn keep_writes_the_delegation_without_a_generation_bump_unless_quarantined() {
        let Some(store) = local_store() else {
            return;
        };
        let owner = Uuid::new_v4();
        let did = unique_did("Keep");
        let w = sample(owner, "fleet", &did);
        store.create_workload(&w).await.unwrap();
        let mut d = delegation(&did, owner, Some(w.workload_id.clone()));
        store.create_agent_delegation(&d).await.unwrap();

        // The same DID re-authorized for the same workload replaces its own
        // delegation; the workload row is untouched.
        d.short_lived = true;
        store
            .commit_binding(Binding::Keep(&w), &d, 1_790_000_100)
            .await
            .unwrap();
        assert!(
            store
                .get_agent_delegation(&did)
                .await
                .unwrap()
                .unwrap()
                .short_lived
        );
        assert_eq!(
            store.get_workload(&w.workload_id).await.unwrap(),
            Some(w.clone())
        );

        // A quarantine landing after the read blocks the write.
        let q = AgentWorkload {
            state: WorkloadState::Quarantined,
            incident: Some("inc".into()),
            ..sample(owner, "q", &unique_did("Q"))
        };
        store.create_workload(&q).await.unwrap();
        let read_while_eligible = AgentWorkload {
            state: WorkloadState::Eligible,
            incident: None,
            ..q.clone()
        };
        let dq = delegation(&q.current_did, owner, Some(q.workload_id.clone()));
        assert!(matches!(
            store
                .commit_binding(Binding::Keep(&read_while_eligible), &dq, 1_790_000_100)
                .await,
            Err(DynamoDBError::ConditionalConflict)
        ));
        assert!(
            store
                .get_agent_delegation(&q.current_did)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn rebind_revokes_the_previous_delegation_in_the_same_write() {
        let Some(store) = local_store() else {
            return;
        };
        let owner = Uuid::new_v4();
        let old_did = unique_did("Old");
        let w = sample(owner, "fleet", &old_did);
        store.create_workload(&w).await.unwrap();
        store
            .create_agent_delegation(&delegation(&old_did, owner, Some(w.workload_id.clone())))
            .await
            .unwrap();
        rebind(&store, &w, &unique_did("New"), "kit-1", true, 1_790_000_100)
            .await
            .unwrap();
        let old = store.get_agent_delegation(&old_did).await.unwrap().unwrap();
        assert!(old.revoked_at.is_some());
    }

    #[tokio::test]
    async fn a_stale_no_revoke_rebind_fails_once_the_previous_did_is_live_again() {
        let Some(store) = local_store() else {
            return;
        };
        let owner = Uuid::new_v4();
        let old_did = unique_did("Relive");
        let w = sample(owner, "fleet", &old_did);
        store.create_workload(&w).await.unwrap();
        // Decided while the old DID read as revoked: nothing to revoke.
        let mut revoked = delegation(&old_did, owner, Some(w.workload_id.clone()));
        revoked.revoked_at = Some(1_790_000_000);
        store.create_agent_delegation(&revoked).await.unwrap();
        // Before the rebind commits, the old DID is re-authorized for the
        // same workload (a Keep: no generation bump), so it is live again.
        store
            .commit_binding(
                Binding::Keep(&w),
                &delegation(&old_did, owner, Some(w.workload_id.clone())),
                1_790_000_050,
            )
            .await
            .unwrap();
        let new_did = unique_did("New");
        assert!(matches!(
            rebind(&store, &w, &new_did, "kit-1", false, 1_790_000_100).await,
            Err(DynamoDBError::ConditionalConflict)
        ));
        assert_eq!(
            store.get_workload(&w.workload_id).await.unwrap(),
            Some(w.clone())
        );
        assert!(
            store
                .get_agent_delegation(&new_did)
                .await
                .unwrap()
                .is_none()
        );
        // Decided afresh, the rebind revokes it.
        rebind(&store, &w, &new_did, "kit-1", true, 1_790_000_100)
            .await
            .unwrap();
        let old = store.get_agent_delegation(&old_did).await.unwrap().unwrap();
        assert!(old.revoked_at.is_some());
    }

    #[tokio::test]
    async fn a_no_revoke_rebind_still_commits_when_the_previous_did_is_gone_or_elsewhere() {
        let Some(store) = local_store() else {
            return;
        };
        let owner = Uuid::new_v4();
        // No row at all for the previous DID.
        let w = sample(owner, "gone", &unique_did("Gone"));
        store.create_workload(&w).await.unwrap();
        rebind(
            &store,
            &w,
            &unique_did("New"),
            "kit-1",
            false,
            1_790_000_100,
        )
        .await
        .unwrap();
        // A legacy row (no workload_id) and a row for another workload.
        for (name, wid) in [
            ("legacy", None),
            ("moved", Some(workload_id_for(&owner, "x"))),
        ] {
            let old_did = unique_did("Prev");
            let w = sample(owner, name, &old_did);
            store.create_workload(&w).await.unwrap();
            store
                .create_agent_delegation(&delegation(&old_did, owner, wid))
                .await
                .unwrap();
            rebind(
                &store,
                &w,
                &unique_did("New"),
                "kit-1",
                false,
                1_790_000_100,
            )
            .await
            .unwrap();
            let prev = store.get_agent_delegation(&old_did).await.unwrap().unwrap();
            assert!(
                prev.revoked_at.is_none(),
                "{name}: not this workload's to revoke"
            );
        }
    }

    #[tokio::test]
    async fn rebind_never_revokes_a_delegation_bound_to_another_workload() {
        let Some(store) = local_store() else {
            return;
        };
        let owner = Uuid::new_v4();
        let old_did = unique_did("Moved");
        let w = sample(owner, "fleet", &old_did);
        store.create_workload(&w).await.unwrap();
        // Since `w` was read, the old DID was authorized under another
        // workload: the revocation's condition fails and nothing is written.
        let elsewhere = Some(workload_id_for(&owner, "elsewhere"));
        store
            .create_agent_delegation(&delegation(&old_did, owner, elsewhere.clone()))
            .await
            .unwrap();
        let new_did = unique_did("New");
        assert!(matches!(
            rebind(&store, &w, &new_did, "kit-1", true, 1_790_000_100).await,
            Err(DynamoDBError::ConditionalConflict)
        ));
        let kept = store.get_agent_delegation(&old_did).await.unwrap().unwrap();
        assert_eq!((kept.revoked_at, kept.workload_id), (None, elsewhere));
        assert_eq!(store.get_workload(&w.workload_id).await.unwrap(), Some(w));
        assert!(
            store
                .get_agent_delegation(&new_did)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_legacy_delegation_is_replaceable_only_by_its_own_owner() {
        let Some(store) = local_store() else {
            return;
        };
        let (owner, stranger) = (Uuid::new_v4(), Uuid::new_v4());
        let did = unique_did("Legacy");
        store
            .create_agent_delegation(&delegation(&did, owner, None))
            .await
            .unwrap();
        let theirs = delegation(&did, stranger, Some(workload_id_for(&stranger, "fleet")));
        assert!(matches!(
            store.create_agent_delegation(&theirs).await,
            Err(DynamoDBError::ConditionalConflict)
        ));
        assert_eq!(
            store
                .get_agent_delegation(&did)
                .await
                .unwrap()
                .unwrap()
                .root_user_id,
            owner
        );
        let mine = delegation(&did, owner, Some(workload_id_for(&owner, "fleet")));
        store.create_agent_delegation(&mine).await.unwrap();
        assert_eq!(
            store
                .get_agent_delegation(&did)
                .await
                .unwrap()
                .unwrap()
                .workload_id,
            mine.workload_id
        );
    }

    #[tokio::test]
    async fn quarantine_latches_once_per_incident() {
        let Some(store) = local_store() else {
            return;
        };
        let w = sample(Uuid::new_v4(), "fleet", "did:key:z6MkA");
        store.create_workload(&w).await.unwrap();

        let first = store
            .quarantine_workload(
                &w.workload_id,
                "inc-1",
                Some("ev-1"),
                "owner:x",
                1_790_000_100,
            )
            .await
            .unwrap();
        let QuarantineOutcome::Latched(q) = first else {
            panic!("expected Latched, got {first:?}");
        };
        assert_eq!(q.state, WorkloadState::Quarantined);
        assert_eq!(q.generation, 2);
        assert_eq!(q.incident.as_deref(), Some("inc-1"));
        assert_eq!(q.evidence_ref.as_deref(), Some("ev-1"));
        assert_eq!(q.quarantined_by.as_deref(), Some("owner:x"));
        assert_eq!(q.quarantined_at, Some(1_790_000_100));

        let again = store
            .quarantine_workload(&w.workload_id, "inc-1", None, "guardian:g", 1_790_000_200)
            .await
            .unwrap();
        assert!(
            matches!(&again, QuarantineOutcome::AlreadyLatched(a)
                if a.generation == 2 && a.quarantined_by.as_deref() == Some("owner:x")),
            "{again:?}"
        );

        let other = store
            .quarantine_workload(&w.workload_id, "inc-2", None, "owner:x", 1_790_000_300)
            .await
            .unwrap();
        assert!(
            matches!(&other, QuarantineOutcome::OtherIncident(o)
                if o.incident.as_deref() == Some("inc-1") && o.generation == 2),
            "{other:?}"
        );

        assert_eq!(
            store
                .quarantine_workload("wl-absent", "inc-1", None, "owner:x", 1)
                .await
                .unwrap(),
            QuarantineOutcome::NotFound
        );
        assert_eq!(
            store.get_workload("wl-absent").await.unwrap(),
            None,
            "no stub row"
        );

        // A recovered workload refuses the incident it just cleared, so a
        // replayed report cannot re-latch it; a new incident still latches.
        let recovered = AgentWorkload {
            last_cleared_incident: Some("inc-old".into()),
            ..sample(Uuid::new_v4(), "fleet", "did:key:z6MkB")
        };
        store.create_workload(&recovered).await.unwrap();
        let cleared = store
            .quarantine_workload(
                &recovered.workload_id,
                "inc-old",
                None,
                "guardian:g",
                1_790_000_400,
            )
            .await
            .unwrap();
        assert!(
            matches!(&cleared, QuarantineOutcome::ClearedIncident(c)
                if c.state == WorkloadState::Eligible && c.generation == 1),
            "{cleared:?}"
        );
        assert!(matches!(
            store
                .quarantine_workload(
                    &recovered.workload_id,
                    "inc-new",
                    None,
                    "guardian:g",
                    1_790_000_500
                )
                .await
                .unwrap(),
            QuarantineOutcome::Latched(_)
        ));
    }

    #[tokio::test]
    async fn a_workload_without_a_swarm_stores_and_rebinds_without_one() {
        let Some(store) = local_store() else {
            return;
        };
        let w = AgentWorkload {
            swarm: String::new(),
            ..sample(Uuid::new_v4(), "onboarded", "did:key:z6MkA")
        };
        store.create_workload(&w).await.unwrap();
        assert_eq!(
            store
                .get_workload(&w.workload_id)
                .await
                .unwrap()
                .unwrap()
                .swarm,
            ""
        );
        let b = unique_did("B");
        rebind(&store, &w, &b, "", false, 1_790_000_100)
            .await
            .unwrap();
        let r = store.get_workload(&w.workload_id).await.unwrap().unwrap();
        assert_eq!(
            (r.current_did.as_str(), r.swarm.as_str(), r.generation),
            (b.as_str(), "", 2)
        );
        rebind(&store, &r, &b, "kit-7", false, 1_790_000_200)
            .await
            .unwrap();
        let r = store.get_workload(&w.workload_id).await.unwrap().unwrap();
        assert_eq!((r.swarm.as_str(), r.generation), ("kit-7", 3));
    }

    /// Latch `incident` on `wid`, returning the quarantined row.
    async fn latch(store: &DynamoDBStore, wid: &str, incident: &str) -> AgentWorkload {
        match store
            .quarantine_workload(wid, incident, Some("ev"), "owner:x", 1_790_000_100)
            .await
            .unwrap()
        {
            QuarantineOutcome::Latched(q) => q,
            other => panic!("expected Latched, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn recover_requires_the_latched_incident_and_revokes_the_delegation() {
        let Some(store) = local_store() else {
            return;
        };
        let owner = Uuid::new_v4();
        let did = unique_did("Rec");
        let w = sample(owner, "fleet", &did);
        store.create_workload(&w).await.unwrap();
        store
            .create_agent_delegation(&delegation(&did, owner, Some(w.workload_id.clone())))
            .await
            .unwrap();
        let q = latch(&store, &w.workload_id, "inc-1").await;

        assert!(
            matches!(
                store
                    .recover_workload(&q, "inc-2", true, 1_790_000_200)
                    .await,
                Err(DynamoDBError::ConditionalConflict)
            ),
            "the wrong incident"
        );
        assert!(
            matches!(
                store
                    .recover_workload(&w, "inc-1", true, 1_790_000_200)
                    .await,
                Err(DynamoDBError::ConditionalConflict)
            ),
            "a stale (pre-quarantine) snapshot"
        );
        assert!(
            store
                .get_agent_delegation(&did)
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none(),
            "a cancelled transaction revokes nothing"
        );

        store
            .recover_workload(&q, "inc-1", true, 1_790_000_300)
            .await
            .unwrap();
        let r = store.get_workload(&w.workload_id).await.unwrap().unwrap();
        assert_eq!(r.state, WorkloadState::Eligible);
        assert_eq!(r.current_did, "");
        assert_eq!(r.generation, 3);
        assert_eq!(r.incident, None);
        assert_eq!(r.evidence_ref, None);
        assert_eq!(r.quarantined_by, None);
        assert_eq!(r.quarantined_at, None);
        assert_eq!(r.last_cleared_incident.as_deref(), Some("inc-1"));
        assert!(
            store
                .get_agent_delegation(&did)
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
        assert!(
            matches!(
                store
                    .recover_workload(&q, "inc-1", true, 1_790_000_400)
                    .await,
                Err(DynamoDBError::ConditionalConflict)
            ),
            "a second recovery from the same snapshot"
        );
        assert_eq!(
            store
                .get_workload(&w.workload_id)
                .await
                .unwrap()
                .unwrap()
                .generation,
            3
        );
    }

    #[tokio::test]
    async fn recover_leaves_a_did_authorized_elsewhere_and_refuses_a_stale_nothing_to_revoke() {
        let Some(store) = local_store() else {
            return;
        };
        let owner = Uuid::new_v4();
        let did = unique_did("Moved");
        let w = sample(owner, "fleet", &did);
        store.create_workload(&w).await.unwrap();
        store
            .create_agent_delegation(&delegation(&did, owner, Some(w.workload_id.clone())))
            .await
            .unwrap();
        let q = latch(&store, &w.workload_id, "inc-1").await;

        // The caller decided there was nothing to revoke, but the DID still
        // holds a live delegation for this workload: refused.
        assert!(matches!(
            store
                .recover_workload(&q, "inc-1", false, 1_790_000_200)
                .await,
            Err(DynamoDBError::ConditionalConflict)
        ));

        // The DID's delegation was revoked and it has since been authorized
        // into another workload: recovery must not revoke that delegation
        // (P4), and must not be blocked by it.
        store.revoke_delegation(&did).await.unwrap();
        let elsewhere = workload_id_for(&owner, "other");
        store
            .create_agent_delegation(&delegation(&did, owner, Some(elsewhere.clone())))
            .await
            .unwrap();
        assert!(matches!(
            store
                .recover_workload(&q, "inc-1", true, 1_790_000_200)
                .await,
            Err(DynamoDBError::ConditionalConflict)
        ));
        store
            .recover_workload(&q, "inc-1", false, 1_790_000_300)
            .await
            .unwrap();
        let d = store.get_agent_delegation(&did).await.unwrap().unwrap();
        assert_eq!(d.workload_id, Some(elsewhere));
        assert!(d.revoked_at.is_none());
        assert_eq!(
            store
                .get_workload(&w.workload_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            WorkloadState::Eligible
        );
    }

    /// `Raced` is a quarantine whose conditional write failed against the
    /// latch and whose re-read then saw a recovery land. Hammer quarantine
    /// with a new incident while the old one is recovered until that
    /// interleaving happens; a retry then latches.
    #[tokio::test]
    async fn a_quarantine_racing_a_recovery_reports_raced_and_a_retry_latches() {
        let Some(store) = local_store() else {
            return;
        };
        let w = sample(Uuid::new_v4(), "fleet", "");
        store.create_workload(&w).await.unwrap();
        let wid = w.workload_id.as_str();
        let mut incident = 0u32;
        let mut raced = None;
        for _ in 0..40 {
            incident += 1;
            let latched = format!("inc-{incident}");
            let next = format!("inc-{}", incident + 1);
            let q = latch(&store, wid, &latched).await;
            let recover = store.recover_workload(&q, &latched, false, 1_790_000_200);
            let hammer = async {
                for _ in 0..1_000 {
                    match store
                        .quarantine_workload(wid, &next, None, "owner:x", 1_790_000_300)
                        .await
                        .unwrap()
                    {
                        QuarantineOutcome::OtherIncident(_) => continue,
                        other => return other,
                    }
                }
                panic!("the recovery never landed");
            };
            let (recovered, outcome) = tokio::join!(recover, hammer);
            recovered.unwrap();
            match outcome {
                QuarantineOutcome::Raced => {
                    raced = Some(next);
                    break;
                }
                // The hammer latched after the recovery: clear it and go again.
                QuarantineOutcome::Latched(q2) => {
                    incident += 1;
                    store
                        .recover_workload(&q2, &next, false, 1_790_000_400)
                        .await
                        .unwrap();
                }
                other => panic!("unexpected outcome {other:?}"),
            }
        }
        let next = raced.expect("no quarantine raced a recovery in 40 rounds");
        let after = store.get_workload(wid).await.unwrap().unwrap();
        assert_eq!(
            after.state,
            WorkloadState::Eligible,
            "Raced changed nothing"
        );
        assert!(matches!(
            store
                .quarantine_workload(wid, &next, None, "owner:x", 1_790_000_500)
                .await
                .unwrap(),
            QuarantineOutcome::Latched(_)
        ));
    }
}
