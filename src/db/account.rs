//! Account deletion (#88). The account's `credentials` row is replaced, in
//! one conditional put, by a tombstone that carries no username, passkey,
//! DID, DID log or entitlement: from that write on, the account no longer
//! exists for any read path ([`DynamoDBStore::get_user_by_id`] reports a
//! tombstone as absent, and without `username` the row drops out of the
//! `username-index` GSI, freeing the name). The tombstone keeps only the
//! `user_id`, the deletion's id and its progress, which the status endpoint
//! reports and which refuses the account's still-unexpired tokens.
//!
//! Everything else bound to the account lives in other tables and is removed
//! by the sweep (`account::sweep`) through the methods below. Each is
//! idempotent, so a sweep that fails part-way is simply run again.

use super::agent_state::{classify, n, s};
use super::{DynamoDBError, DynamoDBStore};
use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;
use uuid::Uuid;

/// Present only on a tombstone; its presence is what makes a row one.
pub(crate) const DELETED_AT: &str = "deleted_at";
/// The condition every write to a live account's row carries, so nothing
/// written after the tombstone can land on it (or recreate the row).
pub(crate) const LIVE_ROW: &str = "attribute_exists(user_id) AND attribute_not_exists(deleted_at)";

/// Progress of a deletion, as stored and as the status endpoint reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeletionState {
    /// The account is gone; the sweep of the data bound to it is still to
    /// run (or running, or being retried).
    Pending,
    /// The sweep ran out of retries. The account itself stays deleted; an
    /// operator must look at the logs (the sweep also resumes at startup).
    Failed,
    /// Everything bound to the account has been removed.
    Completed,
}

impl DeletionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Failed => "failed",
            Self::Completed => "completed",
        }
    }

    fn parse(v: &str) -> Option<Self> {
        match v {
            "pending" => Some(Self::Pending),
            "failed" => Some(Self::Failed),
            "completed" => Some(Self::Completed),
            _ => None,
        }
    }
}

/// A tombstone, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountDeletion {
    pub user_id: Uuid,
    pub deletion_id: String,
    pub state: DeletionState,
    pub deleted_at: i64,
    pub completed_at: Option<i64>,
    pub attempts: u32,
    /// The handle row to remove (`<username>.arkavo.social`). Held only until
    /// the sweep completes, since it names the deleted username.
    pub handle: Option<String>,
}

/// Outcome of [`DynamoDBStore::tombstone_account`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tombstoned {
    /// This call deleted the account.
    Created(AccountDeletion),
    /// The account had already been deleted; this is that deletion.
    AlreadyDeleted(AccountDeletion),
    /// No row for this user at all.
    NotFound,
}

fn parse_tombstone(item: &HashMap<String, AttributeValue>) -> Option<AccountDeletion> {
    let text = |k: &str| item.get(k).and_then(|v| v.as_s().ok()).cloned();
    let num = |k: &str| {
        item.get(k)
            .and_then(|v| v.as_n().ok())
            .and_then(|v| v.parse::<i64>().ok())
    };
    Some(AccountDeletion {
        user_id: Uuid::parse_str(&text("user_id")?).ok()?,
        deletion_id: text("deletion_id")?,
        // An unreadable state reads as pending: the sweep runs again rather
        // than the deletion being reported done.
        state: text("deletion_state")
            .and_then(|v| DeletionState::parse(&v))
            .unwrap_or(DeletionState::Pending),
        deleted_at: num(DELETED_AT)?,
        completed_at: num("deletion_completed_at"),
        attempts: num("deletion_attempts").unwrap_or(0).max(0) as u32,
        handle: text("deletion_handle"),
    })
}

/// Is this credentials item a tombstone?
pub(crate) fn is_tombstone(item: &HashMap<String, AttributeValue>) -> bool {
    item.contains_key(DELETED_AT)
}

impl DynamoDBStore {
    /// Does this account exist (and is it not deleted)? Every path that acts
    /// on a token alone checks this: the account's tokens outlive it.
    pub async fn is_account_live(&self, user_id: &Uuid) -> Result<bool, DynamoDBError> {
        Ok(self.get_user_by_id(user_id).await?.is_some())
    }

    /// Delete the account: replace its row with a tombstone, conditional on
    /// the row existing and not being one already. A repeat returns the
    /// first deletion, so a retried request reports the same `deletion_id`.
    pub async fn tombstone_account(
        &self,
        user_id: &Uuid,
        deletion_id: &str,
        handle: Option<&str>,
        now: i64,
    ) -> Result<Tombstoned, DynamoDBError> {
        let mut put = self
            .client
            .put_item()
            .table_name(&self.credentials_table)
            .item("user_id", s(&user_id.to_string()))
            .item(DELETED_AT, n(now))
            .item("deletion_id", s(deletion_id))
            .item("deletion_state", s(DeletionState::Pending.as_str()))
            .item("deletion_attempts", n(0))
            .condition_expression(LIVE_ROW);
        if let Some(h) = handle {
            put = put.item("deletion_handle", s(h));
        }
        match put.send().await {
            Ok(_) => Ok(Tombstoned::Created(AccountDeletion {
                user_id: *user_id,
                deletion_id: deletion_id.to_string(),
                state: DeletionState::Pending,
                deleted_at: now,
                completed_at: None,
                attempts: 0,
                handle: handle.map(str::to_string),
            })),
            Err(e) => match classify(e, &self.credentials_table) {
                DynamoDBError::ConditionalConflict => {
                    match self.get_account_deletion(user_id).await? {
                        Some(d) => Ok(Tombstoned::AlreadyDeleted(d)),
                        None if self.get_user_by_id(user_id).await?.is_none() => {
                            Ok(Tombstoned::NotFound)
                        }
                        // The row is live, so the condition failed for a
                        // reason that has since gone away. Report the race.
                        None => Err(DynamoDBError::ConditionalConflict),
                    }
                }
                other => Err(other),
            },
        }
    }

    /// The account's deletion, if it has been deleted. Strongly consistent.
    pub async fn get_account_deletion(
        &self,
        user_id: &Uuid,
    ) -> Result<Option<AccountDeletion>, DynamoDBError> {
        let out = self
            .client
            .get_item()
            .table_name(&self.credentials_table)
            .key("user_id", s(&user_id.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| classify(e, &self.credentials_table))?;
        Ok(out
            .item
            .filter(is_tombstone)
            .and_then(|i| parse_tombstone(&i)))
    }

    /// Every deletion whose sweep has not completed (pending or failed), for
    /// resuming at startup. A paginated scan of `credentials`; deletions are
    /// rare and the table is small.
    pub async fn list_unfinished_deletions(&self) -> Result<Vec<AccountDeletion>, DynamoDBError> {
        let mut out = Vec::new();
        let mut start = None;
        loop {
            let page = self
                .client
                .scan()
                .table_name(&self.credentials_table)
                .filter_expression("attribute_exists(#d) AND deletion_state <> :done")
                .expression_attribute_names("#d", DELETED_AT)
                .expression_attribute_values(":done", s(DeletionState::Completed.as_str()))
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(|e| classify(e, &self.credentials_table))?;
            out.extend(page.items().iter().filter_map(parse_tombstone));
            match page.last_evaluated_key {
                Some(k) => start = Some(k),
                None => break,
            }
        }
        Ok(out)
    }

    /// Record a sweep that finished: the deletion is complete and the
    /// remembered handle (the deleted username) is dropped.
    pub async fn complete_account_deletion(
        &self,
        user_id: &Uuid,
        now: i64,
    ) -> Result<(), DynamoDBError> {
        self.client
            .update_item()
            .table_name(&self.credentials_table)
            .key("user_id", s(&user_id.to_string()))
            .condition_expression("attribute_exists(#d)")
            .update_expression(
                "SET deletion_state = :done, deletion_completed_at = :now REMOVE deletion_handle",
            )
            .expression_attribute_names("#d", DELETED_AT)
            .expression_attribute_values(":done", s(DeletionState::Completed.as_str()))
            .expression_attribute_values(":now", n(now))
            .send()
            .await
            .map_err(|e| classify(e, &self.credentials_table))?;
        Ok(())
    }

    /// Record a sweep that failed: one more attempt, and `failed` once
    /// `give_up` is reached. Returns the new attempt count.
    pub async fn record_deletion_failure(
        &self,
        user_id: &Uuid,
        give_up: u32,
    ) -> Result<u32, DynamoDBError> {
        let out = self
            .client
            .update_item()
            .table_name(&self.credentials_table)
            .key("user_id", s(&user_id.to_string()))
            .condition_expression("attribute_exists(#d) AND deletion_state <> :done")
            .update_expression(
                "SET deletion_attempts = if_not_exists(deletion_attempts, :zero) + :one",
            )
            .expression_attribute_names("#d", DELETED_AT)
            .expression_attribute_values(":done", s(DeletionState::Completed.as_str()))
            .expression_attribute_values(":zero", n(0))
            .expression_attribute_values(":one", n(1))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::UpdatedNew)
            .send()
            .await
            .map_err(|e| classify(e, &self.credentials_table))?;
        let attempts = out
            .attributes()
            .and_then(|a| a.get("deletion_attempts"))
            .and_then(|v| v.as_n().ok())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(give_up);
        if attempts >= give_up {
            self.client
                .update_item()
                .table_name(&self.credentials_table)
                .key("user_id", s(&user_id.to_string()))
                .condition_expression("attribute_exists(#d) AND deletion_state <> :done")
                .update_expression("SET deletion_state = :failed")
                .expression_attribute_names("#d", DELETED_AT)
                .expression_attribute_values(":done", s(DeletionState::Completed.as_str()))
                .expression_attribute_values(":failed", s(DeletionState::Failed.as_str()))
                .send()
                .await
                .map_err(|e| classify(e, &self.credentials_table))?;
        }
        Ok(attempts)
    }

    /// Remove the account's Patreon link row: the sealed access and refresh
    /// tokens and the KMS-wrapped key that seals them. Patreon offers no
    /// token revocation, so this is the server's whole copy.
    pub async fn delete_patreon_link(&self, user_id: &Uuid) -> Result<(), DynamoDBError> {
        self.client
            .delete_item()
            .table_name(&self.patreon_tokens_table)
            .key("user_id", s(&user_id.to_string()))
            .send()
            .await
            .map_err(|e| classify(e, &self.patreon_tokens_table))?;
        Ok(())
    }

    /// Remove the handle row, only while it is still the deleted account's
    /// (the name is free the moment the account is deleted, and a new owner
    /// may already have claimed it).
    pub async fn delete_handle_if_owned(
        &self,
        handle: &str,
        user_id: &Uuid,
    ) -> Result<(), DynamoDBError> {
        let result = self
            .client
            .delete_item()
            .table_name(&self.handles_table)
            .key("handle", s(&handle.to_lowercase()))
            .condition_expression("user_id = :uid")
            .expression_attribute_values(":uid", s(&user_id.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) => match classify(e, &self.handles_table) {
                // Absent, or someone else's now: nothing of ours to remove.
                DynamoDBError::ConditionalConflict => Ok(()),
                other => Err(other),
            },
        }
    }

    /// Delete every row of `table` whose `user_id` attribute is this account.
    /// `identity_links` and `device_bindings` have no index on `user_id`, so
    /// this is a paginated scan; each delete is conditional on the row still
    /// naming the account. Returns how many rows were removed.
    async fn delete_rows_owned_by(
        &self,
        table: &str,
        key: &str,
        user_id: &Uuid,
    ) -> Result<u32, DynamoDBError> {
        let uid = s(&user_id.to_string());
        let mut removed = 0;
        let mut start = None;
        loop {
            let page = self
                .client
                .scan()
                .table_name(table)
                .filter_expression("user_id = :uid")
                .projection_expression("#k")
                .expression_attribute_names("#k", key)
                .expression_attribute_values(":uid", uid.clone())
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(|e| classify(e, table))?;
            for item in page.items() {
                let Some(k) = item.get(key) else { continue };
                let result = self
                    .client
                    .delete_item()
                    .table_name(table)
                    .key(key, k.clone())
                    .condition_expression("user_id = :uid")
                    .expression_attribute_values(":uid", uid.clone())
                    .send()
                    .await;
                match result {
                    Ok(_) => removed += 1,
                    Err(e) => match classify(e, table) {
                        DynamoDBError::ConditionalConflict => {}
                        other => return Err(other),
                    },
                }
            }
            match page.last_evaluated_key {
                Some(k) => start = Some(k),
                None => break,
            }
        }
        Ok(removed)
    }

    /// Remove every Apple, Google and Patreon identity link of the account.
    pub async fn delete_identity_links_of(&self, user_id: &Uuid) -> Result<u32, DynamoDBError> {
        let table = self.identity_links_table.clone();
        self.delete_rows_owned_by(&table, "link_pk", user_id).await
    }

    /// Remove every App Attest device binding of the account.
    pub async fn delete_device_bindings_of(&self, user_id: &Uuid) -> Result<u32, DynamoDBError> {
        let table = self.device_bindings_table.clone();
        self.delete_rows_owned_by(&table, "device_id", user_id)
            .await
    }

    /// Revoke every agent delegation rooted at the account (and, through the
    /// existing cascade, any delegation chained under one), and strip what
    /// names the person: the owner's username and the agent's label. The rows
    /// stay, revoked, because a row is the agent key's identity — deleting it
    /// would let a quarantined or recovered key be authorized afresh.
    pub async fn revoke_and_scrub_delegations_of(
        &self,
        user_id: &Uuid,
        now: i64,
    ) -> Result<u32, DynamoDBError> {
        let table = &self.agent_delegations_table;
        let mut dids = Vec::new();
        let mut start = None;
        loop {
            let page = self
                .client
                .query()
                .table_name(table)
                .index_name("root_user_id-index")
                .key_condition_expression("root_user_id = :uid")
                .expression_attribute_values(":uid", s(&user_id.to_string()))
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(|e| classify(e, table))?;
            dids.extend(
                page.items()
                    .iter()
                    .filter_map(|i| i.get("agent_did").and_then(|v| v.as_s().ok()).cloned()),
            );
            match page.last_evaluated_key {
                Some(k) => start = Some(k),
                None => break,
            }
        }
        for did in &dids {
            // A newly revoked row moves `state_version`, as every revocation
            // does; an already revoked one keeps it (a repeated sweep is not
            // a state change).
            let revoke = self
                .client
                .update_item()
                .table_name(table)
                .key("agent_did", s(did))
                .condition_expression(
                    "attribute_exists(agent_did) AND attribute_not_exists(revoked_at)",
                )
                .update_expression(
                    "SET revoked_at = :now, \
                     state_version = if_not_exists(state_version, :zero) + :one",
                )
                .expression_attribute_values(":now", n(now))
                .expression_attribute_values(":zero", n(0))
                .expression_attribute_values(":one", n(1))
                .send()
                .await;
            match revoke {
                Ok(_) => {}
                Err(e) => match classify(e, table) {
                    DynamoDBError::ConditionalConflict => {}
                    other => return Err(other),
                },
            }
            self.client
                .update_item()
                .table_name(table)
                .key("agent_did", s(did))
                .condition_expression("attribute_exists(agent_did)")
                .update_expression(
                    "SET #nm = :empty \
                     REMOVE delegator_username, challenge, challenge_nonce, challenge_issued_at",
                )
                .expression_attribute_names("#nm", "name")
                .expression_attribute_values(":empty", s(""))
                .send()
                .await
                .map_err(|e| classify(e, table))?;
            self.revoke_delegations_with_chain(did).await?;
        }
        Ok(dids.len() as u32)
    }

    /// Revoke every Guardian the account enrolled and clear its label. The
    /// rows stay (revocation is a marker, never a delete), so a Guardian key
    /// can still never re-enroll.
    pub async fn revoke_and_scrub_guardians_of(
        &self,
        user_id: &Uuid,
        now: i64,
    ) -> Result<u32, DynamoDBError> {
        let table = &self.guardians_table;
        let owner = s(&user_id.to_string());
        let mut ids = Vec::new();
        let mut start = None;
        loop {
            let page = self
                .client
                .scan()
                .table_name(table)
                .filter_expression("#o = :owner")
                .projection_expression("guardian_id")
                .expression_attribute_names("#o", "owner")
                .expression_attribute_values(":owner", owner.clone())
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(|e| classify(e, table))?;
            ids.extend(
                page.items()
                    .iter()
                    .filter_map(|i| i.get("guardian_id").and_then(|v| v.as_s().ok()).cloned()),
            );
            match page.last_evaluated_key {
                Some(k) => start = Some(k),
                None => break,
            }
        }
        for id in &ids {
            self.client
                .update_item()
                .table_name(table)
                .key("guardian_id", s(id))
                .condition_expression("attribute_exists(guardian_id) AND #o = :owner")
                .update_expression("SET revoked_at = if_not_exists(revoked_at, :now), #nm = :empty")
                .expression_attribute_names("#o", "owner")
                .expression_attribute_names("#nm", "name")
                .expression_attribute_values(":owner", owner.clone())
                .expression_attribute_values(":now", n(now))
                .expression_attribute_values(":empty", s(""))
                .send()
                .await
                .map_err(|e| classify(e, table))?;
        }
        Ok(ids.len() as u32)
    }
}

#[cfg(test)]
impl DynamoDBStore {
    /// The `user_id` a handle row names, if the row exists.
    pub(crate) async fn handle_owner(&self, handle: &str) -> Option<String> {
        self.client
            .get_item()
            .table_name(&self.handles_table)
            .key("handle", s(&handle.to_lowercase()))
            .consistent_read(true)
            .send()
            .await
            .unwrap()
            .item?
            .get("user_id")?
            .as_s()
            .ok()
            .cloned()
    }

    /// The raw `credentials` item, tombstone or not.
    pub(crate) async fn raw_credentials_item(
        &self,
        user_id: &Uuid,
    ) -> Option<HashMap<String, AttributeValue>> {
        self.client
            .get_item()
            .table_name(&self.credentials_table)
            .key("user_id", s(&user_id.to_string()))
            .consistent_read(true)
            .send()
            .await
            .unwrap()
            .item
    }
}
