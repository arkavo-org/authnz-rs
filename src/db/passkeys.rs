//! The passkey → account index behind credential attestations (#104).
//!
//! `GET /passkeys/credentials/:id/status` is keyed by credential id alone, and
//! the `credentials` table is keyed by account, so the index is an
//! `identity_links` row: `link_pk = passkey#<base64url credential id>`,
//! `provider = passkey`. It is written the first time the account asks for an
//! attestation of the credential (so passkeys registered before #104 are
//! covered on demand), never deleted, and revoked (`revoked_at`) when the
//! credential is removed. No sign-in path reads it: `identity::resolve_linked_account`
//! is only called with the literal providers `apple` and `google`.

use super::account::is_tombstone;
use super::agent_state::{classify, n, s};
use super::{DynamoDBError, DynamoDBStore};
use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;
use uuid::Uuid;

/// `provider` of a passkey index row.
pub(crate) const PASSKEY_PROVIDER: &str = "passkey";

/// Condition (and scan filter) that leaves passkey index rows out, with its
/// one value. Account deletion revokes them instead of deleting them.
pub(super) const NOT_PASSKEY: &str = "(attribute_not_exists(provider) OR provider <> :passkey)";
pub(super) fn not_passkey_value() -> (&'static str, AttributeValue) {
    (":passkey", s(PASSKEY_PROVIDER))
}

fn link_pk(credential_id: &str) -> String {
    format!("{PASSKEY_PROVIDER}#{credential_id}")
}

/// Outcome of [`DynamoDBStore::link_passkey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyLinked {
    /// The row names this account and is not revoked (new or already there).
    Linked,
    /// The credential was revoked: it was removed from this account.
    Revoked,
    /// The row names a different account.
    OtherAccount,
}

/// What `GET /passkeys/credentials/:id/status` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyStatus {
    pub user_id: Uuid,
    pub revoked: bool,
    /// When it was revoked, if known: the row's `revoked_at`, else the
    /// deletion time of the account it belonged to.
    pub revoked_at: Option<i64>,
}

fn num(item: &HashMap<String, AttributeValue>, k: &str) -> Option<i64> {
    item.get(k)?.as_n().ok()?.parse().ok()
}

impl DynamoDBStore {
    /// Record that `credential_id` (canonical base64url, no padding) belongs
    /// to `user_id`. Idempotent; never repoints a row or revives a revoked one.
    pub async fn link_passkey(
        &self,
        user_id: &Uuid,
        credential_id: &str,
        now: i64,
    ) -> Result<PasskeyLinked, DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .update_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(credential_id)))
            .update_expression(
                "SET user_id = :uid, provider = :p, subject = :sub, \
                 linked_at = if_not_exists(linked_at, :now)",
            )
            .condition_expression(
                "attribute_not_exists(link_pk) OR \
                 (user_id = :uid AND attribute_not_exists(revoked_at))",
            )
            .expression_attribute_values(":uid", s(&user_id.to_string()))
            .expression_attribute_values(":p", s(PASSKEY_PROVIDER))
            .expression_attribute_values(":sub", s(credential_id))
            .expression_attribute_values(":now", n(now))
            .send()
            .await;
        match result {
            Ok(_) => Ok(PasskeyLinked::Linked),
            Err(e) => match classify(e, table) {
                DynamoDBError::ConditionalConflict => {
                    match self.get_passkey_link(credential_id).await? {
                        Some((owner, _)) if owner != *user_id => Ok(PasskeyLinked::OtherAccount),
                        Some((_, Some(_))) => Ok(PasskeyLinked::Revoked),
                        // The row changed between the write and the read.
                        _ => Err(DynamoDBError::ConditionalConflict),
                    }
                }
                other => Err(other),
            },
        }
    }

    /// The account a credential's index row names, and its `revoked_at`.
    /// Strongly consistent.
    async fn get_passkey_link(
        &self,
        credential_id: &str,
    ) -> Result<Option<(Uuid, Option<i64>)>, DynamoDBError> {
        let table = &self.identity_links_table;
        let item = self
            .client
            .get_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(credential_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| self.map_get_item_err(table, e))?
            .item;
        let Some(item) = item else { return Ok(None) };
        let user_id = item
            .get("user_id")
            .and_then(|v| v.as_s().ok())
            .ok_or_else(|| DynamoDBError::Internal("passkey link has no user_id".into()))?;
        Ok(Some((Uuid::parse_str(user_id)?, num(&item, "revoked_at"))))
    }

    /// Whether a credential is revoked. `None` for a credential no
    /// attestation was ever issued for. Revoked when the index row says so,
    /// when the account has been deleted (from the tombstone on, before the
    /// sweep marks the row), or when the account no longer holds the
    /// credential.
    pub async fn passkey_status(
        &self,
        credential_id: &str,
        credential_id_bytes: &[u8],
    ) -> Result<Option<PasskeyStatus>, DynamoDBError> {
        let Some((user_id, revoked_at)) = self.get_passkey_link(credential_id).await? else {
            return Ok(None);
        };
        if revoked_at.is_some() {
            return Ok(Some(PasskeyStatus {
                user_id,
                revoked: true,
                revoked_at,
            }));
        }
        let item = self
            .client
            .get_item()
            .table_name(&self.credentials_table)
            .key("user_id", s(&user_id.to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| self.map_get_item_err(&self.credentials_table, e))?
            .item;
        let (revoked, revoked_at) = match item {
            Some(item) if is_tombstone(&item) => (true, num(&item, super::account::DELETED_AT)),
            Some(item) => {
                let user = self.item_to_user_credentials(&item)?;
                let held = user
                    .credentials
                    .iter()
                    .any(|p| p.cred_id().as_ref() == credential_id_bytes);
                (!held, None)
            }
            None => (true, None),
        };
        Ok(Some(PasskeyStatus {
            user_id,
            revoked,
            revoked_at,
        }))
    }

    /// Revoke every passkey index row of a deleted account, as of `at` (its
    /// deletion time, so the status route reports one `revokedAt` before and
    /// after the sweep). The rows stay. Returns how many were marked.
    pub async fn revoke_passkey_links_of(
        &self,
        user_id: &Uuid,
        at: i64,
    ) -> Result<u32, DynamoDBError> {
        let table = self.identity_links_table.clone();
        let uid = s(&user_id.to_string());
        let mut marked = 0;
        let mut start = None;
        loop {
            let page = self
                .client
                .scan()
                .table_name(&table)
                .filter_expression("user_id = :uid AND provider = :p")
                .projection_expression("link_pk")
                .expression_attribute_values(":uid", uid.clone())
                .expression_attribute_values(":p", s(PASSKEY_PROVIDER))
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(|e| classify(e, &table))?;
            for item in page.items() {
                let Some(k) = item.get("link_pk") else {
                    continue;
                };
                let result = self
                    .client
                    .update_item()
                    .table_name(&table)
                    .key("link_pk", k.clone())
                    .update_expression("SET revoked_at = if_not_exists(revoked_at, :at)")
                    .condition_expression("user_id = :uid")
                    .expression_attribute_values(":uid", uid.clone())
                    .expression_attribute_values(":at", n(at))
                    .send()
                    .await;
                match result {
                    Ok(_) => marked += 1,
                    Err(e) => match classify(e, &table) {
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
        Ok(marked)
    }
}
