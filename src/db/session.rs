//! Passkey sessions (#108): one `identity_links` row per session,
//! `link_pk = session#<session id>`, `provider = session`. A session belongs
//! to an account, not to an identity, but its rows follow the `passkey#` and
//! `appstore#` precedent (no new table), and the account-deletion sweep's
//! link step deletes them with the account's other link rows. No sign-in
//! path reads them: `identity::resolve_linked_account` is only called with
//! the literal providers `apple` and `google`.
//!
//! `expires_at` (= `assertion_at + SESSION_MAX_SECONDS`) is written so that
//! enabling a DynamoDB TTL on the table later needs no code change; until
//! then an ended session is deleted when a renewal is refused.

use super::agent_state::{classify, n, s};
use super::{DynamoDBError, DynamoDBStore};
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;
use uuid::Uuid;

/// `provider` of a session row.
pub(crate) const SESSION_PROVIDER: &str = "session";

fn link_pk(session_id: &Uuid) -> String {
    format!("{SESSION_PROVIDER}#{session_id}")
}

/// A stored session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub session_id: Uuid,
    pub user_id: Uuid,
    /// The device key: a 65-byte uncompressed X9.63 P-256 point.
    pub public_key: Vec<u8>,
    /// When the passkey assertion that opened the session happened.
    pub assertion_at: i64,
    pub last_renewed_at: i64,
    /// The generation of the current credential; +1 on every renewal.
    pub generation: u64,
    /// SHA-256 of the current credential string.
    pub credential_hash: Vec<u8>,
}

/// Outcome of [`DynamoDBStore::open_session`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOpened {
    Opened,
    /// A row with this id exists: the token already opened a session.
    Exists,
}

fn num(item: &HashMap<String, AttributeValue>, k: &str) -> Result<i64, DynamoDBError> {
    item.get(k)
        .and_then(|v| v.as_n().ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| DynamoDBError::Internal(format!("session row has no {k}")))
}

fn bytes(item: &HashMap<String, AttributeValue>, k: &str) -> Result<Vec<u8>, DynamoDBError> {
    item.get(k)
        .and_then(|v| v.as_b().ok())
        .map(|b| b.as_ref().to_vec())
        .ok_or_else(|| DynamoDBError::Internal(format!("session row has no {k}")))
}

impl DynamoDBStore {
    /// Write a new session row. Never overwrites one.
    pub async fn open_session(
        &self,
        session: &Session,
        now: i64,
    ) -> Result<SessionOpened, DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .put_item()
            .table_name(table)
            .item("link_pk", s(&link_pk(&session.session_id)))
            .item("provider", s(SESSION_PROVIDER))
            .item("subject", s(&session.session_id.to_string()))
            .item("user_id", s(&session.user_id.to_string()))
            .item(
                "public_key",
                AttributeValue::B(Blob::new(session.public_key.clone())),
            )
            .item("assertion_at", n(session.assertion_at))
            .item("created_at", n(now))
            .item("last_renewed_at", n(session.last_renewed_at))
            .item("generation", n(session.generation))
            .item(
                "credential_hash",
                AttributeValue::B(Blob::new(session.credential_hash.clone())),
            )
            .item(
                "expires_at",
                n(session.assertion_at + crate::constants::SESSION_MAX_SECONDS),
            )
            .condition_expression("attribute_not_exists(link_pk)")
            .send()
            .await;
        match result {
            Ok(_) => Ok(SessionOpened::Opened),
            Err(e) => match classify(e, table) {
                DynamoDBError::ConditionalConflict => Ok(SessionOpened::Exists),
                other => Err(other),
            },
        }
    }

    /// A session by id. Strongly consistent.
    pub async fn get_session(&self, session_id: &Uuid) -> Result<Option<Session>, DynamoDBError> {
        let table = &self.identity_links_table;
        let item = self
            .client
            .get_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(session_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| self.map_get_item_err(table, e))?
            .item;
        let Some(item) = item else { return Ok(None) };
        let user_id = item
            .get("user_id")
            .and_then(|v| v.as_s().ok())
            .ok_or_else(|| DynamoDBError::Internal("session row has no user_id".into()))?;
        Ok(Some(Session {
            session_id: *session_id,
            user_id: Uuid::parse_str(user_id)?,
            public_key: bytes(&item, "public_key")?,
            assertion_at: num(&item, "assertion_at")?,
            last_renewed_at: num(&item, "last_renewed_at")?,
            generation: u64::try_from(num(&item, "generation")?)
                .map_err(|_| DynamoDBError::Internal("negative session generation".into()))?,
            credential_hash: bytes(&item, "credential_hash")?,
        }))
    }

    /// Rotate the credential: one conditional write on the generation and
    /// hash the caller presented. `false` when the condition failed (the
    /// session was renewed or deleted meanwhile); the caller re-reads.
    pub async fn rotate_session(
        &self,
        session_id: &Uuid,
        from_generation: u64,
        from_hash: &[u8],
        new_hash: &[u8],
        now: i64,
    ) -> Result<bool, DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .update_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(session_id)))
            .update_expression(
                "SET generation = :next, credential_hash = :new, last_renewed_at = :now",
            )
            .condition_expression(
                "attribute_exists(link_pk) AND generation = :gen AND credential_hash = :old",
            )
            .expression_attribute_values(":gen", n(from_generation))
            .expression_attribute_values(":next", n(from_generation + 1))
            .expression_attribute_values(":old", AttributeValue::B(Blob::new(from_hash.to_vec())))
            .expression_attribute_values(":new", AttributeValue::B(Blob::new(new_hash.to_vec())))
            .expression_attribute_values(":now", n(now))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(e) => match classify(e, table) {
                DynamoDBError::ConditionalConflict => Ok(false),
                other => Err(other),
            },
        }
    }

    /// End a session. Idempotent.
    pub async fn delete_session(&self, session_id: &Uuid) -> Result<(), DynamoDBError> {
        let table = &self.identity_links_table;
        self.client
            .delete_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(session_id)))
            .send()
            .await
            .map(|_| ())
            .map_err(|e| classify(e, table))
    }
}
