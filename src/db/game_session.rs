//! Game sessions (#151): one `identity_links` row per game session,
//! `link_pk = game-session#<game session id>`, `provider = game-session`.
//! Like a passkey session's row (`db::session`) it belongs to an account and
//! carries `user_id`, so the account-deletion sweep's link step deletes it.
//!
//! A game session is never written after it is opened: it has no credential
//! and no idle clock. `expires_at` (= `assertion_at + GAME_SESSION_SECONDS`)
//! is written for a future DynamoDB TTL; until then a row past its deadline
//! stays (and is refused) until sign-out or account deletion removes it.

use super::agent_state::{classify, n, s};
use super::{DynamoDBError, DynamoDBStore};
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::AttributeValue;
use uuid::Uuid;

/// `provider` of a game session row.
pub(crate) const GAME_SESSION_PROVIDER: &str = "game-session";

fn link_pk(game_session_id: &Uuid) -> String {
    format!("{GAME_SESSION_PROVIDER}#{game_session_id}")
}

/// A stored game session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameSession {
    pub game_session_id: Uuid,
    pub user_id: Uuid,
    /// The device key of the passkey session that opened it: a 65-byte
    /// uncompressed X9.63 P-256 point.
    pub public_key: Vec<u8>,
    /// When the passkey assertion behind that session happened. The
    /// deadline counts from here, never from the open.
    pub assertion_at: i64,
}

impl DynamoDBStore {
    /// Write a game session row unless one with this id exists. The id is
    /// derived from the passkey session, so an existing row is the same
    /// game session and the open is idempotent.
    pub async fn open_game_session(
        &self,
        session: &GameSession,
        now: i64,
    ) -> Result<(), DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .put_item()
            .table_name(table)
            .item("link_pk", s(&link_pk(&session.game_session_id)))
            .item("provider", s(GAME_SESSION_PROVIDER))
            .item("subject", s(&session.game_session_id.to_string()))
            .item("user_id", s(&session.user_id.to_string()))
            .item(
                "public_key",
                AttributeValue::B(Blob::new(session.public_key.clone())),
            )
            .item("assertion_at", n(session.assertion_at))
            .item("created_at", n(now))
            .item(
                "expires_at",
                n(session.assertion_at + crate::constants::GAME_SESSION_SECONDS),
            )
            .condition_expression("attribute_not_exists(link_pk)")
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) => match classify(e, table) {
                DynamoDBError::ConditionalConflict => Ok(()),
                other => Err(other),
            },
        }
    }

    /// A game session by id. Strongly consistent.
    pub async fn get_game_session(
        &self,
        game_session_id: &Uuid,
    ) -> Result<Option<GameSession>, DynamoDBError> {
        let table = &self.identity_links_table;
        let item = self
            .client
            .get_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(game_session_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| self.map_get_item_err(table, e))?
            .item;
        let Some(item) = item else { return Ok(None) };
        let missing = |k: &str| DynamoDBError::Internal(format!("game session row has no {k}"));
        let user_id = item
            .get("user_id")
            .and_then(|v| v.as_s().ok())
            .ok_or_else(|| missing("user_id"))?;
        Ok(Some(GameSession {
            game_session_id: *game_session_id,
            user_id: Uuid::parse_str(user_id)?,
            public_key: item
                .get("public_key")
                .and_then(|v| v.as_b().ok())
                .map(|b| b.as_ref().to_vec())
                .ok_or_else(|| missing("public_key"))?,
            assertion_at: item
                .get("assertion_at")
                .and_then(|v| v.as_n().ok())
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| missing("assertion_at"))?,
        }))
    }

    /// End a game session. Idempotent.
    pub async fn delete_game_session(&self, game_session_id: &Uuid) -> Result<(), DynamoDBError> {
        let table = &self.identity_links_table;
        self.client
            .delete_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(game_session_id)))
            .send()
            .await
            .map(|_| ())
            .map_err(|e| classify(e, table))
    }
}
