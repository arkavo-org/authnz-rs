//! Sign in with Apple refresh tokens held for revocation (the `apple_tokens`
//! table). There is one row per linked Apple identity, keyed by its
//! identity-link key `apple#<sub>`, holding the token sealed by the Patreon
//! KMS envelope. `POST /oauth/apple/link` writes the rows; the
//! account-deletion sweep removes each one after Apple revoked its token.

use super::agent_state::{classify, n, s};
use super::{DynamoDBError, DynamoDBStore};
use crate::apple_tokens::AppleTokenRow;
use crate::patreon::SealedToken;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::AttributeValue;
use log::{error, warn};
use std::collections::HashMap;
use uuid::Uuid;

fn parse_row(item: &HashMap<String, AttributeValue>) -> Option<AppleTokenRow> {
    let text = |k: &str| item.get(k).and_then(|v| v.as_s().ok()).cloned();
    let bytes = |k: &str| {
        item.get(k)
            .and_then(|v| v.as_b().ok())
            .map(|b| b.as_ref().to_vec())
    };
    Some(AppleTokenRow {
        link_key: text("link_key")?,
        user_id: Uuid::parse_str(&text("user_id")?).ok()?,
        client_id: text("client_id")?,
        sealed: SealedToken {
            wrapped_dek: bytes("wrapped_dek")?,
            nonce: bytes("token_nonce")?,
            ciphertext: bytes("token_ct")?,
        },
        stored_at: item
            .get("stored_at")
            .and_then(|v| v.as_n().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    })
}

impl DynamoDBStore {
    /// Keep Apple refresh tokens in `table` (`DYNAMODB_APPLE_TOKENS_TABLE`).
    pub fn with_apple_tokens_table(mut self, table: String) -> Self {
        self.apple_tokens_table = table;
        self
    }

    /// Store a sealed refresh token for an Apple identity, replacing any row
    /// for the same identity (a re-link). The replaced token is not revoked:
    /// Apple's revoke is authorization-wide, so it would also end the token
    /// just stored.
    pub async fn put_apple_token(&self, row: &AppleTokenRow) -> Result<(), DynamoDBError> {
        let table = &self.apple_tokens_table;
        self.client
            .put_item()
            .table_name(table)
            .item("link_key", s(&row.link_key))
            .item("user_id", s(&row.user_id.to_string()))
            .item("client_id", s(&row.client_id))
            .item(
                "wrapped_dek",
                AttributeValue::B(Blob::new(row.sealed.wrapped_dek.clone())),
            )
            .item(
                "token_nonce",
                AttributeValue::B(Blob::new(row.sealed.nonce.clone())),
            )
            .item(
                "token_ct",
                AttributeValue::B(Blob::new(row.sealed.ciphertext.clone())),
            )
            .item("stored_at", n(row.stored_at))
            .send()
            .await
            .map_err(|e| classify(e, table))?;
        Ok(())
    }

    /// Every stored Apple token of the account. A paginated, consistent scan
    /// (no `user_id` index; deletions are rare). A missing table holds none.
    /// An unreadable row is logged and left in place.
    pub async fn apple_tokens_of(
        &self,
        user_id: &Uuid,
    ) -> Result<Vec<AppleTokenRow>, DynamoDBError> {
        let table = &self.apple_tokens_table;
        let uid = s(&user_id.to_string());
        let mut rows = Vec::new();
        let mut start = None;
        loop {
            let page = match self
                .client
                .scan()
                .table_name(table)
                .filter_expression("user_id = :uid")
                .expression_attribute_values(":uid", uid.clone())
                .consistent_read(true)
                .set_exclusive_start_key(start)
                .send()
                .await
            {
                Ok(page) => page,
                Err(e) => match classify(e, table) {
                    DynamoDBError::TableNotExists(t) => {
                        warn!("Apple token table {t} does not exist; no Apple tokens to revoke");
                        return Ok(Vec::new());
                    }
                    other => return Err(other),
                },
            };
            for item in page.items() {
                match parse_row(item) {
                    Some(row) => rows.push(row),
                    None => error!("Unreadable {table} row of {user_id} left in place"),
                }
            }
            match page.last_evaluated_key {
                Some(k) => start = Some(k),
                None => break,
            }
        }
        Ok(rows)
    }

    /// Remove a stored token once Apple has revoked it, only while the row
    /// still belongs to `user_id` (the same Apple identity may since have
    /// been linked by another account, whose row must stay).
    pub async fn delete_apple_token(
        &self,
        link_key: &str,
        user_id: &Uuid,
    ) -> Result<(), DynamoDBError> {
        let table = &self.apple_tokens_table;
        let result = self
            .client
            .delete_item()
            .table_name(table)
            .key("link_key", s(link_key))
            .condition_expression("user_id = :uid")
            .expression_attribute_values(":uid", s(&user_id.to_string()))
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

    /// The stored row for an identity, if any.
    #[cfg(test)]
    pub(crate) async fn get_apple_token(&self, link_key: &str) -> Option<AppleTokenRow> {
        self.client
            .get_item()
            .table_name(&self.apple_tokens_table)
            .key("link_key", s(link_key))
            .consistent_read(true)
            .send()
            .await
            .unwrap()
            .item
            .as_ref()
            .and_then(parse_row)
    }
}

#[cfg(test)]
mod tests {
    use crate::apple_tokens::{AppleTokenRow, apple_link_key};
    use crate::db::DynamoDBError;
    use crate::db::tests::local_store;
    use crate::patreon::TokenSealer;
    use uuid::Uuid;

    fn sub() -> String {
        format!("001234.{}", Uuid::new_v4().simple())
    }

    async fn row(user_id: Uuid, sub: &str, token: &str) -> AppleTokenRow {
        AppleTokenRow {
            link_key: apple_link_key(sub),
            user_id,
            client_id: "com.arkavo.ArkavoCreator".into(),
            sealed: TokenSealer::Plaintext.seal(token.as_bytes()).await.unwrap(),
            stored_at: 1,
        }
    }

    async fn opened(r: &AppleTokenRow) -> Vec<u8> {
        TokenSealer::Plaintext.open(&r.sealed).await.unwrap()
    }

    #[tokio::test]
    async fn a_sealed_token_round_trips_and_a_put_replaces_the_row() {
        let Some(store) = local_store() else { return };
        let (uid, s) = (Uuid::new_v4(), sub());

        store
            .put_apple_token(&row(uid, &s, "rt-1").await)
            .await
            .unwrap();
        let stored = store
            .get_apple_token(&apple_link_key(&s))
            .await
            .expect("stored");
        assert_eq!(stored.user_id, uid);
        assert_eq!(stored.client_id, "com.arkavo.ArkavoCreator");
        assert_eq!(opened(&stored).await, b"rt-1");

        store
            .put_apple_token(&row(uid, &s, "rt-2").await)
            .await
            .unwrap();
        let now = store.get_apple_token(&apple_link_key(&s)).await.unwrap();
        assert_eq!(opened(&now).await, b"rt-2");
        let rows = store.apple_tokens_of(&uid).await.unwrap();
        assert_eq!(
            rows.len(),
            1,
            "a re-link replaces the row, it does not add one"
        );
        assert_eq!(rows[0].link_key, apple_link_key(&s));
    }

    #[tokio::test]
    async fn an_accounts_tokens_are_found_by_user() {
        let Some(store) = local_store() else { return };
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (s1, s2, s3) = (sub(), sub(), sub());
        store
            .put_apple_token(&row(a, &s1, "rt-1").await)
            .await
            .unwrap();
        store
            .put_apple_token(&row(a, &s2, "rt-2").await)
            .await
            .unwrap();
        store
            .put_apple_token(&row(b, &s3, "rt-3").await)
            .await
            .unwrap();

        let mut keys: Vec<String> = store
            .apple_tokens_of(&a)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.link_key)
            .collect();
        keys.sort();
        let mut want = vec![apple_link_key(&s1), apple_link_key(&s2)];
        want.sort();
        assert_eq!(keys, want);
        assert_eq!(store.apple_tokens_of(&b).await.unwrap().len(), 1);
        assert!(
            store
                .apple_tokens_of(&Uuid::new_v4())
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Review Focus 4: the Apple ID was re-linked by a new account between
    /// the sweep's scan and its delete.
    #[tokio::test]
    async fn a_token_row_is_deleted_only_for_its_own_account() {
        let Some(store) = local_store() else { return };
        let (deleted, newcomer, s) = (Uuid::new_v4(), Uuid::new_v4(), sub());
        store
            .put_apple_token(&row(newcomer, &s, "rt-new").await)
            .await
            .unwrap();

        store
            .delete_apple_token(&apple_link_key(&s), &deleted)
            .await
            .unwrap();
        assert!(
            store.get_apple_token(&apple_link_key(&s)).await.is_some(),
            "newcomer's row deleted"
        );

        store
            .delete_apple_token(&apple_link_key(&s), &newcomer)
            .await
            .unwrap();
        assert!(store.get_apple_token(&apple_link_key(&s)).await.is_none());
        // Deleting an absent row is not an error.
        store
            .delete_apple_token(&apple_link_key(&s), &newcomer)
            .await
            .unwrap();
    }

    /// Review Focus 5: no table (dev, staging, a deploy before the table exists).
    #[tokio::test]
    async fn a_missing_table_holds_no_tokens_and_refuses_writes() {
        let Some(store) = local_store() else { return };
        let store = store.with_apple_tokens_table(format!("missing-{}", Uuid::new_v4()));
        assert!(
            store
                .apple_tokens_of(&Uuid::new_v4())
                .await
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            store
                .put_apple_token(&row(Uuid::new_v4(), &sub(), "rt").await)
                .await,
            Err(DynamoDBError::TableNotExists(_))
        ));
    }
}
