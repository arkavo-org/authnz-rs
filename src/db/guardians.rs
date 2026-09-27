//! Guardians (`guardians` table): Ed25519 keys an owner enrolls so that a
//! Guardian can latch quarantines on the owner's workloads. The key is read
//! from here on every request; a request never supplies its own key.

use super::workloads::{classify, n, s};
use super::{DynamoDBError, DynamoDBStore};
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::AttributeValue;
use log::info;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guardian {
    pub guardian_id: String,
    pub owner: Uuid,
    pub name: String,
    pub public_key: [u8; 32],
    pub created_at: i64,
}

impl DynamoDBStore {
    pub async fn create_guardian(&self, g: &Guardian) -> Result<(), DynamoDBError> {
        self.client
            .put_item()
            .table_name(&self.guardians_table)
            .item("guardian_id", s(&g.guardian_id))
            .item("owner", s(&g.owner.to_string()))
            .item("name", s(&g.name))
            .item(
                "public_key",
                AttributeValue::B(Blob::new(g.public_key.to_vec())),
            )
            .item("created_at", n(g.created_at))
            .condition_expression("attribute_not_exists(guardian_id)")
            .send()
            .await
            .map_err(|e| classify(e, &self.guardians_table))?;
        info!("Enrolled guardian {} for owner {}", g.guardian_id, g.owner);
        Ok(())
    }

    pub async fn get_guardian(&self, guardian_id: &str) -> Result<Option<Guardian>, DynamoDBError> {
        let out = self
            .client
            .get_item()
            .table_name(&self.guardians_table)
            .key("guardian_id", s(guardian_id))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| classify(e, &self.guardians_table))?;
        let Some(item) = out.item else {
            return Ok(None);
        };
        let text = |k: &str| {
            item.get(k)
                .and_then(|v| v.as_s().ok())
                .cloned()
                .ok_or_else(|| DynamoDBError::Internal(format!("guardian row missing {k}")))
        };
        let public_key = item
            .get("public_key")
            .and_then(|v| v.as_b().ok())
            .and_then(|b| <[u8; 32]>::try_from(b.as_ref()).ok())
            .ok_or_else(|| DynamoDBError::Internal("guardian row has no 32-byte key".into()))?;
        let created_at = item
            .get("created_at")
            .and_then(|v| v.as_n().ok())
            .and_then(|v| v.parse::<i64>().ok())
            .ok_or_else(|| DynamoDBError::Internal("guardian row missing created_at".into()))?;
        Ok(Some(Guardian {
            guardian_id: text("guardian_id")?,
            owner: Uuid::parse_str(&text("owner")?)?,
            name: text("name")?,
            public_key,
            created_at,
        }))
    }

    /// Record `timestamp` as this Guardian's last accepted signature time,
    /// only if it is strictly later than the one stored. A replay — or any
    /// older signature — inside the ±60 s window fails here.
    pub async fn advance_guardian_clock(
        &self,
        guardian_id: &str,
        timestamp: i64,
    ) -> Result<(), DynamoDBError> {
        self.client
            .update_item()
            .table_name(&self.guardians_table)
            .key("guardian_id", s(guardian_id))
            .condition_expression(
                "attribute_exists(guardian_id) AND \
                 (attribute_not_exists(last_signed_at) OR last_signed_at < :ts)",
            )
            .update_expression("SET last_signed_at = :ts")
            .expression_attribute_values(":ts", n(timestamp))
            .send()
            .await
            .map_err(|e| classify(e, &self.guardians_table))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tests::local_store;

    #[tokio::test]
    async fn guardian_round_trips_and_ids_are_single_use() {
        let Some(store) = local_store() else {
            return;
        };
        let g = Guardian {
            guardian_id: Uuid::new_v4().to_string(),
            owner: Uuid::new_v4(),
            name: "pager".into(),
            public_key: [9u8; 32],
            created_at: 1_790_000_000,
        };
        store.create_guardian(&g).await.unwrap();
        assert_eq!(
            store.get_guardian(&g.guardian_id).await.unwrap(),
            Some(g.clone())
        );
        assert!(matches!(
            store.create_guardian(&g).await,
            Err(DynamoDBError::ConditionalConflict)
        ));
        assert_eq!(store.get_guardian("absent").await.unwrap(), None);
    }

    #[tokio::test]
    async fn guardian_clock_only_moves_forward() {
        let Some(store) = local_store() else {
            return;
        };
        let g = Guardian {
            guardian_id: Uuid::new_v4().to_string(),
            owner: Uuid::new_v4(),
            name: "pager".into(),
            public_key: [9u8; 32],
            created_at: 1_790_000_000,
        };
        store.create_guardian(&g).await.unwrap();
        store
            .advance_guardian_clock(&g.guardian_id, 1_790_000_100)
            .await
            .unwrap();
        for replayed_or_older in [1_790_000_100, 1_790_000_099] {
            assert!(matches!(
                store
                    .advance_guardian_clock(&g.guardian_id, replayed_or_older)
                    .await,
                Err(DynamoDBError::ConditionalConflict)
            ));
        }
        store
            .advance_guardian_clock(&g.guardian_id, 1_790_000_101)
            .await
            .unwrap();
        assert!(
            matches!(
                store.advance_guardian_clock("absent", 1_790_000_200).await,
                Err(DynamoDBError::ConditionalConflict)
            ),
            "never creates a row"
        );
        assert_eq!(store.get_guardian(&g.guardian_id).await.unwrap(), Some(g));
    }
}
