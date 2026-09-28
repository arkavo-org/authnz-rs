//! Guardians (`guardians` table): Ed25519 keys an owner enrolls so that a
//! Guardian can latch quarantines on, and appraise, the owner's agents. The key is read
//! from here on every request; a request never supplies its own key.

use super::agent_state::{classify, n, s};
use super::{DynamoDBError, DynamoDBStore};
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::AttributeValue;
use log::{info, warn};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guardian {
    pub guardian_id: String,
    pub owner: Uuid,
    pub name: String,
    pub public_key: [u8; 32],
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

/// The id a key is enrolled under: a UUID (version 8) from the key's
/// SHA-256. The signed bytes do not name the Guardian, so one key under two
/// ids would have two replay clocks; deriving the id makes the key's row
/// unique, and the put's `attribute_not_exists` makes enrollment race-free.
pub fn guardian_id_for(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_custom_bytes(bytes)
        .into_uuid()
        .to_string()
}

impl Guardian {
    /// A new, unrevoked Guardian under the id its key derives.
    pub fn enrolling(owner: Uuid, name: String, public_key: [u8; 32], now: i64) -> Self {
        Self {
            guardian_id: guardian_id_for(&public_key),
            owner,
            name,
            public_key,
            created_at: now,
            revoked_at: None,
        }
    }
}

impl DynamoDBStore {
    /// Enroll `g`. `ConditionalConflict` when its key is already enrolled —
    /// by any owner, revoked or not: a revoked key never gets a fresh clock.
    pub async fn create_guardian(&self, g: &Guardian) -> Result<(), DynamoDBError> {
        if g.guardian_id != guardian_id_for(&g.public_key) {
            return Err(DynamoDBError::Internal(
                "guardian id is not derived from its key".into(),
            ));
        }
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
        let number = |k: &str| {
            item.get(k)
                .and_then(|v| v.as_n().ok())
                .and_then(|v| v.parse::<i64>().ok())
        };
        let public_key = item
            .get("public_key")
            .and_then(|v| v.as_b().ok())
            .and_then(|b| <[u8; 32]>::try_from(b.as_ref()).ok())
            .ok_or_else(|| DynamoDBError::Internal("guardian row has no 32-byte key".into()))?;
        Ok(Some(Guardian {
            guardian_id: text("guardian_id")?,
            owner: Uuid::parse_str(&text("owner")?)?,
            name: text("name")?,
            public_key,
            created_at: number("created_at")
                .ok_or_else(|| DynamoDBError::Internal("guardian row missing created_at".into()))?,
            revoked_at: number("revoked_at"),
        }))
    }

    /// Record `timestamp` as this Guardian's last accepted signature time,
    /// only if it is strictly later than the one stored and the Guardian is
    /// not revoked. A replay — or any older signature — inside the ±60 s
    /// window fails here, as does a request that raced a revocation.
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
                "attribute_exists(guardian_id) AND attribute_not_exists(revoked_at) AND \
                 (attribute_not_exists(last_signed_at) OR last_signed_at < :ts)",
            )
            .update_expression("SET last_signed_at = :ts")
            .expression_attribute_values(":ts", n(timestamp))
            .send()
            .await
            .map_err(|e| classify(e, &self.guardians_table))?;
        Ok(())
    }

    /// Mark `owner`'s Guardian revoked. A marker, not a delete: the row keeps
    /// the key enrolled (so it cannot re-enroll with a fresh clock) and keeps
    /// `quarantined_by = guardian:<id>` resolvable. Repeats keep the first
    /// revocation time. `ConditionalConflict` when the Guardian does not
    /// exist or belongs to someone else.
    pub async fn revoke_guardian(
        &self,
        guardian_id: &str,
        owner: Uuid,
        now: i64,
    ) -> Result<(), DynamoDBError> {
        self.client
            .update_item()
            .table_name(&self.guardians_table)
            .key("guardian_id", s(guardian_id))
            .condition_expression("attribute_exists(guardian_id) AND #o = :owner")
            .update_expression("SET revoked_at = if_not_exists(revoked_at, :now)")
            .expression_attribute_names("#o", "owner")
            .expression_attribute_values(":owner", s(&owner.to_string()))
            .expression_attribute_values(":now", n(now))
            .send()
            .await
            .map_err(|e| classify(e, &self.guardians_table))?;
        warn!("Guardian {guardian_id} revoked by owner {owner}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tests::local_store;

    fn random_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).unwrap();
        k
    }

    fn pager(owner: Uuid, key: [u8; 32]) -> Guardian {
        Guardian::enrolling(owner, "pager".into(), key, 1_790_000_000)
    }

    #[test]
    fn a_guardian_id_is_a_uuid_derived_from_its_key() {
        let (k1, k2) = ([1u8; 32], [2u8; 32]);
        assert_eq!(guardian_id_for(&k1), guardian_id_for(&k1));
        assert_ne!(guardian_id_for(&k1), guardian_id_for(&k2));
        assert!(Uuid::parse_str(&guardian_id_for(&k1)).is_ok());
        let g = pager(Uuid::from_u128(1), k1);
        assert_eq!(g.guardian_id, guardian_id_for(&k1));
        assert_eq!(g.revoked_at, None);
    }

    #[tokio::test]
    async fn guardian_round_trips_and_ids_are_single_use() {
        let Some(store) = local_store() else {
            return;
        };
        let g = pager(Uuid::new_v4(), random_key());
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
    async fn a_key_enrolls_once_whoever_the_owner() {
        let Some(store) = local_store() else {
            return;
        };
        let key = random_key();
        store
            .create_guardian(&pager(Uuid::new_v4(), key))
            .await
            .unwrap();
        assert!(matches!(
            store.create_guardian(&pager(Uuid::new_v4(), key)).await,
            Err(DynamoDBError::ConditionalConflict)
        ));
        let mismatched = Guardian {
            guardian_id: Uuid::new_v4().to_string(),
            ..pager(Uuid::new_v4(), key)
        };
        assert!(
            matches!(
                store.create_guardian(&mismatched).await,
                Err(DynamoDBError::Internal(_))
            ),
            "an id not derived from the key would give the key a second clock"
        );
    }

    #[tokio::test]
    async fn guardian_clock_only_moves_forward() {
        let Some(store) = local_store() else {
            return;
        };
        let g = pager(Uuid::new_v4(), random_key());
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

    #[tokio::test]
    async fn revocation_is_owner_bound_sticky_and_stops_the_clock() {
        let Some(store) = local_store() else {
            return;
        };
        let owner = Uuid::new_v4();
        let g = pager(owner, random_key());
        store.create_guardian(&g).await.unwrap();
        assert!(matches!(
            store
                .revoke_guardian(&g.guardian_id, Uuid::new_v4(), 1_790_000_300)
                .await,
            Err(DynamoDBError::ConditionalConflict)
        ));
        assert!(matches!(
            store.revoke_guardian("absent", owner, 1_790_000_300).await,
            Err(DynamoDBError::ConditionalConflict)
        ));
        store
            .revoke_guardian(&g.guardian_id, owner, 1_790_000_300)
            .await
            .unwrap();
        store
            .revoke_guardian(&g.guardian_id, owner, 1_790_000_400)
            .await
            .unwrap();
        let revoked = store.get_guardian(&g.guardian_id).await.unwrap().unwrap();
        assert_eq!(
            revoked.revoked_at,
            Some(1_790_000_300),
            "the first revocation time stays"
        );
        assert!(
            matches!(
                store
                    .advance_guardian_clock(&g.guardian_id, 1_790_000_500)
                    .await,
                Err(DynamoDBError::ConditionalConflict)
            ),
            "a revoked Guardian's clock never advances"
        );
    }
}
