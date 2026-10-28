//! Which Arkavo account owns a Patreon campaign (#128): the `creator_sub` a
//! patron's token carries on each membership.
//!
//! An `identity_links` row, `link_pk = patreon-campaign#<campaign id>`,
//! `provider = patreon-campaign`, `subject` = the campaign id, `user_id` = the
//! owner. Written when a live materialization sees the account own the
//! campaign, removed when it no longer does. The conditional put keeps one
//! account per campaign: a second account claiming it is refused (logged by
//! the caller) and its patrons get no `creator_sub` for it. Account deletion
//! removes it with the account's other links (`delete_identity_links_of`).
//! No sign-in path reads it.

use super::agent_state::{classify, n, s};
use super::{DynamoDBError, DynamoDBStore};
use aws_sdk_dynamodb::types::{AttributeValue, KeysAndAttributes};
use std::collections::HashMap;
use uuid::Uuid;

/// `provider` of a campaign-owner row.
pub(crate) const PATREON_CAMPAIGN_PROVIDER: &str = "patreon-campaign";

/// BatchGetItem's limit on keys per request.
const BATCH_GET_MAX_KEYS: usize = 100;

fn link_pk(campaign_id: &str) -> String {
    format!("{PATREON_CAMPAIGN_PROVIDER}#{campaign_id}")
}

impl DynamoDBStore {
    /// Record `user_id` as the owner of `campaign_id`. `Ok(false)` when
    /// another account already holds the campaign; idempotent for the owner.
    pub async fn put_patreon_campaign_owner(
        &self,
        campaign_id: &str,
        user_id: &Uuid,
        now: i64,
    ) -> Result<bool, DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .update_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(campaign_id)))
            .update_expression(
                "SET user_id = :uid, provider = :p, subject = :sub, \
                 linked_at = if_not_exists(linked_at, :now)",
            )
            .condition_expression("attribute_not_exists(link_pk) OR user_id = :uid")
            .expression_attribute_values(":uid", s(&user_id.to_string()))
            .expression_attribute_values(":p", s(PATREON_CAMPAIGN_PROVIDER))
            .expression_attribute_values(":sub", s(campaign_id))
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

    /// Remove `user_id`'s claim on `campaign_id`. Never removes another
    /// account's row; a missing row is not an error.
    pub async fn delete_patreon_campaign_owner(
        &self,
        campaign_id: &str,
        user_id: &Uuid,
    ) -> Result<(), DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .delete_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(campaign_id)))
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

    /// The owner of each of `campaign_ids` that has one, in batches of 100.
    /// Eventually consistent: a `creator_sub` is display data, cached 5 min.
    pub async fn patreon_campaign_owners(
        &self,
        campaign_ids: &[String],
    ) -> Result<HashMap<String, Uuid>, DynamoDBError> {
        let table = &self.identity_links_table;
        let mut owners = HashMap::new();
        let mut unique: Vec<&String> = Vec::new();
        for cid in campaign_ids {
            if !unique.contains(&cid) {
                unique.push(cid);
            }
        }
        for chunk in unique.chunks(BATCH_GET_MAX_KEYS) {
            let mut keys = KeysAndAttributes::builder();
            for cid in chunk {
                keys = keys.keys(HashMap::from([("link_pk".to_string(), s(&link_pk(cid)))]));
            }
            let mut request = HashMap::from([(
                table.clone(),
                keys.build()
                    .map_err(|e| DynamoDBError::Internal(e.to_string()))?,
            )]);
            // BatchGetItem may return part of the keys as unprocessed; ask
            // again for those, a bounded number of times.
            for _ in 0..3 {
                let out = self
                    .client
                    .batch_get_item()
                    .set_request_items(Some(request))
                    .send()
                    .await
                    .map_err(|e| classify(e, table))?;
                for item in out
                    .responses
                    .and_then(|mut r| r.remove(table))
                    .unwrap_or_default()
                {
                    if let Some((cid, uid)) = owner_of(&item) {
                        owners.insert(cid, uid);
                    }
                }
                match out.unprocessed_keys.filter(|u| !u.is_empty()) {
                    Some(rest) => request = rest,
                    None => break,
                }
            }
        }
        Ok(owners)
    }
}

/// `(campaign id, owner)` of a campaign-owner row; `None` for anything else.
fn owner_of(item: &HashMap<String, AttributeValue>) -> Option<(String, Uuid)> {
    if item.get("provider")?.as_s().ok()? != PATREON_CAMPAIGN_PROVIDER {
        return None;
    }
    let cid = item.get("subject")?.as_s().ok()?.clone();
    let uid = Uuid::parse_str(item.get("user_id")?.as_s().ok()?).ok()?;
    Some((cid, uid))
}

#[cfg(test)]
mod tests {
    use super::super::tests::local_store;
    use uuid::Uuid;

    /// One account per campaign; the owner's put is idempotent; only the
    /// owner's delete removes it; the batch read finds the rest.
    #[tokio::test]
    async fn campaign_owner_rows_hold_one_account_per_campaign() {
        let Some(store) = local_store() else {
            return;
        };
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let cid = format!("9{}", &Uuid::new_v4().as_u128().to_string()[..9]);
        let other = format!("8{}", &Uuid::new_v4().as_u128().to_string()[..9]);

        assert!(store.put_patreon_campaign_owner(&cid, &a, 1).await.unwrap());
        assert!(store.put_patreon_campaign_owner(&cid, &a, 2).await.unwrap());
        assert!(!store.put_patreon_campaign_owner(&cid, &b, 3).await.unwrap());
        assert!(
            store
                .put_patreon_campaign_owner(&other, &b, 3)
                .await
                .unwrap()
        );

        let owners = store
            .patreon_campaign_owners(&[cid.clone(), other.clone(), "1".into(), cid.clone()])
            .await
            .unwrap();
        assert_eq!(owners.len(), 2);
        assert_eq!(owners[&cid], a);
        assert_eq!(owners[&other], b);

        // Another account's delete leaves it; the owner's removes it.
        store.delete_patreon_campaign_owner(&cid, &b).await.unwrap();
        assert_eq!(
            store
                .patreon_campaign_owners(std::slice::from_ref(&cid))
                .await
                .unwrap()[&cid],
            a
        );
        store.delete_patreon_campaign_owner(&cid, &a).await.unwrap();
        assert!(
            store
                .patreon_campaign_owners(std::slice::from_ref(&cid))
                .await
                .unwrap()
                .is_empty()
        );
        store.delete_patreon_campaign_owner(&cid, &a).await.unwrap();
        assert!(store.put_patreon_campaign_owner(&cid, &b, 4).await.unwrap());
    }
}
