//! market.arkavo.com purchase links (#141), on existing tables (no new table,
//! no new IAM grant).
//!
//! - **The link**: an `identity_links` item `market#<checkoutSessionId>` with
//!   `user_id`, `provider = market` and `created_at`. It binds a purchase to
//!   one account, and holds no token, so the deletion sweep's link step
//!   removes it, which frees the purchase for another account.
//! - **The account's list**: a string set `market_links` on the account's
//!   `credentials` row. `identity_links` has no `user_id` index, so this is
//!   how a mint finds the account's links, in the one consistent read that
//!   also yields the suspension and the App Store records
//!   (`get_publishing_state`). It is written under `LIVE_ROW`, and the
//!   tombstone drops it.
//!
//! Nothing about the purchase is stored: no tier, price, refund or
//! revocation. Identity asks the market at every mint (`crate::market`).
//!
//! A checkout session id is the purchase's bearer secret: the errors and log
//! lines here never carry one.

use super::agent_state::{classify, n, s};
use super::{DynamoDBError, DynamoDBStore, account};
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use aws_sdk_dynamodb::types::{AttributeValue, TransactWriteItem, Update};
use uuid::Uuid;

pub(super) const ATTR: &str = "market_links";
const LINK_PREFIX: &str = "market#";
const PROVIDER: &str = "market";

fn link_pk(session_id: &str) -> String {
    format!("{LINK_PREFIX}{session_id}")
}

/// Outcome of [`DynamoDBStore::link_market_purchase`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketLinkOutcome {
    /// Newly linked to the account.
    Linked,
    /// Already the account's.
    AlreadyYours,
    /// Moved to the account from a deleted one the sweep had not reached.
    Moved,
    /// Linked to another live account, which keeps it. Nothing was written.
    Elsewhere,
}

impl DynamoDBStore {
    /// Atomically link a purchase to `user_id` across both tables using
    /// `TransactWriteItems`:
    /// - `identity_links` (`market#<session_id>` → `user_id`)
    /// - `credentials` (`ADD market_links :id` conditioned on `LIVE_ROW`).
    ///
    /// A link naming another account moves only when that account is not
    /// live (deleted, before the sweep removed the link); a live owner keeps
    /// it ([`MarketLinkOutcome::Elsewhere`]). Because both writes commit or
    /// abort together, a failed or timed-out link can never leave an orphaned
    /// `market#` row or dangling `market_links` entry.
    ///
    /// [`DynamoDBError::AccountGone`]: `user_id` has no live row.
    pub async fn link_market_purchase(
        &self,
        session_id: &str,
        user_id: &Uuid,
    ) -> Result<MarketLinkOutcome, DynamoDBError> {
        let now = chrono::Utc::now().timestamp();
        for _ in 0..5 {
            let (link_update, outcome) = match self.market_link_owner(session_id).await? {
                None => {
                    let update = Update::builder()
                        .table_name(&self.identity_links_table)
                        .key("link_pk", s(&link_pk(session_id)))
                        .update_expression("SET user_id = :uid, provider = :p, created_at = :now")
                        .condition_expression("attribute_not_exists(link_pk)")
                        .expression_attribute_values(":uid", s(&user_id.to_string()))
                        .expression_attribute_values(":p", s(PROVIDER))
                        .expression_attribute_values(":now", n(now))
                        .build()
                        .map_err(|e| {
                            DynamoDBError::Internal(format!("build market link update failed: {e}"))
                        })?;
                    (update, MarketLinkOutcome::Linked)
                }
                Some(owner) if owner == *user_id => {
                    let update = Update::builder()
                        .table_name(&self.identity_links_table)
                        .key("link_pk", s(&link_pk(session_id)))
                        .update_expression(
                            "SET user_id = :uid, provider = :p, created_at = if_not_exists(created_at, :now)",
                        )
                        .condition_expression("user_id = :uid")
                        .expression_attribute_values(":uid", s(&user_id.to_string()))
                        .expression_attribute_values(":p", s(PROVIDER))
                        .expression_attribute_values(":now", n(now))
                        .build()
                        .map_err(|e| {
                            DynamoDBError::Internal(format!("build market link update failed: {e}"))
                        })?;
                    (update, MarketLinkOutcome::AlreadyYours)
                }
                Some(owner) => {
                    if self.is_account_live(&owner).await? {
                        return Ok(MarketLinkOutcome::Elsewhere);
                    }
                    let update = Update::builder()
                        .table_name(&self.identity_links_table)
                        .key("link_pk", s(&link_pk(session_id)))
                        .update_expression("SET user_id = :to, provider = :p, created_at = :now")
                        .condition_expression("user_id = :from")
                        .expression_attribute_values(":from", s(&owner.to_string()))
                        .expression_attribute_values(":to", s(&user_id.to_string()))
                        .expression_attribute_values(":p", s(PROVIDER))
                        .expression_attribute_values(":now", n(now))
                        .build()
                        .map_err(|e| {
                            DynamoDBError::Internal(format!("build market move update failed: {e}"))
                        })?;
                    (update, MarketLinkOutcome::Moved)
                }
            };

            let account_update = Update::builder()
                .table_name(&self.credentials_table)
                .key("user_id", s(&user_id.to_string()))
                .update_expression("ADD #ml :id")
                .condition_expression(account::LIVE_ROW)
                .expression_attribute_names("#ml", ATTR)
                .expression_attribute_values(":id", AttributeValue::Ss(vec![session_id.to_string()]))
                .build()
                .map_err(|e| {
                    DynamoDBError::Internal(format!("build credentials market_links update failed: {e}"))
                })?;

            let result = self
                .client
                .transact_write_items()
                .transact_items(TransactWriteItem::builder().update(link_update).build())
                .transact_items(TransactWriteItem::builder().update(account_update).build())
                .send()
                .await;

            match result {
                Ok(_) => return Ok(outcome),
                Err(e) => {
                    if let SdkError::ServiceError(ref se) = e
                        && let TransactWriteItemsError::TransactionCanceledException(canceled) =
                            se.err()
                    {
                        let reasons = canceled.cancellation_reasons();
                        // Item 1 is credentials (LIVE_ROW): if it failed, the account is gone.
                        if reasons.get(1).and_then(|r| r.code()) == Some("ConditionalCheckFailed") {
                            return Err(DynamoDBError::AccountGone);
                        }
                        // Item 0 is identity_links: owner changed concurrently; retry.
                        if matches!(
                            reasons.first().and_then(|r| r.code()),
                            Some("ConditionalCheckFailed" | "TransactionConflict")
                        ) || reasons.get(1).and_then(|r| r.code()) == Some("TransactionConflict")
                        {
                            continue;
                        }
                    }
                    return Err(classify(e, &self.identity_links_table));
                }
            }
        }
        Err(DynamoDBError::Internal(
            "market link changed on every attempt".into(),
        ))
    }

    /// The account a purchase is linked to. A consistent read.
    pub async fn market_link_owner(&self, session_id: &str) -> Result<Option<Uuid>, DynamoDBError> {
        let table = &self.identity_links_table;
        let out = self
            .client
            .get_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(session_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| self.map_get_item_err(table, e))?;
        let Some(item) = out.item else {
            return Ok(None);
        };
        let user_id = item
            .get("user_id")
            .and_then(|v| v.as_s().ok())
            .ok_or_else(|| DynamoDBError::Internal("market link has no user_id".into()))?;
        Ok(Some(Uuid::parse_str(user_id)?))
    }
}

/// The `market_links` of a `credentials` item, sorted. Absent reads as none;
/// an attribute of another type is an error (the caller fails closed).
pub(super) fn links_from_item(
    item: &std::collections::HashMap<String, AttributeValue>,
) -> Result<Vec<String>, DynamoDBError> {
    let Some(v) = item.get(ATTR) else {
        return Ok(Vec::new());
    };
    let mut links = v
        .as_ss()
        .map_err(|_| DynamoDBError::Internal(format!("{ATTR} is not a string set")))?
        .clone();
    links.sort();
    Ok(links)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tests::local_store;

    async fn user(store: &DynamoDBStore, tag: &str) -> Uuid {
        store
            .create_user(
                &format!("{tag}-{}", Uuid::new_v4().simple()),
                "did:key:z6MkMarketTest",
            )
            .await
            .expect("create user")
            .user_id
    }

    async fn tombstone(store: &DynamoDBStore, id: &Uuid) {
        store
            .tombstone_account(id, &format!("{id}.test"), None, 1_700_000_000)
            .await
            .expect("tombstone");
    }

    fn session() -> String {
        format!("cs_live_{}", Uuid::new_v4().simple())
    }

    async fn links_of(store: &DynamoDBStore, id: &Uuid) -> Vec<String> {
        store
            .get_publishing_state(id)
            .await
            .unwrap()
            .expect("live row")
            .market_links
    }

    #[tokio::test]
    async fn link_is_idempotent_and_listed_on_the_account() {
        let Some(store) = local_store() else { return };
        let id = user(&store, "mkt").await;
        let cs = session();
        assert_eq!(
            store.link_market_purchase(&cs, &id).await.unwrap(),
            MarketLinkOutcome::Linked
        );
        assert_eq!(
            store.link_market_purchase(&cs, &id).await.unwrap(),
            MarketLinkOutcome::AlreadyYours
        );
        assert_eq!(store.market_link_owner(&cs).await.unwrap(), Some(id));
        assert_eq!(links_of(&store, &id).await, vec![cs.clone()]);

        let second = session();
        store.link_market_purchase(&second, &id).await.unwrap();
        let mut both = vec![cs, second];
        both.sort();
        assert_eq!(links_of(&store, &id).await, both);
    }

    #[tokio::test]
    async fn another_live_account_keeps_the_purchase() {
        let Some(store) = local_store() else { return };
        let (a, b) = (user(&store, "mkt-a").await, user(&store, "mkt-b").await);
        let cs = session();
        store.link_market_purchase(&cs, &a).await.unwrap();
        assert_eq!(
            store.link_market_purchase(&cs, &b).await.unwrap(),
            MarketLinkOutcome::Elsewhere
        );
        assert_eq!(store.market_link_owner(&cs).await.unwrap(), Some(a));
        assert!(links_of(&store, &b).await.is_empty());
    }

    #[tokio::test]
    async fn a_deleted_owners_purchase_moves_before_the_sweep() {
        let Some(store) = local_store() else { return };
        let (a, b) = (user(&store, "mkt-a").await, user(&store, "mkt-b").await);
        let cs = session();
        store.link_market_purchase(&cs, &a).await.unwrap();
        tombstone(&store, &a).await;
        assert_eq!(
            store.link_market_purchase(&cs, &b).await.unwrap(),
            MarketLinkOutcome::Moved
        );
        assert_eq!(store.market_link_owner(&cs).await.unwrap(), Some(b));
        assert_eq!(links_of(&store, &b).await, vec![cs]);
    }

    #[tokio::test]
    async fn a_dead_caller_leaves_no_link() {
        let Some(store) = local_store() else { return };
        let id = user(&store, "mkt").await;
        tombstone(&store, &id).await;
        let cs = session();
        assert!(matches!(
            store.link_market_purchase(&cs, &id).await,
            Err(DynamoDBError::AccountGone)
        ));
        assert_eq!(store.market_link_owner(&cs).await.unwrap(), None);
        // An unknown account likewise.
        assert!(matches!(
            store.link_market_purchase(&cs, &Uuid::new_v4()).await,
            Err(DynamoDBError::AccountGone)
        ));
        assert_eq!(store.market_link_owner(&cs).await.unwrap(), None);
    }

    /// The sweep's link step removes the purchase, which frees it for
    /// another account; the tombstone drops `market_links`.
    #[tokio::test]
    async fn the_deletion_sweep_frees_the_purchase() {
        let Some(store) = local_store() else { return };
        let (a, b) = (user(&store, "mkt-a").await, user(&store, "mkt-b").await);
        let cs = session();
        store.link_market_purchase(&cs, &a).await.unwrap();
        tombstone(&store, &a).await;
        assert!(store.get_publishing_state(&a).await.unwrap().is_none());
        store.delete_identity_links_of(&a).await.unwrap();
        assert_eq!(store.market_link_owner(&cs).await.unwrap(), None);
        assert_eq!(
            store.link_market_purchase(&cs, &b).await.unwrap(),
            MarketLinkOutcome::Linked
        );
    }
}
