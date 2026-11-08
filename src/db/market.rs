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
use aws_sdk_dynamodb::types::{AttributeValue, ReturnValue};
use log::warn;
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

/// What a conditional write of the link row did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bind {
    Bound,
    AlreadyYours,
    BoundElsewhere,
}

impl DynamoDBStore {
    /// Link a purchase to `user_id`: the `market#` row, then the id in the
    /// account's `market_links` (under `LIVE_ROW`).
    ///
    /// A link naming another account moves only when that account is not
    /// live (deleted, before the sweep removed the link); a live owner keeps
    /// it ([`MarketLinkOutcome::Elsewhere`]). The move is conditional on the
    /// owner read, so a race with another link or the sweep is re-evaluated
    /// (a few times at most).
    ///
    /// [`DynamoDBError::AccountGone`]: `user_id` has no live row. A link row
    /// this call wrote is deleted then, and on any other failure of the
    /// second write, so a retry starts clean (an earlier, complete link
    /// stays). A retry is idempotent.
    pub async fn link_market_purchase(
        &self,
        session_id: &str,
        user_id: &Uuid,
    ) -> Result<MarketLinkOutcome, DynamoDBError> {
        for _ in 0..3 {
            match self.bind_market_link(session_id, user_id).await? {
                Bind::Bound => {
                    self.add_market_link_to_account(session_id, user_id, true)
                        .await?;
                    return Ok(MarketLinkOutcome::Linked);
                }
                Bind::AlreadyYours => {
                    self.add_market_link_to_account(session_id, user_id, false)
                        .await?;
                    return Ok(MarketLinkOutcome::AlreadyYours);
                }
                Bind::BoundElsewhere => {}
            }
            // Gone again (swept), or now the caller's: the next bind settles it.
            let Some(owner) = self.market_link_owner(session_id).await? else {
                continue;
            };
            if owner == *user_id {
                continue;
            }
            if self.is_account_live(&owner).await? {
                return Ok(MarketLinkOutcome::Elsewhere);
            }
            if self.move_market_link(session_id, &owner, user_id).await? {
                self.add_market_link_to_account(session_id, user_id, true)
                    .await?;
                return Ok(MarketLinkOutcome::Moved);
            }
        }
        Err(DynamoDBError::Internal(
            "market link changed on every attempt".into(),
        ))
    }

    /// One conditional `UpdateItem`: the link row is absent or already this
    /// account's (a re-bind keeps `created_at`).
    async fn bind_market_link(
        &self,
        session_id: &str,
        user_id: &Uuid,
    ) -> Result<Bind, DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .update_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(session_id)))
            .update_expression(
                "SET user_id = :uid, provider = :p, created_at = if_not_exists(created_at, :now)",
            )
            .condition_expression("attribute_not_exists(link_pk) OR user_id = :uid")
            .expression_attribute_values(":uid", s(&user_id.to_string()))
            .expression_attribute_values(":p", s(PROVIDER))
            .expression_attribute_values(":now", n(chrono::Utc::now().timestamp()))
            .return_values(ReturnValue::AllOld)
            .send()
            .await;
        match result {
            Ok(out) if out.attributes().is_some_and(|a| !a.is_empty()) => Ok(Bind::AlreadyYours),
            Ok(_) => Ok(Bind::Bound),
            Err(e) => match classify(e, table) {
                DynamoDBError::ConditionalConflict => Ok(Bind::BoundElsewhere),
                other => Err(other),
            },
        }
    }

    /// Move the link from `from` to `to`: one conditional update on the link
    /// still naming `from` (a move is a new binding, so `created_at`
    /// restarts). `Ok(false)`: it no longer does, and nothing was written.
    async fn move_market_link(
        &self,
        session_id: &str,
        from: &Uuid,
        to: &Uuid,
    ) -> Result<bool, DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .update_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(session_id)))
            .update_expression("SET user_id = :to, provider = :p, created_at = :now")
            .condition_expression("user_id = :from")
            .expression_attribute_values(":from", s(&from.to_string()))
            .expression_attribute_values(":to", s(&to.to_string()))
            .expression_attribute_values(":p", s(PROVIDER))
            .expression_attribute_values(":now", n(chrono::Utc::now().timestamp()))
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

    /// `ADD` the id to the account's `market_links`, under `LIVE_ROW`.
    ///
    /// On a dead account the link is deleted (whoever wrote it: dead either
    /// way) and [`DynamoDBError::AccountGone`] returned. On any other failure
    /// a link this call `wrote` is taken back, so the failed request leaves
    /// nothing; one that was already this account's stays.
    async fn add_market_link_to_account(
        &self,
        session_id: &str,
        user_id: &Uuid,
        wrote: bool,
    ) -> Result<(), DynamoDBError> {
        let table = &self.credentials_table;
        let result = self
            .client
            .update_item()
            .table_name(table)
            .key("user_id", s(&user_id.to_string()))
            .update_expression("ADD #ml :id")
            .condition_expression(account::LIVE_ROW)
            .expression_attribute_names("#ml", ATTR)
            .expression_attribute_values(":id", AttributeValue::Ss(vec![session_id.to_string()]))
            .send()
            .await;
        let err = match result {
            Ok(_) => return Ok(()),
            Err(e) => classify(e, table),
        };
        let (take_back, err) = match err {
            DynamoDBError::ConditionalConflict => (true, DynamoDBError::AccountGone),
            other => (wrote, other),
        };
        // A link that could not be taken back stays: the sweep removes it on
        // a dead account, and a retry completes it on a live one.
        if take_back && let Err(e) = self.delete_market_link(session_id, user_id).await {
            warn!("could not take back a market link: {e}");
        }
        Err(err)
    }

    /// Delete the link while it still names `user_id`.
    async fn delete_market_link(
        &self,
        session_id: &str,
        user_id: &Uuid,
    ) -> Result<(), DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .delete_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(session_id)))
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
