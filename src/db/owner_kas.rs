//! Owner-KAS routes (#148): one `identity_links` row per route,
//! `link_pk = owner-kas-route#<route_id>`, `provider = owner-kas-route`,
//! holding the owner (`user_id`), the passkey-signed bundle and its `seq`,
//! and the owner's APNs push token.
//!
//! **Retired, never deleted.** Every recipient of a shared file knows its
//! route id. If turning sharing off or deleting the account freed the id, a
//! recipient could register it and receive later requests for the old
//! owner's files. So both set `retired_at` and remove the bundle and the
//! push token, keeping `user_id`; a retired row takes no further write.
//! The account-deletion sweep's link step skips these rows (as it skips
//! passkey index rows) and [`DynamoDBStore::retire_owner_kas_routes_of`]
//! retires them.

use super::agent_state::{classify, n, s};
use super::{DynamoDBError, DynamoDBStore};
use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;
use uuid::Uuid;

/// `provider` of an owner-KAS route row.
pub(crate) const ROUTE_PROVIDER: &str = "owner-kas-route";

fn link_pk(route_id: &str) -> String {
    format!("{ROUTE_PROVIDER}#{route_id}")
}

/// A stored route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKasRoute {
    pub user_id: Uuid,
    pub seq: u64,
    /// The bundle as put (JSON). Absent once retired.
    pub bundle: Option<String>,
    pub apns_token: Option<String>,
    pub apns_environment: Option<String>,
    pub retired_at: Option<i64>,
}

/// Outcome of a route write by its owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteWrite {
    Done,
    /// No row: the route was never registered.
    Unknown,
    /// Another account's route.
    NotOwner,
    /// Retired: it takes no further write.
    Retired,
    /// `PUT` only: `seq` is not above the stored one.
    StaleSeq,
}

fn opt_s(item: &HashMap<String, AttributeValue>, k: &str) -> Option<String> {
    item.get(k).and_then(|v| v.as_s().ok()).cloned()
}

fn opt_n(item: &HashMap<String, AttributeValue>, k: &str) -> Option<i64> {
    item.get(k)?.as_n().ok()?.parse().ok()
}

impl DynamoDBStore {
    /// The route, strongly consistent. `None` if it was never registered.
    pub async fn get_owner_kas_route(
        &self,
        route_id: &str,
    ) -> Result<Option<OwnerKasRoute>, DynamoDBError> {
        let table = &self.identity_links_table;
        let item = self
            .client
            .get_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(route_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| self.map_get_item_err(table, e))?
            .item;
        let Some(item) = item else { return Ok(None) };
        let user_id = item
            .get("user_id")
            .and_then(|v| v.as_s().ok())
            .ok_or_else(|| DynamoDBError::Internal("owner-KAS route has no user_id".into()))?;
        Ok(Some(OwnerKasRoute {
            user_id: Uuid::parse_str(user_id)?,
            seq: opt_n(&item, "seq").unwrap_or(0).max(0) as u64,
            bundle: opt_s(&item, "bundle"),
            apns_token: opt_s(&item, "apns_token"),
            apns_environment: opt_s(&item, "apns_environment"),
            retired_at: opt_n(&item, "retired_at"),
        }))
    }

    /// After a refused conditional write by `user_id`: why.
    async fn route_refusal(
        &self,
        route_id: &str,
        user_id: &Uuid,
    ) -> Result<RouteWrite, DynamoDBError> {
        Ok(match self.get_owner_kas_route(route_id).await? {
            None => RouteWrite::Unknown,
            Some(r) if r.user_id != *user_id => RouteWrite::NotOwner,
            Some(r) if r.retired_at.is_some() => RouteWrite::Retired,
            Some(_) => RouteWrite::StaleSeq,
        })
    }

    /// Create the route for `user_id`, or replace its bundle with one of a
    /// higher `seq`. Never moves a route to another account or revives a
    /// retired one.
    pub async fn put_owner_kas_route(
        &self,
        user_id: &Uuid,
        route_id: &str,
        seq: u64,
        bundle: &str,
        now: i64,
    ) -> Result<RouteWrite, DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .update_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(route_id)))
            .update_expression(
                "SET user_id = :uid, provider = :p, subject = :sub, seq = :seq, \
                 bundle = :b, updated_at = :now, created_at = if_not_exists(created_at, :now)",
            )
            .condition_expression(
                "attribute_not_exists(link_pk) OR \
                 (user_id = :uid AND seq < :seq AND attribute_not_exists(retired_at))",
            )
            .expression_attribute_values(":uid", s(&user_id.to_string()))
            .expression_attribute_values(":p", s(ROUTE_PROVIDER))
            .expression_attribute_values(":sub", s(route_id))
            .expression_attribute_values(":seq", n(seq))
            .expression_attribute_values(":b", s(bundle))
            .expression_attribute_values(":now", n(now))
            .send()
            .await;
        match result {
            Ok(_) => Ok(RouteWrite::Done),
            Err(e) => match classify(e, table) {
                DynamoDBError::ConditionalConflict => {
                    match self.route_refusal(route_id, user_id).await? {
                        // Vanished between the write and the read: never happens
                        // (rows are not deleted), but report it as a race.
                        RouteWrite::Unknown => Err(DynamoDBError::ConditionalConflict),
                        other => Ok(other),
                    }
                }
                other => Err(other),
            },
        }
    }

    /// Retire `user_id`'s route as of `at`: keep the owner, remove the
    /// bundle and the push token. Idempotent.
    pub async fn retire_owner_kas_route(
        &self,
        user_id: &Uuid,
        route_id: &str,
        at: i64,
    ) -> Result<RouteWrite, DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .update_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(route_id)))
            .update_expression(
                "SET retired_at = if_not_exists(retired_at, :at), updated_at = :at \
                 REMOVE bundle, apns_token, apns_environment",
            )
            .condition_expression("user_id = :uid")
            .expression_attribute_values(":uid", s(&user_id.to_string()))
            .expression_attribute_values(":at", n(at))
            .send()
            .await;
        match result {
            Ok(_) => Ok(RouteWrite::Done),
            Err(e) => match classify(e, table) {
                DynamoDBError::ConditionalConflict => self.route_refusal(route_id, user_id).await,
                other => Err(other),
            },
        }
    }

    /// Set (`Some`) or remove (`None`) the owner's push token on a live
    /// route.
    pub async fn set_owner_kas_push(
        &self,
        user_id: &Uuid,
        route_id: &str,
        push: Option<(&str, &str)>,
        now: i64,
    ) -> Result<RouteWrite, DynamoDBError> {
        let table = &self.identity_links_table;
        let mut req = self
            .client
            .update_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(route_id)))
            .condition_expression("user_id = :uid AND attribute_not_exists(retired_at)")
            .expression_attribute_values(":uid", s(&user_id.to_string()))
            .expression_attribute_values(":now", n(now));
        req = match push {
            Some((token, environment)) => req
                .update_expression("SET apns_token = :t, apns_environment = :e, updated_at = :now")
                .expression_attribute_values(":t", s(token))
                .expression_attribute_values(":e", s(environment)),
            None => {
                req.update_expression("SET updated_at = :now REMOVE apns_token, apns_environment")
            }
        };
        match req.send().await {
            Ok(_) => Ok(RouteWrite::Done),
            Err(e) => match classify(e, table) {
                DynamoDBError::ConditionalConflict => self.route_refusal(route_id, user_id).await,
                other => Err(other),
            },
        }
    }

    /// Remove the route's push token if it is still `token` (APNs reported
    /// it unregistered). A token the owner set meanwhile stays. Returns
    /// whether one was removed.
    pub async fn clear_owner_kas_push_if(
        &self,
        route_id: &str,
        token: &str,
    ) -> Result<bool, DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .update_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(route_id)))
            .update_expression("REMOVE apns_token, apns_environment")
            .condition_expression("apns_token = :t")
            .expression_attribute_values(":t", s(token))
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

    /// Retire every route of a deleted account, as of `at`. The rows stay.
    /// Returns how many were retired.
    pub async fn retire_owner_kas_routes_of(
        &self,
        user_id: &Uuid,
        at: i64,
    ) -> Result<u32, DynamoDBError> {
        let table = self.identity_links_table.clone();
        let uid = s(&user_id.to_string());
        let mut retired = 0;
        let mut start = None;
        loop {
            let page = self
                .client
                .scan()
                .table_name(&table)
                .filter_expression("user_id = :uid AND provider = :p")
                .projection_expression("subject")
                .expression_attribute_values(":uid", uid.clone())
                .expression_attribute_values(":p", s(ROUTE_PROVIDER))
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(|e| classify(e, &table))?;
            for item in page.items() {
                let Some(route_id) = item.get("subject").and_then(|v| v.as_s().ok()) else {
                    continue;
                };
                if self.retire_owner_kas_route(user_id, route_id, at).await? == RouteWrite::Done {
                    retired += 1;
                }
            }
            match page.last_evaluated_key {
                Some(k) => start = Some(k),
                None => break,
            }
        }
        Ok(retired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route() -> String {
        // A fresh canonical ULID-shaped id per test run.
        let hex = Uuid::new_v4().simple().to_string().to_uppercase();
        let tail: String = hex
            .chars()
            .map(|c| match c {
                'A'..='F' | '0'..='9' => c,
                _ => '0',
            })
            .take(25)
            .collect();
        format!("0{tail}")
    }

    #[tokio::test]
    async fn a_route_has_one_owner_rising_seqs_and_retires_for_good() {
        let Some(store) = super::super::tests::local_store() else {
            return;
        };
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let r = route();

        assert_eq!(
            store
                .put_owner_kas_route(&a, &r, 1, "{}", 10)
                .await
                .unwrap(),
            RouteWrite::Done
        );
        assert_eq!(
            store
                .put_owner_kas_route(&a, &r, 1, "{}", 11)
                .await
                .unwrap(),
            RouteWrite::StaleSeq
        );
        assert_eq!(
            store
                .put_owner_kas_route(&b, &r, 9, "{}", 12)
                .await
                .unwrap(),
            RouteWrite::NotOwner
        );
        assert_eq!(
            store
                .put_owner_kas_route(&a, &r, 2, "{\"s\":2}", 13)
                .await
                .unwrap(),
            RouteWrite::Done
        );

        assert_eq!(
            store
                .set_owner_kas_push(&a, &r, Some(("ab".repeat(32).as_str(), "production")), 14)
                .await
                .unwrap(),
            RouteWrite::Done
        );
        assert_eq!(
            store.set_owner_kas_push(&b, &r, None, 14).await.unwrap(),
            RouteWrite::NotOwner
        );
        let got = store.get_owner_kas_route(&r).await.unwrap().unwrap();
        assert_eq!((got.user_id, got.seq), (a, 2));
        assert_eq!(got.bundle.as_deref(), Some("{\"s\":2}"));
        assert_eq!(got.apns_token, Some("ab".repeat(32)));

        assert!(
            !store
                .clear_owner_kas_push_if(&r, &"cd".repeat(32))
                .await
                .unwrap()
        );
        assert!(
            store
                .clear_owner_kas_push_if(&r, &"ab".repeat(32))
                .await
                .unwrap()
        );
        assert_eq!(
            store
                .get_owner_kas_route(&r)
                .await
                .unwrap()
                .unwrap()
                .apns_token,
            None
        );

        assert_eq!(
            store.retire_owner_kas_route(&b, &r, 20).await.unwrap(),
            RouteWrite::NotOwner
        );
        assert_eq!(
            store.retire_owner_kas_route(&a, &r, 20).await.unwrap(),
            RouteWrite::Done
        );
        assert_eq!(
            store.retire_owner_kas_route(&a, &r, 30).await.unwrap(),
            RouteWrite::Done
        );
        let got = store.get_owner_kas_route(&r).await.unwrap().unwrap();
        assert_eq!(
            (got.user_id, got.retired_at, got.bundle),
            (a, Some(20), None)
        );

        // Retired for good, for the owner and for anyone else.
        assert_eq!(
            store
                .put_owner_kas_route(&a, &r, 3, "{}", 40)
                .await
                .unwrap(),
            RouteWrite::Retired
        );
        assert_eq!(
            store
                .put_owner_kas_route(&b, &r, 3, "{}", 40)
                .await
                .unwrap(),
            RouteWrite::NotOwner
        );
        assert_eq!(
            store
                .set_owner_kas_push(&a, &r, Some(("ab".repeat(32).as_str(), "production")), 40)
                .await
                .unwrap(),
            RouteWrite::Retired
        );
        assert_eq!(
            store
                .retire_owner_kas_route(&a, &route(), 40)
                .await
                .unwrap(),
            RouteWrite::Unknown
        );
    }

    #[tokio::test]
    async fn deletion_retires_routes_and_the_link_step_keeps_them() {
        let Some(store) = super::super::tests::local_store() else {
            return;
        };
        let a = Uuid::new_v4();
        let (r1, r2) = (route(), route());
        store
            .put_owner_kas_route(&a, &r1, 1, "{}", 10)
            .await
            .unwrap();
        store
            .put_owner_kas_route(&a, &r2, 1, "{}", 10)
            .await
            .unwrap();

        store.delete_identity_links_of(&a).await.unwrap();
        assert!(store.get_owner_kas_route(&r1).await.unwrap().is_some());

        assert_eq!(store.retire_owner_kas_routes_of(&a, 50).await.unwrap(), 2);
        for r in [&r1, &r2] {
            let got = store.get_owner_kas_route(r).await.unwrap().unwrap();
            assert_eq!(
                (got.user_id, got.retired_at, got.bundle),
                (a, Some(50), None)
            );
        }
    }
}
