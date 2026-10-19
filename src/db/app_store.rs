//! App Store membership storage, on existing tables (no new table, no new IAM
//! grant).
//!
//! - **The link**: an `identity_links` item `appstore#<original_transaction_id>`
//!   with `user_id` and `created_at`. It binds a subscription to one account
//!   and holds no token, so the deletion sweep's link step removes it.
//! - **The state**: a map attribute `app_store` on the account's `credentials`
//!   row, keyed by original transaction id. Each value is
//!   `{product_id, environment, expires_at, grace_expires_at?, revoked_at?,
//!   last_signed_at}`, all times unix seconds.
//!
//! Ordering is by the transaction's `last_signed_at` (Apple's `signedDate`)
//! and the `original_transaction_id`, never by the bytes of a JWS: an ECDSA
//! signature is malleable, so two different byte strings verify for one
//! payload. The JWS itself is not stored.

use super::agent_state::{classify, n, s};
use super::publishing::{self, PublishingSuspension};
use super::{DynamoDBError, DynamoDBStore, account};
use crate::app_store::Environment;
use aws_sdk_dynamodb::types::{AttributeValue, ReturnValue};
use log::warn;
use std::collections::HashMap;
use uuid::Uuid;

const ATTR: &str = "app_store";
const LINK_PREFIX: &str = "appstore#";

fn link_pk(otid: &str) -> String {
    format!("{LINK_PREFIX}{otid}")
}

/// One subscription's stored state. The key in the map is
/// `original_transaction_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppStoreRecord {
    pub original_transaction_id: String,
    pub product_id: String,
    pub environment: Environment,
    pub expires_at: i64,
    pub grace_expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub last_signed_at: i64,
}

/// Outcome of [`DynamoDBStore::bind_app_store_link`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkOutcome {
    /// The subscription is now bound to this account.
    Bound,
    /// It was already bound to this account.
    AlreadyYours,
    /// It is bound to another account; nothing was written.
    BoundElsewhere,
}

/// Outcome of [`DynamoDBStore::put_app_store_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateOutcome {
    /// The record was written.
    Applied,
    /// A record with a later `last_signed_at` is stored; nothing changed.
    Stale,
    /// The account has no live row (unknown or deleted); nothing was written.
    AccountGone,
}

/// What a state write does to the stored `grace_expires_at`. Only the
/// notifications know the grace period (it comes from their renewal info), so
/// a client's post is `Keep` and never changes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraceUpdate {
    /// Leave a stored grace as it is; a new entry gets none. The record's own
    /// `grace_expires_at` is ignored.
    Keep,
    /// Store this grace (or clear it with `None`), whatever the record says.
    Set(Option<i64>),
}

/// What one consistent read of the `credentials` row yields for a mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishingState {
    // Read by the mint, which arrives in a later change.
    #[cfg_attr(not(test), allow(dead_code))]
    pub suspension: Option<PublishingSuspension>,
    pub app_store: Vec<AppStoreRecord>,
}

fn environment_str(e: Environment) -> &'static str {
    match e {
        Environment::Production => "Production",
        Environment::Sandbox => "Sandbox",
    }
}

fn parse_environment(v: &str) -> Option<Environment> {
    match v {
        "Production" => Some(Environment::Production),
        "Sandbox" => Some(Environment::Sandbox),
        _ => None,
    }
}

fn to_attr(rec: &AppStoreRecord) -> AttributeValue {
    let mut m = HashMap::new();
    m.insert("product_id".to_string(), s(&rec.product_id));
    m.insert(
        "environment".to_string(),
        s(environment_str(rec.environment)),
    );
    m.insert("expires_at".to_string(), n(rec.expires_at));
    if let Some(g) = rec.grace_expires_at {
        m.insert("grace_expires_at".to_string(), n(g));
    }
    if let Some(r) = rec.revoked_at {
        m.insert("revoked_at".to_string(), n(r));
    }
    m.insert("last_signed_at".to_string(), n(rec.last_signed_at));
    AttributeValue::M(m)
}

/// Parse one stored record. `None` for a malformed one.
fn from_attr(otid: &str, v: &AttributeValue) -> Option<AppStoreRecord> {
    let m = v.as_m().ok()?;
    let text = |k: &str| m.get(k).and_then(|v| v.as_s().ok()).cloned();
    let num = |k: &str| {
        m.get(k)
            .and_then(|v| v.as_n().ok())
            .and_then(|v| v.parse::<i64>().ok())
    };
    // An optional field that is present but unreadable makes the record
    // malformed: dropping a `revoked_at` would grant what a refund removed.
    let optional = |k: &str| match m.get(k) {
        None => Some(None),
        Some(_) => num(k).map(Some),
    };
    Some(AppStoreRecord {
        original_transaction_id: otid.to_string(),
        product_id: text("product_id")?,
        environment: parse_environment(&text("environment")?)?,
        expires_at: num("expires_at")?,
        grace_expires_at: optional("grace_expires_at")?,
        revoked_at: optional("revoked_at")?,
        last_signed_at: num("last_signed_at")?,
    })
}

impl DynamoDBStore {
    /// Bind a subscription to an account: a conditional write of
    /// `appstore#<otid>` that succeeds when the link is absent or already this
    /// account's (a re-bind keeps `created_at`). Afterwards the account is
    /// checked again: a deletion may have swept the links before this one
    /// landed, so on a dead account the link is deleted and
    /// [`DynamoDBError::AccountGone`] returned (even when the delete fails;
    /// the sweep removes the link then). If the re-check itself fails, its
    /// error is returned and a link this call created is taken back; the
    /// caller retries, which is idempotent.
    pub async fn bind_app_store_link(
        &self,
        otid: &str,
        user_id: &Uuid,
    ) -> Result<LinkOutcome, DynamoDBError> {
        let table = &self.identity_links_table;
        let uid = s(&user_id.to_string());
        let result = self
            .client
            .update_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(otid)))
            .update_expression("SET user_id = :uid, created_at = if_not_exists(created_at, :now)")
            .condition_expression("attribute_not_exists(link_pk) OR user_id = :uid")
            .expression_attribute_values(":uid", uid)
            .expression_attribute_values(":now", n(chrono::Utc::now().timestamp()))
            .return_values(ReturnValue::AllOld)
            .send()
            .await;
        let outcome = match result {
            Ok(out) => {
                if out.attributes.is_some_and(|a| !a.is_empty()) {
                    LinkOutcome::AlreadyYours
                } else {
                    LinkOutcome::Bound
                }
            }
            Err(e) => match classify(e, table) {
                DynamoDBError::ConditionalConflict => return Ok(LinkOutcome::BoundElsewhere),
                other => return Err(other),
            },
        };
        match self.is_account_live(user_id).await {
            Ok(true) => Ok(outcome),
            Ok(false) => {
                // Dead either way: a link that could not be taken back stays
                // for the deletion sweep (it removes every link of the
                // account), and the caller still hears the account is gone.
                if let Err(e) = self.delete_app_store_link(otid, user_id).await {
                    warn!("could not take back app store link original_transaction_id={otid}: {e}");
                }
                Err(DynamoDBError::AccountGone)
            }
            Err(e) => {
                // Unknown whether the account died. A link this call just
                // wrote is taken back so the failed bind leaves nothing; one
                // that was already this account's was bound by an earlier,
                // checked call and stays.
                if outcome == LinkOutcome::Bound
                    && let Err(del) = self.delete_app_store_link(otid, user_id).await
                {
                    warn!(
                        "could not take back app store link original_transaction_id={otid}: {del}"
                    );
                }
                Err(e)
            }
        }
    }

    /// Delete `appstore#<otid>` while it still names `user_id`.
    async fn delete_app_store_link(&self, otid: &str, user_id: &Uuid) -> Result<(), DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .delete_item()
            .table_name(table)
            .key("link_pk", s(&link_pk(otid)))
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

    /// The account a subscription is bound to. A consistent read.
    pub async fn app_store_link_owner(&self, otid: &str) -> Result<Option<Uuid>, DynamoDBError> {
        let out = self
            .client
            .get_item()
            .table_name(&self.identity_links_table)
            .key("link_pk", s(&link_pk(otid)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| self.map_get_item_err(&self.identity_links_table, e))?;
        let Some(item) = out.item else {
            return Ok(None);
        };
        let user_id = item
            .get("user_id")
            .and_then(|v| v.as_s().ok())
            .ok_or_else(|| DynamoDBError::Internal("app store link has no user_id".into()))?;
        Ok(Some(Uuid::parse_str(user_id)?))
    }

    /// Store a subscription's state on the account's `credentials` row.
    ///
    /// Every write is conditional on `LIVE_ROW` and on the ordering rule: the
    /// incoming `last_signed_at` must be later than the stored one, or equal
    /// to it unless that would replace a stored `revoked_at` with a snapshot
    /// that has none (two snapshots signed in the same second apply in
    /// arrival order, but a refund is never undone by a tie).
    ///
    /// An existing entry is updated field by field, so a field the write does
    /// not own (`grace_expires_at` under [`GraceUpdate::Keep`]) is left
    /// alone; the whole entry is written only when it is new. DynamoDB
    /// rejects overlapping document paths in one expression and cannot create
    /// a map and a key in it at once, so the attempts are conditional
    /// updates, each atomic: update the existing entry; else ensure the map
    /// and insert the entry if absent; else (a concurrent insert won) update
    /// once more. If none applies the record is `Stale` (a later or tied
    /// revoked snapshot is stored) or the account is gone.
    pub async fn put_app_store_state(
        &self,
        user_id: &Uuid,
        rec: &AppStoreRecord,
        grace: GraceUpdate,
    ) -> Result<StateOutcome, DynamoDBError> {
        if self.update_app_store_entry(user_id, rec, grace).await? {
            return Ok(StateOutcome::Applied);
        }
        if self.insert_app_store_entry(user_id, rec, grace).await? {
            return Ok(StateOutcome::Applied);
        }
        if self.update_app_store_entry(user_id, rec, grace).await? {
            return Ok(StateOutcome::Applied);
        }
        if self.is_account_live(user_id).await? {
            Ok(StateOutcome::Stale)
        } else {
            Ok(StateOutcome::AccountGone)
        }
    }

    /// Update the fields of an existing entry. `false`: the entry is absent,
    /// the row is not live, or the ordering rule refuses the write.
    async fn update_app_store_entry(
        &self,
        user_id: &Uuid,
        rec: &AppStoreRecord,
        grace: GraceUpdate,
    ) -> Result<bool, DynamoDBError> {
        let table = &self.credentials_table;
        let entry = "#as.#otid";
        let mut sets = vec![
            format!("{entry}.#pid = :pid"),
            format!("{entry}.#env = :env"),
            format!("{entry}.#exp = :exp"),
            format!("{entry}.#signed = :signed"),
        ];
        let mut removes = Vec::new();
        match rec.revoked_at {
            Some(_) => sets.push(format!("{entry}.#rev = :rev")),
            None => removes.push(format!("{entry}.#rev")),
        }
        match grace {
            GraceUpdate::Keep => {}
            GraceUpdate::Set(Some(_)) => sets.push(format!("{entry}.#grace = :grace")),
            GraceUpdate::Set(None) => removes.push(format!("{entry}.#grace")),
        }
        let mut expression = format!("SET {}", sets.join(", "));
        if !removes.is_empty() {
            expression.push_str(&format!(" REMOVE {}", removes.join(", ")));
        }
        // A tie replaces a stored snapshot unless that drops its revocation.
        let ordering = if rec.revoked_at.is_some() {
            format!("{entry}.#signed <= :signed")
        } else {
            format!(
                "({entry}.#signed < :signed OR \
                 ({entry}.#signed = :signed AND attribute_not_exists({entry}.#rev)))"
            )
        };
        let mut update = self
            .client
            .update_item()
            .table_name(table)
            .key("user_id", s(&user_id.to_string()))
            .update_expression(expression)
            .condition_expression(format!(
                "{} AND attribute_exists({entry}) AND {ordering}",
                account::LIVE_ROW
            ))
            .expression_attribute_names("#as", ATTR)
            .expression_attribute_names("#otid", &rec.original_transaction_id)
            .expression_attribute_names("#pid", "product_id")
            .expression_attribute_names("#env", "environment")
            .expression_attribute_names("#exp", "expires_at")
            .expression_attribute_names("#signed", "last_signed_at")
            .expression_attribute_values(":pid", s(&rec.product_id))
            .expression_attribute_values(":env", s(environment_str(rec.environment)))
            .expression_attribute_values(":exp", n(rec.expires_at))
            .expression_attribute_values(":signed", n(rec.last_signed_at));
        if let Some(revoked) = rec.revoked_at {
            update = update
                .expression_attribute_names("#rev", "revoked_at")
                .expression_attribute_values(":rev", n(revoked));
        } else {
            update = update.expression_attribute_names("#rev", "revoked_at");
        }
        match grace {
            GraceUpdate::Set(Some(g)) => {
                update = update
                    .expression_attribute_names("#grace", "grace_expires_at")
                    .expression_attribute_values(":grace", n(g));
            }
            GraceUpdate::Set(None) => {
                update = update.expression_attribute_names("#grace", "grace_expires_at");
            }
            GraceUpdate::Keep => {}
        }
        match update.send().await {
            Ok(_) => Ok(true),
            Err(e) => match classify(e, table) {
                DynamoDBError::ConditionalConflict => Ok(false),
                other => Err(other),
            },
        }
    }

    /// Ensure the `app_store` map exists, then write the whole entry if it is
    /// absent. `false`: the entry exists already or the row is not live.
    async fn insert_app_store_entry(
        &self,
        user_id: &Uuid,
        rec: &AppStoreRecord,
        grace: GraceUpdate,
    ) -> Result<bool, DynamoDBError> {
        let table = &self.credentials_table;
        let key = s(&user_id.to_string());

        let ensure = self
            .client
            .update_item()
            .table_name(table)
            .key("user_id", key.clone())
            .update_expression("SET #as = :empty")
            .condition_expression(format!(
                "{} AND attribute_not_exists(#as)",
                account::LIVE_ROW
            ))
            .expression_attribute_names("#as", ATTR)
            .expression_attribute_values(":empty", AttributeValue::M(HashMap::new()))
            .send()
            .await;
        if let Err(e) = ensure {
            // Already there (or no live row, which the insert reports).
            match classify(e, table) {
                DynamoDBError::ConditionalConflict => {}
                other => return Err(other),
            }
        }

        let entry = AppStoreRecord {
            grace_expires_at: match grace {
                GraceUpdate::Keep => None,
                GraceUpdate::Set(g) => g,
            },
            ..rec.clone()
        };
        let set = self
            .client
            .update_item()
            .table_name(table)
            .key("user_id", key)
            .update_expression("SET #as.#otid = :rec")
            .condition_expression(format!(
                "{} AND attribute_exists(#as) AND attribute_not_exists(#as.#otid)",
                account::LIVE_ROW
            ))
            .expression_attribute_names("#as", ATTR)
            .expression_attribute_names("#otid", &rec.original_transaction_id)
            .expression_attribute_values(":rec", to_attr(&entry))
            .send()
            .await;
        match set {
            Ok(_) => Ok(true),
            Err(e) => match classify(e, table) {
                DynamoDBError::ConditionalConflict => Ok(false),
                other => Err(other),
            },
        }
    }

    /// The suspension and the App Store records of an account, from one
    /// consistent read of its `credentials` row. `Ok(None)` when there is no
    /// live row. A record that cannot be read is left out (it grants nothing)
    /// and logged by transaction id; the others and the suspension still
    /// count. A suspension or an `app_store` attribute of the wrong type is
    /// an error, so the caller fails closed.
    pub async fn get_publishing_state(
        &self,
        user_id: &Uuid,
    ) -> Result<Option<PublishingState>, DynamoDBError> {
        let out = self
            .client
            .get_item()
            .table_name(&self.credentials_table)
            .key("user_id", s(&user_id.to_string()))
            .projection_expression("user_id, #ps, #as, deleted_at")
            .expression_attribute_names("#ps", publishing::ATTR)
            .expression_attribute_names("#as", ATTR)
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| classify(e, &self.credentials_table))?;
        let Some(item) = out.item.filter(|i| !account::is_tombstone(i)) else {
            return Ok(None);
        };
        let suspension = match item.get(publishing::ATTR) {
            Some(v) => Some(publishing::from_attr(v)?),
            None => None,
        };
        let mut app_store = Vec::new();
        if let Some(v) = item.get(ATTR) {
            let map = v
                .as_m()
                .map_err(|_| DynamoDBError::Internal(format!("{ATTR} is not a map")))?;
            for (otid, v) in map {
                match from_attr(otid, v) {
                    Some(rec) => app_store.push(rec),
                    None => warn!("unreadable app store record original_transaction_id={otid}"),
                }
            }
        }
        // Stable order for callers and tests.
        app_store.sort_by(|a, b| a.original_transaction_id.cmp(&b.original_transaction_id));
        Ok(Some(PublishingState {
            suspension,
            app_store,
        }))
    }
}

impl DynamoDBStore {
    /// This store with another `credentials` table name. Tests point it at a
    /// table that does not exist to make account lookups fail.
    #[cfg(test)]
    pub(crate) fn with_credentials_table(&self, table: String) -> DynamoDBStore {
        DynamoDBStore::with_client(
            self.client.clone(),
            table,
            self.handles_table.clone(),
            self.device_bindings_table.clone(),
            self.identity_links_table.clone(),
            self.patreon_tokens_table.clone(),
            self.agent_delegations_table.clone(),
            self.device_attest_keys_table.clone(),
            self.guardians_table.clone(),
            self.default_entitlements.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tests::local_store;

    fn otid() -> String {
        // Numeric, as Apple's are; unique per test run.
        Uuid::new_v4().as_u128().to_string()
    }

    fn rec(otid: &str, signed: i64) -> AppStoreRecord {
        AppStoreRecord {
            original_transaction_id: otid.to_string(),
            product_id: "com.arkavo.ArkavoCreator.membership.monthly".into(),
            environment: Environment::Production,
            expires_at: signed + 2_592_000,
            grace_expires_at: None,
            revoked_at: None,
            last_signed_at: signed,
        }
    }

    /// Store `rec` as a notification would: its own grace, set or cleared.
    fn set(rec: &AppStoreRecord) -> GraceUpdate {
        GraceUpdate::Set(rec.grace_expires_at)
    }

    async fn user(store: &DynamoDBStore, tag: &str) -> Uuid {
        store
            .create_user(
                &format!("{tag}-{}", Uuid::new_v4().simple()),
                "did:key:z6MkAppStoreTest",
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

    async fn state_of(store: &DynamoDBStore, id: &Uuid) -> Vec<AppStoreRecord> {
        store
            .get_publishing_state(id)
            .await
            .unwrap()
            .expect("live row")
            .app_store
    }

    #[test]
    fn record_attr_roundtrip_with_and_without_optionals() {
        let plain = rec("111", 1_700_000_000);
        assert_eq!(from_attr("111", &to_attr(&plain)), Some(plain));
        let full = AppStoreRecord {
            grace_expires_at: Some(1_800_000_000),
            revoked_at: Some(1_750_000_000),
            environment: Environment::Sandbox,
            ..rec("222", 1_700_000_000)
        };
        assert_eq!(from_attr("222", &to_attr(&full)), Some(full));
    }

    #[test]
    fn malformed_record_is_none_not_a_default() {
        assert_eq!(from_attr("1", &AttributeValue::S("x".into())), None);
        assert_eq!(from_attr("1", &AttributeValue::M(HashMap::new())), None);
        // A present but unreadable revoked_at must not read as "not revoked".
        let AttributeValue::M(mut m) = to_attr(&rec("1", 10)) else {
            unreachable!()
        };
        m.insert("revoked_at".into(), s("soon"));
        assert_eq!(from_attr("1", &AttributeValue::M(m)), None);
    }

    #[tokio::test]
    async fn bind_link_new_then_already_yours_then_elsewhere() {
        let Some(store) = local_store() else { return };
        let (a, b) = (user(&store, "asb-a").await, user(&store, "asb-b").await);
        let t = otid();

        assert_eq!(store.app_store_link_owner(&t).await.unwrap(), None);
        assert_eq!(
            store.bind_app_store_link(&t, &a).await.unwrap(),
            LinkOutcome::Bound
        );
        assert_eq!(store.app_store_link_owner(&t).await.unwrap(), Some(a));
        let created = |item: HashMap<String, AttributeValue>| item["created_at"].clone();
        let first = created(link_item(&store, &t).await);

        assert_eq!(
            store.bind_app_store_link(&t, &a).await.unwrap(),
            LinkOutcome::AlreadyYours
        );
        // A re-bind keeps the original created_at.
        assert_eq!(created(link_item(&store, &t).await), first);

        assert_eq!(
            store.bind_app_store_link(&t, &b).await.unwrap(),
            LinkOutcome::BoundElsewhere
        );
        // The refused bind wrote nothing.
        assert_eq!(store.app_store_link_owner(&t).await.unwrap(), Some(a));
    }

    /// A store whose `credentials` table does not exist, so the liveness
    /// re-check after a link write errors while the link write itself works.
    fn store_with_unreadable_accounts(store: &DynamoDBStore) -> DynamoDBStore {
        store.with_credentials_table(format!("missing-credentials-{}", Uuid::new_v4().simple()))
    }

    /// Fails every `DeleteItem` before it is sent.
    #[derive(Debug)]
    struct RefuseDeletes;

    impl aws_sdk_dynamodb::config::Intercept for RefuseDeletes {
        fn name(&self) -> &'static str {
            "RefuseDeletes"
        }

        fn read_before_transmit(
            &self,
            context: &aws_sdk_dynamodb::config::interceptors::BeforeTransmitInterceptorContextRef<
                '_,
            >,
            _: &aws_sdk_dynamodb::config::RuntimeComponents,
            _: &mut aws_sdk_dynamodb::config::ConfigBag,
        ) -> Result<(), aws_sdk_dynamodb::error::BoxError> {
            let target = context.request().headers().get("x-amz-target");
            if target.is_some_and(|t| t.ends_with(".DeleteItem")) {
                return Err("delete refused by the test".into());
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_dead_account_is_gone_even_when_the_take_back_fails() {
        let Some(store) = local_store() else { return };
        let config = store
            .client
            .config()
            .to_builder()
            .interceptor(RefuseDeletes)
            .build();
        let no_deletes = DynamoDBStore::with_client(
            aws_sdk_dynamodb::Client::from_conf(config),
            store.credentials_table.clone(),
            store.handles_table.clone(),
            store.device_bindings_table.clone(),
            store.identity_links_table.clone(),
            store.patreon_tokens_table.clone(),
            store.agent_delegations_table.clone(),
            store.device_attest_keys_table.clone(),
            store.guardians_table.clone(),
            vec![],
        );
        let gone = user(&store, "asb-nodelete").await;
        tombstone(&store, &gone).await;
        let t = otid();

        // The take-back itself fails (proved below by the link surviving),
        // yet the caller is told the account is gone, not given a 5xx.
        let err = no_deletes.bind_app_store_link(&t, &gone).await.unwrap_err();
        assert!(matches!(err, DynamoDBError::AccountGone), "{err:?}");
        assert_eq!(store.app_store_link_owner(&t).await.unwrap(), Some(gone));

        // The deletion sweep removes what the take-back could not.
        store.delete_identity_links_of(&gone).await.unwrap();
        assert_eq!(store.app_store_link_owner(&t).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_failed_liveness_recheck_takes_back_the_link_it_wrote() {
        let Some(store) = local_store() else { return };
        let blind = store_with_unreadable_accounts(&store);
        let id = user(&store, "asb-recheck").await;
        let t = otid();

        let err = blind.bind_app_store_link(&t, &id).await.unwrap_err();
        assert!(!matches!(err, DynamoDBError::AccountGone), "{err:?}");
        // The failed bind left nothing behind.
        assert_eq!(store.app_store_link_owner(&t).await.unwrap(), None);

        // A link an earlier, checked bind made is not this call's to remove.
        assert_eq!(
            store.bind_app_store_link(&t, &id).await.unwrap(),
            LinkOutcome::Bound
        );
        let err = blind.bind_app_store_link(&t, &id).await.unwrap_err();
        assert!(!matches!(err, DynamoDBError::AccountGone), "{err:?}");
        assert_eq!(store.app_store_link_owner(&t).await.unwrap(), Some(id));
    }

    async fn link_item(store: &DynamoDBStore, t: &str) -> HashMap<String, AttributeValue> {
        store
            .client
            .get_item()
            .table_name(&store.identity_links_table)
            .key("link_pk", s(&link_pk(t)))
            .consistent_read(true)
            .send()
            .await
            .unwrap()
            .item
            .expect("link row")
    }

    #[tokio::test]
    async fn bind_link_for_tombstoned_account_is_removed() {
        let Some(store) = local_store() else { return };
        let gone = user(&store, "asb-gone").await;
        tombstone(&store, &gone).await;
        let t = otid();

        let err = store.bind_app_store_link(&t, &gone).await.unwrap_err();
        assert!(matches!(err, DynamoDBError::AccountGone), "{err:?}");
        // The link written before the re-check was taken back.
        assert_eq!(store.app_store_link_owner(&t).await.unwrap(), None);

        // The subscription is free for a live account.
        let live = user(&store, "asb-live").await;
        assert_eq!(
            store.bind_app_store_link(&t, &live).await.unwrap(),
            LinkOutcome::Bound
        );
    }

    #[tokio::test]
    async fn state_put_creates_map_then_applies() {
        let Some(store) = local_store() else { return };
        let id = user(&store, "ass-new").await;
        assert!(state_of(&store, &id).await.is_empty());

        let (t1, t2) = (otid(), otid());
        let first = rec(&t1, 1_700_000_000);
        assert_eq!(
            store
                .put_app_store_state(&id, &first, set(&first))
                .await
                .unwrap(),
            StateOutcome::Applied
        );
        assert_eq!(state_of(&store, &id).await, vec![first.clone()]);

        // A second subscription shares the map; the first is untouched.
        let second = AppStoreRecord {
            grace_expires_at: Some(1_800_000_000),
            revoked_at: Some(1_790_000_000),
            environment: Environment::Sandbox,
            ..rec(&t2, 1_700_000_100)
        };
        assert_eq!(
            store
                .put_app_store_state(&id, &second, set(&second))
                .await
                .unwrap(),
            StateOutcome::Applied
        );
        let mut want = vec![first.clone(), second];
        want.sort_by(|a, b| a.original_transaction_id.cmp(&b.original_transaction_id));
        assert_eq!(state_of(&store, &id).await, want);

        // A newer snapshot of the first replaces it; an equal one applies too.
        let renewed = rec(&t1, 1_700_001_000);
        assert_eq!(
            store
                .put_app_store_state(&id, &renewed, set(&renewed))
                .await
                .unwrap(),
            StateOutcome::Applied
        );
        let same_time = AppStoreRecord {
            revoked_at: Some(1_700_001_500),
            ..renewed
        };
        assert_eq!(
            store
                .put_app_store_state(&id, &same_time, set(&same_time))
                .await
                .unwrap(),
            StateOutcome::Applied
        );
        let got = state_of(&store, &id).await;
        assert_eq!(
            got.iter().find(|r| r.original_transaction_id == t1),
            Some(&same_time)
        );
    }

    #[tokio::test]
    async fn state_put_older_signed_is_stale() {
        let Some(store) = local_store() else { return };
        let id = user(&store, "ass-stale").await;
        let t = otid();
        let newer = rec(&t, 1_700_002_000);
        assert_eq!(
            store
                .put_app_store_state(&id, &newer, set(&newer))
                .await
                .unwrap(),
            StateOutcome::Applied
        );
        // An older EXPIRED arriving late must not replace the newer renewal.
        let older = AppStoreRecord {
            expires_at: 1_700_000_500,
            ..rec(&t, 1_700_001_000)
        };
        assert_eq!(
            store
                .put_app_store_state(&id, &older, set(&older))
                .await
                .unwrap(),
            StateOutcome::Stale
        );
        assert_eq!(state_of(&store, &id).await, vec![newer]);
    }

    #[tokio::test]
    async fn state_put_on_tombstone_is_account_gone() {
        let Some(store) = local_store() else { return };
        let gone = user(&store, "ass-gone").await;
        tombstone(&store, &gone).await;
        assert_eq!(
            store
                .put_app_store_state(&gone, &rec(&otid(), 1_700_000_000), GraceUpdate::Keep)
                .await
                .unwrap(),
            StateOutcome::AccountGone
        );
        // Nothing landed on the tombstone.
        let raw = store.raw_credentials_item(&gone).await.unwrap();
        assert!(!raw.contains_key(ATTR));
        assert_eq!(store.get_publishing_state(&gone).await.unwrap(), None);

        // An unknown account is gone too, and no row is created.
        let unknown = Uuid::new_v4();
        assert_eq!(
            store
                .put_app_store_state(&unknown, &rec(&otid(), 1_700_000_000), GraceUpdate::Keep)
                .await
                .unwrap(),
            StateOutcome::AccountGone
        );
        assert!(store.raw_credentials_item(&unknown).await.is_none());
    }

    #[tokio::test]
    async fn publishing_state_returns_suspension_and_records_in_one_read() {
        let Some(store) = local_store() else { return };
        let id = user(&store, "aps").await;
        assert_eq!(
            store.get_publishing_state(&id).await.unwrap(),
            Some(PublishingState {
                suspension: None,
                app_store: vec![]
            })
        );

        let r = rec(&otid(), 1_700_000_000);
        store.put_app_store_state(&id, &r, set(&r)).await.unwrap();
        let sus = PublishingSuspension {
            reason: "report upheld".into(),
            report_id: Some("rpt-9".into()),
            suspended_by: "client:ops".into(),
            suspended_at: 1_700_000_100,
        };
        store.set_publishing_suspension(&id, &sus).await.unwrap();

        assert_eq!(
            store.get_publishing_state(&id).await.unwrap(),
            Some(PublishingState {
                suspension: Some(sus),
                app_store: vec![r]
            })
        );
        assert_eq!(
            store.get_publishing_state(&Uuid::new_v4()).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn an_unreadable_record_is_left_out_not_fatal() {
        let Some(store) = local_store() else { return };
        let id = user(&store, "aps-bad").await;
        let (good, bad) = (otid(), otid());
        let r = rec(&good, 1_700_000_000);
        store.put_app_store_state(&id, &r, set(&r)).await.unwrap();
        store
            .client
            .update_item()
            .table_name(&store.credentials_table)
            .key("user_id", s(&id.to_string()))
            .update_expression("SET #as.#o = :bad")
            .expression_attribute_names("#as", ATTR)
            .expression_attribute_names("#o", &bad)
            .expression_attribute_values(":bad", s("garbage"))
            .send()
            .await
            .unwrap();
        assert_eq!(state_of(&store, &id).await, vec![r]);
    }

    #[tokio::test]
    async fn delete_identity_links_of_removes_appstore_links() {
        let Some(store) = local_store() else { return };
        let id = user(&store, "asd").await;
        let other = user(&store, "asd-other").await;
        let (t1, t2, t3) = (otid(), otid(), otid());
        for t in [&t1, &t2] {
            store.bind_app_store_link(t, &id).await.unwrap();
        }
        store.bind_app_store_link(&t3, &other).await.unwrap();

        assert_eq!(store.delete_identity_links_of(&id).await.unwrap(), 2);
        assert_eq!(store.app_store_link_owner(&t1).await.unwrap(), None);
        assert_eq!(store.app_store_link_owner(&t2).await.unwrap(), None);
        // Another account's link stays.
        assert_eq!(store.app_store_link_owner(&t3).await.unwrap(), Some(other));
    }

    #[tokio::test]
    async fn keep_leaves_a_stored_grace_and_set_replaces_or_clears_it() {
        let Some(store) = local_store() else { return };
        let id = user(&store, "ass-grace").await;
        let t = otid();
        let with_grace = AppStoreRecord {
            grace_expires_at: Some(1_800_000_000),
            ..rec(&t, 1_700_000_000)
        };
        store
            .put_app_store_state(&id, &with_grace, set(&with_grace))
            .await
            .unwrap();

        // A client post: newer, a new term, no say over the grace.
        let renewed = AppStoreRecord {
            expires_at: 1_900_000_000,
            grace_expires_at: Some(42),
            ..rec(&t, 1_700_000_100)
        };
        assert_eq!(
            store
                .put_app_store_state(&id, &renewed, GraceUpdate::Keep)
                .await
                .unwrap(),
            StateOutcome::Applied
        );
        let got = state_of(&store, &id).await;
        assert_eq!(
            got,
            vec![AppStoreRecord {
                grace_expires_at: Some(1_800_000_000),
                ..renewed.clone()
            }]
        );

        // A notification sets another grace, then clears it.
        let later = AppStoreRecord {
            grace_expires_at: Some(1_850_000_000),
            ..rec(&t, 1_700_000_200)
        };
        store
            .put_app_store_state(&id, &later, set(&later))
            .await
            .unwrap();
        assert_eq!(state_of(&store, &id).await, vec![later.clone()]);

        let cleared = AppStoreRecord {
            grace_expires_at: Some(7),
            ..rec(&t, 1_700_000_300)
        };
        store
            .put_app_store_state(&id, &cleared, GraceUpdate::Set(None))
            .await
            .unwrap();
        assert_eq!(
            state_of(&store, &id).await,
            vec![AppStoreRecord {
                grace_expires_at: None,
                ..cleared
            }]
        );
    }

    #[tokio::test]
    async fn keep_on_a_new_entry_stores_no_grace() {
        let Some(store) = local_store() else { return };
        let id = user(&store, "ass-keepnew").await;
        let r = AppStoreRecord {
            grace_expires_at: Some(1_800_000_000),
            ..rec(&otid(), 1_700_000_000)
        };
        assert_eq!(
            store
                .put_app_store_state(&id, &r, GraceUpdate::Keep)
                .await
                .unwrap(),
            StateOutcome::Applied
        );
        assert_eq!(
            state_of(&store, &id).await,
            vec![AppStoreRecord {
                grace_expires_at: None,
                ..r
            }]
        );
    }

    #[tokio::test]
    async fn a_stale_write_leaves_the_grace_alone_too() {
        let Some(store) = local_store() else { return };
        let id = user(&store, "ass-stalegrace").await;
        let t = otid();
        let newer = AppStoreRecord {
            grace_expires_at: Some(1_800_000_000),
            ..rec(&t, 1_700_002_000)
        };
        store
            .put_app_store_state(&id, &newer, set(&newer))
            .await
            .unwrap();
        let older = rec(&t, 1_700_001_000);
        for grace in [GraceUpdate::Keep, GraceUpdate::Set(None)] {
            assert_eq!(
                store.put_app_store_state(&id, &older, grace).await.unwrap(),
                StateOutcome::Stale
            );
        }
        assert_eq!(state_of(&store, &id).await, vec![newer]);
    }

    /// Same-second snapshots apply in arrival order, except that a snapshot
    /// without `revoked_at` never replaces one that has it.
    #[tokio::test]
    async fn a_tie_never_undoes_a_revocation() {
        let Some(store) = local_store() else { return };
        let id = user(&store, "ass-tie").await;
        let t = otid();
        let signed = 1_700_000_000;
        let refunded = AppStoreRecord {
            revoked_at: Some(signed - 5),
            ..rec(&t, signed)
        };
        assert_eq!(
            store
                .put_app_store_state(&id, &refunded, GraceUpdate::Keep)
                .await
                .unwrap(),
            StateOutcome::Applied
        );

        // The same second, no revocation: refused, on either grace mode.
        let live_again = rec(&t, signed);
        for grace in [GraceUpdate::Keep, set(&live_again)] {
            assert_eq!(
                store
                    .put_app_store_state(&id, &live_again, grace)
                    .await
                    .unwrap(),
                StateOutcome::Stale
            );
        }
        assert_eq!(state_of(&store, &id).await, vec![refunded.clone()]);

        // A strictly later snapshot is allowed to lift it.
        let later = rec(&t, signed + 1);
        assert_eq!(
            store
                .put_app_store_state(&id, &later, GraceUpdate::Keep)
                .await
                .unwrap(),
            StateOutcome::Applied
        );
        assert_eq!(state_of(&store, &id).await, vec![later.clone()]);

        // A tie that adds a revocation applies, and ties between plain
        // snapshots apply in arrival order.
        let revoked_now = AppStoreRecord {
            revoked_at: Some(signed + 1),
            ..rec(&t, signed + 1)
        };
        assert_eq!(
            store
                .put_app_store_state(&id, &revoked_now, GraceUpdate::Keep)
                .await
                .unwrap(),
            StateOutcome::Applied
        );
        let t2 = otid();
        let (first, second) = (
            rec(&t2, signed),
            AppStoreRecord {
                expires_at: signed + 99,
                ..rec(&t2, signed)
            },
        );
        for r in [&first, &second] {
            assert_eq!(
                store
                    .put_app_store_state(&id, r, GraceUpdate::Keep)
                    .await
                    .unwrap(),
                StateOutcome::Applied
            );
        }
        let got = state_of(&store, &id).await;
        assert!(
            got.contains(&revoked_now) && got.contains(&second),
            "{got:?}"
        );
    }
}
