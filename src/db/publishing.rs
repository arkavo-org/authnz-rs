//! Publishing suspension (#91): a moderator's override that withholds the
//! derived creator-publishing entitlement from an account whatever its
//! Patreon membership. Stored as one map attribute, `publishing_suspension`,
//! on the account's `credentials` row; the map is the audit record (who, when,
//! why, which report).

use super::agent_state::{classify, n, s};
use super::{DynamoDBError, DynamoDBStore};
use aws_sdk_dynamodb::types::{AttributeValue, ReturnValue};
use std::collections::HashMap;
use uuid::Uuid;

const ATTR: &str = "publishing_suspension";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PublishingSuspension {
    /// Moderator-supplied reason (free text, length-bounded by the handler).
    pub reason: String,
    /// The moderation report this suspension acts on, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_id: Option<String>,
    /// The service client that set it (`client:<id>` from the service CWT).
    pub suspended_by: String,
    /// Unix time it was set.
    pub suspended_at: i64,
}

/// Outcome of [`DynamoDBStore::set_publishing_suspension`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuspensionSet {
    /// The suspension was written.
    Created,
    /// The account was already suspended; the stored record (the original
    /// audit) is kept unchanged and returned.
    AlreadySuspended(PublishingSuspension),
    /// No credentials row for this user.
    UserNotFound,
}

/// Outcome of [`DynamoDBStore::lift_publishing_suspension`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuspensionLift {
    /// The suspension was removed; this was the record.
    Lifted(PublishingSuspension),
    /// The account was not suspended (nothing changed).
    NotSuspended,
    /// No credentials row for this user.
    UserNotFound,
}

fn to_attr(sus: &PublishingSuspension) -> AttributeValue {
    let mut m = HashMap::new();
    m.insert("reason".to_string(), s(&sus.reason));
    if let Some(r) = &sus.report_id {
        m.insert("report_id".to_string(), s(r));
    }
    m.insert("suspended_by".to_string(), s(&sus.suspended_by));
    m.insert("suspended_at".to_string(), n(sus.suspended_at));
    AttributeValue::M(m)
}

/// Parse the stored map. A malformed record is an error, not "not
/// suspended": the caller fails closed on it.
fn from_attr(v: &AttributeValue) -> Result<PublishingSuspension, DynamoDBError> {
    let m = v
        .as_m()
        .map_err(|_| DynamoDBError::Internal(format!("{ATTR} is not a map")))?;
    let text = |k: &str| m.get(k).and_then(|v| v.as_s().ok()).cloned();
    Ok(PublishingSuspension {
        reason: text("reason").unwrap_or_default(),
        report_id: text("report_id"),
        suspended_by: text("suspended_by")
            .ok_or_else(|| DynamoDBError::Internal(format!("{ATTR} missing suspended_by")))?,
        suspended_at: m
            .get("suspended_at")
            .and_then(|v| v.as_n().ok())
            .and_then(|v| v.parse::<i64>().ok())
            .ok_or_else(|| DynamoDBError::Internal(format!("{ATTR} missing suspended_at")))?,
    })
}

impl DynamoDBStore {
    /// The account's publishing suspension. `Ok(None)` when the user row is
    /// absent, `Ok(Some(None))` when it exists unsuspended. Strongly
    /// consistent, so a suspension applies to the very next mint.
    pub async fn get_publishing_suspension(
        &self,
        user_id: &Uuid,
    ) -> Result<Option<Option<PublishingSuspension>>, DynamoDBError> {
        let out = self
            .client
            .get_item()
            .table_name(&self.credentials_table)
            .key("user_id", s(&user_id.to_string()))
            .projection_expression("user_id, #ps")
            .expression_attribute_names("#ps", ATTR)
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| classify(e, &self.credentials_table))?;
        let Some(item) = out.item else {
            return Ok(None);
        };
        match item.get(ATTR) {
            Some(v) => Ok(Some(Some(from_attr(v)?))),
            None => Ok(Some(None)),
        }
    }

    /// Suspend publishing. One conditional `UpdateItem`: the row must exist
    /// and must not already be suspended, so a repeated request keeps the
    /// first record (who/when/why) rather than overwriting the audit.
    pub async fn set_publishing_suspension(
        &self,
        user_id: &Uuid,
        suspension: &PublishingSuspension,
    ) -> Result<SuspensionSet, DynamoDBError> {
        let result = self
            .client
            .update_item()
            .table_name(&self.credentials_table)
            .key("user_id", s(&user_id.to_string()))
            .update_expression("SET #ps = :ps")
            .condition_expression("attribute_exists(user_id) AND attribute_not_exists(#ps)")
            .expression_attribute_names("#ps", ATTR)
            .expression_attribute_values(":ps", to_attr(suspension))
            .send()
            .await;
        match result {
            Ok(_) => Ok(SuspensionSet::Created),
            Err(e) => match classify(e, &self.credentials_table) {
                DynamoDBError::ConditionalConflict => {
                    match self.get_publishing_suspension(user_id).await? {
                        None => Ok(SuspensionSet::UserNotFound),
                        Some(Some(existing)) => Ok(SuspensionSet::AlreadySuspended(existing)),
                        // Lifted between the write and this read: report the
                        // race rather than guess.
                        Some(None) => Err(DynamoDBError::ConditionalConflict),
                    }
                }
                other => Err(other),
            },
        }
    }

    /// Lift a suspension. Conditional on the row existing; idempotent (an
    /// unsuspended account is `NotSuspended`). Returns the removed record so
    /// the caller can write it to the audit log.
    pub async fn lift_publishing_suspension(
        &self,
        user_id: &Uuid,
    ) -> Result<SuspensionLift, DynamoDBError> {
        let result = self
            .client
            .update_item()
            .table_name(&self.credentials_table)
            .key("user_id", s(&user_id.to_string()))
            .update_expression("REMOVE #ps")
            .condition_expression("attribute_exists(user_id)")
            .expression_attribute_names("#ps", ATTR)
            .return_values(ReturnValue::UpdatedOld)
            .send()
            .await;
        match result {
            Ok(out) => match out.attributes.as_ref().and_then(|a| a.get(ATTR)) {
                Some(v) => Ok(SuspensionLift::Lifted(from_attr(v)?)),
                None => Ok(SuspensionLift::NotSuspended),
            },
            Err(e) => match classify(e, &self.credentials_table) {
                DynamoDBError::ConditionalConflict => Ok(SuspensionLift::UserNotFound),
                other => Err(other),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tests::local_store;

    fn sample(by: &str) -> PublishingSuspension {
        PublishingSuspension {
            reason: "copyright report upheld".into(),
            report_id: Some("rpt-1".into()),
            suspended_by: by.into(),
            suspended_at: 1_700_000_000,
        }
    }

    #[test]
    fn attr_roundtrip_with_and_without_report_id() {
        let a = sample("client:ops");
        assert_eq!(from_attr(&to_attr(&a)).unwrap(), a);
        let b = PublishingSuspension {
            report_id: None,
            ..sample("client:ops")
        };
        assert_eq!(from_attr(&to_attr(&b)).unwrap(), b);
    }

    #[test]
    fn malformed_record_is_an_error_not_unsuspended() {
        assert!(from_attr(&AttributeValue::S("x".into())).is_err());
        assert!(from_attr(&AttributeValue::M(HashMap::new())).is_err());
    }

    #[tokio::test]
    async fn set_get_lift_roundtrip_against_dynamodb_local() {
        let Some(store) = local_store() else {
            return;
        };
        let user = store
            .create_user(
                &format!("pub-{}", Uuid::new_v4().simple()),
                "did:key:z6MkPublishingSuspensionTest",
            )
            .await
            .expect("create user");
        let id = user.user_id;

        assert_eq!(
            store.get_publishing_suspension(&id).await.unwrap(),
            Some(None)
        );
        assert_eq!(
            store
                .set_publishing_suspension(&id, &sample("client:ops"))
                .await
                .unwrap(),
            SuspensionSet::Created
        );
        assert_eq!(
            store.get_publishing_suspension(&id).await.unwrap(),
            Some(Some(sample("client:ops")))
        );
        // A second set keeps the first audit record.
        assert_eq!(
            store
                .set_publishing_suspension(&id, &sample("client:other"))
                .await
                .unwrap(),
            SuspensionSet::AlreadySuspended(sample("client:ops"))
        );
        // The stored entitlement list is untouched by suspension.
        let row = store.get_user_by_id(&id).await.unwrap().unwrap();
        assert_eq!(row.entitlements, user.entitlements);

        assert_eq!(
            store.lift_publishing_suspension(&id).await.unwrap(),
            SuspensionLift::Lifted(sample("client:ops"))
        );
        assert_eq!(
            store.lift_publishing_suspension(&id).await.unwrap(),
            SuspensionLift::NotSuspended
        );
        assert_eq!(
            store.get_publishing_suspension(&id).await.unwrap(),
            Some(None)
        );
    }

    #[tokio::test]
    async fn unknown_user_is_reported_not_created() {
        let Some(store) = local_store() else {
            return;
        };
        let id = Uuid::new_v4();
        assert_eq!(store.get_publishing_suspension(&id).await.unwrap(), None);
        assert_eq!(
            store
                .set_publishing_suspension(&id, &sample("client:ops"))
                .await
                .unwrap(),
            SuspensionSet::UserNotFound
        );
        assert_eq!(
            store.lift_publishing_suspension(&id).await.unwrap(),
            SuspensionLift::UserNotFound
        );
        // The conditional writes created no row.
        assert!(store.get_user_by_id(&id).await.unwrap().is_none());
    }
}
