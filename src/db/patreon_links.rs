//! Removing a Patreon link (#97): `DELETE /oauth/patreon/link`, and the rows
//! a relink to a different Patreon account leaves behind.
//!
//! `identity_links` has no `user_id` index, so the `patreon_tokens` row is
//! the only record of which `patreon#<sub>` and `patreon-campaign#<cid>`
//! rows an account holds. Every removal reads that row consistently,
//! deletes the rows it points to, and changes the `patreon_tokens` row
//! last. A failure part way leaves the row in place, so a retry finds the
//! rest; until then the link still materializes.

use super::agent_state::{classify, n, s};
use super::{DynamoDBError, DynamoDBStore};
use uuid::Uuid;

/// `provider` of a Patreon account link (`patreon#<patreon_user_id>`).
pub(crate) const PATREON_PROVIDER: &str = "patreon";

/// Reads of a `patreon_tokens` row an unlink makes before it gives up: a
/// relink landing between the read and the delete is removed too.
const UNLINK_ATTEMPTS: usize = 3;

/// What a `patreon_tokens` row says about the rows beside it. Read without
/// the sealed tokens, so a row whose tokens do not parse can still be
/// unlinked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatreonLinkRef {
    pub patreon_user_id: String,
    /// The campaign the link was last seen to own (creators only).
    pub campaign_id: Option<String>,
    pub role: String,
    pub linked_at: i64,
}

impl DynamoDBStore {
    /// The account's `patreon_tokens` row, read consistently: a link written
    /// a moment ago must not read as absent to the unlink that follows it.
    pub async fn get_patreon_link_ref(
        &self,
        user_id: &Uuid,
    ) -> Result<Option<PatreonLinkRef>, DynamoDBError> {
        let table = &self.patreon_tokens_table;
        let out = self
            .client
            .get_item()
            .table_name(table)
            .key("user_id", s(&user_id.to_string()))
            .consistent_read(true)
            .projection_expression("patreon_user_id, campaign_id, #role, linked_at")
            .expression_attribute_names("#role", "role")
            .send()
            .await
            .map_err(|e| classify(e, table))?;
        let Some(item) = out.item else {
            return Ok(None);
        };
        let text = |key: &str| {
            item.get(key)
                .and_then(|v| v.as_s().ok())
                .filter(|v| !v.is_empty())
                .cloned()
        };
        let patreon_user_id = text("patreon_user_id").ok_or_else(|| {
            DynamoDBError::Internal("patreon_tokens row has no patreon_user_id".into())
        })?;
        let linked_at = item
            .get("linked_at")
            .and_then(|v| v.as_n().ok())
            .and_then(|v| v.parse::<i64>().ok())
            .ok_or_else(|| DynamoDBError::Internal("patreon_tokens row has no linked_at".into()))?;
        Ok(Some(PatreonLinkRef {
            campaign_id: text("campaign_id"),
            role: text("role").unwrap_or_default(),
            patreon_user_id,
            linked_at,
        }))
    }

    /// Delete the `<provider>#<subject>` link if it names `user_id`. A
    /// missing row, or one naming another account, is not an error and is
    /// left as it is.
    pub async fn delete_identity_link_if_owned(
        &self,
        provider: &str,
        subject: &str,
        user_id: &Uuid,
    ) -> Result<(), DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .delete_item()
            .table_name(table)
            .key("link_pk", s(&format!("{provider}#{subject}")))
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

    /// Delete the account's `patreon_tokens` row if it is still the link
    /// read (same Patreon user, same `linked_at`). `Ok(false)` when it is
    /// not: relinked or removed meanwhile.
    async fn delete_patreon_link_if_current(
        &self,
        user_id: &Uuid,
        link: &PatreonLinkRef,
    ) -> Result<bool, DynamoDBError> {
        let table = &self.patreon_tokens_table;
        let result = self
            .client
            .delete_item()
            .table_name(table)
            .key("user_id", s(&user_id.to_string()))
            .condition_expression("patreon_user_id = :pid AND linked_at = :la")
            .expression_attribute_values(":pid", s(&link.patreon_user_id))
            .expression_attribute_values(":la", n(link.linked_at))
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

    /// Remove the account's Patreon link (#97): the `patreon#<sub>` row, the
    /// `patreon-campaign#<cid>` row of a creator, then the `patreon_tokens`
    /// row. Returns the link removed, `None` when there was none. A relink
    /// that lands meanwhile is removed too, up to [`UNLINK_ATTEMPTS`] reads;
    /// past that, `ConditionalConflict`.
    pub async fn unlink_patreon(
        &self,
        user_id: &Uuid,
    ) -> Result<Option<PatreonLinkRef>, DynamoDBError> {
        let mut last_seen = None;
        for _ in 0..UNLINK_ATTEMPTS {
            let Some(link) = self.get_patreon_link_ref(user_id).await? else {
                return Ok(last_seen);
            };
            self.delete_identity_link_if_owned(PATREON_PROVIDER, &link.patreon_user_id, user_id)
                .await?;
            if let Some(cid) = link.campaign_id.as_deref() {
                self.delete_patreon_campaign_owner(cid, user_id).await?;
            }
            if self.delete_patreon_link_if_current(user_id, &link).await? {
                return Ok(Some(link));
            }
            last_seen = Some(link);
        }
        Err(DynamoDBError::ConditionalConflict)
    }

    /// Before a link replaces the account's `patreon_tokens` row, give up
    /// what the row it replaces points to (#97): its `patreon#<sub>` row when
    /// the Patreon account changed, and its campaign row when the campaign
    /// owned changed. Otherwise both outlive the row, the only pointer to
    /// them, and the old Patreon account 409s on every other account.
    pub async fn release_replaced_patreon_link(
        &self,
        user_id: &Uuid,
        patreon_user_id: &str,
        campaign_id: Option<&str>,
    ) -> Result<(), DynamoDBError> {
        let Some(previous) = self.get_patreon_link_ref(user_id).await? else {
            return Ok(());
        };
        if previous.patreon_user_id != patreon_user_id {
            self.delete_identity_link_if_owned(
                PATREON_PROVIDER,
                &previous.patreon_user_id,
                user_id,
            )
            .await?;
        }
        if let Some(old) = previous.campaign_id.as_deref()
            && Some(old) != campaign_id
        {
            self.delete_patreon_campaign_owner(old, user_id).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::local_store;
    use super::*;
    use crate::cwt::OwnedCampaignTiers;
    use crate::patreon::PatreonLink;

    fn link(user_id: Uuid, patreon_user_id: &str, campaign_id: Option<&str>) -> PatreonLink {
        PatreonLink {
            user_id,
            role: if campaign_id.is_some() {
                "creator"
            } else {
                "consumer"
            }
            .into(),
            client_id: "client".into(),
            patreon_user_id: patreon_user_id.into(),
            campaign_id: campaign_id.map(str::to_string),
            scopes: "identity".into(),
            access_token_ct: vec![1],
            access_token_nonce: vec![2; 12],
            refresh_token_ct: vec![3],
            refresh_token_nonce: vec![4; 12],
            wrapped_dek: vec![5],
            token_expires_at: 2,
            linked_at: 1,
            owned_tiers: OwnedCampaignTiers::default(),
        }
    }

    fn unique(prefix: char) -> String {
        format!("{prefix}{}", &Uuid::new_v4().as_u128().to_string()[..9])
    }

    async fn owner_of(store: &DynamoDBStore, cid: &str) -> Option<Uuid> {
        store
            .patreon_campaign_owners(&[cid.to_string()])
            .await
            .unwrap()
            .get(cid)
            .copied()
    }

    /// Unlink removes the token row, the account link and the campaign row,
    /// leaves another account's rows alone, and is idempotent.
    #[tokio::test]
    async fn unlink_removes_the_link_and_what_it_points_to() {
        let Some(store) = local_store() else {
            return;
        };
        let (me, other) = (Uuid::new_v4(), Uuid::new_v4());
        let (pid, cid) = (unique('7'), unique('9'));
        store
            .link_identity(me, PATREON_PROVIDER, &pid)
            .await
            .unwrap();
        assert!(
            store
                .put_patreon_campaign_owner(&cid, &me, 1)
                .await
                .unwrap()
        );
        store
            .put_patreon_link(&link(me, &pid, Some(&cid)))
            .await
            .unwrap();
        // Another account's link to a different Patreon account stays.
        let other_pid = unique('6');
        store
            .link_identity(other, PATREON_PROVIDER, &other_pid)
            .await
            .unwrap();

        let removed = store.unlink_patreon(&me).await.unwrap().unwrap();
        assert_eq!(removed.patreon_user_id, pid);
        assert_eq!(removed.campaign_id.as_deref(), Some(cid.as_str()));
        assert_eq!(removed.role, "creator");
        assert!(store.get_patreon_link_ref(&me).await.unwrap().is_none());
        assert!(store.get_patreon_link(me).await.unwrap().is_none());
        assert_eq!(
            store
                .get_identity_link(PATREON_PROVIDER, &pid)
                .await
                .unwrap(),
            None
        );
        assert_eq!(owner_of(&store, &cid).await, None);
        assert_eq!(
            store
                .get_identity_link(PATREON_PROVIDER, &other_pid)
                .await
                .unwrap(),
            Some(other)
        );

        // Nothing left: a repeat is a no-op.
        assert_eq!(store.unlink_patreon(&me).await.unwrap(), None);
        // The Patreon account is free for another Arkavo account.
        store
            .link_identity(other, PATREON_PROVIDER, &pid)
            .await
            .unwrap();
    }

    /// A retry after a failure part way finishes the job: the token row is
    /// still there to say which rows remain.
    #[tokio::test]
    async fn unlink_finishes_after_a_partial_removal() {
        let Some(store) = local_store() else {
            return;
        };
        let me = Uuid::new_v4();
        let pid = unique('7');
        // The account link is already gone, as after a failed first try.
        store.put_patreon_link(&link(me, &pid, None)).await.unwrap();
        assert!(store.unlink_patreon(&me).await.unwrap().is_some());
        assert!(store.get_patreon_link_ref(&me).await.unwrap().is_none());
    }

    /// A rotation of a link that was unlinked or replaced is dropped, never
    /// written back.
    #[tokio::test]
    async fn a_rotation_never_recreates_or_overwrites_a_link() {
        let Some(store) = local_store() else {
            return;
        };
        let me = Uuid::new_v4();
        let old = link(me, &unique('7'), None);

        // Unlinked: no row comes back.
        assert!(!store.put_rotated_patreon_link(&old).await.unwrap());
        assert!(store.get_patreon_link_ref(&me).await.unwrap().is_none());

        // Current: written.
        store.put_patreon_link(&old).await.unwrap();
        let mut rotated = old.clone();
        rotated.token_expires_at = 99;
        assert!(store.put_rotated_patreon_link(&rotated).await.unwrap());
        assert_eq!(
            store
                .get_patreon_link(me)
                .await
                .unwrap()
                .unwrap()
                .token_expires_at,
            99
        );

        // Relinked to another Patreon account: the new link stays.
        let new = link(me, &unique('8'), None);
        store.put_patreon_link(&new).await.unwrap();
        assert!(!store.put_rotated_patreon_link(&rotated).await.unwrap());
        assert_eq!(
            store
                .get_patreon_link_ref(&me)
                .await
                .unwrap()
                .unwrap()
                .patreon_user_id,
            new.patreon_user_id
        );
    }

    /// A relink to another Patreon account gives up the old account link and
    /// the campaign the old link owned; a relink of the same account keeps
    /// its link row.
    #[tokio::test]
    async fn a_relink_releases_what_the_replaced_link_held() {
        let Some(store) = local_store() else {
            return;
        };
        let me = Uuid::new_v4();
        let (old_pid, new_pid, old_cid) = (unique('7'), unique('8'), unique('9'));
        store
            .link_identity(me, PATREON_PROVIDER, &old_pid)
            .await
            .unwrap();
        assert!(
            store
                .put_patreon_campaign_owner(&old_cid, &me, 1)
                .await
                .unwrap()
        );
        store
            .put_patreon_link(&link(me, &old_pid, Some(&old_cid)))
            .await
            .unwrap();

        // Same Patreon account, same campaign: nothing released.
        store
            .release_replaced_patreon_link(&me, &old_pid, Some(&old_cid))
            .await
            .unwrap();
        assert_eq!(
            store
                .get_identity_link(PATREON_PROVIDER, &old_pid)
                .await
                .unwrap(),
            Some(me)
        );
        assert_eq!(owner_of(&store, &old_cid).await, Some(me));

        // Another Patreon account owning no campaign: both released.
        store
            .link_identity(me, PATREON_PROVIDER, &new_pid)
            .await
            .unwrap();
        store
            .release_replaced_patreon_link(&me, &new_pid, None)
            .await
            .unwrap();
        assert_eq!(
            store
                .get_identity_link(PATREON_PROVIDER, &old_pid)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .get_identity_link(PATREON_PROVIDER, &new_pid)
                .await
                .unwrap(),
            Some(me)
        );
        assert_eq!(owner_of(&store, &old_cid).await, None);
    }
}
