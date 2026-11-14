//! Sign in with Apple refresh tokens held for revocation. A token lives on
//! its identity link: the `identity_links` row `apple#<sub>` carries it,
//! sealed by the Patreon KMS envelope, in the `token_*` attributes.
//! `POST /oauth/apple/link` writes the link and its token in one update; the
//! account-deletion sweep deletes the row once Apple has revoked the token, as
//! does a link whose account was deleted while it was in flight. Until then
//! the sweep's link step leaves a row that holds a token in place.

use super::agent_state::{classify, n, s};
use super::{DynamoDBError, DynamoDBStore};
use crate::apple_tokens::{AppleTokenRow, apple_link_key};
use crate::patreon::SealedToken;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::AttributeValue;
use log::error;
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

/// The attributes of a stored token on an `identity_links` row.
const TOKEN_CLIENT_ID: &str = "token_client_id";
const TOKEN_WRAPPED_DEK: &str = "token_wrapped_dek";
const TOKEN_NONCE: &str = "token_nonce";
const TOKEN_CT: &str = "token_ct";
const TOKEN_STORED_AT: &str = "token_stored_at";

/// A row holding any of these holds a token (or the remains of one) that
/// account deletion must revoke before the row may go.
const TOKEN_ATTRS: [&str; 4] = [TOKEN_CLIENT_ID, TOKEN_WRAPPED_DEK, TOKEN_NONCE, TOKEN_CT];

/// Condition for deleting an identity link in the sweep's link step: the row
/// holds no token. One that does is deleted by the revocation step instead.
pub(super) const HOLDS_NO_TOKEN: &str = "attribute_not_exists(token_client_id) \
     AND attribute_not_exists(token_wrapped_dek) \
     AND attribute_not_exists(token_nonce) AND attribute_not_exists(token_ct)";

fn holds_token(item: &HashMap<String, AttributeValue>) -> bool {
    TOKEN_ATTRS.iter().any(|k| item.contains_key(*k))
}

fn parse_row(item: &HashMap<String, AttributeValue>) -> Option<AppleTokenRow> {
    let text = |k: &str| item.get(k).and_then(|v| v.as_s().ok()).cloned();
    let bytes = |k: &str| {
        item.get(k)
            .and_then(|v| v.as_b().ok())
            .map(|b| b.as_ref().to_vec())
    };
    Some(AppleTokenRow {
        link_key: text("link_pk")?,
        user_id: Uuid::parse_str(&text("user_id")?).ok()?,
        client_id: text(TOKEN_CLIENT_ID)?,
        sealed: SealedToken {
            wrapped_dek: bytes(TOKEN_WRAPPED_DEK)?,
            nonce: bytes(TOKEN_NONCE)?,
            ciphertext: bytes(TOKEN_CT)?,
        },
        stored_at: item
            .get(TOKEN_STORED_AT)
            .and_then(|v| v.as_n().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    })
}

/// An account's Apple identity links, as `apple_tokens_of` found them.
pub struct AppleTokensOfUser {
    /// The rows holding a token that could be read.
    pub rows: Vec<AppleTokenRow>,
    /// The `link_pk` of each row that matched the account and holds token
    /// attributes that cannot be read. Its token cannot be revoked, so a
    /// caller must not treat the account as holding none.
    pub unreadable: Vec<String>,
    /// The `link_pk` of each of the account's Apple links that holds no
    /// token at all (every link made without revocation configured). The
    /// sweep's link step deletes these; `DELETE /oauth/apple/link` does too.
    pub without_token: Vec<String>,
}

impl AppleTokensOfUser {
    /// Whether the account has no Apple link of any kind.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty() && self.unreadable.is_empty() && self.without_token.is_empty()
    }
}

impl fmt::Debug for AppleTokensOfUser {
    // Counts only: a link key holds the full Apple `sub`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppleTokensOfUser")
            .field("rows", &self.rows)
            .field("unreadable", &self.unreadable.len())
            .field("without_token", &self.without_token.len())
            .finish()
    }
}

/// The `credentials` attribute set when the account last unlinked Apple
/// (`DELETE /oauth/apple/link`). A refresh token issued before refresh
/// tokens recorded their Apple ID cannot name it, so the refresh grant ends
/// such a session once this is set.
const APPLE_UNLINKED_AT: &str = "apple_unlinked_at";

/// The `credentials` attribute present while the account may have an Apple
/// link: the time (unix milliseconds) of the last link attempt that got past
/// the id_token check.
/// Set before and after every Apple link write, removed only by an unlink
/// that leaves no Apple link. A passkey token's `arkavo_apple_linked` reads
/// it, so it errs toward present: a link that fails after it was set leaves
/// it, and the unlink route (204 when nothing is linked) clears it.
pub(super) const APPLE_LINKED_AT: &str = "apple_linked_at";

/// Counts every mark of [`APPLE_LINKED_AT`] and is never removed. An unlink
/// reads it before its scan and clears the mark only while it is unchanged,
/// so a link marked during the unlink keeps its mark whatever the clocks
/// say. Absent on a mark written by the backfill script.
const APPLE_LINK_GENERATION: &str = "apple_link_generation";

/// The Apple link mark as an unlink saw it before its scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppleLinkMark {
    generation: Option<i64>,
}

impl DynamoDBStore {
    /// Link an Apple identity to `user_id` and store its sealed refresh token
    /// on the link, in one conditional update: the link and its token are
    /// written together or not at all. A re-link by the same account replaces
    /// the token; the replaced one is not revoked (Apple's revoke is
    /// authorization-wide, so it would also end the token just stored). A link
    /// held by another account is `LinkConflict`, and nothing is written.
    pub async fn link_apple_with_token(
        &self,
        user_id: Uuid,
        sub: &str,
        client_id: &str,
        sealed: &SealedToken,
        now: i64,
    ) -> Result<(), DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .update_item()
            .table_name(table)
            .key("link_pk", s(&apple_link_key(sub)))
            .update_expression(
                "SET user_id = :uid, provider = :provider, subject = :subject, \
                 linked_at = :now, #cid = :cid, #dek = :dek, #nonce = :nonce, \
                 #ct = :ct, #at = :now",
            )
            .condition_expression("attribute_not_exists(link_pk) OR user_id = :uid")
            .expression_attribute_names("#cid", TOKEN_CLIENT_ID)
            .expression_attribute_names("#dek", TOKEN_WRAPPED_DEK)
            .expression_attribute_names("#nonce", TOKEN_NONCE)
            .expression_attribute_names("#ct", TOKEN_CT)
            .expression_attribute_names("#at", TOKEN_STORED_AT)
            .expression_attribute_values(":uid", s(&user_id.to_string()))
            .expression_attribute_values(":provider", s("apple"))
            .expression_attribute_values(":subject", s(sub))
            .expression_attribute_values(":now", n(now))
            .expression_attribute_values(":cid", s(client_id))
            .expression_attribute_values(
                ":dek",
                AttributeValue::B(Blob::new(sealed.wrapped_dek.clone())),
            )
            .expression_attribute_values(
                ":nonce",
                AttributeValue::B(Blob::new(sealed.nonce.clone())),
            )
            .expression_attribute_values(
                ":ct",
                AttributeValue::B(Blob::new(sealed.ciphertext.clone())),
            )
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) => match classify(e, table) {
                DynamoDBError::ConditionalConflict => Err(DynamoDBError::LinkConflict),
                other => Err(other),
            },
        }
    }

    /// Every Apple identity link of the account, and the tokens they hold. A
    /// paginated, consistent scan (no `user_id` index; deletions and unlinks
    /// are rare, and the unlink route is rate limited). A link without token
    /// attributes is named in `without_token`. A row with some but not all of
    /// them is logged, left in place and named in `unreadable`, so the caller
    /// can tell it from "no rows" and fail rather than finish without revoking
    /// its token.
    pub async fn apple_tokens_of(
        &self,
        user_id: &Uuid,
    ) -> Result<AppleTokensOfUser, DynamoDBError> {
        let table = &self.identity_links_table;
        let uid = s(&user_id.to_string());
        let mut found = AppleTokensOfUser {
            rows: Vec::new(),
            unreadable: Vec::new(),
            without_token: Vec::new(),
        };
        let mut start = None;
        loop {
            let page = self
                .client
                .scan()
                .table_name(table)
                .filter_expression("user_id = :uid AND begins_with(link_pk, :apple)")
                .expression_attribute_values(":uid", uid.clone())
                .expression_attribute_values(":apple", s(&apple_link_key("")))
                .consistent_read(true)
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(|e| classify(e, table))?;
            for item in page.items() {
                if !holds_token(item) {
                    if let Some(key) = item.get("link_pk").and_then(|v| v.as_s().ok()) {
                        found.without_token.push(key.clone());
                    }
                    continue;
                }
                match parse_row(item) {
                    Some(row) => found.rows.push(row),
                    None => {
                        error!(
                            "Unreadable Apple token on a {table} row of {user_id} left in place"
                        );
                        found.unreadable.push(
                            item.get("link_pk")
                                .and_then(|v| v.as_s().ok())
                                .cloned()
                                .unwrap_or_else(|| "<unknown>".to_string()),
                        );
                    }
                }
            }
            match page.last_evaluated_key {
                Some(k) => start = Some(k),
                None => break,
            }
        }
        Ok(found)
    }

    /// Delete an Apple identity link and the token it holds, once Apple has
    /// revoked the token, only while the row still belongs to `user_id` (the
    /// same Apple identity may since have been linked by another account,
    /// whose row must stay).
    pub async fn delete_apple_link(
        &self,
        link_key: &str,
        user_id: &Uuid,
    ) -> Result<(), DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .delete_item()
            .table_name(table)
            .key("link_pk", s(link_key))
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

    /// Delete an Apple identity link that holds no token, only while it still
    /// belongs to `user_id` and still holds none: a link that gained a token
    /// meanwhile must be revoked before it goes, so it stays. `false` when
    /// the row was not deleted (gone, another account's, or now holding a
    /// token).
    pub async fn delete_apple_link_without_token(
        &self,
        link_key: &str,
        user_id: &Uuid,
    ) -> Result<bool, DynamoDBError> {
        let table = &self.identity_links_table;
        let result = self
            .client
            .delete_item()
            .table_name(table)
            .key("link_pk", s(link_key))
            .condition_expression(format!("user_id = :uid AND {HOLDS_NO_TOKEN}"))
            .expression_attribute_values(":uid", s(&user_id.to_string()))
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

    /// Record on the live `credentials` row that the account unlinked Apple
    /// at `now`. Written before any link is removed, so a retried unlink that
    /// finds nothing left has already recorded it.
    pub async fn mark_apple_unlinked(&self, user_id: &Uuid, now: i64) -> Result<(), DynamoDBError> {
        let table = &self.credentials_table;
        self.client
            .update_item()
            .table_name(table)
            .key("user_id", s(&user_id.to_string()))
            .update_expression("SET #at = :now")
            .condition_expression(super::account::LIVE_ROW)
            .expression_attribute_names("#at", APPLE_UNLINKED_AT)
            .expression_attribute_values(":now", n(now))
            .send()
            .await
            .map_err(|e| classify(e, table))?;
        Ok(())
    }

    /// Record on the live `credentials` row that the account is linking Apple
    /// at `now_ms` ([`APPLE_LINKED_AT`], unix milliseconds), and count it
    /// ([`APPLE_LINK_GENERATION`]). Called before the link is written, so no
    /// token can say "not linked" while a link exists, and again after.
    /// `ConditionalConflict`: the account is deleted.
    pub async fn mark_apple_linked(
        &self,
        user_id: &Uuid,
        now_ms: i64,
    ) -> Result<(), DynamoDBError> {
        let table = &self.credentials_table;
        self.client
            .update_item()
            .table_name(table)
            .key("user_id", s(&user_id.to_string()))
            .update_expression("SET #at = :now ADD #gen :one")
            .condition_expression(super::account::LIVE_ROW)
            .expression_attribute_names("#at", APPLE_LINKED_AT)
            .expression_attribute_names("#gen", APPLE_LINK_GENERATION)
            .expression_attribute_values(":now", n(now_ms))
            .expression_attribute_values(":one", n(1))
            .send()
            .await
            .map_err(|e| classify(e, table))?;
        Ok(())
    }

    /// The account's Apple link mark, if it is marked (consistent read). An
    /// unlink reads it before its scan and passes it to
    /// [`Self::clear_apple_linked`].
    pub async fn apple_link_mark(
        &self,
        user_id: &Uuid,
    ) -> Result<Option<AppleLinkMark>, DynamoDBError> {
        let table = &self.credentials_table;
        let out = self
            .client
            .get_item()
            .table_name(table)
            .key("user_id", s(&user_id.to_string()))
            .projection_expression("#at, #gen")
            .expression_attribute_names("#at", APPLE_LINKED_AT)
            .expression_attribute_names("#gen", APPLE_LINK_GENERATION)
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| classify(e, table))?;
        let Some(item) = out.item.filter(|item| item.contains_key(APPLE_LINKED_AT)) else {
            return Ok(None);
        };
        Ok(Some(AppleLinkMark {
            generation: item
                .get(APPLE_LINK_GENERATION)
                .and_then(|v| v.as_n().ok())
                .and_then(|v| v.parse().ok()),
        }))
    }

    /// Remove [`APPLE_LINKED_AT`] after an unlink that left no Apple link,
    /// only while the mark is still `seen`, the one the unlink read before its
    /// scan: a link marked since then may have been written after the scan,
    /// so its mark stays. `false` when it was kept or is gone.
    pub async fn clear_apple_linked(
        &self,
        user_id: &Uuid,
        seen: AppleLinkMark,
    ) -> Result<bool, DynamoDBError> {
        let table = &self.credentials_table;
        let mut update = self
            .client
            .update_item()
            .table_name(table)
            .key("user_id", s(&user_id.to_string()))
            .update_expression("REMOVE #at")
            .expression_attribute_names("#at", APPLE_LINKED_AT)
            .expression_attribute_names("#gen", APPLE_LINK_GENERATION);
        let unchanged = match seen.generation {
            Some(g) => {
                update = update.expression_attribute_values(":gen", n(g));
                "#gen = :gen"
            }
            None => "attribute_not_exists(#gen)",
        };
        let result = update
            .condition_expression(format!(
                "{} AND attribute_exists(#at) AND {unchanged}",
                super::account::LIVE_ROW
            ))
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

    /// When the account last unlinked Apple, if ever (consistent read).
    pub async fn apple_unlinked_at(&self, user_id: &Uuid) -> Result<Option<i64>, DynamoDBError> {
        let table = &self.credentials_table;
        let out = self
            .client
            .get_item()
            .table_name(table)
            .key("user_id", s(&user_id.to_string()))
            .projection_expression("#at")
            .expression_attribute_names("#at", APPLE_UNLINKED_AT)
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| classify(e, table))?;
        Ok(out
            .item
            .and_then(|item| item.get(APPLE_UNLINKED_AT).cloned())
            .and_then(|v| v.as_n().ok().and_then(|n| n.parse().ok())))
    }

    /// Mark the account as `scripts/backfill-apple-linked.sh` does: the time
    /// only, no generation.
    #[cfg(test)]
    pub(crate) async fn backfill_apple_link_mark(&self, user_id: &Uuid, at_ms: i64) {
        self.client
            .update_item()
            .table_name(&self.credentials_table)
            .key("user_id", s(&user_id.to_string()))
            .update_expression("SET #at = :at")
            .condition_expression(super::account::LIVE_ROW)
            .expression_attribute_names("#at", APPLE_LINKED_AT)
            .expression_attribute_values(":at", n(at_ms))
            .send()
            .await
            .unwrap();
    }

    /// Write an arbitrary identity link item, to plant a malformed row.
    #[cfg(test)]
    pub(crate) async fn raw_identity_link_put(&self, item: HashMap<&str, AttributeValue>) {
        self.client
            .put_item()
            .table_name(&self.identity_links_table)
            .set_item(Some(
                item.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            ))
            .send()
            .await
            .unwrap();
    }

    /// The token stored on an identity's link, if any.
    #[cfg(test)]
    pub(crate) async fn get_apple_token(&self, link_key: &str) -> Option<AppleTokenRow> {
        self.client
            .get_item()
            .table_name(&self.identity_links_table)
            .key("link_pk", s(link_key))
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
    use crate::apple_tokens::apple_link_key;
    use crate::db::DynamoDBError;
    use crate::db::tests::local_store;
    use crate::patreon::{SealedToken, TokenSealer};
    use aws_sdk_dynamodb::primitives::Blob;
    use aws_sdk_dynamodb::types::AttributeValue;
    use uuid::Uuid;

    const CLIENT: &str = "com.arkavo.ArkavoCreator";

    fn sub() -> String {
        format!("001234.{}", Uuid::new_v4().simple())
    }

    async fn sealed(token: &str) -> SealedToken {
        TokenSealer::Plaintext.seal(token.as_bytes()).await.unwrap()
    }

    async fn opened(sealed: &SealedToken) -> Vec<u8> {
        TokenSealer::Plaintext.open(sealed).await.unwrap()
    }

    #[tokio::test]
    async fn a_link_and_its_token_are_one_row_and_a_relink_replaces_the_token() {
        let Some(store) = local_store() else { return };
        let (uid, s) = (Uuid::new_v4(), sub());

        store
            .link_apple_with_token(uid, &s, CLIENT, &sealed("rt-1").await, 1)
            .await
            .unwrap();
        assert_eq!(
            store.get_identity_link("apple", &s).await.unwrap(),
            Some(uid)
        );
        let stored = store
            .get_apple_token(&apple_link_key(&s))
            .await
            .expect("stored");
        assert_eq!(stored.user_id, uid);
        assert_eq!(stored.client_id, CLIENT);
        assert_eq!(opened(&stored.sealed).await, b"rt-1");

        store
            .link_apple_with_token(uid, &s, CLIENT, &sealed("rt-2").await, 2)
            .await
            .unwrap();
        let now = store.get_apple_token(&apple_link_key(&s)).await.unwrap();
        assert_eq!(opened(&now.sealed).await, b"rt-2");
        let found = store.apple_tokens_of(&uid).await.unwrap();
        assert!(found.unreadable.is_empty());
        assert_eq!(found.rows.len(), 1, "a re-link replaces the token");
        assert_eq!(found.rows[0].link_key, apple_link_key(&s));
    }

    #[tokio::test]
    async fn another_accounts_link_is_a_conflict_and_keeps_its_token() {
        let Some(store) = local_store() else { return };
        let (owner, other, s) = (Uuid::new_v4(), Uuid::new_v4(), sub());
        store
            .link_apple_with_token(owner, &s, CLIENT, &sealed("rt-owner").await, 1)
            .await
            .unwrap();

        assert!(matches!(
            store
                .link_apple_with_token(other, &s, CLIENT, &sealed("rt-other").await, 2)
                .await,
            Err(DynamoDBError::LinkConflict)
        ));
        let row = store.get_apple_token(&apple_link_key(&s)).await.unwrap();
        assert_eq!(row.user_id, owner);
        assert_eq!(opened(&row.sealed).await, b"rt-owner");
    }

    /// A link written without a token (revocation unconfigured) must not
    /// drop one already stored: deletion still has to revoke it.
    #[tokio::test]
    async fn a_plain_relink_keeps_the_stored_token() {
        let Some(store) = local_store() else { return };
        let (uid, s) = (Uuid::new_v4(), sub());
        store
            .link_apple_with_token(uid, &s, CLIENT, &sealed("rt-1").await, 1)
            .await
            .unwrap();
        store.link_identity(uid, "apple", &s).await.unwrap();
        let row = store.get_apple_token(&apple_link_key(&s)).await.unwrap();
        assert_eq!(opened(&row.sealed).await, b"rt-1");
    }

    #[tokio::test]
    async fn an_accounts_tokens_are_found_by_user_and_plain_links_are_skipped() {
        let Some(store) = local_store() else { return };
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (s1, s2, s3, plain) = (sub(), sub(), sub(), sub());
        for (uid, s, t) in [(a, &s1, "rt-1"), (a, &s2, "rt-2"), (b, &s3, "rt-3")] {
            store
                .link_apple_with_token(uid, s, CLIENT, &sealed(t).await, 1)
                .await
                .unwrap();
        }
        store.link_identity(a, "apple", &plain).await.unwrap();
        store.link_identity(a, "google", &sub()).await.unwrap();

        let found = store.apple_tokens_of(&a).await.unwrap();
        assert!(found.unreadable.is_empty());
        let mut keys: Vec<String> = found.rows.into_iter().map(|r| r.link_key).collect();
        keys.sort();
        let mut want = vec![apple_link_key(&s1), apple_link_key(&s2)];
        want.sort();
        assert_eq!(keys, want);
        assert_eq!(store.apple_tokens_of(&b).await.unwrap().rows.len(), 1);
        let none = store.apple_tokens_of(&Uuid::new_v4()).await.unwrap();
        assert!(none.rows.is_empty() && none.unreadable.is_empty());
    }

    /// The sweep's link step leaves a link that holds a token for the
    /// revocation step, and deletes the rest.
    #[tokio::test]
    async fn the_link_step_keeps_links_holding_a_token() {
        let Some(store) = local_store() else { return };
        let uid = Uuid::new_v4();
        let (with_token, plain, google) = (sub(), sub(), sub());
        store
            .link_apple_with_token(uid, &with_token, CLIENT, &sealed("rt").await, 1)
            .await
            .unwrap();
        store.link_identity(uid, "apple", &plain).await.unwrap();
        store.link_identity(uid, "google", &google).await.unwrap();

        assert_eq!(store.delete_identity_links_of(&uid).await.unwrap(), 2);
        assert_eq!(
            store.get_identity_link("apple", &plain).await.unwrap(),
            None
        );
        assert_eq!(
            store.get_identity_link("google", &google).await.unwrap(),
            None
        );
        assert_eq!(
            store.get_identity_link("apple", &with_token).await.unwrap(),
            Some(uid)
        );
        assert_eq!(store.apple_tokens_of(&uid).await.unwrap().rows.len(), 1);
    }

    /// The Apple ID was re-linked by a new account between the sweep's scan
    /// and its delete.
    #[tokio::test]
    async fn an_apple_link_is_deleted_only_for_its_own_account() {
        let Some(store) = local_store() else { return };
        let (deleted, newcomer, s) = (Uuid::new_v4(), Uuid::new_v4(), sub());
        store
            .link_apple_with_token(newcomer, &s, CLIENT, &sealed("rt-new").await, 1)
            .await
            .unwrap();

        store
            .delete_apple_link(&apple_link_key(&s), &deleted)
            .await
            .unwrap();
        assert!(
            store.get_apple_token(&apple_link_key(&s)).await.is_some(),
            "newcomer's row deleted"
        );

        store
            .delete_apple_link(&apple_link_key(&s), &newcomer)
            .await
            .unwrap();
        assert!(store.get_apple_token(&apple_link_key(&s)).await.is_none());
        assert_eq!(store.get_identity_link("apple", &s).await.unwrap(), None);
        // Deleting an absent row is not an error.
        store
            .delete_apple_link(&apple_link_key(&s), &newcomer)
            .await
            .unwrap();
    }

    /// A row that matches the account but whose token cannot be read must
    /// not look like "no rows": the sweep would finish without revoking it.
    #[tokio::test]
    async fn an_unreadable_token_is_reported_not_dropped() {
        let Some(store) = local_store() else { return };
        let (uid, s) = (Uuid::new_v4(), sub());
        let key = apple_link_key(&s);
        // Right key and owner, but no `token_ct`.
        store
            .raw_identity_link_put(
                [
                    ("link_pk", AttributeValue::S(key.clone())),
                    ("user_id", AttributeValue::S(uid.to_string())),
                    ("provider", AttributeValue::S("apple".into())),
                    ("subject", AttributeValue::S(s.clone())),
                    ("token_client_id", AttributeValue::S(CLIENT.into())),
                    ("token_wrapped_dek", AttributeValue::B(Blob::new(vec![1u8]))),
                    ("token_nonce", AttributeValue::B(Blob::new(vec![2u8]))),
                ]
                .into_iter()
                .collect(),
            )
            .await;
        let good = sub();
        store
            .link_apple_with_token(uid, &good, CLIENT, &sealed("rt").await, 1)
            .await
            .unwrap();

        let found = store.apple_tokens_of(&uid).await.unwrap();
        assert_eq!(found.unreadable, vec![key.clone()]);
        assert_eq!(found.rows.len(), 1);
        assert_eq!(found.rows[0].link_key, apple_link_key(&good));
        assert!(
            !format!("{found:?}").contains(&s),
            "Debug leaks the Apple sub"
        );
        // Nor does the link step delete it.
        store.delete_identity_links_of(&uid).await.unwrap();
        assert_eq!(
            store.apple_tokens_of(&uid).await.unwrap().unreadable,
            vec![key]
        );
    }
}
