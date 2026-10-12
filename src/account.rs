//! Account deletion (#88, App Store guideline 5.1.1(v)).
//!
//! `DELETE /account` deletes the signed-in account. It needs a passkey auth
//! CWT minted within [`ACCOUNT_DELETION_TOKEN_MAX_AGE_SECONDS`] (fresh proof
//! of control, as agent recovery requires), and works in two steps:
//!
//! 1. **At once:** the account's `credentials` row is replaced by a tombstone
//!    (`db::account`). Passkeys, username, DID and DID log, entitlements and
//!    any publishing suspension go with it. From then on every token the
//!    account still holds is refused, however long it has left: the
//!    ~99-year registration token, auth CWTs, OIDC codes, access and refresh
//!    tokens, and the agent plane. The username is free to register again.
//! 2. **After [`ACCOUNT_DELETION_GRACE_SECONDS`]:** [`sweep`] removes what is
//!    bound to the account in other tables: the handle, App Attest device
//!    bindings, every Apple/Google/Patreon identity link except an Apple link
//!    holding a token, the Patreon token row (sealed tokens and wrapped key;
//!    Patreon has no revocation endpoint) and its cache, and it revokes the
//!    account's agent delegations and Guardians, stripping their labels.
//!    Last, it revokes the account's Sign in with Apple refresh tokens with
//!    Apple (TN3194) and deletes the links that held them. Three causes
//!    retrying cannot fix mark the deletion `failed` at once: Apple refused a
//!    revocation (a 4xx other than 429, a configuration problem), stored
//!    tokens exist but revocation is not configured, or a stored token is
//!    unreadable. By then everything else is removed, and
//!    the startup resume tries again once the problem is fixed. The grace lets
//!    a request that passed its account check just before the deletion finish
//!    its write, so the sweep removes that write instead of racing it.
//!
//! The response carries a `deletion_id`; `GET /account/deletions/:id` reports
//! `pending`, `failed` or `completed`. That endpoint takes no token (the
//! account's tokens no longer work); the id is unguessable. A retried
//! `DELETE /account` returns the same id.
//!
//! The sweep is idempotent. A failed one is retried
//! ([`ACCOUNT_DELETION_RETRY_SECONDS`]), and every unfinished deletion is
//! resumed at startup.

use crate::AppState;
use crate::apple_tokens::{AppleTokenError, AppleTokens};
use crate::constants::{
    ACCOUNT_DELETION_COMPLETES_WITHIN_SECONDS, ACCOUNT_DELETION_GRACE_SECONDS,
    ACCOUNT_DELETION_RETRY_SECONDS, ACCOUNT_DELETION_TOKEN_MAX_AGE_SECONDS,
};
use crate::db::{AccountDeletion, DeletionState, DynamoDBError, DynamoDBStore, Tombstoned};
use crate::patreon::PatreonState;
use axum::{
    extract::{Extension, Json, Path},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use log::{error, info, warn};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

/// The handle row a username owns.
fn handle_for(username: &str) -> String {
    format!("{}.arkavo.social", username.to_lowercase())
}

/// `<user_id>.<128 random bits, hex>`. The user id locates the tombstone; the
/// random part is what makes the id a secret worth checking.
fn new_deletion_id(user_id: &Uuid) -> Result<String, getrandom::Error> {
    let mut r = [0u8; 16];
    getrandom::getrandom(&mut r)?;
    Ok(format!("{}.{}", user_id, hex::encode(r)))
}

fn user_id_of(deletion_id: &str) -> Option<Uuid> {
    let (uid, secret) = deletion_id.split_once('.')?;
    (secret.len() == 32 && secret.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| Uuid::parse_str(uid).ok())
        .flatten()
}

#[derive(Debug, Serialize)]
pub struct DeletionStatus {
    pub deletion_id: String,
    pub status: DeletionState,
    /// When the deletion was accepted (the account stopped existing).
    pub requested_at: i64,
    /// When the sweep is promised to be done by.
    pub completes_by: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<i64>,
}

impl From<&AccountDeletion> for DeletionStatus {
    fn from(d: &AccountDeletion) -> Self {
        Self {
            deletion_id: d.deletion_id.clone(),
            status: d.state,
            requested_at: d.deleted_at,
            completes_by: d.deleted_at + ACCOUNT_DELETION_COMPLETES_WITHIN_SECONDS,
            completed_at: d.completed_at,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("{0}")]
    Unauthorized(String),
    #[error("not found")]
    NotFound,
    #[error("conflicting concurrent change; retry")]
    Conflict,
    #[error("internal error")]
    Internal,
}

impl IntoResponse for AccountError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "conflict"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        };
        (
            status,
            Json(serde_json::json!({ "error": code, "error_description": self.to_string() })),
        )
            .into_response()
    }
}

impl From<DynamoDBError> for AccountError {
    fn from(e: DynamoDBError) -> Self {
        match e {
            DynamoDBError::ConditionalConflict => Self::Conflict,
            other => {
                error!("Account deletion storage failure: {other}");
                Self::Internal
            }
        }
    }
}

/// Why a sweep attempt stopped.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SweepError {
    #[error(transparent)]
    Db(#[from] DynamoDBError),
    #[error("Apple token revocation: {0}")]
    Apple(#[from] AppleTokenError),
    /// Stored Apple token rows of the account could not be read, so their
    /// tokens cannot be revoked. The count only: a link key holds the Apple
    /// `sub`.
    #[error("{0} stored Apple token row(s) are unreadable")]
    UnreadableAppleTokens(usize),
}

impl SweepError {
    /// Retrying on the schedule cannot fix it: Apple refused a revocation (a
    /// configuration problem: key, client id or secret), tokens are stored
    /// while revocation is not configured, or a stored row is unreadable. The
    /// deletion is marked `failed` at once; the startup resume tries again
    /// once the configuration is fixed.
    pub(crate) fn is_permanent(&self) -> bool {
        match self {
            Self::Db(_) => false,
            Self::Apple(e) => e.is_permanent(),
            Self::UnreadableAppleTokens(_) => true,
        }
    }
}

/// `DELETE /account`: delete the account named by the passkey auth CWT in
/// `X-Auth-Token`. 202 with the deletion's status, on the first request and
/// on every retry; 401 for a missing, invalid or stale token, or an account
/// that never existed.
pub async fn delete_account(
    Extension(app_state): Extension<AppState>,
    Extension(patreon): Extension<PatreonState>,
    Extension(apple): Extension<AppleTokens>,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let now = Utc::now().timestamp();
    let (user_id, issued_at) = crate::agent::verify_passkey_auth_token(&app_state, &headers)
        .map_err(|e| AccountError::Unauthorized(e.to_string()))?;
    if !crate::oidc::within_age(issued_at, now, ACCOUNT_DELETION_TOKEN_MAX_AGE_SECONDS) {
        return Err(AccountError::Unauthorized(format!(
            "deleting an account requires a passkey sign-in within the last {} seconds",
            ACCOUNT_DELETION_TOKEN_MAX_AGE_SECONDS
        )));
    }

    let db = &app_state.db_store;
    // A retry after the deletion was accepted: report it, unchanged.
    if let Some(existing) = db.get_account_deletion(&user_id).await? {
        return Ok(accepted(&existing));
    }
    let Some(user) = db.get_user_by_id(&user_id).await? else {
        return Err(AccountError::Unauthorized("account does not exist".into()));
    };
    let handle = handle_for(&user.username);
    let deletion_id = new_deletion_id(&user_id).map_err(|e| {
        error!("No randomness for a deletion id: {e}");
        AccountError::Internal
    })?;

    let deletion = match db
        .tombstone_account(&user_id, &deletion_id, Some(&handle), now)
        .await?
    {
        Tombstoned::Created(d) => d,
        // Lost a race with a concurrent request for the same account.
        Tombstoned::AlreadyDeleted(d) => return Ok(accepted(&d)),
        Tombstoned::NotFound => {
            return Err(AccountError::Unauthorized("account does not exist".into()));
        }
    };
    // The deletion id is a bearer secret for the status endpoint: not logged.
    info!("audit account_deletion outcome=accepted user_id={user_id}");

    // Free the name at once (a new owner may register it in the next
    // second) and drop the cached Patreon snapshot. Best effort: the sweep
    // does both again.
    if let Err(e) = db.delete_handle_if_owned(&handle, &user_id).await {
        warn!("Deleting the handle of deleted account {user_id} failed (sweep retries): {e}");
    }
    patreon.cache.invalidate(user_id).await;
    // Revoke the account's agents now, not after the grace: the status
    // endpoint the platform checks also refuses them by the tombstone, so a
    // failure here is logged and left to the sweep.
    if let Err(e) = db.revoke_and_scrub_delegations_of(&user_id, now).await {
        warn!("Revoking the agents of deleted account {user_id} failed (sweep retries): {e}");
    }

    schedule_sweep(
        app_state.db_store.clone(),
        patreon,
        apple,
        user_id,
        ACCOUNT_DELETION_GRACE_SECONDS,
    );
    Ok(accepted(&deletion))
}

fn accepted(d: &AccountDeletion) -> Response {
    (StatusCode::ACCEPTED, Json(DeletionStatus::from(d))).into_response()
}

/// `GET /account/deletions/:id`: the status of a deletion. No token: the
/// unguessable id is the credential. 404 for an unknown id.
pub async fn get_deletion_status(
    Extension(app_state): Extension<AppState>,
    Path(deletion_id): Path<String>,
) -> Result<Json<DeletionStatus>, AccountError> {
    let user_id = user_id_of(&deletion_id).ok_or(AccountError::NotFound)?;
    match app_state.db_store.get_account_deletion(&user_id).await? {
        Some(d) if crate::oidc::constant_time_eq(&d.deletion_id, &deletion_id) => {
            Ok(Json(DeletionStatus::from(&d)))
        }
        _ => Err(AccountError::NotFound),
    }
}

/// Remove everything bound to a deleted account outside its own row. Each
/// step is idempotent. A failure stops the sweep and is returned, so the steps
/// after it do not run. The one step that does not stop at its first failure
/// is the last: [`revoke_apple_tokens`] tries every readable token row before
/// it reports what Apple refused or could not take. A DynamoDB error there
/// still stops it at once.
pub(crate) async fn sweep(
    db: &DynamoDBStore,
    patreon: &PatreonState,
    apple: &AppleTokens,
    deletion: &AccountDeletion,
    now: i64,
) -> Result<(), SweepError> {
    let uid = &deletion.user_id;
    if let Some(handle) = &deletion.handle {
        db.delete_handle_if_owned(handle, uid).await?;
    }
    db.delete_patreon_link(uid).await?;
    patreon.cache.invalidate(*uid).await;
    let links = db.delete_identity_links_of(uid).await?;
    let devices = db.delete_device_bindings_of(uid).await?;
    let agents = db.revoke_and_scrub_delegations_of(uid, now).await?;
    let guardians = db.revoke_and_scrub_guardians_of(uid, now).await?;
    // Last: a deletion that stops here holds nothing but the sealed tokens
    // it still has to revoke.
    let apple_tokens = revoke_apple_tokens(db, apple, uid).await?;
    info!(
        "audit account_deletion outcome=swept user_id={uid} identity_links={links} \
         device_bindings={devices} agents={agents} guardians={guardians} \
         apple_tokens={apple_tokens}"
    );
    Ok(())
}

/// Revoke every stored Sign in with Apple token of the account at Apple,
/// deleting each Apple link that holds one once its token is revoked (the
/// link step left those in place). Apple's answer is per row: every readable
/// row is attempted, and one Apple refused or could not take stays. A
/// DynamoDB error while scanning or deleting a row aborts the sweep (the `?`):
/// it is transient and retried on the schedule. After the rows are attempted,
/// rows that matched the account but could not be read fail the sweep
/// permanently. A permanent failure (a refusal or unreadable rows) is
/// reported ahead of a transient one, since retrying cannot fix it.
async fn revoke_apple_tokens(
    db: &DynamoDBStore,
    apple: &AppleTokens,
    uid: &Uuid,
) -> Result<u32, SweepError> {
    let found = db.apple_tokens_of(uid).await?;
    let mut revoked = 0;
    let mut permanent = None;
    let mut transient = None;
    for row in &found.rows {
        match apple.revoke_stored(row).await {
            Ok(()) => {
                db.delete_apple_link(&row.link_key, uid).await?;
                revoked += 1;
            }
            Err(e) => {
                // Status and Apple's error code only (AppleTokenError's Display).
                error!("audit account_deletion apple_token=revoke_failed user_id={uid}: {e}");
                let first = if e.is_permanent() {
                    &mut permanent
                } else {
                    &mut transient
                };
                if first.is_none() {
                    *first = Some(e);
                }
            }
        }
    }
    if let Some(e) = permanent {
        return Err(e.into());
    }
    if !found.unreadable.is_empty() {
        // The count only: the link keys contain the Apple sub.
        let count = found.unreadable.len();
        error!(
            "audit account_deletion apple_token=unreadable user_id={uid} count={count}: \
             rows kept"
        );
        return Err(SweepError::UnreadableAppleTokens(count));
    }
    match transient {
        Some(e) => Err(e.into()),
        None => Ok(revoked),
    }
}

/// Run the sweep for `user_id` after `delay` seconds, in the background,
/// retrying a transient failure on [`ACCOUNT_DELETION_RETRY_SECONDS`]. A
/// permanent failure ([`SweepError::is_permanent`]) is not retried here.
pub(crate) fn schedule_sweep(
    db: Arc<DynamoDBStore>,
    patreon: PatreonState,
    apple: AppleTokens,
    user_id: Uuid,
    delay: i64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut wait = delay.max(0);
        let mut retries = ACCOUNT_DELETION_RETRY_SECONDS.iter();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(wait as u64)).await;
            match run_once(&db, &patreon, &apple, &user_id).await {
                Ok(()) => return,
                // `run_once` marked it failed; the startup resume retries it.
                Err(e) if e.is_permanent() => return,
                Err(e) => {
                    warn!("Account deletion sweep for {user_id} failed: {e}");
                    let give_up = ACCOUNT_DELETION_RETRY_SECONDS.len() as u32 + 1;
                    match db.record_deletion_failure(&user_id, give_up).await {
                        Ok(attempts) if attempts < give_up => {}
                        Ok(_) => {
                            error!(
                                "audit account_deletion outcome=failed user_id={user_id}: \
                                 retries exhausted; resumes at next startup"
                            );
                            return;
                        }
                        Err(e) => warn!("Recording the failed sweep for {user_id} failed: {e}"),
                    }
                    match retries.next() {
                        Some(next) => wait = *next,
                        None => return,
                    }
                }
            }
        }
    })
}

/// One sweep attempt: re-read the tombstone (another instance may have
/// finished it), sweep, mark it complete. A permanent failure marks the
/// deletion `failed` before it is returned.
pub(crate) async fn run_once(
    db: &DynamoDBStore,
    patreon: &PatreonState,
    apple: &AppleTokens,
    user_id: &Uuid,
) -> Result<(), SweepError> {
    let Some(deletion) = db.get_account_deletion(user_id).await? else {
        warn!("Account deletion sweep for {user_id}: no tombstone; nothing to do");
        return Ok(());
    };
    if deletion.state == DeletionState::Completed {
        return Ok(());
    }
    let now = Utc::now().timestamp();
    if let Err(e) = sweep(db, patreon, apple, &deletion, now).await {
        if e.is_permanent() {
            error!(
                "audit account_deletion outcome=failed user_id={user_id}: {e}; \
                 not retried before the next startup"
            );
            if let Err(m) = db.mark_deletion_failed(user_id).await {
                warn!("Marking the deletion of {user_id} failed did not stick: {m}");
            }
        }
        return Err(e);
    }
    db.complete_account_deletion(user_id, now).await?;
    info!("audit account_deletion outcome=completed user_id={user_id}");
    Ok(())
}

/// At startup: resume every deletion whose sweep never completed: the
/// process stopped during the grace or the retries, the retries ran out, or
/// the sweep hit a permanent cause (Apple refused a revocation, stored tokens
/// exist while revocation is not configured, or a stored token row is
/// unreadable) and marked the deletion `failed`.
pub(crate) async fn resume_unfinished(
    db: Arc<DynamoDBStore>,
    patreon: PatreonState,
    apple: AppleTokens,
) {
    let unfinished = match db.list_unfinished_deletions().await {
        Ok(v) => v,
        Err(e) => {
            error!("Listing unfinished account deletions failed: {e}");
            return;
        }
    };
    if !unfinished.is_empty() {
        info!(
            "Resuming {} unfinished account deletion(s)",
            unfinished.len()
        );
    }
    let now = Utc::now().timestamp();
    for d in unfinished {
        let delay = d.deleted_at + ACCOUNT_DELETION_GRACE_SECONDS - now;
        schedule_sweep(db.clone(), patreon.clone(), apple.clone(), d.user_id, delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_ids_carry_the_user_and_128_random_bits() {
        let uid = Uuid::new_v4();
        let a = new_deletion_id(&uid).unwrap();
        let b = new_deletion_id(&uid).unwrap();
        assert_ne!(a, b);
        assert_eq!(user_id_of(&a), Some(uid));
        assert_eq!(a.len(), 36 + 1 + 32);
    }

    #[test]
    fn malformed_deletion_ids_are_refused() {
        let uid = Uuid::new_v4();
        for bad in [
            String::new(),
            uid.to_string(),
            format!("{uid}."),
            format!("{uid}.{}", "a".repeat(31)),
            format!("{uid}.{}", "g".repeat(32)),
            format!("not-a-uuid.{}", "a".repeat(32)),
        ] {
            assert_eq!(user_id_of(&bad), None, "{bad}");
        }
    }

    #[test]
    fn handles_are_lowercased() {
        assert_eq!(handle_for("Alice"), "alice.arkavo.social");
    }
}
