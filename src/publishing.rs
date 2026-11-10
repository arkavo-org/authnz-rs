//! Creator-publishing entitlement (#91) and its moderation override.
//!
//! [`ENTITLEMENT_CREATOR_PUBLISH`] is **derived, never stored**. Every
//! short-lived token minted for a human (passkey auth CWT, DeviceCheck
//! assertion CWT, OIDC access token incl. refresh) gets it appended to
//! `arkavo_entitlements` while all of these hold:
//!
//! 1. a source qualifies, either one:
//!    - Patreon: the feature is configured (`PATREON_PUBLISHER_CAMPAIGN_ID`
//!      and `PATREON_PUBLISHER_TIER_IDS` both set) and the account's
//!      materialized Patreon snapshot (cached ≤ 5 min) either lists a
//!      membership of that campaign with `patron_status = active_patron` and
//!      at least one currently entitled tier ID in the configured set, or
//!      *owns* that campaign (its own `campaign_id`, which Patreon reports
//!      per #99). The owner is Arkavo's own account: Patreon does not let a
//!      creator pledge to its own campaign, so membership can never qualify
//!      it. Owning any other campaign grants nothing;
//!    - App Store: the feature is configured (`APP_STORE_*`) and a
//!      subscription record bound to the account, of a product listed for
//!      publishing, is active ([`app_store_active`] with [`Grant::Publish`]);
//!    - market.arkavo.com: the feature is configured (`MARKET_*`) and a
//!      purchase linked to the account still has a claim that verifies
//!      ([`crate::market::MarketSource::grant`], #141);
//! 2. the account carries no publishing suspension.
//!
//! [`ENTITLEMENT_ONLINE_PLAY`] is derived here too, on its own path: an
//! active App Store record of a product listed for online play grants it,
//! nothing that grants publishing does, and a suspension does not remove it
//! (`docs/online-play-entitlement.md`).
//!
//! The market is asked alongside Patreon, not after it ([`load_sources`]
//! runs while Patreon materializes), so a mint waits for the slower of the
//! two deadlines, never both in turn.
//!
//! Every failure (Patreon or the market down, deadline passed, DB error,
//! malformed record)
//! withholds the entitlement, with one exception: while Patreon is
//! unreachable an owner's fallback snapshot keeps its stored owned campaign,
//! so the publisher campaign's owner still qualifies. It is never written to
//! `credentials.entitlements` ([`crate::entitlements::validate_fqns`]
//! refuses it), so it cannot be delegated to agents, does not appear in
//! `GET /entities`, and is dropped from the ~99-year registration token.
//!
//! The suspension endpoints (`/admin/users/:id/publishing-suspension`) take a
//! service CWT whose client is on `MODERATION_CLIENT_IDS`.

use crate::AppState;
use crate::app_store::{Environment, Grant, app_store_active};
use crate::constants::{
    ENTITLEMENT_CREATOR_PUBLISH, ENTITLEMENT_ONLINE_PLAY, SUSPENSION_REASON_MAX_LEN,
    SUSPENSION_REPORT_ID_MAX_LEN,
};
use crate::cwt::ArkavoPatreon;
use crate::db::{
    DynamoDBError, PublishingState, PublishingSuspension, SuspensionLift, SuspensionSet,
};
use crate::entitlements::{EntitlementError, require_service_cwt_for};
use crate::market::MarketGrant;
use crate::market::subscription::Subscription;
use axum::{
    extract::{Extension, Json, Path},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

/// Patreon `patron_status` that qualifies. No grace period: a
/// `declined_patron` (failed payment) loses the entitlement at the next mint
/// after the membership cache expires.
const ACTIVE_PATRON: &str = "active_patron";

/// Arkavo's own Patreon campaign and the tier IDs that qualify for
/// publishing. Tier **IDs**, not titles: titles are creator-editable
/// display text (see #42).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherConfig {
    pub campaign_id: String,
    pub tier_ids: HashSet<String>,
}

impl PublisherConfig {
    /// Parse `PATREON_PUBLISHER_CAMPAIGN_ID` / `PATREON_PUBLISHER_TIER_IDS`.
    /// `None` (feature off — the entitlement is never granted) unless both
    /// are non-empty.
    pub fn parse(campaign_id: Option<&str>, tier_ids: Option<&str>) -> Option<Self> {
        let campaign_id = campaign_id.map(str::trim).filter(|s| !s.is_empty())?;
        let tier_ids: HashSet<String> = tier_ids
            .unwrap_or_default()
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        if tier_ids.is_empty() {
            return None;
        }
        Some(Self {
            campaign_id: campaign_id.to_string(),
            tier_ids,
        })
    }

    /// Read the two env vars and log, once, which state the feature is in.
    pub fn from_env() -> Option<Self> {
        let campaign = std::env::var("PATREON_PUBLISHER_CAMPAIGN_ID").ok();
        let tiers = std::env::var("PATREON_PUBLISHER_TIER_IDS").ok();
        let parsed = Self::parse(campaign.as_deref(), tiers.as_deref());
        match &parsed {
            Some(cfg) => info!(
                "Creator publishing entitlement ENABLED: campaign_id={} qualifying_tier_ids={}",
                cfg.campaign_id,
                cfg.tier_ids.len()
            ),
            None => {
                let set = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.trim().is_empty());
                if set(&campaign) || set(&tiers) {
                    warn!(
                        "Creator publishing entitlement DISABLED: PATREON_PUBLISHER_CAMPAIGN_ID and \
                         PATREON_PUBLISHER_TIER_IDS must both be set (only one is)"
                    );
                } else {
                    info!(
                        "Creator publishing entitlement DISABLED: PATREON_PUBLISHER_CAMPAIGN_ID / \
                         PATREON_PUBLISHER_TIER_IDS unset"
                    );
                }
            }
        }
        parsed
    }
}

/// Whether a materialized snapshot qualifies under `cfg`: it owns the
/// publisher campaign, or is an active patron of it at a qualifying tier.
/// Pure — the suspension check is separate ([`derived_entitlements`]).
///
/// The owned `campaign_id` is Patreon's answer at materialization, or, in
/// the owner fallback while Patreon is unreachable, the one stored from the
/// last answer; a client cannot set it.
pub(crate) fn qualifies(cfg: &PublisherConfig, snap: &ArkavoPatreon, now: i64) -> bool {
    if snap.cache_expires_at < now {
        return false;
    }
    if snap.campaign_id.as_deref() == Some(cfg.campaign_id.as_str()) {
        return true;
    }
    snap.memberships.iter().any(|m| {
        m.campaign_id == cfg.campaign_id
            && m.patron_status.as_deref() == Some(ACTIVE_PATRON)
            && m.tier_ids.iter().any(|t| cfg.tier_ids.contains(t))
    })
}

/// Why [`try_derived_entitlements`] could not answer. A mint fails closed
/// on either; `GET /entities` answers a 5xx, so a resolver keeps its last
/// answer where a 200 without the entitlement would be cached as a fresh
/// negative.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DeriveError {
    /// The publishing-state read failed.
    #[error(transparent)]
    Database(#[from] DynamoDBError),
    /// A linked market purchase could not be checked and no other source
    /// grants.
    #[error("market_unavailable")]
    MarketUnavailable,
}

/// What [`load_sources`] read before Patreon's answer is known.
#[derive(Debug)]
pub(crate) enum Sources {
    /// Nothing read: only Patreon can grant, and the `credentials` row is
    /// read once it does (so a Patreon-only deployment reads nothing for an
    /// account that does not qualify).
    Unread,
    /// The row was read (the App Store or the market is configured). `None`:
    /// no live row, which grants nothing.
    Read {
        state: Option<PublishingState>,
        market: MarketGrant,
        /// The market's answer about a prepaid online-play term (#151).
        subscription: Subscription,
    },
}

/// The sources that do not depend on Patreon: one strongly consistent read
/// of the `credentials` row (the suspension, the App Store records and the
/// market links), then the market's two questions. Called alongside
/// Patreon's materialization. The membership claims are not asked for when
/// the account is suspended or an App Store membership already grants
/// publishing; the subscription lookup is not made when an App Store pass
/// already grants online play. `recheck`: this mint is a renewal, which may
/// ask again about a subscription cached as "none".
pub(crate) async fn load_sources(
    app_state: &AppState,
    user_id: Option<Uuid>,
    recheck: bool,
) -> Result<Sources, DeriveError> {
    let nothing = |state| Sources::Read {
        state,
        market: MarketGrant::NotGranted,
        subscription: Subscription::None,
    };
    let Some(user_id) = user_id else {
        return Ok(nothing(None));
    };
    let app_store_cfg = app_state.app_store.as_ref().as_ref();
    let market = app_state.market.as_ref().as_ref();
    if app_store_cfg.is_none() && market.is_none() {
        return Ok(Sources::Unread);
    }
    let Some(state) = read_state(app_state, &user_id).await? else {
        return Ok(nothing(None));
    };
    let now = Utc::now().timestamp();
    let granted = |grant| {
        app_store_cfg.is_some_and(|cfg| app_store_active(cfg, grant, &state.app_store, now))
    };
    let (publish_granted, pass_granted) = (granted(Grant::Publish), granted(Grant::OnlinePlay));
    // Each market question is asked only while its answer can change the
    // mint, and both at once, so a mint waits for one deadline.
    let claims = async {
        match market {
            Some(source)
                if !publish_granted
                    && state.suspension.is_none()
                    && !state.market_links.is_empty() =>
            {
                source.grant(&state.market_links).await
            }
            _ => MarketGrant::NotGranted,
        }
    };
    let subscription = async {
        match market {
            Some(source) if !pass_granted => source.subscription(&user_id, recheck).await,
            _ => Subscription::None,
        }
    };
    let (market, subscription) = tokio::join!(claims, subscription);
    Ok(Sources::Read {
        state: Some(state),
        market,
        subscription,
    })
}

async fn read_state(
    app_state: &AppState,
    user_id: &Uuid,
) -> Result<Option<PublishingState>, DeriveError> {
    app_state
        .db_store
        .get_publishing_state(user_id)
        .await
        .map_err(|e| {
            warn!(
                "Publishing state lookup failed for user {}: {} — no publishing entitlement \
                 (a mint fails closed, /entities answers 5xx)",
                user_id, e
            );
            DeriveError::Database(e)
        })
}

/// The entitlements derived for `user_id` at this mint: the
/// creator-publishing entitlement and the online-play entitlement, each or
/// neither.
///
/// Three sources grant it, any one enough: a qualifying Patreon membership
/// (`snap`), an active App Store Creator Membership ([`app_store_active`]),
/// or a linked market purchase whose claim verifies. A suspension withholds
/// it whichever source granted it. Any failure withholds it (fails closed). A
/// Sandbox grant is logged with `env=Sandbox`.
///
/// The sequential form, for tests: a mint calls [`load_sources`] alongside
/// Patreon and then [`derive`] (`oidc::arkavo_user_claims`).
#[cfg(test)]
pub(crate) async fn derived_entitlements(
    app_state: &AppState,
    user_id: Option<Uuid>,
    snap: Option<&ArkavoPatreon>,
) -> Vec<String> {
    try_derived_entitlements(app_state, user_id, snap)
        .await
        .unwrap_or_default()
}

/// [`derived_entitlements`] with a failure returned, not withheld:
/// `GET /entities` answers it with a 5xx.
pub(crate) async fn try_derived_entitlements(
    app_state: &AppState,
    user_id: Option<Uuid>,
    snap: Option<&ArkavoPatreon>,
) -> Result<Vec<String>, DeriveError> {
    let sources = load_sources(app_state, user_id, false).await?;
    derive(app_state, user_id, snap, sources).await?.complete()
}

/// What [`derive`] decided.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Derived {
    /// The entitlements granted. Each was decided on its own path, so this
    /// is right whatever `market_unavailable` says.
    pub entitlements: Vec<String>,
    /// A linked market purchase could not be checked and no other source
    /// grants publishing, so whether the account may publish is unknown.
    /// A mint goes without it; `GET /entities` answers 503.
    pub market_unavailable: bool,
}

impl Derived {
    /// The answer for a caller that must not report an unknown as "not
    /// entitled" (`GET /entities`).
    pub(crate) fn complete(self) -> Result<Vec<String>, DeriveError> {
        if self.market_unavailable {
            return Err(DeriveError::MarketUnavailable);
        }
        Ok(self.entitlements)
    }
}

/// Decide from Patreon's snapshot and what [`load_sources`] read. With
/// [`Sources::Unread`] the row is read here, and only when Patreon
/// qualifies.
///
/// Each entitlement has its own path, and a source grants only its own:
/// publishing from Patreon, an App Store publish product or the market,
/// unless suspended; online play from an App Store online-play product,
/// whatever the suspension and whatever the market answered.
pub(crate) async fn derive(
    app_state: &AppState,
    user_id: Option<Uuid>,
    snap: Option<&ArkavoPatreon>,
    sources: Sources,
) -> Result<Derived, DeriveError> {
    let Some(user_id) = user_id else {
        return Ok(Derived::default());
    };
    let now = Utc::now().timestamp();
    let patreon_ok = match (app_state.publisher.as_ref().as_ref(), snap) {
        (Some(cfg), Some(snap)) => qualifies(cfg, snap, now),
        _ => false,
    };
    let (state, market, subscription) = match sources {
        Sources::Read {
            state,
            market,
            subscription,
        } => (state, market, subscription),
        // Unread means neither an App Store app nor the market is
        // configured: nothing but Patreon can grant anything.
        Sources::Unread if !patreon_ok => return Ok(Derived::default()),
        Sources::Unread => (
            read_state(app_state, &user_id).await?,
            MarketGrant::NotGranted,
            Subscription::None,
        ),
    };
    let Some(state) = state else {
        return Ok(Derived::default());
    };
    let app_store_cfg = app_state.app_store.as_ref().as_ref();
    let mut derived = publishing(&user_id, patreon_ok, app_store_cfg, &state, market, now);
    if online_play(&user_id, app_store_cfg, &state, subscription, now) {
        derived
            .entitlements
            .push(ENTITLEMENT_ONLINE_PLAY.to_string());
    }
    Ok(derived)
}

/// Every Sandbox grant is visible (TestFlight and App Review buy there).
fn log_sandbox_grant(
    what: &str,
    user_id: &Uuid,
    cfg: &crate::app_store::AppStoreConfig,
    grant: Grant,
    state: &PublishingState,
    now: i64,
) {
    let sandbox = state.app_store.iter().any(|r| {
        r.environment == Environment::Sandbox
            && app_store_active(cfg, grant, std::slice::from_ref(r), now)
    });
    if sandbox {
        info!(
            "{what} entitlement granted for user {user_id} from an App Store purchase env=Sandbox"
        );
    }
}

/// The publishing path: Patreon, an App Store publish product or the
/// market, any one enough, and withheld by a suspension.
fn publishing(
    user_id: &Uuid,
    patreon_ok: bool,
    app_store_cfg: Option<&crate::app_store::AppStoreConfig>,
    state: &PublishingState,
    market: MarketGrant,
    now: i64,
) -> Derived {
    let app_store_ok = app_store_cfg
        .is_some_and(|cfg| app_store_active(cfg, Grant::Publish, &state.app_store, now));
    let market_ok = matches!(market, MarketGrant::Granted(_));
    if !patreon_ok && !app_store_ok && !market_ok {
        // Suspended accounts never reach the market check, so this is never
        // a suspended account's unknown.
        return Derived {
            entitlements: Vec::new(),
            market_unavailable: market == MarketGrant::Unavailable,
        };
    }
    if state.suspension.is_some() {
        info!(
            "Publishing entitlement withheld for user {}: publishing is suspended",
            user_id
        );
        return Derived::default();
    }
    if let Some(cfg) = app_store_cfg.filter(|_| app_store_ok) {
        log_sandbox_grant("Publishing", user_id, cfg, Grant::Publish, state, now);
    }
    let mut out = vec![ENTITLEMENT_CREATOR_PUBLISH.to_string()];
    if let MarketGrant::Granted(entitlements) = market {
        for e in entitlements {
            if !out.contains(&e) {
                out.push(e);
            }
        }
    }
    Derived {
        entitlements: out,
        market_unavailable: false,
    }
}

/// The online-play path: an active App Store record of a product configured
/// as online-play, or a prepaid term the market vouches for
/// ([`Subscription::Active`]). Nothing that grants publishing grants it, and
/// a publishing suspension does not remove it: the suspension is about
/// publishing, the pass is paid network access.
///
/// A market that could not answer ([`Subscription::Unavailable`]) grants
/// nothing and is not an error: an outage withholds only the pass, at a
/// mint and in `GET /entities` alike.
fn online_play(
    user_id: &Uuid,
    app_store_cfg: Option<&crate::app_store::AppStoreConfig>,
    state: &PublishingState,
    subscription: Subscription,
    now: i64,
) -> bool {
    if let Some(cfg) = app_store_cfg
        && app_store_active(cfg, Grant::OnlinePlay, &state.app_store, now)
    {
        log_sandbox_grant("Online-play", user_id, cfg, Grant::OnlinePlay, state, now);
        return true;
    }
    subscription == Subscription::Active
}

// --------- Admin: publishing suspension ---------

#[derive(Debug, Deserialize)]
pub struct SuspendRequest {
    pub reason: String,
    #[serde(rename = "reportId", default)]
    pub report_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SuspensionState {
    pub user_id: Uuid,
    pub suspended: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspension: Option<SuspensionView>,
}

/// Wire shape of a suspension record (camelCase `reportId`, matching the
/// request body).
#[derive(Debug, Serialize)]
pub struct SuspensionView {
    pub reason: String,
    #[serde(rename = "reportId", skip_serializing_if = "Option::is_none")]
    pub report_id: Option<String>,
    pub suspended_by: String,
    pub suspended_at: i64,
}

impl From<PublishingSuspension> for SuspensionView {
    fn from(p: PublishingSuspension) -> Self {
        Self {
            reason: p.reason,
            report_id: p.report_id,
            suspended_by: p.suspended_by,
            suspended_at: p.suspended_at,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SuspensionError {
    #[error(transparent)]
    Auth(#[from] EntitlementError),
    #[error("{0}")]
    BadRequest(String),
    #[error("User not found")]
    UserNotFound,
    #[error("Suspension changed concurrently; retry")]
    Conflict,
    #[error("Database error: {0}")]
    Database(Box<DynamoDBError>),
}

impl From<DynamoDBError> for SuspensionError {
    fn from(e: DynamoDBError) -> Self {
        match e {
            DynamoDBError::ConditionalConflict => SuspensionError::Conflict,
            other => SuspensionError::Database(Box::new(other)),
        }
    }
}

impl IntoResponse for SuspensionError {
    fn into_response(self) -> Response {
        match self {
            SuspensionError::Auth(e) => e.into_response(),
            SuspensionError::BadRequest(m) => (StatusCode::BAD_REQUEST, m).into_response(),
            SuspensionError::UserNotFound => {
                (StatusCode::NOT_FOUND, "User not found").into_response()
            }
            SuspensionError::Conflict => (StatusCode::CONFLICT, self.to_string()).into_response(),
            SuspensionError::Database(e) => match *e {
                DynamoDBError::TableNotExists(table) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Service setup incomplete: {} table not configured", table),
                )
                    .into_response(),
                other => {
                    error!("publishing suspension: database error: {}", other);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response()
                }
            },
        }
    }
}

fn is_valid_report_id(r: &str) -> bool {
    (1..=SUSPENSION_REPORT_ID_MAX_LEN).contains(&r.len())
        && r.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn validate_request(req: SuspendRequest) -> Result<(String, Option<String>), SuspensionError> {
    let reason = req.reason.trim().to_string();
    if reason.is_empty() {
        return Err(SuspensionError::BadRequest("reason is required".into()));
    }
    if reason.chars().count() > SUSPENSION_REASON_MAX_LEN {
        return Err(SuspensionError::BadRequest(format!(
            "reason exceeds {SUSPENSION_REASON_MAX_LEN} characters"
        )));
    }
    let report_id = match req.report_id.map(|r| r.trim().to_string()) {
        Some(r) if r.is_empty() => {
            return Err(SuspensionError::BadRequest(
                "reportId must not be empty when present".into(),
            ));
        }
        // Interpolated into `audit` log lines, so a restricted charset: no
        // spaces, `=` or newlines that could forge fields or lines.
        Some(r) if !is_valid_report_id(&r) => {
            return Err(SuspensionError::BadRequest(format!(
                "reportId must be 1-{SUSPENSION_REPORT_ID_MAX_LEN} characters of [A-Za-z0-9._:-]"
            )));
        }
        other => other,
    };
    Ok((reason, report_id))
}

/// `PUT /admin/users/:id/publishing-suspension` — suspend publishing.
/// 201 with the new record; 200 with the original record when already
/// suspended (the first audit record is kept); 404 unknown user.
pub async fn put_publishing_suspension(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
    Json(req): Json<SuspendRequest>,
) -> Result<Response, SuspensionError> {
    let claims = require_service_cwt_for(&app_state, &headers, &app_state.moderation_client_ids)?;
    let (reason, report_id) = validate_request(req)?;
    let suspension = PublishingSuspension {
        reason,
        report_id,
        suspended_by: claims.sub.clone(),
        suspended_at: Utc::now().timestamp(),
    };
    match app_state
        .db_store
        .set_publishing_suspension(&user_id, &suspension)
        .await?
    {
        SuspensionSet::Created => {
            info!(
                "audit publishing_suspension outcome=suspended user_id={} suspended_by={} report_id={}",
                user_id,
                suspension.suspended_by,
                suspension.report_id.as_deref().unwrap_or("-")
            );
            Ok((
                StatusCode::CREATED,
                Json(SuspensionState {
                    user_id,
                    suspended: true,
                    suspension: Some(suspension.into()),
                }),
            )
                .into_response())
        }
        SuspensionSet::AlreadySuspended(existing) => {
            info!(
                "audit publishing_suspension outcome=already_suspended user_id={} requested_by={} \
                 suspended_by={} report_id={}",
                user_id,
                claims.sub,
                existing.suspended_by,
                existing.report_id.as_deref().unwrap_or("-")
            );
            Ok((
                StatusCode::OK,
                Json(SuspensionState {
                    user_id,
                    suspended: true,
                    suspension: Some(existing.into()),
                }),
            )
                .into_response())
        }
        SuspensionSet::UserNotFound => Err(SuspensionError::UserNotFound),
    }
}

/// `DELETE /admin/users/:id/publishing-suspension` — lift. 204 whether or
/// not the account was suspended (idempotent); 404 unknown user.
pub async fn delete_publishing_suspension(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, SuspensionError> {
    let claims = require_service_cwt_for(&app_state, &headers, &app_state.moderation_client_ids)?;
    match app_state
        .db_store
        .lift_publishing_suspension(&user_id)
        .await?
    {
        SuspensionLift::Lifted(old) => {
            info!(
                "audit publishing_suspension outcome=lifted user_id={} lifted_by={} suspended_by={} \
                 suspended_at={} report_id={}",
                user_id,
                claims.sub,
                old.suspended_by,
                old.suspended_at,
                old.report_id.as_deref().unwrap_or("-")
            );
            Ok(StatusCode::NO_CONTENT)
        }
        SuspensionLift::LiftedMalformed(decode_error) => {
            // The removal happened; only the old record could not be read
            // back for the log. Still a successful lift.
            warn!(
                "audit publishing_suspension outcome=lifted user_id={} lifted_by={} \
                 previous_record=malformed",
                user_id, claims.sub
            );
            warn!(
                "publishing suspension record for {} was malformed: {}",
                user_id, decode_error
            );
            Ok(StatusCode::NO_CONTENT)
        }
        SuspensionLift::NotSuspended => {
            info!(
                "audit publishing_suspension outcome=not_suspended user_id={} lifted_by={}",
                user_id, claims.sub
            );
            Ok(StatusCode::NO_CONTENT)
        }
        SuspensionLift::UserNotFound => Err(SuspensionError::UserNotFound),
    }
}

/// `GET /admin/users/:id/publishing-suspension` — the suspension record
/// only. Deliberately says nothing about Patreon membership (no Patreon
/// status endpoint — `.claude/rules/patreon.md`).
pub async fn get_publishing_suspension(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
) -> Result<Json<SuspensionState>, SuspensionError> {
    require_service_cwt_for(&app_state, &headers, &app_state.moderation_client_ids)?;
    let Some(current) = app_state
        .db_store
        .get_publishing_suspension(&user_id)
        .await?
    else {
        return Err(SuspensionError::UserNotFound);
    };
    Ok(Json(SuspensionState {
        user_id,
        suspended: current.is_some(),
        suspension: current.map(Into::into),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cwt::ArkavoPatreonMembership;

    fn cfg() -> PublisherConfig {
        PublisherConfig::parse(Some("arkavo-camp"), Some("t-pub, t-pro")).unwrap()
    }

    fn snap(memberships: Vec<ArkavoPatreonMembership>) -> ArkavoPatreon {
        let now = Utc::now().timestamp();
        ArkavoPatreon {
            role: "consumer".into(),
            patreon_user_id: "p-1".into(),
            campaign_id: None,
            memberships,
            owned_tiers: Default::default(),
            verified_at: now,
            cache_expires_at: now + 300,
        }
    }

    fn member(campaign: &str, status: Option<&str>, tiers: &[&str]) -> ArkavoPatreonMembership {
        ArkavoPatreonMembership {
            creator_sub: None,
            campaign_name: None,
            campaign_id: campaign.into(),
            patron_status: status.map(Into::into),
            tier_ids: tiers.iter().map(|t| t.to_string()).collect(),
            tier_slugs: vec![],
        }
    }

    fn now() -> i64 {
        Utc::now().timestamp()
    }

    #[test]
    fn config_requires_both_vars() {
        assert!(PublisherConfig::parse(None, None).is_none());
        assert!(PublisherConfig::parse(Some("c"), None).is_none());
        assert!(PublisherConfig::parse(Some("c"), Some(" , ")).is_none());
        assert!(PublisherConfig::parse(None, Some("t")).is_none());
        assert!(PublisherConfig::parse(Some("  "), Some("t")).is_none());
        let c = cfg();
        assert_eq!(c.campaign_id, "arkavo-camp");
        assert_eq!(
            c.tier_ids,
            ["t-pub", "t-pro"].iter().map(|s| s.to_string()).collect()
        );
    }

    #[test]
    fn active_patron_of_the_campaign_at_a_qualifying_tier_qualifies() {
        let s = snap(vec![member(
            "arkavo-camp",
            Some("active_patron"),
            &["t-free", "t-pub"],
        )]);
        assert!(qualifies(&cfg(), &s, now()));
    }

    #[test]
    fn campaign_mismatch_does_not_qualify() {
        let s = snap(vec![member(
            "other-camp",
            Some("active_patron"),
            &["t-pub"],
        )]);
        assert!(!qualifies(&cfg(), &s, now()));
    }

    #[test]
    fn non_active_status_does_not_qualify() {
        for status in [Some("declined_patron"), Some("former_patron"), None] {
            let s = snap(vec![member("arkavo-camp", status, &["t-pub"])]);
            assert!(!qualifies(&cfg(), &s, now()), "{status:?}");
        }
    }

    #[test]
    fn tier_not_in_set_does_not_qualify() {
        let s = snap(vec![member(
            "arkavo-camp",
            Some("active_patron"),
            &["t-free"],
        )]);
        assert!(!qualifies(&cfg(), &s, now()));
        let free_follower = snap(vec![member("arkavo-camp", Some("active_patron"), &[])]);
        assert!(!qualifies(&cfg(), &free_follower, now()));
    }

    fn owner_of(campaign: &str) -> ArkavoPatreon {
        let mut s = snap(vec![]);
        s.role = "creator".into();
        s.campaign_id = Some(campaign.into());
        s
    }

    #[test]
    fn owning_the_publisher_campaign_qualifies() {
        // Arkavo's own account owns the campaign and cannot pledge to it.
        assert!(qualifies(&cfg(), &owner_of("arkavo-camp"), now()));
    }

    #[test]
    fn owning_another_campaign_does_not_qualify() {
        assert!(!qualifies(&cfg(), &owner_of("other-camp"), now()));
        // Nor does a membership-less consumer snapshot.
        assert!(!qualifies(&cfg(), &snap(vec![]), now()));
    }

    #[test]
    fn stale_owner_snapshot_does_not_qualify() {
        let mut s = owner_of("arkavo-camp");
        s.cache_expires_at = now() - 1;
        assert!(!qualifies(&cfg(), &s, now()));
    }

    #[test]
    fn stale_snapshot_does_not_qualify() {
        let mut s = snap(vec![member(
            "arkavo-camp",
            Some("active_patron"),
            &["t-pub"],
        )]);
        s.cache_expires_at = now() - 1;
        assert!(!qualifies(&cfg(), &s, now()));
    }

    #[test]
    fn request_validation() {
        let ok = |reason: &str, report: Option<&str>| {
            validate_request(SuspendRequest {
                reason: reason.into(),
                report_id: report.map(Into::into),
            })
        };
        assert_eq!(
            ok(" spam ", Some(" r1 ")).unwrap(),
            ("spam".into(), Some("r1".into()))
        );
        assert_eq!(ok("spam", None).unwrap(), ("spam".into(), None));
        assert!(ok("  ", None).is_err());
        assert!(ok("spam", Some("")).is_err());
        assert!(ok(&"x".repeat(SUSPENSION_REASON_MAX_LEN + 1), None).is_err());
        assert!(ok("spam", Some(&"x".repeat(SUSPENSION_REPORT_ID_MAX_LEN + 1))).is_err());
        // reportId charset: it lands in audit log lines.
        assert!(ok("spam", Some("rpt-2026.04:12_a")).is_ok());
        assert!(ok("spam", Some(&"x".repeat(SUSPENSION_REPORT_ID_MAX_LEN))).is_ok());
        for forged in [
            "r1\naudit publishing_suspension outcome=lifted",
            "r1 suspended_by=client:ops",
            "r1=x",
            "rpt/1",
            "rpt\u{00e9}",
        ] {
            assert!(ok("spam", Some(forged)).is_err(), "{forged:?}");
        }
        let body: SuspendRequest =
            serde_json::from_str(r#"{"reason":"r","reportId":"rpt-9"}"#).unwrap();
        assert_eq!(body.report_id.as_deref(), Some("rpt-9"));
    }
}
