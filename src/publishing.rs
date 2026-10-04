//! Creator-publishing entitlement (#91) and its moderation override.
//!
//! [`ENTITLEMENT_CREATOR_PUBLISH`] is **derived, never stored**. Every
//! short-lived token minted for a human (passkey auth CWT, DeviceCheck
//! assertion CWT, OIDC access token incl. refresh) gets it appended to
//! `arkavo_entitlements` while all of these hold:
//!
//! 1. the feature is configured (`PATREON_PUBLISHER_CAMPAIGN_ID` and
//!    `PATREON_PUBLISHER_TIER_IDS` both set);
//! 2. the account's materialized Patreon snapshot (cached ≤ 5 min) lists a
//!    membership of that campaign with `patron_status = active_patron` and
//!    at least one currently entitled tier ID in the configured set — the
//!    snapshot's own `campaign_id` (the campaign a creator *owns*) is never
//!    consulted;
//! 3. the account carries no publishing suspension.
//!
//! Every failure (Patreon down, deadline passed, DB error, malformed record)
//! withholds the entitlement. It is never written to
//! `credentials.entitlements` ([`crate::entitlements::validate_fqns`]
//! refuses it), so it cannot be delegated to agents, does not appear in
//! `GET /entities`, and is dropped from the ~99-year registration token.
//!
//! The suspension endpoints (`/admin/users/:id/publishing-suspension`) take a
//! service CWT whose client is on `MODERATION_CLIENT_IDS`.

use crate::AppState;
use crate::constants::{
    ENTITLEMENT_CREATOR_PUBLISH, SUSPENSION_REASON_MAX_LEN, SUSPENSION_REPORT_ID_MAX_LEN,
};
use crate::cwt::ArkavoPatreon;
use crate::db::{DynamoDBError, PublishingSuspension, SuspensionLift, SuspensionSet};
use crate::entitlements::{EntitlementError, require_service_cwt_for};
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

/// Whether a materialized snapshot qualifies under `cfg`. Pure: membership
/// only — the suspension check is separate ([`derived_entitlements`]).
pub(crate) fn qualifies(cfg: &PublisherConfig, snap: &ArkavoPatreon, now: i64) -> bool {
    if snap.cache_expires_at < now {
        return false;
    }
    snap.memberships.iter().any(|m| {
        m.campaign_id == cfg.campaign_id
            && m.patron_status.as_deref() == Some(ACTIVE_PATRON)
            && m.tier_ids.iter().any(|t| cfg.tier_ids.contains(t))
    })
}

/// The entitlements derived for `user_id` at this mint (today: the
/// creator-publishing entitlement or nothing). Checks run cheapest first —
/// config, then the already-materialized snapshot, then one strongly
/// consistent read of the suspension — so feature-off, unlinked and
/// non-qualifying users cost no extra DynamoDB call. Fails closed.
pub(crate) async fn derived_entitlements(
    app_state: &AppState,
    user_id: Option<Uuid>,
    snap: Option<&ArkavoPatreon>,
) -> Vec<String> {
    let Some(cfg) = app_state.publisher.as_ref().as_ref() else {
        return Vec::new();
    };
    let (Some(user_id), Some(snap)) = (user_id, snap) else {
        return Vec::new();
    };
    if !qualifies(cfg, snap, Utc::now().timestamp()) {
        return Vec::new();
    }
    match app_state.db_store.get_publishing_suspension(&user_id).await {
        Ok(Some(None)) => vec![ENTITLEMENT_CREATOR_PUBLISH.to_string()],
        Ok(Some(Some(_))) => {
            info!(
                "Publishing entitlement withheld for user {}: publishing is suspended",
                user_id
            );
            Vec::new()
        }
        Ok(None) => Vec::new(),
        Err(e) => {
            warn!(
                "Publishing suspension lookup failed for user {}: {} — failing closed (no \
                 publishing entitlement)",
                user_id, e
            );
            Vec::new()
        }
    }
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
            verified_at: now,
            cache_expires_at: now + 300,
        }
    }

    fn member(campaign: &str, status: Option<&str>, tiers: &[&str]) -> ArkavoPatreonMembership {
        ArkavoPatreonMembership {
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

    #[test]
    fn owning_the_campaign_is_not_membership() {
        // Staff linked as the *creator* of Arkavo's campaign own it but are
        // not its patrons; the snapshot's top-level campaign_id is ignored.
        let mut s = snap(vec![]);
        s.role = "creator".into();
        s.campaign_id = Some("arkavo-camp".into());
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
