//! The agent identity's trust state over HTTP. Contract:
//! docs/agent-credentials-contract.md (v2).

use crate::agent::{AgentError, REFUSE_STALE_ASSERTION};
use crate::constants::{
    GUARDIAN_APPRAISAL_MAX_SECONDS, OWNER_APPRAISAL_TTL_DEFAULT_SECONDS,
    OWNER_APPRAISAL_TTL_MAX_SECONDS,
};

/// How long an appraisal lasts, parsed once at startup. Either value may be
/// configured below its ceiling, never above it: an out-of-range value
/// fails startup rather than being clamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppraisalConfig {
    /// An owner appraisal's `appraised_until` is this long after the owner's
    /// passkey assertion (`auth_time`), never after the request.
    pub owner_ttl_seconds: i64,
    /// The latest `appraised_until` a Guardian may set, from now.
    pub guardian_max_seconds: i64,
}

impl Default for AppraisalConfig {
    fn default() -> Self {
        Self {
            owner_ttl_seconds: OWNER_APPRAISAL_TTL_DEFAULT_SECONDS,
            guardian_max_seconds: GUARDIAN_APPRAISAL_MAX_SECONDS,
        }
    }
}

impl AppraisalConfig {
    /// `AGENT_OWNER_APPRAISAL_TTL_SECONDS` (default 12 h, 1 s to 24 h) and
    /// `AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS` (default 15 min, 1 s to 15 min).
    pub fn parse(owner_ttl: Option<String>, guardian_max: Option<String>) -> Result<Self, String> {
        fn bounded(name: &str, raw: Option<String>, default: i64, max: i64) -> Result<i64, String> {
            let Some(raw) = raw.filter(|v| !v.trim().is_empty()) else {
                return Ok(default);
            };
            let value: i64 = raw
                .trim()
                .parse()
                .map_err(|_| format!("{name} is not an integer: {raw}"))?;
            if !(1..=max).contains(&value) {
                return Err(format!("{name} must be 1 to {max} seconds, got {value}"));
            }
            Ok(value)
        }
        Ok(Self {
            owner_ttl_seconds: bounded(
                "AGENT_OWNER_APPRAISAL_TTL_SECONDS",
                owner_ttl,
                OWNER_APPRAISAL_TTL_DEFAULT_SECONDS,
                OWNER_APPRAISAL_TTL_MAX_SECONDS,
            )?,
            guardian_max_seconds: bounded(
                "AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS",
                guardian_max,
                GUARDIAN_APPRAISAL_MAX_SECONDS,
                GUARDIAN_APPRAISAL_MAX_SECONDS,
            )?,
        })
    }
}

/// Refuse an empty, oversized or control-character label before it reaches
/// storage or a token claim.
pub(crate) fn validate_label(field: &str, value: &str, max: usize) -> Result<(), AgentError> {
    if value.is_empty() || value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(AgentError::InvalidRequest(format!(
            "{field} must be 1 to {max} characters with no control characters"
        )));
    }
    Ok(())
}

/// When an owner appraisal ends: `owner_ttl` after the
/// passkey assertion behind the owner's credential (a passkey auth CWT's
/// `iat`, or an `agents:delegate` token's `auth_time`), never after the
/// request, and never later than `now + owner_ttl`, so a clock-skewed `iat`
/// gains nothing. Refused once that moment has passed: the owner signs in
/// again.
pub(crate) fn owner_appraisal_deadline(
    issued_at: i64,
    owner_ttl: i64,
    now: i64,
) -> Result<i64, AgentError> {
    let deadline = issued_at
        .saturating_add(owner_ttl)
        .min(now.saturating_add(owner_ttl));
    if deadline <= now {
        return Err(AgentError::Forbidden(REFUSE_STALE_ASSERTION.into()));
    }
    Ok(deadline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appraisal_config_defaults_to_twelve_hours_and_fifteen_minutes() {
        let c = AppraisalConfig::parse(None, None).unwrap();
        assert_eq!((c.owner_ttl_seconds, c.guardian_max_seconds), (43_200, 900));
        assert_eq!(c, AppraisalConfig::default());
        assert_eq!(
            AppraisalConfig::parse(Some(" ".into()), Some("".into())).unwrap(),
            c,
            "blank means unset"
        );
    }

    #[test]
    fn appraisal_config_accepts_values_up_to_the_nist_ceilings() {
        let c = AppraisalConfig::parse(Some("86400".into()), Some("900".into())).unwrap();
        assert_eq!((c.owner_ttl_seconds, c.guardian_max_seconds), (86_400, 900));
        let c = AppraisalConfig::parse(Some("3600".into()), Some("60".into())).unwrap();
        assert_eq!((c.owner_ttl_seconds, c.guardian_max_seconds), (3_600, 60));
    }

    #[test]
    fn appraisal_config_refuses_out_of_range_values_instead_of_clamping() {
        for (owner, guardian, needle) in [
            (
                Some("86401"),
                None,
                "AGENT_OWNER_APPRAISAL_TTL_SECONDS must be 1 to 86400",
            ),
            (
                Some("0"),
                None,
                "AGENT_OWNER_APPRAISAL_TTL_SECONDS must be 1 to 86400",
            ),
            (
                Some("-5"),
                None,
                "AGENT_OWNER_APPRAISAL_TTL_SECONDS must be 1 to 86400",
            ),
            (
                Some("12h"),
                None,
                "AGENT_OWNER_APPRAISAL_TTL_SECONDS is not an integer",
            ),
            (
                None,
                Some("901"),
                "AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS must be 1 to 900",
            ),
            (
                None,
                Some("0"),
                "AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS must be 1 to 900",
            ),
        ] {
            let err = AppraisalConfig::parse(owner.map(Into::into), guardian.map(Into::into))
                .unwrap_err();
            assert!(err.contains(needle), "{err}");
        }
    }

    #[test]
    fn an_owner_appraisal_runs_from_the_assertion_and_is_refused_once_past() {
        assert_eq!(
            owner_appraisal_deadline(1_000, 43_200, 1_600).unwrap(),
            44_200
        );
        assert_eq!(
            owner_appraisal_deadline(1_700, 43_200, 1_600).unwrap(),
            44_800,
            "an iat ahead of the clock gains nothing"
        );
        assert_eq!(owner_appraisal_deadline(1_000, 600, 1_599).unwrap(), 1_600);
        for now in [1_600, 5_000] {
            let err = owner_appraisal_deadline(1_000, 600, now).unwrap_err();
            assert_eq!(
                err.to_string(),
                "Forbidden: passkey assertion is older than the owner appraisal lifetime; sign in again"
            );
        }
    }
}
