//! The agent identity's trust state over HTTP. Contract:
//! docs/agent-credentials-contract.md (v2).

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
}
