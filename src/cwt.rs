//! CWT (CBOR Web Token, RFC 8392) minting and verification.
//!
//! All Arkavo-issued tokens (registration, auth, DeviceCheck assertion,
//! OIDC access_token) flow through this module. OIDC id_token and Apple
//! id_token validation remain on jsonwebtoken.

use chrono::Utc;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum CwtError {
    #[error("malformed COSE_Sign1 or CBOR")]
    Malformed,
    #[error("unsupported algorithm (only ES256 is accepted)")]
    UnsupportedAlg,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("token expired")]
    Expired,
    #[error("token not yet valid")]
    NotYetValid,
    #[error("required claim missing: {0}")]
    MissingClaim(&'static str),
    #[error("issuer mismatch")]
    IssuerMismatch,
    #[error("audience mismatch")]
    AudienceMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct Cnf {
    pub cose_key: coset::CoseKey,
    pub kid: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct CustomClaims {
    pub idp: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub arkavo_account_id: Option<String>,
    pub arkavo_roles: Option<Vec<String>>,
    pub arkavo_entitlements: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct ArkavoClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Audience,
    pub exp: i64,
    pub iat: i64,
    pub cti: [u8; 16],
    pub cnf: Option<Cnf>,
    pub custom: CustomClaims,
}

fn random_cti() -> [u8; 16] {
    *Uuid::new_v4().as_bytes()
}

impl ArkavoClaims {
    fn base(iss: &str, sub: &str, aud: Audience, exp_secs: i64) -> Self {
        let iat = Utc::now().timestamp();
        Self {
            iss: iss.to_string(),
            sub: sub.to_string(),
            aud,
            exp: iat + exp_secs,
            iat,
            cti: random_cti(),
            cnf: None,
            custom: CustomClaims::default(),
        }
    }

    pub fn auth(iss: &str, sub: &str, hours: i64) -> Self {
        Self::base(iss, sub, Audience::Single("arkavo".into()), hours * 3600)
    }

    pub fn registration(iss: &str, sub: &str, weeks: i64) -> Self {
        Self::base(
            iss,
            sub,
            Audience::Single("arkavo".into()),
            weeks * 7 * 24 * 3600,
        )
    }

    pub fn devicecheck(iss: &str, sub: &str, hours: i64) -> Self {
        Self::base(
            iss,
            sub,
            Audience::Single("arkavo:devicecheck".into()),
            hours * 3600,
        )
    }

    pub fn oidc_access(iss: &str, sub: &str, audience: &str, hours: i64) -> Self {
        Self::base(iss, sub, Audience::Single(audience.into()), hours * 3600)
    }

    pub fn with_cnf(mut self, cnf: Cnf) -> Self {
        self.cnf = Some(cnf);
        self
    }

    pub fn without_cnf(mut self) -> Self {
        self.cnf = None;
        self
    }

    pub fn with_idp(mut self, idp: &str) -> Self {
        self.custom.idp = Some(idp.into());
        self
    }

    pub fn with_email(mut self, email: &str, verified: bool) -> Self {
        self.custom.email = Some(email.into());
        self.custom.email_verified = Some(verified);
        self
    }

    pub fn with_arkavo_account_id(mut self, id: &str) -> Self {
        self.custom.arkavo_account_id = Some(id.into());
        self
    }

    pub fn with_arkavo_roles(mut self, roles: Vec<String>) -> Self {
        self.custom.arkavo_roles = Some(roles);
        self
    }

    pub fn with_arkavo_entitlements(mut self, ents: Vec<String>) -> Self {
        self.custom.arkavo_entitlements = Some(ents);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwt_error_display() {
        assert_eq!(CwtError::Malformed.to_string(), "malformed COSE_Sign1 or CBOR");
        assert_eq!(
            CwtError::UnsupportedAlg.to_string(),
            "unsupported algorithm (only ES256 is accepted)"
        );
    }

    #[test]
    fn arkavo_claims_auth_defaults() {
        let c = ArkavoClaims::auth("https://identity.arkavo.net", "user-uuid", 1);
        assert_eq!(c.iss, "https://identity.arkavo.net");
        assert_eq!(c.sub, "user-uuid");
        assert_eq!(c.aud, Audience::Single("arkavo".to_string()));
        assert!(c.exp > c.iat);
        assert_eq!(c.exp - c.iat, 3600);
        assert_eq!(c.cti.len(), 16);
        assert!(c.cnf.is_none());
    }

    #[test]
    fn arkavo_claims_oidc_access_with_custom_claims() {
        let c =
            ArkavoClaims::oidc_access("https://identity.arkavo.net", "arkavo:abc", "opentdf", 1)
                .with_idp("arkavo")
                .with_email("a@b.c", true)
                .with_arkavo_account_id("acct-1")
                .with_arkavo_roles(vec!["reader".into()]);
        assert_eq!(c.aud, Audience::Single("opentdf".to_string()));
        assert_eq!(c.custom.idp.as_deref(), Some("arkavo"));
        assert_eq!(c.custom.email.as_deref(), Some("a@b.c"));
        assert_eq!(c.custom.email_verified, Some(true));
        assert_eq!(c.custom.arkavo_account_id.as_deref(), Some("acct-1"));
        assert_eq!(
            c.custom.arkavo_roles.as_deref(),
            Some(&["reader".to_string()][..])
        );
    }

    #[test]
    fn arkavo_claims_cti_differs_across_mints() {
        let a = ArkavoClaims::auth("iss", "sub", 1);
        let b = ArkavoClaims::auth("iss", "sub", 1);
        assert_ne!(a.cti, b.cti);
    }
}
