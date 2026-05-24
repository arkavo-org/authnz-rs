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

use ciborium::value::{Integer, Value};

fn claims_to_cbor(c: &ArkavoClaims) -> Result<Vec<u8>, CwtError> {
    let mut entries: Vec<(Value, Value)> = Vec::new();

    entries.push((Value::Integer(1.into()), Value::Text(c.iss.clone())));
    entries.push((Value::Integer(2.into()), Value::Text(c.sub.clone())));
    entries.push((
        Value::Integer(3.into()),
        match &c.aud {
            Audience::Single(s) => Value::Text(s.clone()),
            Audience::Multiple(v) => {
                Value::Array(v.iter().map(|s| Value::Text(s.clone())).collect())
            }
        },
    ));
    entries.push((Value::Integer(4.into()), Value::Integer(c.exp.into())));
    entries.push((Value::Integer(6.into()), Value::Integer(c.iat.into())));
    entries.push((Value::Integer(7.into()), Value::Bytes(c.cti.to_vec())));

    if let Some(cnf) = &c.cnf {
        let mut cnf_entries: Vec<(Value, Value)> = Vec::new();
        // Serialize CoseKey via coset's AsCborValue.
        use coset::AsCborValue;
        let cose_key_value = cnf
            .cose_key
            .clone()
            .to_cbor_value()
            .map_err(|_| CwtError::Malformed)?;
        cnf_entries.push((Value::Integer(1.into()), cose_key_value));
        cnf_entries.push((Value::Integer(2.into()), Value::Bytes(cnf.kid.clone())));
        entries.push((Value::Integer(8.into()), Value::Map(cnf_entries)));
    }

    if let Some(v) = &c.custom.idp {
        entries.push((Value::Text("idp".into()), Value::Text(v.clone())));
    }
    if let Some(v) = &c.custom.email {
        entries.push((Value::Text("email".into()), Value::Text(v.clone())));
    }
    if let Some(v) = c.custom.email_verified {
        entries.push((Value::Text("email_verified".into()), Value::Bool(v)));
    }
    if let Some(v) = &c.custom.arkavo_account_id {
        entries.push((
            Value::Text("arkavo_account_id".into()),
            Value::Text(v.clone()),
        ));
    }
    if let Some(v) = &c.custom.arkavo_roles {
        entries.push((
            Value::Text("arkavo_roles".into()),
            Value::Array(v.iter().map(|s| Value::Text(s.clone())).collect()),
        ));
    }
    if let Some(v) = &c.custom.arkavo_entitlements {
        entries.push((
            Value::Text("arkavo_entitlements".into()),
            Value::Array(v.iter().map(|s| Value::Text(s.clone())).collect()),
        ));
    }

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut bytes)
        .map_err(|_| CwtError::Malformed)?;
    Ok(bytes)
}

fn claims_from_cbor(bytes: &[u8]) -> Result<ArkavoClaims, CwtError> {
    let value: Value = ciborium::de::from_reader(bytes).map_err(|_| CwtError::Malformed)?;
    let Value::Map(entries) = value else {
        return Err(CwtError::Malformed);
    };

    // Reject duplicate keys.
    {
        let mut seen_ints: Vec<i128> = Vec::new();
        let mut seen_strs: Vec<String> = Vec::new();
        for (k, _) in &entries {
            match k {
                Value::Integer(i) => {
                    let n: i128 = (*i).into();
                    if seen_ints.contains(&n) {
                        return Err(CwtError::Malformed);
                    }
                    seen_ints.push(n);
                }
                Value::Text(s) => {
                    if seen_strs.contains(s) {
                        return Err(CwtError::Malformed);
                    }
                    seen_strs.push(s.clone());
                }
                _ => return Err(CwtError::Malformed),
            }
        }
    }

    let mut iss: Option<String> = None;
    let mut sub: Option<String> = None;
    let mut aud: Option<Audience> = None;
    let mut exp: Option<i64> = None;
    let mut iat: Option<i64> = None;
    let mut cti: Option<[u8; 16]> = None;
    let mut cnf: Option<Cnf> = None;
    let mut custom = CustomClaims::default();

    let int_label = |i: &Integer| -> i128 { (*i).into() };

    for (k, v) in entries {
        match (k, v) {
            (Value::Integer(i), Value::Text(s)) if int_label(&i) == 1 => iss = Some(s),
            (Value::Integer(i), Value::Text(s)) if int_label(&i) == 2 => sub = Some(s),
            (Value::Integer(i), Value::Text(s)) if int_label(&i) == 3 => {
                aud = Some(Audience::Single(s))
            }
            (Value::Integer(i), Value::Array(a)) if int_label(&i) == 3 => {
                let parts: Result<Vec<String>, _> = a
                    .into_iter()
                    .map(|x| match x {
                        Value::Text(s) => Ok(s),
                        _ => Err(CwtError::Malformed),
                    })
                    .collect();
                aud = Some(Audience::Multiple(parts?));
            }
            (Value::Integer(i), Value::Integer(n)) if int_label(&i) == 4 => {
                let v: i128 = n.into();
                exp = Some(v as i64);
            }
            (Value::Integer(i), Value::Integer(n)) if int_label(&i) == 6 => {
                let v: i128 = n.into();
                iat = Some(v as i64);
            }
            (Value::Integer(i), Value::Bytes(b)) if int_label(&i) == 7 => {
                if b.len() != 16 {
                    return Err(CwtError::Malformed);
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&b);
                cti = Some(arr);
            }
            (Value::Integer(i), Value::Map(map)) if int_label(&i) == 8 => {
                let mut cose_key: Option<coset::CoseKey> = None;
                let mut kid: Option<Vec<u8>> = None;
                for (kk, vv) in map {
                    match (kk, vv) {
                        (Value::Integer(j), val) if int_label(&j) == 1 => {
                            use coset::AsCborValue;
                            cose_key = Some(
                                coset::CoseKey::from_cbor_value(val)
                                    .map_err(|_| CwtError::Malformed)?,
                            );
                        }
                        (Value::Integer(j), Value::Bytes(b)) if int_label(&j) == 2 => {
                            kid = Some(b);
                        }
                        _ => {}
                    }
                }
                cnf = Some(Cnf {
                    cose_key: cose_key.ok_or(CwtError::Malformed)?,
                    kid: kid.unwrap_or_default(),
                });
            }
            (Value::Text(s), Value::Text(t)) if s == "idp" => custom.idp = Some(t),
            (Value::Text(s), Value::Text(t)) if s == "email" => custom.email = Some(t),
            (Value::Text(s), Value::Bool(b)) if s == "email_verified" => {
                custom.email_verified = Some(b)
            }
            (Value::Text(s), Value::Text(t)) if s == "arkavo_account_id" => {
                custom.arkavo_account_id = Some(t)
            }
            (Value::Text(s), Value::Array(a)) if s == "arkavo_roles" => {
                let parts: Result<Vec<String>, _> = a
                    .into_iter()
                    .map(|x| match x {
                        Value::Text(t) => Ok(t),
                        _ => Err(CwtError::Malformed),
                    })
                    .collect();
                custom.arkavo_roles = Some(parts?);
            }
            (Value::Text(s), Value::Array(a)) if s == "arkavo_entitlements" => {
                let parts: Result<Vec<String>, _> = a
                    .into_iter()
                    .map(|x| match x {
                        Value::Text(t) => Ok(t),
                        _ => Err(CwtError::Malformed),
                    })
                    .collect();
                custom.arkavo_entitlements = Some(parts?);
            }
            _ => {} // Ignore unknown claims (forward-compat).
        }
    }

    Ok(ArkavoClaims {
        iss: iss.ok_or(CwtError::MissingClaim("iss"))?,
        sub: sub.ok_or(CwtError::MissingClaim("sub"))?,
        aud: aud.ok_or(CwtError::MissingClaim("aud"))?,
        exp: exp.ok_or(CwtError::MissingClaim("exp"))?,
        iat: iat.ok_or(CwtError::MissingClaim("iat"))?,
        cti: cti.ok_or(CwtError::MissingClaim("cti"))?,
        cnf,
        custom,
    })
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

    #[test]
    fn cbor_roundtrip_minimal_claims() {
        let c = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let bytes = claims_to_cbor(&c).expect("encode");
        let decoded = claims_from_cbor(&bytes).expect("decode");
        assert_eq!(decoded.iss, c.iss);
        assert_eq!(decoded.sub, c.sub);
        assert_eq!(decoded.aud, c.aud);
        assert_eq!(decoded.exp, c.exp);
        assert_eq!(decoded.iat, c.iat);
        assert_eq!(decoded.cti, c.cti);
        assert!(decoded.cnf.is_none());
    }

    #[test]
    fn cbor_roundtrip_full_oidc_claims() {
        let c = ArkavoClaims::oidc_access("iss-1", "arkavo:abc", "opentdf", 1)
            .with_idp("arkavo")
            .with_email("a@b.c", true)
            .with_arkavo_account_id("acct-1")
            .with_arkavo_roles(vec!["reader".into(), "writer".into()])
            .with_arkavo_entitlements(vec!["ent-a".into()]);
        let bytes = claims_to_cbor(&c).expect("encode");
        let decoded = claims_from_cbor(&bytes).expect("decode");
        assert_eq!(decoded.custom.idp, c.custom.idp);
        assert_eq!(decoded.custom.email, c.custom.email);
        assert_eq!(decoded.custom.email_verified, c.custom.email_verified);
        assert_eq!(decoded.custom.arkavo_account_id, c.custom.arkavo_account_id);
        assert_eq!(decoded.custom.arkavo_roles, c.custom.arkavo_roles);
        assert_eq!(
            decoded.custom.arkavo_entitlements,
            c.custom.arkavo_entitlements
        );
    }

    #[test]
    fn cbor_decode_rejects_duplicate_keys() {
        // Hand-craft CBOR: map with two entries for key 1 (iss).
        // 0xa3 = map(3 entries); 0x01 = uint 1; 0x61, 'a' = tstr "a"; 0x01 = uint 1; 0x61, 'b' = tstr "b"; 0x02 = uint 2; 0x61, 'c' = tstr "c"
        let bytes = vec![0xa3, 0x01, 0x61, b'a', 0x01, 0x61, b'b', 0x02, 0x61, b'c'];
        let result = claims_from_cbor(&bytes);
        assert!(matches!(result, Err(CwtError::Malformed)), "got {:?}", result);
    }
}
