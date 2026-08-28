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
    #[error("unsupported credential key type (only P-256 EC2 is supported)")]
    UnsupportedKeyType,
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

/// RFC 8693 §4.1 actor entry: who may present this token on the subject's behalf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub sub: String,
}

/// Non-person-entity descriptor (spec §1). `npe_type` is `"agent"` or `"device"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkavoNpe {
    pub npe_type: String,
    pub class: Option<String>,
    pub attestation_expiry: Option<i64>,
    pub device_id: Option<String>,
    pub delegation_id: Option<String>,
    pub depth: Option<u8>,
    pub chain: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct CustomClaims {
    pub idp: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub arkavo_account_id: Option<String>,
    pub arkavo_roles: Option<Vec<String>>,
    pub arkavo_entitlements: Option<Vec<String>>,
    /// Materialized Patreon membership snapshot. Populated by the OIDC token
    /// endpoint at mint time from the user's linked Patreon account. Verifiers
    /// (KAS, downstream RPs) read this directly off the access_token CWT —
    /// per the architecture statement, "Patreon proves membership, authnz-rs
    /// materializes entitlement", and the materialization lives in the token.
    pub arkavo_patreon: Option<ArkavoPatreon>,
    pub act: Option<Vec<Actor>>,
    pub arkavo_npe: Option<ArkavoNpe>,
}

/// Materialized Patreon membership for embedding in a CWT access token.
///
/// One snapshot per minted token. `verified_at` is the wall-clock second when
/// the Patreon API was queried (or the cache was warmed); `cache_expires_at`
/// is the latest second the cached snapshot may be reused without re-querying
/// Patreon. Downstream consumers should treat any value where
/// `cache_expires_at < now` as stale and re-mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkavoPatreon {
    /// `creator` or `consumer`. Determines how the membership list is
    /// interpreted: a creator owns `campaign_id`; a consumer is enrolled in
    /// zero or more campaigns.
    pub role: String,
    /// Patreon user id (the `data.id` returned by `/api/oauth2/v2/identity`).
    pub patreon_user_id: String,
    /// Creator-only: the Patreon campaign id discovered at link time. None
    /// for consumers (their memberships are listed in `memberships`).
    pub campaign_id: Option<String>,
    /// Consumer memberships. Empty for creators.
    pub memberships: Vec<ArkavoPatreonMembership>,
    /// Unix timestamp when this snapshot was materialized.
    pub verified_at: i64,
    /// Unix timestamp after which the snapshot is stale.
    pub cache_expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkavoPatreonMembership {
    pub campaign_id: String,
    /// Patreon's `patron_status` string. `active_patron`, `declined_patron`,
    /// `former_patron`, or absent (then `None`). Only `active_patron` should
    /// be treated as conferring entitlement by downstream policy.
    pub patron_status: Option<String>,
    /// Patreon tier IDs the user is currently entitled to. Empty list means
    /// the user is a free follower (no paid tier).
    pub tier_ids: Vec<String>,
    /// Slugified tier titles (lowercase, hyphenated) the user is entitled
    /// to within this campaign — the creator's own tier vocabulary. Feeds
    /// the platform's campaign-qualified entitlements
    /// (`campaign-tier/value/<campaign_id>_<slug>`). An independent,
    /// deduplicated SET — NOT parallel to `tier_ids` (slugify is not
    /// injective and titleless tiers are dropped). Empty until materialized.
    pub tier_slugs: Vec<String>,
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
        // Defensive: callers pass duration constants today, so this can only
        // overflow on a programmer error (e.g. someone bumps a unit). Panic
        // loudly rather than wrap silently and mint a token with an absurd exp.
        let exp = iat
            .checked_add(exp_secs)
            .expect("ArkavoClaims::base: iat + exp_secs overflowed i64");
        Self {
            iss: iss.to_string(),
            sub: sub.to_string(),
            aud,
            exp,
            iat,
            cti: random_cti(),
            cnf: None,
            custom: CustomClaims::default(),
        }
    }

    fn hours_to_secs(hours: i64) -> i64 {
        hours
            .checked_mul(3600)
            .expect("ArkavoClaims: hours * 3600 overflowed i64")
    }

    fn weeks_to_secs(weeks: i64) -> i64 {
        weeks
            .checked_mul(7 * 24 * 3600)
            .expect("ArkavoClaims: weeks * 7*24*3600 overflowed i64")
    }

    pub fn auth(iss: &str, sub: &str, hours: i64) -> Self {
        Self::base(
            iss,
            sub,
            Audience::Single("arkavo".into()),
            Self::hours_to_secs(hours),
        )
    }

    pub fn registration(iss: &str, sub: &str, weeks: i64) -> Self {
        Self::base(
            iss,
            sub,
            Audience::Single("arkavo".into()),
            Self::weeks_to_secs(weeks),
        )
    }

    pub fn devicecheck(iss: &str, sub: &str, hours: i64) -> Self {
        Self::base(
            iss,
            sub,
            Audience::Single("arkavo:devicecheck".into()),
            Self::hours_to_secs(hours),
        )
    }

    pub fn oidc_access(iss: &str, sub: &str, audience: &str, hours: i64) -> Self {
        Self::base(
            iss,
            sub,
            Audience::Single(audience.into()),
            Self::hours_to_secs(hours),
        )
    }

    /// Agent NPE token: multi-audience, minutes-scale lifetime, hard-capped
    /// at [`crate::constants::AGENT_TOKEN_MINUTES_MAX`].
    pub fn agent(iss: &str, sub: &str, audiences: Vec<String>, minutes: i64) -> Self {
        let capped = minutes.clamp(1, crate::constants::AGENT_TOKEN_MINUTES_MAX);
        Self::base(iss, sub, Audience::Multiple(audiences), capped * 60)
    }

    pub fn with_act(mut self, actors: Vec<Actor>) -> Self {
        self.custom.act = Some(actors);
        self
    }

    pub fn with_arkavo_npe(mut self, npe: ArkavoNpe) -> Self {
        self.custom.arkavo_npe = Some(npe);
        self
    }

    pub fn with_cnf(mut self, cnf: Cnf) -> Self {
        self.cnf = Some(cnf);
        self
    }

    #[cfg(test)]
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

    pub fn with_arkavo_patreon(mut self, p: ArkavoPatreon) -> Self {
        self.custom.arkavo_patreon = Some(p);
        self
    }
}

use base64::Engine;
use ciborium::value::{Integer, Value};
use coset::{AsCborValue, CborSerializable, CoseSign1Builder, HeaderBuilder, iana};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};

/// Convert a P-256 VerifyingKey into a COSE_Key (RFC 9052 §7).
pub fn cose_key_from_p256_verifying_key(vk: &VerifyingKey, kid: &[u8]) -> coset::CoseKey {
    let encoded = vk.to_encoded_point(false);
    let x = encoded
        .x()
        .expect("uncompressed P-256 point has x")
        .to_vec();
    let y = encoded
        .y()
        .expect("uncompressed P-256 point has y")
        .to_vec();

    coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
        .algorithm(iana::Algorithm::ES256)
        .key_id(kid.to_vec())
        .build()
}

/// Build a [`Cnf`] claim from a registered WebAuthn [`Passkey`].
///
/// `cose_key` is derived from the passkey's credential public key.
/// `kid` is set to the credential_id bytes.
///
/// Only P-256 (SECP256R1) EC2 keys are supported. Returns
/// [`CwtError::UnsupportedKeyType`] for any other key type.
pub fn cnf_from_passkey(passkey: &webauthn_rs::prelude::Passkey) -> Result<Cnf, CwtError> {
    use webauthn_rs::prelude::{COSEKeyType, ECDSACurve};

    let kid = passkey.cred_id().as_ref().to_vec();

    let cose_pub = passkey.get_public_key();
    let cose_key = match &cose_pub.key {
        COSEKeyType::EC_EC2(ec2) if ec2.curve == ECDSACurve::SECP256R1 => {
            let x = ec2.x.as_ref().to_vec();
            let y = ec2.y.as_ref().to_vec();
            coset::CoseKeyBuilder::new_ec2_pub_key(coset::iana::EllipticCurve::P_256, x, y)
                .algorithm(coset::iana::Algorithm::ES256)
                .key_id(kid.clone())
                .build()
        }
        _ => return Err(CwtError::UnsupportedKeyType),
    };

    Ok(Cnf { cose_key, kid })
}

/// Build a Cnf claim from a DeviceCheck/App Attest binding.
///
/// `public_key_bytes` is the device's P-256 public key in uncompressed
/// SEC1 format (65 bytes: 0x04 || x || y), as stored in the
/// `device_bindings` DynamoDB table. `device_id` is the App Attest
/// key ID, used as the cnf.kid.
pub fn cnf_from_app_attest(public_key_bytes: &[u8], device_id: &[u8]) -> Result<Cnf, CwtError> {
    let vk = VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|_| CwtError::Malformed)?;
    let cose_key = cose_key_from_p256_verifying_key(&vk, device_id);
    Ok(Cnf {
        cose_key,
        kid: device_id.to_vec(),
    })
}

/// `cnf` for an Ed25519 key (agent did:key): COSE_Key kty=OKP, crv=Ed25519.
pub fn cnf_from_ed25519(public_key: &[u8; 32], kid: &[u8]) -> Cnf {
    use coset::{CoseKey, KeyType, Label, iana};
    let cose_key = CoseKey {
        kty: KeyType::Assigned(iana::KeyType::OKP),
        key_id: kid.to_vec(),
        params: vec![
            (
                Label::Int(iana::OkpKeyParameter::Crv as i64),
                Value::from(iana::EllipticCurve::Ed25519 as u64),
            ),
            (
                Label::Int(iana::OkpKeyParameter::X as i64),
                Value::Bytes(public_key.to_vec()),
            ),
        ],
        ..Default::default()
    };
    Cnf {
        cose_key,
        kid: kid.to_vec(),
    }
}

/// CBOR encoding of tag #6.61 (CWT, RFC 8392 §6):
/// major type 6, additional info 24, uint8 = 61.
pub(crate) const CWT_TAG_PREFIX: [u8; 2] = [0xD8, 0x3D];

/// Strip the CWT CBOR tag #6.61 prefix. Strict: input MUST start with the
/// tag. Untagged COSE_Sign1 is rejected so a downstream verifier cannot be
/// tricked by feeding raw COSE_Sign1 to a CWT consumer.
pub(crate) fn strip_cwt_tag(bytes: &[u8]) -> Result<&[u8], CwtError> {
    bytes
        .strip_prefix(&CWT_TAG_PREFIX[..])
        .ok_or(CwtError::Malformed)
}

pub fn mint(claims: &ArkavoClaims, key: &SigningKey, kid: &[u8]) -> Result<Vec<u8>, CwtError> {
    let payload = claims_to_cbor(claims)?;

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(kid.to_vec())
        .build();

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(b"", |to_sign| {
            let sig: Signature = key.sign(to_sign);
            sig.to_bytes().to_vec()
        })
        .build();

    let inner = sign1.to_vec().map_err(|_| CwtError::Malformed)?;
    // Wrap in CBOR tag #6.61 (CWT) per RFC 8392 §6 so strict CWT verifiers
    // (HSM-backed validators, opentdf tdf-rs) can disambiguate the message
    // from a generic COSE_Sign1.
    let mut out = Vec::with_capacity(CWT_TAG_PREFIX.len() + inner.len());
    out.extend_from_slice(&CWT_TAG_PREFIX);
    out.extend_from_slice(&inner);
    Ok(out)
}

pub(crate) fn claims_to_cbor(c: &ArkavoClaims) -> Result<Vec<u8>, CwtError> {
    let mut entries: Vec<(Value, Value)> = Vec::new();

    entries.push((Value::Integer(1.into()), Value::Text(c.iss.clone())));
    entries.push((Value::Integer(2.into()), Value::Text(c.sub.clone())));
    entries.push((
        Value::Integer(3.into()),
        match &c.aud {
            Audience::Single(s) => Value::Text(s.clone()),
            Audience::Multiple(v) => {
                // Decoder rejects an empty multi-audience array; reject the
                // same shape on the way out so a misuse can't produce a token
                // the verifier (or any RFC 8392 verifier) refuses.
                if v.is_empty() {
                    return Err(CwtError::Malformed);
                }
                Value::Array(v.iter().map(|s| Value::Text(s.clone())).collect())
            }
        },
    ));
    entries.push((Value::Integer(4.into()), Value::Integer(c.exp.into())));
    entries.push((Value::Integer(6.into()), Value::Integer(c.iat.into())));
    entries.push((Value::Integer(7.into()), Value::Bytes(c.cti.to_vec())));

    if let Some(cnf) = &c.cnf {
        let mut cnf_entries: Vec<(Value, Value)> = Vec::new();
        // Serialize CoseKey via coset's AsCborValue (imported at module level).
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
    if let Some(p) = &c.custom.arkavo_patreon {
        entries.push((Value::Text("arkavo_patreon".into()), patreon_to_cbor(p)));
    }
    if let Some(actors) = &c.custom.act {
        entries.push((
            Value::Text("act".into()),
            Value::Array(
                actors
                    .iter()
                    .map(|a| {
                        Value::Map(vec![(
                            Value::Text("sub".into()),
                            Value::Text(a.sub.clone()),
                        )])
                    })
                    .collect(),
            ),
        ));
    }
    if let Some(n) = &c.custom.arkavo_npe {
        let mut m = vec![(Value::Text("type".into()), Value::Text(n.npe_type.clone()))];
        if let Some(v) = &n.class {
            m.push((Value::Text("class".into()), Value::Text(v.clone())));
        }
        if let Some(v) = n.attestation_expiry {
            m.push((
                Value::Text("attestation_expiry".into()),
                Value::Integer(v.into()),
            ));
        }
        if let Some(v) = &n.device_id {
            m.push((Value::Text("device_id".into()), Value::Text(v.clone())));
        }
        if let Some(v) = &n.delegation_id {
            m.push((Value::Text("delegation_id".into()), Value::Text(v.clone())));
        }
        if let Some(v) = n.depth {
            m.push((
                Value::Text("depth".into()),
                Value::Integer((v as i64).into()),
            ));
        }
        if let Some(v) = &n.chain {
            m.push((
                Value::Text("chain".into()),
                Value::Array(v.iter().map(|s| Value::Text(s.clone())).collect()),
            ));
        }
        entries.push((Value::Text("arkavo_npe".into()), Value::Map(m)));
    }

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut bytes)
        .map_err(|_| CwtError::Malformed)?;
    Ok(bytes)
}

fn patreon_to_cbor(p: &ArkavoPatreon) -> Value {
    let mut entries: Vec<(Value, Value)> = Vec::new();
    entries.push((Value::Text("role".into()), Value::Text(p.role.clone())));
    entries.push((
        Value::Text("patreon_user_id".into()),
        Value::Text(p.patreon_user_id.clone()),
    ));
    if let Some(cid) = &p.campaign_id {
        entries.push((Value::Text("campaign_id".into()), Value::Text(cid.clone())));
    }
    if !p.memberships.is_empty() {
        let arr: Vec<Value> = p
            .memberships
            .iter()
            .map(|m| {
                let mut m_entries: Vec<(Value, Value)> = Vec::new();
                m_entries.push((
                    Value::Text("campaign_id".into()),
                    Value::Text(m.campaign_id.clone()),
                ));
                if let Some(status) = &m.patron_status {
                    m_entries.push((
                        Value::Text("patron_status".into()),
                        Value::Text(status.clone()),
                    ));
                }
                m_entries.push((
                    Value::Text("tier_ids".into()),
                    Value::Array(m.tier_ids.iter().map(|t| Value::Text(t.clone())).collect()),
                ));
                if !m.tier_slugs.is_empty() {
                    m_entries.push((
                        Value::Text("tier_slugs".into()),
                        Value::Array(
                            m.tier_slugs
                                .iter()
                                .map(|t| Value::Text(t.clone()))
                                .collect(),
                        ),
                    ));
                }
                Value::Map(m_entries)
            })
            .collect();
        entries.push((Value::Text("memberships".into()), Value::Array(arr)));
    }
    entries.push((
        Value::Text("verified_at".into()),
        Value::Integer(p.verified_at.into()),
    ));
    entries.push((
        Value::Text("cache_expires_at".into()),
        Value::Integer(p.cache_expires_at.into()),
    ));
    Value::Map(entries)
}

fn patreon_from_cbor(v: Value) -> Result<ArkavoPatreon, CwtError> {
    let Value::Map(entries) = v else {
        return Err(CwtError::Malformed);
    };
    let mut role: Option<String> = None;
    let mut patreon_user_id: Option<String> = None;
    let mut campaign_id: Option<String> = None;
    let mut memberships: Vec<ArkavoPatreonMembership> = Vec::new();
    let mut verified_at: Option<i64> = None;
    let mut cache_expires_at: Option<i64> = None;

    for (k, vv) in entries {
        let key = match k {
            Value::Text(s) => s,
            _ => return Err(CwtError::Malformed),
        };
        match (key.as_str(), vv) {
            ("role", Value::Text(s)) => role = Some(s),
            ("patreon_user_id", Value::Text(s)) => patreon_user_id = Some(s),
            ("campaign_id", Value::Text(s)) => campaign_id = Some(s),
            ("memberships", Value::Array(arr)) => {
                for item in arr {
                    let Value::Map(m_entries) = item else {
                        return Err(CwtError::Malformed);
                    };
                    let mut m_campaign_id: Option<String> = None;
                    let mut m_status: Option<String> = None;
                    let mut m_tiers: Vec<String> = Vec::new();
                    let mut m_slugs: Vec<String> = Vec::new();
                    for (mk, mv) in m_entries {
                        let mkey = match mk {
                            Value::Text(s) => s,
                            _ => return Err(CwtError::Malformed),
                        };
                        match (mkey.as_str(), mv) {
                            ("campaign_id", Value::Text(s)) => m_campaign_id = Some(s),
                            ("patron_status", Value::Text(s)) => m_status = Some(s),
                            ("tier_ids", Value::Array(a)) => {
                                m_tiers = a
                                    .into_iter()
                                    .map(|t| match t {
                                        Value::Text(s) => Ok(s),
                                        _ => Err(CwtError::Malformed),
                                    })
                                    .collect::<Result<_, _>>()?;
                            }
                            ("tier_slugs", Value::Array(a)) => {
                                m_slugs = a
                                    .into_iter()
                                    .map(|t| match t {
                                        Value::Text(s) => Ok(s),
                                        _ => Err(CwtError::Malformed),
                                    })
                                    .collect::<Result<_, _>>()?;
                            }
                            _ => {}
                        }
                    }
                    memberships.push(ArkavoPatreonMembership {
                        campaign_id: m_campaign_id.ok_or(CwtError::Malformed)?,
                        patron_status: m_status,
                        tier_ids: m_tiers,
                        tier_slugs: m_slugs,
                    });
                }
            }
            ("verified_at", Value::Integer(n)) => {
                let v: i128 = n.into();
                verified_at = Some(i64::try_from(v).map_err(|_| CwtError::Malformed)?);
            }
            ("cache_expires_at", Value::Integer(n)) => {
                let v: i128 = n.into();
                cache_expires_at = Some(i64::try_from(v).map_err(|_| CwtError::Malformed)?);
            }
            _ => {}
        }
    }
    Ok(ArkavoPatreon {
        role: role.ok_or(CwtError::Malformed)?,
        patreon_user_id: patreon_user_id.ok_or(CwtError::Malformed)?,
        campaign_id,
        memberships,
        verified_at: verified_at.ok_or(CwtError::Malformed)?,
        cache_expires_at: cache_expires_at.ok_or(CwtError::Malformed)?,
    })
}

pub(crate) fn claims_from_cbor(bytes: &[u8]) -> Result<ArkavoClaims, CwtError> {
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
                let parts = parts?;
                if parts.is_empty() {
                    return Err(CwtError::Malformed);
                }
                aud = Some(Audience::Multiple(parts));
            }
            (Value::Integer(i), Value::Integer(n)) if int_label(&i) == 4 => {
                let v: i128 = n.into();
                exp = Some(i64::try_from(v).map_err(|_| CwtError::Malformed)?);
            }
            (Value::Integer(i), Value::Integer(n)) if int_label(&i) == 6 => {
                let v: i128 = n.into();
                iat = Some(i64::try_from(v).map_err(|_| CwtError::Malformed)?);
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
                // Reject duplicate keys inside the cnf sub-map.
                {
                    let mut seen_ints: Vec<i128> = Vec::new();
                    for (k, _) in &map {
                        match k {
                            Value::Integer(j) => {
                                let n: i128 = (*j).into();
                                if seen_ints.contains(&n) {
                                    return Err(CwtError::Malformed);
                                }
                                seen_ints.push(n);
                            }
                            _ => return Err(CwtError::Malformed),
                        }
                    }
                }
                let mut cose_key: Option<coset::CoseKey> = None;
                let mut kid: Option<Vec<u8>> = None;
                for (kk, vv) in map {
                    match (kk, vv) {
                        (Value::Integer(j), val) if int_label(&j) == 1 => {
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
            (Value::Text(s), v) if s == "arkavo_patreon" => {
                custom.arkavo_patreon = Some(patreon_from_cbor(v)?);
            }
            (Value::Text(s), Value::Array(a)) if s == "act" => {
                let mut actors = Vec::new();
                for entry in a {
                    let Value::Map(m) = entry else {
                        return Err(CwtError::Malformed);
                    };
                    let sub = m
                        .into_iter()
                        .find_map(|(k, v)| match (k, v) {
                            (Value::Text(k), Value::Text(v)) if k == "sub" => Some(v),
                            _ => None,
                        })
                        .ok_or(CwtError::Malformed)?;
                    actors.push(Actor { sub });
                }
                custom.act = Some(actors);
            }
            (Value::Text(s), Value::Map(m)) if s == "arkavo_npe" => {
                let mut n = ArkavoNpe {
                    npe_type: String::new(),
                    class: None,
                    attestation_expiry: None,
                    device_id: None,
                    delegation_id: None,
                    depth: None,
                    chain: None,
                };
                for (k, v) in m {
                    match (k, v) {
                        (Value::Text(k), Value::Text(v)) if k == "type" => n.npe_type = v,
                        (Value::Text(k), Value::Text(v)) if k == "class" => n.class = Some(v),
                        (Value::Text(k), Value::Integer(v)) if k == "attestation_expiry" => {
                            n.attestation_expiry = Some(
                                i64::try_from(i128::from(v)).map_err(|_| CwtError::Malformed)?,
                            )
                        }
                        (Value::Text(k), Value::Text(v)) if k == "device_id" => {
                            n.device_id = Some(v)
                        }
                        (Value::Text(k), Value::Text(v)) if k == "delegation_id" => {
                            n.delegation_id = Some(v)
                        }
                        (Value::Text(k), Value::Integer(v)) if k == "depth" => {
                            n.depth =
                                Some(u8::try_from(i128::from(v)).map_err(|_| CwtError::Malformed)?)
                        }
                        (Value::Text(k), Value::Array(a)) if k == "chain" => {
                            let parts: Result<Vec<String>, CwtError> = a
                                .into_iter()
                                .map(|x| match x {
                                    Value::Text(t) => Ok(t),
                                    _ => Err(CwtError::Malformed),
                                })
                                .collect();
                            n.chain = Some(parts?)
                        }
                        _ => {}
                    }
                }
                if n.npe_type.is_empty() {
                    return Err(CwtError::Malformed);
                }
                custom.arkavo_npe = Some(n);
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

#[derive(Debug, Clone)]
pub struct VerifyOptions<'a> {
    pub expected_iss: Option<&'a str>,
    pub expected_aud: Option<&'a str>,
    pub now: i64,
    pub skew_secs: i64,
}

pub const DEFAULT_SKEW_SECS: i64 = 60;

pub fn verify(
    bytes: &[u8],
    key: &VerifyingKey,
    opts: &VerifyOptions,
) -> Result<ArkavoClaims, CwtError> {
    // RFC 8392 §6: strict require the CWT CBOR tag #6.61 around the
    // COSE_Sign1. Untagged input is rejected.
    let inner = strip_cwt_tag(bytes)?;
    let sign1 = coset::CoseSign1::from_slice(inner).map_err(|_| CwtError::Malformed)?;

    // Strictness: alg MUST be ES256 in the PROTECTED header.
    match sign1.protected.header.alg {
        Some(coset::Algorithm::Assigned(coset::iana::Algorithm::ES256)) => {}
        _ => return Err(CwtError::UnsupportedAlg),
    }

    // Verify signature.
    sign1
        .verify_signature(b"", |sig_bytes, to_verify| {
            let sig = Signature::from_slice(sig_bytes).map_err(|_| ())?;
            key.verify(to_verify, &sig).map_err(|_| ())
        })
        .map_err(|_| CwtError::InvalidSignature)?;

    // Decode payload (borrowed from sign1, no clone).
    let payload = sign1.payload.as_ref().ok_or(CwtError::Malformed)?;
    let claims = claims_from_cbor(payload)?;

    // iss check.
    if let Some(want) = opts.expected_iss {
        if claims.iss != want {
            return Err(CwtError::IssuerMismatch);
        }
    }

    // aud check.
    if let Some(want) = opts.expected_aud {
        let matches_aud = match &claims.aud {
            Audience::Single(s) => s == want,
            Audience::Multiple(v) => v.iter().any(|s| s == want),
        };
        if !matches_aud {
            return Err(CwtError::AudienceMismatch);
        }
    }

    // Reject internally-inconsistent lifetimes (a well-formed issuer never mints
    // exp < iat; rejecting closes a class of token-forgery / clock-skew shenanigans).
    if claims.iat > claims.exp {
        return Err(CwtError::Malformed);
    }

    // exp / iat with ±skew.
    if claims.exp <= opts.now - opts.skew_secs {
        return Err(CwtError::Expired);
    }
    if claims.iat > opts.now + opts.skew_secs {
        return Err(CwtError::NotYetValid);
    }

    Ok(claims)
}

pub fn encode_for_header(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode_from_header(s: &str) -> Result<Vec<u8>, CwtError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| CwtError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;

    fn test_keypair() -> (SigningKey, p256::ecdsa::VerifyingKey) {
        let sk = SigningKey::random(&mut OsRng);
        let vk = *sk.verifying_key();
        (sk, vk)
    }

    fn test_kid() -> Vec<u8> {
        b"test-kid".to_vec()
    }

    #[test]
    fn mint_produces_parseable_cose_sign1() {
        let (sk, _vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let bytes = mint(&claims, &sk, &test_kid()).expect("mint");
        // Strip the CWT tag and decode the COSE_Sign1 envelope.
        let inner = strip_cwt_tag(&bytes).expect("CWT tag");
        let sign1 = coset::CoseSign1::from_slice(inner).expect("parse COSE_Sign1");
        assert_eq!(
            sign1.protected.header.alg,
            Some(coset::Algorithm::Assigned(coset::iana::Algorithm::ES256))
        );
        assert_eq!(sign1.protected.header.key_id, test_kid());
        assert!(sign1.payload.is_some());
    }

    #[test]
    fn mint_payload_contains_expected_claims() {
        let (sk, _vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let bytes = mint(&claims, &sk, &test_kid()).expect("mint");
        let sign1 = coset::CoseSign1::from_slice(strip_cwt_tag(&bytes).unwrap()).unwrap();
        let payload_bytes = sign1.payload.unwrap();
        let decoded = claims_from_cbor(&payload_bytes).expect("decode payload");
        assert_eq!(decoded.iss, "iss-1");
        assert_eq!(decoded.sub, "sub-1");
    }

    #[test]
    fn cwt_error_display() {
        assert_eq!(
            CwtError::Malformed.to_string(),
            "malformed COSE_Sign1 or CBOR"
        );
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
    fn cbor_roundtrip_arkavo_patreon_consumer_claim() {
        let snap = ArkavoPatreon {
            role: "consumer".into(),
            patreon_user_id: "patreon-user-42".into(),
            campaign_id: None,
            memberships: vec![
                ArkavoPatreonMembership {
                    campaign_id: "camp-1".into(),
                    patron_status: Some("active_patron".into()),
                    tier_ids: vec!["tier-gold".into(), "tier-vip".into()],
                    tier_slugs: vec!["gold".into(), "vip".into()],
                },
                ArkavoPatreonMembership {
                    campaign_id: "camp-2".into(),
                    patron_status: Some("former_patron".into()),
                    tier_ids: vec![],
                    tier_slugs: vec![],
                },
            ],
            verified_at: 1_700_000_000,
            cache_expires_at: 1_700_000_300,
        };
        let mut c = ArkavoClaims::oidc_access("iss-1", "arkavo:abc", "opentdf", 1);
        c = c.with_arkavo_patreon(snap.clone());
        let bytes = claims_to_cbor(&c).expect("encode");
        let decoded = claims_from_cbor(&bytes).expect("decode");
        assert_eq!(decoded.custom.arkavo_patreon, Some(snap));
    }

    #[test]
    fn cbor_roundtrip_arkavo_patreon_creator_claim() {
        let snap = ArkavoPatreon {
            role: "creator".into(),
            patreon_user_id: "patreon-user-7".into(),
            campaign_id: Some("camp-9".into()),
            memberships: vec![],
            verified_at: 1_700_000_000,
            cache_expires_at: 1_700_000_300,
        };
        let mut c = ArkavoClaims::oidc_access("iss-1", "arkavo:creator", "opentdf", 1);
        c = c.with_arkavo_patreon(snap.clone());
        let bytes = claims_to_cbor(&c).expect("encode");
        let decoded = claims_from_cbor(&bytes).expect("decode");
        assert_eq!(decoded.custom.arkavo_patreon, Some(snap));
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
        assert!(
            matches!(result, Err(CwtError::Malformed)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn cbor_roundtrip_audience_multiple() {
        let mut c = ArkavoClaims::auth("iss-1", "sub-1", 1);
        c.aud = Audience::Multiple(vec!["a".into(), "b".into()]);
        let bytes = claims_to_cbor(&c).expect("encode");
        let decoded = claims_from_cbor(&bytes).expect("decode");
        match decoded.aud {
            Audience::Multiple(v) => assert_eq!(v, vec!["a".to_string(), "b".to_string()]),
            other => panic!("expected Multiple, got {:?}", other),
        }
    }

    #[test]
    fn cbor_decode_rejects_empty_audience_multiple() {
        // Hand-craft a minimal claims map with aud = empty array.
        // Map(6 entries): {1: "i", 2: "s", 3: [], 4: 0, 6: 0, 7: <16 zero bytes>}
        let mut bytes = vec![
            0xa6, // map(6)
            0x01, 0x61, b'i', // 1: "i"
            0x02, 0x61, b's', // 2: "s"
            0x03, 0x80, // 3: []  (empty array)
            0x04, 0x00, // 4: 0
            0x06, 0x00, // 6: 0
            0x07, 0x50, // 7: bstr(16) follows
        ];
        bytes.extend_from_slice(&[0u8; 16]);
        let result = claims_from_cbor(&bytes);
        assert!(
            matches!(result, Err(CwtError::Malformed)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn cbor_decode_rejects_oversize_exp() {
        // Hand-craft minimal map with exp = i64::MAX + 1 (which is 2^63).
        // CBOR encoding of 2^63: uint major type (0x1b) + 8 bytes 0x80 00 00 00 00 00 00 00
        let mut bytes = vec![
            0xa6, // map(6)
            0x01, 0x61, b'i', 0x02, 0x61, b's', 0x03, 0x61, b'a', // aud: "a"
            0x04, 0x1b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exp: 2^63
            0x06, 0x00, // iat: 0
            0x07, 0x50, // cti: 16 bytes
        ];
        bytes.extend_from_slice(&[0u8; 16]);
        let result = claims_from_cbor(&bytes);
        assert!(
            matches!(result, Err(CwtError::Malformed)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn verify_roundtrip_succeeds() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();

        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            now: claims.iat + 10,
            skew_secs: 60,
        };
        let decoded = verify(&bytes, &vk, &opts).expect("verify");
        assert_eq!(decoded.sub, "sub-1");
    }

    #[test]
    fn mint_emits_cwt_cbor_tag_61() {
        let (sk, _vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let bytes = mint(&claims, &sk, &test_kid()).expect("mint");
        // RFC 8392 §6: tag 61 encodes as [0xD8, 0x3D] (major-6 + uint8(61)).
        assert_eq!(&bytes[..2], &[0xD8, 0x3D]);
    }

    #[test]
    fn verify_rejects_untagged_cose_sign1() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let tagged = mint(&claims, &sk, &test_kid()).unwrap();
        // Strip the tag -> bare COSE_Sign1; verifier must reject.
        let untagged = &tagged[CWT_TAG_PREFIX.len()..];

        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            now: claims.iat + 10,
            skew_secs: 60,
        };
        let result = verify(untagged, &vk, &opts);
        assert!(
            matches!(result, Err(CwtError::Malformed)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (sk, _vk) = test_keypair();
        let (_sk2, vk2) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();

        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            now: claims.iat + 10,
            skew_secs: 60,
        };
        let result = verify(&bytes, &vk2, &opts);
        assert!(matches!(result, Err(CwtError::InvalidSignature)));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let mut bytes = mint(&claims, &sk, &test_kid()).unwrap();
        // Flip a bit somewhere in the middle (likely in the payload).
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;

        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            now: claims.iat + 10,
            skew_secs: 60,
        };
        let result = verify(&bytes, &vk, &opts);
        assert!(matches!(
            result,
            Err(CwtError::InvalidSignature) | Err(CwtError::Malformed)
        ));
    }

    #[test]
    fn verify_rejects_non_es256_alg() {
        let (sk, vk) = test_keypair();
        // Manually build a COSE_Sign1 with alg=ES384 but still ES256-signed,
        // simulating an attacker swapping the alg field.
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let payload = claims_to_cbor(&claims).unwrap();

        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES384)
            .key_id(test_kid())
            .build();

        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |to_sign| {
                let sig: p256::ecdsa::Signature = sk.sign(to_sign);
                sig.to_bytes().to_vec()
            })
            .build();
        let mut bytes = CWT_TAG_PREFIX.to_vec();
        bytes.extend_from_slice(&sign1.to_vec().unwrap());

        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            now: claims.iat + 10,
            skew_secs: 60,
        };
        let result = verify(&bytes, &vk, &opts);
        assert!(
            matches!(result, Err(CwtError::UnsupportedAlg)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn verify_rejects_missing_alg() {
        // Build a COSE_Sign1 with NO algorithm in protected header.
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let payload = claims_to_cbor(&claims).unwrap();
        let (sk, vk) = test_keypair();

        let protected = coset::HeaderBuilder::new().key_id(test_kid()).build();

        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |to_sign| {
                let sig: p256::ecdsa::Signature = sk.sign(to_sign);
                sig.to_bytes().to_vec()
            })
            .build();
        let mut bytes = CWT_TAG_PREFIX.to_vec();
        bytes.extend_from_slice(&sign1.to_vec().unwrap());

        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            now: claims.iat + 10,
            skew_secs: 60,
        };
        let result = verify(&bytes, &vk, &opts);
        assert!(
            matches!(result, Err(CwtError::UnsupportedAlg)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn verify_rejects_expired() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();

        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            // now well past exp + skew
            now: claims.exp + 120,
            skew_secs: 60,
        };
        let result = verify(&bytes, &vk, &opts);
        assert!(matches!(result, Err(CwtError::Expired)), "got {:?}", result);
    }

    #[test]
    fn verify_rejects_not_yet_valid() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();

        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            // now before iat by more than skew
            now: claims.iat - 120,
            skew_secs: 60,
        };
        let result = verify(&bytes, &vk, &opts);
        assert!(
            matches!(result, Err(CwtError::NotYetValid)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn verify_accepts_within_skew_window() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();

        // now is 30s before iat: within ±60 skew, accepted.
        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            now: claims.iat - 30,
            skew_secs: 60,
        };
        verify(&bytes, &vk, &opts).expect("verify within skew");
    }

    #[test]
    fn verify_rejects_iss_mismatch() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();
        let opts = VerifyOptions {
            expected_iss: Some("iss-other"),
            expected_aud: None,
            now: claims.iat + 10,
            skew_secs: 60,
        };
        assert!(matches!(
            verify(&bytes, &vk, &opts),
            Err(CwtError::IssuerMismatch)
        ));
    }

    #[test]
    fn verify_rejects_aud_mismatch() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();
        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: Some("other-audience"),
            now: claims.iat + 10,
            skew_secs: 60,
        };
        assert!(matches!(
            verify(&bytes, &vk, &opts),
            Err(CwtError::AudienceMismatch)
        ));
    }

    #[test]
    fn verify_accepts_aud_match_against_arkavo() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();
        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: Some("arkavo"),
            now: claims.iat + 10,
            skew_secs: 60,
        };
        verify(&bytes, &vk, &opts).expect("verify");
    }

    fn sample_cose_key() -> coset::CoseKey {
        let (_, vk) = test_keypair();
        cose_key_from_p256_verifying_key(&vk, b"sample-kid")
    }

    #[test]
    fn cnf_from_passkey_uses_credential_id_as_kid() {
        // Smoke test only: confirms that the Cnf struct correctly stores the
        // credential_id as kid. Full WebAuthn ceremony coverage (calling
        // cnf_from_passkey with a real Passkey) is exercised by integration
        // tests in later tasks.
        let cred_id: Vec<u8> = b"test-credential-id".to_vec();
        let cose_key = sample_cose_key();
        let cnf = Cnf {
            cose_key,
            kid: cred_id.clone(),
        };
        assert_eq!(cnf.kid, cred_id);
    }

    #[test]
    fn mint_with_cnf_roundtrips() {
        let (sk, vk) = test_keypair();
        let cose_key = sample_cose_key();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1).with_cnf(Cnf {
            cose_key: cose_key.clone(),
            kid: b"cred-id".to_vec(),
        });
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();

        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            now: claims.iat + 10,
            skew_secs: 60,
        };
        let decoded = verify(&bytes, &vk, &opts).expect("verify");
        let decoded_cnf = decoded.cnf.expect("cnf present");
        assert_eq!(decoded_cnf.kid, b"cred-id".to_vec());
        // CoseKey roundtrip: compare via CBOR serialization.
        use coset::AsCborValue;
        let a = decoded_cnf.cose_key.clone().to_cbor_value().unwrap();
        let b = cose_key.clone().to_cbor_value().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn without_cnf_omits_cnf_from_payload() {
        let (sk, _vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1)
            .with_cnf(Cnf {
                cose_key: sample_cose_key(),
                kid: b"x".to_vec(),
            })
            .without_cnf();
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();
        let sign1 = coset::CoseSign1::from_slice(strip_cwt_tag(&bytes).unwrap()).unwrap();
        let decoded = claims_from_cbor(sign1.payload.as_ref().unwrap()).unwrap();
        assert!(decoded.cnf.is_none());
    }

    #[test]
    fn encode_for_header_is_unpadded_base64url() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();
        let encoded = encode_for_header(&bytes);
        // No padding, no '+' or '/' chars.
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));

        let decoded = decode_from_header(&encoded).expect("decode");
        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            now: claims.iat + 10,
            skew_secs: 60,
        };
        verify(&decoded, &vk, &opts).expect("verify roundtrip via header transport");
    }

    #[test]
    fn decode_from_header_rejects_invalid_base64() {
        assert!(matches!(
            decode_from_header("!!!not-base64!!!"),
            Err(CwtError::Malformed)
        ));
    }

    #[test]
    fn cnf_from_app_attest_constructs_cnf() {
        // Mock device binding's public key as raw uncompressed P-256 (65 bytes: 0x04 || x || y).
        let (_sk, vk) = test_keypair();
        let public_key_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
        let device_id = b"app-attest-key-id".to_vec();

        let cnf = cnf_from_app_attest(&public_key_bytes, &device_id).expect("build cnf");
        assert_eq!(cnf.kid, device_id);
    }

    #[test]
    fn cnf_from_app_attest_rejects_invalid_pubkey() {
        let cnf = cnf_from_app_attest(&[0xde, 0xad, 0xbe, 0xef], b"id");
        assert!(matches!(cnf, Err(CwtError::Malformed)));
    }

    #[test]
    fn agent_claims_round_trip_act_npe_cnf() {
        let (sk, vk) = test_keypair();
        let kid = test_kid();
        let npe = ArkavoNpe {
            npe_type: "agent".into(),
            class: None,
            attestation_expiry: None,
            device_id: None,
            delegation_id: Some("deleg-1".into()),
            depth: Some(0),
            chain: Some(vec![]),
        };
        let claims = ArkavoClaims::agent(
            "https://identity.arkavo.net",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            vec![
                "https://platform.arkavo.net".into(),
                "https://kas.arkavo.net".into(),
            ],
            15,
        )
        .with_act(vec![Actor {
            sub: "https://kg.arkavo.net".into(),
        }])
        .with_arkavo_npe(npe.clone())
        .with_cnf(cnf_from_ed25519(&[7u8; 32], b"agent-kid"))
        .with_arkavo_roles(vec!["agent".into()])
        .with_arkavo_entitlements(vec!["https://arkavo.ai/attr/action/value/read".into()]);

        assert_eq!(claims.exp - claims.iat, 15 * 60);
        let bytes = mint(&claims, &sk, &kid).unwrap();
        let opts = VerifyOptions {
            expected_iss: Some("https://identity.arkavo.net"),
            expected_aud: Some("https://kas.arkavo.net"),
            now: claims.iat + 1,
            skew_secs: DEFAULT_SKEW_SECS,
        };
        let back = verify(&bytes, &vk, &opts).unwrap();
        assert_eq!(back.custom.act.unwrap()[0].sub, "https://kg.arkavo.net");
        let got = back.custom.arkavo_npe.unwrap();
        assert_eq!(got.npe_type, "agent");
        assert_eq!(got.delegation_id.as_deref(), Some("deleg-1"));
        assert_eq!(got.depth, Some(0));
        let cnf = back.cnf.unwrap();
        assert_eq!(cnf.kid, b"agent-kid");
        assert_eq!(
            cnf.cose_key.kty,
            coset::KeyType::Assigned(coset::iana::KeyType::OKP)
        );
        let crv = cnf
            .cose_key
            .params
            .iter()
            .find(|(l, _)| *l == coset::Label::Int(-1))
            .map(|(_, v)| v.clone())
            .expect("crv param present");
        assert_eq!(crv, Value::from(coset::iana::EllipticCurve::Ed25519 as u64));
        let x = cnf
            .cose_key
            .params
            .iter()
            .find(|(l, _)| *l == coset::Label::Int(-2))
            .map(|(_, v)| v.clone())
            .expect("x param present");
        assert_eq!(x, Value::Bytes(vec![7u8; 32]));
    }

    #[test]
    fn agent_claims_never_exceed_15_minutes() {
        let c = ArkavoClaims::agent("i", "did:key:z", vec!["a".into()], 60);
        assert_eq!(c.exp - c.iat, 15 * 60);
    }

    #[test]
    fn device_npe_round_trip() {
        let (sk, vk) = test_keypair();
        let kid = test_kid();
        let claims =
            ArkavoClaims::auth("https://identity.arkavo.net", "u", 1).with_arkavo_npe(ArkavoNpe {
                npe_type: "device".into(),
                class: Some("attested".into()),
                attestation_expiry: Some(1_800_000_000),
                device_id: Some("keyid".into()),
                delegation_id: None,
                depth: None,
                chain: None,
            });
        let bytes = mint(&claims, &sk, &kid).unwrap();
        let opts = VerifyOptions {
            expected_iss: None,
            expected_aud: None,
            now: claims.iat,
            skew_secs: 60,
        };
        let back = verify(&bytes, &vk, &opts)
            .unwrap()
            .custom
            .arkavo_npe
            .unwrap();
        assert_eq!(back.class.as_deref(), Some("attested"));
        assert_eq!(back.attestation_expiry, Some(1_800_000_000));
    }

    /// Hand-craft a minimal well-formed claims map (iss/sub/aud/exp/iat/cti)
    /// plus an `arkavo_npe` entry set to `npe_value`, so an out-of-range or
    /// wrongly-typed field can be injected without going through the
    /// type-safe `ArkavoNpe`/`claims_to_cbor` path.
    fn claims_bytes_with_npe(npe_value: Value) -> Vec<u8> {
        let entries = vec![
            (Value::Integer(1.into()), Value::Text("iss-1".into())),
            (Value::Integer(2.into()), Value::Text("sub-1".into())),
            (Value::Integer(3.into()), Value::Text("aud-1".into())),
            (Value::Integer(4.into()), Value::Integer(1.into())),
            (Value::Integer(6.into()), Value::Integer(0.into())),
            (Value::Integer(7.into()), Value::Bytes(vec![0u8; 16])),
            (Value::Text("arkavo_npe".into()), npe_value),
        ];
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut bytes).expect("encode");
        bytes
    }

    #[test]
    fn npe_depth_out_of_range_is_malformed() {
        let too_big = Value::Map(vec![
            (Value::Text("type".into()), Value::Text("agent".into())),
            (Value::Text("depth".into()), Value::Integer(256.into())),
        ]);
        let result = claims_from_cbor(&claims_bytes_with_npe(too_big));
        assert!(
            matches!(result, Err(CwtError::Malformed)),
            "got {:?}",
            result
        );

        let negative = Value::Map(vec![
            (Value::Text("type".into()), Value::Text("agent".into())),
            (Value::Text("depth".into()), Value::Integer((-1).into())),
        ]);
        let result = claims_from_cbor(&claims_bytes_with_npe(negative));
        assert!(
            matches!(result, Err(CwtError::Malformed)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn npe_attestation_expiry_out_of_range_is_malformed() {
        // i64::MAX + 1, as an i128 — fits in CBOR's u64-backed uint range but
        // overflows i64::try_from.
        let too_big = i128::from(i64::MAX) + 1;
        let npe = Value::Map(vec![
            (Value::Text("type".into()), Value::Text("device".into())),
            (
                Value::Text("attestation_expiry".into()),
                Value::Integer(Integer::try_from(too_big).expect("fits CBOR uint range")),
            ),
        ]);
        let result = claims_from_cbor(&claims_bytes_with_npe(npe));
        assert!(
            matches!(result, Err(CwtError::Malformed)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn npe_chain_non_text_is_malformed() {
        let npe = Value::Map(vec![
            (Value::Text("type".into()), Value::Text("agent".into())),
            (
                Value::Text("chain".into()),
                Value::Array(vec![Value::Text("ok".into()), Value::Integer(1.into())]),
            ),
        ]);
        let result = claims_from_cbor(&claims_bytes_with_npe(npe));
        assert!(
            matches!(result, Err(CwtError::Malformed)),
            "got {:?}",
            result
        );
    }
}
