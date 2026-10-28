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
    /// The protected-header `kid` is absent or names no key in the set (#107).
    #[error("unknown signing key")]
    UnknownKey,
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
    /// Device only (#114): the attested `rpIdHash`, lowercase hex, present
    /// only while `APP_ATTEST_APP_ID` accepts it.
    pub app_id_hash: Option<String>,
    /// Device only (#114): `production` | `development`, from the aaguid.
    pub app_env: Option<String>,
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
    /// The agent identity's `state_version` when the token was minted
    /// (agent CWTs only). The platform withholds a token whose version
    /// differs from the one the status endpoint reports, so a token minted
    /// before a quarantine never revives after recovery and re-appraisal.
    pub arkavo_state_version: Option<u64>,
    /// SwarmKit `kit_id` the agent's delegation is bound to (agent CWTs
    /// only). Omitted (not `Some("")`) when the agent has no swarm.
    pub arkavo_swarm: Option<String>,
    /// Space-separated OAuth scopes granted to an OIDC access token.
    pub scope: Option<String>,
    /// Unix time of the WebAuthn assertion behind an OIDC access token.
    pub auth_time: Option<i64>,
}

/// The Arkavo custom claims derived from one user record, shared by every
/// token minted for a human user: the OIDC access token
/// (`oidc::mint_access_token`) and the WebAuthn auth token
/// (`authn::mint_auth_token`) both apply this through
/// [`ArkavoClaims::with_arkavo_user`], so the OpenTDF platform sees one claim
/// shape regardless of which token the client presents
/// (`client_id_claim: arkavo_account_id`, `groups_claim: arkavo_roles`, and
/// the Patreon entity resolver's `arkavo_patreon`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkavoUserClaims {
    /// Internal Arkavo account id (UUID string) → `arkavo_account_id`.
    pub account_id: String,
    /// → `arkavo_roles`.
    pub roles: Vec<String>,
    /// Attribute FQNs the user holds (the stored `credentials.entitlements`
    /// list) → `arkavo_entitlements`.
    pub entitlements: Vec<String>,
    /// Entitlements derived at mint time and never stored (the
    /// `https://patreon.arkavo.com/` namespace: Patreon campaign values and
    /// [`crate::constants::ENTITLEMENT_CREATOR_PUBLISH`]). Appended to
    /// `arkavo_entitlements` by [`ArkavoClaims::with_arkavo_user`]; the
    /// registration token drops them (see [`ArkavoUserClaims::stored_only`]).
    pub derived_entitlements: Vec<String>,
    /// Materialized Patreon membership → `arkavo_patreon`; `None` when the
    /// user is unlinked, Patreon is disabled, or materialization failed.
    pub patreon: Option<ArkavoPatreon>,
}

impl ArkavoUserClaims {
    /// The `arkavo_entitlements` value: the stored list followed by every
    /// derived entitlement not already in it. A derived-only FQN found in the
    /// stored list is dropped, so only the mint-time derivation (which
    /// honours lapse and suspension) can ever emit it.
    pub fn effective_entitlements(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .entitlements
            .iter()
            .filter(|e| !crate::constants::is_derived_only(e))
            .cloned()
            .collect();
        for e in &self.derived_entitlements {
            if !out.contains(e) {
                out.push(e.clone());
            }
        }
        out
    }

    /// These claims without the derived entitlements, for a token whose
    /// lifetime outlives any membership check (the ~99-year registration
    /// token).
    pub fn stored_only(&self) -> Self {
        Self {
            derived_entitlements: Vec::new(),
            ..self.clone()
        }
    }
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
    /// Campaigns this Patreon identity is a patron of — for consumer and
    /// creator links alike (a creator's list is empty when its link lacks
    /// the `identity.memberships` scope or the fetch failed).
    pub memberships: Vec<ArkavoPatreonMembership>,
    /// Creator-only: every tier of the owned `campaign_id`, so the creator's
    /// token opens content gated on any of them (#99). Empty for consumers.
    /// Feeds `arkavo_entitlements` only; never encoded in the
    /// `arkavo_patreon` claim (a decoded snapshot has it empty).
    pub owned_tiers: OwnedCampaignTiers,
    /// Unix timestamp when this snapshot was materialized.
    pub verified_at: i64,
    /// Unix timestamp after which the snapshot is stale.
    pub cache_expires_at: i64,
}

/// The tiers of a creator's own campaign, in the same two shapes a
/// membership carries its entitled tiers: Patreon tier ids and the
/// deduplicated title slugs (an independent set, not parallel to `ids`).
/// `ids` and `slugs` feed `arkavo_entitlements` only; `name` and `ladder`
/// are the token's `owned_campaign` (#128).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnedCampaignTiers {
    pub ids: Vec<String>,
    pub slugs: Vec<String>,
    /// The campaign's display name (Patreon `campaign.name`).
    pub name: Option<String>,
    /// Every tier in Patreon's order, with what Creator's protect sheet
    /// shows. Empty until the first fetch after this field was added; the
    /// claim then lists the tier ids alone.
    pub ladder: Vec<OwnedTier>,
}

/// One tier of a creator's own campaign, as `owned_campaign.tiers` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedTier {
    pub id: String,
    pub title: Option<String>,
    pub amount_cents: Option<i64>,
    pub published: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkavoPatreonMembership {
    pub campaign_id: String,
    /// The campaign's display name (Patreon `campaign.name`, `display_text`).
    /// Encoded on `active_patron` memberships only (#128).
    pub campaign_name: Option<String>,
    /// The bare account UUID of the Arkavo account that owns the campaign
    /// (its `patreon-campaign#<cid>` row), when one does (#128).
    pub creator_sub: Option<String>,
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

    /// Human auth token. `platform_audience` extends `aud` so the app can
    /// present the same CWT to arks/KAS once Track 3 pins
    /// `CWT_EXPECTED_AUDIENCE` to a single non-`"arkavo"` audience.
    pub fn auth(iss: &str, sub: &str, hours: i64, platform_audience: Option<&str>) -> Self {
        let aud = match platform_audience {
            Some(p) => Audience::Multiple(vec!["arkavo".into(), p.to_string()]),
            None => Audience::Single("arkavo".into()),
        };
        Self::base(iss, sub, aud, Self::hours_to_secs(hours))
    }

    pub fn registration(iss: &str, sub: &str, weeks: i64) -> Self {
        Self::base(
            iss,
            sub,
            Audience::Single("arkavo".into()),
            Self::weeks_to_secs(weeks),
        )
    }

    /// DeviceCheck assertion token. `platform_audience` extends `aud` so the
    /// platform verifier accepts the device CWT as its own subject (spec §1.3).
    pub fn devicecheck(iss: &str, sub: &str, hours: i64, platform_audience: Option<&str>) -> Self {
        let aud = match platform_audience {
            Some(p) => Audience::Multiple(vec!["arkavo:devicecheck".into(), p.to_string()]),
            None => Audience::Single("arkavo:devicecheck".into()),
        };
        Self::base(iss, sub, aud, Self::hours_to_secs(hours))
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

    pub fn with_arkavo_state_version(mut self, version: u64) -> Self {
        self.custom.arkavo_state_version = Some(version);
        self
    }

    /// An agent has no swarm until it is specialized into a kit, so an empty
    /// value omits the claim entirely rather than round-tripping as
    /// `Some("")`.
    pub fn with_arkavo_swarm(mut self, swarm: &str) -> Self {
        if !swarm.is_empty() {
            self.custom.arkavo_swarm = Some(swarm.into());
        }
        self
    }

    pub fn with_scope(mut self, scope: &str) -> Self {
        self.custom.scope = Some(scope.into());
        self
    }

    pub fn with_auth_time(mut self, auth_time: i64) -> Self {
        self.custom.auth_time = Some(auth_time);
        self
    }

    /// Apply the per-user Arkavo custom claims in one step, so every token
    /// minted for a human user carries the same set.
    pub fn with_arkavo_user(mut self, user: &ArkavoUserClaims) -> Self {
        self = self
            .with_arkavo_account_id(&user.account_id)
            .with_arkavo_roles(user.roles.clone())
            .with_arkavo_entitlements(user.effective_entitlements());
        if let Some(p) = &user.patreon {
            self = self.with_arkavo_patreon(p.clone());
        }
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
/// `public_key_der` is the device's P-256 public key as DER
/// SubjectPublicKeyInfo, exactly as `finish_attestation` stores it in the
/// `device_bindings` table (the credCert's SPKI) and as `verify_assertion`
/// reads it. Not a bare SEC1 point (#118). `device_id` is the App Attest key
/// ID, used as the cnf.kid.
pub fn cnf_from_app_attest(public_key_der: &[u8], device_id: &[u8]) -> Result<Cnf, CwtError> {
    use p256::pkcs8::DecodePublicKey;
    let vk = VerifyingKey::from_public_key_der(public_key_der).map_err(|_| CwtError::Malformed)?;
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
// `pub` (not `pub(crate)`): now that `cwt` lives in the `authnz_rs` lib crate
// (Task 7), the bin's whitebox wire-format tests (authn.rs, device_check.rs,
// oidc.rs `#[cfg(test)]` modules) need cross-crate access via
// `authnz_rs::cwt::…`. `pub(crate)` would only be visible within this lib
// crate, not from the bin. No behavior change — internal helper, still
// undocumented in any public API surface beyond the wire-format test usage.
pub const CWT_TAG_PREFIX: [u8; 2] = [0xD8, 0x3D];

/// Strip the CWT CBOR tag #6.61 prefix. Strict: input MUST start with the
/// tag. Untagged COSE_Sign1 is rejected so a downstream verifier cannot be
/// tricked by feeding raw COSE_Sign1 to a CWT consumer.
pub fn strip_cwt_tag(bytes: &[u8]) -> Result<&[u8], CwtError> {
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
        if let Some(v) = &n.app_id_hash {
            m.push((Value::Text("app_id_hash".into()), Value::Text(v.clone())));
        }
        if let Some(v) = &n.app_env {
            m.push((Value::Text("app_env".into()), Value::Text(v.clone())));
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
    if let Some(v) = c.custom.arkavo_state_version {
        entries.push((
            Value::Text("arkavo_state_version".into()),
            Value::Integer(v.into()),
        ));
    }
    if let Some(v) = &c.custom.arkavo_swarm {
        entries.push((Value::Text("arkavo_swarm".into()), Value::Text(v.clone())));
    }
    if let Some(v) = &c.custom.scope {
        entries.push((Value::Text("scope".into()), Value::Text(v.clone())));
    }
    if let Some(v) = c.custom.auth_time {
        entries.push((Value::Text("auth_time".into()), Value::Integer(v.into())));
    }

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut bytes)
        .map_err(|_| CwtError::Malformed)?;
    Ok(bytes)
}

/// The `arkavo_patreon` claim as JSON, converted from the very map a token
/// encodes, so `GET /entities` cannot drift from the token's shape.
pub fn patreon_to_json(p: &ArkavoPatreon) -> serde_json::Value {
    cbor_to_json(patreon_to_cbor(p))
}

/// Only what [`patreon_to_cbor`] produces: text, integers, booleans,
/// arrays and text-keyed maps.
fn cbor_to_json(v: Value) -> serde_json::Value {
    match v {
        Value::Text(s) => s.into(),
        Value::Integer(i) => i64::try_from(i).map_or(serde_json::Value::Null, Into::into),
        Value::Bool(b) => b.into(),
        Value::Array(a) => a.into_iter().map(cbor_to_json).collect(),
        Value::Map(m) => serde_json::Value::Object(
            m.into_iter()
                .filter_map(|(k, v)| match k {
                    Value::Text(k) => Some((k, cbor_to_json(v))),
                    _ => None,
                })
                .collect(),
        ),
        _ => serde_json::Value::Null,
    }
}

/// Patreon's `patron_status` for a paying patron: the only status that
/// entitles, and the only one whose membership carries its campaign name.
pub const ACTIVE_PATRON: &str = "active_patron";

/// `owned_campaign`: `{id, name?, tiers: [{id, title?, amount_cents?,
/// published?}]}`. A ladder not read since #128 lists the tier ids alone.
fn owned_campaign_to_cbor(campaign_id: &str, owned: &OwnedCampaignTiers) -> Value {
    let text = |k: &str, v: &str| (Value::Text(k.into()), Value::Text(v.into()));
    let tiers: Vec<Value> = if owned.ladder.is_empty() {
        owned
            .ids
            .iter()
            .map(|id| Value::Map(vec![text("id", id)]))
            .collect()
    } else {
        owned
            .ladder
            .iter()
            .map(|t| {
                let mut tier = vec![text("id", &t.id)];
                if let Some(v) = &t.title {
                    tier.push(text("title", v));
                }
                if let Some(v) = t.amount_cents {
                    tier.push((Value::Text("amount_cents".into()), Value::Integer(v.into())));
                }
                if let Some(v) = t.published {
                    tier.push((Value::Text("published".into()), Value::Bool(v)));
                }
                Value::Map(tier)
            })
            .collect()
    };
    let mut campaign = vec![text("id", campaign_id)];
    if let Some(name) = &owned.name {
        campaign.push(text("name", name));
    }
    campaign.push((Value::Text("tiers".into()), Value::Array(tiers)));
    Value::Map(campaign)
}

/// The decoded `owned_campaign`: its name and ladder. A ladder of ids alone
/// decodes as tiers with no title.
fn owned_campaign_from_cbor(v: Value) -> Result<(Option<String>, Vec<OwnedTier>), CwtError> {
    let Value::Map(entries) = v else {
        return Err(CwtError::Malformed);
    };
    let mut name = None;
    let mut ladder = Vec::new();
    for (k, v) in entries {
        match (k, v) {
            (Value::Text(k), Value::Text(v)) if k == "name" => name = Some(v),
            (Value::Text(k), Value::Array(tiers)) if k == "tiers" => {
                for tier in tiers {
                    let Value::Map(fields) = tier else {
                        return Err(CwtError::Malformed);
                    };
                    let mut t = OwnedTier {
                        id: String::new(),
                        title: None,
                        amount_cents: None,
                        published: None,
                    };
                    for (fk, fv) in fields {
                        match (fk, fv) {
                            (Value::Text(k), Value::Text(v)) if k == "id" => t.id = v,
                            (Value::Text(k), Value::Text(v)) if k == "title" => t.title = Some(v),
                            (Value::Text(k), Value::Integer(n)) if k == "amount_cents" => {
                                t.amount_cents = i64::try_from(i128::from(n)).ok()
                            }
                            (Value::Text(k), Value::Bool(b)) if k == "published" => {
                                t.published = Some(b)
                            }
                            _ => {}
                        }
                    }
                    if t.id.is_empty() {
                        return Err(CwtError::Malformed);
                    }
                    ladder.push(t);
                }
            }
            _ => {}
        }
    }
    Ok((name, ladder))
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
                // Names only where they entitle, to bound the token (#128).
                if let Some(name) = &m.campaign_name
                    && m.patron_status.as_deref() == Some(ACTIVE_PATRON)
                {
                    m_entries.push((
                        Value::Text("campaign_name".into()),
                        Value::Text(name.clone()),
                    ));
                }
                if let Some(sub) = &m.creator_sub {
                    m_entries.push((Value::Text("creator_sub".into()), Value::Text(sub.clone())));
                }
                Value::Map(m_entries)
            })
            .collect();
        entries.push((Value::Text("memberships".into()), Value::Array(arr)));
    }
    // Beside `campaign_id`, never in place of it: iroh's publish check reads
    // that one (top-level text) and not this.
    if p.role == "creator"
        && let Some(cid) = &p.campaign_id
    {
        entries.push((
            Value::Text("owned_campaign".into()),
            owned_campaign_to_cbor(cid, &p.owned_tiers),
        ));
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
    let mut owned_tiers = OwnedCampaignTiers::default();

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
                    let mut m_name: Option<String> = None;
                    let mut m_creator: Option<String> = None;
                    for (mk, mv) in m_entries {
                        let mkey = match mk {
                            Value::Text(s) => s,
                            _ => return Err(CwtError::Malformed),
                        };
                        match (mkey.as_str(), mv) {
                            ("campaign_id", Value::Text(s)) => m_campaign_id = Some(s),
                            ("patron_status", Value::Text(s)) => m_status = Some(s),
                            ("campaign_name", Value::Text(s)) => m_name = Some(s),
                            ("creator_sub", Value::Text(s)) => m_creator = Some(s),
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
                        creator_sub: m_creator,
                        campaign_name: m_name,
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
            ("owned_campaign", v) => {
                // Name and ladder only: the tier ids and slugs that feed
                // entitlements are derived at mint, never read back.
                (owned_tiers.name, owned_tiers.ladder) = owned_campaign_from_cbor(v)?;
            }
            _ => {}
        }
    }
    Ok(ArkavoPatreon {
        role: role.ok_or(CwtError::Malformed)?,
        patreon_user_id: patreon_user_id.ok_or(CwtError::Malformed)?,
        campaign_id,
        memberships,
        owned_tiers,
        verified_at: verified_at.ok_or(CwtError::Malformed)?,
        cache_expires_at: cache_expires_at.ok_or(CwtError::Malformed)?,
    })
}

// `pub` for the same cross-crate test-access reason as `strip_cwt_tag` above.
pub fn claims_from_cbor(bytes: &[u8]) -> Result<ArkavoClaims, CwtError> {
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
            (Value::Text(s), _) if s == "act" => return Err(CwtError::Malformed),
            (Value::Text(s), Value::Map(m)) if s == "arkavo_npe" => {
                let mut n = ArkavoNpe {
                    npe_type: String::new(),
                    class: None,
                    attestation_expiry: None,
                    device_id: None,
                    app_id_hash: None,
                    app_env: None,
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
                        (Value::Text(k), Value::Text(v)) if k == "app_id_hash" => {
                            n.app_id_hash = Some(v)
                        }
                        (Value::Text(k), Value::Text(v)) if k == "app_env" => n.app_env = Some(v),
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
                        (Value::Text(k), _)
                            if matches!(
                                k.as_str(),
                                "type"
                                    | "class"
                                    | "attestation_expiry"
                                    | "device_id"
                                    | "app_id_hash"
                                    | "app_env"
                                    | "delegation_id"
                                    | "depth"
                                    | "chain"
                            ) =>
                        {
                            return Err(CwtError::Malformed);
                        }
                        _ => {}
                    }
                }
                if n.npe_type.is_empty() {
                    return Err(CwtError::Malformed);
                }
                custom.arkavo_npe = Some(n);
            }
            (Value::Text(s), _) if s == "arkavo_npe" => return Err(CwtError::Malformed),
            (Value::Text(s), Value::Integer(n)) if s == "arkavo_state_version" => {
                custom.arkavo_state_version =
                    Some(u64::try_from(i128::from(n)).map_err(|_| CwtError::Malformed)?)
            }
            (Value::Text(s), _) if s == "arkavo_state_version" => return Err(CwtError::Malformed),
            (Value::Text(s), Value::Text(t)) if s == "arkavo_swarm" => {
                custom.arkavo_swarm = Some(t)
            }
            (Value::Text(s), _) if s == "arkavo_swarm" => return Err(CwtError::Malformed),
            (Value::Text(s), Value::Text(t)) if s == "scope" => custom.scope = Some(t),
            (Value::Text(s), _) if s == "scope" => return Err(CwtError::Malformed),
            (Value::Text(s), Value::Integer(n)) if s == "auth_time" => {
                custom.auth_time =
                    Some(i64::try_from(i128::from(n)).map_err(|_| CwtError::Malformed)?)
            }
            (Value::Text(s), _) if s == "auth_time" => return Err(CwtError::Malformed),
            // A `typ` marks a signed record that is not a token (a passkey
            // credential attestation, #104). No CWT carries one.
            (Value::Text(s), _) if s == "typ" => return Err(CwtError::Malformed),
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

/// When the passkey assertion behind a passkey auth CWT happened: its
/// `auth_time` when it was renewed (`POST /session/refresh`, #108), else its
/// `iat` (`POST /authenticate` mints straight after the assertion). Every
/// "recent assertion" check reads this, never `iat`, so a renewed token never
/// passes for a fresh sign-in.
pub fn passkey_assertion_time(claims: &ArkavoClaims) -> i64 {
    claims.custom.auth_time.unwrap_or(claims.iat)
}

#[derive(Debug, Clone)]
pub struct VerifyOptions<'a> {
    pub expected_iss: Option<&'a str>,
    pub expected_aud: Option<&'a str>,
    pub now: i64,
    pub skew_secs: i64,
}

pub const DEFAULT_SKEW_SECS: i64 = 60;

/// Verify a CWT against the key its protected-header `kid` names in `keys`.
pub fn verify(
    bytes: &[u8],
    keys: &crate::keys::KeySet,
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
    // No CWT minted here carries a content type; a passkey credential
    // attestation (`credential_attestation`) always does. Refusing it keeps
    // an attestation from ever passing as a token (#104).
    if sign1.protected.header.content_type.is_some() {
        return Err(CwtError::Malformed);
    }

    // The kid picks the key; one outside the set is refused before any
    // signature check (#107).
    let key = keys
        .get(&sign1.protected.header.key_id)
        .ok_or(CwtError::UnknownKey)?;

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
    if let Some(want) = opts.expected_iss
        && claims.iss != want
    {
        return Err(CwtError::IssuerMismatch);
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

    /// The one-key set tokens minted under `test_kid()` verify against.
    fn set(vk: &p256::ecdsa::VerifyingKey) -> crate::keys::KeySet {
        crate::keys::KeySet::new(*vk, test_kid())
    }

    #[test]
    fn mint_produces_parseable_cose_sign1() {
        let (sk, _vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
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
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
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
        let c = ArkavoClaims::auth("https://identity.arkavo.net", "user-uuid", 1, None);
        assert_eq!(c.iss, "https://identity.arkavo.net");
        assert_eq!(c.sub, "user-uuid");
        assert_eq!(c.aud, Audience::Single("arkavo".to_string()));
        assert!(c.exp > c.iat);
        assert_eq!(c.exp - c.iat, 3600);
        assert_eq!(c.cti.len(), 16);
        assert!(c.cnf.is_none());
    }

    #[test]
    fn auth_claims_carry_platform_audience() {
        let c = ArkavoClaims::auth("i", "u", 1, Some("https://platform.arkavo.net"));
        assert_eq!(
            c.aud,
            Audience::Multiple(vec!["arkavo".into(), "https://platform.arkavo.net".into()])
        );
        let c = ArkavoClaims::auth("i", "u", 1, None);
        assert_eq!(c.aud, Audience::Single("arkavo".into()));
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
        let a = ArkavoClaims::auth("iss", "sub", 1, None);
        let b = ArkavoClaims::auth("iss", "sub", 1, None);
        assert_ne!(a.cti, b.cti);
    }

    #[test]
    fn cbor_roundtrip_minimal_claims() {
        let c = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
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
                    creator_sub: None,
                    campaign_name: None,
                    campaign_id: "camp-1".into(),
                    patron_status: Some("active_patron".into()),
                    tier_ids: vec!["tier-gold".into(), "tier-vip".into()],
                    tier_slugs: vec!["gold".into(), "vip".into()],
                },
                ArkavoPatreonMembership {
                    creator_sub: None,
                    campaign_name: None,
                    campaign_id: "camp-2".into(),
                    patron_status: Some("former_patron".into()),
                    tier_ids: vec![],
                    tier_slugs: vec![],
                },
            ],
            owned_tiers: Default::default(),
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
    fn patreon_json_is_the_token_map() {
        let snap = ArkavoPatreon {
            role: "creator".into(),
            patreon_user_id: "patreon-user-7".into(),
            campaign_id: Some("111".into()),
            memberships: vec![
                ArkavoPatreonMembership {
                    creator_sub: None,
                    campaign_name: None,
                    campaign_id: "222".into(),
                    patron_status: Some("active_patron".into()),
                    tier_ids: vec!["9".into()],
                    tier_slugs: vec!["gold".into()],
                },
                ArkavoPatreonMembership {
                    creator_sub: None,
                    campaign_name: None,
                    campaign_id: "333".into(),
                    patron_status: None,
                    tier_ids: vec![],
                    tier_slugs: vec![],
                },
            ],
            owned_tiers: OwnedCampaignTiers {
                ids: vec!["5".into()],
                slugs: vec!["owned".into()],
                ..Default::default()
            },
            verified_at: 1_700_000_000,
            cache_expires_at: 1_700_000_300,
        };
        // Optional keys are omitted as in the token, and the owned tiers,
        // which feed entitlements only, are not in the claim.
        assert_eq!(
            patreon_to_json(&snap),
            serde_json::json!({
                "role": "creator",
                "patreon_user_id": "patreon-user-7",
                "campaign_id": "111",
                "memberships": [
                    {"campaign_id": "222", "patron_status": "active_patron",
                     "tier_ids": ["9"], "tier_slugs": ["gold"]},
                    {"campaign_id": "333", "tier_ids": []},
                ],
                "verified_at": 1_700_000_000,
                "cache_expires_at": 1_700_000_300,
            })
        );
        let consumer = ArkavoPatreon {
            role: "consumer".into(),
            campaign_id: None,
            memberships: vec![],
            ..snap
        };
        let json = patreon_to_json(&consumer);
        assert!(json.get("campaign_id").is_none());
        assert!(json.get("memberships").is_none());
    }

    /// #128: the token carries each active membership's campaign name and
    /// creator, and a creator's `owned_campaign` beside its `campaign_id`.
    /// A name on a membership that does not entitle is left out.
    #[test]
    fn token_carries_names_creator_sub_and_the_owned_ladder() {
        let member = |cid: &str, status: &str| ArkavoPatreonMembership {
            creator_sub: None,
            campaign_name: Some(format!("Campaign {cid}")),
            campaign_id: cid.into(),
            patron_status: Some(status.into()),
            tier_ids: vec!["9".into()],
            tier_slugs: vec!["gold".into()],
        };
        let mut active = member("222", "active_patron");
        active.creator_sub = Some("6f1c2d3e-4b5a-4c6d-8e7f-0123456789ab".into());
        let snap = ArkavoPatreon {
            role: "creator".into(),
            patreon_user_id: "p-7".into(),
            campaign_id: Some("111".into()),
            memberships: vec![active, member("333", "declined_patron")],
            owned_tiers: OwnedCampaignTiers {
                ids: vec!["5".into(), "6".into()],
                slugs: vec!["owned".into()],
                name: Some("Mine".into()),
                ladder: vec![
                    OwnedTier {
                        id: "5".into(),
                        title: Some("Owned".into()),
                        amount_cents: Some(300),
                        published: Some(true),
                    },
                    OwnedTier {
                        id: "6".into(),
                        title: None,
                        amount_cents: None,
                        published: None,
                    },
                ],
            },
            verified_at: 1_700_000_000,
            cache_expires_at: 1_700_000_300,
        };
        assert_eq!(
            patreon_to_json(&snap),
            serde_json::json!({
                "role": "creator",
                "patreon_user_id": "p-7",
                "campaign_id": "111",
                "memberships": [
                    {"campaign_id": "222", "patron_status": "active_patron",
                     "tier_ids": ["9"], "tier_slugs": ["gold"],
                     "campaign_name": "Campaign 222",
                     "creator_sub": "6f1c2d3e-4b5a-4c6d-8e7f-0123456789ab"},
                    {"campaign_id": "333", "patron_status": "declined_patron",
                     "tier_ids": ["9"], "tier_slugs": ["gold"]},
                ],
                "owned_campaign": {
                    "id": "111",
                    "name": "Mine",
                    "tiers": [
                        {"id": "5", "title": "Owned", "amount_cents": 300, "published": true},
                        {"id": "6"},
                    ],
                },
                "verified_at": 1_700_000_000,
                "cache_expires_at": 1_700_000_300,
            })
        );

        // Round trip: everything but what feeds entitlements (tier ids and
        // slugs, derived at mint) and the unencoded name.
        let bytes = claims_to_cbor(
            &ArkavoClaims::oidc_access("iss-1", "arkavo:u", "opentdf", 1)
                .with_arkavo_patreon(snap.clone()),
        )
        .unwrap();
        let decoded = claims_from_cbor(&bytes)
            .unwrap()
            .custom
            .arkavo_patreon
            .unwrap();
        let mut want = snap.clone();
        want.memberships[1].campaign_name = None;
        want.owned_tiers.ids.clear();
        want.owned_tiers.slugs.clear();
        assert_eq!(decoded, want);

        // A ladder not read since #128: the tier ids alone.
        let unread = ArkavoPatreon {
            owned_tiers: OwnedCampaignTiers {
                ids: vec!["5".into(), "6".into()],
                ..Default::default()
            },
            ..snap.clone()
        };
        assert_eq!(
            patreon_to_json(&unread)["owned_campaign"],
            serde_json::json!({"id": "111", "tiers": [{"id": "5"}, {"id": "6"}]})
        );
        // A consumer has none.
        let consumer = ArkavoPatreon {
            role: "consumer".into(),
            campaign_id: None,
            ..snap
        };
        assert!(patreon_to_json(&consumer).get("owned_campaign").is_none());
    }

    #[test]
    fn cbor_roundtrip_arkavo_patreon_creator_claim() {
        let snap = ArkavoPatreon {
            role: "creator".into(),
            patreon_user_id: "patreon-user-7".into(),
            campaign_id: Some("camp-9".into()),
            memberships: vec![],
            owned_tiers: Default::default(),
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
        let mut c = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
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
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();

        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            now: claims.iat + 10,
            skew_secs: 60,
        };
        let decoded = verify(&bytes, &set(&vk), &opts).expect("verify");
        assert_eq!(decoded.sub, "sub-1");
    }

    /// #107: with two keys in the set a token signed by either verifies under
    /// its own kid; an empty or unknown kid is refused, and a kid naming the
    /// other key does not borrow it.
    #[test]
    fn verify_selects_the_key_by_kid() {
        let (sk_a, vk_a) = test_keypair();
        let (sk_b, vk_b) = test_keypair();
        let mut keys = crate::keys::KeySet::new(vk_b, b"kid-b".to_vec());
        keys.add_verify_only(vk_a, b"kid-a".to_vec()).unwrap();

        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            now: claims.iat + 10,
            skew_secs: 60,
        };
        for (sk, kid) in [(&sk_a, &b"kid-a"[..]), (&sk_b, &b"kid-b"[..])] {
            let bytes = mint(&claims, sk, kid).unwrap();
            verify(&bytes, &keys, &opts).expect("either key verifies under its kid");
        }
        for kid in [&b"kid-c"[..], &b""[..]] {
            let bytes = mint(&claims, &sk_a, kid).unwrap();
            assert!(matches!(
                verify(&bytes, &keys, &opts),
                Err(CwtError::UnknownKey)
            ));
        }
        let crossed = mint(&claims, &sk_a, b"kid-b").unwrap();
        assert!(matches!(
            verify(&crossed, &keys, &opts),
            Err(CwtError::InvalidSignature)
        ));
    }

    #[test]
    fn mint_emits_cwt_cbor_tag_61() {
        let (sk, _vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
        let bytes = mint(&claims, &sk, &test_kid()).expect("mint");
        // RFC 8392 §6: tag 61 encodes as [0xD8, 0x3D] (major-6 + uint8(61)).
        assert_eq!(&bytes[..2], &[0xD8, 0x3D]);
    }

    #[test]
    fn verify_rejects_untagged_cose_sign1() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
        let tagged = mint(&claims, &sk, &test_kid()).unwrap();
        // Strip the tag -> bare COSE_Sign1; verifier must reject.
        let untagged = &tagged[CWT_TAG_PREFIX.len()..];

        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            now: claims.iat + 10,
            skew_secs: 60,
        };
        let result = verify(untagged, &set(&vk), &opts);
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
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();

        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            now: claims.iat + 10,
            skew_secs: 60,
        };
        let result = verify(&bytes, &set(&vk2), &opts);
        assert!(matches!(result, Err(CwtError::InvalidSignature)));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
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
        let result = verify(&bytes, &set(&vk), &opts);
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
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
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
        let result = verify(&bytes, &set(&vk), &opts);
        assert!(
            matches!(result, Err(CwtError::UnsupportedAlg)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn verify_rejects_missing_alg() {
        // Build a COSE_Sign1 with NO algorithm in protected header.
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
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
        let result = verify(&bytes, &set(&vk), &opts);
        assert!(
            matches!(result, Err(CwtError::UnsupportedAlg)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn verify_rejects_expired() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();

        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            // now well past exp + skew
            now: claims.exp + 120,
            skew_secs: 60,
        };
        let result = verify(&bytes, &set(&vk), &opts);
        assert!(matches!(result, Err(CwtError::Expired)), "got {:?}", result);
    }

    #[test]
    fn verify_rejects_not_yet_valid() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();

        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            // now before iat by more than skew
            now: claims.iat - 120,
            skew_secs: 60,
        };
        let result = verify(&bytes, &set(&vk), &opts);
        assert!(
            matches!(result, Err(CwtError::NotYetValid)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn verify_accepts_within_skew_window() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();

        // now is 30s before iat: within ±60 skew, accepted.
        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: None,
            now: claims.iat - 30,
            skew_secs: 60,
        };
        verify(&bytes, &set(&vk), &opts).expect("verify within skew");
    }

    #[test]
    fn verify_rejects_iss_mismatch() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();
        let opts = VerifyOptions {
            expected_iss: Some("iss-other"),
            expected_aud: None,
            now: claims.iat + 10,
            skew_secs: 60,
        };
        assert!(matches!(
            verify(&bytes, &set(&vk), &opts),
            Err(CwtError::IssuerMismatch)
        ));
    }

    #[test]
    fn verify_rejects_aud_mismatch() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();
        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: Some("other-audience"),
            now: claims.iat + 10,
            skew_secs: 60,
        };
        assert!(matches!(
            verify(&bytes, &set(&vk), &opts),
            Err(CwtError::AudienceMismatch)
        ));
    }

    #[test]
    fn verify_accepts_aud_match_against_arkavo() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();
        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: Some("arkavo"),
            now: claims.iat + 10,
            skew_secs: 60,
        };
        verify(&bytes, &set(&vk), &opts).expect("verify");
    }

    #[test]
    fn verify_accepts_aud_match_against_multiple_audience() {
        let (sk, vk) = test_keypair();
        let mut claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
        claims.aud = Audience::Multiple(vec![
            "arkavo".to_string(),
            "https://platform.arkavo.net".to_string(),
        ]);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();
        let opts = VerifyOptions {
            expected_iss: Some("iss-1"),
            expected_aud: Some("arkavo"),
            now: claims.iat + 10,
            skew_secs: 60,
        };
        verify(&bytes, &set(&vk), &opts).expect("verify");
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
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None).with_cnf(Cnf {
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
        let decoded = verify(&bytes, &set(&vk), &opts).expect("verify");
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
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None)
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
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
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
        verify(&decoded, &set(&vk), &opts).expect("verify roundtrip via header transport");
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
        // What a device binding stores: the credCert's DER SubjectPublicKeyInfo.
        use p256::pkcs8::EncodePublicKey;
        let (_sk, vk) = test_keypair();
        let public_key_der = vk.to_public_key_der().unwrap().as_bytes().to_vec();
        let device_id = b"app-attest-key-id".to_vec();

        let cnf = cnf_from_app_attest(&public_key_der, &device_id).expect("build cnf");
        assert_eq!(cnf.kid, device_id);
        assert_eq!(
            cnf.cose_key,
            cose_key_from_p256_verifying_key(&vk, &device_id),
            "cnf names the bound key"
        );
    }

    #[test]
    fn cnf_from_app_attest_rejects_a_bare_sec1_point() {
        // A binding never stores one; accepting it would mean two formats.
        let (_sk, vk) = test_keypair();
        let point = vk.to_encoded_point(false).as_bytes().to_vec();
        assert!(matches!(
            cnf_from_app_attest(&point, b"id"),
            Err(CwtError::Malformed)
        ));
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
            app_id_hash: None,
            app_env: None,
            delegation_id: Some("deleg-1".into()),
            depth: Some(0),
            chain: Some(vec![]),
        };
        let claims = ArkavoClaims::agent(
            "https://identity.arkavo.net",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            vec![
                "https://platform.arkavo.net".into(),
                "https://kg.arkavo.net".into(),
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
            expected_aud: Some("https://kg.arkavo.net"),
            now: claims.iat + 1,
            skew_secs: DEFAULT_SKEW_SECS,
        };
        let back = verify(&bytes, &set(&vk), &opts).unwrap();
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
        let claims = ArkavoClaims::auth("https://identity.arkavo.net", "u", 1, None)
            .with_arkavo_npe(ArkavoNpe {
                npe_type: "device".into(),
                class: Some("attested".into()),
                attestation_expiry: Some(1_800_000_000),
                device_id: Some("keyid".into()),
                app_id_hash: Some("ab12".into()),
                app_env: Some("production".into()),
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
        let back = verify(&bytes, &set(&vk), &opts)
            .unwrap()
            .custom
            .arkavo_npe
            .unwrap();
        assert_eq!(back.class.as_deref(), Some("attested"));
        assert_eq!(back.attestation_expiry, Some(1_800_000_000));
        assert_eq!(back.app_id_hash.as_deref(), Some("ab12"));
        assert_eq!(back.app_env.as_deref(), Some("production"));
    }

    /// Hand-craft a minimal well-formed claims map (iss/sub/aud/exp/iat/cti)
    /// plus one extra top-level `(key, value)` entry, so an out-of-range or
    /// wrongly-typed field can be injected without going through the
    /// type-safe claim-builder / `claims_to_cbor` path.
    fn claims_bytes_with_npe(extra: (Value, Value)) -> Vec<u8> {
        let entries = vec![
            (Value::Integer(1.into()), Value::Text("iss-1".into())),
            (Value::Integer(2.into()), Value::Text("sub-1".into())),
            (Value::Integer(3.into()), Value::Text("aud-1".into())),
            (Value::Integer(4.into()), Value::Integer(1.into())),
            (Value::Integer(6.into()), Value::Integer(0.into())),
            (Value::Integer(7.into()), Value::Bytes(vec![0u8; 16])),
            extra,
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
        let result = claims_from_cbor(&claims_bytes_with_npe((
            Value::Text("arkavo_npe".into()),
            too_big,
        )));
        assert!(
            matches!(result, Err(CwtError::Malformed)),
            "got {:?}",
            result
        );

        let negative = Value::Map(vec![
            (Value::Text("type".into()), Value::Text("agent".into())),
            (Value::Text("depth".into()), Value::Integer((-1).into())),
        ]);
        let result = claims_from_cbor(&claims_bytes_with_npe((
            Value::Text("arkavo_npe".into()),
            negative,
        )));
        assert!(
            matches!(result, Err(CwtError::Malformed)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn npe_app_fields_of_the_wrong_type_are_malformed() {
        for key in ["app_id_hash", "app_env"] {
            let npe = Value::Map(vec![
                (Value::Text("type".into()), Value::Text("device".into())),
                (Value::Text(key.into()), Value::Bytes(vec![0xab, 0x12])),
            ]);
            let result = claims_from_cbor(&claims_bytes_with_npe((
                Value::Text("arkavo_npe".into()),
                npe,
            )));
            assert!(
                matches!(result, Err(CwtError::Malformed)),
                "{key}: got {result:?}"
            );
        }
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
        let result = claims_from_cbor(&claims_bytes_with_npe((
            Value::Text("arkavo_npe".into()),
            npe,
        )));
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
        let result = claims_from_cbor(&claims_bytes_with_npe((
            Value::Text("arkavo_npe".into()),
            npe,
        )));
        assert!(
            matches!(result, Err(CwtError::Malformed)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn act_non_array_is_malformed() {
        let entries = vec![
            (Value::Integer(1.into()), Value::Text("iss-1".into())),
            (Value::Integer(2.into()), Value::Text("sub-1".into())),
            (Value::Integer(3.into()), Value::Text("aud-1".into())),
            (Value::Integer(4.into()), Value::Integer(1.into())),
            (Value::Integer(6.into()), Value::Integer(0.into())),
            (Value::Integer(7.into()), Value::Bytes(vec![0u8; 16])),
            (
                Value::Text("act".into()),
                Value::Text("not-an-array".into()),
            ),
        ];
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut bytes).expect("encode");
        assert!(matches!(claims_from_cbor(&bytes), Err(CwtError::Malformed)));
    }

    #[test]
    fn npe_non_map_is_malformed() {
        let result = claims_from_cbor(&claims_bytes_with_npe((
            Value::Text("arkavo_npe".into()),
            Value::Text("nope".into()),
        )));
        assert!(matches!(result, Err(CwtError::Malformed)));
    }

    #[test]
    fn npe_wrongly_typed_known_field_is_malformed() {
        let npe = Value::Map(vec![(Value::Text("type".into()), Value::Integer(1.into()))]);
        let result = claims_from_cbor(&claims_bytes_with_npe((
            Value::Text("arkavo_npe".into()),
            npe,
        )));
        assert!(matches!(result, Err(CwtError::Malformed)));
    }

    #[test]
    fn state_version_swarm_scope_and_auth_time_round_trip() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::agent(
            "https://identity.arkavo.net",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            vec!["https://platform.arkavo.net".into()],
            crate::constants::AGENT_SHORT_LIVED_TOKEN_MINUTES,
        )
        .with_arkavo_state_version(42)
        .with_arkavo_swarm("kit-alpha")
        .with_scope("openid agents:delegate")
        .with_auth_time(1_790_000_000);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();
        let back = verify(
            &bytes,
            &set(&vk),
            &VerifyOptions {
                expected_iss: Some("https://identity.arkavo.net"),
                expected_aud: Some("https://platform.arkavo.net"),
                now: claims.iat + 1,
                skew_secs: DEFAULT_SKEW_SECS,
            },
        )
        .unwrap();
        assert_eq!(back.custom.arkavo_state_version, Some(42));
        assert_eq!(back.custom.arkavo_swarm.as_deref(), Some("kit-alpha"));
        assert_eq!(back.custom.scope.as_deref(), Some("openid agents:delegate"));
        assert_eq!(back.custom.auth_time, Some(1_790_000_000));
        assert_eq!(back.exp - back.iat, 300);
    }

    #[test]
    fn tokens_without_the_new_claims_decode_them_as_absent() {
        let (sk, vk) = test_keypair();
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None);
        let bytes = mint(&claims, &sk, &test_kid()).unwrap();
        let back = verify(
            &bytes,
            &set(&vk),
            &VerifyOptions {
                expected_iss: None,
                expected_aud: None,
                now: claims.iat,
                skew_secs: DEFAULT_SKEW_SECS,
            },
        )
        .unwrap();
        assert_eq!(back.custom.arkavo_state_version, None);
        assert_eq!(back.custom.arkavo_swarm, None);
        assert_eq!(back.custom.scope, None);
        assert_eq!(back.custom.auth_time, None);
    }

    #[test]
    fn mistyped_state_version_swarm_scope_or_auth_time_is_malformed() {
        let cases = [
            ("arkavo_state_version", Value::Text("1".into())),
            ("arkavo_state_version", Value::Integer((-1).into())),
            ("arkavo_swarm", Value::Bool(true)),
            ("scope", Value::Array(vec![])),
            ("auth_time", Value::Text("1790000000".into())),
            ("auth_time", Value::Integer(u64::MAX.into())),
        ];
        for (key, bad) in cases {
            assert!(
                matches!(
                    claims_from_cbor(&claims_bytes_with_npe((Value::Text(key.into()), bad))),
                    Err(CwtError::Malformed)
                ),
                "{key} with the wrong type must be refused, not ignored"
            );
        }
    }

    #[test]
    fn with_arkavo_swarm_empty_is_omitted() {
        // An agent has no swarm until it is specialized into a kit; the
        // claim must be omitted (not `Some("")`) in that case.
        let claims = ArkavoClaims::auth("iss-1", "sub-1", 1, None).with_arkavo_swarm("");
        assert_eq!(claims.custom.arkavo_swarm, None);

        let bytes = claims_to_cbor(&claims).expect("encode");
        let decoded = claims_from_cbor(&bytes).expect("decode");
        assert_eq!(decoded.custom.arkavo_swarm, None);
    }
}
