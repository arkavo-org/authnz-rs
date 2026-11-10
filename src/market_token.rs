//! Market app tokens (#151): the credential an app presents to the market's
//! request API (`POST https://market.arkavo.com/api/requests`) for the
//! account signed in to it.
//!
//! The passkey auth CWT is a bearer token every Arkavo service accepts, so
//! the market does not take it. It takes this token instead: bound to the
//! market (`aud`) and to a key the app holds (`cnf`), for at most
//! [`LIFETIME_SECONDS`]. The market requires a signature by that key on
//! every request. Its contract: arkavo-com/market
//! `docs/market-identity-interface.md`, "Requests: the tokens identity
//! issues".
//!
//! Wire format:
//!
//! - CBOR tag 61 (CWT) around a COSE_Sign1, ES256, empty external AAD.
//! - Protected header: `alg` ES256, `kid` (a key in `/.well-known/cose-keys`),
//!   `content type` (label 3) = [`CONTENT_TYPE`]. `cwt::verify` refuses any
//!   content type, so no identity route, and no verifier that refuses typed
//!   CWTs, takes this token for a session token.
//! - Payload: a CBOR map with exactly these keys, in deterministic order
//!   (RFC 8949 §4.2.1): `iss` (1), `sub` (2, the account's bare lowercase
//!   UUID), `aud` (3, one text string, the market), `exp` (4), `iat` (6),
//!   `cti` (7, 16 bytes), `cnf` (8, `{1: COSE_Key {1: 2, -1: 1, -2: x, -3:
//!   y}}`, no `kid` and no `alg`), `arkavo_roles` (`["user"]`, never
//!   `agent`: that word selects the market's agent rules) and
//!   `arkavo_account_id` (the same UUID as `sub`; the market reads the
//!   account from it).
//!
//! Nothing else: no entitlement, handle, Patreon data or email. The bearer
//! is the account, so the market needs no entitlement from it.

use crate::cwt::{CWT_TAG_PREFIX, CwtError, strip_cwt_tag};
use crate::owner_kas_token::{cnf_cbor, parse_cnf};
use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, iana};
use p256::ecdsa::{Signature, SigningKey, signature::Signer, signature::Verifier};

/// The protected header's `content type` (label 3).
pub const CONTENT_TYPE: &str = "application/market+cwt";

/// `exp - iat`. The market refuses an app token that lasts longer.
pub const LIFETIME_SECONDS: i64 = 900;

/// The one role an app token carries: a person, as in the passkey auth CWT.
pub const ROLE: &str = "user";

/// The payload keys of the roles and the account.
pub const ROLES_CLAIM: &str = "arkavo_roles";
pub const ACCOUNT_CLAIM: &str = "arkavo_account_id";

/// The app key: the same encoding as an owner-KAS request key (unpadded
/// base64url of the 65-byte uncompressed P-256 point). Returns `(x, y)`.
pub use crate::owner_kas_token::parse_cnf_key;

/// A market app token's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketToken {
    pub iss: String,
    /// The account's bare lowercase UUID: `sub` and `arkavo_account_id`.
    pub account: String,
    /// The market, as it names itself (`https://market.arkavo.com`).
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub cti: [u8; 16],
    /// The app-held key (P-256).
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// Sign `t` with `key` under `kid`: the tag-61 CWT bytes.
pub fn mint(t: &MarketToken, key: &SigningKey, kid: &[u8]) -> Result<Vec<u8>, CwtError> {
    let int = |n: i64| Value::Integer(n.into());
    // Text keys follow the integer ones, shorter first (RFC 8949 §4.2.1).
    let payload = Value::Map(vec![
        (int(1), Value::Text(t.iss.clone())),
        (int(2), Value::Text(t.account.clone())),
        (int(3), Value::Text(t.aud.clone())),
        (int(4), int(t.exp)),
        (int(6), int(t.iat)),
        (int(7), Value::Bytes(t.cti.to_vec())),
        (int(8), cnf_cbor(&t.x, &t.y)),
        (
            Value::Text(ROLES_CLAIM.into()),
            Value::Array(vec![Value::Text(ROLE.into())]),
        ),
        (
            Value::Text(ACCOUNT_CLAIM.into()),
            Value::Text(t.account.clone()),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&payload, &mut bytes).map_err(|_| CwtError::Malformed)?;

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(kid.to_vec())
        .content_type(CONTENT_TYPE.to_string())
        .build();
    let inner = CoseSign1Builder::new()
        .protected(protected)
        .payload(bytes)
        .create_signature(b"", |to_sign| {
            let sig: Signature = key.sign(to_sign);
            sig.to_bytes().to_vec()
        })
        .build()
        .to_vec()
        .map_err(|_| CwtError::Malformed)?;
    let mut out = Vec::with_capacity(CWT_TAG_PREFIX.len() + inner.len());
    out.extend_from_slice(&CWT_TAG_PREFIX);
    out.extend_from_slice(&inner);
    Ok(out)
}

/// The checks the market makes, as a reference: the tag, ES256, the content
/// type, a `kid` in `keys`, the signature, exactly the payload keys above
/// with `aud` = `audience`, and `iat`/`exp` within `skew_secs` of `now`.
/// Identity never accepts one of these tokens; this exists to pin the
/// format.
pub fn verify(
    bytes: &[u8],
    keys: &crate::keys::KeySet,
    audience: &str,
    now: i64,
    skew_secs: i64,
) -> Result<MarketToken, CwtError> {
    let sign1 =
        coset::CoseSign1::from_slice(strip_cwt_tag(bytes)?).map_err(|_| CwtError::Malformed)?;
    let header = &sign1.protected.header;
    match header.alg {
        Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)) => {}
        _ => return Err(CwtError::UnsupportedAlg),
    }
    if header.content_type != Some(coset::ContentType::Text(CONTENT_TYPE.into()))
        || !header.crit.is_empty()
    {
        return Err(CwtError::Malformed);
    }
    let key = keys.get(&header.key_id).ok_or(CwtError::UnknownKey)?;
    sign1
        .verify_signature(b"", |sig_bytes, to_verify| {
            let sig = Signature::from_slice(sig_bytes).map_err(|_| ())?;
            key.verify(to_verify, &sig).map_err(|_| ())
        })
        .map_err(|_| CwtError::InvalidSignature)?;
    let t = parse_payload(sign1.payload.as_deref().ok_or(CwtError::Malformed)?)?;
    if t.aud != audience {
        return Err(CwtError::AudienceMismatch);
    }
    if t.iat > t.exp || t.exp - t.iat > LIFETIME_SECONDS {
        return Err(CwtError::Malformed);
    }
    if t.exp <= now - skew_secs {
        return Err(CwtError::Expired);
    }
    if t.iat > now + skew_secs {
        return Err(CwtError::NotYetValid);
    }
    Ok(t)
}

fn parse_payload(bytes: &[u8]) -> Result<MarketToken, CwtError> {
    let value: Value = ciborium::de::from_reader(bytes).map_err(|_| CwtError::Malformed)?;
    let Value::Map(entries) = value else {
        return Err(CwtError::Malformed);
    };
    if entries.len() != 9 {
        return Err(CwtError::Malformed);
    }
    let get = |want: &Value| -> Result<&Value, CwtError> {
        entries
            .iter()
            .find(|(k, _)| k == want)
            .map(|(_, v)| v)
            .ok_or(CwtError::Malformed)
    };
    let int_key = |n: i64| Value::Integer(n.into());
    let text = |v: &Value| v.as_text().map(str::to_string).ok_or(CwtError::Malformed);
    let number = |v: &Value| {
        v.as_integer()
            .and_then(|i| i64::try_from(i).ok())
            .ok_or(CwtError::Malformed)
    };

    let account = text(get(&int_key(2))?)?;
    // One account under both names, and exactly the one role.
    if text(get(&Value::Text(ACCOUNT_CLAIM.into()))?)? != account
        || *get(&Value::Text(ROLES_CLAIM.into()))? != Value::Array(vec![Value::Text(ROLE.into())])
    {
        return Err(CwtError::Malformed);
    }
    let cti: [u8; 16] = get(&int_key(7))?
        .as_bytes()
        .and_then(|b| b.as_slice().try_into().ok())
        .ok_or(CwtError::Malformed)?;
    let (x, y) = parse_cnf(get(&int_key(8))?)?;
    Ok(MarketToken {
        iss: text(get(&int_key(1))?)?,
        account,
        aud: text(get(&int_key(3))?)?,
        exp: number(get(&int_key(4))?)?,
        iat: number(get(&int_key(6))?)?,
        cti,
        x,
        y,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::rand_core::OsRng;

    const KID: &[u8] = b"market-token-test-kid";
    const MARKET: &str = "https://market.example";

    fn sample(now: i64) -> MarketToken {
        let sk = SigningKey::random(&mut OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        MarketToken {
            iss: "https://identity.example".into(),
            account: "0a1b2c3d-0000-4000-8000-000000000001".into(),
            aud: MARKET.into(),
            iat: now,
            exp: now + LIFETIME_SECONDS,
            cti: [9; 16],
            x: (*point.x().unwrap()).into(),
            y: (*point.y().unwrap()).into(),
        }
    }

    fn signer() -> (SigningKey, crate::keys::KeySet) {
        let sk = SigningKey::random(&mut OsRng);
        let set = crate::keys::KeySet::new(*sk.verifying_key(), KID.to_vec());
        (sk, set)
    }

    #[test]
    fn a_minted_token_verifies_and_round_trips() {
        let (sk, set) = signer();
        let now = 1_760_000_000;
        let t = sample(now);
        let bytes = mint(&t, &sk, KID).unwrap();
        assert!(bytes.starts_with(&CWT_TAG_PREFIX));
        assert_eq!(verify(&bytes, &set, MARKET, now + 10, 60).unwrap(), t);
    }

    #[test]
    fn the_payload_is_exactly_the_contract_in_deterministic_order() {
        let (sk, _) = signer();
        let t = sample(1_760_000_000);
        let bytes = mint(&t, &sk, KID).unwrap();
        let sign1 = coset::CoseSign1::from_slice(&bytes[2..]).unwrap();
        assert_eq!(
            sign1.protected.header.content_type,
            Some(coset::ContentType::Text(CONTENT_TYPE.into()))
        );
        assert_eq!(sign1.protected.header.key_id, KID);
        assert!(sign1.unprotected.is_empty());
        let raw = sign1.payload.as_deref().unwrap();
        let payload: Value = ciborium::de::from_reader(raw).unwrap();
        let entries = payload.as_map().unwrap();
        let keys: Vec<&Value> = entries.iter().map(|(k, _)| k).collect();
        let int = |n: i64| Value::Integer(n.into());
        assert_eq!(
            keys,
            [
                &int(1),
                &int(2),
                &int(3),
                &int(4),
                &int(6),
                &int(7),
                &int(8),
                &Value::Text("arkavo_roles".into()),
                &Value::Text("arkavo_account_id".into()),
            ]
        );
        assert_eq!(
            entries[2].1,
            Value::Text(MARKET.into()),
            "aud is one string"
        );
        assert_eq!(entries[6].1, cnf_cbor(&t.x, &t.y));
        assert_eq!(entries[7].1, Value::Array(vec![Value::Text("user".into())]));
        assert_eq!(entries[1].1, entries[8].1, "sub is the account");
        // Deterministic: the encoded keys are in bytewise order.
        let encoded: Vec<Vec<u8>> = keys
            .iter()
            .map(|k| {
                let mut b = Vec::new();
                ciborium::ser::into_writer(k, &mut b).unwrap();
                b
            })
            .collect();
        assert!(encoded.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn identitys_own_verifier_refuses_it() {
        let (sk, set) = signer();
        let now = 1_760_000_000;
        let bytes = mint(&sample(now), &sk, KID).unwrap();
        let opts = crate::cwt::VerifyOptions {
            expected_iss: None,
            expected_aud: None,
            now,
            skew_secs: 60,
        };
        assert!(matches!(
            crate::cwt::verify(&bytes, &set, &opts),
            Err(CwtError::Malformed)
        ));
    }

    #[test]
    fn the_reference_verifier_refuses_what_the_market_refuses() {
        let (sk, set) = signer();
        let now = 1_760_000_000;
        let t = sample(now);
        let bytes = mint(&t, &sk, KID).unwrap();

        assert!(matches!(
            verify(&bytes, &set, "https://other.example", now, 60),
            Err(CwtError::AudienceMismatch)
        ));
        assert!(matches!(
            verify(&bytes, &set, MARKET, now + LIFETIME_SECONDS + 60, 60),
            Err(CwtError::Expired)
        ));
        assert!(matches!(
            verify(&bytes, &set, MARKET, now - 61, 60),
            Err(CwtError::NotYetValid)
        ));
        let (_, other) = signer();
        assert!(verify(&bytes, &other, MARKET, now, 60).is_err());

        let long = MarketToken {
            exp: t.iat + LIFETIME_SECONDS + 1,
            ..t.clone()
        };
        let bytes = mint(&long, &sk, KID).unwrap();
        assert!(matches!(
            verify(&bytes, &set, MARKET, now, 60),
            Err(CwtError::Malformed)
        ));

        let mut tampered = mint(&t, &sk, KID).unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            verify(&tampered, &set, MARKET, now, 60),
            Err(CwtError::InvalidSignature)
        ));
    }
}
