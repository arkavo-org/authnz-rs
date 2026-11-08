//! Owner-KAS tokens (#146): the credential a receiver's request carries to an
//! owner's phone.
//!
//! arkavo-ios's owner KAS (design §4.1, arkavo-ios ADR-0072) has
//! the owner's phone, not a server, decide each key release. A receiver's
//! request reaches that phone through a relay, so it must not carry the
//! receiver's session token. It carries this token instead: bound to one
//! owner route (`aud`) and to the receiver's per-attempt request key (`cnf`),
//! for at most [`LIFETIME_SECONDS`].
//!
//! Wire format:
//!
//! - CBOR tag 61 (CWT) around a COSE_Sign1, ES256, empty external AAD.
//! - Protected header: `alg` ES256, `kid` (a key in `/.well-known/cose-keys`),
//!   `content type` (label 3) = [`CONTENT_TYPE`]. `cwt::verify` refuses any
//!   content type, so identity never takes this token for a session token,
//!   and the owner's phone accepts only this type.
//! - Payload: a CBOR map with exactly these keys, in deterministic order
//!   (RFC 8949 §4.2.1): `iss` (1), `sub` (2, the receiver's bare lowercase
//!   UUID), `aud` (3, `owner-kas:<route_id>`), `exp` (4), `iat` (6), `cti`
//!   (7, 16 bytes), `cnf` (8, `{1: COSE_Key {1: 2, -1: 1, -2: x, -3: y}}`, no
//!   `kid` and no `alg`), and `arkavo_handle` (the receiver's permanent
//!   handle, lowercase).
//!
//! Nothing else: no entitlement, Patreon data or email. The token lands on
//! another user's phone.

use crate::cwt::{CWT_TAG_PREFIX, CwtError, strip_cwt_tag};
use base64::Engine;
use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, iana};
use p256::ecdsa::{Signature, SigningKey, signature::Signer, signature::Verifier};

/// The protected header's `content type` (label 3).
pub const CONTENT_TYPE: &str = "application/owner-kas+cwt";

/// `aud` is this prefix followed by the route id.
pub const AUDIENCE_PREFIX: &str = "owner-kas:";

/// The payload key of the receiver's handle.
pub const HANDLE_CLAIM: &str = "arkavo_handle";

/// `exp - iat`. It is the owner's window to answer: the owner's phone has no
/// trusted submission time, so it checks `exp` against its own clock when it
/// services the request (60 s skew).
pub const LIFETIME_SECONDS: i64 = 900;

/// Crockford base-32 in canonical (uppercase) form: no I, L, O or U.
const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A owner-KAS token's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKasToken {
    pub iss: String,
    /// The receiver's bare lowercase account UUID, as in the passkey CWT.
    pub sub: String,
    /// The owner route; `aud` is [`AUDIENCE_PREFIX`] + this.
    pub route_id: String,
    pub iat: i64,
    pub exp: i64,
    pub cti: [u8; 16],
    /// The receiver's request key (P-256).
    pub x: [u8; 32],
    pub y: [u8; 32],
    /// The receiver's permanent handle (`alice.arkavo.social`), lowercase.
    pub handle: String,
}

/// A canonical ULID: 26 uppercase Crockford base-32 characters, the first
/// `0`–`7` (a larger first character overflows 128 bits). Never normalized:
/// `aud` is compared as a string on the owner's phone.
pub fn is_route_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 26 && (b'0'..=b'7').contains(&b[0]) && b.iter().all(|c| CROCKFORD.contains(c))
}

/// The request key: base64url without padding of the 65-byte SEC1
/// uncompressed point `04‖X‖Y`, a valid P-256 point. Returns `(x, y)`.
pub fn parse_cnf_key(s: &str) -> Option<([u8; 32], [u8; 32])> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()?;
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return None;
    }
    // Refuses a point off the curve.
    p256::PublicKey::from_sec1_bytes(&bytes).ok()?;
    let x: [u8; 32] = bytes[1..33].try_into().ok()?;
    let y: [u8; 32] = bytes[33..65].try_into().ok()?;
    Some((x, y))
}

fn cnf_cbor(x: &[u8; 32], y: &[u8; 32]) -> Value {
    let key = Value::Map(vec![
        (
            Value::Integer((iana::KeyParameter::Kty as i64).into()),
            Value::Integer((iana::KeyType::EC2 as i64).into()),
        ),
        (
            Value::Integer((iana::Ec2KeyParameter::Crv as i64).into()),
            Value::Integer((iana::EllipticCurve::P_256 as i64).into()),
        ),
        (
            Value::Integer((iana::Ec2KeyParameter::X as i64).into()),
            Value::Bytes(x.to_vec()),
        ),
        (
            Value::Integer((iana::Ec2KeyParameter::Y as i64).into()),
            Value::Bytes(y.to_vec()),
        ),
    ]);
    // RFC 8747 §3.2: `cnf` {1 (COSE_Key): key}.
    Value::Map(vec![(Value::Integer(1.into()), key)])
}

/// Sign `t` with `key` under `kid`: the tag-61 CWT bytes.
pub fn mint(t: &OwnerKasToken, key: &SigningKey, kid: &[u8]) -> Result<Vec<u8>, CwtError> {
    let int = |n: i64| Value::Integer(n.into());
    let payload = Value::Map(vec![
        (int(1), Value::Text(t.iss.clone())),
        (int(2), Value::Text(t.sub.clone())),
        (
            int(3),
            Value::Text(format!("{AUDIENCE_PREFIX}{}", t.route_id)),
        ),
        (int(4), int(t.exp)),
        (int(6), int(t.iat)),
        (int(7), Value::Bytes(t.cti.to_vec())),
        (int(8), cnf_cbor(&t.x, &t.y)),
        (
            Value::Text(HANDLE_CLAIM.into()),
            Value::Text(t.handle.clone()),
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

/// The checks the owner's phone makes, as a reference: the tag, ES256, the
/// content type, a `kid` in `keys`, the signature, exactly the payload keys
/// above, and `iat`/`exp` within `skew_secs` of `now`. Identity never
/// accepts one of these tokens; this exists to pin the format.
pub fn verify(
    bytes: &[u8],
    keys: &crate::keys::KeySet,
    now: i64,
    skew_secs: i64,
) -> Result<OwnerKasToken, CwtError> {
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

fn parse_payload(bytes: &[u8]) -> Result<OwnerKasToken, CwtError> {
    let value: Value = ciborium::de::from_reader(bytes).map_err(|_| CwtError::Malformed)?;
    let Value::Map(entries) = value else {
        return Err(CwtError::Malformed);
    };
    if entries.len() != 8 {
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

    let aud = text(get(&int_key(3))?)?;
    let route_id = aud
        .strip_prefix(AUDIENCE_PREFIX)
        .filter(|r| is_route_id(r))
        .ok_or(CwtError::AudienceMismatch)?
        .to_string();
    let cti: [u8; 16] = get(&int_key(7))?
        .as_bytes()
        .and_then(|b| b.as_slice().try_into().ok())
        .ok_or(CwtError::Malformed)?;
    let (x, y) = parse_cnf(get(&int_key(8))?)?;
    Ok(OwnerKasToken {
        iss: text(get(&int_key(1))?)?,
        sub: text(get(&int_key(2))?)?,
        route_id,
        exp: number(get(&int_key(4))?)?,
        iat: number(get(&int_key(6))?)?,
        cti,
        x,
        y,
        handle: text(get(&Value::Text(HANDLE_CLAIM.into()))?)?,
    })
}

fn parse_cnf(v: &Value) -> Result<([u8; 32], [u8; 32]), CwtError> {
    let Some([(k, key)]) = v.as_map().map(Vec::as_slice) else {
        return Err(CwtError::Malformed);
    };
    if *k != Value::Integer(1.into()) {
        return Err(CwtError::Malformed);
    }
    let Some(params) = key.as_map().filter(|m| m.len() == 4) else {
        return Err(CwtError::Malformed);
    };
    let param = |label: i64| {
        params
            .iter()
            .find(|(k, _)| *k == Value::Integer(label.into()))
            .map(|(_, v)| v)
            .ok_or(CwtError::Malformed)
    };
    if *param(iana::KeyParameter::Kty as i64)? != Value::Integer((iana::KeyType::EC2 as i64).into())
        || *param(iana::Ec2KeyParameter::Crv as i64)?
            != Value::Integer((iana::EllipticCurve::P_256 as i64).into())
    {
        return Err(CwtError::UnsupportedKeyType);
    }
    let coord = |label: i64| -> Result<[u8; 32], CwtError> {
        param(label)?
            .as_bytes()
            .and_then(|b| b.as_slice().try_into().ok())
            .ok_or(CwtError::Malformed)
    };
    Ok((
        coord(iana::Ec2KeyParameter::X as i64)?,
        coord(iana::Ec2KeyParameter::Y as i64)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::rand_core::OsRng;

    const KID: &[u8] = b"owner-kas-test-kid";
    const ROUTE: &str = "01JC0000000000000000000000";

    fn request_key() -> ([u8; 32], [u8; 32], String) {
        let sk = SigningKey::random(&mut OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.as_bytes());
        (
            (*point.x().unwrap()).into(),
            (*point.y().unwrap()).into(),
            b64,
        )
    }

    fn sample(now: i64) -> OwnerKasToken {
        let (x, y, _) = request_key();
        OwnerKasToken {
            iss: "https://identity.arkavo.net".into(),
            sub: "0a1b2c3d-0000-4000-8000-000000000001".into(),
            route_id: ROUTE.into(),
            iat: now,
            exp: now + LIFETIME_SECONDS,
            cti: [9; 16],
            x,
            y,
            handle: "alice.arkavo.social".into(),
        }
    }

    fn signer() -> (SigningKey, crate::keys::KeySet) {
        let sk = SigningKey::random(&mut OsRng);
        let set = crate::keys::KeySet::new(*sk.verifying_key(), KID.to_vec());
        (sk, set)
    }

    #[test]
    fn route_ids_are_canonical_ulids_only() {
        assert!(is_route_id(ROUTE));
        assert!(is_route_id("7ZZZZZZZZZZZZZZZZZZZZZZZZZ"));
        for bad in [
            "",
            "01JC000000000000000000000",   // 25
            "01JC00000000000000000000000", // 27
            "81JC0000000000000000000000",  // first above 7
            "01jc0000000000000000000000",  // lowercase: never normalized
            "01JC000000000000000000000I",  // I, L, O, U are not Crockford
            "01JC000000000000000000000L",
            "01JC000000000000000000000O",
            "01JC000000000000000000000U",
            "01JC00000000000000000000-0",
        ] {
            assert!(!is_route_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn cnf_keys_are_unpadded_base64url_points_on_the_curve() {
        let (x, y, b64) = request_key();
        assert_eq!(parse_cnf_key(&b64), Some((x, y)));

        let mut raw = vec![0x04];
        raw.extend_from_slice(&x);
        raw.extend_from_slice(&y);
        let std = base64::engine::general_purpose::STANDARD.encode(&raw);
        let padded = base64::engine::general_purpose::URL_SAFE.encode(&raw);
        let mut compressed = vec![0x02 | (y[31] & 1)];
        compressed.extend_from_slice(&x);
        let mut off_curve = raw.clone();
        off_curve[64] ^= 1;
        let enc = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        for bad in [
            String::new(),
            format!("{b64}="),
            padded,
            enc(&compressed),
            enc(&off_curve),
            enc(&raw[..64]),
            enc(&[0u8; 65]),
        ] {
            assert_eq!(parse_cnf_key(&bad), None, "{bad:?}");
        }
        // Standard base64 only parses when it happens to use neither + nor /.
        if std.contains(['+', '/']) {
            assert_eq!(parse_cnf_key(std.trim_end_matches('=')), None);
        }
    }

    #[test]
    fn a_minted_token_verifies_and_round_trips() {
        let (sk, set) = signer();
        let now = 1_760_000_000;
        let t = sample(now);
        let bytes = mint(&t, &sk, KID).unwrap();
        assert!(bytes.starts_with(&CWT_TAG_PREFIX));
        assert_eq!(verify(&bytes, &set, now + 10, 60).unwrap(), t);
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
        let payload: Value = ciborium::de::from_reader(sign1.payload.as_deref().unwrap()).unwrap();
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
                &Value::Text(HANDLE_CLAIM.into()),
            ]
        );
        assert_eq!(
            entries[2].1,
            Value::Text(format!("owner-kas:{ROUTE}")),
            "aud is one text string"
        );
        // cnf = {1: {1: 2, -1: 1, -2: x, -3: y}}, no kid or alg.
        assert_eq!(
            entries[6].1,
            Value::Map(vec![(
                int(1),
                Value::Map(vec![
                    (int(1), int(2)),
                    (int(-1), int(1)),
                    (int(-2), Value::Bytes(t.x.to_vec())),
                    (int(-3), Value::Bytes(t.y.to_vec())),
                ])
            )])
        );
        // Deterministic CBOR: re-encoding the decoded map gives the same bytes.
        let mut again = Vec::new();
        ciborium::ser::into_writer(&payload, &mut again).unwrap();
        assert_eq!(again, sign1.payload.unwrap());
    }

    #[test]
    fn identity_never_takes_it_for_a_session_token() {
        let (sk, set) = signer();
        let now = chrono::Utc::now().timestamp();
        let bytes = mint(&sample(now), &sk, KID).unwrap();
        let opts = crate::cwt::VerifyOptions {
            expected_iss: None,
            expected_aud: None,
            now,
            skew_secs: crate::cwt::DEFAULT_SKEW_SECS,
        };
        assert!(matches!(
            crate::cwt::verify(&bytes, &set, &opts),
            Err(CwtError::Malformed)
        ));
    }

    #[test]
    fn a_session_cwt_is_not_a_owner_kas_token() {
        let (sk, set) = signer();
        let now = chrono::Utc::now().timestamp();
        let session = crate::cwt::ArkavoClaims::auth("https://identity.arkavo.net", "u", 1, None);
        let bytes = crate::cwt::mint(&session, &sk, KID).unwrap();
        assert!(matches!(
            verify(&bytes, &set, now, 60),
            Err(CwtError::Malformed)
        ));
    }

    #[test]
    fn verification_enforces_key_signature_and_time() {
        let (sk, set) = signer();
        let now = 1_760_000_000;
        let t = sample(now);
        let bytes = mint(&t, &sk, KID).unwrap();

        let other = crate::keys::KeySet::new(*sk.verifying_key(), b"another-kid".to_vec());
        assert!(matches!(
            verify(&bytes, &other, now, 60),
            Err(CwtError::UnknownKey)
        ));

        let (wrong, _) = signer();
        let forged = mint(&t, &wrong, KID).unwrap();
        assert!(matches!(
            verify(&forged, &set, now, 60),
            Err(CwtError::InvalidSignature)
        ));

        assert!(verify(&bytes, &set, t.exp + 59, 60).is_ok());
        assert!(matches!(
            verify(&bytes, &set, t.exp + 60, 60),
            Err(CwtError::Expired)
        ));
        assert!(matches!(
            verify(&bytes, &set, now - 61, 60),
            Err(CwtError::NotYetValid)
        ));

        let long = OwnerKasToken {
            exp: now + LIFETIME_SECONDS + 1,
            ..t.clone()
        };
        assert!(matches!(
            verify(&mint(&long, &sk, KID).unwrap(), &set, now, 60),
            Err(CwtError::Malformed)
        ));

        let untagged = &bytes[CWT_TAG_PREFIX.len()..];
        assert!(verify(untagged, &set, now, 60).is_err());
    }
}
