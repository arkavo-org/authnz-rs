//! Peer certificates (#143): identity's dated statement that a key belonged
//! to an account, for peers that must authenticate each other with no
//! internet.
//!
//! The app holds the key (a Secure Enclave P-256 key that signs arbitrary
//! bytes). A peer verifies the certificate offline against a stored copy of
//! `/.well-known/cose-keys`, then has the other side prove it holds the key.
//! Contract: `docs/peer-certificate.md`.
//!
//! Wire format:
//!
//! - CBOR tag 61 (CWT) around a COSE_Sign1, ES256, empty external AAD.
//! - Protected header: `alg` ES256, `kid` (a key in `/.well-known/cose-keys`),
//!   `content type` (label 3) = [`CONTENT_TYPE`]. `cwt::verify` refuses any
//!   content type, so identity never takes a certificate for a session token.
//! - Payload: a CBOR map with exactly these keys, in deterministic order
//!   (RFC 8949 §4.2.1): `iss` (1), `sub` (2, the account's bare lowercase
//!   UUID), `aud` (3, one peer audience), `exp` (4), `iat` (6), `cti` (7, 16
//!   bytes), `cnf` (8, `{1: COSE_Key {1: 2, -1: 1, -2: x, -3: y}}`),
//!   `auth_time` (the passkey assertion time) and `arkavo_handle` (the
//!   account's permanent handle, lowercase).
//!
//! Nothing else, and never an entitlement: a certificate lives up to
//! [`MAX_LIFETIME_SECONDS`] and is shown to other users' devices.

use crate::cwt::{CWT_TAG_PREFIX, CwtError, strip_cwt_tag};
use crate::owner_kas_token::{HANDLE_CLAIM, cnf_cbor, parse_cnf};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, iana};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};

/// The protected header's `content type` (label 3).
pub const CONTENT_TYPE: &str = "application/peer-certificate+cwt";

/// The payload key of the passkey assertion time, as in a renewed passkey
/// auth CWT.
pub const AUTH_TIME_CLAIM: &str = "auth_time";

/// The longest `exp - iat` identity mints and a peer accepts: 7 days. It is
/// also how long an offline peer keeps accepting a deleted account.
pub const MAX_LIFETIME_SECONDS: i64 = 7 * 24 * 3600;

/// First line of the message the peer key signs to get a certificate.
pub const PROOF_CONTEXT: &str = "arkavo-peer-certificate-v1";

/// Longest peer audience.
pub const MAX_AUDIENCE_LEN: usize = 64;

/// A peer certificate's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCertificate {
    pub iss: String,
    /// The account's bare lowercase UUID, as in the passkey CWT.
    pub sub: String,
    /// The peer protocol the certificate is for.
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub cti: [u8; 16],
    /// The peer key (P-256).
    pub x: [u8; 32],
    pub y: [u8; 32],
    /// When the account last asserted its passkey.
    pub auth_time: i64,
    /// The account's permanent handle (`alice.arkavo.social`), lowercase.
    pub handle: String,
}

/// Whether `s` is shaped like a peer audience: 1 to [`MAX_AUDIENCE_LEN`]
/// ASCII letters, digits, `.`, `_`, `:` or `-`. No newline, so it is one
/// line of the proof message.
pub fn is_audience(s: &str) -> bool {
    (1..=MAX_AUDIENCE_LEN).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// The message the peer key signs to get a certificate: the context, the
/// auth CWT's `sub` and `cti`, the audience and the key as sent. The `cti`
/// ties it to one sign-in; the audience keeps it from being used for
/// another protocol.
pub fn proof_message(sub: &str, cti: &[u8], audience: &str, cnf_key: &str) -> String {
    format!(
        "{PROOF_CONTEXT}\n{sub}\n{}\n{audience}\n{cnf_key}",
        URL_SAFE_NO_PAD.encode(cti)
    )
}

/// Whether `proof` is the unpadded base64url raw r‖s (64 bytes, never DER)
/// ES256 signature by the key `(x, y)` over `message`.
pub fn proof_verifies(x: &[u8; 32], y: &[u8; 32], message: &str, proof: &str) -> bool {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(proof) else {
        return false;
    };
    if bytes.len() != 64 {
        return false;
    }
    let Ok(signature) = Signature::from_slice(&bytes) else {
        return false;
    };
    let point = p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
    let Ok(key) = VerifyingKey::from_encoded_point(&point) else {
        return false;
    };
    key.verify(message.as_bytes(), &signature).is_ok()
}

/// Sign `c` with `key` under `kid`: the tag-61 CWT bytes.
pub fn mint(c: &PeerCertificate, key: &SigningKey, kid: &[u8]) -> Result<Vec<u8>, CwtError> {
    let int = |n: i64| Value::Integer(n.into());
    // Deterministic order: integer keys ascending, then text keys by encoded
    // length (`auth_time` is shorter than `arkavo_handle`).
    let payload = Value::Map(vec![
        (int(1), Value::Text(c.iss.clone())),
        (int(2), Value::Text(c.sub.clone())),
        (int(3), Value::Text(c.aud.clone())),
        (int(4), int(c.exp)),
        (int(6), int(c.iat)),
        (int(7), Value::Bytes(c.cti.to_vec())),
        (int(8), cnf_cbor(&c.x, &c.y)),
        (Value::Text(AUTH_TIME_CLAIM.into()), int(c.auth_time)),
        (
            Value::Text(HANDLE_CLAIM.into()),
            Value::Text(c.handle.clone()),
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

/// The checks a peer makes before the live proof, as a reference: the tag,
/// ES256, the content type, a `kid` in `keys`, the signature, exactly the
/// payload keys above, `iss` and `aud` as expected, a lifetime of at most
/// [`MAX_LIFETIME_SECONDS`], and `iat`/`exp` within `skew_secs` of `now`.
/// Identity never accepts a certificate; this exists to pin the format.
///
/// It does not prove the presenter holds the key: the peer protocol does
/// that with a fresh challenge.
pub fn verify(
    bytes: &[u8],
    keys: &crate::keys::KeySet,
    expected_iss: &str,
    expected_aud: &str,
    now: i64,
    skew_secs: i64,
) -> Result<PeerCertificate, CwtError> {
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
    let c = parse_payload(sign1.payload.as_deref().ok_or(CwtError::Malformed)?)?;
    if c.iss != expected_iss {
        return Err(CwtError::IssuerMismatch);
    }
    if c.aud != expected_aud {
        return Err(CwtError::AudienceMismatch);
    }
    if c.iat > c.exp || c.exp - c.iat > MAX_LIFETIME_SECONDS {
        return Err(CwtError::Malformed);
    }
    if c.exp <= now - skew_secs {
        return Err(CwtError::Expired);
    }
    if c.iat > now + skew_secs {
        return Err(CwtError::NotYetValid);
    }
    Ok(c)
}

fn parse_payload(bytes: &[u8]) -> Result<PeerCertificate, CwtError> {
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

    let cti: [u8; 16] = get(&int_key(7))?
        .as_bytes()
        .and_then(|b| b.as_slice().try_into().ok())
        .ok_or(CwtError::Malformed)?;
    let (x, y) = parse_cnf(get(&int_key(8))?)?;
    Ok(PeerCertificate {
        iss: text(get(&int_key(1))?)?,
        sub: text(get(&int_key(2))?)?,
        aud: text(get(&int_key(3))?)?,
        exp: number(get(&int_key(4))?)?,
        iat: number(get(&int_key(6))?)?,
        cti,
        x,
        y,
        auth_time: number(get(&Value::Text(AUTH_TIME_CLAIM.into()))?)?,
        handle: text(get(&Value::Text(HANDLE_CLAIM.into()))?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner_kas_token::{self, OwnerKasToken};
    use p256::elliptic_curve::rand_core::OsRng;

    const KID: &[u8] = b"peer-test-kid";
    const ISS: &str = "https://identity.example";
    const AUD: &str = "example-game:peer";

    /// A fresh peer key: the signer, its coordinates and the request string.
    fn peer_key() -> (SigningKey, [u8; 32], [u8; 32], String) {
        let sk = SigningKey::random(&mut OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        let b64 = URL_SAFE_NO_PAD.encode(point.as_bytes());
        let (x, y) = ((*point.x().unwrap()).into(), (*point.y().unwrap()).into());
        (sk, x, y, b64)
    }

    fn sample(now: i64) -> PeerCertificate {
        let (_, x, y, _) = peer_key();
        PeerCertificate {
            iss: ISS.into(),
            sub: "0a1b2c3d-0000-4000-8000-000000000001".into(),
            aud: AUD.into(),
            iat: now,
            exp: now + MAX_LIFETIME_SECONDS,
            cti: [9; 16],
            x,
            y,
            auth_time: now - 7_200,
            handle: "alice.arkavo.social".into(),
        }
    }

    fn signer() -> (SigningKey, crate::keys::KeySet) {
        let sk = SigningKey::random(&mut OsRng);
        let set = crate::keys::KeySet::new(*sk.verifying_key(), KID.to_vec());
        (sk, set)
    }

    fn raw_signature(sk: &SigningKey, message: &str) -> String {
        let sig: Signature = sk.sign(message.as_bytes());
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }

    #[test]
    fn audiences_are_short_ascii_labels() {
        for ok in ["example-game:peer", "a", "Game.v2_peer", &"a".repeat(64)] {
            assert!(is_audience(ok), "{ok:?}");
        }
        for bad in [
            "",
            &"a".repeat(65),
            "has space",
            "line\nbreak",
            "comma,separated",
            "https://example.com/peer",
            "naïve",
        ] {
            assert!(!is_audience(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_minted_certificate_verifies_and_round_trips() {
        let (sk, set) = signer();
        let now = 1_760_000_000;
        let c = sample(now);
        let bytes = mint(&c, &sk, KID).unwrap();
        assert!(bytes.starts_with(&CWT_TAG_PREFIX));
        assert_eq!(verify(&bytes, &set, ISS, AUD, now + 10, 60).unwrap(), c);
    }

    #[test]
    fn the_payload_is_exactly_the_contract_in_deterministic_order() {
        let (sk, _) = signer();
        let c = sample(1_760_000_000);
        let bytes = mint(&c, &sk, KID).unwrap();
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
        // Exactly these nine, in this order: no entitlement, Patreon or
        // email claim can ride along.
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
                &Value::Text("auth_time".into()),
                &Value::Text("arkavo_handle".into()),
            ]
        );
        assert_eq!(entries[2].1, Value::Text(AUD.into()), "aud is one string");
        assert_eq!(
            entries[6].1,
            Value::Map(vec![(
                int(1),
                Value::Map(vec![
                    (int(1), int(2)),
                    (int(-1), int(1)),
                    (int(-2), Value::Bytes(c.x.to_vec())),
                    (int(-3), Value::Bytes(c.y.to_vec())),
                ])
            )])
        );
        assert_eq!(entries[7].1, int(c.auth_time));
        // RFC 8949 §4.2.1: each key's encoding sorts bytewise after the one
        // before it.
        let encoded: Vec<Vec<u8>> = keys
            .iter()
            .map(|k| {
                let mut b = Vec::new();
                ciborium::ser::into_writer(k, &mut b).unwrap();
                b
            })
            .collect();
        assert!(encoded.windows(2).all(|w| w[0] < w[1]), "{encoded:?}");
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
        // Nor is it an owner-KAS token.
        assert!(matches!(
            owner_kas_token::verify(&bytes, &set, now, 60),
            Err(CwtError::Malformed)
        ));
    }

    #[test]
    fn other_tokens_are_not_peer_certificates() {
        let (sk, set) = signer();
        let now = chrono::Utc::now().timestamp();
        let session = crate::cwt::ArkavoClaims::auth(ISS, "u", 1, None);
        let bytes = crate::cwt::mint(&session, &sk, KID).unwrap();
        assert!(matches!(
            verify(&bytes, &set, ISS, AUD, now, 60),
            Err(CwtError::Malformed)
        ));

        let c = sample(now);
        let owner_kas = owner_kas_token::mint(
            &OwnerKasToken {
                iss: ISS.into(),
                sub: c.sub.clone(),
                route_id: "01JC0000000000000000000000".into(),
                iat: now,
                exp: now + owner_kas_token::LIFETIME_SECONDS,
                cti: [1; 16],
                x: c.x,
                y: c.y,
                handle: c.handle.clone(),
            },
            &sk,
            KID,
        )
        .unwrap();
        assert!(matches!(
            verify(&owner_kas, &set, ISS, AUD, now, 60),
            Err(CwtError::Malformed)
        ));
    }

    #[test]
    fn verification_enforces_key_signature_issuer_audience_and_time() {
        let (sk, set) = signer();
        let now = 1_760_000_000;
        let c = sample(now);
        let bytes = mint(&c, &sk, KID).unwrap();

        let other = crate::keys::KeySet::new(*sk.verifying_key(), b"another-kid".to_vec());
        assert!(matches!(
            verify(&bytes, &other, ISS, AUD, now, 60),
            Err(CwtError::UnknownKey)
        ));

        let (wrong, _) = signer();
        let forged = mint(&c, &wrong, KID).unwrap();
        assert!(matches!(
            verify(&forged, &set, ISS, AUD, now, 60),
            Err(CwtError::InvalidSignature)
        ));

        assert!(matches!(
            verify(&bytes, &set, "https://other.example", AUD, now, 60),
            Err(CwtError::IssuerMismatch)
        ));
        assert!(matches!(
            verify(&bytes, &set, ISS, "another-game:peer", now, 60),
            Err(CwtError::AudienceMismatch)
        ));

        assert!(verify(&bytes, &set, ISS, AUD, c.exp + 59, 60).is_ok());
        assert!(matches!(
            verify(&bytes, &set, ISS, AUD, c.exp + 60, 60),
            Err(CwtError::Expired)
        ));
        assert!(matches!(
            verify(&bytes, &set, ISS, AUD, now - 61, 60),
            Err(CwtError::NotYetValid)
        ));

        // Longer than the cap is refused whatever the issuer was configured
        // with.
        let long = PeerCertificate {
            exp: now + MAX_LIFETIME_SECONDS + 1,
            ..c.clone()
        };
        assert!(matches!(
            verify(&mint(&long, &sk, KID).unwrap(), &set, ISS, AUD, now, 60),
            Err(CwtError::Malformed)
        ));

        let untagged = &bytes[CWT_TAG_PREFIX.len()..];
        assert!(verify(untagged, &set, ISS, AUD, now, 60).is_err());
    }

    #[test]
    fn the_proof_message_is_five_lines() {
        assert_eq!(
            proof_message("sub-uuid", &[0xfb, 0xff], "example-game:peer", "KEY"),
            "arkavo-peer-certificate-v1\nsub-uuid\n-_8\nexample-game:peer\nKEY"
        );
    }

    #[test]
    fn the_proof_binds_key_sign_in_audience_and_encoding() {
        let (sk, x, y, key) = peer_key();
        let sub = "0a1b2c3d-0000-4000-8000-000000000001";
        let cti = [7u8; 16];
        let message = proof_message(sub, &cti, AUD, &key);
        let proof = raw_signature(&sk, &message);
        assert!(proof_verifies(&x, &y, &message, &proof));

        // Another key's signature.
        let (other_sk, ox, oy, _) = peer_key();
        assert!(!proof_verifies(
            &x,
            &y,
            &message,
            &raw_signature(&other_sk, &message)
        ));
        assert!(!proof_verifies(&ox, &oy, &message, &proof));
        // Another sign-in, account or audience.
        for other in [
            proof_message(sub, &[8u8; 16], AUD, &key),
            proof_message("0a1b2c3d-0000-4000-8000-000000000002", &cti, AUD, &key),
            proof_message(sub, &cti, "another-game:peer", &key),
        ] {
            assert!(!proof_verifies(&x, &y, &other, &proof));
        }
        // DER, padded and standard base64 are refused.
        let sig: Signature = sk.sign(message.as_bytes());
        let der = URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes());
        assert!(!proof_verifies(&x, &y, &message, &der));
        assert!(!proof_verifies(&x, &y, &message, &format!("{proof}=")));
        assert!(!proof_verifies(&x, &y, &message, ""));
    }
}
