//! Passkey credential attestations (#104): the IdP's signed statement that a
//! passkey credential belonged to an Arkavo account.
//!
//! Catalog v2 (tdf-iroh-s3#27) has a creator sign a catalog pointer with
//! their passkey. Viewers and the node learn which account the passkey
//! belongs to from this record, without trusting the node. The wire format is
//! [docs/passkey-credential-attestation.md](../docs/passkey-credential-attestation.md):
//!
//! - COSE_Sign1 (tag 18, never the CWT tag 61), ES256, empty external AAD.
//! - Protected header: `alg` ES256, `kid` (a key in `/.well-known/cose-keys`),
//!   `content type` (label 3) = [`CONTENT_TYPE`]. CWTs carry no content type.
//! - Payload: a CBOR map with exactly seven text keys: `typ` ([`TYP`]),
//!   `iss`, `sub`, `credentialId` (bytes), `publicKey` (COSE_Key: kty EC2,
//!   crv P-256, x, y), `rpId`, `iat`.
//!
//! It has no `exp`: it says the credential belonged to `sub` at `iat`, and a
//! pointer signed later, while the creator is offline, must still verify.
//! Revocation is the status route's job. It must never verify as a CWT:
//! `cwt::verify` refuses it three ways (no tag 61, a content type, a `typ`
//! claim), and it has no `aud`, `exp` or `scope` besides.

use crate::cwt::CwtError;
use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable, iana};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};

/// The payload's `typ`. Every CWT verifier refuses a payload carrying it.
pub const TYP: &str = "arkavo-passkey-credential";

/// The protected header's `content type` (label 3).
pub const CONTENT_TYPE: &str = "application/arkavo-passkey-credential+cbor";

/// The payload's keys, in the order they are written.
const KEYS: [&str; 7] = [
    "typ",
    "iss",
    "sub",
    "credentialId",
    "publicKey",
    "rpId",
    "iat",
];

/// A credential attestation's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialAttestation {
    pub iss: String,
    /// The account's `sub`, exactly as in its CWTs (the bare account UUID
    /// of the passkey auth CWT).
    pub sub: String,
    pub credential_id: Vec<u8>,
    /// The credential's P-256 public key, as stored at registration.
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub rp_id: String,
    pub iat: i64,
}

/// The credential's public key as a COSE_Key: kty, crv, x and y only.
fn public_key_cbor(x: &[u8; 32], y: &[u8; 32]) -> Value {
    Value::Map(vec![
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
    ])
}

/// Sign `a` with `key` under `kid`: the tagged COSE_Sign1 bytes.
pub fn mint(a: &CredentialAttestation, key: &SigningKey, kid: &[u8]) -> Result<Vec<u8>, CwtError> {
    let payload = Value::Map(vec![
        (Value::Text("typ".into()), Value::Text(TYP.into())),
        (Value::Text("iss".into()), Value::Text(a.iss.clone())),
        (Value::Text("sub".into()), Value::Text(a.sub.clone())),
        (
            Value::Text("credentialId".into()),
            Value::Bytes(a.credential_id.clone()),
        ),
        (Value::Text("publicKey".into()), public_key_cbor(&a.x, &a.y)),
        (Value::Text("rpId".into()), Value::Text(a.rp_id.clone())),
        (Value::Text("iat".into()), Value::Integer(a.iat.into())),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&payload, &mut bytes).map_err(|_| CwtError::Malformed)?;

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(kid.to_vec())
        .content_type(CONTENT_TYPE.to_string())
        .build();
    CoseSign1Builder::new()
        .protected(protected)
        .payload(bytes)
        .create_signature(b"", |to_sign| {
            let sig: Signature = key.sign(to_sign);
            sig.to_bytes().to_vec()
        })
        .build()
        .to_tagged_vec()
        .map_err(|_| CwtError::Malformed)
}

/// Verify an attestation's signature and shape against `key`, as a consumer
/// would (tdf-iroh-s3, Creator, arkavo-ios implement the same rules; this
/// one pins them in tests). Accepts tag 18 or untagged; refuses the CWT tag.
/// Checking `iss`, `rpId` and `sub` against expectations is the caller's.
pub fn verify(bytes: &[u8], key: &VerifyingKey) -> Result<CredentialAttestation, CwtError> {
    if bytes.starts_with(&crate::cwt::CWT_TAG_PREFIX) {
        return Err(CwtError::Malformed);
    }
    let sign1 = coset::CoseSign1::from_tagged_slice(bytes)
        .or_else(|_| coset::CoseSign1::from_slice(bytes))
        .map_err(|_| CwtError::Malformed)?;
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
    sign1
        .verify_signature(b"", |sig_bytes, to_verify| {
            let sig = Signature::from_slice(sig_bytes).map_err(|_| ())?;
            key.verify(to_verify, &sig).map_err(|_| ())
        })
        .map_err(|_| CwtError::InvalidSignature)?;
    let payload = sign1.payload.as_ref().ok_or(CwtError::Malformed)?;
    parse_payload(payload)
}

fn parse_payload(bytes: &[u8]) -> Result<CredentialAttestation, CwtError> {
    let value: Value = ciborium::de::from_reader(bytes).map_err(|_| CwtError::Malformed)?;
    let Value::Map(entries) = value else {
        return Err(CwtError::Malformed);
    };
    // Exactly the seven keys, each once.
    if entries.len() != KEYS.len() {
        return Err(CwtError::Malformed);
    }
    let get = |name: &str| {
        let mut found = entries
            .iter()
            .filter(|(k, _)| matches!(k, Value::Text(t) if t == name));
        match (found.next(), found.next()) {
            (Some((_, v)), None) => Ok(v),
            _ => Err(CwtError::Malformed),
        }
    };
    let text = |name: &str| match get(name)? {
        Value::Text(t) => Ok(t.clone()),
        _ => Err(CwtError::Malformed),
    };
    if text("typ")? != TYP {
        return Err(CwtError::Malformed);
    }
    let credential_id = match get("credentialId")? {
        Value::Bytes(b) if !b.is_empty() => b.clone(),
        _ => return Err(CwtError::Malformed),
    };
    let iat = match get("iat")? {
        Value::Integer(i) => i64::try_from(i128::from(*i)).map_err(|_| CwtError::Malformed)?,
        _ => return Err(CwtError::Malformed),
    };
    let (x, y) = parse_public_key(get("publicKey")?)?;
    Ok(CredentialAttestation {
        iss: text("iss")?,
        sub: text("sub")?,
        credential_id,
        x,
        y,
        rp_id: text("rpId")?,
        iat,
    })
}

fn parse_public_key(v: &Value) -> Result<([u8; 32], [u8; 32]), CwtError> {
    let Value::Map(entries) = v else {
        return Err(CwtError::Malformed);
    };
    let get = |label: i64| {
        let mut found = entries
            .iter()
            .filter(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == label as i128));
        match (found.next(), found.next()) {
            (Some((_, v)), None) => Ok(v),
            _ => Err(CwtError::Malformed),
        }
    };
    let int = |label: i64| match get(label)? {
        Value::Integer(i) => Ok(i128::from(*i)),
        _ => Err(CwtError::Malformed),
    };
    let coord = |label: i64| match get(label)? {
        Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).map_err(|_| CwtError::Malformed),
        _ => Err(CwtError::Malformed),
    };
    if int(iana::KeyParameter::Kty as i64)? != iana::KeyType::EC2 as i128
        || int(iana::Ec2KeyParameter::Crv as i64)? != iana::EllipticCurve::P_256 as i128
    {
        return Err(CwtError::UnsupportedKeyType);
    }
    let x = coord(iana::Ec2KeyParameter::X as i64)?;
    let y = coord(iana::Ec2KeyParameter::Y as i64)?;
    // The point must be on the curve.
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&x);
    sec1[33..].copy_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| CwtError::UnsupportedKeyType)?;
    Ok((x, y))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::rand_core::OsRng;

    fn sample(credential_key: &VerifyingKey) -> CredentialAttestation {
        let point = credential_key.to_encoded_point(false);
        CredentialAttestation {
            iss: "https://identity.arkavo.net".into(),
            sub: "0a1b2c3d-0000-4000-8000-000000000001".into(),
            credential_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
            x: (*point.x().unwrap()).into(),
            y: (*point.y().unwrap()).into(),
            rp_id: "identity.arkavo.net".into(),
            iat: 1_760_000_000,
        }
    }

    fn keys() -> (SigningKey, VerifyingKey, CredentialAttestation) {
        let sk = SigningKey::random(&mut OsRng);
        let vk = *sk.verifying_key();
        let cred = SigningKey::random(&mut OsRng);
        (sk, vk, sample(cred.verifying_key()))
    }

    /// The fixed inputs of the golden vector (shared with tdf-iroh-s3's
    /// fixture): IdP key scalar 0x42 * 32, credential key scalar 0x07 * 32.
    fn golden() -> (SigningKey, CredentialAttestation) {
        let sk = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let cred = SigningKey::from_slice(&[0x07; 32]).unwrap();
        let mut a = sample(cred.verifying_key());
        a.credential_id = (0u8..16).collect();
        (sk, a)
    }

    const GOLDEN_KID: &[u8] = b"arkavo-fixture-kid-1";

    /// The exact bytes the encoder produces for [`golden`]: ES256 here is
    /// deterministic (RFC 6979), so any change to the encoding shows up as a
    /// diff. tdf-iroh-s3 verifies this same vector; changing it breaks them.
    const GOLDEN_ATTESTATION: &str = "d2845846a3012603782a6170706c69636174696f6e2f61726b61766f2d706173736b65792d63726564656e7469616c2b63626f72045461726b61766f2d666978747572652d6b69642d31a0590100a763747970781961726b61766f2d706173736b65792d63726564656e7469616c63697373781b68747470733a2f2f6964656e746974792e61726b61766f2e6e657463737562782430613162326333642d303030302d343030302d383030302d3030303030303030303030316c63726564656e7469616c496450000102030405060708090a0b0c0d0e0f697075626c69634b6579a4010220012158201e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896e225820a46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a36472704964736964656e746974792e61726b61766f2e6e6574636961741a68e778005840f568be35ab831986618bee8fc0b863cbb02169a3b8e870cc4a02a96982387707e21a8551a68a3f9c7349042b24bde95cba23692298a8df9760407c49d5821557";

    #[test]
    fn golden_vector() {
        let (sk, a) = golden();
        let bytes = mint(&a, &sk, GOLDEN_KID).unwrap();
        assert_eq!(hex::encode(&bytes), GOLDEN_ATTESTATION);
        let issuer = sk.verifying_key().to_encoded_point(false);
        assert_eq!(
            hex::encode(issuer.as_bytes()),
            "043ad3861a95621392516bb593ef05583ed2e5866f5cb6260a3017237fd89b90af\
             d0961c7e37075a6791a39c61f56295b02b6d26567b615e60aa41ee1c8e83388d"
        );
        let parsed = verify(
            &hex::decode(GOLDEN_ATTESTATION).unwrap(),
            sk.verifying_key(),
        )
        .unwrap();
        assert_eq!(parsed, a);
        assert_eq!(
            hex::encode(parsed.x),
            "1e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896e"
        );
        assert_eq!(
            hex::encode(parsed.y),
            "a46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3"
        );
    }

    #[test]
    fn roundtrip() {
        let (sk, vk, a) = keys();
        let bytes = mint(&a, &sk, b"kid").unwrap();
        assert_eq!(verify(&bytes, &vk).unwrap(), a);
    }

    /// The layout tdf-iroh-s3 verifies, byte by byte where it matters.
    #[test]
    fn wire_layout() {
        let (sk, _, a) = keys();
        let bytes = mint(&a, &sk, b"the-kid").unwrap();
        // COSE_Sign1 tag 18 (0xD2), never the CWT tag 61.
        assert_eq!(bytes[0], 0xD2);
        let sign1 = coset::CoseSign1::from_tagged_slice(&bytes).unwrap();
        let h = &sign1.protected.header;
        assert_eq!(
            h.alg,
            Some(coset::Algorithm::Assigned(iana::Algorithm::ES256))
        );
        assert_eq!(h.key_id, b"the-kid");
        assert_eq!(
            h.content_type,
            Some(coset::ContentType::Text(CONTENT_TYPE.into()))
        );
        assert!(h.crit.is_empty());
        assert!(sign1.unprotected.is_empty());

        let payload: Value = ciborium::de::from_reader(sign1.payload.as_deref().unwrap()).unwrap();
        let Value::Map(entries) = payload else {
            panic!("payload is not a map")
        };
        let names: Vec<&str> = entries
            .iter()
            .map(|(k, _)| k.as_text().expect("text key"))
            .collect();
        assert_eq!(names, KEYS);
        let field = |n: &str| {
            &entries
                .iter()
                .find(|(k, _)| k.as_text() == Some(n))
                .unwrap()
                .1
        };
        assert_eq!(field("typ").as_text(), Some(TYP));
        assert_eq!(field("credentialId").as_bytes(), Some(&a.credential_id));
        assert_eq!(
            field("iat").as_integer().map(i128::from),
            Some(1_760_000_000)
        );
        let Value::Map(pk) = field("publicKey") else {
            panic!("publicKey is not a map")
        };
        let labels: Vec<i128> = pk
            .iter()
            .map(|(k, _)| i128::from(k.as_integer().unwrap()))
            .collect();
        // kty, crv, x, y; no alg, no kid.
        assert_eq!(labels, [1, -1, -2, -3]);
        assert_eq!(pk[0].1.as_integer().map(i128::from), Some(2));
        assert_eq!(pk[1].1.as_integer().map(i128::from), Some(1));
    }

    #[test]
    fn untagged_is_accepted() {
        let (sk, vk, a) = keys();
        let tagged = mint(&a, &sk, b"kid").unwrap();
        let untagged = coset::CoseSign1::from_tagged_slice(&tagged)
            .unwrap()
            .to_vec()
            .unwrap();
        assert_eq!(verify(&untagged, &vk).unwrap(), a);
    }

    #[test]
    fn wrong_key_is_refused() {
        let (sk, _, a) = keys();
        let bytes = mint(&a, &sk, b"kid").unwrap();
        let other = *SigningKey::random(&mut OsRng).verifying_key();
        assert!(matches!(
            verify(&bytes, &other),
            Err(CwtError::InvalidSignature)
        ));
    }

    /// The point of the separate format: an attestation is never a token,
    /// even re-wrapped in the CWT tag and fed to the CWT verifier with the
    /// key that signed it.
    #[test]
    fn never_verifies_as_a_cwt() {
        let (sk, vk, a) = keys();
        let bytes = mint(&a, &sk, b"kid").unwrap();
        let opts = crate::cwt::VerifyOptions {
            expected_iss: None,
            expected_aud: None,
            now: a.iat,
            skew_secs: crate::cwt::DEFAULT_SKEW_SECS,
        };
        assert!(crate::cwt::verify(&bytes, &vk, &opts).is_err());

        let untagged = coset::CoseSign1::from_tagged_slice(&bytes)
            .unwrap()
            .to_vec()
            .unwrap();
        let mut as_cwt = crate::cwt::CWT_TAG_PREFIX.to_vec();
        as_cwt.extend_from_slice(&untagged);
        assert!(crate::cwt::verify(&as_cwt, &vk, &opts).is_err());
        // And the verifier here refuses the CWT tag.
        assert!(verify(&as_cwt, &vk).is_err());
    }

    #[test]
    fn a_cwt_never_verifies_as_an_attestation() {
        let sk = SigningKey::random(&mut OsRng);
        let vk = *sk.verifying_key();
        let claims = crate::cwt::ArkavoClaims::auth("https://identity.arkavo.net", "u", 1, None);
        let token = crate::cwt::mint(&claims, &sk, b"kid").unwrap();
        let inner = crate::cwt::strip_cwt_tag(&token).unwrap();
        assert!(verify(inner, &vk).is_err());
    }
}
