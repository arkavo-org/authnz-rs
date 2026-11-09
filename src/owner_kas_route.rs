//! Owner-KAS route records (#148): the passkey-signed statement of where an
//! owner's KAS answers, stored at identity so account deletion reaches it.
//!
//! The owner's phone `PUT`s a bundle (arkavo-ios design §4.3):
//!
//! ```text
//! { "record": b64url, "credential": b64url,
//!   "assertion": { "credentialId", "authenticatorData", "clientDataJSON", "signature" } }
//! ```
//!
//! every value unpadded base64url. `record` is a deterministic CBOR map
//! (RFC 8949 §4.2.1) with exactly the text keys `v` (1), `route_id`,
//! `owner_sub`, `kas_key`, `kas_kid`, `service_key`, `seq` and `issued_at`.
//! `assertion` is a WebAuthn assertion whose challenge is SHA-256 of the
//! record bytes, and `credential` is identity's credential attestation of the
//! passkey that made it (`credential_attestation`). Identity checks the
//! assertion itself: webauthn-rs only verifies a challenge it issued.

use crate::owner_kas_token::is_route_id;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::Value;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Largest `PUT` body.
pub const MAX_BUNDLE_BYTES: usize = 8 * 1024;

/// Largest `seq`: 2^53 − 1, so a JavaScript or JSON reader holds it exactly.
pub const MAX_SEQ: u64 = (1 << 53) - 1;

/// Longest `kas_kid`, in bytes.
const MAX_KAS_KID_BYTES: usize = 256;

/// The flags an assertion must carry: user present (UP) and verified (UV).
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

/// The bundle, as put and as returned by the mint. Unknown members are
/// refused, so what is stored is exactly what was signed for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteBundle {
    pub record: String,
    pub assertion: RouteAssertion,
    pub credential: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteAssertion {
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
}

/// A parsed route record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRecord {
    pub route_id: String,
    /// The owner's bare lowercase account UUID.
    pub owner_sub: String,
    pub kas_key: Vec<u8>,
    pub kas_kid: String,
    pub service_key: Vec<u8>,
    pub seq: u64,
    pub issued_at: i64,
}

/// Why a bundle was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    /// Not base64url, or not the bundle's shape.
    Malformed,
    /// The record is not exactly the agreed map, or not deterministic CBOR.
    InvalidRecord(&'static str),
    /// The assertion does not verify.
    InvalidAssertion(&'static str),
}

/// Strict unpadded base64url.
pub fn b64(s: &str) -> Result<Vec<u8>, RouteError> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| RouteError::Malformed)
}

fn is_point(bytes: &[u8]) -> bool {
    bytes.len() == 65 && bytes[0] == 0x04 && p256::PublicKey::from_sec1_bytes(bytes).is_ok()
}

fn is_bare_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|u| u.hyphenated().to_string() == s)
}

/// Parse `bytes` as a route record: a deterministic CBOR map with exactly the
/// agreed keys, each well formed. It does not compare `route_id` or
/// `owner_sub` with anything.
pub fn parse_record(bytes: &[u8]) -> Result<RouteRecord, RouteError> {
    use RouteError::InvalidRecord as Bad;
    let value: Value = ciborium::de::from_reader(bytes).map_err(|_| Bad("not CBOR"))?;
    // Deterministic: re-encoding gives the same bytes (shortest forms, no
    // trailing data) and the keys are in bytewise order of their encodings.
    let mut again = Vec::new();
    ciborium::ser::into_writer(&value, &mut again).map_err(|_| Bad("not CBOR"))?;
    if again != bytes {
        return Err(Bad("not deterministic CBOR"));
    }
    let Value::Map(entries) = value else {
        return Err(Bad("not a map"));
    };
    let encoded_keys: Vec<Vec<u8>> = entries
        .iter()
        .map(|(k, _)| {
            let mut b = Vec::new();
            ciborium::ser::into_writer(k, &mut b).map(|_| b)
        })
        .collect::<Result<_, _>>()
        .map_err(|_| Bad("not CBOR"))?;
    if !encoded_keys.windows(2).all(|w| w[0] < w[1]) {
        return Err(Bad("keys not in deterministic order"));
    }
    const KEYS: [&str; 8] = [
        "v",
        "route_id",
        "owner_sub",
        "kas_key",
        "kas_kid",
        "service_key",
        "seq",
        "issued_at",
    ];
    if entries.len() != KEYS.len()
        || !entries
            .iter()
            .all(|(k, _)| k.as_text().is_some_and(|t| KEYS.contains(&t)))
    {
        return Err(Bad("keys"));
    }
    let get = |key: &str| {
        entries
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
            .ok_or(Bad("keys"))
    };
    let int = |key: &'static str| -> Result<i128, RouteError> {
        get(key)?.as_integer().map(i128::from).ok_or(Bad(key))
    };

    if int("v")? != 1 {
        return Err(Bad("v"));
    }
    let route_id = get("route_id")?
        .as_text()
        .filter(|r| is_route_id(r))
        .ok_or(Bad("route_id"))?
        .to_string();
    let owner_sub = get("owner_sub")?
        .as_text()
        .filter(|s| is_bare_uuid(s))
        .ok_or(Bad("owner_sub"))?
        .to_string();
    let point = |key: &'static str| -> Result<Vec<u8>, RouteError> {
        get(key)?
            .as_bytes()
            .filter(|b| is_point(b))
            .cloned()
            .ok_or(Bad(key))
    };
    let kas_key = point("kas_key")?;
    let service_key = point("service_key")?;
    let kas_kid = get("kas_kid")?
        .as_text()
        .filter(|k| !k.is_empty() && k.len() <= MAX_KAS_KID_BYTES)
        .ok_or(Bad("kas_kid"))?
        .to_string();
    let seq = u64::try_from(int("seq")?)
        .ok()
        .filter(|s| (1..=MAX_SEQ).contains(s))
        .ok_or(Bad("seq"))?;
    let issued_at = i64::try_from(int("issued_at")?)
        .ok()
        .filter(|t| *t >= 0)
        .ok_or(Bad("issued_at"))?;
    Ok(RouteRecord {
        route_id,
        owner_sub,
        kas_key,
        kas_kid,
        service_key,
        seq,
        issued_at,
    })
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
}

/// Verify `assertion` as a WebAuthn assertion over SHA-256(`record`), for
/// `rp_id` and `origin`, with user presence and verification, under the
/// P-256 key `(x, y)`. The sign count is not checked: synced passkeys
/// report 0.
pub fn verify_assertion(
    record: &[u8],
    assertion: &RouteAssertion,
    rp_id: &str,
    origin: &str,
    x: &[u8; 32],
    y: &[u8; 32],
) -> Result<(), RouteError> {
    use RouteError::InvalidAssertion as Bad;
    let auth_data = b64(&assertion.authenticator_data)?;
    let client_data_json = b64(&assertion.client_data_json)?;
    let signature = b64(&assertion.signature)?;

    let client: ClientData =
        serde_json::from_slice(&client_data_json).map_err(|_| Bad("clientDataJSON"))?;
    if client.typ != "webauthn.get" {
        return Err(Bad("type"));
    }
    if client.challenge != URL_SAFE_NO_PAD.encode(Sha256::digest(record)) {
        return Err(Bad("challenge"));
    }
    if client.origin != origin || client.cross_origin == Some(true) {
        return Err(Bad("origin"));
    }

    // rpIdHash (32) ‖ flags (1) ‖ signCount (4) ‖ extensions…
    if auth_data.len() < 37 {
        return Err(Bad("authenticatorData"));
    }
    if auth_data[..32] != Sha256::digest(rp_id.as_bytes())[..] {
        return Err(Bad("rpIdHash"));
    }
    let flags = auth_data[32];
    if flags & FLAG_UP == 0 || flags & FLAG_UV == 0 {
        return Err(Bad("flags"));
    }

    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    let key = VerifyingKey::from_sec1_bytes(&point).map_err(|_| Bad("key"))?;
    let sig = Signature::from_der(&signature).map_err(|_| Bad("signature"))?;
    let mut signed = auth_data;
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    key.verify(&signed, &sig).map_err(|_| Bad("signature"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};
    use p256::elliptic_curve::rand_core::OsRng;

    const RP: &str = "identity.arkavo.net";
    const ORIGIN: &str = "https://identity.arkavo.net";
    const ROUTE: &str = "01JC5Z8Q4M7N2P3R6S9T0V1W2X";
    const OWNER: &str = "0a1b2c3d-0000-4000-8000-000000000001";

    fn point() -> Vec<u8> {
        SigningKey::random(&mut OsRng)
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// The record's entries, in any order; [`encode`] sorts them.
    fn entries(seq: u64) -> Vec<(Value, Value)> {
        let t = |s: &str| Value::Text(s.into());
        vec![
            (t("v"), Value::Integer(1.into())),
            (t("route_id"), t(ROUTE)),
            (t("owner_sub"), t(OWNER)),
            (t("kas_key"), Value::Bytes(point())),
            (t("kas_kid"), t("owner-kas-1")),
            (t("service_key"), Value::Bytes(point())),
            (t("seq"), Value::Integer(seq.into())),
            (t("issued_at"), Value::Integer(1_760_000_000.into())),
        ]
    }

    /// Deterministic CBOR of `entries`: keys sorted by their encodings.
    fn encode(mut entries: Vec<(Value, Value)>) -> Vec<u8> {
        let enc = |v: &Value| {
            let mut b = Vec::new();
            ciborium::ser::into_writer(v, &mut b).unwrap();
            b
        };
        entries.sort_by_key(|(k, _)| enc(k));
        enc(&Value::Map(entries))
    }

    fn sign(key: &SigningKey, client_data: serde_json::Value, flags: u8) -> RouteAssertion {
        let mut auth_data = Sha256::digest(RP.as_bytes()).to_vec();
        auth_data.push(flags);
        auth_data.extend_from_slice(&[0, 0, 0, 0]);
        let client_data_json = serde_json::to_vec(&client_data).unwrap();
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let sig: Signature = key.sign(&signed);
        RouteAssertion {
            credential_id: URL_SAFE_NO_PAD.encode([7u8; 16]),
            authenticator_data: URL_SAFE_NO_PAD.encode(&auth_data),
            client_data_json: URL_SAFE_NO_PAD.encode(&client_data_json),
            signature: URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes()),
        }
    }

    fn client_data(record: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "type": "webauthn.get",
            "challenge": URL_SAFE_NO_PAD.encode(Sha256::digest(record)),
            "origin": ORIGIN,
        })
    }

    fn coords(key: &SigningKey) -> ([u8; 32], [u8; 32]) {
        let p = key.verifying_key().to_encoded_point(false);
        ((*p.x().unwrap()).into(), (*p.y().unwrap()).into())
    }

    #[test]
    fn a_well_formed_record_parses() {
        let r = parse_record(&encode(entries(3))).unwrap();
        assert_eq!(r.route_id, ROUTE);
        assert_eq!(r.owner_sub, OWNER);
        assert_eq!(r.kas_kid, "owner-kas-1");
        assert_eq!(r.seq, 3);
        assert_eq!(r.issued_at, 1_760_000_000);
        assert_eq!(r.kas_key.len(), 65);
    }

    #[test]
    fn records_off_the_contract_are_refused() {
        let t = |s: &str| Value::Text(s.into());
        let with = |key: &str, v: Value| {
            let mut e = entries(1);
            e.iter_mut()
                .find(|(k, _)| k.as_text() == Some(key))
                .unwrap()
                .1 = v;
            encode(e)
        };
        let mut extra = entries(1);
        extra.push((t("extra"), Value::Integer(0.into())));
        let mut missing = entries(1);
        missing.retain(|(k, _)| k.as_text() != Some("kas_kid"));
        let mut unsorted = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries(1)), &mut unsorted).unwrap();
        let mut trailing = encode(entries(1));
        trailing.push(0);

        for (name, bytes) in [
            ("extra key", encode(extra)),
            ("missing key", encode(missing)),
            ("unsorted", unsorted),
            ("trailing byte", trailing),
            ("v 2", with("v", Value::Integer(2.into()))),
            (
                "lowercase route",
                with("route_id", t(&ROUTE.to_lowercase())),
            ),
            (
                "arkavo: sub",
                with("owner_sub", t(&format!("arkavo:{OWNER}"))),
            ),
            ("uppercase sub", with("owner_sub", t(&OWNER.to_uppercase()))),
            ("short key", with("kas_key", Value::Bytes(vec![4; 33]))),
            ("off-curve key", {
                let mut p = point();
                p[64] ^= 1;
                with("service_key", Value::Bytes(p))
            }),
            ("empty kid", with("kas_kid", t(""))),
            ("seq 0", with("seq", Value::Integer(0.into()))),
            (
                "seq 2^53",
                with("seq", Value::Integer((MAX_SEQ + 1).into())),
            ),
            (
                "negative time",
                with("issued_at", Value::Integer((-1).into())),
            ),
            ("not a map", {
                let mut b = Vec::new();
                ciborium::ser::into_writer(&Value::Array(vec![]), &mut b).unwrap();
                b
            }),
        ] {
            assert!(
                matches!(parse_record(&bytes), Err(RouteError::InvalidRecord(_))),
                "{name}"
            );
        }
        assert!(parse_record(&with("seq", Value::Integer(MAX_SEQ.into()))).is_ok());
    }

    #[test]
    fn an_assertion_over_the_record_verifies() {
        let key = SigningKey::random(&mut OsRng);
        let (x, y) = coords(&key);
        let record = encode(entries(1));
        let a = sign(&key, client_data(&record), FLAG_UP | FLAG_UV);
        assert_eq!(verify_assertion(&record, &a, RP, ORIGIN, &x, &y), Ok(()));
    }

    #[test]
    fn assertions_that_do_not_bind_the_record_are_refused() {
        let key = SigningKey::random(&mut OsRng);
        let (x, y) = coords(&key);
        let record = encode(entries(1));
        let other = encode(entries(2));
        let bad = |a: &RouteAssertion, why: &str| match verify_assertion(
            &record, a, RP, ORIGIN, &x, &y,
        ) {
            Err(RouteError::InvalidAssertion(got)) => assert_eq!(got, why),
            other => panic!("{why}: {other:?}"),
        };
        let cd = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v = client_data(&record);
            f(&mut v);
            v
        };

        bad(
            &sign(&key, client_data(&other), FLAG_UP | FLAG_UV),
            "challenge",
        );
        bad(
            &sign(
                &key,
                cd(&|v| v["type"] = "webauthn.create".into()),
                FLAG_UP | FLAG_UV,
            ),
            "type",
        );
        bad(
            &sign(
                &key,
                cd(&|v| v["origin"] = "https://evil.example".into()),
                FLAG_UP | FLAG_UV,
            ),
            "origin",
        );
        bad(
            &sign(
                &key,
                cd(&|v| v["crossOrigin"] = true.into()),
                FLAG_UP | FLAG_UV,
            ),
            "origin",
        );
        bad(&sign(&key, client_data(&record), FLAG_UP), "flags");
        bad(&sign(&key, client_data(&record), FLAG_UV), "flags");

        let wrong_key = SigningKey::random(&mut OsRng);
        bad(
            &sign(&wrong_key, client_data(&record), FLAG_UP | FLAG_UV),
            "signature",
        );

        let mut a = sign(&key, client_data(&record), FLAG_UP | FLAG_UV);
        let mut auth = b64(&a.authenticator_data).unwrap();
        auth[0] ^= 1;
        a.authenticator_data = URL_SAFE_NO_PAD.encode(&auth);
        bad(&a, "rpIdHash");

        let mut a = sign(&key, client_data(&record), FLAG_UP | FLAG_UV);
        a.signature = format!("{}=", a.signature);
        assert_eq!(
            verify_assertion(&record, &a, RP, ORIGIN, &x, &y),
            Err(RouteError::Malformed)
        );
    }

    #[test]
    fn the_bundle_refuses_unknown_members() {
        let ok = serde_json::json!({
            "record": "AA", "credential": "AA",
            "assertion": {"credentialId": "AA", "authenticatorData": "AA",
                          "clientDataJSON": "AA", "signature": "AA"}
        });
        assert!(serde_json::from_value::<RouteBundle>(ok.clone()).is_ok());
        let mut extra = ok.clone();
        extra["seq"] = 1.into();
        assert!(serde_json::from_value::<RouteBundle>(extra).is_err());
        let mut extra = ok;
        extra["assertion"]["userHandle"] = "AA".into();
        assert!(serde_json::from_value::<RouteBundle>(extra).is_err());
    }
}
