//! Game-server tokens (#151): the credential an app presents to a game
//! server on the internet.
//!
//! The passkey auth CWT's audience is shared by every service, so a game
//! server cannot pin it. This token is for one game server (`aud`), bound to
//! the passkey session's device key (`cnf`), and carries the account, its
//! handle and, while the account holds the pass, the online-play
//! entitlement. The game server requires each request to be signed with the
//! `cnf` key ([`request_message`]). Contract: `docs/game-token.md`.
//!
//! Wire format:
//!
//! - CBOR tag 61 (CWT) around a COSE_Sign1, ES256, empty external AAD.
//! - Protected header: `alg` ES256, `kid` (a key in `/.well-known/cose-keys`),
//!   `content type` (label 3) = [`CONTENT_TYPE`]. `cwt::verify` refuses any
//!   content type, so identity never takes it for a session token.
//! - Payload: a CBOR map with exactly these keys, in deterministic order
//!   (RFC 8949 §4.2.1): `iss` (1), `sub` (2, the account's bare lowercase
//!   UUID), `aud` (3, one game server), `exp` (4), `iat` (6), `cti` (7, 16
//!   bytes), `cnf` (8, `{1: COSE_Key {1: 2, -1: 1, -2: x, -3: y}}`),
//!   `arkavo_handle`, and `arkavo_entitlements` (an array of the one
//!   online-play FQN) only while the account holds the pass.
//!
//! Nothing else: no other entitlement, Patreon data or email.

use crate::constants::ENTITLEMENT_ONLINE_PLAY;
use crate::cwt::{CWT_TAG_PREFIX, CwtError, strip_cwt_tag};
use crate::owner_kas_token::{HANDLE_CLAIM, cnf_cbor, parse_cnf};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, iana};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use sha2::{Digest, Sha256};

/// The protected header's `content type` (label 3).
pub const CONTENT_TYPE: &str = "application/game+cwt";

/// The payload key of the entitlement list, as in every other token.
pub const ENTITLEMENTS_CLAIM: &str = "arkavo_entitlements";

/// The longest `exp - iat` identity mints and a game server accepts. The
/// entitlement may ride only in tokens that expire within an hour.
pub const MAX_LIFETIME_SECONDS: i64 = 3600;

/// First line of the message the device key signs to get a token.
pub const MINT_CONTEXT: &str = "arkavo-game-token-v1";

/// First line of the message the `cnf` key signs for each request to the
/// game server.
pub const REQUEST_CONTEXT: &str = "arkavo-game-request-v1";

/// First line of the message the device key signs to open a game session.
pub const SESSION_OPEN_CONTEXT: &str = "arkavo-game-session-open-v1";

/// First line of the message the device key signs to get a token from a
/// game session.
pub const SESSION_MINT_CONTEXT: &str = "arkavo-game-session-token-v1";

/// First line of the message the device key signs to end a game session.
pub const SESSION_END_CONTEXT: &str = "arkavo-game-session-end-v1";

/// Domain separator of the game session id's hash of the passkey session id.
const GAME_SESSION_ID_CONTEXT: &[u8] = b"arkavo-game-session-id-v1";

/// Longest game audience.
pub const MAX_AUDIENCE_LEN: usize = 128;

/// A game-server token's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameToken {
    pub iss: String,
    /// The account's bare lowercase UUID, as in the passkey CWT.
    pub sub: String,
    /// The game server the token is for.
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub cti: [u8; 16],
    /// The session's device key (P-256).
    pub x: [u8; 32],
    pub y: [u8; 32],
    /// The account's permanent handle (`alice.arkavo.social`), lowercase.
    pub handle: String,
    /// Whether the account holds the pass: the token then carries the
    /// online-play entitlement, and otherwise no entitlement claim at all.
    pub online_play: bool,
}

/// Whether `s` is shaped like a game audience: 1 to [`MAX_AUDIENCE_LEN`]
/// printable ASCII characters with no space and no comma (it is one item of
/// a comma-separated list, and one line of the signed messages).
pub fn is_audience(s: &str) -> bool {
    (1..=MAX_AUDIENCE_LEN).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_graphic() && b != b',')
}

/// The message the session's device key signs to get a token: the context,
/// the session, the audience as sent and the device's clock. The audience
/// keeps a signature from being used for another game server; the time
/// bounds how long a captured request can be replayed.
pub fn mint_message(session_id: &uuid::Uuid, audience: &str, issued_at: i64) -> String {
    format!("{MINT_CONTEXT}\n{session_id}\n{audience}\n{issued_at}")
}

/// The game session a passkey session opens: a UUID (version 8) from
/// SHA-256 of the passkey session's id. One passkey session has one game
/// session, so opening it again answers the same one.
pub fn game_session_id_for(session_id: &uuid::Uuid) -> uuid::Uuid {
    let mut hasher = Sha256::new();
    hasher.update(GAME_SESSION_ID_CONTEXT);
    hasher.update(session_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_custom_bytes(bytes).into_uuid()
}

/// The message a passkey session's device key signs to open its game
/// session.
pub fn session_open_message(session_id: &uuid::Uuid, issued_at: i64) -> String {
    format!("{SESSION_OPEN_CONTEXT}\n{session_id}\n{issued_at}")
}

/// The message a game session's device key signs to get a token: as
/// [`mint_message`], under its own context and naming the game session.
pub fn session_mint_message(
    game_session_id: &uuid::Uuid,
    audience: &str,
    issued_at: i64,
) -> String {
    format!("{SESSION_MINT_CONTEXT}\n{game_session_id}\n{audience}\n{issued_at}")
}

/// The message a game session's device key signs to end it.
pub fn session_end_message(game_session_id: &uuid::Uuid, issued_at: i64) -> String {
    format!("{SESSION_END_CONTEXT}\n{game_session_id}\n{issued_at}")
}

/// The message the `cnf` key signs for one request to the game server:
/// the context, the token's audience, the method (uppercase), the request
/// target as sent, the device's clock, and the hashes of the body and of
/// the token's text.
pub fn request_message(
    audience: &str,
    method: &str,
    path: &str,
    t: i64,
    body: &[u8],
    token: &str,
) -> String {
    let hash = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(Sha256::digest(bytes));
    format!(
        "{REQUEST_CONTEXT}\n{audience}\n{method}\n{path}\n{t}\n{}\n{}",
        hash(body),
        hash(token.as_bytes())
    )
}

/// Whether `signature` is the unpadded base64url raw r‖s (64 bytes, never
/// DER) ES256 signature by the key `(x, y)` over `message`.
pub fn signature_verifies(x: &[u8; 32], y: &[u8; 32], message: &str, signature: &str) -> bool {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(signature) else {
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

/// The proof a game server requires with each request, as a reference:
/// `signature` by the token's `cnf` key over [`request_message`], with `t`
/// within `skew_secs` of `now`. `token_text` is the token as it was sent.
#[allow(clippy::too_many_arguments)]
pub fn request_proof_verifies(
    token: &GameToken,
    token_text: &str,
    method: &str,
    path: &str,
    body: &[u8],
    t: i64,
    signature: &str,
    now: i64,
    skew_secs: i64,
) -> bool {
    (now - t).abs() <= skew_secs
        && signature_verifies(
            &token.x,
            &token.y,
            &request_message(&token.aud, method, path, t, body, token_text),
            signature,
        )
}

/// Sign `t` with `key` under `kid`: the tag-61 CWT bytes.
pub fn mint(t: &GameToken, key: &SigningKey, kid: &[u8]) -> Result<Vec<u8>, CwtError> {
    let int = |n: i64| Value::Integer(n.into());
    // Deterministic order: integer keys ascending, then text keys by encoded
    // length (`arkavo_handle` is shorter than `arkavo_entitlements`).
    let mut entries = vec![
        (int(1), Value::Text(t.iss.clone())),
        (int(2), Value::Text(t.sub.clone())),
        (int(3), Value::Text(t.aud.clone())),
        (int(4), int(t.exp)),
        (int(6), int(t.iat)),
        (int(7), Value::Bytes(t.cti.to_vec())),
        (int(8), cnf_cbor(&t.x, &t.y)),
        (
            Value::Text(HANDLE_CLAIM.into()),
            Value::Text(t.handle.clone()),
        ),
    ];
    if t.online_play {
        entries.push((
            Value::Text(ENTITLEMENTS_CLAIM.into()),
            Value::Array(vec![Value::Text(ENTITLEMENT_ONLINE_PLAY.into())]),
        ));
    }
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut bytes)
        .map_err(|_| CwtError::Malformed)?;

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

/// The checks a game server makes before the request proof, as a reference:
/// the tag, ES256, the content type, a `kid` in `keys`, the signature,
/// exactly the payload keys above, `iss` and `aud` as expected, a lifetime
/// of at most [`MAX_LIFETIME_SECONDS`], and `iat`/`exp` within `skew_secs`
/// of `now`. Identity never accepts one of these tokens; this exists to pin
/// the format.
pub fn verify(
    bytes: &[u8],
    keys: &crate::keys::KeySet,
    expected_iss: &str,
    expected_aud: &str,
    now: i64,
    skew_secs: i64,
) -> Result<GameToken, CwtError> {
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
    if t.iss != expected_iss {
        return Err(CwtError::IssuerMismatch);
    }
    if t.aud != expected_aud {
        return Err(CwtError::AudienceMismatch);
    }
    if t.iat > t.exp || t.exp - t.iat > MAX_LIFETIME_SECONDS {
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

fn parse_payload(bytes: &[u8]) -> Result<GameToken, CwtError> {
    let value: Value = ciborium::de::from_reader(bytes).map_err(|_| CwtError::Malformed)?;
    let Value::Map(entries) = value else {
        return Err(CwtError::Malformed);
    };
    let find = |want: &Value| entries.iter().find(|(k, _)| k == want).map(|(_, v)| v);
    let get = |want: &Value| find(want).ok_or(CwtError::Malformed);
    let int_key = |n: i64| Value::Integer(n.into());
    let text = |v: &Value| v.as_text().map(str::to_string).ok_or(CwtError::Malformed);
    let number = |v: &Value| {
        v.as_integer()
            .and_then(|i| i64::try_from(i).ok())
            .ok_or(CwtError::Malformed)
    };

    // The entitlement claim is all or nothing: absent, or exactly the one
    // online-play value. Anything else is not a token identity minted.
    let online_play = match find(&Value::Text(ENTITLEMENTS_CLAIM.into())) {
        None => false,
        Some(Value::Array(list))
            if list.as_slice() == [Value::Text(ENTITLEMENT_ONLINE_PLAY.into())] =>
        {
            true
        }
        Some(_) => return Err(CwtError::Malformed),
    };
    if entries.len() != 8 + usize::from(online_play) {
        return Err(CwtError::Malformed);
    }
    let cti: [u8; 16] = get(&int_key(7))?
        .as_bytes()
        .and_then(|b| b.as_slice().try_into().ok())
        .ok_or(CwtError::Malformed)?;
    let (x, y) = parse_cnf(get(&int_key(8))?)?;
    Ok(GameToken {
        iss: text(get(&int_key(1))?)?,
        sub: text(get(&int_key(2))?)?,
        aud: text(get(&int_key(3))?)?,
        exp: number(get(&int_key(4))?)?,
        iat: number(get(&int_key(6))?)?,
        cti,
        x,
        y,
        handle: text(get(&Value::Text(HANDLE_CLAIM.into()))?)?,
        online_play,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner_kas_token::{self, OwnerKasToken};
    use p256::elliptic_curve::rand_core::OsRng;

    const KID: &[u8] = b"game-test-kid";
    const ISS: &str = "https://identity.example";
    const AUD: &str = "https://game.example";

    /// A fresh device key: the signer and its coordinates.
    fn device_key() -> (SigningKey, [u8; 32], [u8; 32]) {
        let sk = SigningKey::random(&mut OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        let (x, y) = ((*point.x().unwrap()).into(), (*point.y().unwrap()).into());
        (sk, x, y)
    }

    fn sample(now: i64, online_play: bool) -> (GameToken, SigningKey) {
        let (device, x, y) = device_key();
        let token = GameToken {
            iss: ISS.into(),
            sub: "0a1b2c3d-0000-4000-8000-000000000001".into(),
            aud: AUD.into(),
            iat: now,
            exp: now + 900,
            cti: [9; 16],
            x,
            y,
            handle: "alice.arkavo.social".into(),
            online_play,
        };
        (token, device)
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

    fn payload_of(bytes: &[u8]) -> (coset::CoseSign1, Value) {
        let sign1 = coset::CoseSign1::from_slice(&bytes[2..]).unwrap();
        let payload = ciborium::de::from_reader(sign1.payload.as_deref().unwrap()).unwrap();
        (sign1, payload)
    }

    #[test]
    fn audiences_are_printable_unspaced_and_uncomma_d() {
        for ok in [
            AUD,
            "game",
            "https://game.example:8443/v1",
            &"a".repeat(128),
        ] {
            assert!(is_audience(ok), "{ok:?}");
        }
        for bad in [
            "",
            &"a".repeat(129),
            "has space",
            "line\nbreak",
            "a,b",
            "naïve",
        ] {
            assert!(!is_audience(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_minted_token_verifies_and_round_trips_with_and_without_the_pass() {
        let (sk, set) = signer();
        let now = 1_760_000_000;
        for online_play in [true, false] {
            let (t, _) = sample(now, online_play);
            let bytes = mint(&t, &sk, KID).unwrap();
            assert!(bytes.starts_with(&CWT_TAG_PREFIX));
            assert_eq!(verify(&bytes, &set, ISS, AUD, now + 10, 60).unwrap(), t);
        }
    }

    #[test]
    fn the_payload_is_exactly_the_contract_in_deterministic_order() {
        let (sk, _) = signer();
        let int = |n: i64| Value::Integer(n.into());
        let base = [int(1), int(2), int(3), int(4), int(6), int(7), int(8)];

        let (t, _) = sample(1_760_000_000, true);
        let (sign1, payload) = payload_of(&mint(&t, &sk, KID).unwrap());
        assert_eq!(
            sign1.protected.header.content_type,
            Some(coset::ContentType::Text(CONTENT_TYPE.into()))
        );
        assert_eq!(sign1.protected.header.key_id, KID);
        assert!(sign1.unprotected.is_empty());
        let entries = payload.as_map().unwrap();
        let keys: Vec<Value> = entries.iter().map(|(k, _)| k.clone()).collect();
        let mut expected = base.to_vec();
        expected.push(Value::Text("arkavo_handle".into()));
        expected.push(Value::Text("arkavo_entitlements".into()));
        assert_eq!(keys, expected);
        assert_eq!(entries[2].1, Value::Text(AUD.into()), "aud is one string");
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
        // The pass, and no other entitlement.
        assert_eq!(
            entries[8].1,
            Value::Array(vec![Value::Text(
                "https://arkavo.net/attr/network/value/online-play".into()
            )])
        );
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

        // Without the pass the claim is absent, not empty.
        let (t, _) = sample(1_760_000_000, false);
        let (_, payload) = payload_of(&mint(&t, &sk, KID).unwrap());
        let keys: Vec<Value> = payload
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.clone())
            .collect();
        let mut expected = base.to_vec();
        expected.push(Value::Text("arkavo_handle".into()));
        assert_eq!(keys, expected);
    }

    /// A signed payload with one member changed: what a verifier must refuse
    /// even though identity's key signed it.
    fn signed_with(sk: &SigningKey, edit: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
        let (t, _) = sample(1_760_000_000, true);
        let (_, payload) = payload_of(&mint(&t, sk, KID).unwrap());
        let Value::Map(mut entries) = payload else {
            unreachable!()
        };
        edit(&mut entries);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut bytes).unwrap();
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(KID.to_vec())
            .content_type(CONTENT_TYPE.to_string())
            .build();
        let inner = CoseSign1Builder::new()
            .protected(protected)
            .payload(bytes)
            .create_signature(b"", |to_sign| {
                let sig: Signature = sk.sign(to_sign);
                sig.to_bytes().to_vec()
            })
            .build()
            .to_vec()
            .unwrap();
        [CWT_TAG_PREFIX.as_slice(), &inner].concat()
    }

    #[test]
    fn any_other_entitlement_or_extra_claim_is_refused() {
        let (sk, set) = signer();
        let now = 1_760_000_000;
        type Edit = Box<dyn FnOnce(&mut Vec<(Value, Value)>)>;
        let cases: Vec<Edit> = vec![
            // Another entitlement beside the pass.
            Box::new(|e| {
                e[8].1 = Value::Array(vec![
                    Value::Text(ENTITLEMENT_ONLINE_PLAY.into()),
                    Value::Text(
                        "https://patreon.arkavo.com/attr/arkavo-creator/value/publish".into(),
                    ),
                ])
            }),
            // Another entitlement in its place.
            Box::new(|e| e[8].1 = Value::Array(vec![Value::Text("https://x.example/y".into())])),
            Box::new(|e| e[8].1 = Value::Array(vec![])),
            Box::new(|e| e[8].1 = Value::Text(ENTITLEMENT_ONLINE_PLAY.into())),
            // A claim the contract does not list.
            Box::new(|e| {
                e.push((
                    Value::Text("email".into()),
                    Value::Text("a@b.example".into()),
                ))
            }),
            // A required claim missing.
            Box::new(|e| {
                e.remove(7);
            }),
        ];
        for (i, edit) in cases.into_iter().enumerate() {
            assert!(
                matches!(
                    verify(&signed_with(&sk, edit), &set, ISS, AUD, now, 60),
                    Err(CwtError::Malformed)
                ),
                "case {i}"
            );
        }
        // The helper itself signs a valid token when nothing is changed.
        assert!(verify(&signed_with(&sk, |_| {}), &set, ISS, AUD, now, 60).is_ok());
    }

    #[test]
    fn identity_and_the_other_typed_verifiers_never_take_it() {
        let (sk, set) = signer();
        let now = chrono::Utc::now().timestamp();
        let (t, _) = sample(now, true);
        let bytes = mint(&t, &sk, KID).unwrap();
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
        assert!(matches!(
            owner_kas_token::verify(&bytes, &set, now, 60),
            Err(CwtError::Malformed)
        ));

        // And the other way: a session CWT and an owner-KAS token are not
        // game tokens.
        let session = crate::cwt::ArkavoClaims::auth(ISS, "u", 1, None);
        let session = crate::cwt::mint(&session, &sk, KID).unwrap();
        assert!(matches!(
            verify(&session, &set, ISS, AUD, now, 60),
            Err(CwtError::Malformed)
        ));
        let owner_kas = owner_kas_token::mint(
            &OwnerKasToken {
                iss: ISS.into(),
                sub: t.sub.clone(),
                route_id: "01JC0000000000000000000000".into(),
                iat: now,
                exp: now + owner_kas_token::LIFETIME_SECONDS,
                cti: [1; 16],
                x: t.x,
                y: t.y,
                handle: t.handle.clone(),
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
        let (t, _) = sample(now, true);
        let bytes = mint(&t, &sk, KID).unwrap();

        let other = crate::keys::KeySet::new(*sk.verifying_key(), b"another-kid".to_vec());
        assert!(matches!(
            verify(&bytes, &other, ISS, AUD, now, 60),
            Err(CwtError::UnknownKey)
        ));
        let (wrong, _) = signer();
        assert!(matches!(
            verify(&mint(&t, &wrong, KID).unwrap(), &set, ISS, AUD, now, 60),
            Err(CwtError::InvalidSignature)
        ));
        assert!(matches!(
            verify(&bytes, &set, "https://other.example", AUD, now, 60),
            Err(CwtError::IssuerMismatch)
        ));
        // Another game server, and the audiences of other services.
        for aud in [
            "https://other-game.example",
            "arkavo",
            "https://platform.example",
        ] {
            assert!(matches!(
                verify(&bytes, &set, ISS, aud, now, 60),
                Err(CwtError::AudienceMismatch)
            ));
        }
        assert!(verify(&bytes, &set, ISS, AUD, t.exp + 59, 60).is_ok());
        assert!(matches!(
            verify(&bytes, &set, ISS, AUD, t.exp + 60, 60),
            Err(CwtError::Expired)
        ));
        assert!(matches!(
            verify(&bytes, &set, ISS, AUD, now - 61, 60),
            Err(CwtError::NotYetValid)
        ));
        // Longer than an hour is refused whatever the issuer was set to.
        let long = GameToken {
            exp: now + MAX_LIFETIME_SECONDS + 1,
            ..t.clone()
        };
        assert!(matches!(
            verify(&mint(&long, &sk, KID).unwrap(), &set, ISS, AUD, now, 60),
            Err(CwtError::Malformed)
        ));
        assert!(verify(&bytes[CWT_TAG_PREFIX.len()..], &set, ISS, AUD, now, 60).is_err());
    }

    #[test]
    fn the_signed_messages_are_byte_exact() {
        let id = uuid::Uuid::parse_str("0f0e0d0c-0b0a-8908-8706-050403020100").unwrap();
        assert_eq!(
            mint_message(&id, "https://game.example", 1_794_268_800),
            "arkavo-game-token-v1\n0f0e0d0c-0b0a-8908-8706-050403020100\nhttps://game.example\n1794268800"
        );
        // The game session messages, and the id a passkey session's game
        // session gets (UUID v8 of SHA-256(context || the id's 16 bytes)).
        assert_eq!(
            session_open_message(&id, 1_794_268_800),
            "arkavo-game-session-open-v1\n0f0e0d0c-0b0a-8908-8706-050403020100\n1794268800"
        );
        let game = game_session_id_for(&id);
        assert_eq!(game.to_string(), "35729ecb-43ef-8b98-8dc6-0e8c64dfd0d2");
        assert_eq!(
            session_mint_message(&game, "https://game.example", 1_794_268_800),
            "arkavo-game-session-token-v1\n35729ecb-43ef-8b98-8dc6-0e8c64dfd0d2\nhttps://game.example\n1794268800"
        );
        assert_eq!(
            session_end_message(&game, 1_794_268_800),
            "arkavo-game-session-end-v1\n35729ecb-43ef-8b98-8dc6-0e8c64dfd0d2\n1794268800"
        );
        // SHA-256 of the empty string, and of "abc".
        assert_eq!(
            request_message(
                "https://game.example",
                "POST",
                "/v1/runs?war=7",
                1_794_268_800,
                b"",
                "abc"
            ),
            "arkavo-game-request-v1\nhttps://game.example\nPOST\n/v1/runs?war=7\n1794268800\n\
             47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU\n\
             ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
    }

    #[test]
    fn the_mint_proof_binds_session_audience_time_and_encoding() {
        let (device, x, y) = device_key();
        let id = uuid::Uuid::new_v4();
        let message = mint_message(&id, AUD, 1_794_268_800);
        let proof = raw_signature(&device, &message);
        assert!(signature_verifies(&x, &y, &message, &proof));

        let (other, ox, oy) = device_key();
        assert!(!signature_verifies(
            &x,
            &y,
            &message,
            &raw_signature(&other, &message)
        ));
        assert!(!signature_verifies(&ox, &oy, &message, &proof));
        for changed in [
            mint_message(&uuid::Uuid::new_v4(), AUD, 1_794_268_800),
            mint_message(&id, "https://other-game.example", 1_794_268_800),
            mint_message(&id, AUD, 1_794_268_801),
        ] {
            assert!(!signature_verifies(&x, &y, &changed, &proof));
        }
        // A session message signed by the same key is not a mint proof.
        let refresh = format!("arkavo-session-refresh-v1\n{id}\n1.c2VjcmV0");
        assert!(!signature_verifies(
            &x,
            &y,
            &message,
            &raw_signature(&device, &refresh)
        ));
        // DER and padding are refused.
        let sig: Signature = device.sign(message.as_bytes());
        let der = URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes());
        assert!(!signature_verifies(&x, &y, &message, &der));
        assert!(!signature_verifies(&x, &y, &message, &format!("{proof}=")));
        assert!(!signature_verifies(&x, &y, &message, ""));
    }

    #[test]
    fn a_request_proof_binds_the_request_the_token_and_the_time() {
        let now = 1_794_268_800;
        let (token, device) = sample(now, true);
        let text = "dG9rZW4tdGV4dA";
        let sign = |method: &str, path: &str, t: i64, body: &[u8], token_text: &str| {
            raw_signature(
                &device,
                &request_message(&token.aud, method, path, t, body, token_text),
            )
        };
        let proof = sign("POST", "/v1/runs", now, b"{}", text);
        let check = |method: &str, path: &str, body: &[u8], t: i64, token_text: &str, at: i64| {
            request_proof_verifies(&token, token_text, method, path, body, t, &proof, at, 60)
        };
        assert!(check("POST", "/v1/runs", b"{}", now, text, now));
        assert!(check("POST", "/v1/runs", b"{}", now, text, now + 60));
        // Too old or from the future.
        assert!(!check("POST", "/v1/runs", b"{}", now, text, now + 61));
        assert!(!check("POST", "/v1/runs", b"{}", now, text, now - 61));
        // Another method, path, body, time or token.
        assert!(!check("GET", "/v1/runs", b"{}", now, text, now));
        assert!(!check("POST", "/v1/runs?x=1", b"{}", now, text, now));
        assert!(!check("POST", "/v1/runs", b"{ }", now, text, now));
        assert!(!check("POST", "/v1/runs", b"{}", now + 1, text, now));
        assert!(!check("POST", "/v1/runs", b"{}", now, "b3RoZXI", now));
        // Signed by a key that is not the token's.
        let (stranger, _, _) = device_key();
        let forged = raw_signature(
            &stranger,
            &request_message(&token.aud, "POST", "/v1/runs", now, b"{}", text),
        );
        assert!(!request_proof_verifies(
            &token, text, "POST", "/v1/runs", b"{}", now, &forged, now, 60
        ));
        // A token for another game server signs a different message.
        let elsewhere = GameToken {
            aud: "https://other-game.example".into(),
            ..token.clone()
        };
        assert!(!request_proof_verifies(
            &elsewhere, text, "POST", "/v1/runs", b"{}", now, &proof, now, 60
        ));
    }
}
