//! Guardians: enrollment (`POST /guardians`), revocation
//! (`DELETE /guardians/{id}`) and request authentication by
//! `X-Guardian-Signature`. A Guardian may only latch a quarantine on, or
//! appraise, its owner's agents. Contract: docs/agent-credentials-contract.md (v2).

use crate::AppState;
use crate::agent::{AgentError, db_err};
use crate::agent_state::validate_label;
use crate::constants::{GUARDIAN_NAME_MAX_LEN, GUARDIAN_SIGNATURE_SKEW_SECONDS};
use crate::db::{DynamoDBError, Guardian};
use axum::Json;
use axum::extract::{Extension, Path};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::IntoResponse;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(crate) const GUARDIAN_SIGNATURE_HEADER: &str = "X-Guardian-Signature";

#[derive(Debug, Deserialize)]
pub struct EnrollGuardianRequest {
    /// base64url (no padding) of the 32-byte Ed25519 public key.
    pub public_key: String,
    pub name: String,
    /// base64url (no padding) Ed25519 signature by that key over
    /// [`enrollment_input`]. Optional here only so a missing proof answers
    /// with the contract's 400 rather than the extractor's 422.
    #[serde(default)]
    pub proof: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EnrollGuardianResponse {
    pub guardian_id: String,
}

/// The one answer for a Guardian id that does not verify: unknown, revoked,
/// or a bad signature all read alike.
const DOES_NOT_VERIFY: &str = "guardian signature does not verify";

/// POST /guardians — the owner enrolls a Guardian's Ed25519 key, proving
/// possession of it. A key enrolls once, across all owners and even after
/// revocation (409); the proof names the enrolling owner, so nobody who
/// merely learns a key (or a proof made for someone else) can claim it.
pub async fn enroll_guardian(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Json(req): Json<EnrollGuardianRequest>,
) -> Result<impl IntoResponse, AgentError> {
    refuse_guardian(&headers)?;
    let owner = crate::agent::authenticate_human(&app_state, &headers).await?;
    validate_label("name", &req.name, GUARDIAN_NAME_MAX_LEN)?;
    let public_key = parse_guardian_key(&req.public_key)?;
    verify_enrollment_proof(owner.user_id, &public_key, req.proof.as_deref())?;
    let guardian = Guardian::enrolling(owner.user_id, req.name, public_key, Utc::now().timestamp());
    match app_state.db_store.create_guardian(&guardian).await {
        Ok(()) => Ok(Json(EnrollGuardianResponse {
            guardian_id: guardian.guardian_id,
        })),
        Err(DynamoDBError::ConditionalConflict) => Err(AgentError::Conflict(
            "public_key is already enrolled".into(),
        )),
        Err(e) => Err(db_err(e)),
    }
}

/// DELETE /guardians/:guardian_id — the enrolling owner revokes a Guardian.
/// Its signatures then answer 401 like an unknown Guardian's. Idempotent.
pub async fn revoke_guardian(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Path(guardian_id): Path<String>,
) -> Result<StatusCode, AgentError> {
    refuse_guardian(&headers)?;
    let owner = crate::agent::authenticate_human(&app_state, &headers).await?;
    if !is_guardian_id(&guardian_id) {
        return Err(AgentError::GuardianNotFound);
    }
    let guardian = app_state
        .db_store
        .get_guardian(&guardian_id)
        .await
        .map_err(db_err)?
        .ok_or(AgentError::GuardianNotFound)?;
    if guardian.owner != owner.user_id {
        return Err(AgentError::Forbidden(
            "guardian belongs to a different owner".into(),
        ));
    }
    match app_state
        .db_store
        .revoke_guardian(&guardian_id, owner.user_id, Utc::now().timestamp())
        .await
    {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        // Rows are never deleted and their owner never changes, so the only
        // way the conditioned write fails after the read above is a row
        // that is gone.
        Err(DynamoDBError::ConditionalConflict) => Err(AgentError::GuardianNotFound),
        Err(e) => Err(db_err(e)),
    }
}

/// A 32-byte Ed25519 public key that decodes to a point of large order. A
/// small-order ("weak") key would let the non-strict check accept
/// signatures nobody made.
pub(crate) fn parse_guardian_key(b64: &str) -> Result<[u8; 32], AgentError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| AgentError::InvalidRequest("public_key is not base64url".into()))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AgentError::InvalidRequest("public_key must be 32 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(&key)
        .map_err(|_| AgentError::InvalidRequest("public_key is not an Ed25519 point".into()))?;
    if vk.is_weak() {
        return Err(AgentError::InvalidRequest(
            "public_key is a small-order point".into(),
        ));
    }
    Ok(key)
}

/// Whether `id` could name a Guardian: a canonical (hyphenated, lower-case)
/// UUID. Anything else is refused before it reaches a storage key.
fn is_guardian_id(id: &str) -> bool {
    Uuid::try_parse(id).is_ok_and(|u| u.hyphenated().to_string() == id)
}

/// The bytes a Guardian key signs to be enrolled for `owner` (contract v1):
/// `arkavo-guardian-enroll \n owner_uuid \n public_key_b64url`.
pub(crate) fn enrollment_input(owner: Uuid, public_key: &[u8; 32]) -> Vec<u8> {
    format!(
        "arkavo-guardian-enroll\n{}\n{}",
        owner.hyphenated(),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key)
    )
    .into_bytes()
}

fn verify_enrollment_proof(
    owner: Uuid,
    public_key: &[u8; 32],
    proof: Option<&str>,
) -> Result<(), AgentError> {
    let bad = || {
        AgentError::InvalidRequest(
            "proof must be the Guardian key's signature over its enrollment for this owner".into(),
        )
    };
    let sig: [u8; 64] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(proof.ok_or_else(bad)?)
        .map_err(|_| bad())?
        .try_into()
        .map_err(|_| bad())?;
    VerifyingKey::from_bytes(public_key)
        .map_err(|_| bad())?
        .verify_strict(
            &enrollment_input(owner, public_key),
            &Signature::from_bytes(&sig),
        )
        .map_err(|_| bad())
}

/// The bytes a Guardian signs (contract v1):
/// `METHOD \n PATH \n unix_ts \n hex(sha256(body))`.
pub(crate) fn signing_input(method: &str, path: &str, timestamp: i64, body: &[u8]) -> Vec<u8> {
    format!(
        "{method}\n{path}\n{timestamp}\n{}",
        hex::encode(Sha256::digest(body))
    )
    .into_bytes()
}

struct SignatureHeader {
    guardian_id: String,
    timestamp: i64,
    signature: Signature,
}

fn parse_signature_header(raw: &str) -> Result<SignatureHeader, AgentError> {
    let bad = || AgentError::Unauthorized("malformed X-Guardian-Signature".into());
    let mut parts = raw.splitn(3, '.');
    let (Some(id), Some(ts), Some(sig)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(bad());
    };
    if id.is_empty() {
        return Err(bad());
    }
    let timestamp = ts.parse::<i64>().map_err(|_| bad())?;
    let sig: [u8; 64] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| bad())?
        .try_into()
        .map_err(|_| bad())?;
    Ok(SignatureHeader {
        guardian_id: id.to_string(),
        timestamp,
        signature: Signature::from_bytes(&sig),
    })
}

/// Authenticate a Guardian request against the key enrolled under the
/// claimed `guardian_id` — never a key the request carries (the lesson of
/// arkavo-edge #697).
pub(crate) async fn verify_guardian_request(
    app_state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    body: &[u8],
    now: i64,
) -> Result<Guardian, AgentError> {
    let raw = headers
        .get(GUARDIAN_SIGNATURE_HEADER)
        .ok_or(AgentError::MissingToken)?
        .to_str()
        .map_err(|_| AgentError::Unauthorized("malformed X-Guardian-Signature".into()))?;
    let header = parse_signature_header(raw)?;
    if !is_guardian_id(&header.guardian_id) {
        return Err(AgentError::Unauthorized(DOES_NOT_VERIFY.into()));
    }
    if header.timestamp.abs_diff(now) > GUARDIAN_SIGNATURE_SKEW_SECONDS {
        return Err(AgentError::Unauthorized(
            "guardian signature timestamp is outside the allowed skew".into(),
        ));
    }
    let guardian = app_state
        .db_store
        .get_guardian(&header.guardian_id)
        .await
        .map_err(db_err)?
        .filter(|g| g.revoked_at.is_none())
        .ok_or_else(|| AgentError::Unauthorized(DOES_NOT_VERIFY.into()))?;
    let key = VerifyingKey::from_bytes(&guardian.public_key)
        .map_err(|_| AgentError::Unauthorized(DOES_NOT_VERIFY.into()))?;
    key.verify_strict(
        &signing_input(method.as_str(), path, header.timestamp, body),
        &header.signature,
    )
    .map_err(|_| AgentError::Unauthorized(DOES_NOT_VERIFY.into()))?;
    // Only after the signature verifies, so unauthenticated traffic cannot
    // move a Guardian's clock.
    match app_state
        .db_store
        .advance_guardian_clock(&guardian.guardian_id, header.timestamp)
        .await
    {
        Ok(()) => Ok(guardian),
        Err(crate::db::DynamoDBError::ConditionalConflict) => Err(AgentError::Unauthorized(
            "guardian signature replayed or older than the last accepted one".into(),
        )),
        Err(e) => Err(db_err(e)),
    }
}

/// Guardians may call only quarantine. Every other agent-plane handler calls
/// this first, so a Guardian gets 403 there — whether or not its signature
/// would verify — rather than a 401 for the CWT it does not have.
pub(crate) fn refuse_guardian(headers: &HeaderMap) -> Result<(), AgentError> {
    if headers.contains_key(GUARDIAN_SIGNATURE_HEADER) {
        return Err(AgentError::Forbidden(
            "guardians may only quarantine".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn signing_input_is_method_path_time_and_body_hash() {
        assert_eq!(
            signing_input(
                "POST",
                "/agents/did:key:z6Mkexample/quarantine",
                1_790_000_000,
                b"{}"
            ),
            b"POST\n/agents/did:key:z6Mkexample/quarantine\n1790000000\n\
44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
                .to_vec()
        );
        assert!(
            String::from_utf8(signing_input("GET", "/x", 1, b""))
                .unwrap()
                .ends_with("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn guardian_keys_must_be_32_byte_non_weak_points() {
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        assert_eq!(
            parse_guardian_key(&b64(sk.verifying_key().as_bytes())).unwrap(),
            sk.verifying_key().to_bytes()
        );
        assert!(matches!(
            parse_guardian_key(&b64(&[1u8; 31])),
            Err(AgentError::InvalidRequest(_))
        ));
        assert!(matches!(
            parse_guardian_key("not base64url!"),
            Err(AgentError::InvalidRequest(_))
        ));
        // The encoded identity point (y = 1) is small-order: any signature
        // "verifies" under it with the non-strict check.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(matches!(
            parse_guardian_key(&b64(&identity)),
            Err(AgentError::InvalidRequest(_))
        ));
    }

    #[test]
    fn signature_header_parses_three_dot_separated_parts() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.sign(b"m").to_bytes());
        let h = parse_signature_header(&format!("g-1.1790000000.{sig}")).unwrap();
        assert_eq!(
            (h.guardian_id.as_str(), h.timestamp),
            ("g-1", 1_790_000_000)
        );
        for bad in [
            "",
            "g-1",
            "g-1.1790000000",
            ".1790000000.AAAA",
            "g-1.soon.AAAA",
            "g-1.1790000000.AAAA",
        ] {
            assert!(parse_signature_header(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn enrollment_input_names_the_owner_and_the_key() {
        let owner = Uuid::parse_str("0f0e0d0c-0b0a-4908-8706-050403020100").unwrap();
        assert_eq!(
            enrollment_input(owner, &[0u8; 32]),
            b"arkavo-guardian-enroll\n0f0e0d0c-0b0a-4908-8706-050403020100\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .to_vec()
        );
    }

    #[test]
    fn only_canonical_uuids_are_guardian_ids() {
        let id = Uuid::new_v4().to_string();
        assert!(is_guardian_id(&id));
        for bad in [
            String::new(),
            "not-a-uuid".into(),
            id.to_uppercase(),
            id.replace('-', ""),
            format!("{{{id}}}"),
            "a".repeat(3000),
        ] {
            assert!(!is_guardian_id(&bad), "{bad:.40}");
        }
    }

    #[test]
    fn a_guardian_header_is_refused_outside_quarantine() {
        let mut headers = HeaderMap::new();
        assert!(refuse_guardian(&headers).is_ok());
        headers.insert(GUARDIAN_SIGNATURE_HEADER, "anything".parse().unwrap());
        assert!(matches!(
            refuse_guardian(&headers),
            Err(AgentError::Forbidden(_))
        ));
    }
}
