//! Passkey credential attestations (#104).
//!
//! - `POST /passkeys/credential-attestation`: the account's passkey auth CWT
//!   (`X-Auth-Token`) asks the IdP to vouch for one of its own passkeys. The
//!   answer is a COSE_Sign1 (`authnz_rs::credential_attestation`) tying the
//!   credential's public key to the account's `sub`, with no expiry.
//! - `GET /passkeys/credentials/:credential_id/status`: public. Whether the
//!   credential has been revoked. The node checks it when it accepts a
//!   catalog pointer signed with the passkey; viewers may.
//!
//! Contract: [docs/passkey-credential-attestation.md](../docs/passkey-credential-attestation.md).

use crate::AppState;
use crate::db::{DynamoDBError, PasskeyLinked};
use authnz_rs::credential_attestation::{self, CredentialAttestation};
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{COSEKeyType, ECDSACurve, Passkey};

/// WebAuthn's limit on a credential id (bytes).
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("{0}")]
    Unauthorized(String),
    #[error("credentialId must be base64url without padding, 1 to 1023 bytes")]
    InvalidCredentialId,
    /// Not a credential of this account (or, on the status route, of any
    /// account an attestation was issued for), or one that was removed.
    #[error("unknown credential")]
    UnknownCredential,
    #[error("the credential is bound to another account")]
    CredentialConflict,
    #[error("only P-256 (ES256) passkeys can be attested")]
    UnsupportedKeyType,
    #[error("internal error")]
    Internal,
}

impl IntoResponse for PasskeyError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::InvalidCredentialId => (StatusCode::BAD_REQUEST, "invalid_credential_id"),
            Self::UnknownCredential => (StatusCode::NOT_FOUND, "unknown_credential"),
            Self::CredentialConflict => (StatusCode::CONFLICT, "credential_conflict"),
            Self::UnsupportedKeyType => (StatusCode::UNPROCESSABLE_ENTITY, "unsupported_key_type"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        };
        (
            status,
            [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({ "error": code, "error_description": self.to_string() })),
        )
            .into_response()
    }
}

impl From<DynamoDBError> for PasskeyError {
    fn from(e: DynamoDBError) -> Self {
        error!("Passkey attestation storage failure: {e}");
        Self::Internal
    }
}

/// Decode a credential id: base64url without padding, strictly (so every
/// spelling of one id is one string), 1 to 1023 bytes. Returns the bytes and
/// the canonical spelling the index is keyed by.
fn decode_credential_id(id: &str) -> Result<(Vec<u8>, String), PasskeyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(id)
        .map_err(|_| PasskeyError::InvalidCredentialId)?;
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_ID_BYTES {
        return Err(PasskeyError::InvalidCredentialId);
    }
    let canonical = URL_SAFE_NO_PAD.encode(&bytes);
    if canonical != id {
        return Err(PasskeyError::InvalidCredentialId);
    }
    Ok((bytes, canonical))
}

/// The passkey's P-256 public key coordinates, as stored at registration.
fn p256_coordinates(passkey: &Passkey) -> Result<([u8; 32], [u8; 32]), PasskeyError> {
    match &passkey.get_public_key().key {
        COSEKeyType::EC_EC2(ec2) if ec2.curve == ECDSACurve::SECP256R1 => {
            let x = <[u8; 32]>::try_from(ec2.x.as_ref())
                .map_err(|_| PasskeyError::UnsupportedKeyType)?;
            let y = <[u8; 32]>::try_from(ec2.y.as_ref())
                .map_err(|_| PasskeyError::UnsupportedKeyType)?;
            Ok((x, y))
        }
        _ => Err(PasskeyError::UnsupportedKeyType),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttestationRequest {
    credential_id: String,
}

#[derive(Debug, Serialize)]
pub struct AttestationResponse {
    /// base64url (no padding) of the tagged COSE_Sign1.
    attestation: String,
}

/// `POST /passkeys/credential-attestation`.
///
/// 200 `{attestation}`; 401 for a missing or invalid passkey auth CWT (a
/// registration token or an OIDC access token is not one) or a deleted
/// account; 400 for a malformed `credentialId`; 404 for a credential the
/// account does not hold or that was removed; 409 if another account's index
/// row claims it; 422 for a key other than P-256.
pub async fn issue_credential_attestation(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Json(body): Json<AttestationRequest>,
) -> Result<Response, PasskeyError> {
    let (user_id, _) = crate::agent::verify_passkey_auth_token(&app_state, &headers)
        .map_err(|e| PasskeyError::Unauthorized(e.to_string()))?;
    let (credential_id, canonical) = decode_credential_id(&body.credential_id)?;

    let db = &app_state.db_store;
    // Tokens outlive the account (#88): the row is the authority.
    let Some(user) = db.get_user_by_id(&user_id).await? else {
        return Err(PasskeyError::Unauthorized("account does not exist".into()));
    };
    let passkey = user
        .credentials
        .iter()
        .find(|p| p.cred_id().as_ref() == credential_id.as_slice())
        .ok_or(PasskeyError::UnknownCredential)?;
    let (x, y) = p256_coordinates(passkey)?;

    let now = Utc::now().timestamp();
    // Index before signing, so every attestation issued has a status. An
    // account deleted after the read above still reads as revoked: the
    // status route checks the account, not only this row.
    match db.link_passkey(&user_id, &canonical, now).await {
        Ok(PasskeyLinked::Linked) => {}
        Ok(PasskeyLinked::Revoked) => return Err(PasskeyError::UnknownCredential),
        Ok(PasskeyLinked::OtherAccount) => {
            warn!("audit passkey_attestation outcome=conflict user_id={user_id}");
            return Err(PasskeyError::CredentialConflict);
        }
        // A concurrent change to the row: the client retries.
        Err(DynamoDBError::ConditionalConflict) => return Err(PasskeyError::Internal),
        Err(e) => return Err(e.into()),
    }

    let attestation = CredentialAttestation {
        iss: app_state.issuer.to_string(),
        // Exactly the passkey auth CWT's `sub` (authn::mint_auth_token).
        sub: user_id.to_string(),
        credential_id,
        x,
        y,
        rp_id: authnz_rs::constants::WEBAUTHN_RP_ID.to_string(),
        iat: now,
    };
    let bytes =
        credential_attestation::mint(&attestation, &app_state.cwt_signing_key, &app_state.cwt_kid)
            .map_err(|e| {
                error!("Signing a passkey credential attestation failed: {e}");
                PasskeyError::Internal
            })?;
    info!("audit passkey_attestation outcome=issued user_id={user_id}");
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(AttestationResponse {
            attestation: URL_SAFE_NO_PAD.encode(bytes),
        }),
    )
        .into_response())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    sub: String,
    revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<i64>,
}

/// `GET /passkeys/credentials/:credential_id/status`. No authentication.
///
/// 200 `{sub, revoked, revokedAt?}`; 400 for a malformed id; 404 for a
/// credential no attestation was ever issued for. `Cache-Control: no-store`:
/// the node checks it to refuse a revoked passkey, which a cache would defeat.
pub async fn credential_status(
    Extension(app_state): Extension<AppState>,
    Path(credential_id): Path<String>,
) -> Result<Response, PasskeyError> {
    let (bytes, canonical) = decode_credential_id(&credential_id)?;
    let status = app_state
        .db_store
        .passkey_status(&canonical, &bytes)
        .await?
        .ok_or(PasskeyError::UnknownCredential)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(CredentialStatus {
            sub: status.user_id.to_string(),
            revoked: status.revoked,
            revoked_at: status.revoked_at,
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_ids_must_be_canonical_base64url() {
        let (bytes, canonical) = decode_credential_id("AQIDBA").unwrap();
        assert_eq!(bytes, [1, 2, 3, 4]);
        assert_eq!(canonical, "AQIDBA");
        for bad in [
            "",
            "AQIDBA==", // padding
            "AQID+A",   // standard alphabet
            "AQIDBB",   // non-zero trailing bits
            "not base64!",
        ] {
            assert!(
                matches!(
                    decode_credential_id(bad),
                    Err(PasskeyError::InvalidCredentialId)
                ),
                "{bad:?} must be refused"
            );
        }
        let too_long = URL_SAFE_NO_PAD.encode([0u8; MAX_CREDENTIAL_ID_BYTES + 1]);
        assert!(decode_credential_id(&too_long).is_err());
        let longest = URL_SAFE_NO_PAD.encode([0u8; MAX_CREDENTIAL_ID_BYTES]);
        assert!(decode_credential_id(&longest).is_ok());
    }
}
