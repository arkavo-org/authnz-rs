//! Apple DeviceCheck/App Attest server-side validation
//!
//! This module implements server-side verification for Apple's App Attest framework,
//! enabling hardware-backed device attestation for iOS applications.
//!
//! # Overview
//!
//! App Attest allows servers to verify that requests originate from genuine, unmodified
//! iOS apps running on authentic Apple devices with Secure Enclave support.
//!
//! # Flows
//!
//! ## One-time Attestation (Device Binding)
//! 1. Client requests challenge via `GET /device-check/challenge/:username`
//! 2. Server generates random UUID challenge, stores in session
//! 3. Client generates Secure Enclave key via `DCAppAttestService.generateKey()`
//! 4. Client computes clientDataHash = SHA256(challenge)
//! 5. Client performs attestation: `DCAppAttestService.attestKey(keyId, clientDataHash)`
//! 6. Client POSTs CBOR attestation object to `/device-check/attest`
//! 7. Server validates attestation and stores device binding
//!
//! ## Ongoing Assertions (Authentication)
//! 1. Client requests assertion challenge via `GET /device-check/assert-challenge/:username`
//! 2. Server generates challenge, validates JWT token
//! 3. Client signs challenge with device key
//! 4. Client POSTs assertion to `/device-check/assert`
//! 5. Server verifies signature, enforces counter increment, issues JWT
//!
//! # Security Features
//!
//! - **Hardware-backed keys**: Secure Enclave generates per-app, per-device keys
//! - **Certificate chain validation**: Attestation anchored to Apple's root CA
//! - **Replay protection**: Monotonic counter must increment with each assertion
//! - **Signature verification**: ECDSA P-256 signatures verified using stored public keys
//! - **Nonce binding**: Challenge bound to attestation/assertion via SHA256
//! - **Race condition protection**: Conditional DynamoDB updates prevent counter races
//!
//! # Known Limitations
//!
//! - Re-attesting an existing `key_id` under the same account resets `counter`
//!   to 0, reopening a replay window for assertions captured before it
//!
//! # Requirements
//!
//! - iOS 14+ with Secure Enclave support
//! - Entitlement: `com.apple.developer.devicecheck.appattest-environment`
//! - Not available in iOS Simulator

use crate::AppState;
use crate::constants::AUTH_TOKEN_HOURS;
use crate::db::DynamoDBError;
use axum::http::HeaderMap;
use axum::{
    extract::{Extension, Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use base64::Engine;
use chrono::Utc;
use ecdsa::signature::Verifier;
use log::{error, info, warn};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use thiserror::Error;
use tower_sessions::Session;
use uuid::Uuid;
use x509_parser::prelude::*;

const SESSION_ATTEST_STATE_KEY: &str = "attest_state";
const SESSION_ASSERT_STATE_KEY: &str = "assert_state";

// Cached parsed Apple root certificate data (initialized on first use)
// Stores the DER-encoded certificate bytes to avoid lifetime issues
static APPLE_ROOT_CERT_DER: OnceLock<Vec<u8>> = OnceLock::new();

// Apple's App Attest root CA certificate (production)
// This is Apple's public root certificate for App Attest
const APPLE_APP_ATTEST_ROOT_CA: &str = r#"-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceBinding {
    pub device_id: String,
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub app_id: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge: String,
}

#[derive(Debug, Deserialize)]
pub struct AttestationRequest {
    pub key_id: String,
    pub attestation_object: String, // Base64 encoded
    pub client_data_hash: String,   // Base64 encoded (SHA256 of challenge)
}

#[derive(Debug, Deserialize)]
pub struct AssertionRequest {
    pub key_id: String,
    pub assertion: String,        // Base64 encoded
    pub client_data_hash: String, // Base64 encoded (SHA256 of challenge)
}

#[derive(Debug, Serialize)]
pub struct AttestationResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct AssertionResponse {
    /// Arkavo-issued CWT (base64url-encoded COSE_Sign1 wrapped in CBOR tag 61).
    /// Field name is format-agnostic so clients don't conflate it with a JWT.
    pub token: String,
}

// CBOR structures for App Attest.
//
// Apple's attestation object uses camelCase keys — `attStmt`, `authData` —
// per the WebAuthn attestation-object format App Attest follows. Without the
// rename these fields never match and ciborium fails with
// `missing field att_stmt` on every genuine attestation, so nothing Apple
// produces could ever be parsed. `fmt`, `x5c` and `receipt` are unaffected,
// having no case difference.
// `Serialize` exists for the tamper tests, which re-encode a modified
// attestation to prove a mutated authData is refused. Nothing in production
// writes an attestation object.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestationObject {
    fmt: String,
    att_stmt: AttestationStatement,
    auth_data: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct AttestationStatement {
    x5c: Vec<Vec<u8>>,
    receipt: Option<Vec<u8>>,
}

/// An attestation that passed [`verify_attestation`].
///
/// `key_id` and `counter` are unread on the bound-device path, which takes
/// them from the request and has already enforced `counter == 0`. Task 5's
/// unauthenticated path consumes both: `key_id` keys the registration budget,
/// and the caller has no trusted request field to fall back on.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AttestedKey {
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub rp_id_hash_str: String,
    pub counter: u32,
}

/// How strictly [`verify_attestation`] treats the app-id configuration.
pub struct VerifyOptions<'a> {
    /// Accepted `rpIdHash` values, lowercase hex. A **set**: more than one app
    /// registers users, so a single value would refuse the others. Empty means
    /// unset, and `require_app_id` decides whether that warns or refuses.
    pub expected_app_ids: &'a [String],
    /// When true, an empty `expected_app_ids` is an error rather than a
    /// warning. The registration gate sets this; the bound-device path does not.
    pub require_app_id: bool,
}

/// Verify an App Attest attestation and return the attested key.
///
/// Extracted from [`finish_attestation`] so the unauthenticated registration
/// path (Task 5) shares one implementation rather than growing a second copy
/// that can drift from this one.
///
/// Behaviour is unchanged for the bound-device path: pass
/// `require_app_id: false` and an unset `expected_app_ids` still warns and
/// continues. The gate passes `true`, where an unset value is refused.
///
/// The nonce extension (Task 2), the full certificate chain (Task 3), the
/// aaguid, and the binding of `key_id` to the attested key are verified here.
/// The app-id relaxation above is the only behaviour that differs by path;
/// the aaguid and key_id checks refuse on both. The remaining documented gap — `counter` resetting to 0 when
/// an existing `key_id` re-attests — is a property of the bound-device
/// assertion path, not of this function.
pub fn verify_attestation(
    challenge: &str,
    key_id: &str,
    attestation_object_b64: &str,
    client_data_hash_b64: &str,
    opts: &VerifyOptions<'_>,
) -> Result<AttestedKey, DeviceCheckError> {
    verify_attestation_at(
        challenge,
        key_id,
        attestation_object_b64,
        client_data_hash_b64,
        opts,
        ASN1Time::now(),
    )
}

/// As [`verify_attestation`], but with the certificate-validity instant
/// supplied.
///
/// **Production always passes `ASN1Time::now()`** — [`verify_attestation`] is
/// the only non-test caller. See [`validate_certificate_chain_at`] for why the
/// parameter exists: the captured fixture's leaf is valid for about three
/// days, and tests that drive the whole verifier would otherwise start failing
/// on a calendar date rather than a code change.
pub fn verify_attestation_at(
    challenge: &str,
    key_id: &str,
    attestation_object_b64: &str,
    client_data_hash_b64: &str,
    opts: &VerifyOptions<'_>,
    now: ASN1Time,
) -> Result<AttestedKey, DeviceCheckError> {
    // Decode the attestation object from base64
    let attestation_bytes = base64::engine::general_purpose::STANDARD
        .decode(attestation_object_b64)
        .map_err(|e| DeviceCheckError::InvalidAttestationObject(e.to_string()))?;

    // Parse CBOR attestation object
    let attestation: AttestationObject = ciborium::from_reader(&attestation_bytes[..])
        .map_err(|e| DeviceCheckError::InvalidAttestationObject(e.to_string()))?;

    // Verify format is "apple-appattest"
    if attestation.fmt != "apple-appattest" {
        return Err(DeviceCheckError::InvalidFormat(format!(
            "Expected 'apple-appattest', got '{}'",
            attestation.fmt
        )));
    }

    // Decode client data hash
    let client_data_hash = base64::engine::general_purpose::STANDARD
        .decode(client_data_hash_b64)
        .map_err(|e| DeviceCheckError::InvalidClientData(e.to_string()))?;

    // Verify the challenge matches
    let expected_hash = Sha256::digest(challenge.as_bytes());
    if client_data_hash.as_slice() != &expected_hash[..] {
        return Err(DeviceCheckError::ChallengeMismatch);
    }

    // Validate certificate chain
    validate_certificate_chain_at(&attestation.att_stmt.x5c, now)?;

    // Extract public key from certificate
    let public_key = extract_public_key_from_cert(&attestation.att_stmt.x5c[0])?;

    // Parse authenticator data
    let auth_data = parse_authenticator_data(&attestation.auth_data)?;

    // Verify counter is 0 for initial attestation
    if auth_data.counter != 0 {
        return Err(DeviceCheckError::InvalidCounter(format!(
            "Expected counter 0 for attestation, got {}",
            auth_data.counter
        )));
    }

    // SECURITY: `rpIdHash` identifies the app that produced the attestation.
    // Unenforced, any App Attest-capable app — not just ours — can mint
    // bindings. Enforced only when `APP_ATTEST_APP_ID` is configured, so
    // deployments that have not set it keep today's behaviour and a warning.
    let expected_app_ids = opts.expected_app_ids;
    if expected_app_ids.is_empty() {
        if opts.require_app_id {
            // Admission control: an unset value would admit an attestation
            // from any App Attest-capable app at all, so the gate refuses
            // rather than warns.
            error!("APP_ATTEST_APP_ID is unset and this path requires it; refusing");
            return Err(DeviceCheckError::AppIdNotConfigured);
        }
        warn!(
            "APP_ATTEST_APP_ID is unset; accepting attestation with unverified rpIdHash {}",
            auth_data.rp_id_hash_str
        );
    } else if !app_id_is_accepted(&auth_data.rp_id_hash_str, expected_app_ids) {
        warn!(
            "App Attest rpIdHash mismatch for key_id {}: got {}, expected one of [{}]",
            key_id,
            auth_data.rp_id_hash_str,
            expected_app_ids.join(", ")
        );
        return Err(DeviceCheckError::AppIdMismatch);
    }

    // SECURITY: bind the claimed key_id to the key Apple actually attested.
    //
    // key_id is caller-supplied and keys the registration budget. Without
    // this, one genuine attestation could be presented under any key_id, and
    // the per-key budget would bound nothing. Apple defines key_id as
    // SHA256 of the credCert's public key, and authData's credentialId as
    // that same hash. The key_id string must be its canonical (padded
    // standard base64) encoding so one key cannot own two budget rows.
    //
    // Runs before the nonce compare: every tamper here also changes the
    // nonce, and a check shadowed by NonceMismatch is a check nobody can test.
    let credential = parse_attested_credential(&attestation.auth_data)?;
    if !ACCEPTED_AAGUIDS.contains(&credential.aaguid) {
        return Err(DeviceCheckError::InvalidAaguid(hex::encode(
            credential.aaguid,
        )));
    }
    let key_hash = attested_key_hash(&attestation.att_stmt.x5c[0])?;
    let canonical_key_id = base64::engine::general_purpose::STANDARD.encode(key_hash);
    if key_id != canonical_key_id || credential.credential_id != key_hash.as_slice() {
        warn!(
            "App Attest key_id mismatch: claimed {}, attested key is {}",
            key_id, canonical_key_id
        );
        return Err(DeviceCheckError::KeyIdMismatch);
    }

    // Calculate nonce: SHA256(authData || clientDataHash)
    let mut nonce_data = Vec::new();
    nonce_data.extend_from_slice(&attestation.auth_data);
    nonce_data.extend_from_slice(&client_data_hash);
    let calculated_nonce = Sha256::digest(&nonce_data);

    // SECURITY: bind the attestation to the challenge this server issued.
    //
    // The credCert carries the nonce Apple computed at attestation time in
    // extension 1.2.840.113635.100.8.2, and the Secure Enclave signs the cert
    // over it. Comparing it against our own SHA256(authData || clientDataHash)
    // is what makes a captured attestation useless against a later challenge —
    // every other check (chain, rpIdHash, counter) is satisfied by a replay.
    let cert_nonce = extract_attestation_nonce(&attestation.att_stmt.x5c[0])?;
    if cert_nonce.as_slice() != &calculated_nonce[..] {
        warn!(
            "App Attest nonce mismatch for key_id {}: credCert has {}, computed {}",
            key_id,
            hex::encode(&cert_nonce),
            hex::encode(calculated_nonce)
        );
        return Err(DeviceCheckError::NonceMismatch);
    }

    Ok(AttestedKey {
        key_id: key_id.to_string(),
        public_key,
        rp_id_hash_str: auth_data.rp_id_hash_str,
        counter: auth_data.counter,
    })
}

// ---------------------------------------------------------------------------
// Task 5: the unauthenticated registration preflight
// ---------------------------------------------------------------------------

/// Session key holding the preflight challenge, between the two calls.
pub const SESSION_REG_CHALLENGE_KEY: &str = "reg_attest_challenge";
/// Session key holding the ticket an attested caller spends at `/register`.
pub const SESSION_REG_TICKET_KEY: &str = "reg_attest_ticket";

/// How long an attested registration ticket remains spendable.
const REG_TICKET_TTL_SECONDS: i64 = 300;

/// Proof that a caller attested, spendable once at `/register`.
///
/// Server-side only: it lives in the session and is never sent to the client,
/// so there is nothing for a caller to forge or replay across sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationTicket {
    pub key_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Spent by `authn::require_registration_ticket`, which is what makes
/// `/register` require a ticket. Defined here with the type it validates so
/// the two cannot drift.
pub fn ticket_is_valid(ticket: &RegistrationTicket, now: i64) -> bool {
    now <= ticket.expires_at
}

/// What `register-attest` returns on success.
///
/// Carries only `expires_at`; the ticket itself stays in the session.
#[derive(Debug, Serialize, Deserialize)]
pub struct PreflightResponse {
    pub expires_at: i64,
}

/// A machine-readable refusal from the two preflight routes.
///
/// These routes answer JSON, unlike the rest of `DeviceCheckError`, which
/// renders plain text. That is not cosmetic: without a stable token the client
/// cannot tell a permanent refusal from a retryable one, falls back to
/// retryable for everything, and a genuinely spent `key_id` is told to retry
/// forever. See `docs/app-attest-preflight-contract.md`.
#[derive(Debug, Serialize)]
pub struct PreflightErrorBody {
    pub error: &'static str,
    pub error_description: String,
}

/// Wraps a [`DeviceCheckError`] so the preflight routes answer the contract's
/// JSON shape instead of the legacy plain-text body.
#[derive(Debug)]
pub struct PreflightRejection(pub DeviceCheckError);

impl From<DeviceCheckError> for PreflightRejection {
    fn from(e: DeviceCheckError) -> Self {
        Self(e)
    }
}

/// Map an error to its contract `(status, token, retry_after)`.
///
/// Split out from `into_response` so the mapping is testable without building
/// an HTTP response, and so the one rule that matters — exactly one permanent
/// code — can be asserted directly.
pub fn preflight_error_mapping(err: &DeviceCheckError) -> (StatusCode, &'static str, Option<i64>) {
    match err {
        DeviceCheckError::AppIdMismatch => (StatusCode::BAD_REQUEST, "app_id_mismatch", None),
        DeviceCheckError::AppIdNotConfigured => (
            StatusCode::SERVICE_UNAVAILABLE,
            "app_id_not_configured",
            None,
        ),

        DeviceCheckError::CorruptSession
        | DeviceCheckError::InvalidSessionState(_)
        | DeviceCheckError::SessionError(_) => (StatusCode::BAD_REQUEST, "session_invalid", None),

        DeviceCheckError::InvalidAttestationObject(_)
        | DeviceCheckError::InvalidFormat(_)
        | DeviceCheckError::InvalidCertificateChain(_)
        | DeviceCheckError::NonceExtensionMissing
        | DeviceCheckError::NonceMismatch
        | DeviceCheckError::KeyIdMismatch
        | DeviceCheckError::InvalidAaguid(_)
        | DeviceCheckError::InvalidAuthenticatorData(_)
        | DeviceCheckError::InvalidCounter(_)
        | DeviceCheckError::InvalidClientData(_)
        | DeviceCheckError::ChallengeMismatch => {
            (StatusCode::BAD_REQUEST, "attestation_invalid", None)
        }

        DeviceCheckError::DynamoDBOperationError(db) => match **db {
            // The only permanent refusal in this contract. `registrations`
            // only increases, so no delay makes this succeed — and therefore
            // no Retry-After.
            DynamoDBError::AttestLifetimeCapExceeded => {
                (StatusCode::FORBIDDEN, "attest_registration_cap", None)
            }
            DynamoDBError::RateLimited { retry_after } => (
                StatusCode::TOO_MANY_REQUESTS,
                "attest_rate_limited",
                Some(retry_after),
            ),
            _ => (StatusCode::SERVICE_UNAVAILABLE, "attest_unavailable", None),
        },

        // Anything else cannot arise on an unauthenticated route (no token is
        // presented, no user is resolved). Answer retryable rather than
        // inventing a permanent verdict from an unexpected variant.
        _ => (StatusCode::SERVICE_UNAVAILABLE, "attest_unavailable", None),
    }
}

impl IntoResponse for PreflightRejection {
    fn into_response(self) -> axum::response::Response {
        let (status, error, retry_after) = preflight_error_mapping(&self.0);
        let body = PreflightErrorBody {
            error,
            error_description: self.0.to_string(),
        };
        let mut resp = (status, Json(body)).into_response();
        if let Some(secs) = retry_after
            && let Ok(v) = secs.to_string().parse()
        {
            resp.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, v);
        }
        resp
    }
}

/// Issue an attestation challenge to a caller with no account yet.
///
/// Deliberately takes no username: pre-account, a username-keyed endpoint
/// would tell an unauthenticated caller which handles exist.
pub async fn register_challenge(session: Session) -> Result<impl IntoResponse, PreflightRejection> {
    let challenge = generate_random_challenge();
    session
        .insert(SESSION_REG_CHALLENGE_KEY, challenge.clone())
        .await
        .map_err(DeviceCheckError::InvalidSessionState)?;
    Ok(Json(ChallengeResponse { challenge }))
}

/// Verify an attestation from an unregistered caller and issue a one-shot
/// registration ticket.
///
/// **This does not gate registration.** `/register` does not require a ticket
/// until Task 6, so a 200 here is not evidence that registration is protected.
pub async fn register_attest(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(request): Json<AttestationRequest>,
) -> Result<impl IntoResponse, PreflightRejection> {
    let challenge: String = session
        .get(SESSION_REG_CHALLENGE_KEY)
        .await
        .map_err(DeviceCheckError::InvalidSessionState)?
        .ok_or(DeviceCheckError::CorruptSession)?;

    // One challenge, one attempt — consumed whether or not what follows
    // succeeds, so a caller cannot grind attestations against one challenge.
    session
        .remove_value(SESSION_REG_CHALLENGE_KEY)
        .await
        .map_err(|e| DeviceCheckError::SessionError(e.to_string()))?;

    let attested = verify_attestation(
        &challenge,
        &request.key_id,
        &request.attestation_object,
        &request.client_data_hash,
        &VerifyOptions {
            expected_app_ids: app_state.app_attest_app_id.as_slice(),
            // Admission control: unset would admit an attestation from any
            // App Attest-capable app, so this path refuses rather than warns.
            require_app_id: true,
        },
    )?;

    // Advisory only — takes no slot. The slot is charged at account creation
    // (Task 6), so a device that abandons the passkey ceremony is not billed
    // for an account it never made. Checking here keeps the 429/403 on the
    // preflight response, where the client already handles them, rather than
    // surfacing a budget refusal after a full WebAuthn ceremony.
    app_state
        .db_store
        .check_attest_registration_budget(&attested.key_id)
        .await
        .map_err(|e| DeviceCheckError::DynamoDBOperationError(Box::new(e)))?;

    let now = Utc::now().timestamp();
    let ticket = RegistrationTicket {
        key_id: attested.key_id.clone(),
        issued_at: now,
        expires_at: now + REG_TICKET_TTL_SECONDS,
    };
    session
        .insert(SESSION_REG_TICKET_KEY, ticket.clone())
        .await
        .map_err(DeviceCheckError::InvalidSessionState)?;

    info!(
        "Issued registration ticket for attested key_id {} (expires {})",
        attested.key_id, ticket.expires_at
    );
    Ok(Json(PreflightResponse {
        expires_at: ticket.expires_at,
    }))
}

/// Is `rp_id_hash` one of the configured app-id hashes?
///
/// Membership, not equality: more than one app registers users, so a single
/// accepted value would refuse every other app with `AppIdMismatch`. Callers
/// must treat an empty `expected` as "not configured" and decide separately
/// whether that warns or refuses — this returns `false` for it, which is the
/// safe answer but not the whole policy.
pub fn app_id_is_accepted(rp_id_hash: &str, expected: &[String]) -> bool {
    expected.iter().any(|e| rp_id_hash.eq_ignore_ascii_case(e))
}

/// Generate a challenge for attestation or assertion
///
/// SECURITY: requires a CWT bound to `:username`, exactly as
/// [`generate_assertion_challenge`] does. App Attest proves the request comes
/// from a genuine, unmodified Apple app — it says nothing about *which*
/// account the device belongs to. Without this gate anyone could bind a
/// device they control to an arbitrary username, and (because
/// `finish_assertion` mints for the binding's user) trade it for a token
/// carrying that user's identity and entitlements.
pub async fn generate_challenge(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, DeviceCheckError> {
    info!("Generating App Attest challenge for user: {}", username);

    let user_id = authenticate_for_username(&app_state, &headers, &username).await?;

    // Generate a random challenge (32 bytes = 256 bits)
    let challenge = generate_random_challenge();

    // Store challenge in session for verification
    if let Err(err) = session
        .insert(
            SESSION_ATTEST_STATE_KEY,
            (username.clone(), user_id, challenge.clone()),
        )
        .await
    {
        error!("Failed to save attestation state: {:?}", err);
        return Err(DeviceCheckError::InvalidSessionState(err));
    }

    info!("Challenge generated successfully for: {}", username);
    Ok(Json(ChallengeResponse { challenge }))
}

/// Complete the attestation process and bind the device
pub async fn finish_attestation(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(request): Json<AttestationRequest>,
) -> Result<impl IntoResponse, DeviceCheckError> {
    info!(
        "Finishing App Attest attestation for key_id: {}",
        request.key_id
    );

    // Retrieve challenge from session. `user_id` was resolved from the CWT at
    // challenge time, so the binding below cannot name an account the caller
    // never authenticated as.
    let (username, user_id, challenge): (String, Uuid, String) = session
        .get(SESSION_ATTEST_STATE_KEY)
        .await?
        .ok_or_else(|| {
            error!("No attestation state found in session");
            DeviceCheckError::CorruptSession
        })?;

    // Clean up session immediately to prevent reuse
    if let Err(e) = session.remove_value(SESSION_ATTEST_STATE_KEY).await {
        error!("Failed to remove attestation state from session: {}", e);
        return Err(DeviceCheckError::SessionError(e.to_string()));
    }

    let attested = verify_attestation(
        &challenge,
        &request.key_id,
        &request.attestation_object,
        &request.client_data_hash,
        &VerifyOptions {
            expected_app_ids: app_state.app_attest_app_id.as_slice(),
            // Legacy bound-device path keeps warn-and-continue on an unset
            // APP_ATTEST_APP_ID; the registration gate (Task 5) passes true.
            require_app_id: false,
        },
    )?;

    let public_key = attested.public_key.clone();

    info!("Binding device {} to user {}", request.key_id, username);

    // Create device binding
    let binding = DeviceBinding {
        device_id: request.key_id.clone(),
        user_id,
        public_key: public_key.clone(),
        counter: 0,
        app_id: attested.rp_id_hash_str.clone(),
        created_at: Utc::now().timestamp(),
        updated_at: Utc::now().timestamp(),
    };

    // Store device binding in database. A key_id already bound to a different
    // account is refused rather than silently repointed.
    app_state
        .db_store
        .create_device_binding(&binding)
        .await
        .map_err(|e| match e {
            DynamoDBError::DeviceBindingConflict => DeviceCheckError::DeviceBindingConflict,
            other => DeviceCheckError::DynamoDBOperationError(Box::new(other)),
        })?;

    info!("Device binding created for key_id: {}", request.key_id);

    Ok(Json(AttestationResponse {
        success: true,
        message: "Device attestation successful".to_string(),
    }))
}

/// Generate assertion challenge (for existing device bindings)
pub async fn generate_assertion_challenge(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, DeviceCheckError> {
    info!("Generating assertion challenge for user: {}", username);

    // Verify CWT token and bind it to the username in the path. The CWT's `sub`
    // must resolve to the same user_id we look up by `username`; otherwise any
    // holder of a valid Arkavo CWT could request assertion challenges (and burn
    // session state) for arbitrary users.
    let user_id = authenticate_for_username(&app_state, &headers, &username).await?;

    // Generate challenge
    let challenge = generate_random_challenge();

    // Store challenge in session
    if let Err(err) = session
        .insert(
            SESSION_ASSERT_STATE_KEY,
            (username.clone(), user_id, challenge.clone()),
        )
        .await
    {
        error!("Failed to save assertion state: {:?}", err);
        return Err(DeviceCheckError::InvalidSessionState(err));
    }

    info!("Assertion challenge generated for: {}", username);
    Ok(Json(ChallengeResponse { challenge }))
}

/// Verify assertion and issue JWT token
pub async fn finish_assertion(
    Extension(app_state): Extension<AppState>,
    Extension(patreon): Extension<crate::patreon::PatreonState>,
    session: Session,
    Json(request): Json<AssertionRequest>,
) -> Result<impl IntoResponse, DeviceCheckError> {
    info!("Finishing assertion for key_id: {}", request.key_id);

    // Retrieve challenge from session
    let (username, session_user_id, challenge): (String, Uuid, String) = session
        .get(SESSION_ASSERT_STATE_KEY)
        .await?
        .ok_or_else(|| {
            error!("No assertion state found in session");
            DeviceCheckError::CorruptSession
        })?;

    // Clean up session
    if let Err(e) = session.remove_value(SESSION_ASSERT_STATE_KEY).await {
        error!("Failed to remove assertion state from session: {}", e);
        return Err(DeviceCheckError::SessionError(e.to_string()));
    }

    // Get device binding from database
    let binding = app_state
        .db_store
        .get_device_binding(&request.key_id)
        .await
        .map_err(|e| DeviceCheckError::DynamoDBOperationError(Box::new(e)))?
        .ok_or(DeviceCheckError::DeviceNotFound)?;

    // SECURITY: the token minted below carries `binding.user_id`, so the
    // binding must belong to the account this session authenticated as.
    // Without this the challenge's username is decorative: any caller holding
    // a device key could assert against a binding owned by someone else and
    // receive that user's identity and entitlements.
    if binding.user_id != session_user_id {
        warn!(
            "Assertion key_id {} is bound to {} but the session authenticated as {} ({})",
            request.key_id, binding.user_id, session_user_id, username
        );
        return Err(DeviceCheckError::DeviceNotFound);
    }

    // Decode assertion
    let assertion_bytes = base64::engine::general_purpose::STANDARD
        .decode(&request.assertion)
        .map_err(|e| DeviceCheckError::InvalidAssertion(e.to_string()))?;

    // Parse authenticator data from assertion
    let auth_data = parse_authenticator_data(&assertion_bytes)?;

    // Verify counter has incremented
    if auth_data.counter <= binding.counter {
        return Err(DeviceCheckError::InvalidCounter(format!(
            "Counter must increment. Expected > {}, got {}",
            binding.counter, auth_data.counter
        )));
    }

    // Decode client data hash
    let client_data_hash = base64::engine::general_purpose::STANDARD
        .decode(&request.client_data_hash)
        .map_err(|e| DeviceCheckError::InvalidClientData(e.to_string()))?;

    // Verify challenge
    let expected_hash = Sha256::digest(challenge.as_bytes());
    if client_data_hash.as_slice() != &expected_hash[..] {
        return Err(DeviceCheckError::ChallengeMismatch);
    }

    // Verify signature using stored public key
    // The assertion contains authenticator data + signature
    // Signature is over: authData || clientDataHash
    verify_assertion_signature(&assertion_bytes, &client_data_hash, &binding.public_key)?;

    // Update counter in database with race condition protection
    // Only update if the counter hasn't been modified by another request
    app_state
        .db_store
        .update_device_counter(&request.key_id, auth_data.counter, binding.counter)
        .await
        .map_err(|e| DeviceCheckError::DynamoDBOperationError(Box::new(e)))?;

    // The assertion token rides the platform audience and is what an iOS
    // client presents at KAS rewrap, so it needs the same Arkavo custom
    // claims as the WebAuthn auth token — without `arkavo_account_id` /
    // `arkavo_roles` the platform refuses it. Fails closed on a missing row.
    let record = app_state
        .db_store
        .get_user_by_id(&binding.user_id)
        .await
        .map_err(|e| DeviceCheckError::DynamoDBOperationError(Box::new(e)))?
        .ok_or(DeviceCheckError::UserNotFound)?;
    let user = crate::oidc::AuthenticatedUser::webauthn(record.user_id, record.entitlements);
    let arkavo_user = crate::oidc::arkavo_user_claims(&app_state, &patreon, &user).await;

    // Mint CWT assertion token with device public key bound via cnf claim
    let token = mint_assertion_token(
        &app_state,
        &binding,
        Some(&arkavo_user),
        Utc::now().timestamp(),
    )?;

    info!("Assertion successful for key_id: {}", request.key_id);

    Ok(Json(AssertionResponse { token }))
}

// Helper functions

fn generate_random_challenge() -> String {
    use uuid::Uuid;
    Uuid::new_v4().to_string()
}

/// Verify the App Attest chain: leaf -> intermediate(s) -> Apple's pinned root.
///
/// Every signature in the chain is checked and the chain must terminate at the
/// embedded root. Apple sends leaf + intermediate, so a one-element chain is
/// refused rather than treated as self-signed.
///
/// `now` is the instant validity windows are checked against.
/// **Production always passes `ASN1Time::now()`**: the only non-test caller is
/// [`verify_attestation_at`], and the only non-test caller of *that* is
/// [`verify_attestation`], which supplies the wall clock. The parameter is not
/// a way to disable expiry checking. It exists because the Task 0 fixture's
/// leaf is valid for about three days, and a suite wired to the wall clock
/// would start failing on a calendar date with no code change behind it —
/// which is how people learn to ignore a red suite.
fn validate_certificate_chain_at(x5c: &[Vec<u8>], now: ASN1Time) -> Result<(), DeviceCheckError> {
    if x5c.len() < 2 {
        return Err(DeviceCheckError::InvalidCertificateChain(format!(
            "expected leaf + intermediate, got {} certificate(s)",
            x5c.len()
        )));
    }

    // Cached Apple root CA DER, parsed once on first use.
    let root_cert_der = APPLE_ROOT_CERT_DER.get_or_init(|| {
        let root_pem = ::pem::parse(APPLE_APP_ATTEST_ROOT_CA.as_bytes())
            .expect("Failed to parse embedded Apple root CA PEM");
        root_pem.contents().to_vec()
    });
    let (_, root_cert) = X509Certificate::from_der(root_cert_der)
        .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?;

    let mut parsed = Vec::with_capacity(x5c.len());
    for der in x5c {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?;
        parsed.push(cert);
    }

    for cert in &parsed {
        if !cert.validity().is_valid_at(now) {
            return Err(DeviceCheckError::InvalidCertificateChain(format!(
                "certificate expired or not yet valid: {}",
                cert.subject()
            )));
        }
    }

    // Each certificate must be signed by the next one along.
    for pair in parsed.windows(2) {
        let (child, issuer) = (&pair[0], &pair[1]);
        if child.issuer() != issuer.subject() {
            return Err(DeviceCheckError::InvalidCertificateChain(format!(
                "issuer mismatch: {} is not issued by {}",
                child.subject(),
                issuer.subject()
            )));
        }
        child
            .verify_signature(Some(issuer.public_key()))
            .map_err(|e| {
                DeviceCheckError::InvalidCertificateChain(format!(
                    "signature check failed for {}: {e}",
                    child.subject()
                ))
            })?;
    }

    // The topmost certificate we were sent must chain to the pinned root.
    let top = parsed.last().expect("length checked above");
    if top.issuer() != root_cert.subject() {
        return Err(DeviceCheckError::InvalidCertificateChain(format!(
            "chain does not terminate at Apple's App Attest root: top issuer is {}",
            top.issuer()
        )));
    }
    top.verify_signature(Some(root_cert.public_key()))
        .map_err(|e| {
            DeviceCheckError::InvalidCertificateChain(format!("root signature check failed: {e}"))
        })?;

    Ok(())
}

/// Apple's App Attest nonce extension on the credCert.
///
/// The value is `SEQUENCE { [1] EXPLICIT OCTET STRING }` holding the 32 bytes
/// of `SHA256(authData || clientDataHash)` as Apple computed them.
const APPLE_NONCE_OID: [u64; 7] = [1, 2, 840, 113635, 100, 8, 2];

/// Read one definite-length DER TLV, checking the tag.
///
/// Hand-rolled rather than routed through a BER parser because the shape here
/// is fixed and three levels deep, and because BER's permissiveness is not
/// wanted: an indefinite length or a non-minimal tag in an attestation is a
/// malformed attestation, not something to accept and normalise. Returns the
/// contents and whatever follows the TLV.
fn der_tlv(input: &[u8], expect_tag: u8) -> Result<(&[u8], &[u8]), String> {
    let tag = *input.first().ok_or("truncated DER: no tag")?;
    if tag != expect_tag {
        return Err(format!(
            "expected DER tag 0x{expect_tag:02x}, got 0x{tag:02x}"
        ));
    }
    let first = *input.get(1).ok_or("truncated DER: no length")?;
    let (len, header) = if first < 0x80 {
        (first as usize, 2usize)
    } else {
        // Long form. 0x80 alone is BER's indefinite length, which DER forbids.
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(format!("unsupported DER length form 0x{first:02x}"));
        }
        let bytes = input
            .get(2..2 + n)
            .ok_or("truncated DER: short length bytes")?;
        let len = bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
        (len, 2 + n)
    };
    let end = header
        .checked_add(len)
        .ok_or("DER length overflows the address space")?;
    let contents = input
        .get(header..end)
        .ok_or("DER length runs past the end of the buffer")?;
    Ok((contents, &input[end..]))
}

/// Pull the 32 nonce bytes out of the credCert's App Attest extension.
///
/// A certificate with no such extension is not an App Attest credCert, so it
/// is refused rather than treated as "nothing to check".
fn extract_attestation_nonce(cert_der: &[u8]) -> Result<Vec<u8>, DeviceCheckError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?;

    let oid = x509_parser::der_parser::Oid::from(&APPLE_NONCE_OID).map_err(|e| {
        DeviceCheckError::InvalidCertificateChain(format!("bad nonce OID constant: {e:?}"))
    })?;

    let ext = cert
        .get_extension_unique(&oid)
        .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?
        .ok_or(DeviceCheckError::NonceExtensionMissing)?;

    let bad =
        |e: String| DeviceCheckError::InvalidCertificateChain(format!("nonce extension: {e}"));

    // SEQUENCE { [1] EXPLICIT { OCTET STRING } }
    let (seq, _) = der_tlv(ext.value, 0x30).map_err(bad)?;
    let (tagged, _) = der_tlv(seq, 0xa1).map_err(bad)?;
    let (nonce, _) = der_tlv(tagged, 0x04).map_err(bad)?;

    if nonce.len() != 32 {
        return Err(DeviceCheckError::InvalidCertificateChain(format!(
            "nonce extension is {} bytes, expected 32",
            nonce.len()
        )));
    }
    Ok(nonce.to_vec())
}

fn extract_public_key_from_cert(cert_der: &[u8]) -> Result<Vec<u8>, DeviceCheckError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?;

    let public_key = cert.public_key().raw.to_vec();
    Ok(public_key)
}

#[derive(Debug)]
#[allow(dead_code)]
struct AuthenticatorData {
    rp_id_hash: Vec<u8>,
    rp_id_hash_str: String,
    flags: u8,
    counter: u32,
}

/// The two App Attest environments. iOS release builds emit `appattest` and
/// developer builds `appattestdevelop`; macOS always emits `appattest`, even
/// for a locally signed build. `rpIdHash` already pins Team + Bundle ID, so a
/// development key still needs our signing identity — the check exists to
/// refuse anything that is not App Attest at all.
const ACCEPTED_AAGUIDS: [[u8; 16]; 2] = [*b"appattest\0\0\0\0\0\0\0", *b"appattestdevelop"];

/// authData's attested credential data, present only in an attestation.
struct AttestedCredential<'a> {
    aaguid: [u8; 16],
    credential_id: &'a [u8],
}

/// Read aaguid and credentialId from attestation authData.
///
/// Separate from [`parse_authenticator_data`] because the assertion path parses
/// 37-byte authData that has no attested credential data.
///
/// Layout after the 37-byte header: aaguid (16), credentialId length (2, BE),
/// credentialId.
fn parse_attested_credential(data: &[u8]) -> Result<AttestedCredential<'_>, DeviceCheckError> {
    let bad = |m: &str| DeviceCheckError::InvalidAuthenticatorData(m.to_string());
    let aaguid: [u8; 16] = data
        .get(37..53)
        .ok_or_else(|| bad("attestation authData has no attested credential data"))?
        .try_into()
        .expect("slice is 16 bytes");
    let len_bytes = data
        .get(53..55)
        .ok_or_else(|| bad("attestation authData is missing the credentialId length"))?;
    let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
    let credential_id = data
        .get(55..55 + len)
        .ok_or_else(|| bad("credentialId runs past the end of authData"))?;
    Ok(AttestedCredential {
        aaguid,
        credential_id,
    })
}

/// SHA256 of the credCert's public key as an X9.62 uncompressed point.
///
/// This is Apple's key identifier. It is the 65-byte point, not the DER
/// SubjectPublicKeyInfo that [`extract_public_key_from_cert`] returns.
fn attested_key_hash(cert_der: &[u8]) -> Result<[u8; 32], DeviceCheckError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?;
    let point = &cert.public_key().subject_public_key.data;
    if point.len() != 65 || point[0] != 0x04 {
        return Err(DeviceCheckError::InvalidCertificateChain(format!(
            "credCert key is not an uncompressed P-256 point ({} bytes)",
            point.len()
        )));
    }
    Ok(Sha256::digest(point).into())
}

fn parse_authenticator_data(data: &[u8]) -> Result<AuthenticatorData, DeviceCheckError> {
    if data.len() < 37 {
        return Err(DeviceCheckError::InvalidAuthenticatorData(
            "Authenticator data too short".to_string(),
        ));
    }

    let rp_id_hash = data[0..32].to_vec();
    let rp_id_hash_str = hex::encode(&rp_id_hash);
    let flags = data[32];
    let counter = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

    Ok(AuthenticatorData {
        rp_id_hash,
        rp_id_hash_str,
        flags,
        counter,
    })
}

fn verify_assertion_signature(
    assertion_bytes: &[u8],
    client_data_hash: &[u8],
    public_key_der: &[u8],
) -> Result<(), DeviceCheckError> {
    // App Attest assertion format: authenticatorData || signature
    // Signature is 64 bytes for P-256 ECDSA (r || s, 32 bytes each)
    if assertion_bytes.len() < 37 + 64 {
        return Err(DeviceCheckError::InvalidAssertion(
            "Assertion too short to contain signature".to_string(),
        ));
    }

    let auth_data_len = assertion_bytes.len() - 64;
    let auth_data = &assertion_bytes[0..auth_data_len];
    let signature_bytes = &assertion_bytes[auth_data_len..];

    // Parse the P-256 public key from DER format
    let verifying_key = P256VerifyingKey::from_public_key_der(public_key_der).map_err(|e| {
        DeviceCheckError::InvalidCertificateChain(format!("Failed to parse public key: {}", e))
    })?;

    // Create signature object
    let signature = P256Signature::from_slice(signature_bytes).map_err(|e| {
        DeviceCheckError::InvalidAssertion(format!("Invalid signature format: {}", e))
    })?;

    // The signed data is: authenticatorData || clientDataHash
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(auth_data);
    signed_data.extend_from_slice(client_data_hash);

    // Verify the signature
    verifying_key
        .verify(&signed_data, &signature)
        .map_err(|e| {
            error!("Assertion signature verification failed: {}", e);
            DeviceCheckError::InvalidAssertion(format!("Signature verification failed: {}", e))
        })?;

    info!("Assertion signature verified successfully");
    Ok(())
}

/// Device class derived from App Attest assertion freshness (spec §1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceClass {
    Attested,
    Managed,
    // Not produced by `device_class` today (a binding always exists once we
    // mint here) — reserved for a verifier-side caller that finds no binding
    // at all.
    #[allow(dead_code)]
    Unverified,
}

impl DeviceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceClass::Attested => "attested",
            DeviceClass::Managed => "managed",
            DeviceClass::Unverified => "unverified",
        }
    }
}

/// Class from the last successful assertion time. A binding always exists
/// here (we are minting after a verified assertion), so the floor is `managed`.
pub fn device_class(last_assertion_at: i64, now: i64) -> (DeviceClass, i64) {
    let expiry = last_assertion_at + crate::constants::DEVICE_ATTESTATION_TTL_SECONDS;
    if now <= expiry {
        (DeviceClass::Attested, expiry)
    } else {
        (DeviceClass::Managed, expiry)
    }
}

/// Mint a CWT assertion token for a successfully-attested device.
///
/// The token audience is `"arkavo:devicecheck"` (plus the configured
/// platform audience, when set) and carries the device's App Attest public
/// key as the `cnf` claim so relying parties can perform DPoP-style
/// proof-of-possession checks, along with an `arkavo_npe` device descriptor.
///
/// `arkavo_user` carries the per-user Arkavo custom claims (as derived by
/// `oidc::arkavo_user_claims`) so this token matches the WebAuthn auth token
/// and the OIDC access token at the platform's verifier. `POST
/// /device-check/assert` always passes them; `None` (tests) mints without.
pub fn mint_assertion_token(
    app_state: &AppState,
    binding: &DeviceBinding,
    arkavo_user: Option<&crate::cwt::ArkavoUserClaims>,
    now: i64,
) -> Result<String, DeviceCheckError> {
    let cnf = crate::cwt::cnf_from_app_attest(&binding.public_key, binding.device_id.as_bytes())?;
    let (class, attestation_expiry) = device_class(now, now); // assertion just verified
    let mut claims = crate::cwt::ArkavoClaims::devicecheck(
        &app_state.issuer,
        &binding.user_id.to_string(),
        AUTH_TOKEN_HOURS,
        app_state.platform_audience.as_deref(),
    )
    .with_cnf(cnf)
    .with_arkavo_npe(crate::cwt::ArkavoNpe {
        npe_type: "device".into(),
        class: Some(class.as_str().into()),
        attestation_expiry: Some(attestation_expiry),
        device_id: Some(binding.device_id.clone()),
        delegation_id: None,
        depth: None,
        chain: None,
    });
    if let Some(u) = arkavo_user {
        claims = claims.with_arkavo_user(u);
    }
    let bytes = crate::cwt::mint(&claims, &app_state.cwt_signing_key, &app_state.cwt_kid)?;
    Ok(crate::cwt::encode_for_header(&bytes))
}

/// Verify the caller's `X-Auth-Token` and confirm it belongs to `username`.
///
/// Returns the authenticated `user_id`. Both device-check challenge endpoints
/// go through this: App Attest establishes that a request comes from a genuine
/// Apple device, never which Arkavo account that device belongs to, so account
/// ownership has to be proven separately before a binding is created or used.
async fn authenticate_for_username(
    app_state: &AppState,
    headers: &HeaderMap,
    username: &str,
) -> Result<Uuid, DeviceCheckError> {
    let Some(token_header) = headers.get("X-Auth-Token") else {
        return Err(DeviceCheckError::MissingToken);
    };
    let token = token_header
        .to_str()
        .map_err(|_| DeviceCheckError::InvalidToken)?;
    let claims = verify_inbound_token(app_state, token)?;
    let token_user_id = Uuid::parse_str(&claims.sub).map_err(|_| DeviceCheckError::UserNotFound)?;

    let user = app_state
        .db_store
        .get_user_by_name(username)
        .await
        .map_err(|e| DeviceCheckError::DynamoDBOperationError(Box::new(e)))?
        .ok_or(DeviceCheckError::UserNotFound)?;
    if token_user_id != user.user_id {
        return Err(DeviceCheckError::UserNotFound);
    }
    Ok(user.user_id)
}

/// Verify an inbound CWT X-Auth-Token at the assertion challenge endpoint.
///
/// Accepts only tokens with `aud = "arkavo"` (standard Arkavo auth tokens).
/// Legacy JWTs are rejected — callers receive `Err(DeviceCheckError::Cwt(_))`.
pub fn verify_inbound_token(
    app_state: &AppState,
    token: &str,
) -> Result<crate::cwt::ArkavoClaims, DeviceCheckError> {
    let bytes = crate::cwt::decode_from_header(token)?;
    let opts = crate::cwt::VerifyOptions {
        expected_iss: Some(&app_state.issuer),
        // The assertion challenge endpoint expects a standard Arkavo auth token,
        // NOT a devicecheck assertion token (that would create a cycle).
        expected_aud: Some("arkavo"),
        now: chrono::Utc::now().timestamp(),
        skew_secs: crate::cwt::DEFAULT_SKEW_SECS,
    };
    Ok(crate::cwt::verify(
        &bytes,
        &app_state.cwt_verifying_key,
        &opts,
    )?)
}

#[derive(Error, Debug)]
pub enum DeviceCheckError {
    #[error("Corrupt Session")]
    CorruptSession,

    #[error("CWT error: {0}")]
    Cwt(#[from] crate::cwt::CwtError),

    #[error("User Not Found")]
    UserNotFound,

    #[error("Device Not Found")]
    DeviceNotFound,

    #[error("Deserializing Session failed: {0}")]
    InvalidSessionState(#[from] tower_sessions::session::Error),

    #[error("Missing token")]
    MissingToken,

    #[error("Invalid token")]
    InvalidToken,

    #[error("DynamoDB operation failed: {0}")]
    DynamoDBOperationError(#[from] Box<DynamoDBError>),

    #[error("Session operation failed: {0}")]
    SessionError(String),

    #[error("Invalid attestation object: {0}")]
    InvalidAttestationObject(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Invalid certificate chain: {0}")]
    InvalidCertificateChain(String),

    #[error("Invalid authenticator data: {0}")]
    InvalidAuthenticatorData(String),

    #[error("Invalid counter: {0}")]
    InvalidCounter(String),

    #[error("Invalid client data: {0}")]
    InvalidClientData(String),

    #[error("Challenge mismatch")]
    ChallengeMismatch,

    #[error("Invalid assertion: {0}")]
    InvalidAssertion(String),

    #[error("credCert is missing the App Attest nonce extension")]
    NonceExtensionMissing,

    #[error("Attestation nonce does not match the issued challenge")]
    NonceMismatch,

    /// The claimed `key_id` is not the attested key: it is not
    /// `SHA256(publicKey)`, or authData's `credentialId` disagrees with it.
    #[error("key_id does not identify the attested key")]
    KeyIdMismatch,

    /// authData's aaguid is neither App Attest environment.
    #[error("Invalid App Attest aaguid: {0}")]
    InvalidAaguid(String),

    #[error("App ID mismatch")]
    AppIdMismatch,

    /// `APP_ATTEST_APP_ID` is unset on a path that requires it.
    ///
    /// Distinct from [`Self::AppIdMismatch`]: that is a client presenting the
    /// wrong app, this is the server unable to decide. It is a server
    /// misconfiguration, so it must never reach a client as a permanent
    /// "this device is barred" verdict — see
    /// `docs/app-attest-preflight-contract.md`.
    #[error("App Attest app id is not configured")]
    AppIdNotConfigured,

    #[error("Device is already bound to a different account")]
    DeviceBindingConflict,
}

impl IntoResponse for DeviceCheckError {
    fn into_response(self) -> axum::response::Response {
        // CWT verification failures map to 401 Unauthorized; everything else is 400.
        let (status, body) = match self {
            DeviceCheckError::Cwt(err) => {
                (StatusCode::UNAUTHORIZED, format!("Unauthorized: {}", err))
            }
            DeviceCheckError::CorruptSession => {
                (StatusCode::BAD_REQUEST, "Corrupt Session".to_string())
            }
            DeviceCheckError::UserNotFound => {
                (StatusCode::BAD_REQUEST, "User Not Found".to_string())
            }
            DeviceCheckError::DeviceNotFound => {
                (StatusCode::BAD_REQUEST, "Device Not Found".to_string())
            }
            DeviceCheckError::AppIdMismatch => (
                StatusCode::BAD_REQUEST,
                "Attestation was produced by an unexpected app".to_string(),
            ),
            // 401, not 400: both are a rejected attestation — the caller
            // failed to prove it holds an attestation for *this* challenge —
            // rather than a malformed request the client could reshape.
            DeviceCheckError::NonceExtensionMissing => (
                StatusCode::UNAUTHORIZED,
                "credCert is missing the App Attest nonce extension".to_string(),
            ),
            DeviceCheckError::NonceMismatch => (
                StatusCode::UNAUTHORIZED,
                "Attestation nonce does not match the issued challenge".to_string(),
            ),
            DeviceCheckError::KeyIdMismatch => (
                StatusCode::UNAUTHORIZED,
                "key_id does not identify the attested key".to_string(),
            ),
            DeviceCheckError::InvalidAaguid(err) => (
                StatusCode::UNAUTHORIZED,
                format!("Invalid App Attest aaguid: {}", err),
            ),
            // 503, deliberately not 403: the server cannot decide, which is an
            // operator problem and is retryable. A 403 here would be
            // indistinguishable from a genuine permanent refusal at the first
            // enforcing deploy, where an unset value fails closed for every
            // user at once.
            DeviceCheckError::AppIdNotConfigured => (
                StatusCode::SERVICE_UNAVAILABLE,
                "App Attest is not configured on this server".to_string(),
            ),
            DeviceCheckError::DeviceBindingConflict => (
                StatusCode::CONFLICT,
                "Device is already bound to a different account".to_string(),
            ),
            DeviceCheckError::InvalidSessionState(_) => (
                StatusCode::BAD_REQUEST,
                "Deserializing Session failed".to_string(),
            ),
            DeviceCheckError::MissingToken => {
                (StatusCode::UNAUTHORIZED, "Missing token".to_string())
            }
            DeviceCheckError::InvalidToken => {
                (StatusCode::UNAUTHORIZED, "Invalid token".to_string())
            }
            DeviceCheckError::DynamoDBOperationError(err) => match *err {
                DynamoDBError::TableNotExists(table) => (
                    StatusCode::BAD_REQUEST,
                    format!("Service setup incomplete: {} table not configured", table),
                ),
                _ => (
                    StatusCode::BAD_REQUEST,
                    format!("Database operation failed: {}", err),
                ),
            },
            DeviceCheckError::SessionError(err) => (
                StatusCode::BAD_REQUEST,
                format!("Session operation failed: {}", err),
            ),
            DeviceCheckError::InvalidAttestationObject(err) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid attestation object: {}", err),
            ),
            DeviceCheckError::InvalidFormat(err) => {
                (StatusCode::BAD_REQUEST, format!("Invalid format: {}", err))
            }
            DeviceCheckError::InvalidCertificateChain(err) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid certificate chain: {}", err),
            ),
            DeviceCheckError::InvalidAuthenticatorData(err) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid authenticator data: {}", err),
            ),
            DeviceCheckError::InvalidCounter(err) => {
                (StatusCode::BAD_REQUEST, format!("Invalid counter: {}", err))
            }
            DeviceCheckError::InvalidClientData(err) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid client data: {}", err),
            ),
            DeviceCheckError::ChallengeMismatch => {
                (StatusCode::BAD_REQUEST, "Challenge mismatch".to_string())
            }
            DeviceCheckError::InvalidAssertion(err) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid assertion: {}", err),
            ),
        };
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {

    use super::{
        PreflightRejection, REG_TICKET_TTL_SECONDS, RegistrationTicket, preflight_error_mapping,
        ticket_is_valid,
    };
    use crate::db::DynamoDBError;

    #[tokio::test]
    async fn register_challenge_route_answers_unauthenticated_and_sets_a_session() {
        use axum::{Router, routing::get};
        use tower::ServiceExt;
        use tower_sessions::{MemoryStore, SessionManagerLayer};

        let app = Router::new()
            .route("/device-check/register-challenge", get(register_challenge))
            .layer(SessionManagerLayer::new(MemoryStore::default()).with_secure(false));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/device-check/register-challenge")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the preflight challenge must not require authentication — the caller has no account yet"
        );
        assert!(
            resp.headers().get(axum::http::header::SET_COOKIE).is_some(),
            "the challenge lives in the session, so the response must establish one; \
             a client that drops this cookie gets session_invalid on register-attest"
        );

        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            v["challenge"].as_str().is_some_and(|c| !c.is_empty()),
            "challenge must be present and non-empty"
        );
    }

    /// Regression: Apple sends camelCase keys, so the snake_case struct
    /// matched nothing and every genuine attestation died at CBOR decode with
    /// `missing field att_stmt` — long before any verification ran. The bug
    /// survived because no test ever fed the parser Apple's actual shape, and
    /// the only caller (the bound-device path) had no clients.
    #[test]
    fn attestation_object_parses_apples_camelcase_keys() {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode("o2NmbXRvYXBwbGUtYXBwYXR0ZXN0Z2F0dFN0bXSiY3g1Y4JIbGVhZmNlcnRMaW50ZXJtZWRpYXRlZ3JlY2VpcHRMcmVjZWlwdGJ5dGVzaGF1dGhEYXRhWDnqLe/J578UuDKw+15K2o8K8OEU3Kn8d0HNoX2HXPG8AUAAAAAAYXBwYXR0ZXN0AAAAAAAAAHRhaWw=")
            .unwrap();
        let att: AttestationObject = ciborium::from_reader(&bytes[..])
            .expect("Apple's camelCase attestation object must deserialize");
        assert_eq!(att.fmt, "apple-appattest");
        assert_eq!(att.att_stmt.x5c.len(), 2, "x5c must survive the rename");
        assert!(
            att.att_stmt.receipt.is_some(),
            "receipt is Task 0 Step 4's input"
        );
        assert!(
            !att.auth_data.is_empty(),
            "authData must survive the rename"
        );
    }

    #[test]
    fn attestation_object_rejects_snake_case_keys() {
        // Pins the direction of the fix: the shape the old struct expected is
        // not a shape Apple produces, so accepting it would mean the rename
        // had been applied the wrong way round.
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode("o2NmbXRvYXBwbGUtYXBwYXR0ZXN0aGF0dF9zdG10omN4NWOBSGxlYWZjZXJ0Z3JlY2VpcHRBcmlhdXRoX2RhdGFYOeot78nnvxS4MrD7Xkrajwrw4RTcqfx3Qc2hfYdc8bwBQAAAAABhcHBhdHRlc3QAAAAAAAAAdGFpbA==")
            .unwrap();
        let parsed: Result<AttestationObject, _> = ciborium::from_reader(&bytes[..]);
        assert!(parsed.is_err(), "snake_case is not Apple's wire format");
    }

    fn load_fixture() -> serde_json::Value {
        let raw = std::fs::read_to_string("tests/fixtures/appattest/attestation.json")
            .expect("Task 0 fixture missing: tests/fixtures/appattest/attestation.json");
        serde_json::from_str(&raw).expect("fixture is not valid JSON")
    }

    /// The first test in this codebase to run a **genuine** Apple attestation
    /// through the parser. Everything before it round-tripped hand-built
    /// structs through the same field names, which is precisely the test that
    /// cannot catch a wire-format mismatch — and did not, for the whole life
    /// of this module.
    #[test]
    fn real_attestation_parses_and_matches_its_recorded_fields() {
        use base64::Engine as _;
        let f = load_fixture();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(f["attestation_object"].as_str().unwrap())
            .unwrap();

        let att: AttestationObject =
            ciborium::from_reader(&bytes[..]).expect("a real attestation must deserialize");

        assert_eq!(att.fmt, "apple-appattest");
        assert_eq!(
            att.att_stmt.x5c.len(),
            2,
            "leaf + Apple App Attestation CA 1"
        );
        assert!(
            att.att_stmt.receipt.as_ref().is_some_and(|r| !r.is_empty()),
            "the receipt is Task 0 Step 4's input and must survive parsing"
        );

        let auth = parse_authenticator_data(&att.auth_data).expect("authData must parse");
        assert_eq!(
            auth.rp_id_hash_str,
            f["rp_id_hash"].as_str().unwrap(),
            "rpIdHash must equal SHA256(TeamID.BundleID) — macOS binds per App ID"
        );
        assert_eq!(auth.counter, 0, "attestation counter is always 0");
    }

    #[test]
    fn real_attestation_challenge_hashes_to_its_client_data_hash() {
        use base64::Engine as _;
        let f = load_fixture();
        let want = base64::engine::general_purpose::STANDARD
            .decode(f["client_data_hash"].as_str().unwrap())
            .unwrap();
        let got = Sha256::digest(f["challenge"].as_str().unwrap().as_bytes());
        assert_eq!(&got[..], want.as_slice());
    }

    #[test]
    fn real_attestation_app_id_is_accepted_by_the_configured_set() {
        // The macOS hash must pass app_id_is_accepted alongside the iOS one —
        // both apps register users, so the set has to admit either.
        let f = load_fixture();
        let macos = f["app_id_hash"].as_str().unwrap().to_string();
        let ios = "543398d88f303adedb67445ee9edbf1e1733a73d92bf6992cfbf228d60763cf8".to_string();
        let set = vec![ios, macos.clone()];
        assert!(app_id_is_accepted(&macos, &set));
    }

    #[test]
    fn fixture_verify_at_sits_inside_the_leaf_certificate_window() {
        // The leaf is valid ~3 days. Task 3 checks the chain against verify_at
        // rather than the wall clock, so if this drifts outside the window the
        // suite starts failing on a date unrelated to any code change.
        let f = load_fixture();
        let at = f["verify_at"].as_i64().unwrap();
        let nb = chrono::DateTime::parse_from_rfc3339(f["leaf_cert_not_before"].as_str().unwrap())
            .unwrap()
            .timestamp();
        let na = chrono::DateTime::parse_from_rfc3339(f["leaf_cert_not_after"].as_str().unwrap())
            .unwrap()
            .timestamp();
        assert!(nb <= at && at <= na, "verify_at {at} outside [{nb}, {na}]");
    }

    #[test]
    fn ticket_expiry_is_enforced() {
        let now = 1_800_000_000i64;
        let fresh = RegistrationTicket {
            key_id: "k".into(),
            issued_at: now,
            expires_at: now + REG_TICKET_TTL_SECONDS,
        };
        assert!(ticket_is_valid(&fresh, now));
        assert!(ticket_is_valid(&fresh, now + REG_TICKET_TTL_SECONDS));
        assert!(
            !ticket_is_valid(&fresh, now + REG_TICKET_TTL_SECONDS + 1),
            "an expired ticket must not admit"
        );
    }

    /// Every contract code, asserted against docs/app-attest-preflight-contract.md.
    #[test]
    fn preflight_codes_match_the_published_contract() {
        let cases: Vec<(DeviceCheckError, StatusCode, &str)> = vec![
            (
                DeviceCheckError::AppIdMismatch,
                StatusCode::BAD_REQUEST,
                "app_id_mismatch",
            ),
            (
                DeviceCheckError::AppIdNotConfigured,
                StatusCode::SERVICE_UNAVAILABLE,
                "app_id_not_configured",
            ),
            (
                DeviceCheckError::CorruptSession,
                StatusCode::BAD_REQUEST,
                "session_invalid",
            ),
            (
                DeviceCheckError::ChallengeMismatch,
                StatusCode::BAD_REQUEST,
                "attestation_invalid",
            ),
            (
                DeviceCheckError::InvalidAttestationObject("x".into()),
                StatusCode::BAD_REQUEST,
                "attestation_invalid",
            ),
            (
                DeviceCheckError::DynamoDBOperationError(Box::new(
                    DynamoDBError::AttestLifetimeCapExceeded,
                )),
                StatusCode::FORBIDDEN,
                "attest_registration_cap",
            ),
            (
                DeviceCheckError::DynamoDBOperationError(Box::new(DynamoDBError::RateLimited {
                    retry_after: 60,
                })),
                StatusCode::TOO_MANY_REQUESTS,
                "attest_rate_limited",
            ),
            (
                DeviceCheckError::DynamoDBOperationError(Box::new(DynamoDBError::Internal(
                    "boom".into(),
                ))),
                StatusCode::SERVICE_UNAVAILABLE,
                "attest_unavailable",
            ),
        ];
        for (err, want_status, want_code) in cases {
            let (status, code, _) = preflight_error_mapping(&err);
            assert_eq!(status, want_status, "status for {code}");
            assert_eq!(code, want_code);
        }
    }

    #[test]
    fn attest_registration_cap_is_the_only_permanent_code() {
        // The contract's load-bearing rule. If a second code ever maps to 403,
        // a client treating 403 as permanent starts barring devices for a
        // reason that can clear — which at the first enforcing deploy would
        // hit every user at once.
        let every_error = vec![
            DeviceCheckError::AppIdMismatch,
            DeviceCheckError::AppIdNotConfigured,
            DeviceCheckError::CorruptSession,
            DeviceCheckError::ChallengeMismatch,
            DeviceCheckError::InvalidFormat("x".into()),
            DeviceCheckError::InvalidCounter("x".into()),
            DeviceCheckError::InvalidClientData("x".into()),
            DeviceCheckError::InvalidCertificateChain("x".into()),
            DeviceCheckError::SessionError("x".into()),
            DeviceCheckError::MissingToken,
            DeviceCheckError::UserNotFound,
            DeviceCheckError::DynamoDBOperationError(Box::new(DynamoDBError::RateLimited {
                retry_after: 1,
            })),
            DeviceCheckError::DynamoDBOperationError(Box::new(
                DynamoDBError::AttestLifetimeCapExceeded,
            )),
        ];
        let permanent: Vec<&str> = every_error
            .iter()
            .map(preflight_error_mapping)
            .filter(|(s, _, _)| *s == StatusCode::FORBIDDEN)
            .map(|(_, c, _)| c)
            .collect();
        assert_eq!(permanent, vec!["attest_registration_cap"]);
    }

    #[test]
    fn only_rate_limited_carries_retry_after() {
        let (_, _, ra) = preflight_error_mapping(&DeviceCheckError::DynamoDBOperationError(
            Box::new(DynamoDBError::RateLimited { retry_after: 3600 }),
        ));
        assert_eq!(ra, Some(3600));

        // A permanent refusal must not suggest a retry that can never work.
        let (_, _, ra) = preflight_error_mapping(&DeviceCheckError::DynamoDBOperationError(
            Box::new(DynamoDBError::AttestLifetimeCapExceeded),
        ));
        assert_eq!(ra, None);
    }

    #[tokio::test]
    async fn preflight_rejection_body_is_json_with_a_stable_token() {
        // The Task 5 acceptance criterion: a plain-text body leaves the client
        // with nothing to discriminate on, so it falls back to retryable and
        // the permanent case becomes unreachable.
        let resp = PreflightRejection(DeviceCheckError::AppIdNotConfigured).into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/json"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"], "app_id_not_configured");
        assert!(v["error_description"].is_string());
    }

    #[tokio::test]
    async fn rate_limited_rejection_sets_retry_after_header() {
        let resp = PreflightRejection(DeviceCheckError::DynamoDBOperationError(Box::new(
            DynamoDBError::RateLimited { retry_after: 120 },
        )))
        .into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers().get(axum::http::header::RETRY_AFTER).unwrap(),
            "120"
        );
    }

    use super::{AttestedKey, VerifyOptions, verify_attestation};

    #[test]
    fn app_id_not_configured_is_503_not_403() {
        // Contract: a server that cannot decide must not look like a permanent
        // refusal. At the first enforcing deploy an unset APP_ATTEST_APP_ID
        // fails closed for every user at once; as a 403 next to the genuine
        // lifetime-cap refusal, a client would tell the whole user base their
        // hardware is barred. See docs/app-attest-preflight-contract.md.
        let resp = DeviceCheckError::AppIdNotConfigured.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn app_id_mismatch_and_not_configured_are_distinct_statuses() {
        // A client discriminating on status alone must still separate "wrong
        // app" from "server not configured".
        assert_ne!(
            DeviceCheckError::AppIdMismatch.into_response().status(),
            DeviceCheckError::AppIdNotConfigured
                .into_response()
                .status()
        );
    }

    #[test]
    fn verify_attestation_rejects_non_base64_attestation() {
        let err = verify_attestation(
            "challenge",
            "key",
            "!!!not base64!!!",
            "",
            &VerifyOptions {
                expected_app_ids: &[],
                require_app_id: false,
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, DeviceCheckError::InvalidAttestationObject(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_attestation_rejects_non_cbor_payload() {
        use base64::Engine as _;
        let garbage = base64::engine::general_purpose::STANDARD.encode(b"not cbor at all");
        let err = verify_attestation(
            "challenge",
            "key",
            &garbage,
            "",
            &VerifyOptions {
                expected_app_ids: &[],
                require_app_id: false,
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, DeviceCheckError::InvalidAttestationObject(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_options_carries_a_set_not_a_single_value() {
        // Guards the Task 1 / Task 5 contradiction: the plan declared
        // expected_app_id as Option<&str>, which cannot hold both apps.
        let ids = vec!["aaa".to_string(), "bbb".to_string()];
        let opts = VerifyOptions {
            expected_app_ids: &ids,
            require_app_id: true,
        };
        assert_eq!(opts.expected_app_ids.len(), 2);
        assert!(opts.require_app_id);
    }

    #[test]
    fn attested_key_round_trips_the_verified_fields() {
        let k = AttestedKey {
            key_id: "k".into(),
            public_key: vec![1, 2, 3],
            rp_id_hash_str: "ea2d".into(),
            counter: 0,
        };
        assert_eq!(k.key_id, "k");
        assert_eq!(k.counter, 0);
        assert_eq!(k.rp_id_hash_str, "ea2d");
    }

    use super::app_id_is_accepted;

    #[test]
    fn app_id_accepts_any_member_of_the_set() {
        let set = vec!["aaa".to_string(), "bbb".to_string()];
        assert!(app_id_is_accepted("aaa", &set));
        assert!(
            app_id_is_accepted("bbb", &set),
            "the second app must not be refused; both register users"
        );
        assert!(!app_id_is_accepted("ccc", &set));
    }

    #[test]
    fn app_id_comparison_is_case_insensitive() {
        assert!(app_id_is_accepted("AAA", &["aaa".to_string()]));
    }

    #[test]
    fn app_id_is_refused_when_the_set_is_empty() {
        // Empty means "not configured". This returns false; the caller decides
        // whether that warns (bound device path) or refuses (gate path).
        assert!(!app_id_is_accepted("aaa", &[]));
    }

    use super::*;

    #[test]
    fn test_generate_random_challenge() {
        let challenge1 = generate_random_challenge();
        let challenge2 = generate_random_challenge();

        // Challenges should be UUIDs
        assert!(Uuid::parse_str(&challenge1).is_ok());
        assert!(Uuid::parse_str(&challenge2).is_ok());

        // Different challenges should be different
        assert_ne!(challenge1, challenge2);
    }

    #[test]
    fn test_parse_authenticator_data() {
        // Create a minimal valid authenticator data (37 bytes)
        let mut data = vec![0u8; 37];
        // Set counter to 5
        data[33] = 0;
        data[34] = 0;
        data[35] = 0;
        data[36] = 5;

        let result = parse_authenticator_data(&data);
        assert!(result.is_ok());

        let auth_data = result.unwrap();
        assert_eq!(auth_data.counter, 5);
        assert_eq!(auth_data.rp_id_hash.len(), 32);
    }

    #[test]
    fn test_parse_authenticator_data_too_short() {
        let data = vec![0u8; 36]; // Too short
        let result = parse_authenticator_data(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_device_check_error_messages() {
        // BAD_REQUEST errors
        let bad_request_errors = vec![
            DeviceCheckError::CorruptSession,
            DeviceCheckError::UserNotFound,
            DeviceCheckError::DeviceNotFound,
            DeviceCheckError::ChallengeMismatch,
            DeviceCheckError::AppIdMismatch,
        ];

        for error in bad_request_errors {
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        // A key_id already bound elsewhere is a conflict, not a bad request.
        assert_eq!(
            DeviceCheckError::DeviceBindingConflict
                .into_response()
                .status(),
            StatusCode::CONFLICT
        );

        // UNAUTHORIZED errors — token-related failures
        let unauthorized_errors = vec![
            DeviceCheckError::MissingToken,
            DeviceCheckError::InvalidToken,
            DeviceCheckError::Cwt(crate::cwt::CwtError::InvalidSignature),
        ];

        for error in unauthorized_errors {
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[test]
    fn test_app_id_comparison_is_case_insensitive_hex() {
        // `APP_ATTEST_APP_ID` is operator-supplied hex; AppState lower-cases it
        // at startup, but the parsed rpIdHash is formatted independently, so
        // the comparison must not be case-sensitive.
        let expected = "8a1b2c3d";
        assert!("8A1B2C3D".eq_ignore_ascii_case(expected));
        assert!("8a1b2c3d".eq_ignore_ascii_case(expected));
        assert!(!"8a1b2c3e".eq_ignore_ascii_case(expected));
    }

    #[test]
    fn test_attestation_format_validation() {
        // Valid format
        assert_eq!("apple-appattest", "apple-appattest");

        // Invalid formats
        assert_ne!("fido-u2f", "apple-appattest");
        assert_ne!("packed", "apple-appattest");
    }

    #[test]
    fn test_counter_validation() {
        // Initial attestation should have counter 0
        assert_eq!(0, 0);

        // Assertions should increment
        let old_counter = 5u32;
        let new_counter = 6u32;
        assert!(new_counter > old_counter);

        // Invalid: counter doesn't increment
        let invalid_counter = 5u32;
        assert!(invalid_counter <= old_counter);
    }

    #[test]
    fn test_signature_verification_input_validation() {
        // Test that assertion must be long enough to contain signature
        let short_assertion = vec![0u8; 50]; // Too short (needs at least 37 + 64 = 101)
        let client_data = vec![0u8; 32];
        let public_key = vec![0u8; 91]; // Minimal P-256 public key DER

        let result = verify_assertion_signature(&short_assertion, &client_data, &public_key);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("too short to contain signature")
        );
    }

    #[test]
    fn test_nonce_calculation() {
        // Verify nonce is properly calculated from authData and clientDataHash
        let auth_data = vec![1u8; 37];
        let client_data_hash = vec![2u8; 32];

        let mut nonce_data = Vec::new();
        nonce_data.extend_from_slice(&auth_data);
        nonce_data.extend_from_slice(&client_data_hash);

        let nonce = Sha256::digest(&nonce_data);

        // Nonce should be 32 bytes (SHA256 output)
        assert_eq!(nonce.len(), 32);

        // Nonce should be deterministic
        let nonce2 = Sha256::digest(&nonce_data);
        assert_eq!(&nonce[..], &nonce2[..]);
    }

    #[tokio::test]
    async fn assertion_token_is_cose_sign1_with_devicecheck_aud() {
        use coset::CborSerializable;
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
        }
        unsafe {
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        }
        unsafe {
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        }

        let app_state = crate::test_helpers::build_test_app_state().await;
        let user_id = uuid::Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        // Sample P-256 public key for cnf (uncompressed SEC1).
        let scalar = p256::FieldBytes::from([0x99u8; 32]);
        let secret = p256::SecretKey::from_bytes(&scalar).expect("scalar");
        let vk: p256::ecdsa::VerifyingKey = *p256::ecdsa::SigningKey::from(&secret).verifying_key();
        let pubkey = vk.to_encoded_point(false).as_bytes().to_vec();

        let binding = DeviceBinding {
            device_id: "device-1".to_string(),
            user_id,
            public_key: pubkey,
            counter: 1,
            app_id: "app-id".to_string(),
            created_at: now,
            updated_at: now,
        };

        let token = crate::device_check::mint_assertion_token(&app_state, &binding, None, now)
            .expect("mint");

        let raw = crate::cwt::decode_from_header(&token).unwrap();
        let inner = crate::cwt::strip_cwt_tag(&raw).expect("CWT tag");
        let sign1 = coset::CoseSign1::from_slice(inner).unwrap();
        let claims = crate::cwt::claims_from_cbor(sign1.payload.as_ref().unwrap()).unwrap();
        assert_eq!(
            claims.aud,
            crate::cwt::Audience::Single("arkavo:devicecheck".into())
        );
        assert!(claims.cnf.is_some());
        let npe = claims.custom.arkavo_npe.expect("arkavo_npe present");
        assert_eq!(npe.npe_type, "device");
        assert_eq!(npe.class.as_deref(), Some("attested"));
        assert_eq!(npe.device_id.as_deref(), Some("device-1"));
    }

    #[tokio::test]
    async fn inbound_jwt_rejected_at_assertion_challenge() {
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
        }
        unsafe {
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        }
        unsafe {
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        }

        let app_state = crate::test_helpers::build_test_app_state().await;
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        #[derive(serde::Serialize)]
        struct LegacyClaims {
            sub: String,
            exp: usize,
        }
        let claims = LegacyClaims {
            sub: uuid::Uuid::new_v4().to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
        };
        let jwt = jsonwebtoken::encode(&header, &claims, &app_state.encoding_key).unwrap();
        let result = crate::device_check::verify_inbound_token(&app_state, &jwt);
        assert!(result.is_err());
    }

    #[test]
    fn device_class_from_assertion_freshness() {
        let now = 1_800_000_000;
        let ttl = crate::constants::DEVICE_ATTESTATION_TTL_SECONDS;
        let (c, exp) = device_class(now - 10, now);
        assert_eq!(c, DeviceClass::Attested);
        assert_eq!(exp, now - 10 + ttl);
        let (c, _) = device_class(now - ttl, now);
        assert_eq!(c, DeviceClass::Attested, "now == expiry is still attested");
        let (c, _) = device_class(now - ttl - 1, now);
        assert_eq!(c, DeviceClass::Managed);
        assert_eq!(DeviceClass::Unverified.as_str(), "unverified");
    }

    #[test]
    fn devicecheck_claims_carry_platform_audience() {
        let c =
            crate::cwt::ArkavoClaims::devicecheck("i", "u", 1, Some("https://platform.arkavo.net"));
        assert_eq!(
            c.aud,
            crate::cwt::Audience::Multiple(vec![
                "arkavo:devicecheck".into(),
                "https://platform.arkavo.net".into()
            ])
        );
        let c = crate::cwt::ArkavoClaims::devicecheck("i", "u", 1, None);
        assert_eq!(
            c.aud,
            crate::cwt::Audience::Single("arkavo:devicecheck".into())
        );
    }

    // -----------------------------------------------------------------------
    // Tasks 2 and 3: nonce extension + full chain verification
    //
    // Every one of these drives the *real* captured attestation. Hand-built
    // structs cannot catch a wire-format mismatch — that is exactly how the
    // camelCase bug survived the module's whole life.
    // -----------------------------------------------------------------------

    /// Decode the fixture's attestation object.
    fn fixture_attestation(f: &serde_json::Value) -> AttestationObject {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(f["attestation_object"].as_str().unwrap())
            .unwrap();
        ciborium::from_reader(&bytes[..]).expect("a real attestation must deserialize")
    }

    /// The fixture's capture time, as an ASN.1 instant.
    fn fixture_instant(f: &serde_json::Value) -> ASN1Time {
        ASN1Time::from_timestamp(f["verify_at"].as_i64().unwrap()).unwrap()
    }

    #[test]
    fn credcert_nonce_matches_the_computed_nonce() {
        use base64::Engine as _;
        let f = load_fixture();
        let att = fixture_attestation(&f);
        let client_data_hash = base64::engine::general_purpose::STANDARD
            .decode(f["client_data_hash"].as_str().unwrap())
            .unwrap();

        let mut nonce_data = att.auth_data.clone();
        nonce_data.extend_from_slice(&client_data_hash);
        let computed = Sha256::digest(&nonce_data);

        let from_cert = extract_attestation_nonce(&att.att_stmt.x5c[0])
            .expect("credCert must carry the 1.2.840.113635.100.8.2 extension");

        assert_eq!(
            from_cert.as_slice(),
            &computed[..],
            "Apple's recorded nonce must equal SHA256(authData || clientDataHash)"
        );
    }

    #[test]
    fn a_certificate_without_the_extension_is_refused() {
        // The Apple intermediate is a real, valid certificate with no App
        // Attest nonce extension. Absence must refuse, not pass silently.
        let f = load_fixture();
        let att = fixture_attestation(&f);
        let err = extract_attestation_nonce(&att.att_stmt.x5c[1]).unwrap_err();
        assert!(
            matches!(err, DeviceCheckError::NonceExtensionMissing),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_attestation_accepts_the_real_fixture() {
        let f = load_fixture();
        let app_id = f["app_id_hash"].as_str().unwrap().to_string();
        let attested = verify_attestation_at(
            f["challenge"].as_str().unwrap(),
            f["key_id"].as_str().unwrap(),
            f["attestation_object"].as_str().unwrap(),
            f["client_data_hash"].as_str().unwrap(),
            &VerifyOptions {
                expected_app_ids: std::slice::from_ref(&app_id),
                require_app_id: true,
            },
            fixture_instant(&f),
        )
        .expect("a genuine Apple attestation must verify end to end");

        assert_eq!(attested.rp_id_hash_str, app_id);
        assert_eq!(attested.counter, 0);
        assert!(!attested.public_key.is_empty());
    }

    #[test]
    fn verify_attestation_rejects_a_tampered_nonce() {
        use base64::Engine as _;
        let f = load_fixture();
        let mut att = fixture_attestation(&f);

        // Flip a byte of authData, which changes the computed nonce while
        // leaving the certificate's recorded nonce untouched. The last byte is
        // past rpIdHash (0..32) and past the counter (33..37), so every other
        // check still passes and only the nonce comparison can refuse this.
        let last = att.auth_data.len() - 1;
        att.auth_data[last] ^= 0xff;

        let mut tampered = Vec::new();
        ciborium::into_writer(&att, &mut tampered).unwrap();
        let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(&tampered);

        let app_id = f["app_id_hash"].as_str().unwrap().to_string();
        let err = verify_attestation_at(
            f["challenge"].as_str().unwrap(),
            f["key_id"].as_str().unwrap(),
            &tampered_b64,
            f["client_data_hash"].as_str().unwrap(),
            &VerifyOptions {
                expected_app_ids: std::slice::from_ref(&app_id),
                require_app_id: true,
            },
            fixture_instant(&f),
        )
        .unwrap_err();

        assert!(
            matches!(err, DeviceCheckError::NonceMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn chain_validation_accepts_the_real_fixture() {
        let f = load_fixture();
        let att = fixture_attestation(&f);
        validate_certificate_chain_at(&att.att_stmt.x5c, fixture_instant(&f))
            .expect("a real Apple chain must validate to the embedded root");
    }

    #[test]
    fn chain_validation_rejects_an_expired_certificate() {
        let f = load_fixture();
        let att = fixture_attestation(&f);

        // Ten years past capture the leaf is certainly outside its window.
        let long_after =
            ASN1Time::from_timestamp(f["verify_at"].as_i64().unwrap() + 10 * 365 * 24 * 3600)
                .unwrap();

        let err = validate_certificate_chain_at(&att.att_stmt.x5c, long_after).unwrap_err();
        assert!(
            matches!(err, DeviceCheckError::InvalidCertificateChain(_)),
            "an expired chain must not validate, got {err:?}"
        );
    }

    #[test]
    fn chain_validation_rejects_a_forged_leaf() {
        let f = load_fixture();
        let att = fixture_attestation(&f);

        // The last bytes of a DER certificate are inside the signature value,
        // so flipping them leaves a structurally valid certificate whose
        // signature no longer verifies — which is the only thing separating a
        // real credCert from one an attacker minted.
        let mut forged = att.att_stmt.x5c.clone();
        let leaf = &mut forged[0];
        let n = leaf.len();
        for b in leaf[n - 8..].iter_mut() {
            *b ^= 0xff;
        }

        let err = validate_certificate_chain_at(&forged, fixture_instant(&f)).unwrap_err();
        assert!(
            matches!(err, DeviceCheckError::InvalidCertificateChain(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn chain_validation_rejects_a_leaf_only_chain() {
        let f = load_fixture();
        let att = fixture_attestation(&f);
        let err =
            validate_certificate_chain_at(&att.att_stmt.x5c[..1], fixture_instant(&f)).unwrap_err();
        assert!(
            matches!(err, DeviceCheckError::InvalidCertificateChain(_)),
            "a chain with no intermediate must not validate, got {err:?}"
        );
    }

    #[test]
    fn chain_validation_rejects_a_chain_that_misses_the_pinned_root() {
        // Leaf + leaf: two parseable certificates that do not chain to Apple's
        // root. A verifier that only checked "did it parse" would accept this.
        let f = load_fixture();
        let att = fixture_attestation(&f);
        let bogus = vec![att.att_stmt.x5c[0].clone(), att.att_stmt.x5c[0].clone()];
        let err = validate_certificate_chain_at(&bogus, fixture_instant(&f)).unwrap_err();
        assert!(
            matches!(err, DeviceCheckError::InvalidCertificateChain(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn nonce_errors_are_401_and_retryable_on_the_preflight() {
        // A rejected attestation is not a permanent verdict on the device: the
        // client mints a fresh key and tries again. Only attest_registration_cap
        // is permanent. See docs/app-attest-preflight-contract.md.
        assert_eq!(
            DeviceCheckError::NonceMismatch.into_response().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            DeviceCheckError::NonceExtensionMissing
                .into_response()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        for e in [
            DeviceCheckError::NonceMismatch,
            DeviceCheckError::NonceExtensionMissing,
        ] {
            let (status, token, _) = preflight_error_mapping(&e);
            assert_eq!(token, "attestation_invalid");
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
    }

    // -----------------------------------------------------------------------
    // key_id binding and aaguid
    //
    // Tampers land in authData bytes 37..87, which also changes the computed
    // nonce. These checks therefore have to run *before* the nonce compare, or
    // every one of these tests would pass on NonceMismatch and prove nothing.
    // -----------------------------------------------------------------------

    /// Run the fixture through the verifier with `att` and `key_id` swapped in.
    fn verify_modified(
        f: &serde_json::Value,
        att: &AttestationObject,
        key_id: &str,
    ) -> Result<AttestedKey, DeviceCheckError> {
        use base64::Engine as _;
        let mut encoded = Vec::new();
        ciborium::into_writer(att, &mut encoded).unwrap();
        let app_id = f["app_id_hash"].as_str().unwrap().to_string();
        verify_attestation_at(
            f["challenge"].as_str().unwrap(),
            key_id,
            &base64::engine::general_purpose::STANDARD.encode(&encoded),
            f["client_data_hash"].as_str().unwrap(),
            &VerifyOptions {
                expected_app_ids: std::slice::from_ref(&app_id),
                require_app_id: true,
            },
            fixture_instant(f),
        )
    }

    #[test]
    fn a_key_id_that_is_not_the_attested_key_is_refused() {
        // key_id names the budget row and, on the bound path, the device
        // binding. Accepted unbound, a genuine attestation could be filed
        // under a key_id the caller does not hold — someone else's — charging
        // or squatting a row it has no claim to.
        let f = load_fixture();
        let att = fixture_attestation(&f);
        let err =
            verify_modified(&f, &att, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap_err();
        assert!(
            matches!(err, DeviceCheckError::KeyIdMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn a_non_canonical_key_id_encoding_is_refused() {
        // Same 32 bytes, padding stripped. Accepting both spellings would give
        // one device two budget rows.
        let f = load_fixture();
        let att = fixture_attestation(&f);
        let unpadded = f["key_id"].as_str().unwrap().trim_end_matches('=');
        let err = verify_modified(&f, &att, unpadded).unwrap_err();
        assert!(
            matches!(err, DeviceCheckError::KeyIdMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn a_credential_id_that_disagrees_with_key_id_is_refused() {
        let f = load_fixture();
        let mut att = fixture_attestation(&f);
        // credentialId: 2-byte length at 53..55, then 32 bytes.
        att.auth_data[55..87].fill(0);
        let err = verify_modified(&f, &att, f["key_id"].as_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, DeviceCheckError::KeyIdMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn an_unknown_aaguid_is_refused() {
        let f = load_fixture();
        let mut att = fixture_attestation(&f);
        att.auth_data[37..53].fill(0);
        let err = verify_modified(&f, &att, f["key_id"].as_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, DeviceCheckError::InvalidAaguid(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn the_development_aaguid_is_accepted() {
        // iOS developer builds emit `appattestdevelop`. There is no second
        // fixture, so prove acceptance by the refusal moving on: the swapped
        // aaguid breaks the nonce, and that must be what refuses it.
        let f = load_fixture();
        let mut att = fixture_attestation(&f);
        att.auth_data[37..53].copy_from_slice(b"appattestdevelop");
        let err = verify_modified(&f, &att, f["key_id"].as_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, DeviceCheckError::NonceMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn authdata_without_attested_credential_data_is_refused() {
        // 37 bytes is a valid *assertion* authData, but an attestation must
        // carry aaguid and credentialId.
        let f = load_fixture();
        let mut att = fixture_attestation(&f);
        att.auth_data.truncate(37);
        let err = verify_modified(&f, &att, f["key_id"].as_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, DeviceCheckError::InvalidAuthenticatorData(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn key_binding_errors_are_401_and_retryable_on_the_preflight() {
        for e in [
            DeviceCheckError::KeyIdMismatch,
            DeviceCheckError::InvalidAaguid("x".into()),
        ] {
            let (status, token, _) = preflight_error_mapping(&e);
            assert_eq!(token, "attestation_invalid", "{e:?}");
            assert_eq!(status, StatusCode::BAD_REQUEST, "{e:?}");
            assert_eq!(e.into_response().status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[test]
    fn der_tlv_refuses_indefinite_length() {
        // BER's indefinite length is 0x80. DER forbids it, and an attestation
        // carrying one is malformed rather than something to normalise.
        let err = der_tlv(&[0x30, 0x80, 0x00, 0x00], 0x30).unwrap_err();
        assert!(err.contains("unsupported DER length form"), "{err}");
    }

    #[test]
    fn der_tlv_refuses_a_length_past_the_buffer() {
        let err = der_tlv(&[0x04, 0x20, 0x01, 0x02], 0x04).unwrap_err();
        assert!(err.contains("runs past the end"), "{err}");
    }

    #[test]
    fn der_tlv_reads_a_long_form_length() {
        let mut buf = vec![0x04, 0x81, 0x80];
        buf.extend(std::iter::repeat_n(0xAAu8, 0x80));
        buf.push(0xFF); // trailing byte, must come back as the remainder
        let (contents, rest) = der_tlv(&buf, 0x04).unwrap();
        assert_eq!(contents.len(), 0x80);
        assert_eq!(rest, &[0xFF]);
    }
}
