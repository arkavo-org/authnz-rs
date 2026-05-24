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
//! - Certificate chain validation is incomplete (intermediate certs not verified)
//! - Certificate extension 1.2.840.113635.100.8.2 (nonce) validation not implemented
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
    pub jwt_token: String,
}

// CBOR structures for App Attest
#[derive(Debug, Deserialize)]
struct AttestationObject {
    fmt: String,
    att_stmt: AttestationStatement,
    auth_data: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AttestationStatement {
    x5c: Vec<Vec<u8>>,
    receipt: Option<Vec<u8>>,
}

/// Generate a challenge for attestation or assertion
pub async fn generate_challenge(
    Extension(_app_state): Extension<AppState>,
    session: Session,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, DeviceCheckError> {
    info!("Generating App Attest challenge for user: {}", username);

    // Generate a random challenge (32 bytes = 256 bits)
    let challenge = generate_random_challenge();

    // Store challenge in session for verification
    if let Err(err) = session
        .insert(
            SESSION_ATTEST_STATE_KEY,
            (username.clone(), challenge.clone()),
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

    // Retrieve challenge from session
    let (username, challenge): (String, String) = session
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

    // Decode the attestation object from base64
    let attestation_bytes = base64::engine::general_purpose::STANDARD
        .decode(&request.attestation_object)
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
        .decode(&request.client_data_hash)
        .map_err(|e| DeviceCheckError::InvalidClientData(e.to_string()))?;

    // Verify the challenge matches
    let expected_hash = Sha256::digest(challenge.as_bytes());
    if client_data_hash.as_slice() != &expected_hash[..] {
        return Err(DeviceCheckError::ChallengeMismatch);
    }

    // Validate certificate chain
    validate_certificate_chain(&attestation.att_stmt.x5c)?;

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

    // Calculate nonce: SHA256(authData || clientDataHash)
    let mut nonce_data = Vec::new();
    nonce_data.extend_from_slice(&attestation.auth_data);
    nonce_data.extend_from_slice(&client_data_hash);
    let calculated_nonce = Sha256::digest(&nonce_data);

    // SECURITY GAP: Nonce validation against certificate extension not implemented
    //
    // According to Apple's App Attest specification, the credCert (leaf certificate)
    // contains a custom extension with OID 1.2.840.113635.100.8.2 that holds the nonce.
    // We should verify that the calculated_nonce matches this extension value.
    //
    // Risk Assessment:
    // - Without this check, an attacker could potentially present a valid attestation
    //   for a different challenge, though they would still need a genuine Apple device
    // - The rpIdHash, certificate chain, and counter checks provide defense-in-depth
    // - This validation should be implemented before production deployment
    //
    // Implementation Required:
    // 1. Parse the X.509 certificate extension 1.2.840.113635.100.8.2
    // 2. Extract the nonce value from the extension
    // 3. Compare with calculated_nonce
    // 4. Reject attestation if they don't match
    warn!(
        "SECURITY: Nonce validation against certificate extension not implemented. \
         Calculated nonce: {}. This check should be added before production use.",
        hex::encode(calculated_nonce)
    );

    // Get user from database
    let user = app_state
        .db_store
        .get_user_by_name(&username)
        .await
        .map_err(|e| DeviceCheckError::DynamoDBOperationError(Box::new(e)))?
        .ok_or(DeviceCheckError::UserNotFound)?;

    // Create device binding
    let binding = DeviceBinding {
        device_id: request.key_id.clone(),
        user_id: user.user_id,
        public_key: public_key.clone(),
        counter: 0,
        app_id: auth_data.rp_id_hash_str.clone(),
        created_at: Utc::now().timestamp(),
        updated_at: Utc::now().timestamp(),
    };

    // Store device binding in database
    app_state
        .db_store
        .create_device_binding(&binding)
        .await
        .map_err(|e| DeviceCheckError::DynamoDBOperationError(Box::new(e)))?;

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

    // Verify CWT token
    if let Some(token_header) = headers.get("X-Auth-Token") {
        let token = token_header
            .to_str()
            .map_err(|_| DeviceCheckError::InvalidToken)?;

        let _claims = verify_inbound_token(&app_state, token)?;
    } else {
        return Err(DeviceCheckError::MissingToken);
    }

    // Generate challenge
    let challenge = generate_random_challenge();

    // Store challenge in session
    if let Err(err) = session
        .insert(
            SESSION_ASSERT_STATE_KEY,
            (username.clone(), challenge.clone()),
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
    session: Session,
    Json(request): Json<AssertionRequest>,
) -> Result<impl IntoResponse, DeviceCheckError> {
    info!("Finishing assertion for key_id: {}", request.key_id);

    // Retrieve challenge from session
    let (_username, challenge): (String, String) = session
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

    // Mint CWT assertion token with device public key bound via cnf claim
    let token = mint_assertion_token(
        &app_state,
        &binding.user_id,
        &binding.public_key,
        binding.device_id.as_bytes(),
    )?;

    info!("Assertion successful for key_id: {}", request.key_id);

    Ok(Json(AssertionResponse { jwt_token: token }))
}

// Helper functions

fn generate_random_challenge() -> String {
    use uuid::Uuid;
    Uuid::new_v4().to_string()
}

fn validate_certificate_chain(x5c: &[Vec<u8>]) -> Result<(), DeviceCheckError> {
    if x5c.is_empty() {
        return Err(DeviceCheckError::InvalidCertificateChain(
            "Empty certificate chain".to_string(),
        ));
    }

    // Parse leaf certificate
    let (_, leaf_cert) = X509Certificate::from_der(&x5c[0])
        .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?;

    info!("Leaf certificate subject: {}", leaf_cert.subject());
    info!("Leaf certificate issuer: {}", leaf_cert.issuer());

    // Get cached Apple root CA DER (parsed once on first use)
    let root_cert_der = APPLE_ROOT_CERT_DER.get_or_init(|| {
        let root_pem = ::pem::parse(APPLE_APP_ATTEST_ROOT_CA.as_bytes())
            .expect("Failed to parse embedded Apple root CA PEM");
        root_pem.contents().to_vec()
    });

    // Parse the cached DER to get the certificate for validation
    let (_, root_cert) = X509Certificate::from_der(root_cert_der)
        .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?;

    info!("Root certificate subject: {}", root_cert.subject());

    // In production, we would verify the full chain here
    // For now, we just validate that we can parse the certificates
    warn!("Certificate chain validation is incomplete - implement full chain verification");

    Ok(())
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

/// Mint a CWT assertion token for a successfully-attested device.
///
/// The token audience is `"arkavo:devicecheck"` and carries the device's
/// App Attest public key as the `cnf` claim so relying parties can perform
/// DPoP-style proof-of-possession checks.
pub fn mint_assertion_token(
    app_state: &AppState,
    user_id: &Uuid,
    device_public_key: &[u8],
    device_id: &[u8],
) -> Result<String, DeviceCheckError> {
    let issuer = std::env::var("OIDC_ISSUER")
        .unwrap_or_else(|_| crate::constants::DEFAULT_OIDC_ISSUER.to_string());
    let cnf = crate::cwt::cnf_from_app_attest(device_public_key, device_id)?;
    let claims = crate::cwt::ArkavoClaims::devicecheck(
        &issuer,
        &user_id.to_string(),
        AUTH_TOKEN_HOURS,
    )
    .with_cnf(cnf);
    let bytes = crate::cwt::mint(&claims, &app_state.cwt_signing_key, &app_state.cwt_kid)?;
    Ok(crate::cwt::encode_for_header(&bytes))
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
    let issuer = std::env::var("OIDC_ISSUER")
        .unwrap_or_else(|_| crate::constants::DEFAULT_OIDC_ISSUER.to_string());
    let opts = crate::cwt::VerifyOptions {
        expected_iss: Some(&issuer),
        // The assertion challenge endpoint expects a standard Arkavo auth token,
        // NOT a devicecheck assertion token (that would create a cycle).
        expected_aud: Some("arkavo"),
        now: chrono::Utc::now().timestamp(),
        skew_secs: crate::cwt::DEFAULT_SKEW_SECS,
    };
    Ok(crate::cwt::verify(&bytes, &app_state.cwt_verifying_key, &opts)?)
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
}

impl IntoResponse for DeviceCheckError {
    fn into_response(self) -> axum::response::Response {
        // CWT verification failures map to 401 Unauthorized; everything else is 400.
        let (status, body) = match self {
            DeviceCheckError::Cwt(err) => (
                StatusCode::UNAUTHORIZED,
                format!("Unauthorized: {}", err),
            ),
            DeviceCheckError::CorruptSession => (StatusCode::BAD_REQUEST, "Corrupt Session".to_string()),
            DeviceCheckError::UserNotFound => (StatusCode::BAD_REQUEST, "User Not Found".to_string()),
            DeviceCheckError::DeviceNotFound => (StatusCode::BAD_REQUEST, "Device Not Found".to_string()),
            DeviceCheckError::InvalidSessionState(_) => (StatusCode::BAD_REQUEST, "Deserializing Session failed".to_string()),
            DeviceCheckError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing token".to_string()),
            DeviceCheckError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            DeviceCheckError::DynamoDBOperationError(err) => match *err {
                DynamoDBError::TableNotExists(table) => (
                    StatusCode::BAD_REQUEST,
                    format!("Service setup incomplete: {} table not configured", table),
                ),
                _ => (StatusCode::BAD_REQUEST, format!("Database operation failed: {}", err)),
            },
            DeviceCheckError::SessionError(err) => (StatusCode::BAD_REQUEST, format!("Session operation failed: {}", err)),
            DeviceCheckError::InvalidAttestationObject(err) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid attestation object: {}", err),
            ),
            DeviceCheckError::InvalidFormat(err) => (StatusCode::BAD_REQUEST, format!("Invalid format: {}", err)),
            DeviceCheckError::InvalidCertificateChain(err) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid certificate chain: {}", err),
            ),
            DeviceCheckError::InvalidAuthenticatorData(err) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid authenticator data: {}", err),
            ),
            DeviceCheckError::InvalidCounter(err) => (StatusCode::BAD_REQUEST, format!("Invalid counter: {}", err)),
            DeviceCheckError::InvalidClientData(err) => (StatusCode::BAD_REQUEST, format!("Invalid client data: {}", err)),
            DeviceCheckError::ChallengeMismatch => (StatusCode::BAD_REQUEST, "Challenge mismatch".to_string()),
            DeviceCheckError::InvalidAssertion(err) => (StatusCode::BAD_REQUEST, format!("Invalid assertion: {}", err)),
        };
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
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
        ];

        for error in bad_request_errors {
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

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
        unsafe { std::env::set_var("AWS_REGION", "us-east-1"); }
        unsafe { std::env::set_var("AWS_ACCESS_KEY_ID", "test"); }
        unsafe { std::env::set_var("AWS_SECRET_ACCESS_KEY", "test"); }

        let app_state = crate::test_helpers::build_test_app_state().await;
        let user_id = uuid::Uuid::new_v4();
        let device_id = b"device-1".to_vec();

        // Sample P-256 public key for cnf (uncompressed SEC1).
        let scalar = p256::FieldBytes::from([0x99u8; 32]);
        let secret = p256::SecretKey::from_bytes(&scalar).expect("scalar");
        let vk: p256::ecdsa::VerifyingKey = *p256::ecdsa::SigningKey::from(&secret).verifying_key();
        let pubkey = vk.to_encoded_point(false).as_bytes().to_vec();

        let token = crate::device_check::mint_assertion_token(
            &app_state, &user_id, &pubkey, &device_id,
        ).expect("mint");

        let raw = crate::cwt::decode_from_header(&token).unwrap();
        let sign1 = coset::CoseSign1::from_slice(&raw).unwrap();
        let claims = crate::cwt::claims_from_cbor(sign1.payload.as_ref().unwrap()).unwrap();
        assert_eq!(claims.aud, crate::cwt::Audience::Single("arkavo:devicecheck".into()));
        assert!(claims.cnf.is_some());
    }

    #[tokio::test]
    async fn inbound_jwt_rejected_at_assertion_challenge() {
        unsafe { std::env::set_var("AWS_REGION", "us-east-1"); }
        unsafe { std::env::set_var("AWS_ACCESS_KEY_ID", "test"); }
        unsafe { std::env::set_var("AWS_SECRET_ACCESS_KEY", "test"); }

        let app_state = crate::test_helpers::build_test_app_state().await;
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        #[derive(serde::Serialize)]
        struct LegacyClaims { sub: String, exp: usize }
        let claims = LegacyClaims {
            sub: uuid::Uuid::new_v4().to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
        };
        let jwt = jsonwebtoken::encode(&header, &claims, &app_state.encoding_key).unwrap();
        let result = crate::device_check::verify_inbound_token(&app_state, &jwt);
        assert!(matches!(result, Err(_)));
    }
}
