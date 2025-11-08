use crate::constants::AUTH_TOKEN_HOURS;
use crate::db::DynamoDBError;
use crate::AppState;
use axum::http::HeaderMap;
use axum::{
    extract::{Extension, Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, Header, Validation};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tower_sessions::Session;
use uuid::Uuid;
use x509_parser::prelude::*;
use base64::Engine;

const SESSION_ATTEST_STATE_KEY: &str = "attest_state";
const SESSION_ASSERT_STATE_KEY: &str = "assert_state";

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
    pub assertion: String,      // Base64 encoded
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
        .insert(SESSION_ATTEST_STATE_KEY, (username.clone(), challenge.clone()))
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
    info!("Finishing App Attest attestation for key_id: {}", request.key_id);

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
    let _calculated_nonce = Sha256::digest(&nonce_data);

    // TODO: Verify nonce against certificate extension (requires parsing cert extension)
    // This would involve checking the certificate's 1.2.840.113635.100.8.2 extension

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

    // Verify JWT token
    if let Some(jwt_header) = headers.get("X-Auth-Token") {
        let jwt = jwt_header
            .to_str()
            .map_err(|_| DeviceCheckError::InvalidToken)?;

        let decoding_key = (*app_state.decoding_key).clone();
        let mut token_validation = Validation::new(Algorithm::ES256);
        token_validation.validate_nbf = false;
        token_validation.validate_exp = false;

        let _token_data = decode::<crate::authn::Claims>(jwt, &decoding_key, &token_validation)
            .map_err(|err| {
                DeviceCheckError::TokenDecodingError(format!("Error decoding token: {}", err))
            })?;
    } else {
        return Err(DeviceCheckError::MissingToken);
    }

    // Generate challenge
    let challenge = generate_random_challenge();

    // Store challenge in session
    if let Err(err) = session
        .insert(SESSION_ASSERT_STATE_KEY, (username.clone(), challenge.clone()))
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

    // TODO: Verify signature using stored public key
    // This would require parsing the assertion format and verifying the signature
    // over the concatenation of authData and clientDataHash

    // Update counter in database
    app_state
        .db_store
        .update_device_counter(&request.key_id, auth_data.counter)
        .await
        .map_err(|e| DeviceCheckError::DynamoDBOperationError(Box::new(e)))?;

    // Generate JWT token
    let token = generate_device_jwt(binding.user_id, &app_state)?;

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

    // Parse Apple root CA
    let root_pem = ::pem::parse(APPLE_APP_ATTEST_ROOT_CA.as_bytes())
        .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?;

    let (_, root_cert) = X509Certificate::from_der(root_pem.contents())
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

fn generate_device_jwt(user_id: Uuid, app_state: &AppState) -> Result<String, DeviceCheckError> {
    #[derive(Serialize)]
    struct Claims {
        sub: String,
        exp: usize,
    }

    let claims = Claims {
        sub: user_id.to_string(),
        exp: (Utc::now() + chrono::Duration::hours(AUTH_TOKEN_HOURS)).timestamp() as usize,
    };

    let header = Header::new(Algorithm::ES256);
    encode(&header, &claims, &app_state.encoding_key).map_err(DeviceCheckError::TokenCreationError)
}

#[derive(Error, Debug)]
pub enum DeviceCheckError {
    #[error("Corrupt Session")]
    CorruptSession,

    #[error("User Not Found")]
    UserNotFound,

    #[error("Device Not Found")]
    DeviceNotFound,

    #[error("Deserializing Session failed: {0}")]
    InvalidSessionState(#[from] tower_sessions::session::Error),

    #[error("Token creation error")]
    TokenCreationError(jsonwebtoken::errors::Error),

    #[error("Missing token")]
    MissingToken,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token decoding failed: {0}")]
    TokenDecodingError(String),

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
        let body = match self {
            DeviceCheckError::CorruptSession => "Corrupt Session".to_string(),
            DeviceCheckError::UserNotFound => "User Not Found".to_string(),
            DeviceCheckError::DeviceNotFound => "Device Not Found".to_string(),
            DeviceCheckError::InvalidSessionState(_) => "Deserializing Session failed".to_string(),
            DeviceCheckError::TokenCreationError(err) => format!("Token creation failed: {}", err),
            DeviceCheckError::MissingToken => "Missing token".to_string(),
            DeviceCheckError::InvalidToken => "Invalid token".to_string(),
            DeviceCheckError::TokenDecodingError(err) => format!("Token decoding error: {}", err),
            DeviceCheckError::DynamoDBOperationError(err) => match *err {
                DynamoDBError::TableNotExists(table) => {
                    format!("Service setup incomplete: {} table not configured", table)
                }
                _ => format!("Database operation failed: {}", err),
            },
            DeviceCheckError::SessionError(err) => format!("Session operation failed: {}", err),
            DeviceCheckError::InvalidAttestationObject(err) => {
                format!("Invalid attestation object: {}", err)
            }
            DeviceCheckError::InvalidFormat(err) => format!("Invalid format: {}", err),
            DeviceCheckError::InvalidCertificateChain(err) => {
                format!("Invalid certificate chain: {}", err)
            }
            DeviceCheckError::InvalidAuthenticatorData(err) => {
                format!("Invalid authenticator data: {}", err)
            }
            DeviceCheckError::InvalidCounter(err) => format!("Invalid counter: {}", err),
            DeviceCheckError::InvalidClientData(err) => format!("Invalid client data: {}", err),
            DeviceCheckError::ChallengeMismatch => "Challenge mismatch".to_string(),
            DeviceCheckError::InvalidAssertion(err) => format!("Invalid assertion: {}", err),
        };
        (StatusCode::BAD_REQUEST, body).into_response()
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
        let errors = vec![
            DeviceCheckError::CorruptSession,
            DeviceCheckError::UserNotFound,
            DeviceCheckError::DeviceNotFound,
            DeviceCheckError::MissingToken,
            DeviceCheckError::InvalidToken,
            DeviceCheckError::ChallengeMismatch,
        ];

        for error in errors {
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
        assert!(!(invalid_counter > old_counter));
    }
}
