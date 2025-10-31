use crate::authn::WebauthnError;
use ecdsa::signature::Verifier;
use ecdsa::{Signature, VerifyingKey};
use log::{error, info, warn};
use p256::NistP256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use webauthn_rs::prelude::Base64UrlSafeData;

/// Device attestation record stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAttestation {
    /// Device identifier (from App Attest or fallback)
    pub device_id: String,
    /// User who owns this device
    pub user_id: Uuid,
    /// Compressed P-256 public key (33 bytes: 0x02/0x03 + x-coordinate)
    pub public_key: Base64UrlSafeData,
    /// Counter for replay protection (monotonically increasing)
    pub counter: u64,
    /// First attestation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last assertion timestamp
    pub last_used_at: chrono::DateTime<chrono::Utc>,
    /// Platform code (iOS, macOS, etc.)
    pub platform: String,
    /// Device security state
    pub security_state: SecurityState,
}

/// Device security state assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecurityState {
    /// Device passed all security checks
    Trusted,
    /// Device shows suspicious behavior
    Suspicious,
    /// Device is compromised (jailbroken, debugger, etc.)
    Compromised,
    /// Unknown state (not enough data)
    Unknown,
}

/// Attestation request from client (initial device registration)
#[derive(Debug, Deserialize)]
pub struct AttestationRequest {
    /// Device identifier
    pub device_id: String,
    /// Compressed P-256 public key
    pub public_key: Base64UrlSafeData,
    /// Platform code (iOS, macOS, etc.)
    pub platform: String,
    /// Challenge nonce signed by device
    pub challenge_response: Base64UrlSafeData,
}

/// Assertion request from client (ongoing verification)
#[derive(Debug, Deserialize)]
pub struct AssertionRequest {
    /// Device identifier
    pub device_id: String,
    /// Challenge nonce signed by device
    pub challenge_response: Base64UrlSafeData,
    /// Counter value (must be monotonically increasing)
    pub counter: u64,
    /// Additional data to be signed (optional)
    pub client_data: Option<Vec<u8>>,
}

/// Result of attestation validation
#[derive(Debug)]
pub enum AttestationResult {
    /// Attestation valid, device registered
    Valid(DeviceAttestation),
    /// Invalid signature
    InvalidSignature,
    /// Device already registered
    AlreadyRegistered,
    /// Malformed request
    Invalid(String),
}

/// Result of assertion validation
#[derive(Debug)]
pub enum AssertionResult {
    /// Assertion valid, counter updated
    Valid(DeviceAttestation),
    /// Invalid signature
    InvalidSignature,
    /// Counter did not increase (replay attack detected)
    CounterReplayDetected { expected: u64, received: u64 },
    /// Device not found
    DeviceNotFound,
    /// Device is compromised
    DeviceCompromised,
    /// Malformed request
    Invalid(String),
}

/// Verify an attestation request and create device record
pub fn verify_attestation(
    request: AttestationRequest,
    challenge: &[u8],
    user_id: Uuid,
) -> Result<AttestationResult, WebauthnError> {
    info!(
        "Verifying attestation for device: {} (user: {})",
        request.device_id, user_id
    );

    // Parse public key
    let public_key = match parse_public_key(&request.public_key) {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to parse public key: {}", e);
            return Ok(AttestationResult::Invalid(format!(
                "Invalid public key: {}",
                e
            )));
        }
    };

    // Verify signature over challenge
    let message = Sha256::digest(challenge);
    let signature = match Signature::from_der(request.challenge_response.as_ref()) {
        Ok(sig) => sig,
        Err(e) => {
            error!("Failed to parse signature: {}", e);
            return Ok(AttestationResult::Invalid(format!(
                "Invalid signature format: {}",
                e
            )));
        }
    };

    if public_key.verify(&message, &signature).is_err() {
        warn!(
            "Attestation signature verification failed for device: {}",
            request.device_id
        );
        return Ok(AttestationResult::InvalidSignature);
    }

    info!(
        "Attestation signature valid for device: {}",
        request.device_id
    );

    // Create device attestation record
    let now = chrono::Utc::now();
    let attestation = DeviceAttestation {
        device_id: request.device_id.clone(),
        user_id,
        public_key: request.public_key,
        counter: 0, // Initial counter
        created_at: now,
        last_used_at: now,
        platform: request.platform,
        security_state: SecurityState::Trusted,
    };

    Ok(AttestationResult::Valid(attestation))
}

/// Verify an assertion request and update counter
pub fn verify_assertion(
    request: AssertionRequest,
    challenge: &[u8],
    stored_attestation: &DeviceAttestation,
) -> Result<AssertionResult, WebauthnError> {
    info!(
        "Verifying assertion for device: {} (counter: {} -> {})",
        request.device_id, stored_attestation.counter, request.counter
    );

    // Check if device is compromised
    if stored_attestation.security_state == SecurityState::Compromised {
        warn!("Assertion rejected: device {} is compromised", request.device_id);
        return Ok(AssertionResult::DeviceCompromised);
    }

    // Verify counter monotonicity (replay protection)
    if request.counter <= stored_attestation.counter {
        warn!(
            "Counter replay detected for device: {} (expected > {}, received {})",
            request.device_id, stored_attestation.counter, request.counter
        );
        return Ok(AssertionResult::CounterReplayDetected {
            expected: stored_attestation.counter,
            received: request.counter,
        });
    }

    // Parse public key
    let public_key = match parse_public_key(&stored_attestation.public_key) {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to parse stored public key: {}", e);
            return Ok(AssertionResult::Invalid(format!(
                "Invalid stored public key: {}",
                e
            )));
        }
    };

    // Build message to verify: challenge + counter + optional client data
    let mut message_parts = Vec::new();
    message_parts.extend_from_slice(challenge);
    message_parts.extend_from_slice(&request.counter.to_le_bytes());
    if let Some(client_data) = &request.client_data {
        message_parts.extend_from_slice(client_data);
    }
    let message = Sha256::digest(&message_parts);

    // Verify signature
    let signature = match Signature::from_der(request.challenge_response.as_ref()) {
        Ok(sig) => sig,
        Err(e) => {
            error!("Failed to parse signature: {}", e);
            return Ok(AssertionResult::Invalid(format!(
                "Invalid signature format: {}",
                e
            )));
        }
    };

    if public_key.verify(&message, &signature).is_err() {
        warn!(
            "Assertion signature verification failed for device: {}",
            request.device_id
        );
        return Ok(AssertionResult::InvalidSignature);
    }

    info!(
        "Assertion signature valid for device: {} (counter updated: {} -> {})",
        request.device_id, stored_attestation.counter, request.counter
    );

    // Update attestation record
    let mut updated_attestation = stored_attestation.clone();
    updated_attestation.counter = request.counter;
    updated_attestation.last_used_at = chrono::Utc::now();

    Ok(AssertionResult::Valid(updated_attestation))
}

/// Parse compressed P-256 public key from Base64UrlSafe bytes
fn parse_public_key(key_bytes: &Base64UrlSafeData) -> Result<VerifyingKey<NistP256>, String> {
    use p256::EncodedPoint;

    let bytes = key_bytes.as_ref();

    // Compressed key should be 33 bytes (0x02/0x03 + 32-byte x-coordinate)
    if bytes.len() != 33 {
        return Err(format!(
            "Invalid key length: expected 33 bytes, got {}",
            bytes.len()
        ));
    }

    let encoded_point =
        EncodedPoint::from_bytes(bytes).map_err(|e| format!("Failed to parse point: {:?}", e))?;

    VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|e| format!("Failed to create verifying key: {:?}", e))
}

/// Update device security state based on client-reported platform state
pub fn update_security_state(
    attestation: &mut DeviceAttestation,
    reported_state: &str,
) -> SecurityState {
    let new_state = match reported_state.to_lowercase().as_str() {
        "secure" => SecurityState::Trusted,
        "jailbroken" | "rooted" => SecurityState::Compromised,
        "debugmode" => SecurityState::Suspicious,
        _ => SecurityState::Unknown,
    };

    info!(
        "Device {} security state updated: {:?} -> {:?}",
        attestation.device_id, attestation.security_state, new_state
    );

    attestation.security_state = new_state.clone();
    new_state
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn test_attestation_and_assertion_flow() {
        // Generate device key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();
        let public_key = Base64UrlSafeData::from(public_key_bytes);

        // Create attestation challenge
        let challenge = b"attestation-challenge-12345";
        let message = Sha256::digest(challenge);
        let signature: Signature<NistP256> = signing_key.sign(&message);

        // Create attestation request
        let attestation_req = AttestationRequest {
            device_id: "test-device-123".to_string(),
            public_key: public_key.clone(),
            platform: "iOS".to_string(),
            challenge_response: Base64UrlSafeData::from(signature.to_der().as_bytes().to_vec()),
        };

        // Verify attestation
        let user_id = Uuid::new_v4();
        let result = verify_attestation(attestation_req, challenge, user_id).unwrap();

        let attestation = match result {
            AttestationResult::Valid(att) => att,
            _ => panic!("Attestation should be valid"),
        };

        assert_eq!(attestation.device_id, "test-device-123");
        assert_eq!(attestation.counter, 0);

        // Now test assertion with counter increment
        let assertion_challenge = b"assertion-challenge-67890";
        let counter = 1u64;
        let mut message_parts = Vec::new();
        message_parts.extend_from_slice(assertion_challenge);
        message_parts.extend_from_slice(&counter.to_le_bytes());
        let assertion_message = Sha256::digest(&message_parts);
        let assertion_signature: Signature<NistP256> = signing_key.sign(&assertion_message);

        let assertion_req = AssertionRequest {
            device_id: "test-device-123".to_string(),
            challenge_response: Base64UrlSafeData::from(
                assertion_signature.to_der().as_bytes().to_vec(),
            ),
            counter,
            client_data: None,
        };

        // Verify assertion
        let assertion_result =
            verify_assertion(assertion_req, assertion_challenge, &attestation).unwrap();

        match assertion_result {
            AssertionResult::Valid(updated_att) => {
                assert_eq!(updated_att.counter, 1);
            }
            _ => panic!("Assertion should be valid"),
        }
    }

    #[test]
    fn test_counter_replay_detection() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();

        let mut attestation = DeviceAttestation {
            device_id: "test-device".to_string(),
            user_id: Uuid::new_v4(),
            public_key: Base64UrlSafeData::from(public_key_bytes),
            counter: 5,
            created_at: chrono::Utc::now(),
            last_used_at: chrono::Utc::now(),
            platform: "iOS".to_string(),
            security_state: SecurityState::Trusted,
        };

        // Try to replay with same counter
        let challenge = b"test-challenge";
        let counter = 5u64; // Same as stored counter
        let mut message_parts = Vec::new();
        message_parts.extend_from_slice(challenge);
        message_parts.extend_from_slice(&counter.to_le_bytes());
        let message = Sha256::digest(&message_parts);
        let signature: Signature<NistP256> = signing_key.sign(&message);

        let assertion_req = AssertionRequest {
            device_id: "test-device".to_string(),
            challenge_response: Base64UrlSafeData::from(signature.to_der().as_bytes().to_vec()),
            counter,
            client_data: None,
        };

        let result = verify_assertion(assertion_req, challenge, &attestation).unwrap();

        match result {
            AssertionResult::CounterReplayDetected { expected, received } => {
                assert_eq!(expected, 5);
                assert_eq!(received, 5);
            }
            _ => panic!("Should detect counter replay"),
        }
    }

    #[test]
    fn test_security_state_update() {
        let mut attestation = DeviceAttestation {
            device_id: "test-device".to_string(),
            user_id: Uuid::new_v4(),
            public_key: Base64UrlSafeData::from(vec![0; 33]),
            counter: 0,
            created_at: chrono::Utc::now(),
            last_used_at: chrono::Utc::now(),
            platform: "iOS".to_string(),
            security_state: SecurityState::Trusted,
        };

        let state = update_security_state(&mut attestation, "jailbroken");
        assert_eq!(state, SecurityState::Compromised);
        assert_eq!(attestation.security_state, SecurityState::Compromised);
    }
}
