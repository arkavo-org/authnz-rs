use crate::authn::WebauthnError;
use crate::AppState;
use chrono::{DateTime, Utc};
use ecdsa::signature::Signer;
use ecdsa::Signature;
use jsonwebtoken::{encode, Header, Algorithm};
use log::{error, info};
use p256::NistP256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use webauthn_rs::prelude::Base64UrlSafeData;

/// Person Entity (PE) Claims - User identity and authentication level
/// This represents the authenticated user and their auth method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PEClaims {
    /// User's unique identifier
    pub user_id: String,
    /// Authentication level achieved
    pub auth_level: AuthLevel,
    /// Timestamp of PE generation
    pub timestamp: DateTime<Utc>,
    /// Decentralized Identifier
    pub did: String,
}

/// Non-Person Entity (NPE) Claims - Device and platform attestation
/// This wraps the PE claims with device/platform context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NPEClaims {
    /// Platform code (iOS, macOS, etc.)
    pub platform_code: String,
    /// Platform security state
    pub platform_state: PlatformState,
    /// Device identifier (from App Attest or fallback)
    pub device_id: String,
    /// App version string
    pub app_version: String,
    /// Timestamp of NPE generation
    pub timestamp: DateTime<Utc>,
}

/// Terminal Link Claims - IdP-issued authentication token
/// This is the outermost layer wrapping PE->NPE chain + session info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalLinkClaims {
    /// Subject (user_id)
    pub sub: String,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: i64,
    /// Issuer identifier
    pub iss: String,
    /// Session identifier
    pub session_id: Uuid,
    /// Embedded PE claims (signed)
    pub pe_payload: SignedPayload<PEClaims>,
    /// Embedded NPE claims (signed, wrapping PE)
    pub npe_payload: Option<SignedPayload<NPEClaims>>,
    /// DPoP proof JTI for binding (optional)
    pub dpop_jti: Option<String>,
}

/// Authentication level achieved
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthLevel {
    /// Biometric authentication (FaceID, TouchID, Windows Hello)
    Biometric,
    /// Password-based authentication
    Password,
    /// Multi-factor authentication
    MFA,
    /// WebAuthn/Passkey authentication
    WebAuthn,
}

/// Platform security state from device attestation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PlatformState {
    /// Device is secure and unmodified
    Secure,
    /// Device is jailbroken/rooted
    Jailbroken,
    /// Debug mode detected
    DebugMode,
    /// Unknown security state
    Unknown,
}

/// Cryptographically signed payload with ECDSA P-256
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPayload<T> {
    /// The actual claims/data
    pub data: T,
    /// ECDSA signature over SHA256(data)
    pub signature: Base64UrlSafeData,
    /// Compressed P-256 public key (33 bytes)
    pub public_key: Base64UrlSafeData,
    /// Timestamp when signed
    pub timestamp: DateTime<Utc>,
}

impl<T: Serialize> SignedPayload<T> {
    /// Create a new signed payload using the app's signing key
    pub fn new(data: T, app_state: &AppState) -> Result<Self, WebauthnError> {
        let data_bytes = serde_json::to_vec(&data).map_err(|e| {
            error!("Failed to serialize payload: {}", e);
            WebauthnError::TokenCreationError(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidKeyFormat,
            ))
        })?;

        let message = Sha256::digest(&data_bytes);
        let signature: Signature<NistP256> = app_state.signing_key.as_ref().sign(&message);

        // Get compressed public key (33 bytes: 0x02/0x03 + x-coordinate)
        let verifying_key = app_state.signing_key.as_ref().verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();

        Ok(Self {
            data,
            signature: Base64UrlSafeData::from(signature.to_der().as_bytes().to_vec()),
            public_key: Base64UrlSafeData::from(public_key_bytes),
            timestamp: Utc::now(),
        })
    }
}

/// Session information for Terminal Link
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub ttl_seconds: i64,
    pub did: String,
}

/// Generate Terminal Link token wrapping PE and optional NPE claims
pub fn generate_terminal_link(
    session: SessionInfo,
    pe_claims: PEClaims,
    npe_claims: Option<NPEClaims>,
    dpop_jti: Option<String>,
    app_state: &AppState,
) -> Result<String, WebauthnError> {
    info!(
        "Generating Terminal Link for user: {} session: {}",
        session.user_id, session.session_id
    );

    // Create signed PE payload
    let pe_payload = SignedPayload::new(pe_claims, app_state)?;

    // Create signed NPE payload if provided
    let npe_payload = if let Some(npe) = npe_claims {
        Some(SignedPayload::new(npe, app_state)?)
    } else {
        None
    };

    let now = Utc::now().timestamp();
    let claims = TerminalLinkClaims {
        sub: session.user_id.to_string(),
        iat: now,
        exp: now + session.ttl_seconds,
        iss: "authnz-rs".to_string(),
        session_id: session.session_id,
        pe_payload,
        npe_payload,
        dpop_jti,
    };

    let header = Header::new(Algorithm::ES256);
    encode(&header, &claims, &app_state.encoding_key).map_err(|err| {
        error!("Failed to encode Terminal Link: {}", err);
        WebauthnError::TokenCreationError(err)
    })
}

/// Validate a Terminal Link token and extract claims
pub fn validate_terminal_link(
    token: &str,
    app_state: &AppState,
) -> Result<TerminalLinkClaims, WebauthnError> {
    use jsonwebtoken::{decode, Validation};

    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.set_issuer(&["authnz-rs"]);

    let token_data =
        decode::<TerminalLinkClaims>(token, &app_state.decoding_key, &validation).map_err(
            |err| {
                error!("Failed to validate Terminal Link: {}", err);
                WebauthnError::TokenDecodingError(format!("Terminal Link validation failed: {}", err))
            },
        )?;

    info!(
        "Terminal Link validated for user: {} session: {}",
        token_data.claims.sub, token_data.claims.session_id
    );

    Ok(token_data.claims)
}

/// Extract session ID from Terminal Link without full validation (for quick lookups)
pub fn extract_session_id(token: &str) -> Result<Uuid, WebauthnError> {
    use jsonwebtoken::{decode, Validation, DecodingKey, Algorithm};

    // Decode without verification to extract session_id
    let mut validation = Validation::new(Algorithm::ES256);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;

    let token_data = decode::<TerminalLinkClaims>(
        token,
        &DecodingKey::from_secret(&[]),
        &validation,
    )
    .map_err(|err| {
        error!("Failed to extract session ID from Terminal Link: {}", err);
        WebauthnError::TokenDecodingError(format!("Session ID extraction failed: {}", err))
    })?;

    Ok(token_data.claims.session_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_level_serialization() {
        let auth_level = AuthLevel::WebAuthn;
        let json = serde_json::to_string(&auth_level).unwrap();
        assert_eq!(json, "\"webauthn\"");
    }

    #[test]
    fn test_platform_state_serialization() {
        let state = PlatformState::Secure;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"secure\"");
    }

    #[test]
    fn test_pe_claims_creation() {
        let pe_claims = PEClaims {
            user_id: "test-user".to_string(),
            auth_level: AuthLevel::WebAuthn,
            timestamp: Utc::now(),
            did: "did:key:test123".to_string(),
        };

        assert_eq!(pe_claims.user_id, "test-user");
        assert_eq!(pe_claims.auth_level, AuthLevel::WebAuthn);
    }

    #[test]
    fn test_npe_claims_creation() {
        let npe_claims = NPEClaims {
            platform_code: "iOS".to_string(),
            platform_state: PlatformState::Secure,
            device_id: "device-123".to_string(),
            app_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
        };

        assert_eq!(npe_claims.platform_code, "iOS");
        assert_eq!(npe_claims.platform_state, PlatformState::Secure);
    }
}
