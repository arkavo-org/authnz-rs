//! NTDF Token Generation Module
//!
//! Generates NTDF (NanoTDF-based) authentication tokens per the specification:
//! <https://github.com/arkavo-org/specifications/ntdf-token>
//!
//! Wire format: `Authorization: NTDF <Z85-encoded-nanotdf>`
//!
//! This module uses the opentdf-rs library for NanoTDF encryption, ensuring
//! correct HKDF salt (SHA256("L1L")) and spec-compliant binary format.

use log::{debug, info};
use opentdf_crypto::tdf::nanotdf::NanoTdfBuilder;
use opentdf_protocol::nanotdf::header::EccMode;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePublicKey;
use p256::PublicKey;
use thiserror::Error;

/// Capability flags for NTDF token payload
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CapabilityFlag {
    Profile = 0x01,
    OpenId = 0x02,
    Email = 0x04,
    OfflineAccess = 0x08,
    DeviceAttested = 0x10,
    BiometricAuth = 0x20,
    WebAuthn = 0x40,
    PlatformSecure = 0x80,
}

/// Attribute types for NTDF token payload
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum AttributeType {
    Age = 0,
    SubscriptionTier = 1,
    SecurityLevel = 2,
    PlatformCode = 3,
}

/// NTDF token payload containing authentication claims
#[derive(Debug, Clone)]
pub struct NtdfTokenPayload {
    /// Subject UUID (16 bytes)
    pub sub_id: [u8; 16],
    /// Capability flags (bitfield)
    pub flags: u64,
    /// OAuth scopes
    pub scopes: Vec<String>,
    /// Typed attributes (type, value)
    pub attrs: Vec<(u8, u32)>,
    /// DPoP JTI for proof-of-possession binding (optional)
    pub dpop_jti: Option<[u8; 16]>,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expiration (Unix timestamp)
    pub exp: i64,
    /// Audience (target service)
    pub aud: String,
    /// Session tracking ID (optional)
    pub session_id: Option<[u8; 16]>,
    /// Device identifier (optional)
    pub device_id: Option<String>,
    /// Decentralized Identifier (optional)
    pub did: Option<String>,
}

impl NtdfTokenPayload {
    /// Serialize payload to binary format per NTDF spec
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // sub_id (16 bytes)
        buf.extend_from_slice(&self.sub_id);

        // flags (8 bytes, u64 little-endian)
        buf.extend_from_slice(&self.flags.to_le_bytes());

        // scopes_count (2 bytes, u16 little-endian)
        buf.extend_from_slice(&(self.scopes.len() as u16).to_le_bytes());

        // scopes (length-prefixed strings)
        for scope in &self.scopes {
            buf.push(scope.len() as u8);
            buf.extend_from_slice(scope.as_bytes());
        }

        // attrs_count (2 bytes, u16 little-endian)
        buf.extend_from_slice(&(self.attrs.len() as u16).to_le_bytes());

        // attrs (type: 1 byte, value: 4 bytes)
        for (attr_type, attr_value) in &self.attrs {
            buf.push(*attr_type);
            buf.extend_from_slice(&attr_value.to_le_bytes());
        }

        // dpop_jti_present (1 byte)
        if let Some(jti) = &self.dpop_jti {
            buf.push(1);
            buf.extend_from_slice(jti);
        } else {
            buf.push(0);
        }

        // iat (8 bytes, i64 little-endian)
        buf.extend_from_slice(&self.iat.to_le_bytes());

        // exp (8 bytes, i64 little-endian)
        buf.extend_from_slice(&self.exp.to_le_bytes());

        // aud_length (2 bytes, u16 little-endian) + aud
        buf.extend_from_slice(&(self.aud.len() as u16).to_le_bytes());
        buf.extend_from_slice(self.aud.as_bytes());

        // session_id_present (1 byte)
        if let Some(sid) = &self.session_id {
            buf.push(1);
            buf.extend_from_slice(sid);
        } else {
            buf.push(0);
        }

        // device_id_present (1 byte)
        if let Some(device_id) = &self.device_id {
            buf.push(1);
            buf.push(device_id.len() as u8);
            buf.extend_from_slice(device_id.as_bytes());
        } else {
            buf.push(0);
        }

        // did_present (1 byte)
        if let Some(did) = &self.did {
            buf.push(1);
            buf.extend_from_slice(&(did.len() as u16).to_le_bytes());
            buf.extend_from_slice(did.as_bytes());
        } else {
            buf.push(0);
        }

        buf
    }
}

/// Errors that can occur during NTDF token generation
#[derive(Debug, Error)]
pub enum NtdfTokenError {
    #[error("KAS public key not configured")]
    NoKasPublicKey,

    #[error("NanoTDF encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("NanoTDF serialization failed: {0}")]
    SerializationFailed(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
}

/// Builder for generating NTDF tokens using opentdf-rs
pub struct NtdfTokenBuilder {
    /// KAS public key bytes (compressed SEC1 format)
    kas_public_key_bytes: Vec<u8>,
    /// KAS URL to embed in token header
    kas_url: String,
}

impl NtdfTokenBuilder {
    /// Create a new NTDF token builder
    ///
    /// # Arguments
    /// * `kas_public_key` - The KAS P-256 public key for ECDH encryption
    /// * `kas_url` - The KAS URL to embed in the token header
    pub fn new(kas_public_key: PublicKey, kas_url: String) -> Self {
        // Convert to compressed SEC1 format (33 bytes for P-256)
        let kas_public_key_bytes = kas_public_key.to_encoded_point(true).as_bytes().to_vec();
        Self {
            kas_public_key_bytes,
            kas_url,
        }
    }

    /// Load KAS public key from PEM file
    pub fn from_pem(pem_bytes: &[u8], kas_url: String) -> Result<Self, NtdfTokenError> {
        // Parse PEM to extract the public key
        let pem = pem::parse(pem_bytes)
            .map_err(|e| NtdfTokenError::InvalidKeyFormat(format!("PEM parse error: {}", e)))?;

        let public_key = match pem.tag() {
            "PUBLIC KEY" => {
                // SPKI format
                PublicKey::from_public_key_der(pem.contents()).map_err(|e| {
                    NtdfTokenError::InvalidKeyFormat(format!("Invalid SPKI public key: {}", e))
                })?
            }
            "EC PUBLIC KEY" => {
                // SEC1 format
                PublicKey::from_sec1_bytes(pem.contents()).map_err(|e| {
                    NtdfTokenError::InvalidKeyFormat(format!("Invalid SEC1 public key: {}", e))
                })?
            }
            tag => {
                return Err(NtdfTokenError::InvalidKeyFormat(format!(
                    "Unexpected PEM tag: {}",
                    tag
                )))
            }
        };

        Ok(Self::new(public_key, kas_url))
    }

    /// Build an NTDF token from the given payload
    ///
    /// Returns a Z85-encoded NanoTDF token string
    ///
    /// Uses opentdf-rs for NanoTDF generation with:
    /// - P-256 (secp256r1) ECDH key agreement
    /// - HKDF-SHA256 with salt = SHA256("L1L") per NanoTDF spec
    /// - AES-256-GCM encryption
    /// - Embedded plaintext policy containing the serialized payload
    pub fn build(&self, payload: &NtdfTokenPayload) -> Result<String, NtdfTokenError> {
        debug!(
            "Building NTDF token for sub_id={:?}",
            hex::encode(payload.sub_id)
        );

        // 1. Serialize payload to binary
        let plaintext = payload.to_bytes();
        debug!("Payload serialized: {} bytes", plaintext.len());

        // 2. Use opentdf-rs NanoTdfBuilder for encryption
        // The library handles:
        // - Ephemeral key generation
        // - ECDH key agreement
        // - HKDF key derivation with correct NanoTDF salt (SHA256("L1L"))
        // - AES-256-GCM encryption
        // - Binary format assembly
        let nanotdf = NanoTdfBuilder::new()
            .kas_url(&self.kas_url)
            .policy_plaintext(plaintext.clone())
            .ecc_mode(EccMode::Secp256r1)
            .encrypt(&plaintext, &self.kas_public_key_bytes)
            .map_err(|e| NtdfTokenError::EncryptionFailed(e.to_string()))?;

        debug!("NanoTDF encryption complete");

        // 3. Serialize to bytes
        let nanotdf_bytes = nanotdf
            .to_bytes()
            .map_err(|e| NtdfTokenError::SerializationFailed(e.to_string()))?;

        debug!("NanoTDF serialized: {} bytes", nanotdf_bytes.len());

        // 4. Z85 encode
        let z85_token = z85::encode(&nanotdf_bytes);

        info!(
            "NTDF token generated: {} chars, sub_id={}",
            z85_token.len(),
            hex::encode(payload.sub_id)
        );

        Ok(z85_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_serialization() {
        let payload = NtdfTokenPayload {
            sub_id: [0x01; 16],
            flags: CapabilityFlag::WebAuthn as u64 | CapabilityFlag::Profile as u64,
            scopes: vec!["openid".to_string(), "profile".to_string()],
            attrs: vec![(AttributeType::Age as u8, 25)],
            dpop_jti: None,
            iat: 1700000000,
            exp: 2700000000,
            aud: "https://kas.arkavo.net".to_string(),
            session_id: None,
            device_id: None,
            did: Some("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string()),
        };

        let bytes = payload.to_bytes();
        assert!(!bytes.is_empty());

        // Verify sub_id is at the start
        assert_eq!(&bytes[0..16], &[0x01; 16]);

        // Verify flags (bytes 16-23, little-endian u64)
        let flags = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        assert_eq!(flags, 0x41); // WebAuthn (0x40) | Profile (0x01)
    }

    #[test]
    fn test_capability_flags() {
        let flags = CapabilityFlag::WebAuthn as u64
            | CapabilityFlag::Profile as u64
            | CapabilityFlag::DeviceAttested as u64;

        assert_eq!(flags & CapabilityFlag::WebAuthn as u64, 0x40);
        assert_eq!(flags & CapabilityFlag::Profile as u64, 0x01);
        assert_eq!(flags & CapabilityFlag::DeviceAttested as u64, 0x10);
        assert_eq!(flags & CapabilityFlag::Email as u64, 0x00);
    }

    #[test]
    fn test_ntdf_token_roundtrip() {
        use p256::SecretKey;
        use rand_core::OsRng;

        // Generate a test key pair
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();

        // Create builder
        let builder = NtdfTokenBuilder::new(public_key, "https://kas.arkavo.net".to_string());

        // Create payload
        let payload = NtdfTokenPayload {
            sub_id: [0x42; 16],
            flags: CapabilityFlag::WebAuthn as u64,
            scopes: vec!["openid".to_string()],
            attrs: vec![],
            dpop_jti: None,
            iat: 1700000000,
            exp: 1700003600,
            aud: "https://kas.arkavo.net".to_string(),
            session_id: None,
            device_id: None,
            did: None,
        };

        // Build token
        let token = builder.build(&payload).expect("Token generation failed");

        // Verify it's valid Z85
        assert!(!token.is_empty());

        // Decode Z85 and verify it's valid NanoTDF
        let decoded = z85::decode(&token).expect("Z85 decode failed");
        assert!(decoded.len() > 3);

        // Verify magic number "L1L"
        assert_eq!(&decoded[0..3], b"L1L", "Invalid NanoTDF magic number");
    }
}
