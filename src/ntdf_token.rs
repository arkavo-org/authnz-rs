//! NTDF Token Generation and Decoding Module
//!
//! Generates and decodes NTDF (NanoTDF-based) authentication tokens per the specification:
//! <https://github.com/arkavo-org/specifications/ntdf-token>
//!
//! Wire format: `Authorization: NTDF <Z85-encoded-nanotdf>`
//!
//! This module uses the opentdf-rs library for NanoTDF encryption/decryption, ensuring
//! correct HKDF salt (SHA256("L1L")) and spec-compliant binary format.

use chrono::Utc;
use log::{debug, info, warn};
use opentdf_crypto::tdf::nanotdf::{NanoTdf, NanoTdfBuilder};
use opentdf_protocol::nanotdf::header::EccMode;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use p256::{PublicKey, SecretKey};
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
    /// Token issued to a delegated agent (CLI, mesh worker, etc.)
    AgentDelegated = 0x100,
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
    /// Immediate delegator's UUID (for agent delegation)
    pub delegator_id: Option<[u8; 16]>,
    /// Original human's UUID (root of delegation chain)
    pub root_user_id: Option<[u8; 16]>,
    /// Delegation chain depth (0 = direct from human, max 5)
    pub delegation_depth: Option<u8>,
    /// Full DID chain for audit trail (delegator DIDs from root to immediate)
    pub delegation_chain: Option<Vec<String>>,
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

        // delegator_id_present (1 byte)
        if let Some(delegator_id) = &self.delegator_id {
            buf.push(1);
            buf.extend_from_slice(delegator_id);
        } else {
            buf.push(0);
        }

        // root_user_id_present (1 byte)
        if let Some(root_user_id) = &self.root_user_id {
            buf.push(1);
            buf.extend_from_slice(root_user_id);
        } else {
            buf.push(0);
        }

        // delegation_depth_present (1 byte)
        if let Some(depth) = &self.delegation_depth {
            buf.push(1);
            buf.push(*depth);
        } else {
            buf.push(0);
        }

        // delegation_chain_present (1 byte)
        if let Some(chain) = &self.delegation_chain {
            buf.push(1);
            // chain_length (2 bytes, u16 little-endian)
            buf.extend_from_slice(&(chain.len() as u16).to_le_bytes());
            for did in chain {
                // Each DID: length (2 bytes) + string bytes
                buf.extend_from_slice(&(did.len() as u16).to_le_bytes());
                buf.extend_from_slice(did.as_bytes());
            }
        } else {
            buf.push(0);
        }

        buf
    }

    /// Deserialize payload from binary format (inverse of to_bytes())
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NtdfTokenError> {
        let mut pos = 0;

        // Helper macro for reading bytes safely
        macro_rules! read_bytes {
            ($len:expr) => {{
                if pos + $len > bytes.len() {
                    return Err(NtdfTokenError::InvalidPayload(format!(
                        "Unexpected end of data at position {}, need {} bytes",
                        pos, $len
                    )));
                }
                let slice = &bytes[pos..pos + $len];
                pos += $len;
                slice
            }};
        }

        // sub_id (16 bytes)
        let sub_id: [u8; 16] = read_bytes!(16).try_into().unwrap();

        // flags (8 bytes, u64 little-endian)
        let flags = u64::from_le_bytes(read_bytes!(8).try_into().unwrap());

        // scopes_count (2 bytes, u16 little-endian)
        let scopes_count = u16::from_le_bytes(read_bytes!(2).try_into().unwrap()) as usize;

        // scopes (length-prefixed strings)
        let mut scopes = Vec::with_capacity(scopes_count);
        for _ in 0..scopes_count {
            let len = read_bytes!(1)[0] as usize;
            let scope = String::from_utf8(read_bytes!(len).to_vec())
                .map_err(|e| NtdfTokenError::InvalidPayload(format!("Invalid UTF-8 in scope: {}", e)))?;
            scopes.push(scope);
        }

        // attrs_count (2 bytes, u16 little-endian)
        let attrs_count = u16::from_le_bytes(read_bytes!(2).try_into().unwrap()) as usize;

        // attrs (type: 1 byte, value: 4 bytes)
        let mut attrs = Vec::with_capacity(attrs_count);
        for _ in 0..attrs_count {
            let attr_type = read_bytes!(1)[0];
            let attr_value = u32::from_le_bytes(read_bytes!(4).try_into().unwrap());
            attrs.push((attr_type, attr_value));
        }

        // dpop_jti_present (1 byte)
        let dpop_jti = if read_bytes!(1)[0] == 1 {
            Some(read_bytes!(16).try_into().unwrap())
        } else {
            None
        };

        // iat (8 bytes, i64 little-endian)
        let iat = i64::from_le_bytes(read_bytes!(8).try_into().unwrap());

        // exp (8 bytes, i64 little-endian)
        let exp = i64::from_le_bytes(read_bytes!(8).try_into().unwrap());

        // aud_length (2 bytes, u16 little-endian) + aud
        let aud_len = u16::from_le_bytes(read_bytes!(2).try_into().unwrap()) as usize;
        let aud = String::from_utf8(read_bytes!(aud_len).to_vec())
            .map_err(|e| NtdfTokenError::InvalidPayload(format!("Invalid UTF-8 in aud: {}", e)))?;

        // session_id_present (1 byte)
        let session_id = if read_bytes!(1)[0] == 1 {
            Some(read_bytes!(16).try_into().unwrap())
        } else {
            None
        };

        // device_id_present (1 byte)
        let device_id = if read_bytes!(1)[0] == 1 {
            let len = read_bytes!(1)[0] as usize;
            let device = String::from_utf8(read_bytes!(len).to_vec())
                .map_err(|e| NtdfTokenError::InvalidPayload(format!("Invalid UTF-8 in device_id: {}", e)))?;
            Some(device)
        } else {
            None
        };

        // did_present (1 byte)
        let did = if read_bytes!(1)[0] == 1 {
            let len = u16::from_le_bytes(read_bytes!(2).try_into().unwrap()) as usize;
            let did_str = String::from_utf8(read_bytes!(len).to_vec())
                .map_err(|e| NtdfTokenError::InvalidPayload(format!("Invalid UTF-8 in did: {}", e)))?;
            Some(did_str)
        } else {
            None
        };

        // delegator_id_present (1 byte)
        let delegator_id = if read_bytes!(1)[0] == 1 {
            Some(read_bytes!(16).try_into().unwrap())
        } else {
            None
        };

        // root_user_id_present (1 byte)
        let root_user_id = if read_bytes!(1)[0] == 1 {
            Some(read_bytes!(16).try_into().unwrap())
        } else {
            None
        };

        // delegation_depth_present (1 byte)
        let delegation_depth = if read_bytes!(1)[0] == 1 {
            Some(read_bytes!(1)[0])
        } else {
            None
        };

        // delegation_chain_present (1 byte)
        let delegation_chain = if read_bytes!(1)[0] == 1 {
            let chain_len = u16::from_le_bytes(read_bytes!(2).try_into().unwrap()) as usize;
            let mut chain = Vec::with_capacity(chain_len);
            for _ in 0..chain_len {
                let did_len = u16::from_le_bytes(read_bytes!(2).try_into().unwrap()) as usize;
                let did_str = String::from_utf8(read_bytes!(did_len).to_vec())
                    .map_err(|e| NtdfTokenError::InvalidPayload(format!("Invalid UTF-8 in chain did: {}", e)))?;
                chain.push(did_str);
            }
            Some(chain)
        } else {
            None
        };

        Ok(Self {
            sub_id,
            flags,
            scopes,
            attrs,
            dpop_jti,
            iat,
            exp,
            aud,
            session_id,
            device_id,
            did,
            delegator_id,
            root_user_id,
            delegation_depth,
            delegation_chain,
        })
    }
}

/// Errors that can occur during NTDF token generation/decoding
#[derive(Debug, Error)]
pub enum NtdfTokenError {
    #[error("KAS public key not configured")]
    NoKasPublicKey,

    #[error("KAS private key not configured")]
    NoKasPrivateKey,

    #[error("NanoTDF encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("NanoTDF decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("NanoTDF serialization failed: {0}")]
    SerializationFailed(String),

    #[error("NanoTDF deserialization failed: {0}")]
    DeserializationFailed(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Invalid payload format: {0}")]
    InvalidPayload(String),

    #[error("Token expired")]
    TokenExpired,

    #[error("Z85 decode failed: {0}")]
    Z85DecodeFailed(String),
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

/// Decoder for NTDF tokens using opentdf-rs
///
/// Decodes Z85-encoded NanoTDF tokens by:
/// 1. Z85 decoding the token string
/// 2. Parsing the NanoTDF structure
/// 3. Decrypting using the KAS private key
/// 4. Deserializing the payload
pub struct NtdfTokenDecoder {
    /// KAS private key for ECDH decryption (SEC1 format)
    kas_private_key_bytes: Vec<u8>,
    /// Whether to validate token expiration
    validate_exp: bool,
}

impl NtdfTokenDecoder {
    /// Create a new NTDF token decoder from SEC1 DER bytes
    ///
    /// # Arguments
    /// * `kas_private_key` - The KAS P-256 private key for ECDH decryption
    pub fn new(kas_private_key: SecretKey) -> Self {
        // Convert to SEC1 DER format for opentdf-rs compatibility
        let kas_private_key_bytes = kas_private_key.to_sec1_der().expect("SEC1 encoding failed").to_vec();
        Self {
            kas_private_key_bytes,
            validate_exp: true,
        }
    }

    /// Load KAS private key from PEM file
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, NtdfTokenError> {
        // Parse PEM to extract the private key
        let pem = pem::parse(pem_bytes)
            .map_err(|e| NtdfTokenError::InvalidKeyFormat(format!("PEM parse error: {}", e)))?;

        // opentdf-rs expects SEC1 or PKCS8 DER format
        // Store the DER bytes directly to pass to decrypt()
        let (secret_key, der_bytes) = match pem.tag() {
            "PRIVATE KEY" => {
                // PKCS#8 format - validate it, then store DER bytes
                let key = SecretKey::from_pkcs8_der(pem.contents()).map_err(|e| {
                    NtdfTokenError::InvalidKeyFormat(format!("Invalid PKCS#8 private key: {}", e))
                })?;
                (key, pem.contents().to_vec())
            }
            "EC PRIVATE KEY" => {
                // SEC1 format - validate it, then store DER bytes
                let key = SecretKey::from_sec1_der(pem.contents()).map_err(|e| {
                    NtdfTokenError::InvalidKeyFormat(format!("Invalid SEC1 private key: {}", e))
                })?;
                (key, pem.contents().to_vec())
            }
            tag => {
                return Err(NtdfTokenError::InvalidKeyFormat(format!(
                    "Unexpected PEM tag for private key: {}",
                    tag
                )))
            }
        };

        // Verify key is valid by parsing, but store original DER bytes
        let _ = secret_key;
        Ok(Self {
            kas_private_key_bytes: der_bytes,
            validate_exp: true,
        })
    }

    /// Set whether to validate token expiration
    ///
    /// Default is true. Set to false to allow expired tokens (for testing/debugging).
    pub fn validate_exp(mut self, validate: bool) -> Self {
        self.validate_exp = validate;
        self
    }

    /// Decode an NTDF token string
    ///
    /// # Arguments
    /// * `token` - Z85-encoded NanoTDF token string (without "NTDF " prefix)
    ///
    /// # Returns
    /// The decoded payload, or an error if decoding/decryption fails
    pub fn decode(&self, token: &str) -> Result<NtdfTokenPayload, NtdfTokenError> {
        debug!("Decoding NTDF token: {} chars", token.len());

        // 1. Z85 decode
        let nanotdf_bytes = z85::decode(token)
            .map_err(|e| NtdfTokenError::Z85DecodeFailed(format!("{:?}", e)))?;

        debug!("Z85 decoded: {} bytes", nanotdf_bytes.len());

        // 2. Parse NanoTDF structure
        let nanotdf = NanoTdf::from_bytes(&nanotdf_bytes)
            .map_err(|e| NtdfTokenError::DeserializationFailed(e.to_string()))?;

        debug!("NanoTDF parsed successfully");

        // 3. Decrypt with private key
        let plaintext = nanotdf
            .decrypt(&self.kas_private_key_bytes)
            .map_err(|e| NtdfTokenError::DecryptionFailed(e.to_string()))?;

        debug!("NanoTDF decrypted: {} bytes plaintext", plaintext.len());

        // 4. Deserialize payload
        let payload = NtdfTokenPayload::from_bytes(&plaintext)?;

        // 5. Validate expiration if enabled
        if self.validate_exp {
            let now = Utc::now().timestamp();
            if payload.exp < now {
                warn!(
                    "Token expired: exp={}, now={}, diff={}s",
                    payload.exp,
                    now,
                    now - payload.exp
                );
                return Err(NtdfTokenError::TokenExpired);
            }
        }

        info!(
            "NTDF token decoded: sub_id={}",
            hex::encode(payload.sub_id)
        );

        Ok(payload)
    }

    /// Decode an NTDF token from an Authorization header value
    ///
    /// # Arguments
    /// * `header_value` - Full header value (e.g., "NTDF abc123...")
    ///
    /// # Returns
    /// The decoded payload, or an error
    pub fn decode_header(&self, header_value: &str) -> Result<NtdfTokenPayload, NtdfTokenError> {
        let token = header_value
            .strip_prefix("NTDF ")
            .ok_or_else(|| {
                NtdfTokenError::InvalidPayload("Header must start with 'NTDF '".to_string())
            })?;

        self.decode(token)
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
            delegator_id: None,
            root_user_id: None,
            delegation_depth: None,
            delegation_chain: None,
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
            delegator_id: None,
            root_user_id: None,
            delegation_depth: None,
            delegation_chain: None,
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

    #[test]
    fn test_payload_roundtrip() {
        // Create a payload with all optional fields populated
        let original = NtdfTokenPayload {
            sub_id: [0x42; 16],
            flags: CapabilityFlag::WebAuthn as u64 | CapabilityFlag::Profile as u64,
            scopes: vec!["openid".to_string(), "profile".to_string()],
            attrs: vec![(AttributeType::Age as u8, 25), (AttributeType::SecurityLevel as u8, 3)],
            dpop_jti: Some([0xAB; 16]),
            iat: 1700000000,
            exp: 2700000000,
            aud: "https://kas.arkavo.net".to_string(),
            session_id: Some([0xCD; 16]),
            device_id: Some("device-123".to_string()),
            did: Some("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string()),
            delegator_id: Some([0xDE; 16]),
            root_user_id: Some([0xEF; 16]),
            delegation_depth: Some(2),
            delegation_chain: Some(vec!["did:key:abc".to_string(), "did:key:def".to_string()]),
        };

        // Serialize to bytes
        let bytes = original.to_bytes();

        // Deserialize back
        let recovered = NtdfTokenPayload::from_bytes(&bytes).expect("from_bytes failed");

        // Verify all fields match
        assert_eq!(recovered.sub_id, original.sub_id);
        assert_eq!(recovered.flags, original.flags);
        assert_eq!(recovered.scopes, original.scopes);
        assert_eq!(recovered.attrs, original.attrs);
        assert_eq!(recovered.dpop_jti, original.dpop_jti);
        assert_eq!(recovered.iat, original.iat);
        assert_eq!(recovered.exp, original.exp);
        assert_eq!(recovered.aud, original.aud);
        assert_eq!(recovered.session_id, original.session_id);
        assert_eq!(recovered.device_id, original.device_id);
        assert_eq!(recovered.did, original.did);
        assert_eq!(recovered.delegator_id, original.delegator_id);
        assert_eq!(recovered.root_user_id, original.root_user_id);
        assert_eq!(recovered.delegation_depth, original.delegation_depth);
        assert_eq!(recovered.delegation_chain, original.delegation_chain);
    }

    #[test]
    fn test_payload_roundtrip_minimal() {
        // Create a minimal payload with no optional fields
        let original = NtdfTokenPayload {
            sub_id: [0x01; 16],
            flags: 0,
            scopes: vec![],
            attrs: vec![],
            dpop_jti: None,
            iat: 1700000000,
            exp: 1700003600,
            aud: "https://kas.arkavo.net".to_string(),
            session_id: None,
            device_id: None,
            did: None,
            delegator_id: None,
            root_user_id: None,
            delegation_depth: None,
            delegation_chain: None,
        };

        let bytes = original.to_bytes();
        let recovered = NtdfTokenPayload::from_bytes(&bytes).expect("from_bytes failed");

        assert_eq!(recovered.sub_id, original.sub_id);
        assert_eq!(recovered.flags, original.flags);
        assert_eq!(recovered.scopes, original.scopes);
        assert_eq!(recovered.dpop_jti, original.dpop_jti);
        assert_eq!(recovered.did, original.did);
    }

    #[test]
    fn test_decoder_full_roundtrip() {
        use p256::SecretKey;
        use rand_core::OsRng;

        // Generate a test key pair
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();

        // Create builder and decoder
        let builder = NtdfTokenBuilder::new(public_key, "https://kas.arkavo.net".to_string());
        let decoder = NtdfTokenDecoder::new(secret_key).validate_exp(false);

        // Create payload (with exp in the past for testing - exp validation disabled)
        let original = NtdfTokenPayload {
            sub_id: [0x42; 16],
            flags: CapabilityFlag::WebAuthn as u64,
            scopes: vec!["openid".to_string()],
            attrs: vec![],
            dpop_jti: None,
            iat: 1700000000,
            exp: 1700003600, // Expired but we disabled validation
            aud: "https://kas.arkavo.net".to_string(),
            session_id: None,
            device_id: None,
            did: Some("did:key:test".to_string()),
            delegator_id: None,
            root_user_id: None,
            delegation_depth: None,
            delegation_chain: None,
        };

        // Build token
        let token = builder.build(&original).expect("Token generation failed");

        // Decode token
        let recovered = decoder.decode(&token).expect("Token decoding failed");

        // Verify fields match
        assert_eq!(recovered.sub_id, original.sub_id);
        assert_eq!(recovered.flags, original.flags);
        assert_eq!(recovered.scopes, original.scopes);
        assert_eq!(recovered.did, original.did);
    }

    #[test]
    fn test_decoder_header_parsing() {
        use p256::SecretKey;
        use rand_core::OsRng;

        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();

        let builder = NtdfTokenBuilder::new(public_key, "https://kas.arkavo.net".to_string());
        let decoder = NtdfTokenDecoder::new(secret_key).validate_exp(false);

        let payload = NtdfTokenPayload {
            sub_id: [0x01; 16],
            flags: 0,
            scopes: vec![],
            attrs: vec![],
            dpop_jti: None,
            iat: 1700000000,
            exp: 1700003600,
            aud: "https://kas.arkavo.net".to_string(),
            session_id: None,
            device_id: None,
            did: None,
            delegator_id: None,
            root_user_id: None,
            delegation_depth: None,
            delegation_chain: None,
        };

        let token = builder.build(&payload).expect("Token generation failed");
        let header_value = format!("NTDF {}", token);

        let recovered = decoder.decode_header(&header_value).expect("Header decoding failed");
        assert_eq!(recovered.sub_id, payload.sub_id);
    }

    #[test]
    fn test_decoder_invalid_header_prefix() {
        use p256::SecretKey;
        use rand_core::OsRng;

        let secret_key = SecretKey::random(&mut OsRng);
        let decoder = NtdfTokenDecoder::new(secret_key);

        let result = decoder.decode_header("Bearer token123");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NtdfTokenError::InvalidPayload(_)));
    }

    #[test]
    fn test_decoder_invalid_z85() {
        use p256::SecretKey;
        use rand_core::OsRng;

        let secret_key = SecretKey::random(&mut OsRng);
        let decoder = NtdfTokenDecoder::new(secret_key);

        let result = decoder.decode("!!!invalid-z85!!!");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NtdfTokenError::Z85DecodeFailed(_)));
    }
}
