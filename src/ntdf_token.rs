//! NTDF Token Generation Module
//!
//! Generates NTDF (NanoTDF-based) authentication tokens per the specification:
//! <https://github.com/arkavo-org/specifications/ntdf-token>
//!
//! Wire format: `Authorization: NTDF <Z85-encoded-nanotdf>`

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::KeyInit;
use aes_gcm::aead::{Aead, Key};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use log::{debug, info};
use p256::ecdh::EphemeralSecret;
use p256::pkcs8::DecodePublicKey;
use p256::PublicKey;
use rand_core::OsRng;
use sha2::Sha256;
use std::io::Write;
use thiserror::Error;

/// NanoTDF HKDF salt (from opentdf_protocol specification)
/// This is SHA256("L1L") for version 1.2 compatibility
const HKDF_SALT: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

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

    #[error("ECDH key agreement failed: {0}")]
    EcdhError(String),

    #[error("AES-GCM encryption failed")]
    EncryptionFailed,

    #[error("Z85 encoding failed: {0}")]
    Z85EncodeError(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
}

/// Builder for generating NTDF tokens
pub struct NtdfTokenBuilder {
    /// KAS public key for ECDH
    kas_public_key: PublicKey,
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
        Self {
            kas_public_key,
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
    pub fn build(&self, payload: &NtdfTokenPayload) -> Result<String, NtdfTokenError> {
        debug!("Building NTDF token for sub_id={:?}", hex::encode(payload.sub_id));

        // 1. Serialize payload to binary
        let plaintext = payload.to_bytes();
        debug!("Payload serialized: {} bytes", plaintext.len());

        // 2. Generate ephemeral key pair for ECDH
        let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // 3. ECDH key agreement
        let shared_secret = ephemeral_secret.diffie_hellman(&self.kas_public_key);
        let shared_bytes = shared_secret.raw_secret_bytes();

        debug!("ECDH key agreement complete");

        // 4. HKDF key derivation
        let hkdf = Hkdf::<Sha256>::new(Some(&HKDF_SALT), shared_bytes);
        let mut aes_key = [0u8; 32];
        hkdf.expand(b"", &mut aes_key)
            .map_err(|_| NtdfTokenError::EcdhError("HKDF expansion failed".into()))?;

        // 5. AES-256-GCM encryption (zero nonce per NanoTDF spec)
        let nonce = GenericArray::from_slice(&[0u8; 12]);
        let key = Key::<Aes256Gcm>::from(aes_key);
        let cipher = Aes256Gcm::new(&key);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| NtdfTokenError::EncryptionFailed)?;

        debug!("Encrypted payload: {} bytes", ciphertext.len());

        // 6. Build NanoTDF structure
        let nanotdf = self.build_nanotdf(&ephemeral_public, &ciphertext)?;

        debug!("NanoTDF built: {} bytes", nanotdf.len());

        // 7. Z85 encode
        let z85_token = z85::encode(&nanotdf);

        info!(
            "NTDF token generated: {} chars, sub_id={}",
            z85_token.len(),
            hex::encode(payload.sub_id)
        );

        Ok(z85_token)
    }

    /// Build NanoTDF binary structure
    fn build_nanotdf(
        &self,
        ephemeral_public: &PublicKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, NtdfTokenError> {
        let mut buf = Vec::new();

        // Magic number "L1" + version byte (0x4C for v1.2)
        buf.write_all(b"L1L").map_err(|_| NtdfTokenError::EncryptionFailed)?;

        // KAS URL (length-prefixed, 1 byte length for short URLs)
        let kas_bytes = self.kas_url.as_bytes();
        if kas_bytes.len() > 255 {
            return Err(NtdfTokenError::InvalidKeyFormat("KAS URL too long".into()));
        }
        buf.push(kas_bytes.len() as u8);
        buf.write_all(kas_bytes).map_err(|_| NtdfTokenError::EncryptionFailed)?;

        // ECC and binding mode byte:
        // Bits 7-4: ECC mode (0 = secp256r1)
        // Bits 3-2: Binding mode (0 = no binding)
        // Bits 1-0: Symmetric cipher (0 = AES-256-GCM)
        buf.push(0x00);

        // Ephemeral public key (compressed SEC1 format, 33 bytes for P-256)
        let ephemeral_bytes = ephemeral_public.to_sec1_bytes();
        buf.write_all(&ephemeral_bytes).map_err(|_| NtdfTokenError::EncryptionFailed)?;

        // Payload: length (3 bytes big-endian) + ciphertext
        let len = ciphertext.len();
        buf.push(((len >> 16) & 0xFF) as u8);
        buf.push(((len >> 8) & 0xFF) as u8);
        buf.push((len & 0xFF) as u8);
        buf.write_all(ciphertext).map_err(|_| NtdfTokenError::EncryptionFailed)?;

        Ok(buf)
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
}
