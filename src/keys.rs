//! CWT signing-key loading shared by the server binary and `seed-test-user`.
//!
//! Extracted from `main.rs`'s original `load_ec_keys` so both binaries derive
//! the CWT signing/verifying key pair and `kid` identically. The `kid` is the
//! RFC 7638 JWK thumbprint as a raw 32-byte SHA-256 hash — the same bytes
//! `main.rs` has always computed (see `src/oidc.rs::ec_public_key_to_jwk` for
//! the JWKS-facing base64url encoding of the same value).

use base64::Engine;
use p256::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256};

/// Parse a PKCS8 PEM-encoded EC private key (the `ENCODING_KEY_PATH` file) into
/// the P-256 signing/verifying key pair used for CWT (COSE_Sign1, ES256), plus
/// the RFC 7638 thumbprint `kid` derived from the public key.
pub fn load_cwt_signing_key(
    pem: &str,
) -> Result<(p256::ecdsa::SigningKey, p256::ecdsa::VerifyingKey, Vec<u8>), String> {
    let secret = p256::SecretKey::from_pkcs8_pem(pem)
        .map_err(|e| format!("Failed to parse CWT signing key as PKCS8 PEM: {e}"))?;
    let signing_key: p256::ecdsa::SigningKey = secret.into();
    let verifying_key = *signing_key.verifying_key();

    // kid = RFC 7638 JWK thumbprint, raw 32-byte SHA-256 hash.
    let kid = {
        let encoded = verifying_key.to_encoded_point(false);
        let x = encoded
            .x()
            .ok_or_else(|| "EC public key missing x coordinate".to_string())?;
        let y = encoded
            .y()
            .ok_or_else(|| "EC public key missing y coordinate".to_string())?;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let thumb_input = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            b64.encode(x),
            b64.encode(y)
        );
        let mut hasher = Sha256::new();
        hasher.update(thumb_input.as_bytes());
        hasher.finalize().to_vec()
    };

    Ok((signing_key, verifying_key, kid))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
REDACTED-TEST-KEY-LINE\n\
REDACTED-TEST-KEY-LINE\n\
REDACTED-TEST-KEY-LINE\n\
-----END PRIVATE KEY-----\n";

    #[test]
    fn load_cwt_signing_key_derives_matching_pair_and_kid() {
        let (sk, vk, kid) = load_cwt_signing_key(TEST_PEM).expect("valid PKCS8 PEM");
        assert_eq!(*sk.verifying_key(), vk);
        assert_eq!(kid.len(), 32, "kid must be a raw 32-byte SHA-256 hash");
    }

    #[test]
    fn load_cwt_signing_key_is_deterministic() {
        let (_, _, kid1) = load_cwt_signing_key(TEST_PEM).unwrap();
        let (_, _, kid2) = load_cwt_signing_key(TEST_PEM).unwrap();
        assert_eq!(kid1, kid2);
    }

    #[test]
    fn load_cwt_signing_key_rejects_garbage_pem() {
        assert!(load_cwt_signing_key("not a pem").is_err());
    }
}
