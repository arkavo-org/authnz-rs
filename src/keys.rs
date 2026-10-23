//! CWT signing-key loading shared by the server binary and `seed-test-user`.
//!
//! Extracted from `main.rs`'s original `load_ec_keys` so both binaries derive
//! the CWT signing/verifying key pair and `kid` identically:
//!   - the signing key comes from the PKCS8 PEM at `ENCODING_KEY_PATH`
//!   - the verifying key comes from the SPKI PEM at `DECODING_KEY_PATH` —
//!     the same source `main.rs` has always used, kept deliberately separate
//!     from the signing key derivation as a tripwire against a
//!     mismatched/rotated key pair (see the mismatch check below)
//!   - `kid` is the RFC 7638 JWK thumbprint as a raw 32-byte SHA-256 hash,
//!     computed from the (decoding-file) verifying key, exactly as `main.rs`
//!     always computed it (see `src/oidc.rs::ec_public_key_to_jwk` for the
//!     JWKS-facing base64url encoding of the same value).

use base64::Engine;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use sha2::{Digest, Sha256};

/// Parse the CWT signing key pair from the `ENCODING_KEY_PATH` (PKCS8 PEM,
/// private) and `DECODING_KEY_PATH` (SPKI PEM, public) files, plus the RFC
/// 7638 thumbprint `kid` derived from the decoding-file public key.
///
/// Returns `Err` if the two files don't describe the same key pair — a
/// mismatched or stale `DECODING_KEY_PATH` would otherwise mint tokens whose
/// signature nothing (including this same process's own verifier) can check.
pub fn load_cwt_keys(
    encoding_pem: &str,
    decoding_pem: &str,
) -> Result<(p256::ecdsa::SigningKey, p256::ecdsa::VerifyingKey, Vec<u8>), String> {
    let secret = p256::SecretKey::from_pkcs8_pem(encoding_pem)
        .map_err(|e| format!("Failed to parse CWT signing key as PKCS8 PEM: {e}"))?;
    let signing_key: p256::ecdsa::SigningKey = secret.into();

    let pk = p256::PublicKey::from_public_key_pem(decoding_pem)
        .map_err(|e| format!("Failed to parse CWT verifying key as SPKI PEM: {e}"))?;
    let verifying_key = p256::ecdsa::VerifyingKey::from(pk);

    if *signing_key.verifying_key() != verifying_key {
        return Err("DECODING_KEY_PATH public key does not match ENCODING_KEY_PATH".to_string());
    }

    let kid = thumbprint_kid(&verifying_key)?;
    Ok((signing_key, verifying_key, kid))
}

/// `kid` = RFC 7638 JWK thumbprint of `vk`, as the raw 32-byte SHA-256 hash.
pub fn thumbprint_kid(vk: &p256::ecdsa::VerifyingKey) -> Result<Vec<u8>, String> {
    let encoded = vk.to_encoded_point(false);
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
    Ok(hasher.finalize().to_vec())
}

/// Parse a verify-only public key (SPKI PEM, one `VERIFY_ONLY_KEY_PATHS`
/// entry) and derive its `kid` as [`thumbprint_kid`] does.
pub fn load_verify_only_key(pem: &str) -> Result<(p256::ecdsa::VerifyingKey, Vec<u8>), String> {
    let pk = p256::PublicKey::from_public_key_pem(pem)
        .map_err(|e| format!("Failed to parse verify-only key as SPKI PEM: {e}"))?;
    let vk = p256::ecdsa::VerifyingKey::from(pk);
    let kid = thumbprint_kid(&vk)?;
    Ok((vk, kid))
}

/// The keys this issuer trusts (#107): the current signing key's public half
/// first, then every verify-only key, each under its `kid`. Every inbound CWT
/// is checked against the key its protected-header `kid` names, and
/// `/.well-known/cose-keys` and `jwks.json` publish the set in this order.
/// Only the current key signs; a verify-only key is the next key published
/// ahead of a rotation, or a retired one kept while what it signed must still
/// verify.
#[derive(Debug, Clone)]
pub struct KeySet {
    keys: Vec<(Vec<u8>, p256::ecdsa::VerifyingKey)>,
}

impl KeySet {
    /// A set holding only the current key.
    pub fn new(current: p256::ecdsa::VerifyingKey, kid: Vec<u8>) -> Self {
        Self {
            keys: vec![(kid, current)],
        }
    }

    /// Add a verify-only key. A `kid` or key already in the set is refused:
    /// listing the current key again, or one key twice, is a config error.
    pub fn add_verify_only(
        &mut self,
        vk: p256::ecdsa::VerifyingKey,
        kid: Vec<u8>,
    ) -> Result<(), String> {
        if self.keys.iter().any(|(k, v)| *k == kid || *v == vk) {
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            return Err(format!(
                "verify-only key {} is already in the key set",
                b64.encode(&kid)
            ));
        }
        self.keys.push((kid, vk));
        Ok(())
    }

    /// The key published under `kid`, if any. An empty `kid` names none.
    pub fn get(&self, kid: &[u8]) -> Option<&p256::ecdsa::VerifyingKey> {
        if kid.is_empty() {
            return None;
        }
        self.keys.iter().find(|(k, _)| k == kid).map(|(_, v)| v)
    }

    /// `(kid, key)` pairs, current key first.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &p256::ecdsa::VerifyingKey)> {
        self.keys.iter().map(|(k, v)| (k.as_slice(), v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

    /// Build a PKCS8 private-key PEM and matching SPKI public-key PEM at
    /// runtime from a fixed 32-byte scalar, rather than hardcoding literal
    /// PEM blocks in source (GitGuardian flags a literal PEM private key
    /// even when it's test-only and derived from a trivially-fixed scalar).
    fn test_key_pems(scalar_byte: u8) -> (String, String) {
        let scalar = p256::elliptic_curve::ScalarPrimitive::from_slice(&[scalar_byte; 32]).unwrap();
        let secret = p256::SecretKey::new(scalar);
        let encoding_pem = secret
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode PKCS8 PEM")
            .to_string();
        let decoding_pem = secret
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode SPKI PEM");
        (encoding_pem, decoding_pem)
    }

    #[test]
    fn load_cwt_keys_derives_matching_pair_and_kid() {
        let (encoding_pem, decoding_pem) = test_key_pems(0x42);
        let (sk, vk, kid) =
            load_cwt_keys(&encoding_pem, &decoding_pem).expect("matching encoding/decoding PEMs");
        assert_eq!(*sk.verifying_key(), vk);
        assert_eq!(kid.len(), 32, "kid must be a raw 32-byte SHA-256 hash");
    }

    #[test]
    fn load_cwt_keys_is_deterministic() {
        let (encoding_pem, decoding_pem) = test_key_pems(0x42);
        let (_, _, kid1) = load_cwt_keys(&encoding_pem, &decoding_pem).unwrap();
        let (_, _, kid2) = load_cwt_keys(&encoding_pem, &decoding_pem).unwrap();
        assert_eq!(kid1, kid2);
    }

    #[test]
    fn load_cwt_keys_rejects_garbage_pem() {
        assert!(load_cwt_keys("not a pem", "not a pem either").is_err());
    }

    #[test]
    fn verify_only_key_kid_matches_load_cwt_keys() {
        let (encoding_pem, decoding_pem) = test_key_pems(0x42);
        let (_, vk, kid) = load_cwt_keys(&encoding_pem, &decoding_pem).unwrap();
        let (vk2, kid2) = load_verify_only_key(&decoding_pem).unwrap();
        assert_eq!((vk, kid), (vk2, kid2));
        assert!(
            load_verify_only_key(&encoding_pem).is_err(),
            "a private key is not SPKI"
        );
    }

    #[test]
    fn key_set_looks_up_by_kid_and_refuses_duplicates() {
        let (enc_a, dec_a) = test_key_pems(0x42);
        let (_, dec_b) = test_key_pems(0x43);
        let (_, vk_a, kid_a) = load_cwt_keys(&enc_a, &dec_a).unwrap();
        let (vk_b, kid_b) = load_verify_only_key(&dec_b).unwrap();
        assert_ne!(kid_a, kid_b);

        let mut set = KeySet::new(vk_a, kid_a.clone());
        set.add_verify_only(vk_b, kid_b.clone()).unwrap();
        assert_eq!(set.get(&kid_a), Some(&vk_a));
        assert_eq!(set.get(&kid_b), Some(&vk_b));
        assert_eq!(set.get(b"unknown"), None);
        assert_eq!(set.get(b""), None);
        let kids: Vec<&[u8]> = set.iter().map(|(k, _)| k).collect();
        assert_eq!(
            kids,
            vec![kid_a.as_slice(), kid_b.as_slice()],
            "current key first"
        );

        // The current key again, a duplicate, or one key under another kid.
        assert!(set.add_verify_only(vk_a, kid_a.clone()).is_err());
        assert!(set.add_verify_only(vk_b, kid_b).is_err());
        assert!(set.add_verify_only(vk_a, b"other-kid".to_vec()).is_err());
        assert_eq!(set.iter().count(), 2);
    }

    #[test]
    fn load_cwt_keys_rejects_mismatched_decoding_key() {
        let (encoding_pem, _) = test_key_pems(0x42);
        let (_, other_decoding_pem) = test_key_pems(0x43);
        let err = load_cwt_keys(&encoding_pem, &other_decoding_pem)
            .expect_err("mismatched decoding key must be rejected");
        assert_eq!(
            err,
            "DECODING_KEY_PATH public key does not match ENCODING_KEY_PATH"
        );
    }
}
