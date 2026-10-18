//! App Store purchases: verification of the JWS that StoreKit 2 and App Store
//! Server Notifications V2 sign (transactions, renewal info, notification
//! bodies).
//!
//! [`verify_jws`] makes the checks Apple's App Store Server Library makes:
//! ES256 only; an `x5c` of exactly leaf, intermediate and the pinned Apple Root
//! CA - G3; each link's signature; Apple's marker extension on the leaf and on
//! the intermediate; every certificate valid at the payload's `signedDate`;
//! and the leaf's signature over `header.payload`. There is no online
//! revocation (OCSP) check.
//!
//! Errors are unit variants with fixed messages, so nothing from a signed
//! payload can reach a log line or a response body through them.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use std::sync::OnceLock;
use thiserror::Error;
use x509_parser::prelude::*;

/// Apple Root CA - G3, from
/// <https://www.apple.com/certificateauthority/AppleRootCA-G3.cer>: the root
/// of every App Store signing chain.
pub(crate) const APPLE_ROOT_CA_G3: &str = r#"-----BEGIN CERTIFICATE-----
MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwS
QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN
MTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBS
b290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9y
aXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49
AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtf
TjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517
IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySr
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gA
MGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4
at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM
6BgD56KyKA==
-----END CERTIFICATE-----"#;

// DER of the pinned root, decoded once on first use.
static APPLE_ROOT_G3_DER: OnceLock<Vec<u8>> = OnceLock::new();

/// Marker extension of Apple's Worldwide Developer Relations intermediate.
const WWDR_INTERMEDIATE_OID: [u64; 8] = [1, 2, 840, 113635, 100, 6, 2, 1];

/// Marker extension of the App Store receipt-signing leaf.
const RECEIPT_SIGNING_OID: [u64; 8] = [1, 2, 840, 113635, 100, 6, 11, 1];

/// The DER of [`APPLE_ROOT_CA_G3`], decoded once.
// Reached only from tests until a route verifies a purchase.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn apple_root_g3_der() -> &'static [u8] {
    APPLE_ROOT_G3_DER.get_or_init(|| {
        ::pem::parse(APPLE_ROOT_CA_G3.as_bytes())
            .expect("Failed to parse embedded Apple Root CA - G3 PEM")
            .contents()
            .to_vec()
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum AppStoreError {
    #[error("malformed signed payload")]
    Malformed,
    #[error("certificate chain does not verify")]
    InvalidChain,
    #[error("signature does not verify")]
    InvalidSignature,
    // The payload checks produce the rest.
    #[allow(dead_code)]
    #[error("signed for another app")]
    WrongApp,
    #[allow(dead_code)]
    #[error("environment not accepted")]
    WrongEnvironment,
    #[allow(dead_code)]
    #[error("not a purchase by this account")]
    NotPurchased,
    #[allow(dead_code)]
    #[error("app store purchases are not configured")]
    NotConfigured,
}

#[derive(Deserialize)]
struct JwsHeader {
    alg: String,
    x5c: Vec<String>,
}

/// Verify a compact JWS signed by the App Store and return its payload object.
///
/// `root_der` is the trust anchor `x5c[2]` must equal byte for byte:
/// [`apple_root_g3_der`] in production, a fixture root in tests.
// Reached only from tests until a route verifies a purchase.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn verify_jws(jws: &str, root_der: &[u8]) -> Result<Value, AppStoreError> {
    // A fourth segment would leave a '.' in the payload segment, which
    // base64url refuses.
    let (signing_input, signature_b64) = jws.rsplit_once('.').ok_or(AppStoreError::Malformed)?;
    let (header_b64, payload_b64) = signing_input
        .split_once('.')
        .ok_or(AppStoreError::Malformed)?;

    let header: JwsHeader = decode_segment(header_b64)?;
    if header.alg != "ES256" {
        return Err(AppStoreError::Malformed);
    }
    let payload: Map<String, Value> = decode_segment(payload_b64)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| AppStoreError::Malformed)?;
    if signature.len() != 64 {
        return Err(AppStoreError::Malformed);
    }

    let leaf_key = verify_chain_at(&header.x5c, root_der, signed_at(&payload)?)?;

    let signature =
        P256Signature::from_slice(&signature).map_err(|_| AppStoreError::InvalidSignature)?;
    leaf_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| AppStoreError::InvalidSignature)?;

    Ok(Value::Object(payload))
}

fn decode_segment<T: DeserializeOwned>(segment: &str) -> Result<T, AppStoreError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| AppStoreError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| AppStoreError::Malformed)
}

/// The instant the chain is judged at: the payload's `signedDate`
/// (milliseconds since the epoch), or now when it has none.
fn signed_at(payload: &Map<String, Value>) -> Result<ASN1Time, AppStoreError> {
    let Some(signed_date) = payload.get("signedDate") else {
        return Ok(ASN1Time::now());
    };
    let millis = signed_date.as_i64().ok_or(AppStoreError::Malformed)?;
    ASN1Time::from_timestamp(millis.div_euclid(1000)).map_err(|_| AppStoreError::Malformed)
}

/// Check `x5c` is leaf, intermediate and `root_der`, each link signed by the
/// next and each certificate valid at `at`, and return the leaf's key.
fn verify_chain_at(
    x5c: &[String],
    root_der: &[u8],
    at: ASN1Time,
) -> Result<P256VerifyingKey, AppStoreError> {
    let [leaf_b64, intermediate_b64, root_b64] = x5c else {
        return Err(AppStoreError::InvalidChain);
    };
    let leaf_der = decode_certificate(leaf_b64)?;
    let intermediate_der = decode_certificate(intermediate_b64)?;
    if decode_certificate(root_b64)? != root_der {
        return Err(AppStoreError::InvalidChain);
    }

    let leaf = parse_certificate(&leaf_der)?;
    let intermediate = parse_certificate(&intermediate_der)?;
    let root = parse_certificate(root_der)?;

    for cert in [&leaf, &intermediate, &root] {
        if !cert.validity().is_valid_at(at) {
            return Err(AppStoreError::InvalidChain);
        }
    }

    for (child, issuer) in [(&leaf, &intermediate), (&intermediate, &root)] {
        if child.issuer() != issuer.subject() {
            return Err(AppStoreError::InvalidChain);
        }
        child
            .verify_signature(Some(issuer.public_key()))
            .map_err(|_| AppStoreError::InvalidChain)?;
    }

    require_extension(&leaf, &RECEIPT_SIGNING_OID)?;
    require_extension(&intermediate, &WWDR_INTERMEDIATE_OID)?;

    P256VerifyingKey::from_public_key_der(leaf.public_key().raw)
        .map_err(|_| AppStoreError::InvalidChain)
}

fn decode_certificate(b64: &str) -> Result<Vec<u8>, AppStoreError> {
    STANDARD.decode(b64).map_err(|_| AppStoreError::Malformed)
}

/// Parse one DER certificate, refusing trailing bytes.
fn parse_certificate(der: &[u8]) -> Result<X509Certificate<'_>, AppStoreError> {
    match X509Certificate::from_der(der) {
        Ok(([], cert)) => Ok(cert),
        _ => Err(AppStoreError::InvalidChain),
    }
}

fn require_extension(cert: &X509Certificate<'_>, oid: &[u64]) -> Result<(), AppStoreError> {
    let oid = x509_parser::der_parser::Oid::from(oid).map_err(|_| AppStoreError::InvalidChain)?;
    match cert.get_extension_unique(&oid) {
        Ok(Some(_)) => Ok(()),
        _ => Err(AppStoreError::InvalidChain),
    }
}
