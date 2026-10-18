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
//! [`decode_transaction`], [`decode_renewal_grace`] and [`decode_notification`]
//! turn verified payloads into typed values and apply the payload rules: the
//! bundle, the product, a direct purchase and an accepted environment.
//! Production always verifies against the pinned root; only test builds can
//! swap the trust anchor ([`AppStoreConfig::for_tests`]).
//!
//! Errors are unit variants with fixed messages, so nothing from a signed
//! payload can reach a log line or a response body through them.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ecdsa::signature::Verifier;
use log::{info, warn};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::sync::OnceLock;
use thiserror::Error;
use uuid::Uuid;
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
    #[error("signed for another app")]
    WrongApp,
    #[error("environment not accepted")]
    WrongEnvironment,
    #[error("not a direct purchase")]
    NotPurchased,
    // Produced by the routes when the feature is off.
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

// --------- Config ---------

/// The App Store environments a payload can be signed for that we accept.
/// `Xcode` and `LocalTesting` are never accepted: their payloads are unsigned.
/// Serialized as Apple spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Environment {
    Production,
    Sandbox,
}

impl Environment {
    fn from_apple(value: &str) -> Option<Self> {
        match value {
            "Production" => Some(Self::Production),
            "Sandbox" => Some(Self::Sandbox),
            _ => None,
        }
    }
}

/// App Store purchases, enabled by `APP_STORE_BUNDLE_ID`,
/// `APP_STORE_APP_APPLE_ID` and `APP_STORE_PUBLISH_PRODUCT_IDS`.
#[derive(Debug, Clone)]
pub struct AppStoreConfig {
    pub bundle_id: String,
    pub app_apple_id: i64,
    pub product_ids: HashSet<String>,
    pub environments: HashSet<Environment>,
    /// The trust anchor tests verify against instead of Apple's. It exists
    /// only in test builds, so no config can name another root in production.
    #[cfg(test)]
    root_der: Option<Vec<u8>>,
}

impl AppStoreConfig {
    /// Parse the four env values. `Ok(None)`: the feature is off (one of the
    /// first three is unset or empty). `Err`: it is set but unusable, which
    /// also leaves the feature off.
    pub(crate) fn parse(
        bundle_id: Option<&str>,
        app_apple_id: Option<&str>,
        product_ids: Option<&str>,
        environments: Option<&str>,
    ) -> Result<Option<Self>, &'static str> {
        fn present(v: Option<&str>) -> Option<&str> {
            v.map(str::trim).filter(|s| !s.is_empty())
        }
        let (Some(bundle_id), Some(app_apple_id), Some(product_ids)) = (
            present(bundle_id),
            present(app_apple_id),
            present(product_ids),
        ) else {
            return Ok(None);
        };
        let app_apple_id: i64 = app_apple_id
            .parse()
            .map_err(|_| "APP_STORE_APP_APPLE_ID is not an integer")?;
        let product_ids: HashSet<String> = product_ids
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        if product_ids.is_empty() {
            return Ok(None);
        }
        let environments = match present(environments) {
            None => HashSet::from([Environment::Production, Environment::Sandbox]),
            Some(list) => list
                .split(',')
                .map(|e| Environment::from_apple(e.trim()))
                .collect::<Option<HashSet<_>>>()
                .ok_or("APP_STORE_ENVIRONMENTS accepts only Production and Sandbox")?,
        };
        Ok(Some(Self {
            bundle_id: bundle_id.to_string(),
            app_apple_id,
            product_ids,
            environments,
            #[cfg(test)]
            root_der: None,
        }))
    }

    /// Read the env vars and log, once, which state the feature is in.
    pub fn from_env() -> Option<Self> {
        let var = |name: &str| std::env::var(name).ok();
        let (bundle, app_id) = (var("APP_STORE_BUNDLE_ID"), var("APP_STORE_APP_APPLE_ID"));
        let (products, envs) = (
            var("APP_STORE_PUBLISH_PRODUCT_IDS"),
            var("APP_STORE_ENVIRONMENTS"),
        );
        match Self::parse(
            bundle.as_deref(),
            app_id.as_deref(),
            products.as_deref(),
            envs.as_deref(),
        ) {
            Ok(Some(cfg)) => {
                info!(
                    "App Store purchases ENABLED: bundle_id={} app_apple_id={} products={} \
                     environments={}",
                    cfg.bundle_id,
                    cfg.app_apple_id,
                    cfg.product_ids.len(),
                    cfg.environments.len()
                );
                Some(cfg)
            }
            Ok(None) => {
                info!(
                    "App Store purchases DISABLED: APP_STORE_BUNDLE_ID / APP_STORE_APP_APPLE_ID / \
                     APP_STORE_PUBLISH_PRODUCT_IDS not all set"
                );
                None
            }
            Err(reason) => {
                warn!("App Store purchases DISABLED: {reason}");
                None
            }
        }
    }

    /// A config for the production app, verifying against `root_der` instead
    /// of Apple's root.
    #[cfg(test)]
    pub(crate) fn for_tests(root_der: Vec<u8>) -> Self {
        Self {
            bundle_id: "com.arkavo.ArkavoCreator".to_string(),
            app_apple_id: 6_738_845_556,
            product_ids: HashSet::from(["com.arkavo.ArkavoCreator.membership.monthly".to_string()]),
            environments: HashSet::from([Environment::Production, Environment::Sandbox]),
            root_der: Some(root_der),
        }
    }

    #[cfg(not(test))]
    fn root_der(&self) -> &[u8] {
        apple_root_g3_der()
    }

    #[cfg(test)]
    fn root_der(&self) -> &[u8] {
        match &self.root_der {
            Some(der) => der,
            None => apple_root_g3_der(),
        }
    }
}

// --------- Decoding ---------

/// A purchase whose JWS verified and passed the payload rules. Dates are unix
/// seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTransaction {
    pub original_transaction_id: String,
    pub product_id: String,
    pub environment: Environment,
    pub app_account_token: Option<Uuid>,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub signed_at: i64,
}

/// A Server Notification V2 whose JWS, and nested JWS, verified. The type is
/// for logging; the state comes from the transaction and renewal info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNotification {
    pub notification_type: String,
    pub transaction: Option<VerifiedTransaction>,
    pub grace_expires_at: Option<i64>,
}

/// `Xcode` and `LocalTesting` payloads are unsigned, so they are refused
/// before any verification is attempted. The environment read here is not yet
/// trusted; it only ever turns a payload away.
fn refuse_unsigned_environment(unverified: Option<&str>) -> Result<(), AppStoreError> {
    match unverified {
        Some("Xcode" | "LocalTesting") => Err(AppStoreError::WrongEnvironment),
        _ => Ok(()),
    }
}

/// The payload object of a compact JWS, without verifying anything.
fn peek_payload(jws: &str) -> Result<Map<String, Value>, AppStoreError> {
    let payload_b64 = jws.split('.').nth(1).ok_or(AppStoreError::Malformed)?;
    decode_segment(payload_b64)
}

/// Verify `jws`, turning away unsigned environments first.
fn verify_signed(cfg: &AppStoreConfig, jws: &str) -> Result<Map<String, Value>, AppStoreError> {
    let unverified = peek_payload(jws)?;
    // Transactions and renewal info state it at the top; a notification in
    // `data`.
    let environment = |object: &Map<String, Value>| {
        object
            .get("environment")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    refuse_unsigned_environment(environment(&unverified).as_deref())?;
    if let Some(data) = unverified.get("data").and_then(Value::as_object) {
        refuse_unsigned_environment(environment(data).as_deref())?;
    }
    match verify_jws(jws, cfg.root_der())? {
        Value::Object(payload) => Ok(payload),
        _ => Err(AppStoreError::Malformed),
    }
}

fn accepted_environment(cfg: &AppStoreConfig, value: &str) -> Result<Environment, AppStoreError> {
    Environment::from_apple(value)
        .filter(|env| cfg.environments.contains(env))
        .ok_or(AppStoreError::WrongEnvironment)
}

fn string_field<'a>(payload: &'a Map<String, Value>, key: &str) -> Result<&'a str, AppStoreError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .ok_or(AppStoreError::Malformed)
}

/// An Apple date (milliseconds) as unix seconds. `None` when absent or null.
fn seconds_field(payload: &Map<String, Value>, key: &str) -> Result<Option<i64>, AppStoreError> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .map(|ms| Some(ms.div_euclid(1000)))
            .ok_or(AppStoreError::Malformed),
    }
}

fn required_seconds(payload: &Map<String, Value>, key: &str) -> Result<i64, AppStoreError> {
    seconds_field(payload, key)?.ok_or(AppStoreError::Malformed)
}

/// Verify a signed transaction and apply the bundle, environment, product and
/// ownership rules.
// Reached only from tests until a route verifies a purchase.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn decode_transaction(
    cfg: &AppStoreConfig,
    jws: &str,
) -> Result<VerifiedTransaction, AppStoreError> {
    let payload = verify_signed(cfg, jws)?;

    if string_field(&payload, "bundleId")? != cfg.bundle_id {
        return Err(AppStoreError::WrongApp);
    }
    let environment = accepted_environment(cfg, string_field(&payload, "environment")?)?;
    let product_id = string_field(&payload, "productId")?;
    if !cfg.product_ids.contains(product_id) {
        return Err(AppStoreError::WrongApp);
    }
    if payload.get("inAppOwnershipType").and_then(Value::as_str) != Some("PURCHASED") {
        return Err(AppStoreError::NotPurchased);
    }
    let app_account_token = match payload.get("appAccountToken") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            v.as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or(AppStoreError::Malformed)?,
        ),
    };

    Ok(VerifiedTransaction {
        original_transaction_id: string_field(&payload, "originalTransactionId")?.to_string(),
        product_id: product_id.to_string(),
        environment,
        app_account_token,
        expires_at: required_seconds(&payload, "expiresDate")?,
        revoked_at: seconds_field(&payload, "revocationDate")?,
        signed_at: required_seconds(&payload, "signedDate")?,
    })
}

/// Verify signed renewal info and return its `gracePeriodExpiresDate`.
// Reached only from tests until a route verifies a purchase.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn decode_renewal_grace(
    cfg: &AppStoreConfig,
    jws: &str,
) -> Result<Option<i64>, AppStoreError> {
    let payload = verify_signed(cfg, jws)?;
    // The signature is already trusted; the environment is checked when the
    // payload states one.
    if let Some(environment) = payload.get("environment") {
        accepted_environment(cfg, environment.as_str().ok_or(AppStoreError::Malformed)?)?;
    }
    seconds_field(&payload, "gracePeriodExpiresDate")
}

/// Verify a Server Notification V2 body and, when it carries them, the nested
/// transaction and renewal info.
// Reached only from tests until a route verifies a purchase.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn decode_notification(
    cfg: &AppStoreConfig,
    signed_payload: &str,
) -> Result<VerifiedNotification, AppStoreError> {
    let payload = verify_signed(cfg, signed_payload)?;
    let notification_type = string_field(&payload, "notificationType")?.to_string();
    let data = payload
        .get("data")
        .and_then(Value::as_object)
        .ok_or(AppStoreError::Malformed)?;

    if string_field(data, "bundleId")? != cfg.bundle_id {
        return Err(AppStoreError::WrongApp);
    }
    let environment = accepted_environment(cfg, string_field(data, "environment")?)?;
    if environment == Environment::Production
        && data.get("appAppleId").and_then(Value::as_i64) != Some(cfg.app_apple_id)
    {
        return Err(AppStoreError::WrongApp);
    }

    let transaction = data
        .get("signedTransactionInfo")
        .map(|v| decode_transaction(cfg, v.as_str().ok_or(AppStoreError::Malformed)?))
        .transpose()?;
    let grace_expires_at = data
        .get("signedRenewalInfo")
        .map(|v| decode_renewal_grace(cfg, v.as_str().ok_or(AppStoreError::Malformed)?))
        .transpose()?
        .flatten();

    Ok(VerifiedNotification {
        notification_type,
        transaction,
        grace_expires_at,
    })
}
