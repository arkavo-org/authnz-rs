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

use crate::AppState;
use crate::constants::{ENTITLEMENT_CREATOR_PUBLISH, ENTITLEMENT_ONLINE_PLAY};
use crate::db::{
    AppStoreRecord, DynamoDBError, DynamoDBStore, GraceUpdate, LinkOutcome, StateOutcome,
};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ecdsa::signature::Verifier;
use log::{error, info};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
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
    /// A product of this app that is not configured to grant anything.
    /// The client route answers it as it does `WrongApp`; the notification
    /// route acknowledges it (the notification never changes, so a 4xx would
    /// only make Apple retry it).
    #[error("product not configured")]
    UnknownProduct,
    #[error("environment not accepted")]
    WrongEnvironment,
    #[error("not a direct purchase")]
    NotPurchased,
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
    fn as_str(self) -> &'static str {
        match self {
            Self::Production => "Production",
            Self::Sandbox => "Sandbox",
        }
    }

    fn from_apple(value: &str) -> Option<Self> {
        match value {
            "Production" => Some(Self::Production),
            "Sandbox" => Some(Self::Sandbox),
            _ => None,
        }
    }
}

/// The entitlement a product grants. A product grants exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Grant {
    /// Creator publishing ([`ENTITLEMENT_CREATOR_PUBLISH`]).
    Publish,
    /// Play over the operator's network ([`ENTITLEMENT_ONLINE_PLAY`]).
    OnlinePlay,
}

impl Grant {
    /// The entitlement's attribute FQN.
    pub fn fqn(self) -> &'static str {
        match self {
            Self::Publish => ENTITLEMENT_CREATOR_PUBLISH,
            Self::OnlinePlay => ENTITLEMENT_ONLINE_PLAY,
        }
    }
}

/// One app whose App Store purchases are accepted.
#[derive(Debug, Clone)]
pub struct AppStoreApp {
    pub bundle_id: String,
    pub app_apple_id: i64,
    /// Each configured product and the one entitlement it grants.
    pub products: HashMap<String, Grant>,
    pub environments: HashSet<Environment>,
}

/// App Store purchases. The first app is configured by `APP_STORE_BUNDLE_ID`,
/// `APP_STORE_APP_APPLE_ID` and its product lists; further apps by the same
/// names with a tag (`APP_STORE_<TAG>_BUNDLE_ID`, …).
///
/// A bundle id and a product id each appear in at most one app, so a stored
/// record's product names its app and its entitlement.
#[derive(Debug, Clone)]
pub struct AppStoreConfig {
    pub apps: Vec<AppStoreApp>,
    /// The trust anchor tests verify against instead of Apple's. It exists
    /// only in test builds, so no config can name another root in production.
    #[cfg(test)]
    root_der: Option<Vec<u8>>,
}

fn present(v: Option<&str>) -> Option<&str> {
    v.map(str::trim).filter(|s| !s.is_empty())
}

fn id_list(v: Option<&str>) -> Vec<String> {
    v.unwrap_or_default()
        .split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

impl AppStoreApp {
    /// Parse one app's values. `Ok(None)`: not configured (the bundle id, the
    /// Apple ID or every product is missing). `Err`: set but unusable.
    fn parse(
        bundle_id: Option<&str>,
        app_apple_id: Option<&str>,
        publish_products: Option<&str>,
        online_play_products: Option<&str>,
        environments: Option<&str>,
    ) -> Result<Option<Self>, &'static str> {
        let (Some(bundle_id), Some(app_apple_id)) = (present(bundle_id), present(app_apple_id))
        else {
            return Ok(None);
        };
        let mut products = HashMap::new();
        for (list, grant) in [
            (publish_products, Grant::Publish),
            (online_play_products, Grant::OnlinePlay),
        ] {
            for product in id_list(list) {
                if products.insert(product, grant).is_some_and(|g| g != grant) {
                    return Err("a product is listed for two entitlements");
                }
            }
        }
        if products.is_empty() {
            return Ok(None);
        }
        let app_apple_id: i64 = app_apple_id
            .parse()
            .map_err(|_| "APP_STORE_APP_APPLE_ID is not an integer")?;
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
            products,
            environments,
        }))
    }
}

/// The variable `suffix` of the app tagged `tag` (`None`: the first app).
fn app_var(tag: Option<&str>, suffix: &str) -> String {
    match tag {
        Some(tag) => format!("APP_STORE_{tag}_{suffix}"),
        None => format!("APP_STORE_{suffix}"),
    }
}

impl AppStoreConfig {
    /// Parse the first app's values, as before tagged apps existed. `Ok(None)`:
    /// the feature is off (one of the first three is unset or empty). `Err`:
    /// it is set but unusable, which also leaves the feature off.
    #[cfg(test)]
    pub(crate) fn parse(
        bundle_id: Option<&str>,
        app_apple_id: Option<&str>,
        product_ids: Option<&str>,
        environments: Option<&str>,
    ) -> Result<Option<Self>, &'static str> {
        let app = AppStoreApp::parse(bundle_id, app_apple_id, product_ids, None, environments)?;
        Ok(app.map(|app| Self {
            apps: vec![app],
            root_der: None,
        }))
    }

    /// Parse every app from `vars` (the environment). The first app is the
    /// untagged one; tagged apps follow in tag order. Each returned message
    /// names an app that was left out and why. `None`: no app is usable, so
    /// the feature is off.
    ///
    /// A tagged app never takes the first app down with it: an operator's
    /// mistake in one app's variables must not end another app's
    /// memberships.
    pub(crate) fn parse_vars(vars: &HashMap<String, String>) -> (Option<Self>, Vec<String>) {
        let mut tags: Vec<&str> = vars
            .keys()
            .filter_map(|name| {
                name.strip_prefix("APP_STORE_")?
                    .strip_suffix("_BUNDLE_ID")
                    .filter(|tag| !tag.is_empty())
            })
            .collect();
        tags.sort_unstable();

        let mut apps: Vec<AppStoreApp> = Vec::new();
        let mut skipped = Vec::new();
        for tag in std::iter::once(None).chain(tags.into_iter().map(Some)) {
            let get = |suffix: &str| vars.get(&app_var(tag, suffix)).map(String::as_str);
            let name = app_var(tag, "BUNDLE_ID");
            let app = match AppStoreApp::parse(
                get("BUNDLE_ID"),
                get("APP_APPLE_ID"),
                get("PUBLISH_PRODUCT_IDS"),
                get("ONLINE_PLAY_PRODUCT_IDS"),
                get("ENVIRONMENTS"),
            ) {
                Ok(Some(app)) => app,
                // The first app unset is the feature's ordinary off state.
                Ok(None) if tag.is_none() => continue,
                Ok(None) => {
                    skipped.push(format!(
                        "{name}: the app needs its Apple ID and at least one product"
                    ));
                    continue;
                }
                Err(reason) => {
                    skipped.push(format!("{name}: {reason}"));
                    continue;
                }
            };
            if apps.iter().any(|a| a.bundle_id == app.bundle_id) {
                skipped.push(format!("{name}: the bundle id is another app's"));
                continue;
            }
            if apps
                .iter()
                .any(|a| app.products.keys().any(|p| a.products.contains_key(p)))
            {
                skipped.push(format!("{name}: a product id is another app's"));
                continue;
            }
            apps.push(app);
        }
        let cfg = (!apps.is_empty()).then_some(Self {
            apps,
            #[cfg(test)]
            root_der: None,
        });
        (cfg, skipped)
    }

    /// Read the env vars and log, once, which state the feature is in.
    pub fn from_env() -> Option<Self> {
        let vars: HashMap<String, String> = std::env::vars()
            .filter(|(name, _)| name.starts_with("APP_STORE_"))
            .collect();
        let (cfg, skipped) = Self::parse_vars(&vars);
        for reason in &skipped {
            error!("App Store app left out: {reason}");
        }
        match &cfg {
            Some(cfg) => {
                for app in &cfg.apps {
                    let count = |grant| app.products.values().filter(|g| **g == grant).count();
                    info!(
                        "App Store purchases ENABLED: bundle_id={} app_apple_id={} \
                         publish_products={} online_play_products={} environments={}",
                        app.bundle_id,
                        app.app_apple_id,
                        count(Grant::Publish),
                        count(Grant::OnlinePlay),
                        app.environments.len()
                    );
                }
            }
            None => info!(
                "App Store purchases DISABLED: no app has its bundle id, Apple ID and a \
                 product list set (APP_STORE_BUNDLE_ID / APP_STORE_APP_APPLE_ID / \
                 APP_STORE_PUBLISH_PRODUCT_IDS)"
            ),
        }
        cfg
    }

    /// A config for the production app, verifying against `root_der` instead
    /// of Apple's root.
    #[cfg(test)]
    pub(crate) fn for_tests(root_der: Vec<u8>) -> Self {
        Self {
            apps: vec![AppStoreApp {
                bundle_id: "com.arkavo.ArkavoCreator".to_string(),
                app_apple_id: 6_738_845_556,
                products: HashMap::from([(
                    "com.arkavo.ArkavoCreator.membership.monthly".to_string(),
                    Grant::Publish,
                )]),
                environments: HashSet::from([Environment::Production, Environment::Sandbox]),
            }],
            root_der: Some(root_der),
        }
    }

    /// The app a signed payload's `bundleId` names.
    fn app(&self, bundle_id: &str) -> Result<&AppStoreApp, AppStoreError> {
        self.apps
            .iter()
            .find(|app| app.bundle_id == bundle_id)
            .ok_or(AppStoreError::WrongApp)
    }

    /// The entitlement a stored record counts toward: its product's, while
    /// the product is configured and its app accepts the record's
    /// environment. A product id belongs to one app.
    pub(crate) fn grant_of(&self, record: &AppStoreRecord) -> Option<Grant> {
        self.apps.iter().find_map(|app| {
            let grant = app.products.get(&record.product_id)?;
            app.environments
                .contains(&record.environment)
                .then_some(*grant)
        })
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
    /// This transaction (one billing period) of the subscription.
    pub transaction_id: String,
    pub product_id: String,
    /// The one entitlement the product grants.
    pub grant: Grant,
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
    /// The environment `data` states; `None` for a payload without `data`
    /// (a summary).
    pub environment: Option<Environment>,
    pub transaction: Option<VerifiedTransaction>,
    /// What the renewal info says about the billing-retry grace: `Set` (to a
    /// date, or cleared) when the notification carries renewal info, `Keep`
    /// when it does not.
    pub grace: GraceUpdate,
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

fn accepted_environment(app: &AppStoreApp, value: &str) -> Result<Environment, AppStoreError> {
    Environment::from_apple(value)
        .filter(|env| app.environments.contains(env))
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
pub(crate) fn decode_transaction(
    cfg: &AppStoreConfig,
    jws: &str,
) -> Result<VerifiedTransaction, AppStoreError> {
    let payload = verify_signed(cfg, jws)?;

    // The product must be one of the transaction's own app: another
    // configured app's product id under this bundle grants nothing.
    let app = cfg.app(string_field(&payload, "bundleId")?)?;
    let environment = accepted_environment(app, string_field(&payload, "environment")?)?;
    let product_id = string_field(&payload, "productId")?;
    let grant = *app
        .products
        .get(product_id)
        .ok_or(AppStoreError::UnknownProduct)?;
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
        transaction_id: string_field(&payload, "transactionId")?.to_string(),
        product_id: product_id.to_string(),
        grant,
        environment,
        app_account_token,
        expires_at: required_seconds(&payload, "expiresDate")?,
        revoked_at: seconds_field(&payload, "revocationDate")?,
        signed_at: required_seconds(&payload, "signedDate")?,
    })
}

/// Signed renewal info, verified: what a notification needs from it (the
/// subscription it belongs to, its environment when it states one, and the
/// billing-retry grace).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RenewalInfo {
    pub original_transaction_id: Option<String>,
    pub environment: Option<Environment>,
    pub grace_expires_at: Option<i64>,
}

pub(crate) fn decode_renewal_info(
    cfg: &AppStoreConfig,
    jws: &str,
) -> Result<RenewalInfo, AppStoreError> {
    let payload = verify_signed(cfg, jws)?;
    // The signature is already trusted; the environment is checked when the
    // payload states one. Renewal info names no app: a notification holds it
    // to its transaction's environment, which that app accepted.
    let environment = payload
        .get("environment")
        .map(|v| {
            let value = v.as_str().ok_or(AppStoreError::Malformed)?;
            Environment::from_apple(value)
                .filter(|env| cfg.apps.iter().any(|app| app.environments.contains(env)))
                .ok_or(AppStoreError::WrongEnvironment)
        })
        .transpose()?;
    let original_transaction_id = payload
        .get("originalTransactionId")
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or(AppStoreError::Malformed)
        })
        .transpose()?;
    Ok(RenewalInfo {
        original_transaction_id,
        environment,
        grace_expires_at: seconds_field(&payload, "gracePeriodExpiresDate")?,
    })
}

/// Verify a Server Notification V2 body and, when it carries them, the nested
/// transaction and renewal info.
///
/// A verified payload with no `data` (a bulk renewal-date extension's
/// `summary`, an `externalPurchaseToken`) decodes without a transaction, like
/// `TEST`. The nested
/// transaction must state the environment `data` does, and the renewal info
/// must belong to the same subscription (and environment, when it states
/// one): the outer label is what decides whether `appAppleId` is checked, so
/// it must not be able to wrap a transaction of another environment.
pub(crate) fn decode_notification(
    cfg: &AppStoreConfig,
    signed_payload: &str,
) -> Result<VerifiedNotification, AppStoreError> {
    let payload = verify_signed(cfg, signed_payload)?;
    let notification_type = string_field(&payload, "notificationType")?.to_string();
    let Some(data) = payload.get("data").and_then(Value::as_object) else {
        // A verified payload without `data` (a `summary`, an
        // `externalPurchaseToken`, whatever Apple adds) has no transaction to
        // apply and is acknowledged. Where it names a bundle, it must be ours.
        for key in ["summary", "externalPurchaseToken"] {
            if let Some(bundle) = payload
                .get(key)
                .and_then(Value::as_object)
                .and_then(|o| o.get("bundleId"))
                && !bundle.as_str().is_some_and(|b| cfg.app(b).is_ok())
            {
                return Err(AppStoreError::WrongApp);
            }
        }
        return Ok(VerifiedNotification {
            notification_type,
            environment: None,
            transaction: None,
            grace: GraceUpdate::Keep,
        });
    };

    let app = cfg.app(string_field(data, "bundleId")?)?;
    let environment = accepted_environment(app, string_field(data, "environment")?)?;
    if environment == Environment::Production
        && data.get("appAppleId").and_then(Value::as_i64) != Some(app.app_apple_id)
    {
        return Err(AppStoreError::WrongApp);
    }

    let transaction = data
        .get("signedTransactionInfo")
        .map(|v| decode_transaction(cfg, v.as_str().ok_or(AppStoreError::Malformed)?))
        .transpose()?;
    if let Some(tx) = &transaction
        && tx.environment != environment
    {
        return Err(AppStoreError::WrongEnvironment);
    }
    // `data` decided which app's Apple ID was checked, so the nested
    // transaction must be that app's.
    if let Some(tx) = &transaction
        && !app.products.contains_key(&tx.product_id)
    {
        return Err(AppStoreError::WrongApp);
    }
    // Renewal info only qualifies a transaction; without one there is
    // nothing to apply it to. Only renewal info speaks about the grace
    // period, so a notification without it leaves a stored grace alone.
    let grace = match (&transaction, data.get("signedRenewalInfo")) {
        (Some(tx), Some(renewal)) => {
            let renewal =
                decode_renewal_info(cfg, renewal.as_str().ok_or(AppStoreError::Malformed)?)?;
            if renewal.original_transaction_id.as_deref()
                != Some(tx.original_transaction_id.as_str())
            {
                return Err(AppStoreError::Malformed);
            }
            if renewal.environment.is_some_and(|e| e != tx.environment) {
                return Err(AppStoreError::WrongEnvironment);
            }
            GraceUpdate::Set(renewal.grace_expires_at)
        }
        _ => GraceUpdate::Keep,
    };

    Ok(VerifiedNotification {
        notification_type,
        environment: Some(environment),
        transaction,
        grace,
    })
}

// --------- The Active rule ---------

/// Whether an account's stored records grant `grant`.
///
/// A record counts iff its product is configured for `grant` and its app
/// accepts its environment ([`AppStoreConfig::grant_of`]), it has no
/// `revoked_at`, and `now` is before the later of its `expires_at` and its
/// `grace_expires_at` (a billing-retry grace the notifications recorded).
/// One such record is enough, and a record never counts toward another
/// entitlement than its product's. Times are unix seconds.
pub(crate) fn app_store_active(
    cfg: &AppStoreConfig,
    grant: Grant,
    records: &[AppStoreRecord],
    now: i64,
) -> bool {
    records.iter().any(|r| {
        cfg.grant_of(r) == Some(grant)
            && r.revoked_at.is_none()
            && now < r.expires_at.max(r.grace_expires_at.unwrap_or(i64::MIN))
    })
}

// --------- The link ---------

/// How a subscription stands after [`bind_or_move`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Binding {
    /// Newly bound to the account.
    Bound,
    /// Already the account's.
    AlreadyYours,
    /// Moved to the account from another one.
    Moved,
    /// Bound to this other account, which keeps it.
    Elsewhere(Uuid),
}

/// Bind `tx`'s subscription to `to`, moving its link from the current owner
/// when the move rule allows it, which is when either holds:
///
/// - (a) the owner is not live (deleted, not yet swept, or unknown);
/// - (b) the transaction is Sandbox and its `appAccountToken` names `to`.
///   App Review reuses Sandbox Apple IDs with fresh accounts, and a
///   resubscription keeps its `originalTransactionId`.
///
/// A Production subscription of another live account stays where it is. The
/// move is conditional on the owner read, so a race with another bind, move
/// or the deletion sweep is re-evaluated (a few times at most); the old
/// owner's row is never touched (its Sandbox entry is left to expire).
async fn bind_or_move(
    store: &DynamoDBStore,
    tx: &VerifiedTransaction,
    to: &Uuid,
) -> Result<Binding, DynamoDBError> {
    let otid = &tx.original_transaction_id;
    let sandbox_for_to =
        tx.environment == Environment::Sandbox && tx.app_account_token == Some(*to);
    for _ in 0..3 {
        match store.bind_app_store_link(otid, to).await? {
            LinkOutcome::Bound => return Ok(Binding::Bound),
            LinkOutcome::AlreadyYours => return Ok(Binding::AlreadyYours),
            LinkOutcome::BoundElsewhere => {}
        }
        // Gone again (swept), or now `to`'s: the next bind settles it.
        let Some(owner) = store.app_store_link_owner(otid).await? else {
            continue;
        };
        if owner == *to {
            continue;
        }
        if !sandbox_for_to && store.is_account_live(&owner).await? {
            return Ok(Binding::Elsewhere(owner));
        }
        if store.move_app_store_link(otid, &owner, to).await? {
            return Ok(Binding::Moved);
        }
    }
    Err(DynamoDBError::Internal(
        "app store link changed on every attempt".into(),
    ))
}

// --------- POST /app-store/transactions ---------

const BODY_ANOTHER_ACCOUNT: &str = "transaction belongs to another account";
const BODY_ANOTHER_SUBSCRIPTION: &str = "subscription belongs to another account";
const BODY_INVALID: &str = "invalid transaction";
const BODY_UNAVAILABLE: &str = "app store purchases unavailable";

#[derive(Deserialize)]
struct TransactionRequest {
    signed_transaction: String,
}

#[derive(Serialize)]
struct TransactionResponse {
    active: bool,
    expires_at: i64,
    environment: Environment,
    /// The entitlement the purchased product grants (its attribute FQN).
    entitlement: &'static str,
    token_can_publish: bool,
}

/// What the request's one log line says. Only the subscription's
/// `original_transaction_id`, its environment and the outcome: never a JWS, a
/// token or an `appAccountToken`.
struct Trace {
    outcome: &'static str,
    original_transaction_id: Option<String>,
    environment: Option<Environment>,
}

fn refuse(status: StatusCode, body: &'static str) -> Response {
    (status, body).into_response()
}

/// A storage failure: logged here, a bare 500 on the wire.
fn internal(what: &str, e: &DynamoDBError) -> Response {
    error!("app store transaction: {what} failed: {e}");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

/// `POST /app-store/transactions`: bind the purchased subscription in
/// `signed_transaction` to the caller and report its state.
///
/// Order: the feature is configured, the caller authenticates (and still
/// exists), the JWS verifies, the transaction names an account (`appAccountToken`),
/// the link is bound (or moved to the caller, see [`bind_or_move`]), the
/// state is written, and the answer is read back from the stored record, so a
/// grace period a notification recorded counts and a stale or past-period
/// post answers with what is stored.
pub(crate) async fn transactions_handler(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut trace = Trace {
        outcome: "refused",
        original_transaction_id: None,
        environment: None,
    };
    let response = post_transaction(&app_state, &headers, &body, &mut trace).await;
    info!(
        "app_store transaction outcome={} otid={} env={}",
        trace.outcome,
        trace.original_transaction_id.as_deref().unwrap_or("-"),
        trace.environment.map_or("-", Environment::as_str),
    );
    response
}

async fn post_transaction(
    app_state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    trace: &mut Trace,
) -> Response {
    let Some(cfg) = app_state.app_store.as_ref() else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, BODY_UNAVAILABLE);
    };
    let caller = match crate::authn::authenticated_live_account(app_state, headers).await {
        Ok(account) => account,
        Err(status) => return status.into_response(),
    };

    // Parsed here, after authentication, so a caller without a token learns
    // nothing about what the body should look like.
    let Ok(TransactionRequest { signed_transaction }) = serde_json::from_slice(body) else {
        return refuse(StatusCode::UNPROCESSABLE_ENTITY, BODY_INVALID);
    };
    let Ok(tx) = decode_transaction(cfg, &signed_transaction) else {
        return refuse(StatusCode::UNPROCESSABLE_ENTITY, BODY_INVALID);
    };
    trace.original_transaction_id = Some(tx.original_transaction_id.clone());
    trace.environment = Some(tx.environment);

    // The transaction must name the account it was bought for.
    let Some(named) = tx.app_account_token else {
        return refuse(StatusCode::UNPROCESSABLE_ENTITY, BODY_INVALID);
    };
    if named != caller.user_id {
        // Another live account's purchase is not the caller's to claim. A
        // deleted or unknown account's still-billing subscription is.
        match app_state.db_store.is_account_live(&named).await {
            Ok(true) => return refuse(StatusCode::FORBIDDEN, BODY_ANOTHER_ACCOUNT),
            Ok(false) => {}
            Err(e) => return internal("account lookup", &e),
        }
    }

    // Always the link first: the state lands on the caller's row only once the
    // subscription is the caller's.
    let binding = match bind_or_move(&app_state.db_store, &tx, &caller.user_id).await {
        Ok(Binding::Elsewhere(_)) => {
            trace.outcome = "elsewhere";
            return refuse(StatusCode::CONFLICT, BODY_ANOTHER_SUBSCRIPTION);
        }
        Ok(binding) => binding,
        Err(DynamoDBError::AccountGone) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => return internal("link", &e),
    };

    let record = AppStoreRecord {
        original_transaction_id: tx.original_transaction_id.clone(),
        transaction_id: Some(tx.transaction_id),
        product_id: tx.product_id,
        environment: tx.environment,
        expires_at: tx.expires_at,
        grace_expires_at: None,
        revoked_at: tx.revoked_at,
        last_signed_at: tx.signed_at,
    };
    match app_state
        .db_store
        .put_app_store_state(&caller.user_id, &record, GraceUpdate::Keep)
        .await
    {
        Ok(StateOutcome::Applied) => {
            trace.outcome = if binding == Binding::Moved {
                "moved"
            } else {
                "bound"
            };
        }
        Ok(StateOutcome::Stale) => trace.outcome = "stale",
        // Answered with the stored period, as a stale post is.
        Ok(StateOutcome::PastPeriod) => trace.outcome = "past_period",
        // A snapshot of another environment than the stored one.
        Ok(StateOutcome::OtherEnvironment) => {
            trace.outcome = "environment";
            return refuse(StatusCode::UNPROCESSABLE_ENTITY, BODY_INVALID);
        }
        Ok(StateOutcome::AccountGone) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(DynamoDBError::AccountGone) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => return internal("state write", &e),
    }

    // The stored record, not the posted one: it may be newer, and it holds
    // any grace a notification recorded.
    let stored = match app_state
        .db_store
        .get_publishing_state(&caller.user_id)
        .await
    {
        Ok(Some(state)) => state
            .app_store
            .into_iter()
            .find(|r| r.original_transaction_id == tx.original_transaction_id),
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => return internal("state read", &e),
    };
    let Some(stored) = stored else {
        error!("app store transaction: stored record unreadable after write");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    Json(TransactionResponse {
        active: app_store_active(
            cfg,
            tx.grant,
            std::slice::from_ref(&stored),
            chrono::Utc::now().timestamp(),
        ),
        expires_at: stored.expires_at,
        environment: stored.environment,
        entitlement: tx.grant.fqn(),
        token_can_publish: caller.token_can_publish,
    })
    .into_response()
}

// --------- POST /app-store/notifications ---------

#[derive(Deserialize)]
struct NotificationRequest {
    #[serde(rename = "signedPayload")]
    signed_payload: String,
}

/// What a notification's one log line says: the type Apple signed, the
/// subscription's `original_transaction_id`, its environment and the outcome.
/// Never a JWS, a token or an `appAccountToken`.
struct NotificationTrace {
    outcome: &'static str,
    notification_type: Option<String>,
    original_transaction_id: Option<String>,
    environment: Option<Environment>,
}

/// A notification type reduced to what Apple's names use, so nothing a payload
/// carries can shape a log line.
fn loggable_type(notification_type: &str) -> String {
    notification_type
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(48)
        .collect()
}

fn internal_notification(what: &str, e: &DynamoDBError) -> Response {
    error!("app store notification: {what} failed: {e}");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

/// `POST /app-store/notifications`: App Store Server Notifications V2. No
/// auth header; the signature is the only trust.
///
/// Answers 503 when the feature is off, 400 for a body without
/// `signedPayload` or a payload that does not verify or is not for this app
/// (Apple retries a non-2xx), 500 for a storage failure (so Apple retries
/// it), and 200 for every verified payload, applied or ignored.
pub(crate) async fn notifications_handler(
    Extension(app_state): Extension<AppState>,
    body: Bytes,
) -> Response {
    let mut trace = NotificationTrace {
        outcome: "refused",
        notification_type: None,
        original_transaction_id: None,
        environment: None,
    };
    let response = post_notification(&app_state, &body, &mut trace).await;
    info!(
        "app_store notification type={} otid={} env={} outcome={}",
        trace.notification_type.as_deref().unwrap_or("-"),
        trace.original_transaction_id.as_deref().unwrap_or("-"),
        trace.environment.map_or("-", Environment::as_str),
        trace.outcome,
    );
    response
}

async fn post_notification(
    app_state: &AppState,
    body: &[u8],
    trace: &mut NotificationTrace,
) -> Response {
    let Some(cfg) = app_state.app_store.as_ref() else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, BODY_UNAVAILABLE);
    };
    let Ok(NotificationRequest { signed_payload }) = serde_json::from_slice(body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let notification = match decode_notification(cfg, &signed_payload) {
        Ok(notification) => notification,
        // Ours, but not a product that grants membership: nothing to apply,
        // and a 4xx would only make Apple retry it.
        Err(AppStoreError::UnknownProduct) => {
            trace.outcome = "ignored=product";
            return StatusCode::OK.into_response();
        }
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    trace.notification_type = Some(loggable_type(&notification.notification_type));
    trace.environment = notification.environment;

    let Some(tx) = notification.transaction else {
        trace.outcome = "ignored=no_transaction";
        return StatusCode::OK.into_response();
    };
    trace.original_transaction_id = Some(tx.original_transaction_id.clone());
    trace.environment = Some(tx.environment);

    // The account the subscription belongs to, always settled before the
    // state is written: its link, or a link (new, or moved when the move rule
    // allows it) to the live account the purchase was made for.
    let store = &app_state.db_store;
    let linked = match store
        .app_store_link_owner(&tx.original_transaction_id)
        .await
    {
        Ok(linked) => linked,
        Err(e) => return internal_notification("link lookup", &e),
    };
    // The account the purchase names, when it is live and not already the
    // owner. Nothing is ever bound or moved to an account that is not live.
    let claimant = match tx.app_account_token {
        Some(named) if linked != Some(named) => match store.is_account_live(&named).await {
            Ok(true) => Some(named),
            Ok(false) => None,
            Err(e) => return internal_notification("account lookup", &e),
        },
        _ => None,
    };
    let mut link_outcome = None;
    let owner = match (claimant, linked) {
        (Some(named), _) => match bind_or_move(store, &tx, &named).await {
            Ok(Binding::Bound) => {
                link_outcome = Some("bound");
                named
            }
            Ok(Binding::Moved) => {
                link_outcome = Some("moved");
                named
            }
            Ok(Binding::AlreadyYours) => named,
            // A live owner keeps a Production subscription: follow its link.
            Ok(Binding::Elsewhere(owner)) => owner,
            Err(DynamoDBError::AccountGone) => {
                trace.outcome = "ignored=account_gone";
                return StatusCode::OK.into_response();
            }
            Err(e) => return internal_notification("link", &e),
        },
        (None, Some(owner)) => owner,
        // An unknown subscription is bound only to a live account the
        // purchase names; anything else is not ours to track.
        (None, None) => {
            trace.outcome = "ignored=unbound";
            return StatusCode::OK.into_response();
        }
    };

    let record = AppStoreRecord {
        original_transaction_id: tx.original_transaction_id,
        transaction_id: Some(tx.transaction_id),
        product_id: tx.product_id,
        environment: tx.environment,
        expires_at: tx.expires_at,
        grace_expires_at: match notification.grace {
            GraceUpdate::Set(grace) => grace,
            GraceUpdate::Keep => None,
        },
        revoked_at: tx.revoked_at,
        last_signed_at: tx.signed_at,
    };
    match store
        .put_app_store_state(&owner, &record, notification.grace)
        .await
    {
        Ok(StateOutcome::Applied) => trace.outcome = link_outcome.unwrap_or("applied"),
        Ok(StateOutcome::Stale) => trace.outcome = "stale",
        Ok(StateOutcome::PastPeriod) => trace.outcome = "ignored=past_period",
        Ok(StateOutcome::OtherEnvironment) => trace.outcome = "ignored=environment",
        Ok(StateOutcome::AccountGone) | Err(DynamoDBError::AccountGone) => {
            trace.outcome = "ignored=account_gone";
        }
        Err(e) => return internal_notification("state write", &e),
    }
    StatusCode::OK.into_response()
}
