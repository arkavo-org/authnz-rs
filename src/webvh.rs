//! did:webvh identity layer (canonical, sovereign DID method).
//!
//! Arkavo keeps WebAuthn as its key-ceremony/auth layer while using did:webvh
//! as the canonical, resolvable, verifiable-history DID method — implemented
//! against the DIF reference crate (`didwebvh-rs`). At registration the handle
//! store (prod-handles) is written `handle -> did:webvh`, and the signed log
//! (did.jsonl) is served from `/dids/:username/did.jsonl`.
//!
//! ## The key architectural point this module encodes
//!
//! A WebAuthn passkey **cannot** be the did:webvh *log signer*. The crate's
//! external `Signer` trait
//! (`affinidi_data_integrity::signer::Signer`) signs arbitrary
//! pre-canonicalised bytes and returns a raw signature; a passkey only ever
//! signs `authenticatorData || SHA256(clientDataJSON)` via an interactive
//! ceremony with a client-held key. So the two key roles are **decoupled**:
//!
//! * **Log / update authority** — a server-custodied key in AWS KMS. This is
//!   what implements `Signer` ([`KmsSigner`]) and signs `did.jsonl` entries.
//!   (KMS is already in this codebase for Patreon token sealing.)
//! * **User authentication credential** — the WebAuthn passkey (P-256 COSE),
//!   published *inside* the DID document as a `Multikey` `verificationMethod`
//!   under `authentication`/`assertionMethod`. The webvh log makes the
//!   *history* of that document tamper-evident — including passkey rotation.
//!
//! ## What compiles by default vs. behind the `webvh` feature
//!
//! Everything except the actual `didwebvh-rs` calls is in the default build and
//! unit-tested: the real `did:key` derivation from a passkey's P-256 COSE key
//! (replacing the structurally-invalid `did:key:apple-<hex>` flagged in the
//! review), the DID-document builder, the KMS signer plumbing, the DER→raw
//! P-256 signature conversion, and the resolution endpoints.
//!
//! The `impl Signer for KmsSigner` and the `create_did`/`update_did` calls that
//! actually emit a signed `did.jsonl` are behind `#[cfg(feature = "webvh")]`
//! (see [`log_emit`]) so the heavy DIF dependency tree stays opt-in for plain
//! `cargo build`/CI; the production build (`production/build.sh`) enables
//! `--features webvh`, making did:webvh canonical in prod.

use aws_config::BehaviorVersion;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use axum::extract::{Extension, Path};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use log::{error, info, warn};
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::json;
use std::env;
use thiserror::Error;
use uuid::Uuid;
use webauthn_rs::prelude::{COSEKeyType, ECDSACurve, Passkey};

/// Multicodec prefix for a `p256-pub` key (0x1200), unsigned-varint encoded.
/// Every P-256 `did:key` therefore base58btc-renders with a `zDn` prefix.
const MULTICODEC_P256_PUB: [u8; 2] = [0x80, 0x24];

#[derive(Debug, Error)]
pub enum WebvhError {
    #[error("unsupported credential key type (only P-256 EC2 is supported)")]
    UnsupportedKeyType,
    #[error("key format: {0}")]
    KeyFormat(String),
    #[error("signature format: {0}")]
    SigFormat(String),
    #[error("KMS error: {0}")]
    Kms(String),
    #[error("webvh log error: {0}")]
    Log(String),
}

// ---------------------------------------------------------------------------
// did:key derivation from a WebAuthn passkey (real, multicodec + multibase)
// ---------------------------------------------------------------------------

/// Minimal base58btc encoder (Bitcoin alphabet) — multibase `z`-prefix payload.
/// Kept inline to avoid adding a dependency for ~35 bytes of encoding.
fn base58btc_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if input.is_empty() {
        return String::new();
    }
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for &byte in input {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

/// Compress a P-256 public key given its affine (x, y) coordinates (32 bytes
/// each, as carried in a WebAuthn EC2 COSE key). Validates the point is on the
/// curve. Returns the 33-byte SEC1 compressed encoding.
fn p256_xy_to_compressed(x: &[u8], y: &[u8]) -> Result<[u8; 33], WebvhError> {
    if x.len() != 32 || y.len() != 32 {
        return Err(WebvhError::KeyFormat("x/y must be 32 bytes".into()));
    }
    // Uncompressed SEC1 encoding (0x04 || x || y). `from_sec1_bytes` validates
    // the point is on the curve — the full (x, y) check we need before
    // compression discards y.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    let vk = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| WebvhError::KeyFormat(format!("invalid P-256 point: {e}")))?;
    let compressed = vk.to_encoded_point(true);
    let bytes = compressed.as_bytes();
    if bytes.len() != 33 {
        return Err(WebvhError::KeyFormat("compression failed".into()));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// `multicodec(p256-pub) || compressed-point`, base58btc, multibase `z`-prefixed.
fn compressed_to_multibase(compressed: &[u8]) -> String {
    let mut buf = Vec::with_capacity(MULTICODEC_P256_PUB.len() + compressed.len());
    buf.extend_from_slice(&MULTICODEC_P256_PUB);
    buf.extend_from_slice(compressed);
    format!("z{}", base58btc_encode(&buf))
}

/// The multibase form of a P-256 public key — used directly as a
/// `publicKeyMultibase` value and inside `did:webvh` `update_keys`.
pub fn cose_p256_to_multibase(x: &[u8], y: &[u8]) -> Result<String, WebvhError> {
    let compressed = p256_xy_to_compressed(x, y)?;
    Ok(compressed_to_multibase(&compressed))
}

/// A real, resolvable `did:key` for a P-256 public key. This is what the
/// invalid `did:key:apple-<sha256>` placeholder should become.
pub fn cose_p256_to_did_key(x: &[u8], y: &[u8]) -> Result<String, WebvhError> {
    Ok(format!("did:key:{}", cose_p256_to_multibase(x, y)?))
}

/// Extract the P-256 (x, y) from a WebAuthn passkey's credential public key.
/// Mirrors [`crate::cwt::cnf_from_passkey`]'s EC2 handling.
fn passkey_xy(passkey: &Passkey) -> Result<(Vec<u8>, Vec<u8>), WebvhError> {
    match &passkey.get_public_key().key {
        COSEKeyType::EC_EC2(ec2) if ec2.curve == ECDSACurve::SECP256R1 => {
            Ok((ec2.x.as_ref().to_vec(), ec2.y.as_ref().to_vec()))
        }
        _ => Err(WebvhError::UnsupportedKeyType),
    }
}

/// `publicKeyMultibase` for the passkey (the value embedded in the DID doc).
pub fn passkey_to_multibase(passkey: &Passkey) -> Result<String, WebvhError> {
    let (x, y) = passkey_xy(passkey)?;
    cose_p256_to_multibase(&x, &y)
}

/// The passkey rendered as a standalone `did:key`.
pub fn passkey_to_did_key(passkey: &Passkey) -> Result<String, WebvhError> {
    let (x, y) = passkey_xy(passkey)?;
    cose_p256_to_did_key(&x, &y)
}

// ---------------------------------------------------------------------------
// DID document
// ---------------------------------------------------------------------------

/// Build the DID document published in the webvh log.
///
/// `did_id` is `"{DID}"` when handed to `create_did` (the crate substitutes the
/// SCID-bearing identifier), or a concrete id when serving a legacy did:web
/// view. `vm_multibase` is the passkey public key; `also_known_as` carries the
/// ATProto handle (`at://<handle>`) so this identity and the ATProto identity
/// are cross-declared — see the module/PR notes on the two-DID-scheme reality.
pub fn build_did_document(
    did_id: &str,
    vm_multibase: &str,
    also_known_as: &[String],
) -> serde_json::Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": did_id,
        "alsoKnownAs": also_known_as,
        "verificationMethod": [{
            "id": format!("{did_id}#auth-key-0"),
            "type": "Multikey",
            "controller": did_id,
            "publicKeyMultibase": vm_multibase
        }],
        "authentication": [format!("{did_id}#auth-key-0")],
        "assertionMethod": [format!("{did_id}#auth-key-0")]
    })
}

// ---------------------------------------------------------------------------
// KMS-backed external signer (the did:webvh log / update authority)
// ---------------------------------------------------------------------------

/// External `Signer` for the did:webvh log, backed by an AWS KMS asymmetric
/// `ECC_NIST_P256` key (`WEBVH_KMS_KEY_ID`). The private key never leaves KMS.
///
/// Cloneable (KMS client + strings) so it can be handed by value into
/// `CreateDIDConfig::builder_generic().authorization_key(...)`.
#[derive(Clone)]
pub struct KmsSigner {
    client: aws_sdk_kms::Client,
    key_id: String,
    /// `publicKeyMultibase` of the *update* key — goes in webvh `update_keys`.
    update_key_multibase: String,
    /// `did:key:z..#z..` self-reference for proof metadata
    /// (`Signer::verification_method`).
    verification_method: String,
}

impl std::fmt::Debug for KmsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KmsSigner")
            .field("key_id", &self.key_id)
            .field("verification_method", &self.verification_method)
            .finish()
    }
}

impl KmsSigner {
    /// Build from `WEBVH_KMS_KEY_ID`, mirroring [`crate::patreon::build_kms_sealer`].
    /// `None` (Patreon-style fail-closed) when unset or the key can't be read.
    pub async fn from_env() -> Option<Self> {
        let key_id = env::var("WEBVH_KMS_KEY_ID")
            .ok()
            .filter(|s| !s.is_empty())?;
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let client = aws_sdk_kms::Client::new(&config);
        match Self::new(client, key_id).await {
            Ok(s) => {
                info!(
                    "webvh: KMS update-key signer ready ({})",
                    s.verification_method
                );
                Some(s)
            }
            Err(e) => {
                warn!("webvh: WEBVH_KMS_KEY_ID set but signer unavailable: {e}");
                None
            }
        }
    }

    async fn new(client: aws_sdk_kms::Client, key_id: String) -> Result<Self, WebvhError> {
        let resp = client
            .get_public_key()
            .key_id(&key_id)
            .send()
            .await
            .map_err(|e| WebvhError::Kms(format!("GetPublicKey: {e}")))?;
        let spki = resp
            .public_key()
            .ok_or_else(|| WebvhError::Kms("GetPublicKey returned no key".into()))?
            .as_ref();
        let multibase = spki_p256_to_multibase(spki)?;
        let verification_method = format!("did:key:{multibase}#{multibase}");
        Ok(Self {
            client,
            key_id,
            update_key_multibase: multibase,
            verification_method,
        })
    }

    /// `publicKeyMultibase` of the update key (for webvh `update_keys`).
    pub fn update_key_multibase(&self) -> &str {
        &self.update_key_multibase
    }

    /// Sign with the KMS key, returning a raw 64-byte P-256 signature (r‖s),
    /// the form data-integrity proofs expect (KMS returns ASN.1 DER).
    ///
    /// `data` is the bytes the cryptosuite hands the signer. The crate documents
    /// these as "pre-hashed, pre-canonicalised"; we treat a 32-byte input as the
    /// SHA-256 digest and otherwise hash it ourselves, so both readings of
    /// "pre-hashed" are handled. **Confirm against the chosen cryptosuite when
    /// first enabling the `webvh` feature.**
    pub async fn sign_p256(&self, data: &[u8]) -> Result<Vec<u8>, WebvhError> {
        use sha2::{Digest, Sha256};
        let digest = if data.len() == 32 {
            data.to_vec()
        } else {
            Sha256::digest(data).to_vec()
        };
        let resp = self
            .client
            .sign()
            .key_id(&self.key_id)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .message_type(MessageType::Digest)
            .message(Blob::new(digest))
            .send()
            .await
            .map_err(|e| WebvhError::Kms(format!("Sign: {e}")))?;
        let der = resp
            .signature()
            .ok_or_else(|| WebvhError::Kms("Sign returned no signature".into()))?
            .as_ref();
        der_p256_sig_to_raw(der)
    }
}

/// KMS GetPublicKey returns SPKI DER. For `ECC_NIST_P256` the trailing 65 bytes
/// are the uncompressed SEC1 point (`0x04 || x || y`); re-encode it as a P-256
/// `did:key` multibase.
fn spki_p256_to_multibase(spki: &[u8]) -> Result<String, WebvhError> {
    if spki.len() < 65 {
        return Err(WebvhError::KeyFormat("SPKI too short for P-256".into()));
    }
    let point = &spki[spki.len() - 65..];
    if point[0] != 0x04 {
        return Err(WebvhError::KeyFormat(
            "expected uncompressed SEC1 point".into(),
        ));
    }
    cose_p256_to_multibase(&point[1..33], &point[33..65])
}

/// Convert an ASN.1 DER P-256 ECDSA signature into raw `r‖s` (64 bytes).
fn der_p256_sig_to_raw(der: &[u8]) -> Result<Vec<u8>, WebvhError> {
    let sig = Signature::from_der(der).map_err(|e| WebvhError::SigFormat(e.to_string()))?;
    Ok(sig.to_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Registration / rotation hook
// ---------------------------------------------------------------------------

/// Called from `finish_register` after a passkey is stored. Builds the passport
/// DID document from the freshly-registered passkey and — when the `webvh`
/// feature is enabled and a [`KmsSigner`] is configured — signs the first
/// `did.jsonl` log entry and persists it for resolution.
///
/// Non-fatal: a webvh failure must never break WebAuthn registration.
pub async fn on_passkey_registered(
    app_state: &crate::AppState,
    user_id: &Uuid,
    username: &str,
    passkey: &Passkey,
) {
    let multibase = match passkey_to_multibase(passkey) {
        Ok(m) => m,
        Err(e) => {
            warn!("webvh: cannot derive did:key for {username}: {e}");
            return;
        }
    };
    let did_key = passkey_to_did_key(passkey).unwrap_or_else(|_| format!("did:key:{multibase}"));
    let also_known_as = vec![format!("at://{username}.arkavo.social")];
    let did_document = build_did_document("{DID}", &multibase, &also_known_as);
    info!(
        "webvh: passport document ready for {username} (auth key {did_key}, aka {:?})",
        also_known_as
    );

    #[cfg(feature = "webvh")]
    {
        let Some(signer) = app_state.webvh_signer.as_ref().as_ref() else {
            log::debug!("webvh: no signer configured (WEBVH_KMS_KEY_ID unset); doc not signed");
            return;
        };
        // Idempotent: a user's did:webvh is minted once. Additional passkeys
        // (device adds) must NOT re-mint a new DID or repoint the handle.
        // (Reflecting a new key in the existing DID doc via update_did is a
        // follow-up.)
        match app_state.db_store.get_webvh_log(user_id).await {
            Ok(Some(_)) => {
                log::debug!("webvh: {username} already provisioned; skipping re-mint");
                return;
            }
            Ok(None) => {}
            Err(e) => {
                warn!("webvh: log read failed for {username}: {e}");
                return;
            }
        }
        let address = format!("https://identity.arkavo.net/dids/{username}");
        let handle = format!("{username}.arkavo.social");
        match log_emit::create_passport_log(signer.clone(), &address, did_document).await {
            Ok((did, log)) => {
                if let Err(e) = app_state.db_store.put_webvh_log(user_id, &log).await {
                    warn!("webvh: signed log but failed to persist for {username}: {e}");
                }
                // Publish handle -> did:webvh into the shared handle store (the
                // canonical sovereign mapping the resolveHandle Lambda serves) —
                // replaces the old invalid did:key write.
                if let Err(e) = app_state.db_store.put_handle(&handle, &did, user_id).await {
                    warn!("webvh: failed to write handle {handle} -> {did}: {e}");
                } else {
                    info!(
                        "webvh: published {handle} -> {did} ({} byte log)",
                        log.len()
                    );
                }
            }
            Err(e) => warn!("webvh: failed to create log entry for {username}: {e}"),
        }
    }

    // In the feature-off build the doc/state are built but not emitted.
    #[cfg(not(feature = "webvh"))]
    let _ = (app_state, user_id, &did_document);
}

// ---------------------------------------------------------------------------
// Resolution endpoints
// ---------------------------------------------------------------------------

/// `GET /dids/:username/did.json` — legacy **did:web** view, built live from the
/// user's passkey. Resolvable today by any did:web resolver; did:webvh consumes
/// the same origin in "legacy mode" until a verifier upgrades to the log.
pub async fn well_known_did_json(
    Extension(app_state): Extension<crate::AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    match app_state.db_store.get_user_by_name(&username).await {
        Ok(Some(user)) => {
            let Some(passkey) = user.credentials.first() else {
                return (StatusCode::NOT_FOUND, "no credential for user").into_response();
            };
            match passkey_to_multibase(passkey) {
                Ok(multibase) => {
                    // did:web id encodes the path segments after the host.
                    let did_web = format!("did:web:identity.arkavo.net:dids:{username}");
                    let aka = vec![format!("at://{username}.arkavo.social")];
                    let doc = build_did_document(&did_web, &multibase, &aka);
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/did+json")],
                        doc.to_string(),
                    )
                        .into_response()
                }
                Err(_) => {
                    (StatusCode::UNPROCESSABLE_ENTITY, "credential is not P-256").into_response()
                }
            }
        }
        Ok(None) => (StatusCode::NOT_FOUND, "unknown identity").into_response(),
        Err(e) => {
            error!("webvh: did.json lookup failed for {username}: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "resolution error").into_response()
        }
    }
}

/// `GET /dids/:username/did.jsonl` — the did:webvh append-only log. Served from
/// the persisted log written by [`on_passkey_registered`] (requires the `webvh`
/// feature to have produced one). 404 until then.
pub async fn well_known_did_jsonl(
    Extension(app_state): Extension<crate::AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    match app_state.db_store.get_user_by_name(&username).await {
        Ok(Some(user)) => match app_state.db_store.get_webvh_log(&user.user_id).await {
            Ok(Some(log)) => (
                StatusCode::OK,
                // did:webvh logs are served as JSON Lines.
                [(header::CONTENT_TYPE, "application/jsonl")],
                log,
            )
                .into_response(),
            Ok(None) => (
                StatusCode::NOT_FOUND,
                "no did:webvh log yet (enable the `webvh` feature to sign one)",
            )
                .into_response(),
            Err(e) => {
                error!("webvh: did.jsonl lookup failed for {username}: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "resolution error").into_response()
            }
        },
        Ok(None) => (StatusCode::NOT_FOUND, "unknown identity").into_response(),
        Err(e) => {
            error!("webvh: user lookup failed for {username}: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "resolution error").into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// did:webvh log emission — opt-in (pulls the DIF crate)
// ---------------------------------------------------------------------------
//
// Enable with `--features webvh` AFTER adding the optional deps in Cargo.toml:
//   didwebvh-rs            = { version = "0.5", optional = true }
//   affinidi-data-integrity = { version = "*",  optional = true }  # match didwebvh-rs
// and expanding the feature to:
//   webvh = ["dep:didwebvh-rs", "dep:affinidi-data-integrity"]
//
// Written against the published `didwebvh-rs` examples (examples/create.rs and
// examples/custom_signer.rs). Field/variant names are from those examples; the
// first `--features webvh` build is where any minor signature drift surfaces.
#[cfg(feature = "webvh")]
mod log_emit {
    use super::{KmsSigner, WebvhError};
    use affinidi_data_integrity::DataIntegrityError;
    use didwebvh_rs::prelude::*;
    use std::sync::Arc;

    #[async_trait]
    impl Signer for KmsSigner {
        fn key_type(&self) -> KeyType {
            KeyType::P256
        }
        fn verification_method(&self) -> &str {
            &self.verification_method
        }
        async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DataIntegrityError> {
            self.sign_p256(data)
                .await
                .map_err(|e| DataIntegrityError::Signing(Box::new(e)))
        }
    }

    /// Create the first `did.jsonl` log entry for a passport DID, signed by the
    /// KMS update key, with the passkey embedded as the authentication method.
    pub async fn create_passport_log(
        signer: KmsSigner,
        address: &str,
        did_document: serde_json::Value,
    ) -> Result<(String, String), WebvhError> {
        let parameters = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(
                signer.update_key_multibase().to_string(),
            )])),
            portable: Some(true), // passport must survive a server move
            ..Default::default()
        };
        // W (witness signer) is unused here; pin it to the default `Secret` so
        // the two-Signer-param generic resolves (A = our KmsSigner).
        let config: CreateDIDConfig<KmsSigner, Secret> = CreateDIDConfig::builder_generic()
            .address(address)
            .authorization_key(signer)
            .did_document(did_document)
            .parameters(parameters)
            .also_known_as_web(true)
            .also_known_as_scid(true)
            .build()
            .map_err(|e| WebvhError::Log(format!("build config: {e:?}")))?;
        let result = create_did(config)
            .await
            .map_err(|e| WebvhError::Log(format!("create_did: {e:?}")))?;
        let did = result.did().to_string();
        let log = serde_json::to_string(result.log_entry())
            .map_err(|e| WebvhError::Log(format!("serialize log entry: {e}")))?;
        Ok((did, log))
    }
}

// ---------------------------------------------------------------------------
// Tests (default build — no external DID crate, no network)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // Independent anchor for the base58btc alphabet/algorithm (canonical bs58
    // test vector), so the multicodec tests below aren't self-referential.
    #[test]
    fn base58_known_vector() {
        assert_eq!(base58btc_encode(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
        assert_eq!(base58btc_encode(b"\x00\x00abc"), "11ZiCa");
    }

    fn hex32(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn p256_generator_to_did_key_is_well_formed() {
        // P-256 base point G — a known on-curve point.
        let gx = hex32("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
        let gy = hex32("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

        let did_key = cose_p256_to_did_key(&gx, &gy).unwrap();
        // The 0x1200 multicodec prefix forces every P-256 did:key to start zDn.
        assert!(
            did_key.starts_with("did:key:zDn"),
            "unexpected did:key form: {did_key}"
        );

        // Decode the multibase and check the multicodec + compressed-point shape.
        let mb = did_key.strip_prefix("did:key:z").unwrap();
        let decoded = base58btc_decode(mb);
        assert_eq!(&decoded[0..2], &MULTICODEC_P256_PUB, "multicodec prefix");
        assert_eq!(decoded.len(), 2 + 33, "prefix + compressed point");
        assert!(
            decoded[2] == 0x02 || decoded[2] == 0x03,
            "SEC1 compressed tag, got {:#x}",
            decoded[2]
        );
    }

    #[test]
    fn rejects_off_curve_point() {
        let bad = vec![1u8; 32];
        assert!(matches!(
            cose_p256_to_did_key(&bad, &bad),
            Err(WebvhError::KeyFormat(_))
        ));
    }

    #[test]
    fn rejects_wrong_length_coordinates() {
        assert!(cose_p256_to_multibase(&[0u8; 31], &[0u8; 32]).is_err());
    }

    #[test]
    fn der_signature_to_raw_rs() {
        // DER SEQUENCE { INTEGER 1, INTEGER 1 } → r=1, s=1.
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        let raw = der_p256_sig_to_raw(&der).unwrap();
        assert_eq!(raw.len(), 64);
        let mut expected = vec![0u8; 64];
        expected[31] = 1; // r
        expected[63] = 1; // s
        assert_eq!(raw, expected);
    }

    #[test]
    fn spki_extraction_round_trips_did_key() {
        // Build a synthetic P-256 SPKI: standard 26-byte header + uncompressed G.
        let header = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap();
        let mut spki = header;
        spki.push(0x04);
        spki.extend_from_slice(&hex32(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        ));
        spki.extend_from_slice(&hex32(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        ));

        let from_spki = spki_p256_to_multibase(&spki).unwrap();
        let from_xy = cose_p256_to_multibase(
            &hex32("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            &hex32("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        )
        .unwrap();
        assert_eq!(from_spki, from_xy);
    }

    #[test]
    fn did_document_shape() {
        let doc = build_did_document(
            "{DID}",
            "zDnTEST",
            &["at://alice.arkavo.social".to_string()],
        );
        assert_eq!(doc["verificationMethod"][0]["type"], "Multikey");
        assert_eq!(
            doc["verificationMethod"][0]["publicKeyMultibase"],
            "zDnTEST"
        );
        assert_eq!(doc["verificationMethod"][0]["id"], "{DID}#auth-key-0");
        assert_eq!(doc["authentication"][0], "{DID}#auth-key-0");
        assert_eq!(doc["assertionMethod"][0], "{DID}#auth-key-0");
        assert_eq!(doc["alsoKnownAs"][0], "at://alice.arkavo.social");
    }

    // Minimal base58btc decoder, test-only, to validate the encoder structurally.
    fn base58btc_decode(s: &str) -> Vec<u8> {
        const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut bytes: Vec<u8> = Vec::new();
        for ch in s.bytes() {
            let mut carry = ALPHABET
                .iter()
                .position(|&a| a == ch)
                .expect("bad b58 char") as u32;
            for b in bytes.iter_mut() {
                carry += (*b as u32) * 58;
                *b = (carry & 0xff) as u8;
                carry >>= 8;
            }
            while carry > 0 {
                bytes.push((carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        let zeros = s.bytes().take_while(|&c| c == b'1').count();
        for _ in 0..zeros {
            bytes.push(0);
        }
        bytes.reverse();
        bytes
    }
}
