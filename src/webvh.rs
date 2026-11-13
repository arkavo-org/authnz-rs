//! did:webvh identity layer (canonical, sovereign DID method).
//!
//! Arkavo keeps WebAuthn as its key-ceremony/auth layer while using did:webvh
//! as the canonical, resolvable, verifiable-history DID method — implemented
//! against the DIF reference crate (`didwebvh-rs`). At registration the handle
//! store (prod-handles) is written `handle -> did:webvh`, and the signed log
//! (did.jsonl) is served from `/dids/:id/did.jsonl`.
//!
//! ## The key architectural point this module encodes
//!
//! A WebAuthn passkey **cannot** be the did:webvh *log signer*: the log proof is
//! an Ed25519 `eddsa-jcs-2022` signature over canonicalised bytes, whereas a
//! passkey only ever signs `authenticatorData || SHA256(clientDataJSON)` (P-256)
//! via an interactive ceremony with a client-held key. So the two key roles are
//! **decoupled**:
//!
//! * **Log / update authority** — a software **Ed25519** key (the DIF crate's
//!   `Secret`), loaded from `WEBVH_SIGN_KEY_PATH`. did:webvh v1.0 mandates the
//!   `eddsa-jcs-2022` cryptosuite (Ed25519), which AWS KMS cannot sign — so this
//!   is a key file, the same posture as the CWT signing key
//!   (`ENCODING_KEY_PATH`). It signs the `did.jsonl` data-integrity proofs.
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
//! review), the DID-document builder, the Ed25519 key-file loader, and the
//! resolution endpoints.
//!
//! The `create_did` call that emits a signed `did.jsonl` (via the Ed25519
//! `Secret`) is behind `#[cfg(feature = "webvh")]` (see [`log_emit`]) so the
//! heavy DIF dependency tree stays opt-in for plain `cargo build`/CI; the
//! production build (`production/build.sh`) enables `--features webvh`, making
//! did:webvh canonical in prod.

use axum::extract::{Extension, Path};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use log::{error, info, warn};
use p256::ecdsa::VerifyingKey;
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
/// permanent HTTPS handle binding and the optional ATProto bridge alias.
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
// did:webvh log / update key (Ed25519 software key)
// ---------------------------------------------------------------------------
//
// did:webvh v1.0 mandates the eddsa-jcs-2022 cryptosuite (Ed25519), and AWS KMS
// cannot sign Ed25519 — so the log/update key is a software Ed25519 key loaded
// from `WEBVH_SIGN_KEY_PATH` (the crate's `Secret` JSON form). Same
// plaintext-key-file posture as the CWT signing key (`ENCODING_KEY_PATH`). The
// passkey (P-256) is NOT this key — it is published as a verificationMethod in
// the DID document; this key only signs the log's data-integrity proofs.

/// Read the Ed25519 update-signing key (crate `Secret` JSON) from
/// `WEBVH_SIGN_KEY_PATH`. Returns the raw file contents (parsed into a `Secret`
/// under the `webvh` feature). `None` (fail-open) when unset or unreadable — the
/// DID document is still built/served, but no signed log is emitted.
pub fn load_sign_key() -> Option<String> {
    // WEBVH_SIGN_KEY_PATH unset = intentional disable (fail-open, quiet).
    let path = env::var("WEBVH_SIGN_KEY_PATH")
        .ok()
        .filter(|s| !s.is_empty())?;
    // The path IS configured, so a broken key is a misconfiguration, not an
    // intentional disable — log at error! so it stays visible even under
    // ERROR-level filtering. (Fail-open: registration still succeeds; webvh
    // signing is simply off until the key is fixed.)
    let contents = match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => s,
        Ok(_) => {
            error!("webvh: WEBVH_SIGN_KEY_PATH={path} is empty — webvh signing DISABLED");
            return None;
        }
        Err(e) => {
            error!("webvh: cannot read WEBVH_SIGN_KEY_PATH={path}: {e} — webvh signing DISABLED");
            return None;
        }
    };
    // The update key is the DID update authority; flag loudly if its file is
    // readable by group/other (it should be chmod 600).
    #[cfg(unix)]
    if let Ok(meta) = std::fs::metadata(&path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            error!(
                "webvh: update-key file {path} is group/other-accessible (mode {:o}) — chmod 600",
                mode & 0o777
            );
        }
    }
    info!("webvh: update-signing key loaded from {path}");
    Some(contents)
}

// ---------------------------------------------------------------------------
// Registration / rotation hook
// ---------------------------------------------------------------------------

/// Called from `finish_register` after a passkey is stored. Builds the passport
/// DID document from the freshly-registered passkey and — when the `webvh`
/// feature is enabled and an Ed25519 update key is configured — signs the first
/// `did.jsonl` log entry and persists it for resolution.
///
/// Non-fatal: a webvh failure must never break WebAuthn registration.
pub async fn on_passkey_registered(
    app_state: &crate::AppState,
    user_id: &Uuid,
    username: &str,
    handle: &str,
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
    // The account's stored handle, never one derived from the username: the
    // username may change, the handle does not (#132). ATProto handles are
    // lowercase; keep alsoKnownAs and the handle key consistent.
    let handle = handle.to_lowercase();
    let also_known_as = vec![format!("https://{handle}"), format!("at://{handle}")];
    let did_document = build_did_document("{DID}", &multibase, &also_known_as);
    info!(
        "webvh: passport document ready for {username} (auth key {did_key}, aka {:?})",
        also_known_as
    );

    #[cfg(feature = "webvh")]
    {
        let Some(sign_key) = app_state.webvh_sign_key.as_ref().as_ref() else {
            log::debug!("webvh: no signing key (WEBVH_SIGN_KEY_PATH unset); doc not signed");
            return;
        };
        // Idempotent: a user's did:webvh is minted once. Additional passkeys
        // (device adds) must NOT re-mint a new DID or repoint the handle.
        // (Reflecting a new key in the existing DID doc via update_did is a
        // follow-up.)
        match app_state.db_store.get_webvh_log(user_id).await {
            Ok(Some(_)) => {
                refresh_handle_binding(app_state, user_id, &handle).await;
                return;
            }
            Ok(None) => {}
            Err(e) => {
                warn!("webvh: log read failed for {username}: {e}");
                return;
            }
        }
        let address = format!("https://identity.arkavo.net/dids/{user_id}");
        match log_emit::create_passport_log(sign_key, &address, did_document).await {
            Ok((did, log)) => {
                // Persist the log FIRST and treat a persist failure as
                // fatal-to-mint. Publishing handle -> did:webvh while the log
                // failed to persist would (a) make did.jsonl 404 for that DID and
                // (b) let a later re-mint (get_webvh_log == None) repoint the
                // handle to a brand-new DID — breaking did:webvh's stability.
                if let Err(e) = app_state
                    .db_store
                    .compare_and_swap_webvh_log(user_id, None, &log)
                    .await
                {
                    warn!(
                        "webvh: failed to persist log for {username}; NOT publishing handle: {e}"
                    );
                    return;
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

/// Parse the stored snapshot, not a document rebuilt from a passkey. The log
/// is server-authored; verifiers independently validate its proofs. Malformed
/// stored data is an error, never a fallback to another identity.
fn latest_document(log: &str) -> Result<serde_json::Value, WebvhError> {
    let line = log
        .lines()
        .rfind(|line| !line.trim().is_empty())
        .ok_or_else(|| WebvhError::Log("empty log".into()))?;
    let entry: serde_json::Value =
        serde_json::from_str(line).map_err(|e| WebvhError::Log(e.to_string()))?;
    let doc = &entry["state"];
    if !doc["id"]
        .as_str()
        .is_some_and(|id| id.starts_with("did:webvh:"))
    {
        return Err(WebvhError::Log("missing did:webvh state".into()));
    }
    Ok(doc.clone())
}

fn did_path(doc: &serde_json::Value) -> Option<&str> {
    let rest = doc["id"].as_str()?.strip_prefix("did:webvh:")?;
    let (_, location) = rest.split_once(':')?;
    let path = location.strip_prefix("identity.arkavo.net:dids:")?;
    valid_label(path).then_some(path)
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A permanent handle row doubles as the reserved-name map for legacy DID
/// paths. Never look up a legacy path by the current username. Check the log's
/// actual path too: new UUID DIDs must not acquire a username-path alias.
async fn log_for_path(
    store: &crate::db::DynamoDBStore,
    id: &str,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    if !valid_label(id) {
        return Ok(None);
    }
    if let Ok(uid) = Uuid::parse_str(id)
        && store.get_user_by_id(&uid).await?.is_some()
        && let Some(log) = store.get_webvh_log(&uid).await?
        && did_path(&latest_document(&log)?) == Some(id)
    {
        return Ok(Some(log));
    }
    let handle = format!("{id}.arkavo.social");
    if let Some((uid, did)) = store.get_handle_owner(&handle).await?
        && store.get_user_by_id(&uid).await?.is_some()
        && let Some(log) = store.get_webvh_log(&uid).await?
    {
        let doc = latest_document(&log)?;
        if doc["id"].as_str() == Some(&did) && did_path(&doc) == Some(id) {
            return Ok(Some(log));
        }
    }
    Ok(None)
}

/// Rewrite DID URLs belonging to this document, preserving other identities
/// and arbitrary strings (e.g. service endpoints containing the DID).
fn web_document(mut doc: serde_json::Value, id: &str) -> serde_json::Value {
    fn rewrite(value: &mut serde_json::Value, from: &str, to: &str) {
        match value {
            serde_json::Value::String(s) if s == from => *s = to.to_string(),
            serde_json::Value::String(s)
                if s.strip_prefix(from)
                    .is_some_and(|suffix| suffix.starts_with('#')) =>
            {
                *s = format!("{to}{}", &s[from.len()..]);
            }
            serde_json::Value::Array(values) => {
                values.iter_mut().for_each(|v| rewrite(v, from, to))
            }
            serde_json::Value::Object(values) => {
                values.values_mut().for_each(|v| rewrite(v, from, to))
            }
            _ => {}
        }
    }
    let canonical = doc["id"].as_str().unwrap().to_string();
    rewrite(
        &mut doc,
        &canonical,
        &format!("did:web:identity.arkavo.net:dids:{id}"),
    );
    doc
}

fn json_document(doc: serde_json::Value) -> axum::response::Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/did+json")],
        doc.to_string(),
    )
        .into_response()
}

/// `GET /dids/:id/did.json` — parallel did:web view of the latest log state.
pub async fn well_known_did_json(
    Extension(app_state): Extension<crate::AppState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match log_for_path(&app_state.db_store, &id).await {
        Ok(Some(log)) => match latest_document(&log) {
            Ok(doc) => json_document(web_document(doc, &id)),
            Err(e) => resolution_error(e),
        },
        Ok(None) => (StatusCode::NOT_FOUND, "unknown identity").into_response(),
        Err(e) => resolution_error(e),
    }
}

/// `GET /dids/:id/did.jsonl` — the exact persisted append-only log.
pub async fn well_known_did_jsonl(
    Extension(app_state): Extension<crate::AppState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match log_for_path(&app_state.db_store, &id).await {
        Ok(Some(log)) => {
            (StatusCode::OK, [(header::CONTENT_TYPE, "text/jsonl")], log).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "unknown identity").into_response(),
        Err(e) => resolution_error(e),
    }
}

fn resolution_error(e: impl std::fmt::Display) -> axum::response::Response {
    error!("webvh: resolution failed: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "resolution error").into_response()
}

/// Origin for https://<label>.arkavo.social/.well-known/did.json.
/// This alias has no verification methods: signatures name the canonical DID.
pub async fn handle_did_json(
    Extension(app_state): Extension<crate::AppState>,
    Path(label): Path<String>,
) -> axum::response::Response {
    async fn resolve(
        store: &crate::db::DynamoDBStore,
        label: &str,
    ) -> Result<Option<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
        if !valid_label(label) {
            return Ok(None);
        }
        let handle = format!("{label}.arkavo.social");
        let Some((uid, did)) = store.get_handle_owner(&handle).await? else {
            return Ok(None);
        };
        if store.get_user_by_id(&uid).await?.is_none() {
            return Ok(None);
        }
        let Some(log) = store.get_webvh_log(&uid).await? else {
            return Ok(None);
        };
        let doc = latest_document(&log)?;
        // The permanent mapping and signed state must agree. Older logs have
        // only the ATProto alias until their authenticated binding update.
        let aliases = doc["alsoKnownAs"].as_array();
        let has_binding = aliases.is_some_and(|aliases| {
            aliases.contains(&json!(format!("https://{handle}")))
                || aliases.contains(&json!(format!("at://{handle}")))
        });
        if doc["id"].as_str() != Some(&did) || !has_binding {
            return Ok(None);
        }
        Ok(Some(json!({
            "@context": "https://www.w3.org/ns/did/v1",
            "id": format!("did:web:{handle}"),
            "alsoKnownAs": [did]
        })))
    }
    match resolve(&app_state.db_store, &label).await {
        Ok(Some(doc)) => json_document(doc),
        Ok(None) => (StatusCode::NOT_FOUND, "unknown identity").into_response(),
        Err(e) => resolution_error(e),
    }
}

/// Authenticated login/device enrollment backfills the HTTPS binding once.
/// Failure is non-fatal to authentication; no read-only resolver signs logs.
pub async fn refresh_handle_binding(app: &crate::AppState, uid: &Uuid, handle: &str) {
    #[cfg(feature = "webvh")]
    {
        async fn refresh(
            app: &crate::AppState,
            uid: &Uuid,
            handle: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let Some(log) = app.db_store.get_webvh_log(uid).await? else {
                return Ok(());
            };
            // Every sign-in runs this before its token is minted. Once the
            // log names both aliases and the handle row maps them, it reads
            // two rows and does nothing else: no chain verification, no write.
            let mut doc = latest_document(&log)?;
            if !log_emit::has_handle_aliases(&doc, handle)
                && let Some(key) = app.webvh_sign_key.as_ref().as_ref()
                && let Some(updated) = log_emit::add_handle_binding(key, &log, handle).await?
            {
                app.db_store
                    .compare_and_swap_webvh_log(uid, Some(&log), &updated)
                    .await?;
                doc = latest_document(&updated)?;
            }
            // Repair a failed handle write after initial mint without re-minting.
            let did = doc["id"].as_str().unwrap();
            let published = app.db_store.get_handle_owner(handle).await?;
            if !matches!(published, Some((owner, ref mapped)) if owner == *uid && mapped == did) {
                app.db_store.put_handle(handle, did, uid).await?;
            }
            Ok(())
        }
        if let Err(e) = refresh(app, uid, handle).await {
            warn!("webvh: handle binding refresh failed for {uid}: {e}");
        }
    }
    #[cfg(not(feature = "webvh"))]
    let _ = (app, uid, handle);
}

// ---------------------------------------------------------------------------
// did:webvh log emission — opt-in (pulls the DIF crate)
// ---------------------------------------------------------------------------
//
// Behind the `webvh` cargo feature (= `["dep:didwebvh-rs"]`) so the heavy DIF
// dependency tree stays out of the default build. The Ed25519 update key is the
// crate's re-exported `Secret`; no other direct dep is required.
#[cfg(feature = "webvh")]
mod log_emit {
    use super::WebvhError;
    use didwebvh_rs::prelude::*;
    use std::sync::Arc;

    /// Whether the document already names `handle` under both aliases, the
    /// HTTPS one and the ATProto one.
    pub fn has_handle_aliases(doc: &serde_json::Value, handle: &str) -> bool {
        let Some(aliases) = doc["alsoKnownAs"].as_array() else {
            return false;
        };
        [format!("https://{handle}"), format!("at://{handle}")]
            .iter()
            .all(|alias| aliases.iter().any(|v| v.as_str() == Some(alias)))
    }

    /// Verify the existing chain, then append only the missing aliases. Keep
    /// the DID, keys, services, and every prior byte of history unchanged.
    pub async fn add_handle_binding(
        key: &str,
        log: &str,
        handle: &str,
    ) -> Result<Option<String>, WebvhError> {
        let mut doc = super::latest_document(log)?;
        let did = doc["id"].as_str().unwrap().to_string();
        let mut state = DIDWebVHState::default();
        state
            .resolve_log(&did, log, None)
            .await
            .map_err(|e| WebvhError::Log(format!("resolve log: {e}")))?;
        let aliases = doc
            .as_object_mut()
            .unwrap()
            .entry("alsoKnownAs")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut()
            .ok_or_else(|| WebvhError::Log("alsoKnownAs is not an array".into()))?;
        let mut changed = false;
        for alias in [format!("https://{handle}"), format!("at://{handle}")] {
            if !aliases.iter().any(|v| v.as_str() == Some(&alias)) {
                aliases.push(serde_json::Value::String(alias));
                changed = true;
            }
        }
        if !changed {
            return Ok(None);
        }
        let secret: Secret = serde_json::from_str(key)
            .map_err(|e| WebvhError::Log(format!("parse update key: {e}")))?;
        // The library serializes versionTime at second precision but stamps
        // updates with `now`. Two updates in one second otherwise produce a
        // chain its own resolver rejects. Wait at most one second; a log dated
        // further in the future needs a clock correction, not a forged time.
        let last_entry: serde_json::Value =
            serde_json::from_str(log.lines().rfind(|line| !line.trim().is_empty()).unwrap())
                .map_err(|e| WebvhError::Log(e.to_string()))?;
        let last_time = chrono::DateTime::parse_from_rfc3339(
            last_entry["versionTime"]
                .as_str()
                .ok_or_else(|| WebvhError::Log("missing versionTime".into()))?,
        )
        .map_err(|e| WebvhError::Log(e.to_string()))?;
        let delay = last_time.with_timezone(&chrono::Utc) + chrono::Duration::seconds(1)
            - chrono::Utc::now();
        if delay > chrono::Duration::seconds(1) {
            return Err(WebvhError::Log(
                "log versionTime is ahead of the server clock".into(),
            ));
        }
        if let Ok(delay) = delay.to_std() {
            tokio::time::sleep(delay).await;
        }
        let config = UpdateDIDConfig::builder()
            .state(state)
            .signing_key(secret)
            .document(doc)
            .build()
            .map_err(|e| WebvhError::Log(e.to_string()))?;
        let result = update_did(config)
            .await
            .map_err(|e| WebvhError::Log(e.to_string()))?;
        let entry = serde_json::to_string(result.log_entry())
            .map_err(|e| WebvhError::Log(e.to_string()))?;
        let separator = if log.ends_with('\n') { "" } else { "\n" };
        let updated = format!("{log}{separator}{entry}\n");
        DIDWebVHState::default()
            .resolve_log(&did, &updated, None)
            .await
            .map_err(|e| WebvhError::Log(format!("validate updated log: {e}")))?;
        Ok(Some(updated))
    }

    /// Create the first `did.jsonl` log entry for a passport DID, signed by the
    /// Ed25519 update key (parsed from its crate-`Secret` JSON), with the passkey
    /// embedded as the authentication verificationMethod. Returns `(did, log)`.
    pub async fn create_passport_log(
        sign_key_json: &str,
        address: &str,
        did_document: serde_json::Value,
    ) -> Result<(String, String), WebvhError> {
        let secret: Secret = serde_json::from_str(sign_key_json)
            .map_err(|e| WebvhError::Log(format!("parse update key: {e}")))?;
        let update_mb = secret
            .get_public_keymultibase()
            .map_err(|e| WebvhError::Log(format!("update key multibase: {e:?}")))?;
        let parameters = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(update_mb)])),
            portable: Some(true), // passport must survive a server move
            ..Default::default()
        };
        let config = CreateDIDConfig::builder()
            .address(address)
            .authorization_key(secret)
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

    /// Live diagnostic (ignored): generates a fresh Ed25519 update key and drives
    /// `create_did` to confirm did:webvh signing works end-to-end (no KMS, no
    /// env, no network). Run with:
    ///   cargo test --features webvh webvh_live_create -- --ignored --nocapture
    #[cfg(feature = "webvh")]
    #[tokio::test]
    #[ignore]
    async fn webvh_live_create() {
        use didwebvh_rs::did_key::generate_did_key;
        use didwebvh_rs::prelude::*;
        use std::sync::Arc;

        // Ed25519 update key (KMS can't sign Ed25519; did:webvh v1.0 mandates it).
        let (_did, secret) = generate_did_key(KeyType::Ed25519).expect("gen ed25519");
        let key_json = serde_json::to_string(&secret).expect("serialize Secret");
        let gx = hex::decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
            .unwrap();
        let gy = hex::decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
            .unwrap();
        let mb = cose_p256_to_multibase(&gx, &gy).unwrap();
        let doc = build_did_document("{DID}", &mb, &["at://diag.arkavo.social".to_string()]);
        let params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(
                secret.get_public_keymultibase().unwrap(),
            )])),
            portable: Some(true),
            ..Default::default()
        };
        let config = CreateDIDConfig::builder()
            .address("https://identity.arkavo.net/dids/diag")
            .authorization_key(secret)
            .did_document(doc)
            .parameters(params)
            .also_known_as_web(true)
            .also_known_as_scid(true)
            .build()
            .expect("build config");
        match create_did(config).await {
            Ok(result) => {
                println!("DIAG OK did={}", result.did());
                println!("DIAG KEY_JSON={key_json}");
                println!(
                    "DIAG LOG={}",
                    serde_json::to_string(result.log_entry()).unwrap()
                );
            }
            Err(e) => println!("DIAG ERR: {e:?}"),
        }
    }

    /// One-time key generator (ignored). Writes a fresh Ed25519 update key
    /// (crate `Secret` JSON) to `WEBVH_SIGN_KEY_PATH`, refusing to overwrite:
    ///   WEBVH_SIGN_KEY_PATH=production/webvh-signkey.json \
    ///     cargo test --features webvh webvh_generate_key -- --ignored --nocapture
    #[cfg(feature = "webvh")]
    #[tokio::test]
    #[ignore]
    async fn webvh_generate_key() {
        use didwebvh_rs::did_key::generate_did_key;
        use didwebvh_rs::prelude::KeyType;
        let path =
            std::env::var("WEBVH_SIGN_KEY_PATH").expect("set WEBVH_SIGN_KEY_PATH to output file");
        assert!(
            !std::path::Path::new(&path).exists(),
            "refusing to overwrite existing key at {path}"
        );
        let (did_key, secret) = generate_did_key(KeyType::Ed25519).expect("gen ed25519");
        std::fs::write(&path, serde_json::to_string(&secret).expect("serialize")).expect("write");
        println!("WEBVH KEY GENERATED -> {path}\n  update key did:key = {did_key}");
    }

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
        // Base58 encodes each leading zero byte as '1'. Re-add them as a run;
        // `resize` rather than a push loop, which clippy reads as an
        // accidental same-item push.
        let zeros = s.bytes().take_while(|&c| c == b'1').count();
        bytes.resize(bytes.len() + zeros, 0);
        bytes.reverse();
        bytes
    }
}

#[cfg(test)]
#[path = "webvh_tests.rs"]
mod resolution_tests;
