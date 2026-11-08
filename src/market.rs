//! market.arkavo.com as an entitlement source (#141).
//!
//! The market sells a lifetime creator membership. A buyer gets a signed
//! **claim** (a compact ES256 JWS) at `<issuer>/claim/<checkoutSessionId>`
//! and links it to an Arkavo account with `POST /market/link`. Identity treats
//! the market the way it treats Patreon (#91): it stores only the link
//! (`db/market.rs`) and, whenever it mints a token, asks the market whether
//! the purchase still holds. It stores no purchase, price, refund or
//! revocation, and the market pushes nothing. Contract: arkavo-com/market
//! `docs/market-identity-interface.md`.
//!
//! - **Verification** ([`verify_claim`]): `alg` ES256, `typ` JWT, a `kid`
//!   pinned in `MARKET_CLAIM_KEYS_PATH` (the market's JWKS is a rotation
//!   channel, never a trust anchor), the signature, `iss`, `aud` (this
//!   identity's issuer), `jti` equal to the link key, a known `tier`, and an
//!   accepted `livemode` that agrees with the `jti` prefix. No `exp`: the
//!   claim is fetched fresh.
//! - **At mint** ([`MarketSource::grant`]): each linked purchase is fetched
//!   (cached: an answer 5 min, a failure 60 s). A verified `200` grants its
//!   tier's entitlements; `410` (refunded, or a dispute lost) and `404` grant
//!   nothing; anything else grants nothing too (fails closed, no last-good
//!   fallback).
//!
//! A checkout session id is the purchase's bearer secret (anyone holding it
//! can fetch the claim), so no error, log line or `Debug` output here carries
//! one: logs name a purchase by [`SessionId::log_ref`]. Errors are unit
//! variants with fixed messages, so nothing from a claim reaches a log line.

use crate::AppState;
use crate::constants::{
    ENTITLEMENT_CREATOR_PUBLISH, MARKET_CACHE_TTL_SECONDS, MARKET_CLAIM_MAX_BYTES,
    MARKET_FAILURE_CACHE_TTL_SECONDS, MARKET_FETCH_DEADLINE_SECONDS,
};
use crate::db::{DynamoDBError, MarketLinkOutcome};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use log::{error, info, warn};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use thiserror::Error;

const JTI_PREFIX: &str = "market#";
const LIVE_PREFIX: &str = "cs_live_";
const TEST_PREFIX: &str = "cs_test_";
/// Longest checkout session id accepted. Stripe's are about 66 characters;
/// the id is a URL path segment and a DynamoDB key.
const SESSION_ID_MAX_LEN: usize = 255;
/// Longest pasted claim read on `POST /market/link`.
const PASTED_CLAIM_MAX_LEN: usize = 8 * 1024;

// --------- The purchase id ---------

/// A Stripe Checkout Session id, `cs_live_…` or `cs_test_…`: the link key
/// (`market#<id>`) and the purchase's bearer secret.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct SessionId(String);

impl std::fmt::Debug for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionId({})", self.log_ref())
    }
}

impl SessionId {
    /// `cs_live_` or `cs_test_` and then ASCII letters, digits and `_`, at
    /// most [`SESSION_ID_MAX_LEN`] in all.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        let rest = raw
            .strip_prefix(LIVE_PREFIX)
            .or_else(|| raw.strip_prefix(TEST_PREFIX))?;
        let valid = !rest.is_empty()
            && raw.len() <= SESSION_ID_MAX_LEN
            && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        valid.then(|| Self(raw.to_string()))
    }

    /// The id a claim's `jti` (`market#<id>`) names.
    fn from_jti(jti: &str) -> Option<Self> {
        Self::parse(jti.strip_prefix(JTI_PREFIX)?)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    fn jti(&self) -> String {
        format!("{JTI_PREFIX}{}", self.0)
    }

    /// A live-mode purchase (`cs_live_`), as opposed to Stripe test mode.
    pub(crate) fn livemode(&self) -> bool {
        self.0.starts_with(LIVE_PREFIX)
    }

    /// How logs name the purchase: the first 12 hex digits of the id's
    /// SHA-256, never the id.
    pub(crate) fn log_ref(&self) -> String {
        hex::encode(&Sha256::digest(self.0.as_bytes())[..6])
    }
}

// --------- Tiers ---------

/// What a claim grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tier {
    /// The lifetime creator membership: every paid feature, now and later.
    Lifetime,
}

impl Tier {
    fn parse(v: &str) -> Option<Self> {
        match v {
            "lifetime" => Some(Self::Lifetime),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Lifetime => "lifetime",
        }
    }

    /// The entitlements the tier grants at mint. Mapped here, never stored,
    /// so a paid feature added later reaches every lifetime member with no
    /// data migration. Today every paid feature gates on the
    /// creator-publishing FQN.
    pub(crate) fn entitlements(self) -> Vec<String> {
        match self {
            Self::Lifetime => vec![ENTITLEMENT_CREATOR_PUBLISH.to_string()],
        }
    }
}

// --------- Configuration ---------

/// The market source's configuration: `MARKET_ISSUER`,
/// `MARKET_CLAIM_KEYS_PATH` and `MARKET_ACCEPT_TEST_MODE`, with the expected
/// `aud` (this identity's `OIDC_ISSUER`).
#[derive(Debug, Clone)]
pub struct MarketConfig {
    /// The claims' `iss`, and the base of `<issuer>/claim/<id>`. No trailing
    /// slash.
    pub issuer: String,
    /// The claims' expected `aud`: this identity's issuer.
    pub audience: String,
    /// The pinned claim keys, by `kid` (each its RFC 7638 thumbprint).
    keys: HashMap<String, VerifyingKey>,
    /// Whether Stripe test-mode claims (`livemode: false`, `cs_test_`) grant.
    pub accept_test_mode: bool,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Value>,
}

/// The RFC 7638 thumbprint of a P-256 public key, base64url.
fn thumbprint(x: &[u8], y: &[u8]) -> String {
    // The required members in lexicographic order, no whitespace.
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(x),
        URL_SAFE_NO_PAD.encode(y)
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

/// Parse the pinned keys: a JWK Set of P-256 public keys, each with a `kid`
/// equal to its RFC 7638 thumbprint (so a pinned `kid` can never name
/// another key). A private key, another curve or algorithm, a duplicate or
/// an empty set is refused.
fn parse_jwk_set(json: &str) -> Result<HashMap<String, VerifyingKey>, String> {
    let set: JwkSet = serde_json::from_str(json).map_err(|_| "not a JWK Set".to_string())?;
    let mut keys = HashMap::new();
    for (i, jwk) in set.keys.iter().enumerate() {
        let field = |k: &str| jwk.get(k).and_then(Value::as_str);
        if field("kty") != Some("EC") || field("crv") != Some("P-256") {
            return Err(format!("key {i} is not an EC P-256 key"));
        }
        if jwk.get("d").is_some() {
            return Err(format!("key {i} is a private key"));
        }
        if field("alg").is_some_and(|a| a != "ES256") {
            return Err(format!("key {i} is not for ES256"));
        }
        let coord = |k: &str| {
            field(k)
                .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
                .filter(|b| b.len() == 32)
                .ok_or_else(|| format!("key {i} has no valid {k}"))
        };
        let (x, y) = (coord("x")?, coord("y")?);
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        let key = VerifyingKey::from_sec1_bytes(&point)
            .map_err(|_| format!("key {i} is not a point on P-256"))?;
        let kid = thumbprint(&x, &y);
        if field("kid") != Some(kid.as_str()) {
            return Err(format!(
                "key {i}'s kid is not its RFC 7638 thumbprint ({kid})"
            ));
        }
        if keys.insert(kid, key).is_some() {
            return Err(format!("key {i} is listed twice"));
        }
    }
    if keys.is_empty() {
        return Err("the JWK Set has no keys".into());
    }
    Ok(keys)
}

impl MarketConfig {
    /// Parse the values. `Ok(None)`: the feature is off (the issuer or the
    /// keys are unset or empty). `Err`: set but unusable, which also leaves
    /// it off. `keys_json` is the content of the `MARKET_CLAIM_KEYS_PATH`
    /// file.
    pub(crate) fn parse(
        issuer: Option<&str>,
        keys_json: Option<&str>,
        test_mode: Option<&str>,
        audience: &str,
    ) -> Result<Option<Self>, String> {
        fn present(v: Option<&str>) -> Option<&str> {
            v.map(str::trim).filter(|s| !s.is_empty())
        }
        let (Some(issuer), Some(keys_json)) = (present(issuer), present(keys_json)) else {
            return Ok(None);
        };
        let issuer = issuer.trim_end_matches('/');
        let url = url::Url::parse(issuer).map_err(|_| "MARKET_ISSUER is not a URL".to_string())?;
        if !matches!(url.scheme(), "https" | "http")
            || url.host().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("MARKET_ISSUER must be an http(s) URL with no query".into());
        }
        let keys = parse_jwk_set(keys_json).map_err(|e| format!("MARKET_CLAIM_KEYS_PATH: {e}"))?;
        let accept_test_mode = match present(test_mode) {
            None => false,
            Some(v) if v.eq_ignore_ascii_case("true") => true,
            Some(v) if v.eq_ignore_ascii_case("false") => false,
            Some(_) => return Err("MARKET_ACCEPT_TEST_MODE must be true or false".into()),
        };
        Ok(Some(Self {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            keys,
            accept_test_mode,
        }))
    }

    /// Read the env vars (and the keys file) and log, once, which state the
    /// feature is in. `audience` is this identity's issuer.
    pub fn from_env(audience: &str) -> Option<Self> {
        let var = |name: &str| std::env::var(name).ok();
        let issuer = var("MARKET_ISSUER");
        let path = var("MARKET_CLAIM_KEYS_PATH").filter(|p| !p.trim().is_empty());
        let keys_json = match &path {
            Some(p) => match std::fs::read_to_string(p.trim()) {
                Ok(json) => Some(json),
                Err(e) => {
                    warn!(
                        "market purchases DISABLED: MARKET_CLAIM_KEYS_PATH could not be read: {e}"
                    );
                    return None;
                }
            },
            None => None,
        };
        let test_mode = var("MARKET_ACCEPT_TEST_MODE");
        match Self::parse(
            issuer.as_deref(),
            keys_json.as_deref(),
            test_mode.as_deref(),
            audience,
        ) {
            Ok(Some(cfg)) => {
                let mut kids: Vec<&str> = cfg.keys.keys().map(String::as_str).collect();
                kids.sort_unstable();
                info!(
                    "market purchases ENABLED: issuer={} audience={} pinned_kids={} test_mode={}",
                    cfg.issuer,
                    cfg.audience,
                    kids.join(","),
                    cfg.accept_test_mode
                );
                Some(cfg)
            }
            Ok(None) => {
                info!(
                    "market purchases DISABLED: MARKET_ISSUER / MARKET_CLAIM_KEYS_PATH not both set"
                );
                None
            }
            Err(reason) => {
                warn!("market purchases DISABLED: {reason}");
                None
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn for_tests(issuer: &str, audience: &str, key: &p256::ecdsa::SigningKey) -> Self {
        let point = key.verifying_key().to_encoded_point(false);
        let kid = thumbprint(point.x().unwrap(), point.y().unwrap());
        Self {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            keys: HashMap::from([(kid, *key.verifying_key())]),
            accept_test_mode: false,
        }
    }
}

// --------- Claim verification ---------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ClaimError {
    #[error("malformed claim")]
    Malformed,
    #[error("signed by a key that is not pinned")]
    UnknownKey,
    #[error("signature does not verify")]
    InvalidSignature,
    #[error("wrong issuer")]
    WrongIssuer,
    #[error("wrong audience")]
    WrongAudience,
    #[error("names another purchase")]
    WrongPurchase,
    #[error("unknown tier")]
    UnknownTier,
    #[error("livemode disagrees with the purchase id")]
    ModeMismatch,
    #[error("test-mode claims are not accepted")]
    TestMode,
}

/// A claim that verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedClaim {
    pub tier: Tier,
    pub livemode: bool,
}

fn decode_json<T: serde::de::DeserializeOwned>(segment: &str) -> Result<T, ClaimError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| ClaimError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| ClaimError::Malformed)
}

/// The three segments of a compact JWS.
fn segments(jws: &str) -> Result<(&str, &str, &str), ClaimError> {
    let mut it = jws.split('.');
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s), None) => Ok((h, p, s)),
        _ => Err(ClaimError::Malformed),
    }
}

/// Verify a claim the market served for `expected` (the purchase identity
/// fetched it for).
pub(crate) fn verify_claim(
    cfg: &MarketConfig,
    jws: &str,
    expected: &SessionId,
) -> Result<VerifiedClaim, ClaimError> {
    let (header_b64, payload_b64, signature_b64) = segments(jws)?;
    let header: Map<String, Value> = decode_json(header_b64)?;
    let text =
        |m: &Map<String, Value>, k: &str| m.get(k).and_then(Value::as_str).map(str::to_owned);
    if text(&header, "alg").as_deref() != Some("ES256")
        || text(&header, "typ").as_deref() != Some("JWT")
        || header.contains_key("crit")
    {
        return Err(ClaimError::Malformed);
    }
    let kid = text(&header, "kid").ok_or(ClaimError::Malformed)?;
    let key = cfg.keys.get(&kid).ok_or(ClaimError::UnknownKey)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| ClaimError::Malformed)?;
    let signature = Signature::from_slice(&signature).map_err(|_| ClaimError::InvalidSignature)?;
    let signing_input = &jws[..header_b64.len() + 1 + payload_b64.len()];
    key.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| ClaimError::InvalidSignature)?;

    let payload: Map<String, Value> = decode_json(payload_b64)?;
    if text(&payload, "iss").as_deref() != Some(cfg.issuer.as_str()) {
        return Err(ClaimError::WrongIssuer);
    }
    let aud_ok = match payload.get("aud") {
        Some(Value::String(a)) => *a == cfg.audience,
        Some(Value::Array(list)) => list.iter().any(|a| a.as_str() == Some(&cfg.audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(ClaimError::WrongAudience);
    }
    if text(&payload, "jti") != Some(expected.jti()) {
        return Err(ClaimError::WrongPurchase);
    }
    let tier = text(&payload, "tier")
        .as_deref()
        .and_then(Tier::parse)
        .ok_or(ClaimError::UnknownTier)?;
    let livemode = payload
        .get("livemode")
        .and_then(Value::as_bool)
        .ok_or(ClaimError::Malformed)?;
    if livemode != expected.livemode() {
        return Err(ClaimError::ModeMismatch);
    }
    if !livemode && !cfg.accept_test_mode {
        return Err(ClaimError::TestMode);
    }
    Ok(VerifiedClaim { tier, livemode })
}

/// The purchase a pasted claim names, from its `jti`, **unverified**: the
/// pasted claim only shows the caller holds the session id (the bearer
/// secret). The link verifies the claim it fetches fresh, so one saved before
/// a key rotation still links.
fn pasted_session_id(claim: &str) -> Option<SessionId> {
    if claim.len() > PASTED_CLAIM_MAX_LEN {
        return None;
    }
    let (_, payload_b64, _) = segments(claim.trim()).ok()?;
    let payload: Map<String, Value> = decode_json(payload_b64).ok()?;
    SessionId::from_jti(payload.get("jti")?.as_str()?)
}

// --------- Fetching and caching ---------

/// The market's answer for one purchase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaimStatus {
    /// `200` with a claim that verified.
    Valid(Tier),
    /// `410`: fully refunded, or a dispute over it was lost.
    Revoked,
    /// `404`: no paid purchase of the offer at that id.
    NotFound,
    /// `200` with a claim that does not verify (or no claim).
    Invalid,
    /// Unreachable, timed out, or any other status.
    Unavailable,
}

impl ClaimStatus {
    /// How long the answer is cached: a market answer 5 min, a failure 60 s.
    fn ttl(self) -> i64 {
        match self {
            Self::Valid(_) | Self::Revoked | Self::NotFound => MARKET_CACHE_TTL_SECONDS,
            Self::Invalid | Self::Unavailable => MARKET_FAILURE_CACHE_TTL_SECONDS,
        }
    }
}

/// What the market contributes to a mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MarketGrant {
    /// A linked purchase verified: these entitlements.
    Granted(Vec<String>),
    /// No linked purchase grants (none, refunded, unknown, or test mode
    /// while it is off).
    NotGranted,
    /// None granted and at least one could not be checked. A mint grants
    /// nothing; `GET /entities` answers 503 unless another source grants.
    Unavailable,
}

/// A cached answer, and which fetch produced it.
#[derive(Debug, Clone, Copy)]
struct CacheEntry {
    status: ClaimStatus,
    expires_at: i64,
    /// When the fetch began, in [`MarketSource::begin`] order.
    fetch: u64,
}

/// The configured market source: its configuration, an HTTP client and the
/// answer cache (in process: at most one entry per purchase, about 100).
pub struct MarketSource {
    pub config: MarketConfig,
    http: reqwest::Client,
    cache: Mutex<HashMap<SessionId, CacheEntry>>,
    fetches: AtomicU64,
}

impl MarketSource {
    pub fn new(config: MarketConfig) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(MARKET_FETCH_DEADLINE_SECONDS))
            // A redirect is "any other status": the claim is served at one URL.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("market HTTP client: {e}"))?;
        Ok(Self {
            config,
            http,
            cache: Mutex::new(HashMap::new()),
            fetches: AtomicU64::new(0),
        })
    }

    /// Read the configuration from the environment; `None` when it is off.
    pub fn from_env(audience: &str) -> Option<Self> {
        let config = MarketConfig::from_env(audience)?;
        match Self::new(config) {
            Ok(source) => Some(source),
            Err(e) => {
                warn!("market purchases DISABLED: {e}");
                None
            }
        }
    }

    fn cached(&self, id: &SessionId, now: i64) -> Option<ClaimStatus> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache
            .get(id)
            .filter(|e| e.expires_at > now)
            .map(|e| e.status)
    }

    /// Number a fetch as it begins, so its answer can be ordered against
    /// others for the same purchase.
    fn begin(&self) -> u64 {
        self.fetches.fetch_add(1, Ordering::Relaxed)
    }

    /// Cache the answer of the fetch numbered `fetch`, unless an unexpired
    /// answer from a fetch that began later is cached: that one is newer.
    /// So a mint whose fetch hung or timed out never replaces what the link
    /// route (or a concurrent mint) learned meanwhile.
    fn record(&self, id: &SessionId, status: ClaimStatus, fetch: u64, now: i64) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.retain(|_, e| e.expires_at > now);
        if cache.get(id).is_some_and(|e| e.fetch > fetch) {
            return;
        }
        cache.insert(
            id.clone(),
            CacheEntry {
                status,
                expires_at: now + status.ttl(),
                fetch,
            },
        );
    }

    /// Cache an answer as if a fetch had just begun and ended at `now`.
    #[cfg(test)]
    fn remember(&self, id: &SessionId, status: ClaimStatus, now: i64) {
        let fetch = self.begin();
        self.record(id, status, fetch, now);
    }

    /// The market's answer, from the cache while it holds one. A mint reads
    /// the cache and fetches in [`Self::grant`]; this is the single-purchase
    /// form the tests use.
    #[cfg(test)]
    pub(crate) async fn status(&self, id: &SessionId) -> ClaimStatus {
        if let Some(status) = self.cached(id, Utc::now().timestamp()) {
            return status;
        }
        self.fresh_status(id).await
    }

    /// The market's answer, fetched now (the link asks fresh); cached for
    /// the next mint.
    pub(crate) async fn fresh_status(&self, id: &SessionId) -> ClaimStatus {
        let fetch = self.begin();
        let status = self.fetch(id).await;
        self.record(id, status, fetch, Utc::now().timestamp());
        status
    }

    async fn fetch(&self, id: &SessionId) -> ClaimStatus {
        let url = format!("{}/claim/{}", self.config.issuer, id.as_str());
        let response = match self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // The URL holds the session id.
                warn!(
                    "market claim fetch market_ref={} failed: {}",
                    id.log_ref(),
                    e.without_url()
                );
                return ClaimStatus::Unavailable;
            }
        };
        match response.status().as_u16() {
            200 => {}
            404 => return ClaimStatus::NotFound,
            410 => return ClaimStatus::Revoked,
            other => {
                warn!(
                    "market claim fetch market_ref={} answered {other}",
                    id.log_ref()
                );
                return ClaimStatus::Unavailable;
            }
        }
        if response
            .content_length()
            .is_some_and(|n| n > MARKET_CLAIM_MAX_BYTES as u64)
        {
            warn!("market claim market_ref={} is too large", id.log_ref());
            return ClaimStatus::Invalid;
        }
        let body = match response.bytes().await {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "market claim read market_ref={} failed: {}",
                    id.log_ref(),
                    e.without_url()
                );
                return ClaimStatus::Unavailable;
            }
        };
        if body.len() > MARKET_CLAIM_MAX_BYTES {
            warn!("market claim market_ref={} is too large", id.log_ref());
            return ClaimStatus::Invalid;
        }
        #[derive(Deserialize)]
        struct ClaimBody {
            claim: String,
        }
        let Ok(ClaimBody { claim }) = serde_json::from_slice(&body) else {
            warn!("market claim market_ref={} has no claim", id.log_ref());
            return ClaimStatus::Invalid;
        };
        match verify_claim(&self.config, &claim, id) {
            Ok(v) => ClaimStatus::Valid(v.tier),
            Err(e) => {
                warn!(
                    "market claim market_ref={} does not verify: {e}",
                    id.log_ref()
                );
                ClaimStatus::Invalid
            }
        }
    }

    /// What the account's linked purchases (`links`, the `market_links` ids)
    /// grant at this mint, within [`MARKET_FETCH_DEADLINE_SECONDS`] in all.
    /// A purchase that verifies decides (a lifetime membership grants every
    /// paid feature). A test-mode purchase while test mode is off is skipped,
    /// not fetched: a definite "no", never "unavailable".
    ///
    /// Cached answers are read first, so a purchase cached as valid grants at
    /// once without waiting on another that must be fetched. The rest are
    /// fetched in turn until the deadline. One that misses it is cached as
    /// [`ClaimStatus::Unavailable`] (60 s), so a hung market does not make
    /// every mint wait again; one not reached before the deadline is left
    /// uncached and counts as unavailable.
    pub(crate) async fn grant(&self, links: &[String]) -> MarketGrant {
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(MARKET_FETCH_DEADLINE_SECONDS);
        let now = Utc::now().timestamp();
        let mut unavailable = false;
        let mut to_fetch = Vec::new();
        for link in links {
            let Some(id) = SessionId::parse(link) else {
                warn!("unreadable market link on an account; skipped");
                continue;
            };
            if !id.livemode() && !self.config.accept_test_mode {
                continue;
            }
            match self.cached(&id, now) {
                Some(ClaimStatus::Valid(tier)) => return granted(&id, tier),
                Some(ClaimStatus::Revoked | ClaimStatus::NotFound) => {}
                Some(ClaimStatus::Invalid | ClaimStatus::Unavailable) => unavailable = true,
                None => to_fetch.push(id),
            }
        }
        for id in to_fetch {
            if tokio::time::Instant::now() >= deadline {
                // Not reached in time: unknown, so not cached.
                unavailable = true;
                break;
            }
            let fetch = self.begin();
            let status = match tokio::time::timeout_at(deadline, self.fetch(&id)).await {
                Ok(status) => status,
                Err(_) => {
                    warn!(
                        "market check market_ref={} missed the {}s mint deadline",
                        id.log_ref(),
                        MARKET_FETCH_DEADLINE_SECONDS
                    );
                    ClaimStatus::Unavailable
                }
            };
            // Cached either way (a deadline miss as a failure), unless a fetch
            // that began later has answered meanwhile.
            self.record(&id, status, fetch, Utc::now().timestamp());
            match status {
                ClaimStatus::Valid(tier) => return granted(&id, tier),
                ClaimStatus::Revoked | ClaimStatus::NotFound => {}
                ClaimStatus::Invalid | ClaimStatus::Unavailable => unavailable = true,
            }
        }
        if unavailable {
            MarketGrant::Unavailable
        } else {
            MarketGrant::NotGranted
        }
    }
}

/// The grant of a purchase that verified, logging a test-mode one.
fn granted(id: &SessionId, tier: Tier) -> MarketGrant {
    if !id.livemode() {
        info!(
            "market purchase market_ref={} grants from a Stripe test-mode claim",
            id.log_ref()
        );
    }
    MarketGrant::Granted(tier.entitlements())
}

// --------- POST /market/link ---------

const ERR_INVALID: &str = "invalid_claim";
const ERR_REVOKED: &str = "revoked";
const ERR_ALREADY_LINKED: &str = "already_linked";
const ERR_UNAVAILABLE: &str = "market_unavailable";

#[derive(Deserialize)]
struct LinkRequest {
    claim: String,
}

#[derive(Serialize)]
struct LinkResponse {
    tier: &'static str,
    livemode: bool,
    /// What the tier grants. A publishing suspension withholds it from a
    /// token, so this is not a promise about the next one.
    entitlements: Vec<String>,
    /// Whether the presented token already carries the creator-publishing
    /// entitlement; `false` tells the client to renew its token.
    token_can_publish: bool,
}

fn refuse(status: StatusCode, error: &'static str) -> Response {
    (status, Json(serde_json::json!({ "error": error }))).into_response()
}

/// What the request's one log line says: the outcome and the purchase's
/// [`SessionId::log_ref`], never the id or the claim.
struct Trace {
    outcome: &'static str,
    market_ref: Option<String>,
}

/// `POST /market/link`: link the purchase a pasted claim names to the caller.
///
/// Order: the feature is configured (503), the caller authenticates and still
/// exists (401), the body names a purchase (400 `invalid_claim`), a test-mode
/// purchase only while test mode is on (400, before any fetch), the market
/// is asked fresh (`410` ⇒ 409 `revoked`; `404` or a claim that does not
/// verify ⇒ 400 `invalid_claim`; anything else ⇒ 503 `market_unavailable`),
/// then the link is written (another live account's ⇒ 409
/// `already_linked`; the caller deleted meanwhile ⇒ 401).
pub(crate) async fn link_handler(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut trace = Trace {
        outcome: "refused",
        market_ref: None,
    };
    let response = post_link(&app_state, &headers, &body, &mut trace).await;
    info!(
        "market link outcome={} market_ref={} status={}",
        trace.outcome,
        trace.market_ref.as_deref().unwrap_or("-"),
        response.status().as_u16()
    );
    response
}

async fn post_link(
    app_state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    trace: &mut Trace,
) -> Response {
    let Some(source) = app_state.market.as_ref() else {
        trace.outcome = "unconfigured";
        return refuse(StatusCode::SERVICE_UNAVAILABLE, ERR_UNAVAILABLE);
    };
    let caller = match crate::authn::authenticated_live_account(app_state, headers).await {
        Ok(account) => account,
        Err(status) => return status.into_response(),
    };
    // Parsed after authentication, so a caller without a token learns
    // nothing about what the body should look like.
    let Ok(LinkRequest { claim }) = serde_json::from_slice(body) else {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID);
    };
    let Some(id) = pasted_session_id(&claim) else {
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID);
    };
    trace.market_ref = Some(id.log_ref());
    if !id.livemode() && !source.config.accept_test_mode {
        trace.outcome = "test_mode";
        return refuse(StatusCode::BAD_REQUEST, ERR_INVALID);
    }

    let tier = match source.fresh_status(&id).await {
        ClaimStatus::Valid(tier) => tier,
        ClaimStatus::Revoked => {
            trace.outcome = "revoked";
            return refuse(StatusCode::CONFLICT, ERR_REVOKED);
        }
        ClaimStatus::NotFound | ClaimStatus::Invalid => {
            trace.outcome = "invalid";
            return refuse(StatusCode::BAD_REQUEST, ERR_INVALID);
        }
        ClaimStatus::Unavailable => {
            trace.outcome = "unavailable";
            return refuse(StatusCode::SERVICE_UNAVAILABLE, ERR_UNAVAILABLE);
        }
    };

    match app_state
        .db_store
        .link_market_purchase(id.as_str(), &caller.user_id)
        .await
    {
        Ok(MarketLinkOutcome::Elsewhere) => {
            trace.outcome = "elsewhere";
            return refuse(StatusCode::CONFLICT, ERR_ALREADY_LINKED);
        }
        Ok(MarketLinkOutcome::Linked) => trace.outcome = "linked",
        Ok(MarketLinkOutcome::AlreadyYours) => trace.outcome = "already_yours",
        Ok(MarketLinkOutcome::Moved) => trace.outcome = "moved",
        Err(DynamoDBError::AccountGone) => {
            trace.outcome = "account_gone";
            return StatusCode::UNAUTHORIZED.into_response();
        }
        Err(e) => {
            error!("market link: storage failed: {e}");
            trace.outcome = "error";
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    Json(LinkResponse {
        tier: tier.as_str(),
        livemode: id.livemode(),
        entitlements: tier.entitlements(),
        token_can_publish: caller.token_can_publish,
    })
    .into_response()
}

#[cfg(test)]
mod tests;
