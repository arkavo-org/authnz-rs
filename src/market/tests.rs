//! market.arkavo.com source (#141): claim verification and the pinned-key
//! configuration (pure), the fetch, cache and mint grant against a local
//! market (an axum server on 127.0.0.1, no network), and `POST /market/link`
//! plus the mint derivation against DynamoDB Local (those return early
//! unless `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set, as CI's `test` job sets it).

use super::*;
use crate::db::{DynamoDBStore, PublishingSuspension};
use crate::publishing::DeriveError;
use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::Request;
use axum::routing::{get, post};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tower::ServiceExt;
use uuid::Uuid;

/// The key market.arkavo.com published at `/.well-known/jwks.json` on
/// 2026-11-08: its `kid` is its RFC 7638 thumbprint, as the contract says.
const LIVE_MARKET_JWKS: &str = r#"{"keys":[{"alg":"ES256","crv":"P-256","kid":"O4fOSh3MhOPixje-MoGlTO9VL3ycolT2o0a7cBv3gGc","kty":"EC","use":"sig","x":"eDzZ5T1-l5R6BXuO90KM-4QmIEtqo1IY6JTDsdB8huc","y":"i6olis865zkSMcg9NTrlHijFrnB4am6vkiUa2hcevXU"}]}"#;

const AUDIENCE: &str = "https://identity.example";
const ISSUER: &str = "https://market.example";

fn key() -> SigningKey {
    SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng)
}

fn kid_of(key: &SigningKey) -> String {
    let point = key.verifying_key().to_encoded_point(false);
    thumbprint(point.x().unwrap(), point.y().unwrap())
}

fn jwk_of(key: &SigningKey) -> Value {
    let point = key.verifying_key().to_encoded_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": kid_of(key),
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    })
}

fn sign(key: &SigningKey, header: &Value, payload: &Value) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    let sig: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

fn live_id() -> SessionId {
    SessionId::parse(&format!("cs_live_{}", Uuid::new_v4().simple())).unwrap()
}

fn test_id() -> SessionId {
    SessionId::parse(&format!("cs_test_{}", Uuid::new_v4().simple())).unwrap()
}

fn header(key: &SigningKey) -> Value {
    json!({"alg": "ES256", "kid": kid_of(key), "typ": "JWT"})
}

/// The payload the market signs for `id`, with `overrides` merged in.
fn payload(issuer: &str, audience: &str, id: &SessionId, overrides: Value) -> Value {
    let mut p = json!({
        "iss": issuer,
        "aud": audience,
        "jti": id.jti(),
        "tier": "lifetime",
        "offer": "arkavo-lifetime-creator-membership",
        "amount": 49_900,
        "currency": "USD",
        "livemode": id.livemode(),
        "iat": 1_793_923_200,
    });
    if let (Some(p), Some(o)) = (p.as_object_mut(), overrides.as_object()) {
        for (k, v) in o {
            if v.is_null() {
                p.remove(k);
            } else {
                p.insert(k.clone(), v.clone());
            }
        }
    }
    p
}

fn claim_for(key: &SigningKey, cfg: &MarketConfig, id: &SessionId, overrides: Value) -> String {
    sign(
        key,
        &header(key),
        &payload(&cfg.issuer, &cfg.audience, id, overrides),
    )
}

// --------- Configuration ---------

#[test]
fn the_live_market_key_pins_under_its_published_kid() {
    let keys = parse_jwk_set(LIVE_MARKET_JWKS).expect("the live JWKS pins");
    assert_eq!(
        keys.keys().collect::<Vec<_>>(),
        vec!["O4fOSh3MhOPixje-MoGlTO9VL3ycolT2o0a7cBv3gGc"]
    );
}

#[test]
fn a_jwk_set_with_a_wrong_or_unsafe_key_is_refused() {
    let k = key();
    let good = jwk_of(&k);
    let with = |patch: Value| {
        let mut j = good.clone();
        for (name, v) in patch.as_object().unwrap() {
            if v.is_null() {
                j.as_object_mut().unwrap().remove(name);
            } else {
                j[name] = v.clone();
            }
        }
        json!({ "keys": [j] }).to_string()
    };
    assert!(parse_jwk_set(&json!({ "keys": [good.clone()] }).to_string()).is_ok());
    assert!(parse_jwk_set(&with(json!({"alg": "ES256"}))).is_ok());
    for (what, set) in [
        ("another key's kid", with(json!({"kid": kid_of(&key())}))),
        ("no kid", with(json!({"kid": null}))),
        ("a private key", with(json!({"d": "AAAA"}))),
        ("another curve", with(json!({"crv": "P-384"}))),
        ("another type", with(json!({"kty": "OKP"}))),
        ("another algorithm", with(json!({"alg": "ES384"}))),
        ("a short coordinate", with(json!({"x": "AAAA"}))),
        ("no y", with(json!({"y": null}))),
        (
            "twice",
            json!({ "keys": [good.clone(), good.clone()] }).to_string(),
        ),
        ("no keys", json!({ "keys": [] }).to_string()),
        ("not a set", "[]".to_string()),
    ] {
        assert!(parse_jwk_set(&set).is_err(), "{what}");
    }
    // A point that is not on the curve.
    let off_curve = with(json!({"y": URL_SAFE_NO_PAD.encode([1u8; 32])}));
    assert!(parse_jwk_set(&off_curve).is_err());
}

#[test]
fn config_is_off_unless_issuer_and_keys_are_set() {
    assert!(
        MarketConfig::parse(None, None, None, AUDIENCE)
            .unwrap()
            .is_none()
    );
    assert!(
        MarketConfig::parse(Some(ISSUER), None, None, AUDIENCE)
            .unwrap()
            .is_none()
    );
    assert!(
        MarketConfig::parse(Some("  "), Some(LIVE_MARKET_JWKS), None, AUDIENCE)
            .unwrap()
            .is_none()
    );
    let cfg = MarketConfig::parse(
        Some("https://market.arkavo.com/"),
        Some(LIVE_MARKET_JWKS),
        None,
        "https://identity.arkavo.net",
    )
    .unwrap()
    .unwrap();
    assert_eq!(cfg.issuer, "https://market.arkavo.com");
    assert_eq!(cfg.audience, "https://identity.arkavo.net");
    assert!(!cfg.accept_test_mode);
    for (v, accepted) in [
        ("true", true),
        ("TRUE", true),
        ("false", false),
        (" ", false),
    ] {
        let cfg = MarketConfig::parse(Some(ISSUER), Some(LIVE_MARKET_JWKS), Some(v), AUDIENCE)
            .unwrap()
            .unwrap();
        assert_eq!(cfg.accept_test_mode, accepted, "{v:?}");
    }
}

#[test]
fn config_set_but_unusable_is_an_error() {
    for (issuer, keys, test_mode) in [
        ("market.arkavo.com", LIVE_MARKET_JWKS, None),
        ("ftp://market.arkavo.com", LIVE_MARKET_JWKS, None),
        ("https://market.arkavo.com?x=1", LIVE_MARKET_JWKS, None),
        (ISSUER, "{\"keys\":[]}", None),
        (ISSUER, LIVE_MARKET_JWKS, Some("yes")),
    ] {
        assert!(
            MarketConfig::parse(Some(issuer), Some(keys), test_mode, AUDIENCE).is_err(),
            "{issuer} {keys} {test_mode:?}"
        );
    }
}

// --------- The purchase id ---------

#[test]
fn session_ids_parse_strictly_and_never_print() {
    let id = SessionId::parse("cs_live_a1B2c3_D4").unwrap();
    assert!(id.livemode());
    assert_eq!(id.jti(), "market#cs_live_a1B2c3_D4");
    assert!(!SessionId::parse("cs_test_a1").unwrap().livemode());
    for bad in [
        "",
        "cs_live_",
        "cs_live_a/b",
        "cs_live_a.b",
        "cs_live_a%2F",
        "cs_live_ä",
        "cs_other_a1",
        "pi_live_a1",
        "CS_LIVE_a1",
    ] {
        assert!(SessionId::parse(bad).is_none(), "{bad:?}");
    }
    let long = format!("cs_live_{}", "a".repeat(SESSION_ID_MAX_LEN));
    assert!(SessionId::parse(&long).is_none());
    assert_eq!(
        SessionId::from_jti("market#cs_live_x1"),
        SessionId::parse("cs_live_x1")
    );
    assert!(SessionId::from_jti("cs_live_x1").is_none());
    assert!(SessionId::from_jti("appstore#cs_live_x1").is_none());

    // The id is the purchase's bearer secret.
    assert!(!format!("{id:?}").contains("a1B2c3"));
    assert_eq!(id.log_ref().len(), 12);
    assert!(!id.log_ref().contains("a1B2c3"));
}

// --------- Claim verification ---------

#[test]
fn a_claim_verifies_only_when_every_check_passes() {
    let k = key();
    let cfg = MarketConfig::for_tests(ISSUER, AUDIENCE, &k);
    let id = live_id();
    let ok = claim_for(&k, &cfg, &id, json!({}));
    assert_eq!(
        verify_claim(&cfg, &ok, &id),
        Ok(VerifiedClaim {
            tier: Tier::Lifetime,
            livemode: true
        })
    );
    // An `aud` array naming this identity is accepted, as JWT allows.
    let aud_list = claim_for(&k, &cfg, &id, json!({"aud": ["x", AUDIENCE]}));
    assert!(verify_claim(&cfg, &aud_list, &id).is_ok());

    let p = |o: Value| payload(&cfg.issuer, &cfg.audience, &id, o);
    let h = header(&k);
    let other = key();
    // The signature of `ok` over another payload.
    let tampered = {
        let (h64, _, s64) = segments(&ok).unwrap();
        let p64 = URL_SAFE_NO_PAD.encode(p(json!({"amount": 1})).to_string());
        format!("{h64}.{p64}.{s64}")
    };
    let cases: Vec<(&str, String, ClaimError)> = vec![
        (
            "alg none",
            sign(
                &k,
                &json!({"alg": "none", "kid": kid_of(&k), "typ": "JWT"}),
                &p(json!({})),
            ),
            ClaimError::Malformed,
        ),
        (
            "alg ES384",
            sign(
                &k,
                &json!({"alg": "ES384", "kid": kid_of(&k), "typ": "JWT"}),
                &p(json!({})),
            ),
            ClaimError::Malformed,
        ),
        (
            "no typ",
            sign(
                &k,
                &json!({"alg": "ES256", "kid": kid_of(&k)}),
                &p(json!({})),
            ),
            ClaimError::Malformed,
        ),
        (
            "crit",
            sign(
                &k,
                &json!({"alg": "ES256", "kid": kid_of(&k), "typ": "JWT", "crit": ["b64"]}),
                &p(json!({})),
            ),
            ClaimError::Malformed,
        ),
        (
            "no kid",
            sign(&k, &json!({"alg": "ES256", "typ": "JWT"}), &p(json!({}))),
            ClaimError::Malformed,
        ),
        (
            "an unpinned key",
            sign(&other, &header(&other), &p(json!({}))),
            ClaimError::UnknownKey,
        ),
        (
            "another key under the pinned kid",
            sign(&other, &h, &p(json!({}))),
            ClaimError::InvalidSignature,
        ),
        ("a changed payload", tampered, ClaimError::InvalidSignature),
        (
            "wrong issuer",
            sign(&k, &h, &p(json!({"iss": "https://market.evil"}))),
            ClaimError::WrongIssuer,
        ),
        (
            "no issuer",
            sign(&k, &h, &p(json!({"iss": null}))),
            ClaimError::WrongIssuer,
        ),
        (
            "wrong audience",
            sign(&k, &h, &p(json!({"aud": "https://other.example"}))),
            ClaimError::WrongAudience,
        ),
        (
            "no audience",
            sign(&k, &h, &p(json!({"aud": null}))),
            ClaimError::WrongAudience,
        ),
        (
            "another purchase",
            sign(&k, &h, &p(json!({"jti": live_id().jti()}))),
            ClaimError::WrongPurchase,
        ),
        (
            "the bare session id",
            sign(&k, &h, &p(json!({"jti": id.as_str()}))),
            ClaimError::WrongPurchase,
        ),
        (
            "unknown tier",
            sign(&k, &h, &p(json!({"tier": "monthly"}))),
            ClaimError::UnknownTier,
        ),
        (
            "no livemode",
            sign(&k, &h, &p(json!({"livemode": null}))),
            ClaimError::Malformed,
        ),
        (
            "livemode false on a cs_live_ id",
            sign(&k, &h, &p(json!({"livemode": false}))),
            ClaimError::ModeMismatch,
        ),
        ("four segments", format!("{ok}.x"), ClaimError::Malformed),
        (
            "two segments",
            ok.rsplit_once('.').unwrap().0.to_string(),
            ClaimError::Malformed,
        ),
        ("not base64", "!!.!!.!!".to_string(), ClaimError::Malformed),
    ];
    for (what, jws, want) in cases {
        assert_eq!(verify_claim(&cfg, &jws, &id), Err(want), "{what}");
    }
}

#[test]
fn a_test_mode_claim_verifies_only_while_test_mode_is_on() {
    let k = key();
    let mut cfg = MarketConfig::for_tests(ISSUER, AUDIENCE, &k);
    let id = test_id();
    let claim = claim_for(&k, &cfg, &id, json!({}));
    assert_eq!(verify_claim(&cfg, &claim, &id), Err(ClaimError::TestMode));
    cfg.accept_test_mode = true;
    assert_eq!(
        verify_claim(&cfg, &claim, &id),
        Ok(VerifiedClaim {
            tier: Tier::Lifetime,
            livemode: false
        })
    );
    // A test-mode id whose claim says live is refused either way.
    let mismatch = claim_for(&k, &cfg, &id, json!({"livemode": true}));
    assert_eq!(
        verify_claim(&cfg, &mismatch, &id),
        Err(ClaimError::ModeMismatch)
    );
}

/// The market signs with ring, which does not normalise S, so about half
/// its claims carry a high S. p256 verifies those; this pins it, so an
/// upgrade that starts refusing high S fails here, not on half the claims.
#[test]
fn a_high_s_signature_verifies() {
    let k = key();
    let cfg = MarketConfig::for_tests(ISSUER, AUDIENCE, &k);
    let id = live_id();
    let low = claim_for(&k, &cfg, &id, json!({}));
    let (input, sig_b64) = low.rsplit_once('.').unwrap();
    let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(sig_b64).unwrap()).unwrap();
    let (r, s) = sig.split_scalars();
    let high = Signature::from_scalars(r, -*s).unwrap();
    assert!(
        high.normalize_s().is_some(),
        "the negated S is the high one"
    );
    let claim = format!("{input}.{}", URL_SAFE_NO_PAD.encode(high.to_bytes()));
    assert!(verify_claim(&cfg, &claim, &id).is_ok());
}

#[test]
fn a_pasted_claim_names_its_purchase_unverified() {
    let k = key();
    let cfg = MarketConfig::for_tests(ISSUER, AUDIENCE, &k);
    let id = live_id();
    // Signed by a key that is not pinned (a claim saved before a rotation):
    // it still names the purchase; the link verifies the fresh one.
    let other = key();
    let saved = sign(
        &other,
        &header(&other),
        &payload(ISSUER, AUDIENCE, &id, json!({})),
    );
    assert_eq!(pasted_session_id(&saved), Some(id.clone()));
    assert_eq!(pasted_session_id(&format!("  {saved}\n")), Some(id.clone()));
    assert_eq!(
        pasted_session_id(&claim_for(&k, &cfg, &id, json!({}))),
        Some(id)
    );
    for bad in [
        sign(
            &k,
            &header(&k),
            &payload(ISSUER, AUDIENCE, &live_id(), json!({"jti": "cs_live_x"})),
        ),
        sign(
            &k,
            &header(&k),
            &payload(ISSUER, AUDIENCE, &live_id(), json!({"jti": null})),
        ),
        sign(
            &k,
            &header(&k),
            &payload(
                ISSUER,
                AUDIENCE,
                &live_id(),
                json!({"jti": "market#cs_live_a/b"}),
            ),
        ),
        "not a claim".to_string(),
        format!("a.{}.c", "A".repeat(PASTED_CLAIM_MAX_LEN)),
    ] {
        assert!(pasted_session_id(&bad).is_none(), "{bad}");
    }
}

#[test]
fn the_lifetime_tier_grants_every_paid_feature_today() {
    assert_eq!(
        Tier::Lifetime.entitlements(),
        vec![ENTITLEMENT_CREATOR_PUBLISH.to_string()]
    );
    // Derived-only, so never stored and never delegated to an agent.
    for e in Tier::Lifetime.entitlements() {
        assert!(crate::constants::is_derived_only(&e), "{e}");
    }
}

// --------- A local market ---------

#[derive(Clone)]
enum Answer {
    /// 200 `{"claim": …}`.
    Claim(String),
    /// 200 with this body.
    Body(String),
    /// This status, empty body.
    Status(u16),
    /// A redirect to a valid claim's URL.
    Redirect,
    /// Never answers within the deadline.
    Slow,
}

#[derive(Clone, Default)]
struct Market {
    answers: Arc<Mutex<HashMap<String, Answer>>>,
    hits: Arc<AtomicUsize>,
}

impl Market {
    fn answer(&self, id: &SessionId, answer: Answer) {
        self.answers
            .lock()
            .unwrap()
            .insert(id.as_str().to_string(), answer);
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

async fn claim_route(
    State(m): State<Market>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    m.hits.fetch_add(1, Ordering::SeqCst);
    // The contract: JSON asked for, no credentials sent.
    if headers.get("accept").and_then(|v| v.to_str().ok()) != Some("application/json") {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    }
    if headers.contains_key("authorization") || headers.contains_key("x-auth-token") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let answer = m.answers.lock().unwrap().get(&id).cloned();
    match answer {
        None => StatusCode::NOT_FOUND.into_response(),
        Some(Answer::Claim(c)) => Json(json!({ "claim": c })).into_response(),
        Some(Answer::Body(b)) => b.into_response(),
        Some(Answer::Status(s)) => StatusCode::from_u16(s).unwrap().into_response(),
        Some(Answer::Redirect) => {
            (StatusCode::FOUND, [("location", "/claim/elsewhere")]).into_response()
        }
        Some(Answer::Slow) => {
            tokio::time::sleep(Duration::from_secs(MARKET_FETCH_DEADLINE_SECONDS + 5)).await;
            StatusCode::OK.into_response()
        }
    }
}

/// A local market and a source pointed at it, verifying with `key`.
struct Harness {
    key: SigningKey,
    market: Market,
    source: MarketSource,
}

impl Harness {
    async fn new(audience: &str) -> Self {
        let market = Market::default();
        let app = Router::new()
            .route("/claim/:id", get(claim_route))
            .with_state(market.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let key = key();
        let source = MarketSource::new(MarketConfig::for_tests(&base, audience, &key)).unwrap();
        Self {
            key,
            market,
            source,
        }
    }

    fn claim(&self, id: &SessionId, overrides: Value) -> String {
        claim_for(&self.key, &self.source.config, id, overrides)
    }

    /// A purchase the market answers with a valid claim.
    fn valid(&self) -> SessionId {
        let id = live_id();
        self.market
            .answer(&id, Answer::Claim(self.claim(&id, json!({}))));
        id
    }

    fn with(&self, answer: Answer) -> SessionId {
        let id = live_id();
        self.market.answer(&id, answer);
        id
    }
}

#[tokio::test]
async fn market_answers_map_to_statuses() {
    let h = Harness::new(AUDIENCE).await;
    let other = key();
    let unpinned = live_id();
    h.market.answer(
        &unpinned,
        Answer::Claim(sign(
            &other,
            &header(&other),
            &payload(&h.source.config.issuer, AUDIENCE, &unpinned, json!({})),
        )),
    );
    let someone_elses = live_id();
    let cases = [
        (h.valid(), ClaimStatus::Valid(Tier::Lifetime)),
        (h.with(Answer::Status(410)), ClaimStatus::Revoked),
        (live_id(), ClaimStatus::NotFound),
        (h.with(Answer::Status(500)), ClaimStatus::Unavailable),
        (h.with(Answer::Status(503)), ClaimStatus::Unavailable),
        (h.with(Answer::Status(401)), ClaimStatus::Unavailable),
        (h.with(Answer::Redirect), ClaimStatus::Unavailable),
        (unpinned, ClaimStatus::Invalid),
        (
            h.with(Answer::Claim(h.claim(&someone_elses, json!({})))),
            ClaimStatus::Invalid,
        ),
        (h.with(Answer::Body("{}".into())), ClaimStatus::Invalid),
        (
            h.with(Answer::Body("not json".into())),
            ClaimStatus::Invalid,
        ),
        (
            h.with(Answer::Body("x".repeat(MARKET_CLAIM_MAX_BYTES + 1))),
            ClaimStatus::Invalid,
        ),
    ];
    for (id, want) in cases {
        assert_eq!(h.source.fresh_status(&id).await, want, "{id:?}");
    }
}

#[tokio::test]
async fn an_unreachable_market_is_unavailable() {
    // A port nothing listens on.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let source = MarketSource::new(MarketConfig::for_tests(&base, AUDIENCE, &key())).unwrap();
    assert_eq!(source.status(&live_id()).await, ClaimStatus::Unavailable);
}

#[tokio::test]
async fn answers_are_cached_failures_briefly_and_the_link_asks_fresh() {
    assert_eq!(ClaimStatus::Valid(Tier::Lifetime).ttl(), 300);
    assert_eq!(ClaimStatus::Revoked.ttl(), 300);
    assert_eq!(ClaimStatus::NotFound.ttl(), 300);
    assert_eq!(ClaimStatus::Invalid.ttl(), 60);
    assert_eq!(ClaimStatus::Unavailable.ttl(), 60);

    let h = Harness::new(AUDIENCE).await;
    let id = h.valid();
    assert_eq!(
        h.source.status(&id).await,
        ClaimStatus::Valid(Tier::Lifetime)
    );
    assert_eq!(
        h.source.status(&id).await,
        ClaimStatus::Valid(Tier::Lifetime)
    );
    assert_eq!(h.market.hits(), 1, "the second mint reads the cache");

    // A refund is seen once the cached answer expires.
    h.market.answer(&id, Answer::Status(410));
    assert_eq!(
        h.source.status(&id).await,
        ClaimStatus::Valid(Tier::Lifetime)
    );
    let now = Utc::now().timestamp();
    h.source.remember(
        &id,
        ClaimStatus::Valid(Tier::Lifetime),
        now - MARKET_CACHE_TTL_SECONDS - 1,
    );
    assert_eq!(h.source.status(&id).await, ClaimStatus::Revoked);
    assert_eq!(h.market.hits(), 2);

    // A failure is cached too (60 s), so an outage is not hammered.
    let down = h.with(Answer::Status(502));
    assert_eq!(h.source.status(&down).await, ClaimStatus::Unavailable);
    h.market
        .answer(&down, Answer::Claim(h.claim(&down, json!({}))));
    assert_eq!(h.source.status(&down).await, ClaimStatus::Unavailable);
    assert_eq!(h.market.hits(), 3);

    // The link asks fresh, and its answer serves the next mint.
    assert_eq!(
        h.source.fresh_status(&down).await,
        ClaimStatus::Valid(Tier::Lifetime)
    );
    assert_eq!(
        h.source.status(&down).await,
        ClaimStatus::Valid(Tier::Lifetime)
    );
    assert_eq!(h.market.hits(), 4);
}

fn links(ids: &[&SessionId]) -> Vec<String> {
    ids.iter().map(|id| id.as_str().to_string()).collect()
}

#[tokio::test]
async fn grant_takes_a_verified_purchase_and_skips_test_mode() {
    let h = Harness::new(AUDIENCE).await;
    let (refunded, valid) = (h.with(Answer::Status(410)), h.valid());
    assert_eq!(
        h.source.grant(&links(&[&refunded, &valid])).await,
        MarketGrant::Granted(vec![ENTITLEMENT_CREATOR_PUBLISH.to_string()])
    );
    assert_eq!(
        h.source.grant(&links(&[&refunded, &live_id()])).await,
        MarketGrant::NotGranted
    );
    assert_eq!(h.source.grant(&[]).await, MarketGrant::NotGranted);
    // An unreadable stored id is skipped.
    assert_eq!(
        h.source.grant(&["not-an-id".to_string()]).await,
        MarketGrant::NotGranted
    );

    // A test-mode purchase while test mode is off: a definite "no", never
    // fetched (so never "unavailable").
    let test = test_id();
    h.market.answer(&test, Answer::Status(500));
    let before = h.market.hits();
    assert_eq!(
        h.source.grant(&links(&[&test])).await,
        MarketGrant::NotGranted
    );
    assert_eq!(h.market.hits(), before);
}

#[tokio::test]
async fn grant_in_test_mode_takes_a_test_purchase() {
    let mut h = Harness::new(AUDIENCE).await;
    h.source.config.accept_test_mode = true;
    let test = test_id();
    h.market
        .answer(&test, Answer::Claim(h.claim(&test, json!({}))));
    assert_eq!(
        h.source.grant(&links(&[&test])).await,
        MarketGrant::Granted(vec![ENTITLEMENT_CREATOR_PUBLISH.to_string()])
    );
}

#[tokio::test]
async fn grant_is_unavailable_when_a_purchase_cannot_be_checked() {
    let h = Harness::new(AUDIENCE).await;
    let (refunded, down, bad) = (
        h.with(Answer::Status(410)),
        h.with(Answer::Status(500)),
        h.with(Answer::Body("{}".into())),
    );
    assert_eq!(
        h.source.grant(&links(&[&refunded, &down])).await,
        MarketGrant::Unavailable
    );
    assert_eq!(
        h.source.grant(&links(&[&bad])).await,
        MarketGrant::Unavailable
    );
    // A verified purchase decides even when another cannot be checked.
    let valid = h.valid();
    assert!(matches!(
        h.source.grant(&links(&[&down, &valid])).await,
        MarketGrant::Granted(_)
    ));
}

#[tokio::test]
async fn grant_gives_up_at_the_mint_deadline_and_caches_the_miss() {
    let h = Harness::new(AUDIENCE).await;
    let slow = h.with(Answer::Slow);
    let started = std::time::Instant::now();
    assert_eq!(
        h.source.grant(&links(&[&slow])).await,
        MarketGrant::Unavailable
    );
    let waited = started.elapsed();
    assert!(
        waited < Duration::from_secs(MARKET_FETCH_DEADLINE_SECONDS + 2),
        "{waited:?}"
    );
    assert_eq!(h.market.hits(), 1);

    // The miss is cached as a failure (60 s): the next mint neither fetches
    // nor waits.
    let started = std::time::Instant::now();
    assert_eq!(
        h.source.grant(&links(&[&slow])).await,
        MarketGrant::Unavailable
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(h.market.hits(), 1);
}

/// A mint whose fetch misses the deadline does not overwrite an answer
/// another request (here: the link route's fresh fetch) cached meanwhile.
#[tokio::test]
async fn a_deadline_miss_keeps_an_answer_cached_meanwhile() {
    let h = Harness::new(AUDIENCE).await;
    let slow = h.with(Answer::Slow);
    let slow_links = links(&[&slow]);
    let (grant, ()) = tokio::join!(h.source.grant(&slow_links), async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        h.source.remember(
            &slow,
            ClaimStatus::Valid(Tier::Lifetime),
            Utc::now().timestamp(),
        );
    });
    assert_eq!(grant, MarketGrant::Unavailable);
    assert_eq!(
        h.source.cached(&slow, Utc::now().timestamp()),
        Some(ClaimStatus::Valid(Tier::Lifetime))
    );
    assert!(matches!(
        h.source.grant(&links(&[&slow])).await,
        MarketGrant::Granted(_)
    ));
}

/// An answer from an earlier fetch never replaces one from a later fetch.
#[test]
fn a_later_fetch_wins() {
    let source = MarketSource::new(MarketConfig::for_tests(ISSUER, AUDIENCE, &key())).unwrap();
    let id = live_id();
    let now = Utc::now().timestamp();
    let (early, late) = (source.begin(), source.begin());
    source.record(&id, ClaimStatus::Valid(Tier::Lifetime), late, now);
    source.record(&id, ClaimStatus::Unavailable, early, now);
    assert_eq!(
        source.cached(&id, now),
        Some(ClaimStatus::Valid(Tier::Lifetime))
    );
    // A later one replaces an earlier one, whatever it says.
    source.record(&id, ClaimStatus::Revoked, source.begin(), now);
    assert_eq!(source.cached(&id, now), Some(ClaimStatus::Revoked));
    // An expired later answer does not block an earlier one.
    let stale = source.begin();
    source.record(&id, ClaimStatus::NotFound, source.begin(), now - 1_000);
    source.record(&id, ClaimStatus::Unavailable, stale, now);
    assert_eq!(source.cached(&id, now), Some(ClaimStatus::Unavailable));
}

/// A fetch the mint deadline cut short carries no answer: it never replaces
/// one, and any real answer replaces it, however the fetches are ordered.
#[test]
fn a_cut_off_fetch_never_outranks_a_real_answer() {
    let source = MarketSource::new(MarketConfig::for_tests(ISSUER, AUDIENCE, &key())).unwrap();
    let now = Utc::now().timestamp();

    // The link's fetch began first and answers after the mint's cut-off.
    let id = live_id();
    let (link, mint) = (source.begin(), source.begin());
    source.record_cut_off(&id, mint, now);
    assert_eq!(source.cached(&id, now), Some(ClaimStatus::Unavailable));
    source.record(&id, ClaimStatus::Valid(Tier::Lifetime), link, now);
    assert_eq!(
        source.cached(&id, now),
        Some(ClaimStatus::Valid(Tier::Lifetime))
    );

    // A cut-off after a real answer leaves it, even a later-begun one.
    source.record_cut_off(&id, source.begin(), now);
    assert_eq!(
        source.cached(&id, now),
        Some(ClaimStatus::Valid(Tier::Lifetime))
    );

    // With nothing cached, the cut-off is cached as a failure.
    let fresh = live_id();
    source.record_cut_off(&fresh, source.begin(), now);
    assert_eq!(source.cached(&fresh, now), Some(ClaimStatus::Unavailable));
}

#[tokio::test]
async fn a_hung_purchase_does_not_hide_a_valid_one() {
    let h = Harness::new(AUDIENCE).await;
    let (slow, valid) = (h.with(Answer::Slow), h.valid());

    // The hung purchase uses up the deadline before the valid one is
    // fetched, so this mint cannot tell.
    assert_eq!(
        h.source.grant(&links(&[&slow, &valid])).await,
        MarketGrant::Unavailable
    );
    // The next mint skips the cached miss and fetches the valid one.
    assert!(matches!(
        h.source.grant(&links(&[&slow, &valid])).await,
        MarketGrant::Granted(_)
    ));
    // Once cached, a valid purchase grants at once, whatever comes first.
    let other_slow = h.with(Answer::Slow);
    let hits = h.market.hits();
    let started = std::time::Instant::now();
    assert!(matches!(
        h.source.grant(&links(&[&other_slow, &valid])).await,
        MarketGrant::Granted(_)
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(h.market.hits(), hits, "nothing fetched");
}

// --------- POST /market/link ---------

fn link_request(token: Option<&str>, body: String) -> Request<Body> {
    let mut req = Request::post("/market/link").header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("X-Auth-Token", t);
    }
    req.body(Body::from(body)).unwrap()
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/market/link", post(link_handler))
        .layer(Extension(state))
}

#[tokio::test]
async fn link_is_503_unconfigured_and_401_without_a_token() {
    unsafe {
        std::env::set_var("AWS_REGION", "us-east-1");
        std::env::set_var("AWS_ACCESS_KEY_ID", "fake");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "fake");
    }
    let mut state = crate::test_helpers::build_test_app_state().await;
    let body = json!({"claim": "x"}).to_string();
    let (status, err) = call(&router(state.clone()), link_request(None, body.clone())).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(err, json!({"error": "market_unavailable"}));

    let h = Harness::new(&state.issuer).await;
    state.market = Arc::new(Some(h.source));
    let (status, _) = call(&router(state), link_request(None, body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[test]
fn link_fetches_are_limited_per_account_per_minute() {
    let source = MarketSource::new(MarketConfig::for_tests(ISSUER, AUDIENCE, &key())).unwrap();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let t = 1_800_000_000;
    for _ in 0..MARKET_LINK_FETCHES_PER_MINUTE {
        assert!(source.admit_link(&a, t).is_ok());
    }
    assert_eq!(source.admit_link(&a, t), Err(60));
    assert_eq!(source.admit_link(&a, t + 45), Err(15));
    // Another account has its own budget.
    assert!(source.admit_link(&b, t + 45).is_ok());
    // The next window admits again.
    assert!(source.admit_link(&a, t + 60).is_ok());
}

/// A user, a token for it, and the link route with a local market.
struct LinkFixture {
    store: Arc<DynamoDBStore>,
    state: AppState,
    app: Router,
    h: Arc<Harness>,
}

impl LinkFixture {
    async fn new() -> Option<Self> {
        let store = Arc::new(crate::db::tests::local_store()?);
        let mut state = crate::test_helpers::build_test_app_state_with_store(store.clone());
        let h = Harness::new(&state.issuer).await;
        // The source moves into the state; the harness keeps the market and
        // the key, and a copy of the configuration for signing.
        let source = MarketSource::new(h.source.config.clone()).unwrap();
        state.market = Arc::new(Some(source));
        Some(Self {
            app: router(state.clone()),
            store,
            state,
            h: Arc::new(h),
        })
    }

    async fn user(&self) -> (Uuid, String) {
        let id = self
            .store
            .create_user(
                &format!("mk-{}", &Uuid::new_v4().simple().to_string()[..12]),
                "did:key:z6MkMarketRoute",
            )
            .await
            .unwrap()
            .user_id;
        let token = crate::authn::mint_auth_token(&self.state, &id, None, None).unwrap();
        (id, token)
    }

    async fn link(&self, token: &str, id: &SessionId) -> (StatusCode, Value) {
        let claim = self.h.claim(id, json!({}));
        call(
            &self.app,
            link_request(Some(token), json!({ "claim": claim }).to_string()),
        )
        .await
    }

    fn source(&self) -> &MarketSource {
        self.state.market.as_ref().as_ref().unwrap()
    }
}

#[tokio::test]
async fn link_binds_a_verified_purchase_once() {
    let Some(f) = LinkFixture::new().await else {
        return;
    };
    let (alice, alice_token) = f.user().await;
    let id = f.h.valid();
    let (status, body) = f.link(&alice_token, &id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({
            "tier": "lifetime",
            "livemode": true,
            "entitlements": [ENTITLEMENT_CREATOR_PUBLISH],
            "token_can_publish": false,
        })
    );
    assert_eq!(
        f.store.market_link_owner(id.as_str()).await.unwrap(),
        Some(alice)
    );
    let state = f.store.get_publishing_state(&alice).await.unwrap().unwrap();
    assert_eq!(state.market_links, vec![id.as_str().to_string()]);

    // Idempotent.
    let (status, _) = f.link(&alice_token, &id).await;
    assert_eq!(status, StatusCode::OK);

    // Another live account cannot take it.
    let (_, bob_token) = f.user().await;
    let (status, body) = f.link(&bob_token, &id).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, json!({"error": "already_linked"}));
    assert_eq!(
        f.store.market_link_owner(id.as_str()).await.unwrap(),
        Some(alice)
    );
}

#[tokio::test]
async fn link_refuses_what_the_market_does_not_vouch_for() {
    let Some(f) = LinkFixture::new().await else {
        return;
    };
    let (user, token) = f.user().await;
    let refunded = f.h.with(Answer::Status(410));
    let unknown = live_id();
    let down = f.h.with(Answer::Status(500));
    let other = key();
    let unpinned = live_id();
    f.h.market.answer(
        &unpinned,
        Answer::Claim(sign(
            &other,
            &header(&other),
            &payload(
                &f.h.source.config.issuer,
                &f.state.issuer,
                &unpinned,
                json!({}),
            ),
        )),
    );
    for (id, want, error) in [
        (&refunded, StatusCode::CONFLICT, "revoked"),
        (&unknown, StatusCode::BAD_REQUEST, "invalid_claim"),
        // Fetched fresh from the market: a claim that does not verify is the
        // operators' fault (an unpinned key), so "try again", not "bad claim".
        (
            &unpinned,
            StatusCode::SERVICE_UNAVAILABLE,
            "market_unavailable",
        ),
        (&down, StatusCode::SERVICE_UNAVAILABLE, "market_unavailable"),
    ] {
        let (status, body) = f.link(&token, id).await;
        assert_eq!((status, body), (want, json!({ "error": error })), "{id:?}");
        assert_eq!(f.store.market_link_owner(id.as_str()).await.unwrap(), None);
    }

    // A test-mode purchase while test mode is off: refused before any fetch.
    let test = test_id();
    f.h.market
        .answer(&test, Answer::Claim(f.h.claim(&test, json!({}))));
    let before = f.h.market.hits();
    let (status, body) = f.link(&token, &test).await;
    assert_eq!(
        (status, body),
        (StatusCode::BAD_REQUEST, json!({"error": "invalid_claim"}))
    );
    assert_eq!(f.h.market.hits(), before);

    // A body that names no purchase.
    for body in [
        "{}".to_string(),
        "not json".to_string(),
        json!({"claim": "a.b.c"}).to_string(),
    ] {
        let (status, err) = call(&f.app, link_request(Some(&token), body)).await;
        assert_eq!(
            (status, err),
            (StatusCode::BAD_REQUEST, json!({"error": "invalid_claim"}))
        );
    }
    let state = f.store.get_publishing_state(&user).await.unwrap().unwrap();
    assert!(state.market_links.is_empty());
}

#[tokio::test]
async fn link_is_429_past_the_per_account_limit() {
    let Some(f) = LinkFixture::new().await else {
        return;
    };
    let (_, token) = f.user().await;
    for _ in 0..MARKET_LINK_FETCHES_PER_MINUTE {
        let (status, _) = f.link(&token, &live_id()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let hits = f.h.market.hits();
    let claim = f.h.claim(&f.h.valid(), json!({}));
    let resp = f
        .app
        .clone()
        .oneshot(link_request(
            Some(&token),
            json!({ "claim": claim }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = resp.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&retry));
    assert_eq!(f.h.market.hits(), hits, "refused before any fetch");
    // Another account is not held back.
    let (_, other) = f.user().await;
    assert_eq!(f.link(&other, &f.h.valid()).await.0, StatusCode::OK);
}

#[tokio::test]
async fn link_for_a_deleted_account_is_401_and_leaves_nothing() {
    let Some(f) = LinkFixture::new().await else {
        return;
    };
    let (user, token) = f.user().await;
    f.store
        .tombstone_account(&user, &format!("{user}.test"), None, 1_700_000_000)
        .await
        .unwrap();
    let id = f.h.valid();
    let (status, _) = f.link(&token, &id).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(f.store.market_link_owner(id.as_str()).await.unwrap(), None);
}

// --------- The mint ---------

async fn derived(state: &AppState, user: Uuid) -> Vec<String> {
    crate::publishing::derived_entitlements(state, Some(user), None).await
}

#[tokio::test]
async fn a_mint_derives_publishing_from_a_linked_purchase() {
    let Some(f) = LinkFixture::new().await else {
        return;
    };
    let (user, token) = f.user().await;
    let id = f.h.valid();
    assert!(
        derived(&f.state, user).await.is_empty(),
        "nothing linked yet"
    );
    assert_eq!(f.link(&token, &id).await.0, StatusCode::OK);
    assert_eq!(
        derived(&f.state, user).await,
        vec![ENTITLEMENT_CREATOR_PUBLISH.to_string()]
    );

    // Through the one claims builder every human token uses.
    let patreon = crate::patreon::PatreonState::new(
        None,
        None,
        fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None),
    );
    let user_auth = crate::oidc::AuthenticatedUser::webauthn(user, vec![]);
    let claims = crate::oidc::arkavo_user_claims(&f.state, &patreon, &user_auth).await;
    assert!(
        claims
            .effective_entitlements()
            .contains(&ENTITLEMENT_CREATOR_PUBLISH.to_string())
    );
    // Derived, never stored: the registration token drops it.
    assert!(
        !claims
            .entitlements
            .contains(&ENTITLEMENT_CREATOR_PUBLISH.to_string())
    );

    // A suspension withholds it.
    f.store
        .set_publishing_suspension(
            &user,
            &PublishingSuspension {
                reason: "report upheld".into(),
                report_id: None,
                suspended_by: "client:moderation".into(),
                suspended_at: 1_700_000_000,
            },
        )
        .await
        .unwrap();
    assert!(derived(&f.state, user).await.is_empty());
}

#[tokio::test]
async fn a_refund_ends_the_grant_and_an_outage_fails_closed() {
    let Some(f) = LinkFixture::new().await else {
        return;
    };
    let (user, token) = f.user().await;
    let id = f.h.valid();
    assert_eq!(f.link(&token, &id).await.0, StatusCode::OK);
    let now = Utc::now().timestamp();
    let expire = |status| {
        f.source()
            .remember(&id, status, now - MARKET_CACHE_TTL_SECONDS - 1)
    };

    // Refunded: a definite "no" (a 200 from /entities).
    f.h.market.answer(&id, Answer::Status(410));
    expire(ClaimStatus::Valid(Tier::Lifetime));
    assert!(derived(&f.state, user).await.is_empty());
    expire(ClaimStatus::Valid(Tier::Lifetime));
    assert!(matches!(
        crate::publishing::try_derived_entitlements(&f.state, Some(user), None).await,
        Ok(v) if v.is_empty()
    ));

    // Down: a mint grants nothing; /entities must not read that as "no".
    f.h.market.answer(&id, Answer::Status(503));
    expire(ClaimStatus::Valid(Tier::Lifetime));
    assert!(derived(&f.state, user).await.is_empty());
    expire(ClaimStatus::Valid(Tier::Lifetime));
    assert!(matches!(
        crate::publishing::try_derived_entitlements(&f.state, Some(user), None).await,
        Err(DeriveError::MarketUnavailable)
    ));
    let user_auth = crate::oidc::AuthenticatedUser::webauthn(user, vec![]);
    assert!(matches!(
        crate::oidc::try_arkavo_user_claims_from(&f.state, &user_auth, None).await,
        Err(DeriveError::MarketUnavailable)
    ));

    // A suspended account is a definite "no" whatever the market says.
    f.store
        .set_publishing_suspension(
            &user,
            &PublishingSuspension {
                reason: "report upheld".into(),
                report_id: None,
                suspended_by: "client:moderation".into(),
                suspended_at: 1_700_000_000,
            },
        )
        .await
        .unwrap();
    expire(ClaimStatus::Valid(Tier::Lifetime));
    assert!(matches!(
        crate::publishing::try_derived_entitlements(&f.state, Some(user), None).await,
        Ok(v) if v.is_empty()
    ));
}
