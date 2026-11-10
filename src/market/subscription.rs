//! The market's account lookup (#151): whether an account holds a prepaid
//! term of the online-play subscription (the Game Pass).
//!
//! `GET <issuer>/subscriptions/<account uuid>` with a shared bearer secret
//! ([`LookupToken`], `MARKET_LOOKUP_TOKEN`). A `200` carries a claim signed
//! with the same pinned keys as a membership claim; it grants only when it
//! verifies ([`verify_answer`]). `404` is "no term covers now". Anything else
//! is a failure: it grants nothing, and it is never taken for "none".
//!
//! The lookup runs at every human mint, so three rules keep a market outage
//! from slowing sign-in or hiding a payment (contract: arkavo-com/market
//! `docs/market-identity-interface.md`, "Account lookups (subscriptions)"):
//!
//! - **Cache**, per account: an answer 5 min, a failure 60 s.
//! - **Circuit breaker**: after an outage (no usable response) no account is
//!   asked for 60 s; then one caller probes. A claim that does not verify is
//!   one account's failure and leaves the breaker closed. Meanwhile the answer is unknown, never "none", and a
//!   cached "active" still grants.
//! - **Recheck**: a renewal may skip a cached "none" (the app refreshes right
//!   after a payment), a few times a minute per account, never through an
//!   open breaker.
//!
//! The token is a secret: it is sent only in the `Authorization` header,
//! marked sensitive, and appears in no log line, error or `Debug` output.

use super::{ClaimError, MarketConfig, MarketSource, verified_payload};
use crate::constants::{
    MARKET_CACHE_TTL_SECONDS, MARKET_CLAIM_MAX_BYTES, MARKET_FAILURE_CACHE_TTL_SECONDS,
    MARKET_FETCH_DEADLINE_SECONDS, MARKET_SUBSCRIPTION_RECHECKS_PER_MINUTE,
};
use chrono::Utc;
use log::{error, warn};
use reqwest::header::HeaderValue;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

/// The claim's `tier` for the subscription. A membership claim's tier
/// (`lifetime`) is not this one, so it is never taken for a lookup answer.
const TIER: &str = "online-play";

/// Shortest token the market accepts.
const TOKEN_MIN_LEN: usize = 32;

/// The shared secret, ready to send. No `Debug` output shows it.
#[derive(Clone)]
pub struct LookupToken(HeaderValue);

impl std::fmt::Debug for LookupToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LookupToken(..)")
    }
}

impl LookupToken {
    /// Parse `MARKET_LOOKUP_TOKEN`. `Ok(None)`: unset or empty. `Err`: set
    /// but not at least 32 printable ASCII characters with no space. The
    /// error never carries the value.
    pub(crate) fn parse(raw: Option<&str>) -> Result<Option<Self>, &'static str> {
        let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        const UNUSABLE: &str =
            "MARKET_LOOKUP_TOKEN must be at least 32 printable ASCII characters with no spaces";
        if raw.len() < TOKEN_MIN_LEN || !raw.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(UNUSABLE);
        }
        let mut header = HeaderValue::from_str(&format!("Bearer {raw}")).map_err(|_| UNUSABLE)?;
        header.set_sensitive(true);
        Ok(Some(Self(header)))
    }
}

/// What the market says about one account's subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Subscription {
    /// A verified `200`: a paid term covers now.
    Active,
    /// `404`: no term covers now. Also the answer when no lookup is
    /// configured: there is no such source.
    None,
    /// The market could not answer (or the breaker is open). Grants nothing,
    /// and is never "none".
    Unavailable,
}

impl Subscription {
    fn ttl(self) -> i64 {
        match self {
            Self::Active | Self::None => MARKET_CACHE_TTL_SECONDS,
            Self::Unavailable => MARKET_FAILURE_CACHE_TTL_SECONDS,
        }
    }
}

/// How one lookup ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fetched {
    /// The market answered: a verified `200`, or `404`.
    Answer(Subscription),
    /// A `200` whose claim does not verify. A failure for this account
    /// only: the market is up, so the breaker stays closed.
    Unverified,
    /// No usable response: unreachable, timed out, any other status, or a
    /// body that is not the answer. Opens the breaker for every account.
    Outage,
}

impl Fetched {
    fn status(self) -> Subscription {
        match self {
            Self::Answer(status) => status,
            Self::Unverified | Self::Outage => Subscription::Unavailable,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    status: Subscription,
    expires_at: i64,
}

/// The lookup's state: the token, the per-account answer cache, the breaker
/// and the recheck budget. All in process.
#[derive(Debug)]
pub struct SubscriptionLookup {
    token: LookupToken,
    cache: Mutex<HashMap<Uuid, Entry>>,
    /// No account is asked before this time (unix seconds). 0: closed.
    breaker_until: Mutex<i64>,
    /// Rechecks per account in the current minute: (window start, count).
    rechecks: Mutex<HashMap<Uuid, (i64, u32)>>,
}

impl SubscriptionLookup {
    pub(crate) fn new(token: LookupToken) -> Self {
        Self {
            token,
            cache: Mutex::new(HashMap::new()),
            breaker_until: Mutex::new(0),
            rechecks: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, account: &Uuid, now: i64) -> Option<Subscription> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache
            .get(account)
            .filter(|e| e.expires_at > now)
            .map(|e| e.status)
    }

    /// Cache `status`. A failure never replaces an unexpired answer: what a
    /// concurrent lookup learned stands.
    fn record(&self, account: &Uuid, status: Subscription, now: i64) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.retain(|_, e| e.expires_at > now);
        if status == Subscription::Unavailable
            && cache
                .get(account)
                .is_some_and(|e| e.status != Subscription::Unavailable)
        {
            return;
        }
        cache.insert(
            *account,
            Entry {
                status,
                expires_at: now + status.ttl(),
            },
        );
    }

    /// Whether a lookup may go out at `now`. While the breaker is open: no.
    /// When its time is up the first caller is let through as the probe, and
    /// the breaker stays shut behind it for one fetch deadline, so the other
    /// mints of that moment do not all wait on a market that is still down.
    fn admit(&self, now: i64) -> bool {
        let mut until = self.breaker_until.lock().unwrap_or_else(|e| e.into_inner());
        if *until == 0 {
            return true;
        }
        if now < *until {
            return false;
        }
        *until = now + MARKET_FETCH_DEADLINE_SECONDS as i64 + 1;
        true
    }

    /// Open the breaker for the failure window after an outage; close it
    /// after anything the market answered, a claim that does not verify
    /// included: that is one account's failure, and the market is up.
    fn settle(&self, fetched: Fetched, now: i64) {
        let mut until = self.breaker_until.lock().unwrap_or_else(|e| e.into_inner());
        *until = match fetched {
            Fetched::Answer(_) | Fetched::Unverified => 0,
            Fetched::Outage => now + MARKET_FAILURE_CACHE_TTL_SECONDS,
        };
    }

    /// Admit one recheck of a cached "none" for `account`: at most
    /// [`MARKET_SUBSCRIPTION_RECHECKS_PER_MINUTE`] in a fixed 60 s window.
    fn admit_recheck(&self, account: &Uuid, now: i64) -> bool {
        const WINDOW: i64 = 60;
        let mut map = self.rechecks.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, (start, _)| now - *start < WINDOW);
        let (_, count) = map.entry(*account).or_insert((now, 0));
        if *count >= MARKET_SUBSCRIPTION_RECHECKS_PER_MINUTE {
            return false;
        }
        *count += 1;
        true
    }
}

/// Verify the claim of a `200` for `account`: the signature, `alg`, `typ`,
/// `iss` and `aud` exactly as for a membership claim (the same pinned keys),
/// then `sub` equal to the account asked about, `tier` `online-play`, and an
/// accepted `livemode`. A claim for another account never verifies, so a
/// saved or replayed answer cannot grant the wrong account.
pub(crate) fn verify_answer(
    cfg: &MarketConfig,
    jws: &str,
    account: &Uuid,
) -> Result<(), ClaimError> {
    let payload = verified_payload(cfg, jws)?;
    let text = |k: &str| payload.get(k).and_then(Value::as_str);
    // The account id is identity's lowercase hyphenated UUID, compared as
    // text: never the `arkavo:`-prefixed OIDC `sub`.
    if text("sub") != Some(account.hyphenated().to_string().as_str()) {
        return Err(ClaimError::WrongAccount);
    }
    if text("tier") != Some(TIER) {
        return Err(ClaimError::UnknownTier);
    }
    let livemode = payload
        .get("livemode")
        .and_then(Value::as_bool)
        .ok_or(ClaimError::Malformed)?;
    if !livemode && !cfg.accept_test_mode {
        return Err(ClaimError::TestMode);
    }
    Ok(())
}

impl MarketSource {
    /// Whether `account` holds a prepaid term now.
    ///
    /// Order: the cache, then the breaker, then the market. `recheck` lets a
    /// cached "none" be asked again (a renewal right after a payment),
    /// within the per-account budget; it never bypasses a cached failure or
    /// an open breaker.
    pub(crate) async fn subscription(&self, account: &Uuid, recheck: bool) -> Subscription {
        let Some(lookup) = &self.subscriptions else {
            return Subscription::None;
        };
        let now = Utc::now().timestamp();
        match lookup.cached(account, now) {
            Some(Subscription::None) if recheck && lookup.admit_recheck(account, now) => {}
            Some(status) => return status,
            None => {}
        }
        if !lookup.admit(now) {
            return Subscription::Unavailable;
        }
        let fetched = self.fetch_subscription(lookup, account).await;
        let now = Utc::now().timestamp();
        lookup.settle(fetched, now);
        let status = fetched.status();
        lookup.record(account, status, now);
        status
    }

    async fn fetch_subscription(&self, lookup: &SubscriptionLookup, account: &Uuid) -> Fetched {
        let url = format!(
            "{}/subscriptions/{}",
            self.config.issuer,
            account.hyphenated()
        );
        let response = match self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::AUTHORIZATION, lookup.token.0.clone())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    "market subscription lookup for {account} failed: {}",
                    e.without_url()
                );
                return Fetched::Outage;
            }
        };
        match response.status().as_u16() {
            200 => {}
            404 => return Fetched::Answer(Subscription::None),
            401 => {
                // Identity's own fault, and every account's: alert on it.
                error!(
                    "market subscription lookup refused (401): MARKET_LOOKUP_TOKEN does not \
                     match the market's token; no subscription is granted until it does"
                );
                return Fetched::Outage;
            }
            other => {
                warn!("market subscription lookup for {account} answered {other}");
                return Fetched::Outage;
            }
        }
        if response
            .content_length()
            .is_some_and(|n| n > MARKET_CLAIM_MAX_BYTES as u64)
        {
            warn!("market subscription answer for {account} is too large");
            return Fetched::Outage;
        }
        let body = match response.bytes().await {
            Ok(b) if b.len() <= MARKET_CLAIM_MAX_BYTES => b,
            Ok(_) => {
                warn!("market subscription answer for {account} is too large");
                return Fetched::Outage;
            }
            Err(e) => {
                warn!(
                    "market subscription read for {account} failed: {}",
                    e.without_url()
                );
                return Fetched::Outage;
            }
        };
        // `until` is not signed: nothing is granted from it, so it is not
        // read.
        #[derive(Deserialize)]
        struct Answer {
            claim: String,
        }
        let Ok(Answer { claim }) = serde_json::from_slice(&body) else {
            warn!("market subscription answer for {account} has no claim");
            return Fetched::Outage;
        };
        match verify_answer(&self.config, &claim, account) {
            Ok(()) => Fetched::Answer(Subscription::Active),
            // A 200 that does not verify is a failure, never "none": this
            // account's alone, since the market did answer.
            Err(e) => {
                warn!("market subscription claim for {account} does not verify: {e}");
                Fetched::Unverified
            }
        }
    }
}

#[cfg(test)]
#[path = "subscription_tests.rs"]
pub(crate) mod tests;
