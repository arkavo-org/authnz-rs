//! Bounded session storage and atomic take-once ephemeral challenge/ticket store.
//!
//! `tower-sessions` clones the session `Record` per request and writes it back
//! on handler exit only when `!res.status().is_server_error()`. Storing
//! single-use WebAuthn ceremonies, App Attest challenges/tickets, or OAuth
//! nonces directly inside the `tower-sessions` record therefore breaks
//! single-use semantics under concurrent requests or 5xx responses, and
//! `MemoryStore::default()` grows without bound because nothing evicts expired
//! sessions.
//!
//! This module fixes both:
//! - [`EphemeralStore`]: atomic take-once store backed by Redis (`SET EX` /
//!   `GETDEL` / `SET NX EX`) with a bounded, TTL-enforcing, poison-safe
//!   in-memory fallback that checks local before Redis on `take`/`peek` and
//!   clears both on `delete` (preventing Redis reconnect split-brain).
//! - [`BoundedSessionStore`]: bounded, TTL-evicting `tower_sessions::SessionStore`
//!   replacing `MemoryStore::default()`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use fred::interfaces::{ClientLike, KeysInterface};
use log::warn;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tower_sessions::cookie::time::OffsetDateTime;
use tower_sessions::session::{Id, Record};
use tower_sessions::session_store::{self, SessionStore};

/// Hard cap on in-memory entries for [`EphemeralStore`]'s local fallback.
pub(crate) const MAX_EPHEMERAL_LOCAL_ENTRIES: usize = 16_384;

/// Hard cap on local replay-protection markers held in [`EphemeralStore`] when
/// Redis is offline. Unexpired markers are NEVER evicted; once full, new
/// `mark_consumed_once` calls fail closed.
pub(crate) const MAX_CONSUMED_LOCAL_ENTRIES: usize = 65_536;

/// Hard cap on sessions held in [`BoundedSessionStore`].
pub(crate) const MAX_BOUNDED_SESSIONS: usize = 32_768;

/// Default TTL (seconds) for DeviceCheck / App Attest challenges (non-sliding).
pub(crate) const DEVICE_CHECK_CHALLENGE_TTL_SECONDS: i64 = 300;

/// Default TTL (seconds) for WebAuthn ceremony state (non-sliding).
pub(crate) const WEBAUTHN_CEREMONY_TTL_SECONDS: i64 = 600;

#[derive(Clone)]
struct LocalEntry {
    json: String,
    expires_at: i64,
}

/// Atomic take-once store for single-use challenges, ceremonies, registration
/// tickets, and replay markers.
///
/// Handlers keep only a random opaque handle in the `tower-sessions` cookie and
/// store the actual single-use payload here. `take` consumes the entry
/// immediately (Redis `GETDEL` or `Mutex<HashMap::remove>`), independent of
/// `tower-sessions`' deferred response save.
#[derive(Clone)]
pub struct EphemeralStore {
    redis: fred::clients::RedisClient,
    local: Arc<Mutex<HashMap<String, LocalEntry>>>,
    max_local_entries: usize,
    /// Dedicated replay-marker map when Redis is offline. Isolated from
    /// ceremony entries and never evicts unexpired markers.
    consumed: Arc<Mutex<HashMap<String, i64>>>,
    max_consumed_entries: usize,
}

impl std::fmt::Debug for EphemeralStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralStore")
            .field("max_local_entries", &self.max_local_entries)
            .field("max_consumed_entries", &self.max_consumed_entries)
            .finish()
    }
}

impl EphemeralStore {
    pub fn new(redis: fred::clients::RedisClient) -> Self {
        Self::with_capacity(redis, MAX_EPHEMERAL_LOCAL_ENTRIES)
    }

    pub fn with_capacity(redis: fred::clients::RedisClient, max_local_entries: usize) -> Self {
        Self {
            redis,
            local: Arc::new(Mutex::new(HashMap::new())),
            max_local_entries: max_local_entries.max(1),
            consumed: Arc::new(Mutex::new(HashMap::new())),
            max_consumed_entries: MAX_CONSUMED_LOCAL_ENTRIES.min(max_local_entries.max(1) * 4),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_consumed_capacity(
        redis: fred::clients::RedisClient,
        max_consumed_entries: usize,
    ) -> Self {
        Self {
            redis,
            local: Arc::new(Mutex::new(HashMap::new())),
            max_local_entries: MAX_EPHEMERAL_LOCAL_ENTRIES,
            consumed: Arc::new(Mutex::new(HashMap::new())),
            max_consumed_entries: max_consumed_entries.max(1),
        }
    }

    /// Local-only store for tests (disconnected Redis client, never dialed).
    pub fn local_only() -> Self {
        let redis =
            fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None);
        Self::new(redis)
    }

    fn key(namespace: &str, id: &str) -> String {
        format!("authnz:eph:{namespace}:{id}")
    }

    fn random_id() -> Result<String, String> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|e| format!("RNG failure: {e}"))?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn lock_local(&self) -> std::sync::MutexGuard<'_, HashMap<String, LocalEntry>> {
        self.local.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_consumed(&self) -> std::sync::MutexGuard<'_, HashMap<String, i64>> {
        self.consumed.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn insert_local(&self, key: String, json: String, expires_at: i64) {
        let now = Utc::now().timestamp();
        let mut map = self.lock_local();
        map.retain(|_, v| v.expires_at > now);
        if map.len() >= self.max_local_entries && !map.contains_key(&key) {
            // Evict the entry expiring soonest so memory stays bounded.
            if let Some(evict_key) = map
                .iter()
                .min_by_key(|(_, v)| v.expires_at)
                .map(|(k, _)| k.clone())
            {
                map.remove(&evict_key);
            }
        }
        map.insert(key, LocalEntry { json, expires_at });
    }

    /// Store `value` under a fresh random handle with absolute TTL `ttl_secs`.
    pub async fn insert<T: Serialize>(
        &self,
        namespace: &str,
        value: &T,
        ttl_secs: i64,
    ) -> Result<String, String> {
        let id = Self::random_id()?;
        self.put_keyed(namespace, &id, value, ttl_secs).await?;
        Ok(id)
    }

    /// Store `value` under a caller-provided key with absolute TTL `ttl_secs`.
    pub async fn put_keyed<T: Serialize>(
        &self,
        namespace: &str,
        id: &str,
        value: &T,
        ttl_secs: i64,
    ) -> Result<(), String> {
        let now = Utc::now().timestamp();
        let expires_at = now.saturating_add(ttl_secs);
        let wrapper = StoredEnvelope {
            expires_at,
            payload: value,
        };
        let json = serde_json::to_string(&wrapper).map_err(|e| format!("serialize failed: {e}"))?;
        let key = Self::key(namespace, id);
        let redis_ttl = ttl_secs.max(1);

        if self.redis.is_connected() {
            // Fail closed on ambiguous Redis SET errors: writing a local copy
            // after an attempted Redis write could leave the single-use item in
            // both stores and permit double-redemption.
            self.redis
                .set::<(), _, _>(
                    &key,
                    json,
                    Some(fred::types::Expiration::EX(redis_ttl)),
                    None,
                    false,
                )
                .await
                .map_err(|e| format!("Redis SET failed ({namespace}): {e}"))?;
            self.lock_local().remove(&key);
            return Ok(());
        }
        self.insert_local(key, json, expires_at);
        Ok(())
    }

    /// Read `id` without consuming it. Returns `None` if absent or expired.
    pub async fn peek<T: DeserializeOwned>(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<T>, String> {
        let key = Self::key(namespace, id);
        let now = Utc::now().timestamp();

        if self.redis.is_connected() {
            let val: Option<String> = self
                .redis
                .get(&key)
                .await
                .map_err(|e| format!("Redis GET failed: {e}"))?;
            if let Some(json) = val {
                let env: OwnedEnvelope<T> =
                    serde_json::from_str(&json).map_err(|e| format!("deserialize failed: {e}"))?;
                return Ok((env.expires_at >= now).then_some(env.payload));
            }
            return Ok(None);
        }

        let mut map = self.lock_local();
        if let Some(entry) = map.get(&key) {
            if entry.expires_at < now {
                map.remove(&key);
                return Ok(None);
            }
            let env: OwnedEnvelope<T> =
                serde_json::from_str(&entry.json).map_err(|e| format!("deserialize failed: {e}"))?;
            return Ok((env.expires_at >= now).then_some(env.payload));
        }
        Ok(None)
    }

    /// Atomically fetch and delete `id`. Exactly one concurrent caller wins.
    /// Returns `None` if absent or expired.
    pub async fn take<T: DeserializeOwned>(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<T>, String> {
        let key = Self::key(namespace, id);
        let now = Utc::now().timestamp();

        if self.redis.is_connected() {
            // Redis GETDEL is the sole authoritative redemption path when
            // connected, avoiding split-brain double redemption across stores.
            self.lock_local().remove(&key);
            let val: Option<String> = self
                .redis
                .getdel(&key)
                .await
                .map_err(|e| format!("Redis GETDEL failed: {e}"))?;
            if let Some(json) = val {
                let env: OwnedEnvelope<T> =
                    serde_json::from_str(&json).map_err(|e| format!("deserialize failed: {e}"))?;
                return Ok((env.expires_at >= now).then_some(env.payload));
            }
            return Ok(None);
        }

        let local_hit = self.lock_local().remove(&key);
        if let Some(entry) = local_hit {
            if entry.expires_at < now {
                return Ok(None);
            }
            let env: OwnedEnvelope<T> =
                serde_json::from_str(&entry.json).map_err(|e| format!("deserialize failed: {e}"))?;
            return Ok((env.expires_at >= now).then_some(env.payload));
        }
        Ok(None)
    }

    /// Delete `id` from both local fallback and Redis (best-effort on Redis).
    pub async fn delete(&self, namespace: &str, id: &str) {
        let key = Self::key(namespace, id);
        self.lock_local().remove(&key);
        if self.redis.is_connected() {
            let _: Result<(), _> = self.redis.del(&key).await;
        }
    }

    /// Record `id` as consumed for `ttl_secs`. Returns `Ok(true)` the first
    /// time `id` is seen (and marks it consumed); returns `Ok(false)` on any
    /// replay within `ttl_secs`.
    pub async fn mark_consumed_once(
        &self,
        namespace: &str,
        id: &str,
        ttl_secs: i64,
    ) -> Result<bool, String> {
        let key = Self::key(namespace, id);
        let now = Utc::now().timestamp();
        let ttl = ttl_secs.max(1);
        let expires_at = now.saturating_add(ttl);

        // If already marked locally (e.g. recorded while Redis was offline),
        // refuse replay immediately.
        {
            let mut map = self.lock_consumed();
            map.retain(|_, exp| *exp > now);
            if map.contains_key(&key) {
                return Ok(false);
            }
        }

        if self.redis.is_connected() {
            // Fail closed on Redis errors: never fall back to local after an
            // ambiguous SET NX.
            let res: Option<String> = self
                .redis
                .set(
                    &key,
                    "1",
                    Some(fred::types::Expiration::EX(ttl)),
                    Some(fred::types::SetOptions::NX),
                    false,
                )
                .await
                .map_err(|e| format!("Redis SET NX failed ({namespace}): {e}"))?;
            // Mirror the replay marker locally so a subsequent Redis
            // disconnect cannot let an already-consumed token be replayed
            // against this process.
            let mut map = self.lock_consumed();
            map.retain(|_, exp| *exp > now);
            if map.len() < self.max_consumed_entries {
                map.insert(key, expires_at);
            }
            return Ok(res.is_some());
        }

        let mut map = self.lock_consumed();
        map.retain(|_, exp| *exp > now);
        if map.contains_key(&key) {
            return Ok(false);
        }
        // Never evict an unexpired replay marker: fail closed if full.
        if map.len() >= self.max_consumed_entries {
            warn!("EphemeralStore replay cache full ({namespace}); failing closed");
            return Err("replay protection cache at capacity".into());
        }
        map.insert(key, expires_at);
        Ok(true)
    }
}

#[derive(Serialize)]
struct StoredEnvelope<'a, T: Serialize> {
    expires_at: i64,
    payload: &'a T,
}

#[derive(serde::Deserialize)]
struct OwnedEnvelope<T> {
    expires_at: i64,
    payload: T,
}

/// Bounded, TTL-evicting in-memory `tower_sessions::SessionStore`.
///
/// Replaces `tower_sessions::MemoryStore::default()`, which has neither a size
/// cap nor expiry eviction.
#[derive(Clone, Debug)]
pub struct BoundedSessionStore {
    records: Arc<Mutex<HashMap<Id, Record>>>,
    max_entries: usize,
}

impl Default for BoundedSessionStore {
    fn default() -> Self {
        Self::new(MAX_BOUNDED_SESSIONS)
    }
}

impl BoundedSessionStore {
    pub fn new(max_entries: usize) -> Self {
        Self {
            records: Arc::new(Mutex::new(HashMap::new())),
            max_entries: max_entries.max(1),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Id, Record>> {
        self.records.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Purge expired sessions. Called on writes and may also be driven by a
    /// periodic background task.
    pub fn purge_expired(&self) -> usize {
        let now = OffsetDateTime::now_utc();
        let mut map = self.lock();
        let before = map.len();
        map.retain(|_, record| record.expiry_date > now);
        before - map.len()
    }

    fn insert_bounded(map: &mut HashMap<Id, Record>, max_entries: usize, record: Record) {
        let now = OffsetDateTime::now_utc();
        map.retain(|_, r| r.expiry_date > now);
        if map.len() >= max_entries
            && !map.contains_key(&record.id)
            && let Some(evict_id) = map
                .iter()
                .min_by_key(|(_, r)| r.expiry_date)
                .map(|(k, _)| *k)
        {
            map.remove(&evict_id);
        }
        map.insert(record.id, record);
    }
}

impl SessionStore for BoundedSessionStore {
    fn create<'life0, 'life1, 'async_trait>(
        &'life0 self,
        record: &'life1 mut Record,
    ) -> Pin<Box<dyn Future<Output = session_store::Result<()>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let mut map = self.lock();
            while map.contains_key(&record.id) {
                record.id = Id::default();
            }
            Self::insert_bounded(&mut map, self.max_entries, record.clone());
            Ok(())
        })
    }

    fn save<'life0, 'life1, 'async_trait>(
        &'life0 self,
        record: &'life1 Record,
    ) -> Pin<Box<dyn Future<Output = session_store::Result<()>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let mut map = self.lock();
            Self::insert_bounded(&mut map, self.max_entries, record.clone());
            Ok(())
        })
    }

    fn load<'life0, 'life1, 'async_trait>(
        &'life0 self,
        session_id: &'life1 Id,
    ) -> Pin<Box<dyn Future<Output = session_store::Result<Option<Record>>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let now = OffsetDateTime::now_utc();
            let mut map = self.lock();
            match map.get(session_id) {
                Some(record) if record.expiry_date > now => Ok(Some(record.clone())),
                Some(_) => {
                    map.remove(session_id);
                    Ok(None)
                }
                None => Ok(None),
            }
        })
    }

    fn delete<'life0, 'life1, 'async_trait>(
        &'life0 self,
        session_id: &'life1 Id,
    ) -> Pin<Box<dyn Future<Output = session_store::Result<()>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            self.lock().remove(session_id);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn take_is_strictly_single_use() {
        let store = EphemeralStore::local_only();
        let id = store.insert("test", &"secret-value", 60).await.unwrap();
        let first: Option<String> = store.take("test", &id).await.unwrap();
        let second: Option<String> = store.take("test", &id).await.unwrap();
        assert_eq!(first.as_deref(), Some("secret-value"));
        assert_eq!(second, None);
    }

    #[tokio::test]
    async fn expired_entries_are_rejected_on_peek_and_take() {
        let store = EphemeralStore::local_only();
        let id = store.insert("test", &"expired", -5).await.unwrap();
        assert_eq!(store.peek::<String>("test", &id).await.unwrap(), None);
        let id2 = store.insert("test", &"expired", -5).await.unwrap();
        assert_eq!(store.take::<String>("test", &id2).await.unwrap(), None);
    }

    #[tokio::test]
    async fn local_store_enforces_capacity_cap() {
        let redis =
            fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None);
        let store = EphemeralStore::with_capacity(redis, 4);
        for i in 0..10 {
            store.insert("cap", &i, 60).await.unwrap();
        }
        assert!(store.lock_local().len() <= 4);
    }

    #[tokio::test]
    async fn mark_consumed_once_blocks_replays() {
        let store = EphemeralStore::local_only();
        assert!(store.mark_consumed_once("replay", "tok1", 60).await.unwrap());
        assert!(!store.mark_consumed_once("replay", "tok1", 60).await.unwrap());
        assert!(store.mark_consumed_once("replay", "tok2", 60).await.unwrap());
    }

    #[tokio::test]
    async fn replay_markers_never_evict_unexpired_entries_when_full() {
        let redis =
            fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None);
        let store = EphemeralStore::with_consumed_capacity(redis, 2);
        assert!(store.mark_consumed_once("replay", "a", 60).await.unwrap());
        assert!(store.mark_consumed_once("replay", "b", 60).await.unwrap());
        // Full of unexpired markers: fail closed instead of evicting "a".
        assert!(store.mark_consumed_once("replay", "c", 60).await.is_err());
        // Original marker is still intact and blocks replay.
        assert!(!store.mark_consumed_once("replay", "a", 60).await.unwrap());
    }

    #[tokio::test]
    async fn bounded_session_store_evicts_expired_and_caps_size() {
        let store = BoundedSessionStore::new(3);
        let future = OffsetDateTime::now_utc() + tower_sessions::cookie::time::Duration::seconds(60);
        let past = OffsetDateTime::now_utc() - tower_sessions::cookie::time::Duration::seconds(10);

        let expired = Record {
            id: Id::default(),
            data: Default::default(),
            expiry_date: past,
        };
        store.save(&expired).await.unwrap();
        assert!(store.load(&expired.id).await.unwrap().is_none());

        for _ in 0..6 {
            let rec = Record {
                id: Id::default(),
                data: Default::default(),
                expiry_date: future,
            };
            store.save(&rec).await.unwrap();
        }
        assert!(store.lock().len() <= 3);
    }
}
