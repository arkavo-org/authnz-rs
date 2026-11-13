//! The server's edge: bounds on what one peer can make the process hold
//! and do:
//!
//! - connections: a total under the open-file limit, which the process
//!   raises at boot, and a peer's share of it ([`tcp_connection_cap`]);
//! - time: TLS handshake, request header and whole-request deadlines;
//! - memory: request body caps ([`MAX_REQUEST_BODY_BYTES`]);
//! - rate: per-peer token buckets on the unauthenticated routes that make the
//!   server hold state or sign ([`PeerRateLimiter`]);
//! - response headers every response carries ([`response_headers`]).
//!
//! A peer is its IPv4 address or its IPv6 /64 ([`peer_key`]), read from the
//! socket. `X-Forwarded-For` is never read: any client can set it.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use log::{error, warn};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Largest request body a handler reads (axum `DefaultBodyLimit`). The
/// largest bodies identity takes are a few KiB: App Attest attestations,
/// WebAuthn registrations with an attestation chain, StoreKit JWS.
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

/// `POST /app-store/notifications`: Apple's `signedPayload` nests the
/// transaction and renewal JWS, each with its own certificate chain.
pub const MAX_APP_STORE_NOTIFICATION_BYTES: usize = 256 * 1024;

/// HTTP/3 buffers a request body before routing, so its cap is the largest
/// route cap.
#[cfg_attr(not(feature = "http3"), allow(dead_code))] // HTTP/3 only
pub const MAX_BUFFERED_BODY_BYTES: usize = MAX_APP_STORE_NOTIFICATION_BYTES;

/// A request's whole life in the router, body read included. The slowest
/// handler, a Patreon link, makes several Patreon calls of up to 10 s each.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The TLS handshake, from accept.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP/1.1: from waiting for a request (a new or idle keep-alive
/// connection) to the end of its headers. Closes slowloris connections, and
/// is also the keep-alive idle timeout: a pooled client that reuses a
/// connection as it closes loses that request, so this stays well above a
/// few seconds (hyper's default, which applied only with a timer).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP/2 and HTTP/3 streams open at once on one connection.
pub const MAX_CONCURRENT_STREAMS: u32 = 64;

/// HTTP/3: a connection with no traffic for this long is closed.
#[cfg_attr(not(feature = "http3"), allow(dead_code))] // HTTP/3 only
pub const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Connections served at once, per listener (TCP; QUIC), before the
/// open-file limit lowers the TCP one ([`tcp_connection_cap`]).
pub const MAX_CONNECTIONS: usize = 1024;

/// Most connections one peer may hold open at once, per listener (an
/// eighth of the total: [`peer_share`]). A NAT or a service client's pool
/// shares one peer, so this is generous.
pub const MAX_CONNECTIONS_PER_PEER: u32 = 128;

/// File descriptors kept free of inbound connections, for outbound calls
/// (DynamoDB, KMS, Redis, Apple, Google, Patreon, the market) and files.
/// Without them, a full listener makes every request fail downstream.
const FD_RESERVE: u64 = 128;

/// The smallest TCP connection cap, whatever the open-file limit says.
const MIN_TCP_CONNECTIONS: usize = 64;

/// Peers a [`PeerRateLimiter`] tracks before it drops idle buckets.
const MAX_TRACKED_PEERS: usize = 65_536;

/// Pause after a failed `accept` that is not about one connection
/// (descriptors exhausted, out of memory), so the loop does not spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The rate-limit and connection-count key of a peer address: the IPv4
/// address, or the IPv6 /64 (a subscriber's prefix; whoever holds one
/// address of it holds them all).
pub fn peer_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

/// A token bucket: `burst` requests at once, then one per `refill`.
#[derive(Clone, Copy, Debug)]
pub struct RateLimit {
    pub burst: u32,
    pub refill: Duration,
}

/// Unauthenticated ceremonies that make the server hold state or sign:
/// WebAuthn registration and sign-in (options and verify), the App Attest
/// registration preflight, DeviceCheck and agent challenges, and the Apple
/// and Google nonces. A sign-in takes 2 requests, a registration 4.
pub const CEREMONY_LIMIT: RateLimit = RateLimit {
    burst: 30,
    refill: Duration::from_secs(2),
};

/// `GET /oauth/authorize` and `POST /oauth/token`. A relying party's
/// backend exchanges and refreshes for all its users from one address, so
/// this is the most generous.
pub const OAUTH_LIMIT: RateLimit = RateLimit {
    burst: 120,
    refill: Duration::from_millis(500),
};

/// Token mints a device or an agent asks for: `POST /game/token` and
/// `POST /agents/token`. Per-account limits sit behind this one.
pub const MINT_LIMIT: RateLimit = RateLimit {
    burst: 60,
    refill: Duration::from_secs(1),
};

struct Bucket {
    tokens: f64,
    at: Instant,
    /// A refusal has been logged since the peer was last admitted.
    logged: bool,
}

/// Per-peer token buckets for one group of routes, in process.
pub struct PeerRateLimiter {
    group: &'static str,
    limit: RateLimit,
    max_peers: usize,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl PeerRateLimiter {
    pub fn new(group: &'static str, limit: RateLimit) -> Arc<Self> {
        Self::with_capacity(group, limit, MAX_TRACKED_PEERS)
    }

    fn with_capacity(group: &'static str, limit: RateLimit, max_peers: usize) -> Arc<Self> {
        assert!(limit.burst > 0 && !limit.refill.is_zero());
        Arc::new(Self {
            group,
            limit,
            max_peers,
            buckets: Mutex::new(HashMap::new()),
        })
    }

    /// Take a token for `peer` (already a [`peer_key`]) at `now`, or the
    /// whole seconds until one is available.
    pub fn admit(&self, peer: IpAddr, now: Instant) -> Result<(), u64> {
        let burst = f64::from(self.limit.burst);
        let refill = self.limit.refill.as_secs_f64();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if buckets.len() >= self.max_peers && !buckets.contains_key(&peer) {
            // A full bucket is the same as no bucket: drop those first.
            let refilled = self.limit.refill * self.limit.burst;
            buckets.retain(|_, b| now.saturating_duration_since(b.at) < refilled);
            if buckets.len() >= self.max_peers {
                // Many peers at once: memory comes first. Everyone starts
                // over with a full bucket.
                warn!(
                    "audit rate_limit group={} outcome=reset tracked={}",
                    self.group,
                    buckets.len()
                );
                buckets.clear();
            }
        }
        let bucket = buckets.entry(peer).or_insert(Bucket {
            tokens: burst,
            at: now,
            logged: false,
        });
        let elapsed = now.saturating_duration_since(bucket.at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed / refill).min(burst);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            bucket.logged = false;
            return Ok(());
        }
        if !bucket.logged {
            bucket.logged = true;
            warn!(
                "audit rate_limit group={} outcome=refused peer={peer}",
                self.group
            );
        }
        Err(((1.0 - bucket.tokens) * refill).ceil().max(1.0) as u64)
    }
}

/// Route middleware (`from_fn_with_state`): 429 `rate_limited` with
/// `Retry-After` once the peer's bucket is empty. Every listener records the
/// peer as `ConnectInfo<SocketAddr>`; a request without one (only in-process
/// tests) is not limited.
pub async fn limit_peer(
    State(limiter): State<Arc<PeerRateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| peer_key(addr.ip()));
    if let Some(peer) = peer
        && let Err(retry_after) = limiter.admit(peer, Instant::now())
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [
                (header::RETRY_AFTER, HeaderValue::from(retry_after)),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            axum::Json(serde_json::json!({ "error": "rate_limited" })),
        )
            .into_response();
    }
    next.run(request).await
}

/// Router middleware: 503 `timeout` when a request takes longer than
/// [`REQUEST_TIMEOUT`], body read included. The handler is dropped there,
/// just as when the client goes away.
pub async fn request_timeout(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(request)).await {
        Ok(response) => response,
        Err(_) => {
            warn!("request timed out after {REQUEST_TIMEOUT:?}: {method} {path}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::CACHE_CONTROL, "no-store")],
                axum::Json(serde_json::json!({ "error": "timeout" })),
            )
                .into_response()
        }
    }
}

/// Request headers that carry a credential: a CWT, a service token, an
/// Apple id_token, or the WebAuthn ceremony's session cookie.
const CREDENTIAL_HEADERS: [&str; 4] = [
    "authorization",
    "x-auth-token",
    "x-apple-id-token",
    "cookie",
];

const HSTS: &str = "max-age=31536000";

/// Router middleware (`from_fn_with_state`, the state says whether the
/// listener is TLS). On every response:
///
/// - `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and
///   `Content-Security-Policy: frame-ancestors 'none'` unless the response
///   set its own policy: nothing here is meant to be framed;
/// - `Referrer-Policy: no-referrer`: an authorize URL carries `state`,
///   `nonce` and PKCE values;
/// - `Strict-Transport-Security` over TLS (no `includeSubDomains`: other
///   hosts under the domain decide for themselves);
/// - `Cache-Control: no-store` when the response set no `Cache-Control` and
///   the request carried a credential, was not a GET or HEAD, or the
///   response sets a cookie. Public GETs keep their caching (a CDN may
///   cache the DID documents).
///
/// No CORS headers are sent, so browsers keep every response from other
/// origins' scripts.
pub async fn response_headers(State(tls): State<bool>, request: Request, next: Next) -> Response {
    let private = !matches!(*request.method(), Method::GET | Method::HEAD)
        || CREDENTIAL_HEADERS
            .iter()
            .any(|name| request.headers().contains_key(*name));
    let mut response = next.run(request).await;
    set_response_headers(response.headers_mut(), tls, private);
    response
}

fn set_response_headers(headers: &mut HeaderMap, tls: bool, private: bool) {
    let fixed: [(HeaderName, &'static str); 3] = [
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
    ];
    for (name, value) in fixed {
        headers.insert(name, HeaderValue::from_static(value));
    }
    headers
        .entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static("frame-ancestors 'none'"));
    if tls {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(HSTS),
        );
    }
    if !headers.contains_key(header::CACHE_CONTROL)
        && (private || headers.contains_key(header::SET_COOKIE))
    {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}

/// Connection counts for one listener: a total, and per peer.
pub struct ConnectionLimits {
    total: Arc<Semaphore>,
    max_per_peer: u32,
    per_peer: Mutex<HashMap<IpAddr, u32>>,
}

/// One admitted connection; dropping it frees its places.
pub struct ConnectionGuard {
    limits: Arc<ConnectionLimits>,
    peer: IpAddr,
    _permit: OwnedSemaphorePermit,
}

impl ConnectionLimits {
    pub fn new(total: usize, max_per_peer: u32) -> Arc<Self> {
        Arc::new(Self {
            total: Arc::new(Semaphore::new(total)),
            max_per_peer,
            per_peer: Mutex::new(HashMap::new()),
        })
    }

    /// Wait for a place under the total. TCP takes one before `accept`, so
    /// a full server leaves new connections in the kernel's backlog.
    pub async fn place(&self) -> OwnedSemaphorePermit {
        self.total
            .clone()
            .acquire_owned()
            .await
            .expect("the connection semaphore is never closed")
    }

    /// A place under the total now, if there is one (QUIC, after the
    /// handshake).
    #[cfg_attr(not(feature = "http3"), allow(dead_code))] // HTTP/3 only
    pub fn try_place(&self) -> Option<OwnedSemaphorePermit> {
        self.total.clone().try_acquire_owned().ok()
    }

    /// Admit a connection from `addr` holding `place`, or `None` when its
    /// peer already holds [`ConnectionLimits::max_per_peer`].
    pub fn admit(
        self: &Arc<Self>,
        addr: IpAddr,
        place: OwnedSemaphorePermit,
    ) -> Option<ConnectionGuard> {
        let peer = peer_key(addr);
        let mut per_peer = self.per_peer.lock().unwrap_or_else(|e| e.into_inner());
        let count = per_peer.entry(peer).or_insert(0);
        if *count >= self.max_per_peer {
            return None;
        }
        *count += 1;
        Some(ConnectionGuard {
            limits: self.clone(),
            peer,
            _permit: place,
        })
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut per_peer = self
            .limits
            .per_peer
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(count) = per_peer.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                per_peer.remove(&self.peer);
            }
        }
    }
}

/// The soft open-file limit the process raises itself to at boot (never
/// past the hard limit): room for [`MAX_CONNECTIONS`] and [`FD_RESERVE`].
const OPEN_FILES_WANTED: u64 = 4096;

/// The TCP connection limits: the total and a peer's share. The total is
/// [`MAX_CONNECTIONS`], lowered to leave [`FD_RESERVE`] descriptors under
/// the open-file limit, which is first raised toward [`OPEN_FILES_WANTED`].
/// Also returns that limit.
pub fn tcp_connection_cap() -> (usize, u32, Option<u64>) {
    let limit = raise_open_file_limit(OPEN_FILES_WANTED);
    let total = match limit {
        Some(limit) => usize::try_from(limit.saturating_sub(FD_RESERVE))
            .unwrap_or(usize::MAX)
            .clamp(MIN_TCP_CONNECTIONS, MAX_CONNECTIONS),
        None => MAX_CONNECTIONS,
    };
    (total, peer_share(total), limit)
}

/// A peer's share of `total` connections: an eighth, at most
/// [`MAX_CONNECTIONS_PER_PEER`], so no one peer holds the whole listener
/// when a low open-file limit shrinks the total.
pub fn peer_share(total: usize) -> u32 {
    u32::try_from(total / 8)
        .unwrap_or(u32::MAX)
        .clamp(8, MAX_CONNECTIONS_PER_PEER)
}

/// Raise the soft open-file limit to `wanted` (at most the hard limit) and
/// return the soft limit now in force.
#[cfg(unix)]
fn raise_open_file_limit(wanted: u64) -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one `rlimit` through a valid, exclusive
    // pointer and reads nothing else.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return None;
    }
    #[allow(clippy::unnecessary_cast)] // rlim_t is u64 on the targets built today
    let wanted = wanted as libc::rlim_t;
    if limit.rlim_cur < wanted {
        let raised = libc::rlimit {
            rlim_cur: wanted.min(limit.rlim_max),
            rlim_max: limit.rlim_max,
        };
        // SAFETY: setrlimit reads one `rlimit` through a valid pointer.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
            limit.rlim_cur = raised.rlim_cur;
        } else {
            warn!(
                "could not raise the open-file limit from {} to {}: {}",
                limit.rlim_cur,
                raised.rlim_cur,
                std::io::Error::last_os_error()
            );
        }
    }
    #[allow(clippy::unnecessary_cast)]
    Some(limit.rlim_cur as u64)
}

#[cfg(not(unix))]
fn raise_open_file_limit(_wanted: u64) -> Option<u64> {
    None
}

/// After a failed `accept`. One connection's failure (aborted or reset
/// before it was accepted) is skipped; anything else (descriptors
/// exhausted, out of memory) is logged and the loop pauses. Never stops
/// the listener.
pub async fn accept_failed(err: &std::io::Error) {
    use std::io::ErrorKind;
    if matches!(
        err.kind(),
        ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::Interrupted
    ) {
        return;
    }
    error!("accept failed, pausing {ACCEPT_BACKOFF:?}: {err}");
    tokio::time::sleep(ACCEPT_BACKOFF).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::routing::{get, post};
    use std::net::Ipv4Addr;
    use tower::ServiceExt;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn peer_key_is_the_ipv4_address_or_the_ipv6_slash_64() {
        assert_eq!(peer_key(v4(192, 0, 2, 7)), v4(192, 0, 2, 7));
        let v6: IpAddr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        let prefix: IpAddr = "2001:db8:1:2::".parse().unwrap();
        assert_eq!(peer_key(v6), prefix);
        let other_host: IpAddr = "2001:db8:1:2:ffff::1".parse().unwrap();
        assert_eq!(peer_key(other_host), prefix);
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(peer_key(mapped), v4(192, 0, 2, 7));
    }

    #[test]
    fn a_bucket_admits_its_burst_then_one_per_refill() {
        let limit = RateLimit {
            burst: 3,
            refill: Duration::from_secs(2),
        };
        let limiter = PeerRateLimiter::new("test", limit);
        let peer = v4(192, 0, 2, 1);
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(limiter.admit(peer, t0), Ok(()));
        }
        assert_eq!(limiter.admit(peer, t0), Err(2));
        assert_eq!(limiter.admit(peer, t0 + Duration::from_secs(1)), Err(1));
        assert_eq!(limiter.admit(peer, t0 + Duration::from_secs(2)), Ok(()));
        assert!(limiter.admit(peer, t0 + Duration::from_secs(2)).is_err());
        // Another peer has its own bucket.
        assert_eq!(limiter.admit(v4(192, 0, 2, 2), t0), Ok(()));
        // A long rest refills to the burst, not past it.
        let later = t0 + Duration::from_secs(3600);
        for _ in 0..3 {
            assert_eq!(limiter.admit(peer, later), Ok(()));
        }
        assert!(limiter.admit(peer, later).is_err());
    }

    #[test]
    fn a_full_limiter_drops_refilled_buckets_then_starts_over() {
        let limit = RateLimit {
            burst: 1,
            refill: Duration::from_secs(10),
        };
        let limiter = PeerRateLimiter::with_capacity("test", limit, 2);
        let t0 = Instant::now();
        assert!(limiter.admit(v4(192, 0, 2, 1), t0).is_ok());
        assert!(
            limiter
                .admit(v4(192, 0, 2, 2), t0 + Duration::from_secs(9))
                .is_ok()
        );
        // .1 has refilled by t0+10: its bucket goes, .2's stays.
        let t1 = t0 + Duration::from_secs(10);
        assert!(limiter.admit(v4(192, 0, 2, 3), t1).is_ok());
        assert!(limiter.admit(v4(192, 0, 2, 2), t1).is_err());
        // Still full of live buckets: memory comes first, all start over.
        assert!(limiter.admit(v4(192, 0, 2, 4), t1).is_ok());
        assert!(limiter.buckets.lock().unwrap().len() <= 2);
    }

    fn with_peer(mut request: axum::http::Request<Body>, ip: IpAddr) -> axum::http::Request<Body> {
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 50000)));
        request
    }

    #[tokio::test]
    async fn limit_peer_answers_429_rate_limited_with_retry_after() {
        let limiter = PeerRateLimiter::new(
            "test",
            RateLimit {
                burst: 1,
                refill: Duration::from_secs(5),
            },
        );
        let app = Router::new().route(
            "/x",
            post(|| async { "ok" })
                .layer(axum::middleware::from_fn_with_state(limiter, limit_peer)),
        );
        let request = || axum::http::Request::post("/x").body(Body::empty()).unwrap();
        let peer = v4(192, 0, 2, 9);
        let first = app
            .clone()
            .oneshot(with_peer(request(), peer))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let second = app
            .clone()
            .oneshot(with_peer(request(), peer))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(second.headers()[header::RETRY_AFTER], "5");
        assert_eq!(second.headers()[header::CACHE_CONTROL], "no-store");
        let body = axum::body::to_bytes(second.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({ "error": "rate_limited" })
        );
        // Another peer, and a request with no recorded peer, pass.
        let other = app
            .clone()
            .oneshot(with_peer(request(), v4(192, 0, 2, 10)))
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::OK);
        let unrecorded = app.oneshot(request()).await.unwrap();
        assert_eq!(unrecorded.status(), StatusCode::OK);
    }

    fn header_app(tls: bool) -> Router {
        Router::new()
            .route("/public", get(|| async { "doc" }))
            .route(
                "/cached",
                get(|| async { ([(header::CACHE_CONTROL, "public, max-age=600")], "keys") }),
            )
            .route(
                "/page",
                get(|| async {
                    (
                        [(header::CONTENT_SECURITY_POLICY, "default-src 'self'")],
                        "<p>",
                    )
                }),
            )
            .route("/mint", post(|| async { "token" }))
            .layer(axum::middleware::from_fn_with_state(tls, response_headers))
    }

    async fn get_headers(app: Router, request: axum::http::Request<Body>) -> HeaderMap {
        app.oneshot(request).await.unwrap().headers().clone()
    }

    #[tokio::test]
    async fn every_response_carries_the_fixed_headers_and_hsts_only_over_tls() {
        let request = || {
            axum::http::Request::get("/public")
                .body(Body::empty())
                .unwrap()
        };
        let h = get_headers(header_app(true), request()).await;
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(h[header::CONTENT_SECURITY_POLICY], "frame-ancestors 'none'");
        assert_eq!(h[header::STRICT_TRANSPORT_SECURITY], "max-age=31536000");
        // A public GET keeps its caching to the cache.
        assert!(!h.contains_key(header::CACHE_CONTROL));

        let plain = get_headers(header_app(false), request()).await;
        assert!(!plain.contains_key(header::STRICT_TRANSPORT_SECURITY));
        assert_eq!(plain[header::X_CONTENT_TYPE_OPTIONS], "nosniff");

        // The 404 fallback is covered too.
        let missing = axum::http::Request::get("/nope")
            .body(Body::empty())
            .unwrap();
        let h = get_headers(header_app(true), missing).await;
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    }

    #[tokio::test]
    async fn a_response_keeps_its_own_policy_and_caching() {
        let page = axum::http::Request::get("/page")
            .body(Body::empty())
            .unwrap();
        let h = get_headers(header_app(true), page).await;
        assert_eq!(h[header::CONTENT_SECURITY_POLICY], "default-src 'self'");
        let cached = axum::http::Request::get("/cached")
            .header("x-auth-token", "t")
            .body(Body::empty())
            .unwrap();
        let h = get_headers(header_app(true), cached).await;
        assert_eq!(h[header::CACHE_CONTROL], "public, max-age=600");
    }

    #[tokio::test]
    async fn credentialed_and_state_changing_responses_are_no_store() {
        let mint = axum::http::Request::post("/mint")
            .body(Body::empty())
            .unwrap();
        let h = get_headers(header_app(true), mint).await;
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        for name in CREDENTIAL_HEADERS {
            let request = axum::http::Request::get("/public")
                .header(name, "v")
                .body(Body::empty())
                .unwrap();
            let h = get_headers(header_app(true), request).await;
            assert_eq!(h[header::CACHE_CONTROL], "no-store", "{name}");
        }
    }

    #[tokio::test]
    async fn a_response_that_sets_a_cookie_is_no_store() {
        let app = Router::new()
            .route(
                "/c",
                get(|| async { ([(header::SET_COOKIE, "s=1")], "challenge") }),
            )
            .layer(axum::middleware::from_fn_with_state(true, response_headers));
        let request = axum::http::Request::get("/c").body(Body::empty()).unwrap();
        let h = get_headers(app, request).await;
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_past_the_deadline_is_503_timeout() {
        let app = Router::new()
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(REQUEST_TIMEOUT + Duration::from_secs(1)).await;
                    "late"
                }),
            )
            .route("/fast", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(request_timeout));
        let slow = axum::http::Request::get("/slow")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(slow).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let fast = axum::http::Request::get("/fast")
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.oneshot(fast).await.unwrap().status(), StatusCode::OK);
    }

    #[test]
    fn a_peer_holds_at_most_its_share_of_connections() {
        let limits = ConnectionLimits::new(10, 2);
        let a = v4(192, 0, 2, 1);
        let first = limits.admit(a, limits.try_place().unwrap()).unwrap();
        let second = limits.admit(a, limits.try_place().unwrap()).unwrap();
        assert!(limits.admit(a, limits.try_place().unwrap()).is_none());
        // Another peer is not affected; a refused place is returned.
        let other = limits.admit(v4(192, 0, 2, 2), limits.try_place().unwrap());
        assert!(other.is_some());
        assert_eq!(limits.total.available_permits(), 7);
        drop(first);
        assert!(limits.admit(a, limits.try_place().unwrap()).is_some());
        drop(second);
        drop(other);
    }

    #[test]
    fn the_total_is_a_hard_cap() {
        let limits = ConnectionLimits::new(1, 5);
        let held = limits.admit(v4(192, 0, 2, 1), limits.try_place().unwrap());
        assert!(limits.try_place().is_none());
        drop(held);
        assert!(limits.try_place().is_some());
        assert!(limits.per_peer.lock().unwrap().is_empty());
    }

    #[test]
    fn the_tcp_cap_stays_within_bounds() {
        let (cap, share, _) = tcp_connection_cap();
        assert!((MIN_TCP_CONNECTIONS..=MAX_CONNECTIONS).contains(&cap));
        assert!((share as usize) < cap);
    }

    #[test]
    fn a_peers_share_is_an_eighth_of_the_total() {
        assert_eq!(peer_share(MAX_CONNECTIONS), MAX_CONNECTIONS_PER_PEER);
        // 256 open files leave 128 connections: 16 per peer, not all 128
        // to one.
        assert_eq!(peer_share(128), 16);
        assert_eq!(peer_share(MIN_TCP_CONNECTIONS), 8);
        assert_eq!(peer_share(100_000), MAX_CONNECTIONS_PER_PEER);
    }
}
