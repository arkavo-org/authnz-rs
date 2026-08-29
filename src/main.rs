use fred::interfaces::ClientLike;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use ecdsa::SigningKey;
use http::Uri;
use jsonwebtoken::{DecodingKey, EncodingKey};
use log::{debug, error};
use p256::{NistP256, SecretKey};
#[cfg(feature = "http3")]
use quinn::crypto::rustls::QuicServerConfig;
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tower::ServiceBuilder;
#[cfg(feature = "http3")]
use tower::ServiceExt; // Router::oneshot in the HTTP/3 → Axum bridge
use tower_sessions::cookie::SameSite;
use tower_sessions::cookie::time::Duration;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};
use webauthn_rs::prelude::*;

use crate::apple_signin::{
    AppleJwksCache, apple_callback_handler, apple_idtoken_handler, apple_link_handler,
    apple_nonce_handler,
};
use crate::authn::{finish_authentication, finish_register, start_authentication, start_register};
use crate::constants::SESSION_TIMEOUT_SECONDS;
use crate::db::DynamoDBStore;
use crate::device_check::{
    finish_assertion, finish_attestation, generate_assertion_challenge, generate_challenge,
};
use crate::oidc::{
    AuthorizationCodeStore, OidcConfig, RefreshTokenStore, authorize as oidc_authorize,
    cose_keys as oidc_cose_keys, discovery as oidc_discovery, jwks as oidc_jwks,
    token as oidc_token, userinfo as oidc_userinfo,
};
use crate::patreon::{PatreonOAuthConfig, PatreonState, build_kms_sealer, patreon_link_handler};
use authnz_rs::{constants, cwt, keys};

mod agent;
mod apple_signin;
mod authn;
mod db;
mod device_check;
mod entities;
mod entitlements;
mod oidc;
mod patreon;
mod webvh;

// HTTP/3 server function (feature-gated)
#[cfg(feature = "http3")]
async fn run_h3_server(
    addr: &str,
    app: Router,
    cert_path: &str,
    key_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load certificates for QUIC
    let certs = {
        let cert_file = File::open(cert_path)?;
        let mut cert_reader = std::io::BufReader::new(cert_file);
        certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?
    };

    let key = {
        let key_file = File::open(key_path)?;
        let mut key_reader = std::io::BufReader::new(key_file);
        private_key(&mut key_reader)?.ok_or("No private key found")?
    };

    // Build rustls ServerConfig for QUIC
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // Disable QUIC/TLS 1.3 0-RTT (early data). 0-RTT data is replayable by a
    // network attacker (RFC 9001 §9.2, RFC 8470), and this service's endpoints
    // are overwhelmingly non-idempotent (token exchange, registration,
    // authentication, identity linking) with no per-request replay protection.
    // The only cost is one extra round trip on session resumption; correctness
    // and replay safety win for an auth/OIDC server. (0 = disabled per rustls.)
    server_config.max_early_data_size = 0;
    server_config.alpn_protocols = vec![b"h3".to_vec()];

    // Create Quinn server config
    let mut quinn_server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_config)?));

    let transport_config = Arc::get_mut(&mut quinn_server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(100_u8.into());
    transport_config.max_concurrent_bidi_streams(100_u8.into());

    // Bind UDP socket
    let socket = std::net::UdpSocket::bind(addr)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(quinn_server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;

    // Accept connections
    while let Some(connecting) = endpoint.accept().await {
        let app = app.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => {
                    if let Err(e) = handle_h3_connection(conn, app).await {
                        eprintln!("HTTP/3 connection error: {}", e);
                    }
                }
                Err(e) => eprintln!("HTTP/3 connection failed: {}", e),
            }
        });
    }

    Ok(())
}

#[cfg(feature = "http3")]
async fn handle_h3_connection(
    conn: quinn::Connection,
    app: Router,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;

    loop {
        match h3_conn.accept().await {
            // h3 0.0.8: accept() yields a RequestResolver; resolve_request()
            // awaits the headers and produces the (Request, RequestStream) pair.
            Ok(Some(resolver)) => {
                let app = app.clone();
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) = handle_h3_request(req, stream, app).await {
                                eprintln!("HTTP/3 request error: {}", e);
                            }
                        }
                        Err(e) => eprintln!("HTTP/3 request resolve error: {}", e),
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                // accept() returns Err when the connection ends — a client
                // disconnecting (graceful close, ApplicationClose, timeout) is
                // routine and terminal, not an operator-actionable error. Record
                // it at debug instead of spamming stderr on every closed
                // connection.
                debug!("HTTP/3 connection accept loop ended: {}", e);
                break;
            }
        }
    }

    Ok(())
}

#[cfg(feature = "http3")]
async fn handle_h3_request(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
    app: Router,
) -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Buf;

    // 1. Collect the H3 request body into an axum Body (bounded — auth/OIDC
    //    payloads are tiny; refuse anything larger rather than buffering
    //    unbounded memory from an untrusted peer).
    const MAX_H3_BODY: usize = 2 * 1024 * 1024; // 2 MiB
    let mut body_bytes: Vec<u8> = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        let remaining = chunk.remaining();
        if body_bytes.len() + remaining > MAX_H3_BODY {
            let resp = http::Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(())
                .unwrap();
            stream.send_response(resp).await?;
            stream.finish().await?;
            return Ok(());
        }
        body_bytes.extend_from_slice(chunk.copy_to_bytes(remaining).as_ref());
    }

    // A response to HEAD must carry the same headers as the GET-equivalent
    // (including Content-Length) but no message body. The TCP path gets this for
    // free from hyper; on H3 we serve the response ourselves, so capture the
    // method now and suppress the body frame below.
    let is_head = req.method() == Method::HEAD;

    // The QUIC stream frames the body, so the bytes we actually buffered are
    // authoritative. Normalize Content-Length so the router never sees a
    // client-supplied value that disagrees with the real body length.
    let (mut parts, _) = req.into_parts();
    parts.headers.remove(http::header::CONTENT_LENGTH);
    if !body_bytes.is_empty() {
        parts.headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from(body_bytes.len() as u64),
        );
    }
    let axum_req = http::Request::from_parts(parts, axum::body::Body::from(body_bytes));

    // 2. Drive the Axum router as a tower::Service (its error type is Infallible).
    let response = app
        .oneshot(axum_req)
        .await
        .map_err(|e| format!("router error: {e}"))?;

    // 3. Send status + headers, then forward the response body frame by frame
    //    (no full-body buffering — keeps memory bounded and preserves streaming
    //    for any future chunked response). A HEAD response carries the headers
    //    but no body.
    let (mut resp_parts, mut resp_body) = response.into_parts();

    // hyper synthesizes Content-Length from the body size at the wire layer on
    // the TCP path; that layer is bypassed here, so replicate it — advertise
    // Content-Length when the body length is exactly known and not already set.
    // This gives H3 clients (including HEAD probes, where the body is suppressed
    // below) the same Content-Length they would see over HTTP/2. Streaming bodies
    // of unknown size are left without it, exactly as on the TCP path.
    if !resp_parts
        .headers
        .contains_key(http::header::CONTENT_LENGTH)
        && let Some(len) = http_body::Body::size_hint(&resp_body).exact()
        && let Ok(value) = http::HeaderValue::from_str(&len.to_string())
    {
        resp_parts
            .headers
            .insert(http::header::CONTENT_LENGTH, value);
    }

    stream
        .send_response(http::Response::from_parts(resp_parts, ()))
        .await?;

    if !is_head {
        use http_body_util::BodyExt;
        while let Some(frame) = resp_body.frame().await {
            // Forward data frames; trailers (rare on these routes) are skipped.
            if let Ok(data) = frame?.into_data() {
                if !data.is_empty() {
                    stream.send_data(data).await?;
                }
            }
        }
    }
    stream.finish().await?;

    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub webauthn: Arc<Webauthn>,
    pub db_store: Arc<DynamoDBStore>,
    pub signing_key: Arc<SigningKey<NistP256>>,
    pub encoding_key: Arc<EncodingKey>,
    pub decoding_key: Arc<DecodingKey>,
    pub cwt_signing_key: Arc<p256::ecdsa::SigningKey>,
    pub cwt_verifying_key: Arc<p256::ecdsa::VerifyingKey>,
    /// RFC 7638 JWK thumbprint as raw 32-byte SHA-256 hash.
    /// JWKS advertises the base64url-encoded form of the same bytes
    /// (see oidc::ec_public_key_to_jwk), so CWT and JWT share the same kid.
    pub cwt_kid: Arc<Vec<u8>>,
    /// CWT/OIDC issuer string. Resolved once at startup from `OIDC_ISSUER`
    /// (falling back to [`crate::constants::DEFAULT_OIDC_ISSUER`]) so mint
    /// and verify always agree on a single value within a process.
    pub issuer: Arc<String>,
    /// Optional shared audience appended to every OIDC access token
    /// (`OIDC_PLATFORM_AUDIENCE`, e.g. "https://platform.arkavo.net").
    /// Access tokens normally carry `aud = client_id`, but a resource server
    /// validating one fixed audience (the OpenTDF platform's CWT verifier)
    /// must accept tokens minted for any RP — RFC 8707-style. None ⇒
    /// single-audience tokens, unchanged.
    pub platform_audience: Arc<Option<String>>,
    /// did:webvh Ed25519 update-signing key (crate `Secret` JSON), loaded from
    /// `WEBVH_SIGN_KEY_PATH`. `None` when unset — the passport DID document is
    /// still built and served as a legacy did:web view, but no signed
    /// `did.jsonl` log is emitted.
    pub webvh_sign_key: Arc<Option<String>>,
    /// Agent access token issuance config, parsed once at startup from
    /// `AGENT_TOKEN_AUDIENCES` / `AGENT_AUTHORIZED_ACTORS` / `AGENT_TOKEN_MINUTES`.
    pub agent_tokens: Arc<agent::AgentTokenConfig>,
    /// OIDC client_ids allowed to call PUT /admin/users/:id/entitlements and
    /// GET /entities/:id (`ADMIN_CLIENT_IDS`). Empty ⇒ no client is authorized.
    pub admin_client_ids: Arc<Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // rustls 0.23 is linked against both `aws-lc-rs` and `ring`, so it cannot
    // auto-pick a crypto provider and `ServerConfig::builder()` panics unless
    // a provider is installed first.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // Load configuration
    let settings = load_config()?;

    // Load and validate EC keys
    let (signing_key, encoding_key, decoding_key, cwt_signing_key, cwt_verifying_key, cwt_kid) =
        load_ec_keys(
            &settings.sign_key_path,
            &settings.encoding_key_path,
            &settings.decoding_key_path,
        )?;

    // Load and cache the apple-app-site-association.json file
    let apple_app_site_association = load_apple_app_site_association().await?;

    // Set up TLS if enabled
    let tls_acceptor = if settings.tls_enabled {
        let certs = {
            let cert_file = File::open(&settings.tls_cert_path).map_err(|e| {
                format!("Failed to open cert file {}: {}", settings.tls_cert_path, e)
            })?;
            let mut cert_reader = std::io::BufReader::new(cert_file);
            certs(&mut cert_reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("Failed to parse certificates: {}", e))?
        };

        let key = {
            let key_file = File::open(&settings.tls_key_path)
                .map_err(|e| format!("Failed to open key file {}: {}", settings.tls_key_path, e))?;
            let mut key_reader = std::io::BufReader::new(key_file);
            private_key(&mut key_reader)
                .map_err(|e| format!("Failed to parse private key: {}", e))?
                .ok_or_else(|| "No private key found in file".to_string())?
        };

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("Failed to build TLS config: {}", e))?;

        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Some(TlsAcceptor::from(Arc::new(server_config)))
    } else {
        None
    };

    // Create the Webauthn instance
    let rp_id = "identity.arkavo.net";
    let rp_origin = Url::parse("https://identity.arkavo.net")
        .map_err(|e| format!("Failed to parse RP origin URL: {}", e))?;
    let builder = WebauthnBuilder::new(rp_id, &rp_origin)
        .map_err(|e| format!("Failed to create WebAuthn builder: {}", e))?;
    let builder = builder.rp_name("Arkavo");
    let webauthn = Arc::new(
        builder
            .build()
            .map_err(|e| format!("Failed to build WebAuthn instance: {}", e))?,
    );

    let default_entitlements = entitlements::parse_user_default_entitlements(
        env::var("USER_DEFAULT_ENTITLEMENTS").ok().as_deref(),
    )
    .map_err(|e| format!("USER_DEFAULT_ENTITLEMENTS: {e}"))?;

    // Initialize DynamoDB store
    let db_store = DynamoDBStore::new(
        env::var("DYNAMODB_CREDENTIALS_TABLE").unwrap_or_else(|_| "credentials".to_string()),
        env::var("DYNAMODB_HANDLES_TABLE").unwrap_or_else(|_| "handles".to_string()),
        env::var("DYNAMODB_DEVICE_BINDINGS_TABLE")
            .unwrap_or_else(|_| "device_bindings".to_string()),
        env::var("DYNAMODB_IDENTITY_LINKS_TABLE").unwrap_or_else(|_| "identity_links".to_string()),
        env::var("DYNAMODB_PATREON_TOKENS_TABLE").unwrap_or_else(|_| "patreon_tokens".to_string()),
        env::var("DYNAMODB_AGENT_DELEGATIONS_TABLE")
            .unwrap_or_else(|_| "agent_delegations".to_string()),
        default_entitlements,
    )
    .await
    .map_err(|e| format!("Failed to initialize DynamoDB store: {}", e))?;

    // Resolve the issuer once so mint and verify in every handler agree on a
    // single value (eliminates per-request env reads and runtime-mutation
    // footguns).
    let issuer = env::var("OIDC_ISSUER")
        .unwrap_or_else(|_| crate::constants::DEFAULT_OIDC_ISSUER.to_string());

    // did:webvh Ed25519 update-signing key (fail-open: None when WEBVH_SIGN_KEY_PATH unset)
    let webvh_sign_key = webvh::load_sign_key();

    let agent_tokens = agent::AgentTokenConfig::parse(
        env::var("AGENT_TOKEN_AUDIENCES").ok(),
        env::var("AGENT_AUTHORIZED_ACTORS").ok(),
        env::var("AGENT_TOKEN_MINUTES").ok(),
    )
    .map_err(|e| format!("agent token config: {e}"))?;

    let admin_client_ids: Vec<String> = env::var("ADMIN_CLIENT_IDS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if admin_client_ids.is_empty() {
        log::warn!(
            "ADMIN_CLIENT_IDS is empty: PUT /admin/users/:id/entitlements and GET /entities/:id will 403"
        );
    }

    // Create the app state
    let app_state = AppState {
        webauthn,
        db_store: Arc::new(db_store),
        signing_key: Arc::new(signing_key),
        encoding_key: Arc::new(encoding_key),
        decoding_key: Arc::new(decoding_key),
        cwt_signing_key: Arc::new(cwt_signing_key),
        cwt_verifying_key: Arc::new(cwt_verifying_key),
        cwt_kid: Arc::new(cwt_kid),
        issuer: Arc::new(issuer),
        platform_audience: Arc::new(
            env::var("OIDC_PLATFORM_AUDIENCE")
                .ok()
                .filter(|v| !v.is_empty()),
        ),
        webvh_sign_key: Arc::new(webvh_sign_key),
        agent_tokens: Arc::new(agent_tokens),
        admin_client_ids: Arc::new(admin_client_ids),
    };

    // Set up Redis Client using fred
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let redis_config = fred::types::RedisConfig::from_url(&redis_url).unwrap_or_else(|_| {
        log::warn!(
            "Invalid REDIS_URL '{}', falling back to default config",
            redis_url
        );
        fred::types::RedisConfig::default()
    });
    let redis_client = fred::clients::RedisClient::new(redis_config, None, None, None);

    // Spawn connection in the background so a connection failure doesn't crash app startup
    let redis_conn_client = redis_client.clone();
    tokio::spawn(async move {
        let _conn_handle = redis_conn_client.connect();
        if let Err(err) = redis_conn_client.wait_for_connect().await {
            log::warn!("Failed to connect to Redis: {:?}", err);
        } else {
            log::info!("Successfully connected to Redis");
        }
    });

    // OIDC provider configuration (issuer, JWKS, registered clients).
    let oidc_config = Arc::new(
        OidcConfig::from_env(&settings.decoding_key_path)
            .map_err(|e| format!("Failed to load OIDC configuration: {}", e))?,
    );
    let oidc_code_store = AuthorizationCodeStore::new(redis_client.clone());
    let oidc_refresh_store = RefreshTokenStore::new(redis_client.clone());
    let apple_jwks_cache = Arc::new(AppleJwksCache::new());

    // Patreon support is optional; if PATREON_CLIENT_ID isn't set, every
    // Patreon code path (link handler + access_token enrichment) is silently
    // disabled. This lets non-Patreon deployments run without forced config.
    let patreon_oauth = PatreonOAuthConfig::from_env();
    let patreon_sealer = build_kms_sealer().await;
    if patreon_oauth.is_some() && patreon_sealer.is_none() {
        log::warn!(
            "PATREON_CLIENT_ID is set but PATREON_KMS_KEY_ID is not — \
             /oauth/patreon/link will reject with 503 (NotConfigured)"
        );
    }
    let patreon_state = PatreonState::new(patreon_oauth, patreon_sealer, redis_client);

    let session_store = MemoryStore::default();
    let session_service = ServiceBuilder::new().layer(
        SessionManagerLayer::new(session_store)
            .with_name("authnz-rs")
            .with_same_site(SameSite::Strict)
            .with_secure(settings.tls_enabled)
            .with_expiry(Expiry::OnInactivity(Duration::seconds(
                SESSION_TIMEOUT_SECONDS,
            ))),
    );

    // build our application with routes
    let app = Router::<()>::new()
        .route("/health", get(health_get).head(health_head))
        .route(
            "/.well-known/apple-app-site-association",
            get(serve_apple_app_site_association),
        )
        // OIDC discovery + JWKS (advertise this server as an OIDC provider)
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/.well-known/jwks.json", get(oidc_jwks))
        .route("/.well-known/cose-keys", get(oidc_cose_keys))
        // OIDC endpoints
        .route("/oauth/authorize", get(oidc_authorize))
        .route("/oauth/token", post(oidc_token))
        .route("/oauth/userinfo", get(oidc_userinfo))
        // Sign in with Apple
        .route("/oauth/apple/nonce", get(apple_nonce_handler))
        .route("/oauth/apple/idtoken", post(apple_idtoken_handler))
        .route("/oauth/apple/link", post(apple_link_handler))
        .route("/oauth/apple/callback", post(apple_callback_handler))
        // Patreon linking (mirrors /oauth/apple/link — same auth-required,
        // identity_links-write contract). Membership + tier are surfaced
        // only on the resulting OIDC access_token CWT; there is deliberately
        // no /me/patreon or /entitlements endpoint surface.
        .route("/oauth/patreon/link", post(patreon_link_handler))
        // Admin: per-user entitlement FQNs (service CWT required). Spec §2.3.
        .route(
            "/admin/users/:id/entitlements",
            axum::routing::put(entitlements::put_user_entitlements),
        )
        // Entity lookup (service CWT required). Spec §2.4.
        .route("/entities/:id", get(entities::get_entity))
        // Existing OAuth callback for native-app deep links (Patreon/Twitch/Discord/Reddit)
        .route("/oauth/:client/:provider", get(handle_oauth_callback))
        .route("/register/:username", get(start_register))
        .route("/register", post(finish_register))
        .route("/authenticate/:username", get(start_authentication))
        .route("/authenticate", post(finish_authentication))
        // Apple DeviceCheck / App Attest endpoints
        .route("/device-check/challenge/:username", get(generate_challenge))
        .route("/device-check/attest", post(finish_attestation))
        .route(
            "/device-check/assert-challenge/:username",
            get(generate_assertion_challenge),
        )
        .route("/device-check/assert", post(finish_assertion))
        // Agent delegation: a human (PE) delegates to an agent NPE (did:key).
        // Contract per arkavo-edge `arkavo-agent-auth` (issue #54).
        .route(
            "/.well-known/agent-configuration",
            get(agent::serve_agent_configuration),
        )
        .route("/agents/authorize", post(agent::authorize_agent))
        .route("/agents/delegations", get(agent::list_delegations))
        .route(
            "/agents/delegations/:did",
            axum::routing::delete(agent::revoke_delegation),
        )
        .route("/agents/challenge", get(agent::generate_agent_challenge))
        .route("/agents/token", post(agent::issue_agent_token))
        // did:webvh passport resolution. did.json is a legacy did:web view
        // (resolvable today); did.jsonl is the signed verifiable-history log
        // (populated when the `webvh` feature signs one).
        .route("/dids/:username/did.json", get(webvh::well_known_did_json))
        .route(
            "/dids/:username/did.jsonl",
            get(webvh::well_known_did_jsonl),
        )
        .layer(Extension(app_state))
        .layer(Extension(oidc_config))
        .layer(Extension(oidc_code_store))
        .layer(Extension(oidc_refresh_store))
        .layer(Extension(apple_jwks_cache))
        .layer(Extension(patreon_state))
        .layer(session_service)
        .layer(Extension(apple_app_site_association))
        .fallback(handler_fallback);

    // The H3 server serves the base router (without the Alt-Svc layer added
    // below), so HTTP/3 responses don't redundantly advertise h3 to themselves —
    // Alt-Svc is only meaningful to upgrade a TCP (HTTP/1.1/2) client to H3.
    #[cfg(feature = "http3")]
    let h3_app_base = app.clone();

    // Advertise HTTP/3 via Alt-Svc on the TCP (HTTP/1.1 + HTTP/2) responses, but
    // only when H3 is actually serving: the feature is compiled in, the runtime
    // toggle is on, and TLS is enabled (H3 is only spawned in the TLS branch).
    // This is a no-op for the default build, keeping the non-http3 path
    // byte-for-byte unchanged.
    let advertise_h3 = cfg!(feature = "http3")
        && settings.tls_enabled
        && env::var("ENABLE_HTTP3").unwrap_or_else(|_| "true".to_string()) == "true";
    let app = if advertise_h3 {
        let alt_svc = alt_svc_header_value(settings.port);
        app.layer(axum::middleware::from_fn(
            move |req: Request, next: axum::middleware::Next| {
                let alt_svc = alt_svc.clone();
                async move {
                    let mut res = next.run(req).await;
                    res.headers_mut().insert(http::header::ALT_SVC, alt_svc);
                    res
                }
            },
        ))
    } else {
        app
    };

    let addr = format!("{}:{}", settings.bind_address, settings.port);
    println!("Listening on: {} (HTTP/1.1, HTTP/2, HTTP/3)", addr);

    if let Some(tls_acceptor) = tls_acceptor {
        // HTTPS mode with TLS - spawn both HTTP/2 and HTTP/3 servers

        // Spawn HTTP/3 (QUIC) server on UDP
        #[cfg(feature = "http3")]
        if env::var("ENABLE_HTTP3").unwrap_or_else(|_| "true".to_string()) == "true" {
            let h3_addr = format!("{}:{}", settings.bind_address, settings.port);
            let h3_app = h3_app_base;
            let h3_cert_path = settings.tls_cert_path.clone();
            let h3_key_path = settings.tls_key_path.clone();

            let log_addr = h3_addr.clone();
            tokio::spawn(async move {
                if let Err(e) = run_h3_server(&h3_addr, h3_app, &h3_cert_path, &h3_key_path).await {
                    eprintln!("HTTP/3 server error: {}", e);
                }
            });
            println!("HTTP/3 (QUIC) enabled on UDP {}", log_addr);
        }

        #[cfg(not(feature = "http3"))]
        {
            println!("HTTP/3 not enabled (compile with --features http3 to enable)");
        }

        // HTTP/2 server on TCP
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;

        let make_service = app.into_make_service();

        loop {
            let (stream, remote_addr) = listener
                .accept()
                .await
                .map_err(|e| format!("Failed to accept connection: {}", e))?;

            let tls_acceptor = tls_acceptor.clone();
            let mut make_service = make_service.clone();

            tokio::spawn(async move {
                match tls_acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let tower_service = match make_service.call(remote_addr).await {
                            Ok(service) => service,
                            Err(_) => {
                                eprintln!("Failed to create service for {}", remote_addr);
                                return;
                            }
                        };

                        let hyper_service = hyper::service::service_fn(
                            move |request: hyper::Request<hyper::body::Incoming>| {
                                tower_service.clone().call(request)
                            },
                        );

                        if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(hyper_util::rt::TokioIo::new(tls_stream), hyper_service)
                        .await
                        {
                            eprintln!("Error serving connection: {:?}", err);
                        }
                    }
                    Err(err) => {
                        eprintln!("TLS handshake error: {:?}", err);
                    }
                }
            });
        }
    } else {
        // HTTP mode without TLS
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;

        axum::serve(listener, app)
            .await
            .map_err(|e| format!("Server error: {}", e))?;
    }

    Ok(())
}

// Health check handlers
async fn health_get() -> &'static str {
    "ok"
}

async fn health_head() -> StatusCode {
    StatusCode::OK
}

/// Build the `Alt-Svc` header value advertising HTTP/3 availability on `port`.
/// `ma` (max-age, seconds) is advisory; 86400s = 24h is a conservative default.
fn alt_svc_header_value(port: u16) -> http::HeaderValue {
    http::HeaderValue::from_str(&format!("h3=\":{}\"; ma=86400", port))
        .expect("alt-svc header value is always valid ASCII")
}

// Fallback handler - properly handle HEAD requests without body
async fn handler_fallback(request: Request) -> Response {
    if request.method() == Method::HEAD {
        // HEAD must return no body, only status code
        StatusCode::NOT_FOUND.into_response()
    } else {
        // GET and other methods can return a body
        (
            StatusCode::NOT_FOUND,
            StatusCode::NOT_FOUND.canonical_reason().unwrap(),
        )
            .into_response()
    }
}

#[derive(Debug, Clone)]
struct ServerSettings {
    bind_address: String,
    port: u16,
    tls_enabled: bool,
    tls_cert_path: String,
    tls_key_path: String,
    sign_key_path: String,
    encoding_key_path: String,
    decoding_key_path: String,
    _enable_timing_logs: bool,
}

// Validate required environment variables on startup
fn validate_env_vars() -> Result<(), Box<dyn std::error::Error>> {
    let required_vars = ["SIGN_KEY_PATH", "ENCODING_KEY_PATH", "DECODING_KEY_PATH"];
    let mut missing_vars = Vec::new();

    for var in &required_vars {
        if env::var(var).is_err() {
            missing_vars.push(*var);
        }
    }

    if !missing_vars.is_empty() {
        return Err(format!(
            "Missing required environment variables: {}",
            missing_vars.join(", ")
        )
        .into());
    }

    Ok(())
}

fn load_config() -> Result<ServerSettings, Box<dyn std::error::Error>> {
    // Validate required environment variables first
    validate_env_vars()?;

    let current_dir = env::current_dir()?;

    Ok(ServerSettings {
        bind_address: env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0".to_string()),
        port: env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()?,
        tls_enabled: env::var("TLS_CERT_PATH").is_ok(),
        tls_cert_path: env::var("TLS_CERT_PATH").unwrap_or_else(|_| {
            current_dir
                .join("fullchain.pem")
                .to_str()
                .unwrap()
                .to_string()
        }),
        tls_key_path: env::var("TLS_KEY_PATH").unwrap_or_else(|_| {
            current_dir
                .join("privkey.pem")
                .to_str()
                .unwrap()
                .to_string()
        }),
        sign_key_path: env::var("SIGN_KEY_PATH").unwrap(),
        encoding_key_path: env::var("ENCODING_KEY_PATH").unwrap(),
        decoding_key_path: env::var("DECODING_KEY_PATH").unwrap(),
        _enable_timing_logs: env::var("ENABLE_TIMING_LOGS")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false),
    })
}

fn load_ec_keys(
    sign_key_path: &str,
    encoding_key_path: &str,
    decoding_key_path: &str,
) -> Result<
    (
        SigningKey<NistP256>,
        EncodingKey,
        DecodingKey,
        p256::ecdsa::SigningKey,
        p256::ecdsa::VerifyingKey,
        Vec<u8>,
    ),
    Box<dyn std::error::Error>,
> {
    debug!("Loading EC signing key from: {}", sign_key_path);
    let signing_key = load_single_ec_key(sign_key_path)?;

    debug!("Loading EC encoding key from: {}", encoding_key_path);
    let encoding_pem = std::fs::read(encoding_key_path)?;
    let encoding_pem_str = std::str::from_utf8(&encoding_pem)
        .map_err(|e| format!("Encoding key PEM is not valid UTF-8: {e}"))?;

    let encoding_key = EncodingKey::from_ec_pem(&encoding_pem).map_err(|e| {
        error!("Failed to create EncodingKey: {:?}", e);
        LoadKeysError::InvalidKeyFormat
    })?;

    debug!("Attempting to create DecodingKey from PEM contents");
    let decoding_pem = std::fs::read(decoding_key_path)?;
    let decoding_pem_str = std::str::from_utf8(&decoding_pem)
        .map_err(|e| format!("Decoding key PEM is not valid UTF-8: {e}"))?;

    let decoding_key = DecodingKey::from_ec_pem(&decoding_pem).map_err(|e| {
        error!("Failed to create DecodingKey: {:?}", e);
        LoadKeysError::InvalidKeyFormat
    })?;

    // Load the same EC key material as p256 type for CWT signing/verification,
    // plus the RFC 7638 thumbprint kid. Shared with `src/bin/seed-test-user.rs`
    // via `authnz_rs::keys::load_cwt_keys` so both binaries derive identical
    // CWT keys/kid from the same encoding/decoding key PEMs. The verifying
    // key comes from `decoding_pem_str` (not derived from the signing key)
    // and is checked against it — a mismatched pair errors out here rather
    // than silently minting tokens nothing can verify.
    let (cwt_signing_key, cwt_verifying_key, cwt_kid) =
        keys::load_cwt_keys(encoding_pem_str, decoding_pem_str)?;

    debug!("Successfully loaded EC keys");
    Ok((
        signing_key,
        encoding_key,
        decoding_key,
        cwt_signing_key,
        cwt_verifying_key,
        cwt_kid,
    ))
}

fn load_single_ec_key(key_path: &str) -> Result<SigningKey<NistP256>, Box<dyn std::error::Error>> {
    let mut file = File::open(key_path)?;
    let mut pem_contents = String::new();
    file.read_to_string(&mut pem_contents)?;

    debug!("Parsing PEM contents");
    let pem = pem::parse(pem_contents)?;

    if pem.tag() != "EC PRIVATE KEY" {
        error!("PEM file does not contain an EC PRIVATE KEY");
        return Err(Box::new(LoadKeysError::InvalidKeyType));
    }

    debug!("Attempting to create SigningKey from PEM contents");
    let secret_key = SecretKey::from_sec1_der(pem.contents()).map_err(|e| {
        error!("Failed to parse EC PRIVATE KEY: {:?}", e);
        LoadKeysError::InvalidKeyFormat
    })?;
    Ok(SigningKey::from(secret_key))
}

async fn load_apple_app_site_association()
-> Result<Arc<RwLock<serde_json::Value>>, Box<dyn std::error::Error>> {
    let content = tokio::fs::read_to_string("apple-app-site-association.json")
        .await
        .map_err(|e| format!("Failed to read apple-app-site-association.json: {}", e))?;
    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse apple-app-site-association.json: {}", e))?;
    Ok(Arc::new(RwLock::new(json)))
}

async fn serve_apple_app_site_association(
    Extension(apple_app_site_association): Extension<Arc<RwLock<serde_json::Value>>>,
) -> impl IntoResponse {
    let json = apple_app_site_association.read().await;
    axum::Json(json.clone())
}

#[derive(Debug, Clone, Copy)]
enum OAuthClient {
    Arkavo,
    ArkavoCreator,
}

impl FromStr for OAuthClient {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sanitized = s.trim().to_lowercase();
        match sanitized.as_str() {
            "arkavo" => Ok(OAuthClient::Arkavo),
            "arkavocreator" => Ok(OAuthClient::ArkavoCreator),
            _ => Err(format!("Unknown OAuth client: {}", s)),
        }
    }
}

impl OAuthClient {
    fn as_scheme(&self) -> &'static str {
        match self {
            OAuthClient::Arkavo => "arkavo",
            OAuthClient::ArkavoCreator => "arkavocreator",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum OAuthProvider {
    Patreon,
    Twitch,
    Discord,
    Reddit,
}

impl FromStr for OAuthProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Sanitize input: trim whitespace, convert to lowercase, remove any special characters
        let sanitized = s.trim().to_lowercase();

        match sanitized.as_str() {
            "patreon" => Ok(OAuthProvider::Patreon),
            "twitch" => Ok(OAuthProvider::Twitch),
            "discord" => Ok(OAuthProvider::Discord),
            "reddit" => Ok(OAuthProvider::Reddit),
            _ => Err(format!("Unknown OAuth provider: {}", s)),
        }
    }
}

// Sanitize the OAuth code
fn sanitize_code(code: &str) -> String {
    // OAuth codes are typically alphanumeric with possibly some special characters
    // Remove any characters that aren't alphanumeric, '-', or '_'
    code.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .take(1024) // Reasonable length limit for OAuth codes
        .collect()
}

// Sanitize error messages
fn sanitize_error(error: &str) -> String {
    // Only allow alphanumeric characters and underscores in error messages
    error
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .take(100) // Reasonable length limit for error messages
        .collect()
}

impl OAuthProvider {
    fn as_str(&self) -> &'static str {
        match self {
            OAuthProvider::Patreon => "patreon",
            OAuthProvider::Twitch => "twitch",
            OAuthProvider::Discord => "discord",
            OAuthProvider::Reddit => "reddit",
        }
    }

    fn get_redirect_uri(&self, code: &str, client: OAuthClient) -> String {
        format!(
            "{}://oauth/{}?code={}",
            client.as_scheme(),
            self.as_str(),
            sanitize_code(code)
        )
    }

    fn get_error_uri(&self, error: &str, client: OAuthClient) -> String {
        format!(
            "{}://oauth/{}?error={}",
            client.as_scheme(),
            self.as_str(),
            sanitize_error(error)
        )
    }
}

async fn handle_oauth_callback(
    uri: Uri,
    axum::extract::Path((client, provider)): axum::extract::Path<(String, String)>,
) -> impl IntoResponse {
    debug!(
        "Received OAuth callback for client: {} and provider: {}",
        client.trim(),
        provider.trim()
    );

    // Validate and parse the client first
    let client = match OAuthClient::from_str(&client) {
        Ok(client) => client,
        Err(e) => {
            error!("Invalid OAuth client: {}", e);
            return Redirect::temporary("arkavo://oauth/error?error=invalid_client");
        }
    };

    // Validate and parse the provider
    let provider = match OAuthProvider::from_str(&provider) {
        Ok(provider) => provider,
        Err(e) => {
            error!("Invalid OAuth provider: {}", e);
            return Redirect::temporary(&format!(
                "{}://oauth/error?error=invalid_provider",
                client.as_scheme()
            ));
        }
    };

    // Parse and validate query parameters
    let query = uri.query().unwrap_or_default();
    let params: HashMap<_, _> = form_urlencoded::parse(query.as_bytes()).collect();

    // Validate state parameter if provider requires it
    if let Some(state) = params.get("state")
        && !validate_oauth_state(state)
    {
        error!("Invalid OAuth state parameter for {:?}", provider);
        return Redirect::temporary(&provider.get_error_uri("invalid_state", client));
    }

    // Handle the authorization code
    match params.get("code").map(|s| s.as_ref()) {
        Some(code) if !code.is_empty() => {
            debug!("Processing OAuth code for {:?}", provider);
            Redirect::temporary(&provider.get_redirect_uri(code, client))
        }
        _ => {
            // Check for error parameters from OAuth provider
            if let Some(error) = params.get("error").map(|s| s.as_ref()) {
                error!("OAuth error from provider: {}", error);
                return Redirect::temporary(&provider.get_error_uri(error, client));
            }

            error!("No code provided in OAuth callback for {:?}", provider);
            Redirect::temporary(&provider.get_error_uri("no_code", client))
        }
    }
}

// Validate OAuth state parameter
fn validate_oauth_state(state: &str) -> bool {
    // State should be alphanumeric and reasonable length
    if state.len() > 100 || state.is_empty() {
        return false;
    }

    state
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

#[derive(Debug, thiserror::Error)]
enum LoadKeysError {
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Invalid key type")]
    InvalidKeyType,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http::StatusCode;
    use tower::ServiceExt;

    // Helper function to create test app
    fn create_test_app() -> Router {
        Router::new().route("/oauth/:client/:provider", get(handle_oauth_callback))
    }

    #[test]
    fn alt_svc_header_advertises_h3_on_port() {
        assert_eq!(
            alt_svc_header_value(443).to_str().unwrap(),
            "h3=\":443\"; ma=86400"
        );
        assert_eq!(
            alt_svc_header_value(8443).to_str().unwrap(),
            "h3=\":8443\"; ma=86400"
        );
    }

    #[tokio::test]
    async fn test_valid_oauth_providers() {
        let app = create_test_app();
        let providers = vec!["patreon", "twitch", "discord", "reddit"];
        let clients = vec!["arkavo", "arkavocreator"];

        for client in clients {
            for provider in providers.clone() {
                let code = "test_auth_code_123";
                let uri = format!("/oauth/{}/{}?code={}", client, provider, code);
                let response = app
                    .clone()
                    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();

                assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
                let location = response
                    .headers()
                    .get("location")
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert_eq!(
                    location,
                    format!("{}://oauth/{}?code=test_auth_code_123", client, provider)
                );
            }
        }
    }

    #[tokio::test]
    async fn test_invalid_oauth_provider() {
        let app = create_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/oauth/arkavo/invalid_provider?code=123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "arkavo://oauth/error?error=invalid_provider");
    }

    #[tokio::test]
    async fn test_missing_code() {
        let app = create_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/oauth/arkavo/patreon")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "arkavo://oauth/patreon?error=no_code");
    }

    #[tokio::test]
    async fn test_provider_case_insensitivity() {
        let app = create_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/oauth/arkavo/PATREON?code=123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "arkavo://oauth/patreon?code=123");
    }

    #[tokio::test]
    async fn test_error_parameter_handling() {
        let app = create_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/oauth/arkavo/patreon?error=access_denied")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "arkavo://oauth/patreon?error=access_denied");
    }

    #[test]
    fn test_provider_from_str() {
        assert!(matches!(
            OAuthProvider::from_str("patreon"),
            Ok(OAuthProvider::Patreon)
        ));
        assert!(matches!(
            OAuthProvider::from_str("PATREON"),
            Ok(OAuthProvider::Patreon)
        ));
        assert!(matches!(
            OAuthProvider::from_str(" patreon "),
            Ok(OAuthProvider::Patreon)
        ));
        assert!(OAuthProvider::from_str("unknown").is_err());
    }

    #[test]
    fn test_sanitize_code() {
        assert_eq!(sanitize_code("abc123"), "abc123");
        assert_eq!(sanitize_code("abc<script>123"), "abcscript123");
        assert_eq!(sanitize_code("abc-123_456"), "abc-123_456");

        // Test length limit
        let long_code = "a".repeat(2000);
        assert_eq!(sanitize_code(&long_code).len(), 1024);
    }

    #[test]
    fn test_sanitize_error() {
        assert_eq!(sanitize_error("access_denied"), "access_denied");
        assert_eq!(sanitize_error("error<script>"), "errorscript");

        // Test length limit
        let long_error = "e".repeat(200);
        assert_eq!(sanitize_error(&long_error).len(), 100);
    }

    #[test]
    fn test_validate_oauth_state() {
        assert!(validate_oauth_state("valid_state_123"));
        assert!(!validate_oauth_state(""));
        assert!(!validate_oauth_state("invalid<script>state"));
        assert!(!validate_oauth_state(&"a".repeat(101)));
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Build an AppState suitable for unit tests. Uses a fixed scalar
    /// so signatures are reproducible. Requires AWS env vars to be set
    /// (fake values are fine) before calling, as DynamoDBStore::new is async.
    pub async fn build_test_app_state() -> AppState {
        use base64::Engine;
        use p256::pkcs8::EncodePrivateKey;

        // Use a fixed [0x42u8; 32] scalar so test signatures are stable.
        let scalar = p256::elliptic_curve::ScalarPrimitive::from_slice(&[0x42u8; 32]).unwrap();
        let secret = p256::SecretKey::new(scalar);

        // SigningKey for attestation envelope.
        let signing_key: ecdsa::SigningKey<p256::NistP256> = (&secret).into();

        // JWT EncodingKey from the PKCS8 DER form.
        let pkcs8_der = secret.to_pkcs8_der().expect("encode pkcs8");
        let encoding_key = jsonwebtoken::EncodingKey::from_ec_der(pkcs8_der.as_bytes());

        // Decoding key — use a placeholder (tests using JWT decoding should use their own key).
        let decoding_key = jsonwebtoken::DecodingKey::from_secret(&[]);

        // CWT keys (same scalar).
        let cwt_signing_key: p256::ecdsa::SigningKey = (&secret).into();
        let cwt_verifying_key = *cwt_signing_key.verifying_key();

        // CWT kid: RFC 7638 thumbprint (raw 32 bytes).
        let cwt_kid: Vec<u8> = {
            let encoded = cwt_verifying_key.to_encoded_point(false);
            let x = encoded.x().unwrap();
            let y = encoded.y().unwrap();
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let thumb_input = format!(
                "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
                b64.encode(x),
                b64.encode(y)
            );
            let mut hasher = Sha256::new();
            hasher.update(thumb_input.as_bytes());
            hasher.finalize().to_vec()
        };

        let webauthn = Arc::new(
            webauthn_rs::WebauthnBuilder::new(
                "identity.arkavo.net",
                &url::Url::parse("https://identity.arkavo.net").unwrap(),
            )
            .unwrap()
            .build()
            .unwrap(),
        );

        let db_store = Arc::new(
            crate::db::DynamoDBStore::new(
                "credentials".to_string(),
                "handles".to_string(),
                "device_bindings".to_string(),
                "identity_links".to_string(),
                "patreon_tokens".to_string(),
                "agent_delegations".to_string(),
                crate::constants::DEFAULT_USER_ENTITLEMENTS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
            )
            .await
            .unwrap(),
        );

        AppState {
            webauthn,
            db_store,
            signing_key: Arc::new(signing_key),
            encoding_key: Arc::new(encoding_key),
            decoding_key: Arc::new(decoding_key),
            cwt_signing_key: Arc::new(cwt_signing_key),
            cwt_verifying_key: Arc::new(cwt_verifying_key),
            cwt_kid: Arc::new(cwt_kid),
            issuer: Arc::new(crate::constants::DEFAULT_OIDC_ISSUER.to_string()),
            platform_audience: Arc::new(None),
            webvh_sign_key: Arc::new(None),
            agent_tokens: Arc::new(agent::AgentTokenConfig {
                audiences: vec!["https://platform.arkavo.net".into()],
                authorized_actors: vec!["https://kg.arkavo.net".into()],
                minutes: 15,
            }),
            admin_client_ids: Arc::new(vec!["it".into()]),
        }
    }
}
