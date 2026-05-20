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
use tower_sessions::cookie::SameSite;
use tower_sessions::cookie::time::Duration;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};
use webauthn_rs::prelude::*;

use crate::apple_signin::{
    AppleJwksCache, apple_callback_handler, apple_idtoken_handler, apple_nonce_handler,
};
use crate::authn::{finish_authentication, finish_register, start_authentication, start_register};
use crate::constants::SESSION_TIMEOUT_SECONDS;
use crate::db::DynamoDBStore;
use crate::device_check::{
    finish_assertion, finish_attestation, generate_assertion_challenge, generate_challenge,
};
use crate::oidc::{
    AuthorizationCodeStore, OidcConfig, RefreshTokenStore, authorize as oidc_authorize,
    discovery as oidc_discovery, jwks as oidc_jwks, token as oidc_token, userinfo as oidc_userinfo,
};

mod apple_signin;
mod authn;
mod constants;
mod db;
mod device_check;
mod oidc;

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

    server_config.max_early_data_size = 0xffffffff;
    server_config.alpn_protocols = vec![b"h3".to_vec()];

    // Create Quinn server config
    let mut quinn_server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_config)?));

    let transport_config = Arc::get_mut(&mut quinn_server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(100_u8.into());
    transport_config.max_concurrent_bidi_streams(100_u8.into());

    // Bind UDP socket
    let socket = std::net::UdpSocket::bind(addr)?;
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(quinn_server_config),
        socket.try_into()?,
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
            Ok(Some((req, stream))) => {
                let app = app.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_h3_request(req, stream, app).await {
                        eprintln!("HTTP/3 request error: {}", e);
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("HTTP/3 accept error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

#[cfg(feature = "http3")]
async fn handle_h3_request(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<h3_quinn::RecvStream>, bytes::Bytes>,
    app: Router,
) -> Result<(), Box<dyn std::error::Error>> {
    // Convert H3 request to Axum request
    let (parts, _) = req.into_parts();
    let body = axum::body::Body::empty(); // TODO: Handle request body if needed
    let axum_req = http::Request::from_parts(parts, body);

    // Call the router (this is simplified - production would need proper integration)
    // For now, just return a basic response
    let response = http::Response::builder().status(200).body(()).unwrap();

    stream.send_response(response).await?;
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Load configuration
    let settings = load_config()?;

    // Load and validate EC keys
    let (signing_key, encoding_key, decoding_key) = load_ec_keys(
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

    // Initialize DynamoDB store
    let db_store = DynamoDBStore::new(
        env::var("DYNAMODB_CREDENTIALS_TABLE").unwrap_or_else(|_| "credentials".to_string()),
        env::var("DYNAMODB_HANDLES_TABLE").unwrap_or_else(|_| "handles".to_string()),
        env::var("DYNAMODB_DEVICE_BINDINGS_TABLE")
            .unwrap_or_else(|_| "device_bindings".to_string()),
    )
    .await
    .map_err(|e| format!("Failed to initialize DynamoDB store: {}", e))?;

    // Create the app state
    let app_state = AppState {
        webauthn,
        db_store: Arc::new(db_store),
        signing_key: Arc::new(signing_key),
        encoding_key: Arc::new(encoding_key),
        decoding_key: Arc::new(decoding_key),
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
            log::error!("Failed to connect to Redis: {:?}", err);
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
    let oidc_refresh_store = RefreshTokenStore::new(redis_client);
    let apple_jwks_cache = Arc::new(AppleJwksCache::new());

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
        // OIDC endpoints
        .route("/oauth/authorize", get(oidc_authorize))
        .route("/oauth/token", post(oidc_token))
        .route("/oauth/userinfo", get(oidc_userinfo))
        // Sign in with Apple
        .route("/oauth/apple/nonce", get(apple_nonce_handler))
        .route("/oauth/apple/idtoken", post(apple_idtoken_handler))
        .route("/oauth/apple/callback", post(apple_callback_handler))
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
        .layer(Extension(app_state))
        .layer(Extension(oidc_config))
        .layer(Extension(oidc_code_store))
        .layer(Extension(oidc_refresh_store))
        .layer(Extension(apple_jwks_cache))
        .layer(session_service)
        .layer(Extension(apple_app_site_association))
        .fallback(handler_fallback);

    let addr = format!("{}:{}", settings.bind_address, settings.port);
    println!("Listening on: {} (HTTP/1.1, HTTP/2, HTTP/3)", addr);

    if let Some(tls_acceptor) = tls_acceptor {
        // HTTPS mode with TLS - spawn both HTTP/2 and HTTP/3 servers

        // Spawn HTTP/3 (QUIC) server on UDP
        #[cfg(feature = "http3")]
        if env::var("ENABLE_HTTP3").unwrap_or_else(|_| "true".to_string()) == "true" {
            let h3_addr = format!("{}:{}", settings.bind_address, settings.port);
            let h3_app = app.clone();
            let h3_cert_path = settings.tls_cert_path.clone();
            let h3_key_path = settings.tls_key_path.clone();

            tokio::spawn(async move {
                if let Err(e) = run_h3_server(&h3_addr, h3_app, &h3_cert_path, &h3_key_path).await {
                    eprintln!("HTTP/3 server error: {}", e);
                }
            });
            println!("HTTP/3 (QUIC) enabled on UDP {}", h3_addr);
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
) -> Result<(SigningKey<NistP256>, EncodingKey, DecodingKey), Box<dyn std::error::Error>> {
    debug!("Loading EC signing key from: {}", sign_key_path);
    let signing_key = load_single_ec_key(sign_key_path)?;

    debug!("Loading EC encoding key from: {}", encoding_key_path);
    let encoding_key =
        EncodingKey::from_ec_pem(&std::fs::read(encoding_key_path)?).map_err(|e| {
            error!("Failed to create EncodingKey: {:?}", e);
            LoadKeysError::InvalidKeyFormat
        })?;

    debug!("Attempting to create DecodingKey from PEM contents");
    let decoding_key =
        DecodingKey::from_ec_pem(&std::fs::read(decoding_key_path)?).map_err(|e| {
            error!("Failed to create DecodingKey: {:?}", e);
            LoadKeysError::InvalidKeyFormat
        })?;

    debug!("Successfully loaded EC keys");
    Ok((signing_key, encoding_key, decoding_key))
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
