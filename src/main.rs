use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Extension, Router};
use axum_server::tls_rustls::RustlsConfig;
use ecdsa::SigningKey;
use http::Uri;
use jsonwebtoken::{DecodingKey, EncodingKey};
use log::{debug, error};
use p256::{NistP256, SecretKey};
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_sessions::cookie::time::Duration;
use tower_sessions::cookie::SameSite;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};
use webauthn_rs::prelude::*;

use crate::authn::{finish_authentication, finish_register, start_authentication, start_register};
use crate::db::DynamoDBStore;

mod authn;
mod db;

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
    let apple_app_site_association = load_apple_app_site_association().await;

    // Set up TLS if not disabled
    let tls_config = if settings.tls_enabled {
        Some(
            RustlsConfig::from_pem_file(
                PathBuf::from(settings.tls_cert_path),
                PathBuf::from(settings.tls_key_path),
            )
            .await
            .unwrap(),
        )
    } else {
        None
    };

    // Create the Webauthn instance
    let rp_id = "arkavo.net";
    let rp_origin = Url::parse("https://arkavo.net").expect("Invalid URL");
    let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
    let builder = builder.rp_name("Arkavo");
    let webauthn = Arc::new(builder.build().expect("Invalid configuration"));

    // Initialize DynamoDB store
    let db_store = DynamoDBStore::new(
        env::var("DYNAMODB_CREDENTIALS_TABLE").unwrap_or_else(|_| "credentials".to_string()),
        env::var("DYNAMODB_HANDLES_TABLE").unwrap_or_else(|_| "handles".to_string()),
    )
    .await
    .expect("Failed to initialize DynamoDB store");

    // Create the app state
    let app_state = AppState {
        webauthn,
        db_store: Arc::new(db_store),
        signing_key: Arc::new(signing_key),
        encoding_key: Arc::new(encoding_key),
        decoding_key: Arc::new(decoding_key),
    };

    let session_store = MemoryStore::default();
    let session_service = ServiceBuilder::new().layer(
        SessionManagerLayer::new(session_store)
            .with_name("authnz-rs")
            .with_same_site(SameSite::Strict)
            .with_secure(settings.tls_enabled)
            .with_expiry(Expiry::OnInactivity(Duration::seconds(600))),
    );

    // build our application with routes
    let app = Router::<()>::new()
        .route(
            "/.well-known/apple-app-site-association",
            get(serve_apple_app_site_association),
        )
        .route("/oauth/:client/:provider", get(handle_oauth_callback))
        .route("/register/:username", get(start_register))
        .route("/register", post(finish_register))
        .route("/authenticate/:username", get(start_authentication))
        .route("/authenticate", post(finish_authentication))
        .layer(Extension(app_state))
        .layer(session_service)
        .layer(Extension(apple_app_site_association))
        .fallback(handler_404);

    let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", settings.port))?;
    println!("Listening on: 0.0.0.0:{}", settings.port);

    if let Some(tls_config) = tls_config {
        axum_server::from_tcp_rustls(listener, tls_config)
            .serve(app.into_make_service())
            .await?;
    } else {
        axum_server::from_tcp(listener)
            .serve(app.into_make_service())
            .await?;
    }

    Ok(())
}

// Rest of the code (helper functions, handler_404, etc.) remains the same
async fn handler_404() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        StatusCode::NOT_FOUND.canonical_reason().unwrap(),
    )
}

#[derive(Debug, Clone)]
struct ServerSettings {
    port: u16,
    tls_enabled: bool,
    tls_cert_path: String,
    tls_key_path: String,
    sign_key_path: String,
    encoding_key_path: String,
    decoding_key_path: String,
    _enable_timing_logs: bool,
}

// Helper functions remain the same
fn load_config() -> Result<ServerSettings, Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;

    Ok(ServerSettings {
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
        sign_key_path: env::var("SIGN_KEY_PATH").expect("SIGN_KEY_PATH must be set"),
        encoding_key_path: env::var("ENCODING_KEY_PATH").expect("ENCODING_KEY_PATH must be set"),
        decoding_key_path: env::var("DECODING_KEY_PATH").expect("DECODING_KEY_PATH must be set"),
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

async fn load_apple_app_site_association() -> Arc<RwLock<serde_json::Value>> {
    let content = tokio::fs::read_to_string("apple-app-site-association.json")
        .await
        .expect("Failed to read apple-app-site-association.json");
    let json: serde_json::Value =
        serde_json::from_str(&content).expect("Failed to parse apple-app-site-association.json");
    Arc::new(RwLock::new(json))
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
    if let Some(state) = params.get("state") {
        if !validate_oauth_state(state) {
            error!("Invalid OAuth state parameter for {:?}", provider);
            return Redirect::temporary(&provider.get_error_uri("invalid_state", client));
        }
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
