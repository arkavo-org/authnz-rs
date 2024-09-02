use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Router};
use axum_server::tls_rustls::RustlsConfig;
use ecdsa::SigningKey;
use p256::{NistP256, SecretKey};
use pem::Pem;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceBuilder;
use tower_sessions::cookie::time::Duration;
use tower_sessions::cookie::SameSite;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};
use webauthn_rs::prelude::*;

use crate::authn::{finish_authentication, finish_register, start_authentication, start_register};

mod authn;

#[derive(Clone)]
pub struct AppState {
    pub webauthn: Arc<Webauthn>,
    pub accounts: Arc<Mutex<AccountData>>,
    pub signing_key: Arc<SigningKey<NistP256>>,
    pub signing_key_pem: Arc<Pem>,
}

pub struct AccountData {
    pub name_to_id: HashMap<String, Uuid>,
    pub keys: HashMap<Uuid, Vec<Passkey>>,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    // Load configuration
    let settings = load_config().unwrap();
    // Load and validate EC keys
    let (signing_key, signing_key_pem) = load_ec_keys(&settings.sign_key_path).expect("Failed to load signing keys");
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
    let rp_id = "webauthn.arkavo.net";
    let rp_origin = Url::parse("https://webauthn.arkavo.net").expect("Invalid URL");
    let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
    let builder = builder.rp_name("Arkavo");
    let webauthn = Arc::new(builder.build().expect("Invalid configuration"));
    // Create the app state
    let app_state = AppState {
        webauthn,
        accounts: Arc::new(Mutex::new(AccountData {
            name_to_id: HashMap::new(),
            keys: HashMap::new(),
        })),
        signing_key: Arc::new(signing_key),
        signing_key_pem: Arc::new(signing_key_pem),
    };
    let session_store = MemoryStore::default();
    let session_service = ServiceBuilder::new().layer(
        SessionManagerLayer::new(session_store)
            .with_name("authnz-rs")
            .with_same_site(SameSite::Strict)
            .with_secure(settings.tls_enabled)
            .with_expiry(Expiry::OnInactivity(Duration::seconds(600))),
    );
    // build our application with a route
    let app = Router::<()>::new()
        .route(
            "/.well-known/apple-app-site-association",
            get(serve_apple_app_site_association),
        )
        .route("/register/:username", get(start_register))
        .route("/register", post(finish_register))
        .route("/authenticate/:username", get(start_authentication))
        .route("/authenticate", post(finish_authentication))
        .layer(Extension(app_state))
        .layer(session_service)
        .layer(Extension(apple_app_site_association))
        .fallback(handler_404);
    let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", settings.port)).unwrap();
    println!("Listening on: 0.0.0.0:{}", settings.port);
    if let Some(tls_config) = tls_config {
        axum_server::from_tcp_rustls(listener, tls_config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    } else {
        axum_server::from_tcp(listener)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }
}

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
    _enable_timing_logs: bool,
}

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
        _enable_timing_logs: env::var("ENABLE_TIMING_LOGS")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false),
    })
}

fn load_ec_keys(key_path: &str) -> Result<(SigningKey<NistP256>, Pem), Box<dyn std::error::Error>> {
    let file = File::open(key_path)?;
    let mut reader = BufReader::new(file);
    let mut contents = Vec::new();
    reader.read_to_end(&mut contents)?;

    let pem_keys = pem::parse_many(&contents)?;
    if pem_keys.is_empty() {
        return Err(Box::new(LoadKeysError::KeysNotFound));
    }

    for pem in pem_keys {
        if pem.tag() != "EC PRIVATE KEY" {
            continue;
        }
        let key_bytes = pem.contents();
        if let Ok(secret_key) = SecretKey::from_sec1_der(&key_bytes) {
            let signing_key = SigningKey::from(secret_key);
            return Ok((signing_key, pem));
        }
    }

    Err(Box::new(LoadKeysError::SigningKeyNotFound))
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

#[derive(Debug, thiserror::Error)]
enum LoadKeysError {
    #[error("Failed to load EC keys")]
    KeysNotFound,
    #[error("Signing key not found")]
    SigningKeyNotFound,
}
