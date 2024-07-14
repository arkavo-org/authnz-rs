use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{Extension, Router};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum_server::tls_rustls::RustlsConfig;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceBuilder;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};
use tower_sessions::cookie::SameSite;
use tower_sessions::cookie::time::Duration;
use webauthn_rs::prelude::*;

use crate::authn::{finish_authentication, finish_register, start_authentication, start_register};

mod authn;

#[tokio::main]
async fn main() {
    // Load configuration
    let settings = load_config().unwrap();
    // Load and cache the apple-app-site-association.json file
    let apple_app_site_association = load_apple_app_site_association().await;
    // Set up TLS if not disabled
    let tls_config = if settings.tls_enabled {
        Some(
            RustlsConfig::from_pem_file(
                PathBuf::from(settings.tls_cert_path),
                PathBuf::from(settings.tls_key_path),
            ).await.unwrap()
        )
    } else {
        None
    };
    // Create the app
    let app_state = AppState::new();
    let session_store = MemoryStore::default();
    let session_service = ServiceBuilder::new()
        .layer(
            SessionManagerLayer::new(session_store)
                .with_name("authnz-rs")
                .with_same_site(SameSite::Strict)
                .with_secure(false) // TODO: change this to true when running on an HTTPS/production server instead of locally
                .with_expiry(Expiry::OnInactivity(Duration::seconds(600))),
        );
    // build our application with a route
    let app = Router::<()>::new()
        .route("/.well-known/apple-app-site-association", get(serve_apple_app_site_association))
        .route("/challenge/:username", get(start_register))
        .route("/register_finish", post(finish_register))
        .route("/login_start/:username", post(start_authentication))
        .route("/login_finish", post(finish_authentication))
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
        axum_server::from_tcp(listener);
    }
}

#[derive(Clone)]
pub struct AppState {
    // Webauthn has no mutable inner state, so Arc and read only is sufficent.
    // Alternately, you could use a reference here provided you can work out
    // lifetimes.
    pub webauthn: Arc<Webauthn>,
    // This needs mutability, so does require a mutex.
    pub accounts: Arc<Mutex<AccountData>>,
}

impl AppState {
    pub fn new() -> Self {
        // Effective domain name.
        let rp_id = "localhost";
        // Url containing the effective domain name
        // MUST include the port number!
        let rp_origin = Url::parse("http://localhost:8080").expect("Invalid URL");
        let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");

        // Now, with the builder you can define other options.
        // Set a "nice" relying party name. Has no security properties and
        // may be changed in the future.
        let builder = builder.rp_name("Axum Webauthn-rs");

        // Consume the builder and create our webauthn instance.
        let webauthn = Arc::new(builder.build().expect("Invalid configuration"));

        let users = Arc::new(Mutex::new(AccountData {
            name_to_id: HashMap::new(),
            keys: HashMap::new(),
        }));

        AppState { webauthn, accounts: users }
    }
}

pub struct AccountData {
    pub name_to_id: HashMap<String, Uuid>,
    pub keys: HashMap<Uuid, Vec<Passkey>>,
}

async fn handler_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND.canonical_reason().unwrap())
}

#[derive(Debug, Clone)]
struct ServerSettings {
    port: u16,
    tls_enabled: bool,
    tls_cert_path: String,
    tls_key_path: String,
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
        _enable_timing_logs: env::var("ENABLE_TIMING_LOGS")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false),
    })
}

async fn load_apple_app_site_association() -> Arc<RwLock<serde_json::Value>> {
    let content = tokio::fs::read_to_string("apple-app-site-association.json")
        .await
        .expect("Failed to read apple-app-site-association.json");
    let json: serde_json::Value = serde_json::from_str(&content)
        .expect("Failed to parse apple-app-site-association.json");
    Arc::new(RwLock::new(json))
}

async fn serve_apple_app_site_association(
    Extension(apple_app_site_association): Extension<Arc<RwLock<serde_json::Value>>>,
) -> impl IntoResponse {
    let json = apple_app_site_association.read().await;
    axum::Json(json.clone())
}
