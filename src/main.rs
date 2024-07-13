use std::collections::HashMap;
use std::sync::Arc;

use axum::{Extension, Router};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use tokio::sync::Mutex;
use tower::ServiceBuilder;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};
use tower_sessions::cookie::SameSite;
use tower_sessions::cookie::time::Duration;
use webauthn_rs::prelude::*;

use crate::authn::{finish_authentication, finish_register, start_authentication, start_register};

mod authn;

#[tokio::main]
async fn main() {
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
        .route("/register_start/:username", post(start_register))
        .route("/register_finish", post(finish_register))
        .route("/login_start/:username", post(start_authentication))
        .route("/login_finish", post(finish_authentication))
        .layer(Extension(app_state))
        .layer(session_service)
        .fallback(handler_404);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
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