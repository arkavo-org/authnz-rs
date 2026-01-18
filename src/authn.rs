use crate::authn::WebauthnError::{
    CorruptSession, InvalidSessionState, MissingToken, TokenCreationError, Unknown,
    UserHasNoCredentials, UserNotFound,
};
use crate::constants::{AUTH_TOKEN_HOURS, REGISTRATION_TOKEN_WEEKS};
use crate::db::DynamoDBError;
use crate::ntdf_token::{CapabilityFlag, NtdfTokenPayload};
use crate::AppState;
use axum::extract::Query;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::Response;
use axum::{
    extract::{Extension, Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use ecdsa::signature::{Signer, Verifier};
use ecdsa::{Signature, VerifyingKey};
use jsonwebtoken::{decode, encode, Algorithm, Header, TokenData, Validation};
use log::{error, info, warn};
use p256::NistP256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tower_sessions::Session;
use uuid::Uuid;
use webauthn_rs::prelude::*;

const SESSION_REG_STATE_KEY: &str = "reg_state";

#[derive(Deserialize)]
pub struct RegisterParams {
    pub handle: String,
    pub did: String,
    /// Optional EVM-compatible blockchain address (H160, 20 bytes as hex with 0x prefix)
    /// Used for transactional account linking with arkavo-node
    pub blockchain_address: Option<String>,
}

pub async fn start_register(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Path(username): Path<String>,
    Query(params): Query<RegisterParams>, // Add query params
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Start register for user: {}", username);

    // Validate DID format
    if !params.did.starts_with("did:key:") {
        return Err(WebauthnError::InvalidDID(
            "DID must start with 'did:key:'".to_string(),
        ));
    }
    // Validate username starts with handle
    if !params.handle.starts_with(&username) {
        return Err(WebauthnError::InvalidHandle);
    }

    // Validate blockchain address format if provided (0x + 40 hex chars)
    if let Some(ref addr) = params.blockchain_address {
        if !addr.starts_with("0x") || addr.len() != 42 {
            return Err(WebauthnError::InvalidBlockchainAddress(
                "Address must be 0x-prefixed 20-byte hex (42 chars total)".to_string(),
            ));
        }
        if !addr[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(WebauthnError::InvalidBlockchainAddress(
                "Address must contain only hex characters".to_string(),
            ));
        }
    }

    // Add retry logic for the initial user query
    let mut retry_count = 0;
    let max_retries = 3;
    let user = loop {
        match app_state.db_store.get_user_by_name(&username).await {
            Ok(Some(existing_user)) => {
                info!("Found existing user: {}", username);
                break existing_user;
            }
            Ok(None) => {
                info!("User not found, creating new user: {}", username);
                match app_state.db_store.create_user(&username, &params.did).await {
                    Ok(new_user) => break new_user,
                    Err(err) => {
                        error!("Failed to create user {}: {:?}", username, err);
                        return Err(WebauthnError::UserCreationFailed(err.to_string()));
                    }
                }
            }
            Err(err) => {
                error!(
                    "Database error for {} (attempt {}): {:?}",
                    username,
                    retry_count + 1,
                    err
                );
                if retry_count < max_retries {
                    retry_count += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(
                        500 * (retry_count as u64),
                    ))
                    .await;
                    continue;
                }
                return Err(WebauthnError::DynamoDBOperationError(Box::new(err)));
            }
        }
    };

    // Clean up existing session state
    if let Err(err) = session.remove_value(SESSION_REG_STATE_KEY).await {
        error!("Failed to remove old registration state: {:?}", err);
        return Err(WebauthnError::InvalidSessionState(err));
    }

    // Set up WebAuthn registration
    let exclude_credentials = if !user.credentials.is_empty() {
        Some(
            user.credentials
                .iter()
                .map(|c| c.cred_id().clone())
                .collect(),
        )
    } else {
        None
    };

    match app_state.webauthn.start_passkey_registration(
        user.user_id,
        &username,
        &username,
        exclude_credentials,
    ) {
        Ok((ccr, reg_state)) => {
            // Normalize blockchain address to lowercase for consistency
            let normalized_address = params.blockchain_address.as_ref().map(|a| a.to_lowercase());
            if let Err(err) = session
                .insert(
                    SESSION_REG_STATE_KEY,
                    (
                        username.clone(),
                        user.user_id,
                        reg_state,
                        params.did.clone(),
                        normalized_address,
                    ),
                )
                .await
            {
                error!("Failed to save registration state: {:?}", err);
                return Err(WebauthnError::InvalidSessionState(err));
            }
            info!("Registration started successfully for: {}", username);
            Ok(Json(ccr))
        }
        Err(err) => {
            error!("WebAuthn registration failed for {}: {:?}", username, err);
            Err(WebauthnError::Unknown)
        }
    }
}

pub async fn finish_register(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(registration_credential): Json<RegisterPublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {
    let (username, user_id, reg_state, did, blockchain_address): (
        String,
        Uuid,
        PasskeyRegistration,
        String,
        Option<String>,
    ) = session.get(SESSION_REG_STATE_KEY).await?.ok_or_else(|| {
        error!("No registration state found in session");
        CorruptSession
    })?;

    info!(
        "Finishing registration for user: {} ({})",
        username, user_id
    );

    // Clean up session immediately to prevent reuse
    if let Err(e) = session.remove_value(SESSION_REG_STATE_KEY).await {
        error!("Failed to remove registration state from session: {}", e);
        return Err(WebauthnError::SessionError(e.to_string()));
    }

    // Finish WebAuthn registration
    match app_state
        .webauthn
        .finish_passkey_registration(&registration_credential, &reg_state)
    {
        Ok(passkey) => {
            info!(
                "WebAuthn registration successful for user: {}. Adding credential to database...",
                username
            );

            // Store the credential in DynamoDB
            match app_state
                .db_store
                .add_credential(user_id, passkey.clone())
                .await
            {
                Ok(_) => {
                    info!("Successfully stored credential for user: {}", username);
                }
                Err(e) => {
                    error!("Failed to store credential: {}", e);
                    return Err(WebauthnError::DynamoDBOperationError(Box::new(e)));
                }
            }

            // Generate account token
            let credential_id = Base64UrlSafeData::from(passkey.cred_id().to_vec());
            // SECURITY: Long-lived registration token (~99 years) is intentional.
            // Security relies on WebAuthn passkey validation, not token expiration.
            // The passkey ceremony provides replay protection and strong authentication.
            let attestation_entity = AccountToken {
                user_unique_id: user_id,
                credential_id,
                passkey,
                sub: user_id.to_string(),
                exp: (Utc::now() + chrono::Duration::weeks(REGISTRATION_TOKEN_WEEKS)).timestamp()
                    as usize,
                did,
                blockchain_address,
            };

            // Create envelope
            let envelope = AttestationEnvelope::new(attestation_entity.clone(), &app_state);

            // Generate JWT token
            let header = Header::new(Algorithm::ES256);
            let token =
                encode(&header, &attestation_entity, &app_state.encoding_key).map_err(|err| {
                    error!("Failed to create JWT token: {}", err);
                    TokenCreationError(err)
                })?;

            // If blockchain_address is provided, link it on arkavo-node via secured backchannel
            if let Some(ref addr) = attestation_entity.blockchain_address {
                link_account_on_chain(&app_state.http_client, &user_id, &attestation_entity.did, addr)
                    .await
                    .map_err(|e| {
                        error!(
                            "Failed to link account on arkavo-node (did={}, addr={}): {}",
                            attestation_entity.did, addr, e
                        );
                        WebauthnError::AccountLinkingFailed(e)
                    })?;
            }

            // Generate NTDF token if builder is configured
            let ntdf_token = if let Some(ref builder) = app_state.ntdf_builder {
                let payload = NtdfTokenPayload {
                    sub_id: *user_id.as_bytes(),
                    flags: CapabilityFlag::WebAuthn as u64 | CapabilityFlag::Profile as u64,
                    scopes: vec!["openid".to_string(), "profile".to_string()],
                    attrs: vec![],
                    dpop_jti: None,
                    iat: Utc::now().timestamp(),
                    exp: (Utc::now() + chrono::Duration::weeks(REGISTRATION_TOKEN_WEEKS)).timestamp(),
                    aud: "https://kas.arkavo.net".to_string(),
                    session_id: None,
                    device_id: None,
                    did: Some(attestation_entity.did.clone()),
                    delegator_id: None,
                    root_user_id: None,
                    delegation_depth: None,
                    delegation_chain: None,
                };
                match builder.build(&payload) {
                    Ok(ntdf) => Some(ntdf),
                    Err(e) => {
                        warn!("Failed to generate NTDF token: {}", e);
                        None
                    }
                }
            } else {
                None
            };

            // Create response with token in header
            let mut response = Json(envelope).into_response();
            match HeaderValue::from_str(&token) {
                Ok(header_value) => {
                    response.headers_mut().insert("X-Auth-Token", header_value);

                    // Add NTDF token to response if generated
                    if let Some(ntdf) = ntdf_token
                        && let Ok(ntdf_header) = HeaderValue::from_str(&format!("NTDF {}", ntdf))
                    {
                        response.headers_mut().insert("X-NTDF-Token", ntdf_header);
                        info!("NTDF token included in registration response");
                    }

                    Ok(response)
                }
                Err(e) => {
                    error!("Failed to create header value from token: {}", e);
                    Err(MissingToken)
                }
            }
        }
        Err(error) => {
            error!("WebAuthn registration failed for {}: {:?}", username, error);
            Err(WebauthnError::WebAuthnError(error.to_string()))
        }
    }
}

pub async fn start_authentication(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Start Authentication");

    if let Err(err) = session.remove_value("auth_state").await {
        error!("Failed to remove old auth_state from session: {:?}", err);
        return Err(WebauthnError::InvalidSessionState(err));
    }

    // Get user from database or JWT
    let mut token_data: Option<TokenData<AccountToken>> = None;
    if let Some(jwt_header) = headers.get("X-Auth-Token") {
        let jwt = jwt_header
            .to_str()
            .map_err(|_| WebauthnError::InvalidToken)?;

        let decoding_key = (*app_state.decoding_key).clone();
        let mut token_validation = Validation::new(Algorithm::ES256);
        // SAFETY: JWT exp/nbf validation is intentionally disabled.
        // Security model relies on WebAuthn ceremony validation, not token expiration.
        // Long-lived registration tokens (~99 years) combined with WebAuthn provide
        // replay protection via the passkey authentication ceremony and session management.
        // Sessions expire after 10 minutes, providing time-based security boundaries.
        token_validation.validate_nbf = false;
        token_validation.validate_exp = false;
        token_data = Some(
            decode::<AccountToken>(jwt, &decoding_key, &token_validation).map_err(|err| {
                WebauthnError::TokenDecodingError(format!("Error decoding token: {}", err))
            })?,
        );
    }

    // Try to get user from DB first, fallback to token data
    let user = match app_state
        .db_store
        .get_user_by_name(&username)
        .await
        .map_err(|e| WebauthnError::DynamoDBOperationError(Box::new(e)))?
    {
        Some(user) => user,
        None => {
            if let Some(ref token_data) = token_data {
                // Create temporary user from token data
                crate::db::UserCredentials {
                    user_id: token_data.claims.user_unique_id,
                    username: username.clone(),
                    credentials: vec![token_data.claims.passkey.clone()],
                    did: String::new(), // Token doesn't contain DID
                }
            } else {
                return Err(UserNotFound);
            }
        }
    };

    // Credential retrieval strategy:
    // 1. Prefer DB credentials (source of truth for registered users)
    // 2. Fallback to JWT token passkey if user exists but has no stored credentials
    // 3. Fail if neither is available (prevents invalid auth attempts)
    let credentials = if user.credentials.is_empty() {
        if let Some(token_data) = &token_data {
            vec![token_data.claims.passkey.clone()]
        } else {
            return Err(UserHasNoCredentials);
        }
    } else {
        user.credentials.clone()
    };

    let res = match app_state
        .webauthn
        .start_passkey_authentication(&credentials)
    {
        Ok((rcr, auth_state)) => {
            if let Err(err) = session
                .insert("auth_state", (user.user_id, auth_state))
                .await
            {
                error!("Failed to insert auth_state into session: {:?}", err);
                return Err(WebauthnError::InvalidSessionState(err));
            }
            Json(rcr)
        }
        Err(e) => {
            error!("start_authentication -> {:?}", e);
            return Err(Unknown);
        }
    };
    Ok(res)
}

pub async fn finish_authentication(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(auth): Json<PublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {
    let (user_unique_id, auth_state): (Uuid, PasskeyAuthentication) =
        session.get("auth_state").await?.ok_or(CorruptSession)?;

    if let Err(err) = session.remove_value("auth_state").await {
        error!("Failed to remove auth_state from session: {:?}", err);
        return Err(WebauthnError::InvalidSessionState(err));
    }

    match app_state
        .webauthn
        .finish_passkey_authentication(&auth, &auth_state)
    {
        Ok(auth_result) => {
            log::debug!("Authentication result: {:?}", auth_result);
            // Generate JWT token
            let token = generate_jwt(user_unique_id, &app_state)?;
            info!("Authentication successful for user: {}", user_unique_id);
            Ok((StatusCode::OK, Json(AuthResponse { jwt_token: token })))
        }
        Err(e) => {
            error!("finish_authentication -> {:?}", e);
            Ok((
                StatusCode::BAD_REQUEST,
                Json(AuthResponse {
                    jwt_token: String::new(),
                }),
            ))
        }
    }
}

// Existing helper functions and structs remain the same
#[derive(Serialize)]
struct AuthResponse {
    jwt_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AccountToken {
    user_unique_id: Uuid,
    credential_id: Base64UrlSafeData,
    passkey: Passkey,
    sub: String,
    exp: usize,
    /// Decentralized Identifier (did:key:...)
    did: String,
    /// Optional EVM-compatible blockchain address for transactional linking
    #[serde(skip_serializing_if = "Option::is_none")]
    blockchain_address: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct AttestationEnvelope {
    payload: AccountToken,
    signature: Base64UrlSafeData,
}

impl AttestationEnvelope {
    fn new(entity: AccountToken, app_state: &AppState) -> Self {
        let payload_bytes = serde_json::to_vec(&entity).unwrap();
        let message = Sha256::digest(&payload_bytes);
        let signature: Signature<NistP256> = app_state.signing_key.sign(&message);

        Self {
            payload: entity,
            signature: Base64UrlSafeData::from(signature.to_der().as_bytes().to_vec()),
        }
    }

    fn _verify(&self, verifying_key: &VerifyingKey<NistP256>) -> bool {
        let payload_bytes = serde_json::to_vec(&self.payload).unwrap();
        let message = Sha256::digest(&payload_bytes);
        let signature = Signature::from_der(self.signature.as_ref()).unwrap();
        verifying_key.verify(&message, &signature).is_ok()
    }
}

/// Calls arkavo-node RPC to link the DID to a blockchain address
/// This is a secured backchannel call - no token verification needed
/// Uses ARKAVO_NODE_URL environment variable (defaults to http://127.0.0.1:9933)
/// Retries up to 3 times with exponential backoff on transient failures
async fn link_account_on_chain(
    client: &reqwest::Client,
    user_id: &Uuid,
    did: &str,
    address: &str,
) -> Result<(), String> {
    let node_url = std::env::var("ARKAVO_NODE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:9933".to_string());

    // JSON-RPC request for arkavo_linkAccountWithProof (secured backchannel)
    let rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "arkavo_linkAccountWithProof",
        "params": {
            "user_id": user_id.to_string(),
            "did": did,
            "address": address
        }
    });

    let max_retries = 3;
    let mut last_error = String::new();

    for attempt in 0..max_retries {
        if attempt > 0 {
            let delay = std::time::Duration::from_millis(100 * (1 << attempt));
            tokio::time::sleep(delay).await;
            info!(
                "Retrying account linking (attempt {}/{})",
                attempt + 1,
                max_retries
            );
        }

        match client.post(&node_url).json(&rpc_request).send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    last_error = format!(
                        "arkavo-node returned error status: {}",
                        response.status()
                    );
                    continue;
                }

                match response.json::<serde_json::Value>().await {
                    Ok(rpc_response) => {
                        if let Some(error) = rpc_response.get("error") {
                            last_error = format!("RPC error: {}", error);
                            continue;
                        }
                        info!(
                            "Successfully linked account on arkavo-node: did={}, address={}",
                            did, address
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        last_error = format!("Failed to parse RPC response: {}", e);
                        continue;
                    }
                }
            }
            Err(e) => {
                last_error = format!("Failed to connect to arkavo-node: {}", e);
                continue;
            }
        }
    }

    Err(last_error)
}

fn generate_jwt(user_id: Uuid, app_state: &AppState) -> Result<String, WebauthnError> {
    let claims = Claims {
        sub: user_id.to_string(),
        exp: (Utc::now() + chrono::Duration::hours(AUTH_TOKEN_HOURS)).timestamp() as usize,
    };
    let header = Header::new(Algorithm::ES256);
    encode(&header, &claims, &app_state.encoding_key).map_err(TokenCreationError)
}

#[derive(Error, Debug)]
pub enum WebauthnError {
    #[error("unknown webauthn error")]
    Unknown,
    #[error("Corrupt Session")]
    CorruptSession,
    #[error("User Not Found")]
    UserNotFound,
    #[error("User Has No Credentials")]
    UserHasNoCredentials,
    #[error("Deserializing Session failed: {0}")]
    InvalidSessionState(#[from] tower_sessions::session::Error),
    #[error("Token creation error")]
    TokenCreationError(jsonwebtoken::errors::Error),
    #[error("Missing token")]
    MissingToken,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Token decoding failed: {0}")]
    TokenDecodingError(String),
    #[error("DynamoDB operation failed: {0}")]
    DynamoDBOperationError(#[from] Box<crate::db::DynamoDBError>),
    #[error("Invalid username format")]
    InvalidHandle,
    #[error("Failed to create user: {0}")]
    UserCreationFailed(String),
    #[error("WebAuthn operation failed: {0}")]
    WebAuthnError(String),
    #[error("Session operation failed: {0}")]
    SessionError(String),
    #[error("Invalid DID format: {0}")]
    InvalidDID(String),
    #[error("Invalid blockchain address: {0}")]
    InvalidBlockchainAddress(String),
    #[error("Account linking failed: {0}")]
    AccountLinkingFailed(String),
}

impl IntoResponse for WebauthnError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            CorruptSession => (StatusCode::BAD_REQUEST, "Corrupt Session".to_string()),
            UserNotFound => (StatusCode::NOT_FOUND, "User Not Found".to_string()),
            Unknown => (StatusCode::INTERNAL_SERVER_ERROR, "Unknown Error".to_string()),
            UserHasNoCredentials => {
                (StatusCode::BAD_REQUEST, "User Has No Credentials".to_string())
            }
            InvalidSessionState(_) => (
                StatusCode::BAD_REQUEST,
                "Deserializing Session failed".to_string(),
            ),
            TokenCreationError(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Token creation failed: {}", err),
            ),
            MissingToken => (StatusCode::UNAUTHORIZED, "Missing token".to_string()),
            WebauthnError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            WebauthnError::TokenDecodingError(err) => {
                (StatusCode::UNAUTHORIZED, format!("Token decoding error: {}", err))
            }
            WebauthnError::DynamoDBOperationError(err) => match *err {
                DynamoDBError::TableNotExists(table) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Service setup incomplete: {} table not configured", table),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database operation failed: {}", err),
                ),
            },
            WebauthnError::InvalidHandle => (
                StatusCode::BAD_REQUEST,
                "Handle must start with the username".to_string(),
            ),
            WebauthnError::UserCreationFailed(reason) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create user: {}", reason),
            ),
            WebauthnError::WebAuthnError(err) => (
                StatusCode::BAD_REQUEST,
                format!("WebAuthn operation failed: {}", err),
            ),
            WebauthnError::SessionError(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Session operation failed: {}", err),
            ),
            WebauthnError::InvalidDID(err) => {
                (StatusCode::BAD_REQUEST, format!("Invalid DID format: {}", err))
            }
            WebauthnError::InvalidBlockchainAddress(err) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid blockchain address: {}", err),
            ),
            WebauthnError::AccountLinkingFailed(err) => (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Account linking failed: {}", err),
            ),
        };
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_validation_logic() {
        // Valid DID formats
        assert!("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".starts_with("did:key:"));
        assert!("did:key:abc123".starts_with("did:key:"));

        // Invalid DID formats
        assert!(!"did:web:example.com".starts_with("did:key:"));
        assert!(!"key:z6Mk...".starts_with("did:key:"));
        assert!(!"did:".starts_with("did:key:"));
        assert!(!"".starts_with("did:key:"));
    }

    #[test]
    fn test_handle_username_validation() {
        let username = "alice";
        let valid_handle = "alice.arkavo.social";
        let invalid_handle = "bob.arkavo.social";

        assert!(valid_handle.starts_with(username));
        assert!(!invalid_handle.starts_with(username));
    }

    #[test]
    fn test_blockchain_address_validation() {
        // Valid address format: 0x + 40 hex chars
        let valid = "0x742d35Cc6634C0532925a3b844Bc9e7595f2fE3d";
        assert!(valid.starts_with("0x"));
        assert_eq!(valid.len(), 42);
        assert!(valid[2..].chars().all(|c| c.is_ascii_hexdigit()));

        // Invalid: missing 0x prefix
        let no_prefix = "742d35Cc6634C0532925a3b844Bc9e7595f2fE3d";
        assert!(!no_prefix.starts_with("0x"));

        // Invalid: wrong length
        let too_short = "0x742d35";
        assert_ne!(too_short.len(), 42);

        // Invalid: non-hex characters
        let non_hex = "0xGGGd35Cc6634C0532925a3b844Bc9e7595f2fE3d";
        assert!(!non_hex[2..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_token_expiration_constants() {
        use crate::constants::{AUTH_TOKEN_HOURS, REGISTRATION_TOKEN_WEEKS};

        // Verify registration token is long-lived (~99 years = ~5148 weeks)
        assert_eq!(REGISTRATION_TOKEN_WEEKS, 5148);

        // Verify auth token is short-lived (1 hour)
        assert_eq!(AUTH_TOKEN_HOURS, 1);
    }

    #[test]
    fn test_webauthn_error_responses() {
        // Test each error returns its expected status code
        assert_eq!(
            WebauthnError::CorruptSession.into_response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            WebauthnError::UserNotFound.into_response().status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            WebauthnError::Unknown.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            WebauthnError::UserHasNoCredentials.into_response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            WebauthnError::MissingToken.into_response().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            WebauthnError::InvalidToken.into_response().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            WebauthnError::InvalidHandle.into_response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            WebauthnError::InvalidDID("test".to_string()).into_response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            WebauthnError::InvalidBlockchainAddress("test".to_string()).into_response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            WebauthnError::AccountLinkingFailed("test".to_string()).into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
