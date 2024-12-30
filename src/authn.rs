use crate::authn::WebauthnError::{
    CorruptSession, DynamoDBOperationError, InvalidSessionState, MissingToken, TokenCreationError,
    Unknown, UserHasNoCredentials, UserNotFound,
};
use crate::db::DynamoDBError;
use crate::AppState;
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
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, Header, TokenData, Validation};
use log::{error, info};
use p256::NistP256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tower_sessions::Session;
use uuid::Uuid;
use webauthn_rs::prelude::*;

const SESSION_REG_STATE_KEY: &str = "reg_state";

pub async fn start_register(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Start register for user: {}", username);

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
                match app_state.db_store.create_user(&username).await {
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
                return Err(WebauthnError::DynamoDBOperationError(err));
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
            if let Err(err) = session
                .insert(
                    SESSION_REG_STATE_KEY,
                    (username.clone(), user.user_id, reg_state),
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
    let (username, user_id, reg_state): (String, Uuid, PasskeyRegistration) = session
        .get(SESSION_REG_STATE_KEY)
        .await?
        .ok_or(CorruptSession)?;
    println!("{}", username);
    session
        .remove_value(SESSION_REG_STATE_KEY)
        .await
        .expect("auth_state removal failed");

    match app_state
        .webauthn
        .finish_passkey_registration(&registration_credential, &reg_state)
    {
        Ok(passkey) => {
            // Store the credential in DynamoDB
            app_state
                .db_store
                .add_credential(user_id, passkey.clone())
                .await
                .map_err(DynamoDBOperationError)?;

            let credential_id = Base64UrlSafeData::from(passkey.cred_id().to_vec());
            let attestation_entity = AccountToken {
                user_unique_id: user_id,
                credential_id,
                passkey,
                sub: user_id.to_string(),
                exp: (Utc::now() + chrono::Duration::weeks(5148)).timestamp() as usize,
            };

            let envelope = AttestationEnvelope::new(attestation_entity.clone(), &app_state);
            let header = Header::new(Algorithm::ES256);
            let token = encode(&header, &attestation_entity, &app_state.encoding_key)
                .map_err(|err| TokenCreationError(err))?;

            let mut response = Json(envelope).into_response();
            match HeaderValue::from_str(&token) {
                Ok(header_value) => {
                    response.headers_mut().insert("X-Auth-Token", header_value);
                    Ok(response)
                }
                Err(_) => Err(MissingToken),
            }
        }
        Err(error) => {
            error!("finish_register -> {:?}", error);
            Ok(StatusCode::BAD_REQUEST.into_response())
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

    session
        .remove_value("auth_state")
        .await
        .expect("auth_state removal failed");

    // Get user from database or JWT
    let mut token_data: Option<TokenData<AccountToken>> = None;
    if let Some(jwt_header) = headers.get("X-Auth-Token") {
        let jwt = jwt_header
            .to_str()
            .map_err(|_| WebauthnError::InvalidToken)?;

        let decoding_key = DecodingKey::from((*app_state.decoding_key).clone());
        let mut token_validation = Validation::new(Algorithm::ES256);
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
        .map_err(DynamoDBOperationError)?
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
            session
                .insert("auth_state", (user.user_id, auth_state))
                .await
                .expect("Failed to insert");
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

    session
        .remove_value("auth_state")
        .await
        .expect("auth_state removal failed");

    let res = match app_state
        .webauthn
        .finish_passkey_authentication(&auth, &auth_state)
    {
        Ok(auth_result) => {
            println!("{:?}", auth_result);
            // Generate JWT token
            let token = generate_jwt(user_unique_id, &app_state)?;
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
    };
    info!("Authentication Successful!");
    res
}

// Existing helper functions and structs remain the same
#[derive(Serialize)]
struct AuthResponse {
    jwt_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AccountToken {
    user_unique_id: Uuid,
    credential_id: Base64UrlSafeData,
    passkey: Passkey,
    sub: String,
    exp: usize,
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

fn generate_jwt(user_id: Uuid, app_state: &AppState) -> Result<String, WebauthnError> {
    let claims = Claims {
        sub: user_id.to_string(),
        exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
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
    DynamoDBOperationError(#[from] crate::db::DynamoDBError),
    #[error("Invalid username format")]
    InvalidUsername,
    #[error("Failed to create user: {0}")]
    UserCreationFailed(String),
    #[error("WebAuthn operation failed: {0}")]
    WebAuthnError(String),
    #[error("Session operation failed: {0}")]
    SessionError(String),
}

impl IntoResponse for WebauthnError {
    fn into_response(self) -> Response {
        let body = match self {
            CorruptSession => "Corrupt Session".to_string(),
            UserNotFound => "User Not Found".to_string(),
            Unknown => "Unknown Error".to_string(),
            UserHasNoCredentials => "User Has No Credentials".to_string(),
            InvalidSessionState(_) => "Deserializing Session failed".to_string(),
            TokenCreationError(err) => format!("Token creation failed: {}", err),
            MissingToken => "Missing token".to_string(),
            WebauthnError::InvalidToken => "Invalid token".to_string(),
            WebauthnError::TokenDecodingError(err) => format!("Token decoding error: {}", err),
            WebauthnError::DynamoDBOperationError(err) => match err {
                DynamoDBError::TableNotExists(table) => {
                    format!("Service setup incomplete: {} table not configured", table)
                }
                _ => format!("Database operation failed: {}", err),
            },
            WebauthnError::InvalidUsername => "Invalid username format".to_string(),
            WebauthnError::UserCreationFailed(reason) => {
                format!("Failed to create user: {}", reason)
            }
            WebauthnError::WebAuthnError(err) => format!("WebAuthn operation failed: {}", err),
            WebauthnError::SessionError(err) => format!("Session operation failed: {}", err),
        };
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
