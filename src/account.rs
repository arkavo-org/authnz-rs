//! Account Management Module
//!
//! Implements account deletion endpoint that permanently removes all user data.
//!
//! # DELETE /account
//!
//! Deletes all data associated with the authenticated user:
//! - Agent delegations (agent_delegations table)
//! - Device bindings (device_bindings table)
//! - Handle (handles table)
//! - User credentials (credentials table)
//!
//! # Security
//!
//! - Requires valid NTDF token in X-NTDF-Token header
//! - No WebAuthn ceremony required (matches DELETE /agents/delegations/:did pattern)
//! - Hard delete - data is permanently removed

use crate::db::DynamoDBError;
use crate::AppState;
use axum::http::HeaderMap;
use axum::{extract::Extension, http::StatusCode, response::IntoResponse, Json};
use log::{error, info, warn};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

/// Error types for account operations
#[derive(Error, Debug)]
pub enum AccountError {
    #[error("Missing token")]
    MissingToken,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token decoding error: {0}")]
    TokenDecodingError(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] Box<DynamoDBError>),

    #[error("NTDF token system not configured")]
    NtdfNotConfigured,
}

impl IntoResponse for AccountError {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = match &self {
            AccountError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing token".to_string()),
            AccountError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            AccountError::TokenDecodingError(msg) => {
                (StatusCode::UNAUTHORIZED, format!("Token error: {}", msg))
            }
            AccountError::UserNotFound(msg) => {
                (StatusCode::NOT_FOUND, format!("User not found: {}", msg))
            }
            AccountError::DatabaseError(e) => match e.as_ref() {
                DynamoDBError::TableNotExists(table) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Service setup incomplete: {} table not configured", table),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database error: {}", e),
                ),
            },
            AccountError::NtdfNotConfigured => (
                StatusCode::SERVICE_UNAVAILABLE,
                "NTDF token system not configured".to_string(),
            ),
        };

        (status, body).into_response()
    }
}

/// Record of a deletion error for a specific resource
#[derive(Debug, Serialize)]
pub struct DeletionError {
    pub resource: String,
    pub error: String,
}

/// Summary of which resources were successfully deleted
#[derive(Debug, Serialize)]
pub struct DeletedResources {
    pub credentials: bool,
    pub handle: bool,
    pub device_bindings_count: u32,
    pub agent_delegations_count: u32,
}

/// Response from account deletion operation
#[derive(Debug, Serialize)]
pub struct AccountDeletionResponse {
    pub success: bool,
    pub deleted: DeletedResources,
    pub errors: Vec<DeletionError>,
}

/// DELETE /account
///
/// Permanently delete all data associated with the authenticated user.
/// Requires valid NTDF token in X-NTDF-Token header.
///
/// Deletion order (designed for safe retry on partial failure):
/// 1. Agent delegations - ancillary data, can be orphaned safely
/// 2. Device bindings - ancillary data, can be orphaned safely
/// 3. Handle - identity mapping, deletion doesn't affect auth
/// 4. Credentials - primary record, deleted last so user can retry
pub async fn delete_account(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AccountError> {
    info!("Processing account deletion request");

    // Extract and validate NTDF token
    let header_value = headers
        .get("X-NTDF-Token")
        .ok_or(AccountError::MissingToken)?
        .to_str()
        .map_err(|_| AccountError::InvalidToken)?;

    let ntdf_decoder = app_state.ntdf_decoder
        .as_ref()
        .ok_or(AccountError::NtdfNotConfigured)?;

    // NTDF exp/nbf validation is intentionally disabled in the decoder - security relies on WebAuthn
    let payload = ntdf_decoder.decode_header(header_value)
        .map_err(|e| AccountError::TokenDecodingError(format!("Error decoding token: {}", e)))?;

    let user_id = Uuid::from_bytes(payload.sub_id);

    info!("Deleting account for user_id: {}", user_id);

    // Get user to retrieve username (needed for handle deletion)
    let user = app_state
        .db_store
        .get_user_by_id(user_id)
        .await
        .map_err(|e| AccountError::DatabaseError(Box::new(e)))?
        .ok_or_else(|| AccountError::UserNotFound(user_id.to_string()))?;

    let username = user.username.clone();
    info!("Found user: {} ({})", username, user_id);

    let mut errors: Vec<DeletionError> = Vec::new();
    let mut deleted = DeletedResources {
        credentials: false,
        handle: false,
        device_bindings_count: 0,
        agent_delegations_count: 0,
    };

    // 1. Delete agent delegations (query by root_user_id-index, delete each)
    match app_state
        .db_store
        .delete_delegations_by_root_user(user_id)
        .await
    {
        Ok(count) => {
            deleted.agent_delegations_count = count;
            info!("Deleted {} agent delegations", count);
        }
        Err(e) => {
            warn!("Failed to delete agent delegations: {:?}", e);
            errors.push(DeletionError {
                resource: "agent_delegations".to_string(),
                error: e.to_string(),
            });
        }
    }

    // 2. Delete device bindings (scan by user_id, delete each)
    match app_state
        .db_store
        .delete_device_bindings_by_user(user_id)
        .await
    {
        Ok(count) => {
            deleted.device_bindings_count = count;
            info!("Deleted {} device bindings", count);
        }
        Err(e) => {
            warn!("Failed to delete device bindings: {:?}", e);
            errors.push(DeletionError {
                resource: "device_bindings".to_string(),
                error: e.to_string(),
            });
        }
    }

    // 3. Delete handle ({username}.arkavo.social)
    match app_state.db_store.delete_handle(&username).await {
        Ok(()) => {
            deleted.handle = true;
            info!("Deleted handle: {}.arkavo.social", username);
        }
        Err(e) => {
            warn!("Failed to delete handle: {:?}", e);
            errors.push(DeletionError {
                resource: "handle".to_string(),
                error: e.to_string(),
            });
        }
    }

    // 4. Delete credentials (primary record - last so user can retry on failure)
    match app_state.db_store.delete_user_credentials(user_id).await {
        Ok(()) => {
            deleted.credentials = true;
            info!("Deleted credentials for user: {}", user_id);
        }
        Err(e) => {
            error!("Failed to delete credentials: {:?}", e);
            errors.push(DeletionError {
                resource: "credentials".to_string(),
                error: e.to_string(),
            });
        }
    }

    // Determine overall success
    // Success requires at minimum credentials deletion (the primary record)
    let success = deleted.credentials;

    if success {
        info!(
            "Account deletion completed for user: {} ({}). Deleted: credentials={}, handle={}, device_bindings={}, agent_delegations={}",
            username, user_id, deleted.credentials, deleted.handle,
            deleted.device_bindings_count, deleted.agent_delegations_count
        );
    } else {
        error!(
            "Account deletion failed for user: {} ({}). Errors: {:?}",
            username, user_id, errors
        );
    }

    let response = AccountDeletionResponse {
        success,
        deleted,
        errors,
    };

    if success {
        Ok((StatusCode::OK, Json(response)))
    } else {
        Ok((StatusCode::INTERNAL_SERVER_ERROR, Json(response)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_error_response_codes() {
        let test_cases = vec![
            (AccountError::MissingToken, StatusCode::UNAUTHORIZED),
            (AccountError::InvalidToken, StatusCode::UNAUTHORIZED),
            (
                AccountError::TokenDecodingError("test".into()),
                StatusCode::UNAUTHORIZED,
            ),
            (
                AccountError::UserNotFound("test".into()),
                StatusCode::NOT_FOUND,
            ),
        ];

        for (error, expected_status) in test_cases {
            let response = error.into_response();
            assert_eq!(response.status(), expected_status);
        }
    }

    #[test]
    fn test_account_error_database_table_not_exists() {
        let db_error = DynamoDBError::TableNotExists("credentials".to_string());
        let account_error = AccountError::DatabaseError(Box::new(db_error));
        let response = account_error.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_deleted_resources_default() {
        let deleted = DeletedResources {
            credentials: false,
            handle: false,
            device_bindings_count: 0,
            agent_delegations_count: 0,
        };

        assert!(!deleted.credentials);
        assert!(!deleted.handle);
        assert_eq!(deleted.device_bindings_count, 0);
        assert_eq!(deleted.agent_delegations_count, 0);
    }

    #[test]
    fn test_account_deletion_response_json_serialization() {
        let response = AccountDeletionResponse {
            success: true,
            deleted: DeletedResources {
                credentials: true,
                handle: true,
                device_bindings_count: 2,
                agent_delegations_count: 3,
            },
            errors: vec![],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"credentials\":true"));
        assert!(json.contains("\"device_bindings_count\":2"));
        assert!(json.contains("\"agent_delegations_count\":3"));
    }

    #[test]
    fn test_deletion_error_serialization() {
        let error = DeletionError {
            resource: "handle".to_string(),
            error: "Table not found".to_string(),
        };

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"resource\":\"handle\""));
        assert!(json.contains("\"error\":\"Table not found\""));
    }
}
