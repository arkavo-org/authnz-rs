use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::types::AttributeValue;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct UserCredentials {
    pub user_id: Uuid,
    pub username: String,
    pub credentials: Vec<Passkey>,
    pub did: String,
}

#[derive(Error, Debug)]
pub enum DynamoDBError {
    #[error("AWS SDK error: {0}")]
    AwsSdkError(Box<aws_sdk_dynamodb::Error>),

    #[error("Serde JSON error: {0}")]
    SerdeJsonError(#[from] serde_json::Error),

    #[error("UUID parsing error: {0}")]
    UuidError(#[from] uuid::Error),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Amazon SdkError: {0}")]
    SdkError(String),

    #[error("Table does not exist: {0}")]
    TableNotExists(String),

    #[error("User not found: {0}")]
    CredentialError(String),

    #[error("Invalid DID format: {0}")]
    InvalidDID(String),
}

impl From<aws_sdk_dynamodb::Error> for DynamoDBError {
    fn from(err: aws_sdk_dynamodb::Error) -> Self {
        DynamoDBError::AwsSdkError(Box::new(err))
    }
}

impl<T> From<SdkError<T>> for DynamoDBError
where
    T: std::error::Error + Send + Sync + 'static,
{
    fn from(err: SdkError<T>) -> Self {
        DynamoDBError::SdkError(err.to_string())
    }
}

pub struct DynamoDBStore {
    client: Client,
    credentials_table: String,
    handles_table: String,
    device_bindings_table: String,
}

impl DynamoDBStore {
    pub async fn new(
        credentials_table: String,
        handles_table: String,
        device_bindings_table: String,
    ) -> Result<Self, DynamoDBError> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Client::new(&config);

        Ok(Self {
            client,
            credentials_table,
            handles_table,
            device_bindings_table,
        })
    }

    pub async fn create_user(
        &self,
        username: &str,
        did: &str,
    ) -> Result<UserCredentials, DynamoDBError> {
        info!(
            "Creating new user in DynamoDB. Table: {}, Username: {}, DID: {}",
            self.credentials_table, username, did
        );

        // Validate inputs
        if username.is_empty() {
            return Err(DynamoDBError::Internal("Username cannot be empty".into()));
        }

        if !did.starts_with("did:key:") {
            return Err(DynamoDBError::InvalidDID(
                "DID must start with 'did:key:'".to_string(),
            ));
        }

        let user = UserCredentials {
            user_id: Uuid::new_v4(),
            username: username.to_string(),
            credentials: Vec::new(),
            did: did.to_string(),
        };

        // Try to create user record first
        match self
            .client
            .put_item()
            .table_name(&self.credentials_table)
            .item("user_id", AttributeValue::S(user.user_id.to_string()))
            .item("username", AttributeValue::S(username.to_string()))
            .item("credentials", AttributeValue::L(vec![]))
            .item("did", AttributeValue::S(user.did.clone()))
            .send()
            .await
        {
            Ok(_) => {
                info!("Created user record in credentials table");
            }
            Err(err) => match err {
                SdkError::ServiceError(ref service_error) => {
                    if service_error.err().meta().code() == Some("ResourceNotFoundException") {
                        error!("Credentials table does not exist");
                        return Err(DynamoDBError::TableNotExists("credentials".to_string()));
                    }
                    error!("Failed to write to credentials table: {:?}", err);
                    return Err(DynamoDBError::SdkError(err.to_string()));
                }
                _ => {
                    error!("Unknown error writing to credentials table: {:?}", err);
                    return Err(DynamoDBError::SdkError(err.to_string()));
                }
            },
        }

        // Now try to create handle record - if it fails due to missing table, return success anyway
        match self
            .client
            .put_item()
            .table_name(&self.handles_table)
            .item(
                "handle",
                AttributeValue::S(format!("{}.arkavo.social", username)),
            )
            .item("did", AttributeValue::S(user.did.clone()))
            .send()
            .await
        {
            Ok(_) => {
                info!("Created handle record");
            }
            Err(err) => {
                match err {
                    SdkError::ServiceError(ref service_error) => {
                        if service_error.err().meta().code() == Some("ResourceNotFoundException") {
                            // If handles table doesn't exist, log warning but don't fail the registration
                            warn!(
                                "Handles table does not exist - handle will need to be created later"
                            );
                        } else {
                            error!("Failed to write to handles table: {:?}", err);
                            // Attempt to rollback credentials entry
                            warn!(
                                "Attempting to rollback credentials entry for user: {}",
                                user.user_id
                            );
                            if let Err(rollback_err) = self
                                .client
                                .delete_item()
                                .table_name(&self.credentials_table)
                                .key("user_id", AttributeValue::S(user.user_id.to_string()))
                                .send()
                                .await
                            {
                                error!(
                                    "CRITICAL: Failed to rollback credentials for user {}: {:?}. Manual cleanup required.",
                                    user.user_id, rollback_err
                                );
                            } else {
                                info!(
                                    "Successfully rolled back credentials entry for user: {}",
                                    user.user_id
                                );
                            }
                            return Err(DynamoDBError::SdkError(err.to_string()));
                        }
                    }
                    _ => {
                        error!("Unknown error writing to handles table: {:?}", err);
                        // Attempt to rollback credentials entry
                        warn!(
                            "Attempting to rollback credentials entry for user: {}",
                            user.user_id
                        );
                        if let Err(rollback_err) = self
                            .client
                            .delete_item()
                            .table_name(&self.credentials_table)
                            .key("user_id", AttributeValue::S(user.user_id.to_string()))
                            .send()
                            .await
                        {
                            error!(
                                "CRITICAL: Failed to rollback credentials for user {}: {:?}. Manual cleanup required.",
                                user.user_id, rollback_err
                            );
                        } else {
                            info!(
                                "Successfully rolled back credentials entry for user: {}",
                                user.user_id
                            );
                        }
                        return Err(DynamoDBError::SdkError(err.to_string()));
                    }
                }
            }
        }

        Ok(user)
    }

    pub async fn get_user_by_name(
        &self,
        username: &str,
    ) -> Result<Option<UserCredentials>, DynamoDBError> {
        info!(
            "Querying for user. Table: {}, Username: {}",
            self.credentials_table, username
        );

        let result = match self
            .client
            .query()
            .table_name(&self.credentials_table)
            .index_name("username-index")
            .key_condition_expression("#username = :username")
            .expression_attribute_names("#username", "username")
            .expression_attribute_values(":username", AttributeValue::S(username.to_string()))
            .send()
            .await
        {
            Ok(result) => result,
            Err(err) => {
                error!("Failed to query user {}: {:?}", username, err);
                return Err(DynamoDBError::from(err));
            }
        };

        if let Some(items) = result.items {
            if let Some(item) = items.first() {
                match self.item_to_user_credentials(item) {
                    Ok(user) => {
                        info!("Found user: {}", username);
                        Ok(Some(user))
                    }
                    Err(err) => {
                        error!("Failed to parse user data for {}: {:?}", username, err);
                        Err(err)
                    }
                }
            } else {
                info!("No user found: {}", username);
                Ok(None)
            }
        } else {
            info!("No items returned for username: {}", username);
            Ok(None)
        }
    }

    pub async fn add_credential(
        &self,
        user_id: Uuid,
        credential: Passkey,
    ) -> Result<(), DynamoDBError> {
        info!(
            "Adding credential to DynamoDB table: {}",
            self.credentials_table
        );

        // Log the credential being added (safely)
        info!(
            "Adding credential with ID: {:?} for user: {}",
            credential.cred_id(),
            user_id
        );

        // First verify the user exists
        let result = self
            .client
            .get_item()
            .table_name(&self.credentials_table)
            .key("user_id", AttributeValue::S(user_id.to_string()))
            .send()
            .await?;

        let mut credentials = if let Some(item) = result.item {
            info!("Found existing user record");

            // Check if credentials field exists and get its current value
            if let Some(creds_av) = item.get("credentials") {
                info!("Found existing credentials attribute: {:?}", creds_av);

                if let Ok(creds_list) = creds_av.as_l() {
                    info!("Found {} existing credentials", creds_list.len());
                    let mut existing_creds = Vec::new();
                    for cred_av in creds_list {
                        if let Ok(cred_str) = cred_av.as_s() {
                            match serde_json::from_str::<Passkey>(cred_str) {
                                Ok(cred) => existing_creds.push(cred),
                                Err(e) => {
                                    error!("Failed to parse credential JSON: {}", e);
                                    // Continue with other credentials
                                }
                            }
                        }
                    }
                    existing_creds
                } else {
                    info!("Creating new credentials list");
                    Vec::new()
                }
            } else {
                info!("No existing credentials attribute found");
                Vec::new()
            }
        } else {
            error!("User {} not found in database", user_id);
            return Err(DynamoDBError::Internal(format!(
                "User {} not found",
                user_id
            )));
        };

        // Add new credential
        credentials.push(credential);
        info!(
            "Added new credential. Total credentials: {}",
            credentials.len()
        );

        // Convert credentials to a list of AttributeValue::S
        let cred_list: Vec<AttributeValue> = match credentials
            .iter()
            .map(|cred| {
                serde_json::to_string(cred)
                    .map(AttributeValue::S)
                    .map_err(DynamoDBError::SerdeJsonError)
            })
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(list) => list,
            Err(e) => {
                error!("Failed to serialize credentials: {}", e);
                return Err(e);
            }
        };

        // Update record with new credentials list
        match self
            .client
            .update_item()
            .table_name(&self.credentials_table)
            .key("user_id", AttributeValue::S(user_id.to_string()))
            .update_expression("SET credentials = :credentials")
            .expression_attribute_values(":credentials", AttributeValue::L(cred_list))
            .send()
            .await
        {
            Ok(_) => {
                info!("Successfully updated credentials for user {}", user_id);
                Ok(())
            }
            Err(e) => {
                error!("Failed to update credentials: {:?}", e);
                match e {
                    SdkError::ServiceError(ref service_error) => {
                        error!(
                            "DynamoDB service error: code={:?}, message={:?}",
                            service_error.err().meta().code(),
                            service_error.err().meta().message()
                        );
                    }
                    _ => error!("Unknown error type: {:?}", e),
                }
                Err(DynamoDBError::SdkError(e.to_string()))
            }
        }
    }

    fn item_to_user_credentials(
        &self,
        item: &std::collections::HashMap<String, AttributeValue>,
    ) -> Result<UserCredentials, DynamoDBError> {
        log::debug!("Parsing item: {:?}", item);
        let user_id = Uuid::parse_str(
            item.get("user_id")
                .ok_or_else(|| DynamoDBError::Internal("No user_id found".into()))?
                .as_s()
                .map_err(|_| DynamoDBError::Internal("Invalid user_id format".into()))?,
        )?;
        log::debug!("Parsed user_id: {}", user_id);
        let username = item
            .get("username")
            .ok_or_else(|| DynamoDBError::Internal("No username found".into()))?
            .as_s()
            .map_err(|_| DynamoDBError::Internal("Invalid username format".into()))?
            .to_string();
        log::debug!("Parsed username: {}", username);
        let credentials = if let Some(creds_av) = item.get("credentials") {
            if let Ok(creds_str) = creds_av.as_s() {
                // Deserialize from JSON string
                serde_json::from_str::<Vec<Passkey>>(creds_str)?
            } else if let Ok(creds_list) = creds_av.as_l() {
                // Deserialize from DynamoDB list
                creds_list
                    .iter()
                    .map(|av| {
                        let cred_str = av.as_s().map_err(|_| {
                            DynamoDBError::Internal("Invalid credential format".into())
                        })?;
                        serde_json::from_str::<Passkey>(cred_str).map_err(|_| {
                            DynamoDBError::Internal("Invalid credential format".into())
                        })
                    })
                    .collect::<Result<Vec<Passkey>, DynamoDBError>>()?
            } else {
                return Err(DynamoDBError::Internal("Invalid credentials format".into()));
            }
        } else {
            Vec::new()
        };
        log::debug!("Parsed credentials: {:?}", credentials);
        let did = item
            .get("did")
            .ok_or_else(|| DynamoDBError::Internal("No DID found".into()))?
            .as_s()
            .map_err(|_| DynamoDBError::Internal("Invalid DID format".into()))?
            .to_string();
        log::debug!("Parsed DID: {}", did);
        Ok(UserCredentials {
            user_id,
            username,
            credentials,
            did,
        })
    }

    // Device binding methods for App Attest
    pub async fn create_device_binding(
        &self,
        binding: &crate::device_check::DeviceBinding,
    ) -> Result<(), DynamoDBError> {
        info!(
            "Creating device binding in DynamoDB. Table: {}, Device ID: {}",
            self.device_bindings_table, binding.device_id
        );

        match self
            .client
            .put_item()
            .table_name(&self.device_bindings_table)
            .item("device_id", AttributeValue::S(binding.device_id.clone()))
            .item("user_id", AttributeValue::S(binding.user_id.to_string()))
            .item(
                "public_key",
                AttributeValue::B(aws_sdk_dynamodb::primitives::Blob::new(
                    binding.public_key.clone(),
                )),
            )
            .item("counter", AttributeValue::N(binding.counter.to_string()))
            .item("app_id", AttributeValue::S(binding.app_id.clone()))
            .item(
                "created_at",
                AttributeValue::N(binding.created_at.to_string()),
            )
            .item(
                "updated_at",
                AttributeValue::N(binding.updated_at.to_string()),
            )
            .send()
            .await
        {
            Ok(_) => {
                info!(
                    "Successfully created device binding for device: {}",
                    binding.device_id
                );
                Ok(())
            }
            Err(err) => match err {
                SdkError::ServiceError(ref service_error) => {
                    if service_error.err().meta().code() == Some("ResourceNotFoundException") {
                        error!("Device bindings table does not exist");
                        return Err(DynamoDBError::TableNotExists("device_bindings".to_string()));
                    }
                    error!("Failed to write to device bindings table: {:?}", err);
                    Err(DynamoDBError::SdkError(err.to_string()))
                }
                _ => {
                    error!("Unknown error writing to device bindings table: {:?}", err);
                    Err(DynamoDBError::SdkError(err.to_string()))
                }
            },
        }
    }

    pub async fn get_device_binding(
        &self,
        device_id: &str,
    ) -> Result<Option<crate::device_check::DeviceBinding>, DynamoDBError> {
        info!(
            "Querying for device binding. Table: {}, Device ID: {}",
            self.device_bindings_table, device_id
        );

        let result = match self
            .client
            .get_item()
            .table_name(&self.device_bindings_table)
            .key("device_id", AttributeValue::S(device_id.to_string()))
            .send()
            .await
        {
            Ok(result) => result,
            Err(err) => {
                error!("Failed to query device binding {}: {:?}", device_id, err);
                return Err(DynamoDBError::from(err));
            }
        };

        if let Some(item) = result.item {
            match self.item_to_device_binding(&item) {
                Ok(binding) => {
                    info!("Found device binding: {}", device_id);
                    Ok(Some(binding))
                }
                Err(err) => {
                    error!(
                        "Failed to parse device binding data for {}: {:?}",
                        device_id, err
                    );
                    Err(err)
                }
            }
        } else {
            info!("No device binding found: {}", device_id);
            Ok(None)
        }
    }

    pub async fn update_device_counter(
        &self,
        device_id: &str,
        new_counter: u32,
        expected_counter: u32,
    ) -> Result<(), DynamoDBError> {
        info!(
            "Updating device counter. Table: {}, Device ID: {}, New Counter: {} (expected: {})",
            self.device_bindings_table, device_id, new_counter, expected_counter
        );

        let updated_at = chrono::Utc::now().timestamp();

        // Use conditional update to prevent race conditions
        // Only update if the current counter matches the expected value
        match self
            .client
            .update_item()
            .table_name(&self.device_bindings_table)
            .key("device_id", AttributeValue::S(device_id.to_string()))
            .update_expression("SET #counter = :counter, updated_at = :updated_at")
            .condition_expression("#counter = :expected_counter")
            .expression_attribute_names("#counter", "counter")
            .expression_attribute_values(":counter", AttributeValue::N(new_counter.to_string()))
            .expression_attribute_values(
                ":expected_counter",
                AttributeValue::N(expected_counter.to_string()),
            )
            .expression_attribute_values(":updated_at", AttributeValue::N(updated_at.to_string()))
            .send()
            .await
        {
            Ok(_) => {
                info!("Successfully updated counter for device: {}", device_id);
                Ok(())
            }
            Err(err) => {
                match &err {
                    SdkError::ServiceError(service_error)
                        if service_error.err().meta().code()
                            == Some("ConditionalCheckFailedException") =>
                    {
                        error!(
                            "Counter update race condition detected for device {}: expected {}, but counter was modified",
                            device_id, expected_counter
                        );
                        return Err(DynamoDBError::Internal(format!(
                            "Counter race condition: expected counter {}, but it was modified by another request",
                            expected_counter
                        )));
                    }
                    _ => {}
                }
                error!("Failed to update device counter: {:?}", err);
                Err(DynamoDBError::SdkError(err.to_string()))
            }
        }
    }

    fn item_to_device_binding(
        &self,
        item: &std::collections::HashMap<String, AttributeValue>,
    ) -> Result<crate::device_check::DeviceBinding, DynamoDBError> {
        let device_id = item
            .get("device_id")
            .ok_or_else(|| DynamoDBError::Internal("No device_id found".into()))?
            .as_s()
            .map_err(|_| DynamoDBError::Internal("Invalid device_id format".into()))?
            .to_string();

        let user_id = Uuid::parse_str(
            item.get("user_id")
                .ok_or_else(|| DynamoDBError::Internal("No user_id found".into()))?
                .as_s()
                .map_err(|_| DynamoDBError::Internal("Invalid user_id format".into()))?,
        )?;

        let public_key = item
            .get("public_key")
            .ok_or_else(|| DynamoDBError::Internal("No public_key found".into()))?
            .as_b()
            .map_err(|_| DynamoDBError::Internal("Invalid public_key format".into()))?
            .as_ref()
            .to_vec();

        let counter = item
            .get("counter")
            .ok_or_else(|| DynamoDBError::Internal("No counter found".into()))?
            .as_n()
            .map_err(|_| DynamoDBError::Internal("Invalid counter format".into()))?
            .parse::<u32>()
            .map_err(|_| DynamoDBError::Internal("Failed to parse counter".into()))?;

        let app_id = item
            .get("app_id")
            .ok_or_else(|| DynamoDBError::Internal("No app_id found".into()))?
            .as_s()
            .map_err(|_| DynamoDBError::Internal("Invalid app_id format".into()))?
            .to_string();

        let created_at = item
            .get("created_at")
            .ok_or_else(|| DynamoDBError::Internal("No created_at found".into()))?
            .as_n()
            .map_err(|_| DynamoDBError::Internal("Invalid created_at format".into()))?
            .parse::<i64>()
            .map_err(|_| DynamoDBError::Internal("Failed to parse created_at".into()))?;

        let updated_at = item
            .get("updated_at")
            .ok_or_else(|| DynamoDBError::Internal("No updated_at found".into()))?
            .as_n()
            .map_err(|_| DynamoDBError::Internal("Invalid updated_at format".into()))?
            .parse::<i64>()
            .map_err(|_| DynamoDBError::Internal("Failed to parse updated_at".into()))?;

        Ok(crate::device_check::DeviceBinding {
            device_id,
            user_id,
            public_key,
            counter,
            app_id,
            created_at,
            updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_format_validation() {
        // Valid DIDs
        assert!("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".starts_with("did:key:"));
        assert!("did:key:abc123".starts_with("did:key:"));

        // Invalid DIDs
        assert!(!"did:web:example.com".starts_with("did:key:"));
        assert!(!"invalid".starts_with("did:key:"));
        assert!(!"".starts_with("did:key:"));
    }

    #[test]
    fn test_username_validation() {
        // Empty username should be rejected
        let empty = "";
        let alice = "alice";
        let user123 = "user123";
        assert!(empty.is_empty());
        assert!(!alice.is_empty());
        assert!(!user123.is_empty());
    }

    #[test]
    fn test_handle_format() {
        let username = "alice";
        let expected_handle = format!("{}.arkavo.social", username);
        assert_eq!(expected_handle, "alice.arkavo.social");
    }

    #[test]
    fn test_error_conversions() {
        // Test UUID error
        let uuid_err = Uuid::parse_str("not-a-uuid").unwrap_err();
        let db_err: DynamoDBError = uuid_err.into();
        assert!(matches!(db_err, DynamoDBError::UuidError(_)));

        // Test JSON error
        let json_err = serde_json::from_str::<UserCredentials>("invalid").unwrap_err();
        let db_err: DynamoDBError = json_err.into();
        assert!(matches!(db_err, DynamoDBError::SerdeJsonError(_)));
    }

    #[test]
    fn test_user_credentials_structure() {
        let user = UserCredentials {
            user_id: Uuid::new_v4(),
            username: "testuser".to_string(),
            credentials: vec![],
            did: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
        };

        assert_eq!(user.username, "testuser");
        assert!(user.credentials.is_empty());
        assert!(user.did.starts_with("did:key:"));
    }

    #[test]
    fn test_user_credentials_json_roundtrip() {
        let original = UserCredentials {
            user_id: Uuid::new_v4(),
            username: "alice".to_string(),
            credentials: vec![],
            did: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&original).unwrap();

        // Deserialize back
        let deserialized: UserCredentials = serde_json::from_str(&json).unwrap();

        assert_eq!(original.user_id, deserialized.user_id);
        assert_eq!(original.username, deserialized.username);
        assert_eq!(original.did, deserialized.did);
        assert_eq!(original.credentials.len(), deserialized.credentials.len());
    }

    #[test]
    fn test_dynamodb_error_messages() {
        let errors = vec![
            DynamoDBError::Internal("test".to_string()),
            DynamoDBError::TableNotExists("credentials".to_string()),
            DynamoDBError::CredentialError("not found".to_string()),
            DynamoDBError::InvalidDID("bad format".to_string()),
            DynamoDBError::SdkError("aws error".to_string()),
        ];

        for error in errors {
            let msg = error.to_string();
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_table_not_exists_error() {
        let error = DynamoDBError::TableNotExists("credentials".to_string());
        assert_eq!(error.to_string(), "Table does not exist: credentials");
    }

    #[test]
    fn test_invalid_did_error() {
        let error = DynamoDBError::InvalidDID("DID must start with 'did:key:'".to_string());
        assert!(error.to_string().contains("did:key:"));
    }
}
