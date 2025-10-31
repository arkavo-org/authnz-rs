use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client;
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
    attestations_table: String,
}

impl DynamoDBStore {
    pub async fn new(
        credentials_table: String,
        handles_table: String,
    ) -> Result<Self, DynamoDBError> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Client::new(&config);
        let attestations_table = std::env::var("DYNAMODB_ATTESTATIONS_TABLE")
            .unwrap_or_else(|_| "device_attestations".to_string());

        Ok(Self {
            client,
            credentials_table,
            handles_table,
            attestations_table,
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
                            warn!("Handles table does not exist - handle will need to be created later");
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

    pub async fn get_user_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<UserCredentials>, DynamoDBError> {
        info!(
            "Getting user by ID. Table: {}, UserID: {}",
            self.credentials_table, user_id
        );

        let result = match self
            .client
            .get_item()
            .table_name(&self.credentials_table)
            .key("user_id", AttributeValue::S(user_id.to_string()))
            .send()
            .await
        {
            Ok(result) => result,
            Err(err) => {
                error!("Failed to get user {}: {:?}", user_id, err);
                return Err(DynamoDBError::from(err));
            }
        };

        if let Some(item) = result.item {
            match self.item_to_user_credentials(&item) {
                Ok(user) => {
                    info!("Found user: {}", user_id);
                    Ok(Some(user))
                }
                Err(err) => {
                    error!("Failed to parse user data for {}: {:?}", user_id, err);
                    Err(err)
                }
            }
        } else {
            info!("No user found with ID: {}", user_id);
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

    // Device Attestation CRUD Operations

    pub async fn save_device_attestation(
        &self,
        attestation: &crate::app_attest::DeviceAttestation,
    ) -> Result<(), DynamoDBError> {
        info!(
            "Saving device attestation for device: {} (user: {})",
            attestation.device_id, attestation.user_id
        );

        let attestation_json = serde_json::to_string(attestation)?;

        self.client
            .put_item()
            .table_name(&self.attestations_table)
            .item("device_id", AttributeValue::S(attestation.device_id.clone()))
            .item("user_id", AttributeValue::S(attestation.user_id.to_string()))
            .item("attestation_data", AttributeValue::S(attestation_json))
            .item(
                "counter",
                AttributeValue::N(attestation.counter.to_string()),
            )
            .item(
                "security_state",
                AttributeValue::S(format!("{:?}", attestation.security_state)),
            )
            .item("platform", AttributeValue::S(attestation.platform.clone()))
            .item(
                "created_at",
                AttributeValue::S(attestation.created_at.to_rfc3339()),
            )
            .item(
                "last_used_at",
                AttributeValue::S(attestation.last_used_at.to_rfc3339()),
            )
            .send()
            .await?;

        info!(
            "Device attestation saved successfully for device: {}",
            attestation.device_id
        );
        Ok(())
    }

    pub async fn get_device_attestation(
        &self,
        device_id: &str,
    ) -> Result<Option<crate::app_attest::DeviceAttestation>, DynamoDBError> {
        info!(
            "Getting device attestation for device: {} from table: {}",
            device_id, self.attestations_table
        );

        let result = self
            .client
            .get_item()
            .table_name(&self.attestations_table)
            .key("device_id", AttributeValue::S(device_id.to_string()))
            .send()
            .await?;

        if let Some(item) = result.item {
            let attestation_json = item
                .get("attestation_data")
                .ok_or_else(|| DynamoDBError::Internal("No attestation_data found".into()))?
                .as_s()
                .map_err(|_| DynamoDBError::Internal("Invalid attestation_data format".into()))?;

            let attestation: crate::app_attest::DeviceAttestation =
                serde_json::from_str(attestation_json)?;

            info!("Device attestation found for device: {}", device_id);
            Ok(Some(attestation))
        } else {
            info!("No device attestation found for device: {}", device_id);
            Ok(None)
        }
    }

    pub async fn update_device_counter(
        &self,
        device_id: &str,
        new_counter: u64,
    ) -> Result<(), DynamoDBError> {
        info!(
            "Updating counter for device: {} to {}",
            device_id, new_counter
        );

        let now = chrono::Utc::now();

        self.client
            .update_item()
            .table_name(&self.attestations_table)
            .key("device_id", AttributeValue::S(device_id.to_string()))
            .update_expression("SET #counter = :new_counter, #last_used = :now")
            .expression_attribute_names("#counter", "counter")
            .expression_attribute_names("#last_used", "last_used_at")
            .expression_attribute_values(":new_counter", AttributeValue::N(new_counter.to_string()))
            .expression_attribute_values(":now", AttributeValue::S(now.to_rfc3339()))
            .send()
            .await?;

        info!(
            "Counter updated successfully for device: {}",
            device_id
        );
        Ok(())
    }

    pub async fn update_device_security_state(
        &self,
        device_id: &str,
        security_state: &crate::app_attest::SecurityState,
    ) -> Result<(), DynamoDBError> {
        info!(
            "Updating security state for device: {} to {:?}",
            device_id, security_state
        );

        self.client
            .update_item()
            .table_name(&self.attestations_table)
            .key("device_id", AttributeValue::S(device_id.to_string()))
            .update_expression("SET #state = :new_state")
            .expression_attribute_names("#state", "security_state")
            .expression_attribute_values(
                ":new_state",
                AttributeValue::S(format!("{:?}", security_state)),
            )
            .send()
            .await?;

        info!(
            "Security state updated successfully for device: {}",
            device_id
        );
        Ok(())
    }

    pub async fn get_user_devices(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<crate::app_attest::DeviceAttestation>, DynamoDBError> {
        info!("Getting all devices for user: {}", user_id);

        // Note: This requires a GSI on user_id for efficient querying
        let result = self
            .client
            .query()
            .table_name(&self.attestations_table)
            .index_name("user_id-index")
            .key_condition_expression("#user_id = :user_id")
            .expression_attribute_names("#user_id", "user_id")
            .expression_attribute_values(":user_id", AttributeValue::S(user_id.to_string()))
            .send()
            .await?;

        let mut devices = Vec::new();
        if let Some(items) = result.items {
            for item in items {
                if let Some(attestation_data) = item.get("attestation_data") {
                    if let Ok(attestation_json) = attestation_data.as_s() {
                        if let Ok(attestation) = serde_json::from_str(attestation_json) {
                            devices.push(attestation);
                        }
                    }
                }
            }
        }

        info!("Found {} devices for user: {}", devices.len(), user_id);
        Ok(devices)
    }
}
