use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client;
use base58::ToBase58;
use did_key::KeyMaterial;
use did_key::{generate, Ed25519KeyPair};
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
    AwsSdkError(#[from] aws_sdk_dynamodb::Error),

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
}

impl DynamoDBStore {
    pub async fn new(
        credentials_table: String,
        handles_table: String,
    ) -> Result<Self, DynamoDBError> {
        let config = aws_config::load_from_env().await;
        let client = Client::new(&config);

        Ok(Self {
            client,
            credentials_table,
            handles_table,
        })
    }

    pub async fn create_user(&self, username: &str) -> Result<UserCredentials, DynamoDBError> {
        info!(
            "Creating new user in DynamoDB. Table: {}, Username: {}",
            self.credentials_table, username
        );

        // Validate inputs
        if username.is_empty() {
            return Err(DynamoDBError::Internal("Username cannot be empty".into()));
        }

        // Generate DID
        let key_pair = generate::<Ed25519KeyPair>(None);
        let did = format!("did:key:{}", &key_pair.public_key_bytes().to_base58());
        info!("Generated DID: {}", did);

        let user = UserCredentials {
            user_id: Uuid::new_v4(),
            username: username.to_string(),
            credentials: Vec::new(),
            did: did.clone(),
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
                AttributeValue::S(format!("{}.arkavo.net", username)),
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
                            // TODO: Should attempt to rollback credentials entry
                            return Err(DynamoDBError::SdkError(err.to_string()));
                        }
                    }
                    _ => {
                        error!("Unknown error writing to handles table: {:?}", err);
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

                if let Ok(creds_str) = creds_av.as_s() {
                    info!("Parsing existing credentials from string");
                    if creds_str.is_empty() {
                        info!("Existing credentials string is empty, starting new list");
                        Vec::new()
                    } else {
                        match serde_json::from_str::<Vec<Passkey>>(creds_str) {
                            Ok(existing_creds) => {
                                info!(
                                    "Successfully parsed {} existing credentials",
                                    existing_creds.len()
                                );
                                // Check for duplicate credential
                                if existing_creds
                                    .iter()
                                    .any(|c| c.cred_id() == credential.cred_id())
                                {
                                    error!("Credential ID already exists for user");
                                    return Err(DynamoDBError::CredentialError(
                                        "Credential already registered".into(),
                                    ));
                                }
                                existing_creds
                            }
                            Err(e) => {
                                error!("Failed to parse existing credentials: {}", e);
                                return Err(DynamoDBError::SerdeJsonError(e));
                            }
                        }
                    }
                } else {
                    info!("Creating new credentials list");
                    Vec::new()
                }
            } else {
                info!("No existing credentials attribute, creating new list");
                Vec::new()
            }
        } else {
            error!("User {} not found in database", user_id);
            return Err(DynamoDBError::Internal(format!(
                "User {} not found",
                user_id
            )));
        };

        // Add new credential to the list
        credentials.push(credential);
        info!(
            "Added new credential. Total credentials: {}",
            credentials.len()
        );

        // Serialize credentials to JSON string
        let creds_json = match serde_json::to_string(&credentials) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize credentials: {}", e);
                return Err(DynamoDBError::SerdeJsonError(e));
            }
        };

        // Update the record with new credentials
        match self
            .client
            .update_item()
            .table_name(&self.credentials_table)
            .key("user_id", AttributeValue::S(user_id.to_string()))
            .update_expression("SET credentials = :credentials")
            .expression_attribute_values(":credentials", AttributeValue::S(creds_json))
            .send()
            .await
        {
            Ok(_) => {
                info!("Successfully updated credentials for user {}", user_id);
                Ok(())
            }
            Err(e) => {
                error!("Failed to update credentials in DynamoDB: {}", e);
                Err(DynamoDBError::from(e))
            }
        }
    }

    fn item_to_user_credentials(
        &self,
        item: &std::collections::HashMap<String, AttributeValue>,
    ) -> Result<UserCredentials, DynamoDBError> {
        println!("Parsing item: {:?}", item);
        let user_id = Uuid::parse_str(
            item.get("user_id")
                .ok_or_else(|| DynamoDBError::Internal("No user_id found".into()))?
                .as_s()
                .map_err(|_| DynamoDBError::Internal("Invalid user_id format".into()))?,
        )?;
        println!("Parsed user_id: {}", user_id);
        let username = item
            .get("username")
            .ok_or_else(|| DynamoDBError::Internal("No username found".into()))?
            .as_s()
            .map_err(|_| DynamoDBError::Internal("Invalid username format".into()))?
            .to_string();
        println!("Parsed username: {}", username);
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
        println!("Parsed credentials: {:?}", credentials);
        let did = item
            .get("did")
            .ok_or_else(|| DynamoDBError::Internal("No DID found".into()))?
            .as_s()
            .map_err(|_| DynamoDBError::Internal("Invalid DID format".into()))?
            .to_string();
        println!("Parsed DID: {}", did);
        Ok(UserCredentials {
            user_id,
            username,
            credentials,
            did,
        })
    }
}
