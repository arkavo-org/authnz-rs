use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client;
use base58::ToBase58;
use did_key::KeyMaterial;
use did_key::{generate, Ed25519KeyPair};
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
        // Generate DID use did:key method
        let key_pair = generate::<Ed25519KeyPair>(None);
        let did = format!("did:key:{}", &key_pair.public_key_bytes().to_base58());

        let user = UserCredentials {
            user_id: Uuid::new_v4(),
            username: username.to_string(),
            credentials: Vec::new(),
            did,
        };

        // Store the initial user record
        self.client
            .put_item()
            .table_name(&self.credentials_table)
            .item("user_id", AttributeValue::S(user.user_id.to_string()))
            .item("username", AttributeValue::S(username.to_string()))
            .item("credentials", AttributeValue::L(vec![]))
            .item("did", AttributeValue::S(user.did.clone()))
            .send()
            .await?;

        // Store the DID in the handles table
        self.client
            .put_item()
            .table_name(&self.handles_table)
            .item(
                "handle",
                AttributeValue::S(format!("{}.arkavo.net", username)),
            )
            .item("did", AttributeValue::S(user.did.clone()))
            .send()
            .await?;

        Ok(user)
    }

    pub async fn get_user_by_name(
        &self,
        username: &str,
    ) -> Result<Option<UserCredentials>, DynamoDBError> {
        let result = self
            .client
            .query()
            .table_name(&self.credentials_table)
            .index_name("username-index")
            .key_condition_expression("#username = :username")
            .expression_attribute_names("#username", "username")
            .expression_attribute_values(":username", AttributeValue::S(username.to_string()))
            .send()
            .await?;

        if let Some(items) = result.items {
            if let Some(item) = items.first() {
                return Ok(Some(self.item_to_user_credentials(item)?));
            }
        }

        Ok(None)
    }

    pub async fn add_credential(
        &self,
        user_id: Uuid,
        credential: Passkey,
    ) -> Result<(), DynamoDBError> {
        // Get existing credentials
        let result = self
            .client
            .get_item()
            .table_name(&self.credentials_table)
            .key("user_id", AttributeValue::S(user_id.to_string()))
            .send()
            .await?;

        let mut credentials = if let Some(item) = result.item {
            let creds_av = item
                .get("credentials")
                .ok_or_else(|| DynamoDBError::Internal("No credentials found".into()))?;
            serde_json::from_str::<Vec<Passkey>>(
                creds_av
                    .as_s()
                    .map_err(|_| DynamoDBError::Internal("Invalid credentials format".into()))?,
            )?
        } else {
            Vec::new()
        };

        // Add new credential
        credentials.push(credential);

        // Update record
        self.client
            .update_item()
            .table_name(&self.credentials_table)
            .key("user_id", AttributeValue::S(user_id.to_string()))
            .update_expression("SET credentials = :credentials")
            .expression_attribute_values(
                ":credentials",
                AttributeValue::S(serde_json::to_string(&credentials)?),
            )
            .send()
            .await?;

        Ok(())
    }

    fn item_to_user_credentials(
        &self,
        item: &std::collections::HashMap<String, AttributeValue>,
    ) -> Result<UserCredentials, DynamoDBError> {
        Ok(UserCredentials {
            user_id: Uuid::parse_str(
                item.get("user_id")
                    .ok_or_else(|| DynamoDBError::Internal("No user_id found".into()))?
                    .as_s()
                    .map_err(|_| DynamoDBError::Internal("Invalid user_id format".into()))?,
            )?,
            username: item
                .get("username")
                .ok_or_else(|| DynamoDBError::Internal("No username found".into()))?
                .as_s()
                .map_err(|_| DynamoDBError::Internal("Invalid username format".into()))?
                .to_string(),
            credentials: serde_json::from_str(
                item.get("credentials")
                    .ok_or_else(|| DynamoDBError::Internal("No credentials found".into()))?
                    .as_s()
                    .map_err(|_| DynamoDBError::Internal("Invalid credentials format".into()))?,
            )?,
            did: item
                .get("did")
                .ok_or_else(|| DynamoDBError::Internal("No DID found".into()))?
                .as_s()
                .map_err(|_| DynamoDBError::Internal("Invalid DID format".into()))?
                .to_string(),
        })
    }
}
