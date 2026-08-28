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
    /// Attribute FQNs the user holds. Populated from the `entitlements`
    /// list attribute; rows written before the attribute existed get
    /// [`crate::constants::DEFAULT_USER_ENTITLEMENTS`].
    pub entitlements: Vec<String>,
}

/// Delegation of a human (PE) or agent to an agent NPE identified by did:key.
///
/// One row per agent DID. A pending challenge for the token flow is stored on
/// the same row (`challenge`, `challenge_nonce`, `challenge_issued_at`) and
/// removed atomically when taken, so no cookie session is involved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDelegation {
    /// Agent's DID (did:key:z6Mk...)
    pub agent_did: String,
    /// Type of delegator: "human" or "agent"
    pub delegator_type: String,
    /// Delegator's identifier (user UUID for human, DID for agent)
    pub delegator_id: String,
    /// Delegator's username (if human)
    pub delegator_username: Option<String>,
    /// Entitlements granted to the agent (attribute FQNs)
    pub entitlements: Vec<String>,
    /// Human-readable name for the agent
    pub name: String,
    /// Delegation depth (0 = direct from human)
    pub depth: u8,
    /// Original human's UUID (root of delegation chain)
    pub root_user_id: Uuid,
    /// DID chain from root to immediate delegator (empty for depth 0)
    pub chain: Vec<String>,
    /// Creation timestamp (Unix epoch)
    pub created_at: i64,
    /// Expiration timestamp (Unix epoch)
    pub expires_at: Option<i64>,
    /// Revocation timestamp (Unix epoch)
    pub revoked_at: Option<i64>,
}

/// A challenge taken from a delegation row by [`DynamoDBStore::take_agent_challenge`].
#[derive(Debug, Clone)]
pub struct TakenChallenge {
    pub issued_at: i64,
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

    #[error("Identity already linked to a different user")]
    LinkConflict,
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
    identity_links_table: String,
    patreon_tokens_table: String,
    agent_delegations_table: String,
}

impl DynamoDBStore {
    pub async fn new(
        credentials_table: String,
        handles_table: String,
        device_bindings_table: String,
        identity_links_table: String,
        patreon_tokens_table: String,
        agent_delegations_table: String,
    ) -> Result<Self, DynamoDBError> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Client::new(&config);

        Ok(Self {
            client,
            credentials_table,
            handles_table,
            device_bindings_table,
            identity_links_table,
            patreon_tokens_table,
            agent_delegations_table,
        })
    }

    /// Persist (or replace) the Patreon token bundle for a user.
    ///
    /// This is keyed by the arkavo `user_id` — one Patreon link per user, per
    /// role. Re-linking overwrites the previous row (a user can re-authorize
    /// to refresh consent or change role from consumer to creator). The
    /// per-(provider, patreon_user_id) uniqueness invariant is enforced
    /// separately via [`link_identity`] on the `identity_links` table, which
    /// mirrors the Apple linking pattern.
    pub async fn put_patreon_link(
        &self,
        link: &crate::patreon::PatreonLink,
    ) -> Result<(), DynamoDBError> {
        info!(
            "Persisting Patreon link. Table: {}, user_id: {}, role: {}",
            self.patreon_tokens_table, link.user_id, link.role
        );

        let mut item_builder = self
            .client
            .put_item()
            .table_name(&self.patreon_tokens_table)
            .item("user_id", AttributeValue::S(link.user_id.to_string()))
            .item("role", AttributeValue::S(link.role.clone()))
            .item("client_id", AttributeValue::S(link.client_id.clone()))
            .item(
                "patreon_user_id",
                AttributeValue::S(link.patreon_user_id.clone()),
            )
            .item("scopes", AttributeValue::S(link.scopes.clone()))
            .item(
                "access_token_ct",
                AttributeValue::B(aws_sdk_dynamodb::primitives::Blob::new(
                    link.access_token_ct.clone(),
                )),
            )
            .item(
                "access_token_nonce",
                AttributeValue::B(aws_sdk_dynamodb::primitives::Blob::new(
                    link.access_token_nonce.clone(),
                )),
            )
            .item(
                "refresh_token_ct",
                AttributeValue::B(aws_sdk_dynamodb::primitives::Blob::new(
                    link.refresh_token_ct.clone(),
                )),
            )
            .item(
                "refresh_token_nonce",
                AttributeValue::B(aws_sdk_dynamodb::primitives::Blob::new(
                    link.refresh_token_nonce.clone(),
                )),
            )
            .item(
                "wrapped_dek",
                AttributeValue::B(aws_sdk_dynamodb::primitives::Blob::new(
                    link.wrapped_dek.clone(),
                )),
            )
            .item(
                "token_expires_at",
                AttributeValue::N(link.token_expires_at.to_string()),
            )
            .item("linked_at", AttributeValue::N(link.linked_at.to_string()));
        if let Some(cid) = &link.campaign_id {
            item_builder = item_builder.item("campaign_id", AttributeValue::S(cid.clone()));
        }

        match item_builder.send().await {
            Ok(_) => Ok(()),
            Err(err) => match err {
                SdkError::ServiceError(ref service_error) => {
                    if service_error.err().meta().code() == Some("ResourceNotFoundException") {
                        error!(
                            "patreon_tokens table {} does not exist",
                            self.patreon_tokens_table
                        );
                        return Err(DynamoDBError::TableNotExists(
                            self.patreon_tokens_table.clone(),
                        ));
                    }
                    error!("Failed to write to patreon_tokens table: {:?}", err);
                    Err(DynamoDBError::SdkError(err.to_string()))
                }
                _ => {
                    error!("Unknown error writing to patreon_tokens table: {:?}", err);
                    Err(DynamoDBError::SdkError(err.to_string()))
                }
            },
        }
    }

    /// Read the Patreon token bundle for a user, if any.
    ///
    /// Returns `Ok(None)` when the user has not linked Patreon.
    pub async fn get_patreon_link(
        &self,
        user_id: Uuid,
    ) -> Result<Option<crate::patreon::PatreonLink>, DynamoDBError> {
        let result = self
            .client
            .get_item()
            .table_name(&self.patreon_tokens_table)
            .key("user_id", AttributeValue::S(user_id.to_string()))
            .send()
            .await
            .map_err(|err| {
                error!("Failed to read patreon_tokens for {}: {:?}", user_id, err);
                DynamoDBError::SdkError(err.to_string())
            })?;

        let Some(item) = result.item else {
            return Ok(None);
        };
        item_to_patreon_link(&item).map(Some)
    }

    /// Write a `handle -> did` row into the shared `handles` (prod-handles)
    /// store. Used by webvh provisioning to publish the canonical `did:webvh`.
    /// The handle is lowercased to match ATProto normalisation and the
    /// resolveHandle Lambda's lowercased read key.
    ///
    /// SECURITY: the write is conditional on handle ownership — a row may only be
    /// created when the handle is unclaimed, or rewritten by its owning
    /// `user_id`. Defense-in-depth against handle/identity takeover (the shared
    /// store the resolveHandle Lambda serves). Pre-existing rows that lack a
    /// `user_id` (legacy did:plc/did:key seeds) are intentionally NOT claimable
    /// here — they require an explicit operator migration (stamp the owning
    /// `user_id`, or delete) rather than being silently overwritten by the first
    /// registrant. A conflicting attempt returns [`DynamoDBError::LinkConflict`].
    pub async fn put_handle(
        &self,
        handle: &str,
        did: &str,
        user_id: &Uuid,
    ) -> Result<(), DynamoDBError> {
        let result = self
            .client
            .put_item()
            .table_name(&self.handles_table)
            .item("handle", AttributeValue::S(handle.to_lowercase()))
            .item("did", AttributeValue::S(did.to_string()))
            .item("user_id", AttributeValue::S(user_id.to_string()))
            .condition_expression("attribute_not_exists(handle) OR user_id = :uid")
            .expression_attribute_values(":uid", AttributeValue::S(user_id.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(err) => {
                if let SdkError::ServiceError(ref se) = err {
                    if se.err().meta().code() == Some("ConditionalCheckFailedException") {
                        warn!(
                            "put_handle: {} owned by another user — write refused",
                            handle
                        );
                        return Err(DynamoDBError::LinkConflict);
                    }
                }
                Err(DynamoDBError::SdkError(err.to_string()))
            }
        }
    }

    /// Link a third-party identity (e.g. Apple `sub`) to an existing user.
    ///
    /// Idempotent on (provider, subject): re-linking the same identity to the
    /// same user succeeds silently; linking to a different user returns
    /// [`DynamoDBError::LinkConflict`] (HTTP 409 upstream).
    ///
    /// Minimum-PII: only the join key is persisted. No email, display name,
    /// relay address, or other identity metadata is stored here.
    pub async fn link_identity(
        &self,
        user_id: Uuid,
        provider: &str,
        subject: &str,
    ) -> Result<(), DynamoDBError> {
        let link_pk = format!("{}#{}", provider, subject);
        let now = chrono::Utc::now().timestamp();

        // Privacy: never log the full link_pk (it contains the pseudonymous
        // IdP subject). The handler in apple_signin.rs deliberately logs only
        // the first 8 chars of subject; mirror that here so the handler →
        // db.rs log chain can still be correlated without disclosing the
        // full sub.
        let subject_log = log_subject_prefix(subject);

        info!(
            "Linking identity. Table: {}, provider: {}, subject_prefix: {}, user_id: {}",
            self.identity_links_table, provider, subject_log, user_id
        );

        let result = self
            .client
            .put_item()
            .table_name(&self.identity_links_table)
            .item("link_pk", AttributeValue::S(link_pk.clone()))
            .item("user_id", AttributeValue::S(user_id.to_string()))
            .item("provider", AttributeValue::S(provider.to_string()))
            .item("subject", AttributeValue::S(subject.to_string()))
            .item("linked_at", AttributeValue::N(now.to_string()))
            // Allow idempotent re-link (same user) but reject linking to a
            // different user — that's the cross-account hijack case.
            .condition_expression("attribute_not_exists(link_pk) OR user_id = :uid")
            .expression_attribute_values(":uid", AttributeValue::S(user_id.to_string()))
            .send()
            .await;

        match result {
            Ok(_) => {
                info!(
                    "Linked identity provider={} subject_prefix={} to user {}",
                    provider, subject_log, user_id
                );
                Ok(())
            }
            Err(err) => match err {
                SdkError::ServiceError(ref service_error) => {
                    let code = service_error.err().meta().code();
                    if code == Some("ConditionalCheckFailedException") {
                        warn!(
                            "Identity provider={} subject_prefix={} already linked to a different user",
                            provider, subject_log
                        );
                        return Err(DynamoDBError::LinkConflict);
                    }
                    if code == Some("ResourceNotFoundException") {
                        error!(
                            "identity_links table {} does not exist",
                            self.identity_links_table
                        );
                        return Err(DynamoDBError::TableNotExists(
                            self.identity_links_table.clone(),
                        ));
                    }
                    error!(
                        "Failed to write identity link provider={} subject_prefix={}: {:?}",
                        provider, subject_log, err
                    );
                    Err(DynamoDBError::SdkError(err.to_string()))
                }
                _ => {
                    error!(
                        "Unknown error writing identity link provider={} subject_prefix={}: {:?}",
                        provider, subject_log, err
                    );
                    Err(DynamoDBError::SdkError(err.to_string()))
                }
            },
        }
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
            entitlements: crate::constants::DEFAULT_USER_ENTITLEMENTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
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
            .item(
                "entitlements",
                AttributeValue::L(
                    crate::constants::DEFAULT_USER_ENTITLEMENTS
                        .iter()
                        .map(|s| AttributeValue::S(s.to_string()))
                        .collect(),
                ),
            )
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

        // NOTE: the handle record is intentionally NOT written here anymore.
        // It used to write `{username}.arkavo.social -> did:key:...`, which is
        // invalid for ATProto consumption and polluted the shared `handles`
        // (prod-handles) store the resolveHandle Lambda serves. The handle is
        // now written as `<handle> -> did:webvh:...` (lowercased) by the webvh
        // provisioning at registration. See [`put_handle`] and src/webvh.rs
        // (`on_passkey_registered`).

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

    /// Fetch a user by primary key (`user_id`). General accessor; intended for
    /// webvh backfill-on-login (provisioning a did:webvh for users who
    /// registered before it existed) — a tracked follow-up.
    pub async fn get_user_by_id(
        &self,
        user_id: &Uuid,
    ) -> Result<Option<UserCredentials>, DynamoDBError> {
        let result = self
            .client
            .get_item()
            .table_name(&self.credentials_table)
            .key("user_id", AttributeValue::S(user_id.to_string()))
            .send()
            .await
            .map_err(|e| DynamoDBError::SdkError(e.to_string()))?;
        match result.item {
            Some(item) => self.item_to_user_credentials(&item).map(Some),
            None => Ok(None),
        }
    }

    /// Entitlements for a user; defaults when the row predates the attribute.
    pub async fn get_user_entitlements(
        &self,
        user_id: &Uuid,
    ) -> Result<Vec<String>, DynamoDBError> {
        Ok(self
            .get_user_by_id(user_id)
            .await?
            .map(|u| u.entitlements)
            .unwrap_or_default())
    }

    /// Replace a user's entitlement list. Fails if the user does not exist.
    pub async fn put_user_entitlements(
        &self,
        user_id: &Uuid,
        entitlements: &[String],
    ) -> Result<(), DynamoDBError> {
        self.client
            .update_item()
            .table_name(&self.credentials_table)
            .key("user_id", AttributeValue::S(user_id.to_string()))
            .condition_expression("attribute_exists(user_id)")
            .update_expression("SET entitlements = :e")
            .expression_attribute_values(
                ":e",
                AttributeValue::L(
                    entitlements
                        .iter()
                        .map(|s| AttributeValue::S(s.clone()))
                        .collect(),
                ),
            )
            .send()
            .await
            .map_err(|err| {
                error!("Failed to put entitlements for {}: {:?}", user_id, err);
                DynamoDBError::SdkError(err.to_string())
            })?;
        Ok(())
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

    pub(crate) fn parse_user_credentials(
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
        let entitlements = match item.get("entitlements").and_then(|av| av.as_l().ok()) {
            Some(list) => list
                .iter()
                .filter_map(|av| av.as_s().ok().map(|s| s.to_string()))
                .collect(),
            None => crate::constants::DEFAULT_USER_ENTITLEMENTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };
        Ok(UserCredentials {
            user_id,
            username,
            credentials,
            did,
            entitlements,
        })
    }

    fn item_to_user_credentials(
        &self,
        item: &std::collections::HashMap<String, AttributeValue>,
    ) -> Result<UserCredentials, DynamoDBError> {
        Self::parse_user_credentials(item)
    }

    /// Persist the did:webvh append-only log (`did.jsonl`) for a user, as a
    /// `webvh_log` attribute on the credentials row. (A future iteration may
    /// move the log to its own table; the credentials-row attribute is the
    /// current home for the resolution endpoint.)
    pub async fn put_webvh_log(&self, user_id: &Uuid, log: &str) -> Result<(), DynamoDBError> {
        self.client
            .update_item()
            .table_name(&self.credentials_table)
            .key("user_id", AttributeValue::S(user_id.to_string()))
            .update_expression("SET webvh_log = :log")
            .expression_attribute_values(":log", AttributeValue::S(log.to_string()))
            .send()
            .await
            .map_err(|e| DynamoDBError::SdkError(e.to_string()))?;
        Ok(())
    }

    /// Read a user's persisted did:webvh log, if any.
    pub async fn get_webvh_log(&self, user_id: &Uuid) -> Result<Option<String>, DynamoDBError> {
        let resp = self
            .client
            .get_item()
            .table_name(&self.credentials_table)
            .key("user_id", AttributeValue::S(user_id.to_string()))
            .projection_expression("webvh_log")
            .send()
            .await
            .map_err(|e| DynamoDBError::SdkError(e.to_string()))?;
        Ok(resp
            .item()
            .and_then(|i| i.get("webvh_log"))
            .and_then(|v| v.as_s().ok())
            .map(|s| s.to_string()))
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

    // ------------------------------------------------------------------
    // Agent delegation (PE → agent NPE)
    // ------------------------------------------------------------------

    /// Create (or overwrite a revoked) agent delegation record.
    pub async fn create_agent_delegation(
        &self,
        delegation: &AgentDelegation,
    ) -> Result<(), DynamoDBError> {
        info!(
            "Creating agent delegation. Table: {}, Agent DID: {}",
            self.agent_delegations_table, delegation.agent_did
        );

        let mut item_builder = self
            .client
            .put_item()
            .table_name(&self.agent_delegations_table)
            .item("agent_did", AttributeValue::S(delegation.agent_did.clone()))
            .item(
                "delegator_type",
                AttributeValue::S(delegation.delegator_type.clone()),
            )
            .item(
                "delegator_id",
                AttributeValue::S(delegation.delegator_id.clone()),
            )
            .item(
                "entitlements",
                AttributeValue::L(
                    delegation
                        .entitlements
                        .iter()
                        .map(|e| AttributeValue::S(e.clone()))
                        .collect(),
                ),
            )
            .item("name", AttributeValue::S(delegation.name.clone()))
            .item("depth", AttributeValue::N(delegation.depth.to_string()))
            .item(
                "root_user_id",
                AttributeValue::S(delegation.root_user_id.to_string()),
            )
            .item(
                "chain",
                AttributeValue::L(
                    delegation
                        .chain
                        .iter()
                        .map(|d| AttributeValue::S(d.clone()))
                        .collect(),
                ),
            )
            .item(
                "created_at",
                AttributeValue::N(delegation.created_at.to_string()),
            );

        if let Some(username) = &delegation.delegator_username {
            item_builder =
                item_builder.item("delegator_username", AttributeValue::S(username.clone()));
        }
        if let Some(expires_at) = delegation.expires_at {
            item_builder =
                item_builder.item("expires_at", AttributeValue::N(expires_at.to_string()));
        }
        if let Some(revoked_at) = delegation.revoked_at {
            item_builder =
                item_builder.item("revoked_at", AttributeValue::N(revoked_at.to_string()));
        }

        match item_builder.send().await {
            Ok(_) => {
                info!("Created agent delegation for: {}", delegation.agent_did);
                Ok(())
            }
            Err(err) => {
                if let SdkError::ServiceError(ref service_error) = err
                    && service_error.err().meta().code() == Some("ResourceNotFoundException")
                {
                    error!(
                        "agent_delegations table {} does not exist",
                        self.agent_delegations_table
                    );
                    return Err(DynamoDBError::TableNotExists(
                        self.agent_delegations_table.clone(),
                    ));
                }
                error!("Failed to write agent delegation: {:?}", err);
                Err(DynamoDBError::SdkError(err.to_string()))
            }
        }
    }

    /// Get an agent delegation by agent DID.
    pub async fn get_agent_delegation(
        &self,
        agent_did: &str,
    ) -> Result<Option<AgentDelegation>, DynamoDBError> {
        let result = self
            .client
            .get_item()
            .table_name(&self.agent_delegations_table)
            .key("agent_did", AttributeValue::S(agent_did.to_string()))
            .send()
            .await
            .map_err(|err| {
                error!("Failed to query agent delegation {}: {:?}", agent_did, err);
                DynamoDBError::from(err)
            })?;

        match result.item {
            Some(item) => Ok(Some(Self::item_to_agent_delegation(&item)?)),
            None => Ok(None),
        }
    }

    /// List all delegations rooted at a user (GSI `root_user_id-index`).
    pub async fn list_delegations_by_root_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AgentDelegation>, DynamoDBError> {
        let result = self
            .client
            .query()
            .table_name(&self.agent_delegations_table)
            .index_name("root_user_id-index")
            .key_condition_expression("root_user_id = :root_user_id")
            .expression_attribute_values(":root_user_id", AttributeValue::S(user_id.to_string()))
            .send()
            .await
            .map_err(|err| {
                error!("Failed to list delegations for user {}: {:?}", user_id, err);
                DynamoDBError::from(err)
            })?;

        let mut delegations = Vec::new();
        for item in result.items.unwrap_or_default() {
            match Self::item_to_agent_delegation(&item) {
                Ok(d) => delegations.push(d),
                Err(err) => warn!("Skipping unparseable delegation item: {:?}", err),
            }
        }
        Ok(delegations)
    }

    /// Count active (non-revoked) delegations rooted at a user.
    pub async fn count_delegations_by_root_user(
        &self,
        user_id: Uuid,
    ) -> Result<u32, DynamoDBError> {
        let result = self
            .client
            .query()
            .table_name(&self.agent_delegations_table)
            .index_name("root_user_id-index")
            .key_condition_expression("root_user_id = :root_user_id")
            .filter_expression("attribute_not_exists(revoked_at)")
            .expression_attribute_values(":root_user_id", AttributeValue::S(user_id.to_string()))
            .select(aws_sdk_dynamodb::types::Select::Count)
            .send()
            .await
            .map_err(|err| {
                error!(
                    "Failed to count delegations for user {}: {:?}",
                    user_id, err
                );
                DynamoDBError::from(err)
            })?;

        Ok(result.count as u32)
    }

    /// Revoke one delegation (sets `revoked_at`).
    pub async fn revoke_delegation(&self, agent_did: &str) -> Result<(), DynamoDBError> {
        let revoked_at = chrono::Utc::now().timestamp();
        self.client
            .update_item()
            .table_name(&self.agent_delegations_table)
            .key("agent_did", AttributeValue::S(agent_did.to_string()))
            .update_expression("SET revoked_at = :revoked_at")
            .expression_attribute_values(":revoked_at", AttributeValue::N(revoked_at.to_string()))
            .send()
            .await
            .map_err(|err| {
                error!("Failed to revoke delegation {}: {:?}", agent_did, err);
                DynamoDBError::SdkError(err.to_string())
            })?;
        info!("Revoked delegation for: {}", agent_did);
        Ok(())
    }

    /// Cascade: revoke every active delegation whose chain contains `did`.
    ///
    /// Uses a table scan; chains are short and this runs on revoke only.
    pub async fn revoke_delegations_with_chain(&self, did: &str) -> Result<u32, DynamoDBError> {
        let result = self
            .client
            .scan()
            .table_name(&self.agent_delegations_table)
            .filter_expression("contains(#chain, :did) AND attribute_not_exists(revoked_at)")
            .expression_attribute_names("#chain", "chain")
            .expression_attribute_values(":did", AttributeValue::S(did.to_string()))
            .send()
            .await
            .map_err(|err| {
                error!("Failed to scan delegations for chain {}: {:?}", did, err);
                DynamoDBError::from(err)
            })?;

        let mut revoked = 0u32;
        for item in result.items.unwrap_or_default() {
            if let Some(agent_did_av) = item.get("agent_did")
                && let Ok(agent_did) = agent_did_av.as_s()
            {
                match self.revoke_delegation(agent_did).await {
                    Ok(()) => revoked += 1,
                    Err(err) => warn!("Cascade revoke failed for {}: {:?}", agent_did, err),
                }
            }
        }
        Ok(revoked)
    }

    /// Store a pending challenge on the delegation row (replaces any prior one).
    /// Fails if no delegation row exists for the DID.
    pub async fn put_agent_challenge(
        &self,
        agent_did: &str,
        challenge: &str,
        nonce: &str,
        issued_at: i64,
    ) -> Result<(), DynamoDBError> {
        self.client
            .update_item()
            .table_name(&self.agent_delegations_table)
            .key("agent_did", AttributeValue::S(agent_did.to_string()))
            .condition_expression("attribute_exists(agent_did)")
            .update_expression("SET challenge = :c, challenge_nonce = :n, challenge_issued_at = :t")
            .expression_attribute_values(":c", AttributeValue::S(challenge.to_string()))
            .expression_attribute_values(":n", AttributeValue::S(nonce.to_string()))
            .expression_attribute_values(":t", AttributeValue::N(issued_at.to_string()))
            .send()
            .await
            .map_err(|err| {
                error!(
                    "Failed to store agent challenge for {}: {:?}",
                    agent_did, err
                );
                DynamoDBError::SdkError(err.to_string())
            })?;
        Ok(())
    }

    /// Atomically take the pending challenge if `(challenge, nonce)` match.
    ///
    /// Returns `Ok(None)` when nothing matched (unknown DID, no pending
    /// challenge, or mismatch) — the caller treats all of those as a failed
    /// proof. A matched challenge is removed so it can never be replayed.
    pub async fn take_agent_challenge(
        &self,
        agent_did: &str,
        challenge: &str,
        nonce: &str,
    ) -> Result<Option<TakenChallenge>, DynamoDBError> {
        let result = self
            .client
            .update_item()
            .table_name(&self.agent_delegations_table)
            .key("agent_did", AttributeValue::S(agent_did.to_string()))
            .condition_expression("challenge = :c AND challenge_nonce = :n")
            .update_expression("REMOVE challenge, challenge_nonce, challenge_issued_at")
            .expression_attribute_values(":c", AttributeValue::S(challenge.to_string()))
            .expression_attribute_values(":n", AttributeValue::S(nonce.to_string()))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .send()
            .await;

        match result {
            Ok(out) => {
                let issued_at = out
                    .attributes
                    .as_ref()
                    .and_then(|a| a.get("challenge_issued_at"))
                    .and_then(|av| av.as_n().ok())
                    .and_then(|n| n.parse::<i64>().ok())
                    .ok_or_else(|| {
                        DynamoDBError::Internal("challenge_issued_at missing on take".into())
                    })?;
                Ok(Some(TakenChallenge { issued_at }))
            }
            Err(err) => {
                if let SdkError::ServiceError(ref service_error) = err
                    && service_error.err().meta().code() == Some("ConditionalCheckFailedException")
                {
                    return Ok(None);
                }
                error!(
                    "Failed to take agent challenge for {}: {:?}",
                    agent_did, err
                );
                Err(DynamoDBError::SdkError(err.to_string()))
            }
        }
    }

    fn item_to_agent_delegation(
        item: &std::collections::HashMap<String, AttributeValue>,
    ) -> Result<AgentDelegation, DynamoDBError> {
        fn req_s(
            item: &std::collections::HashMap<String, AttributeValue>,
            key: &str,
        ) -> Result<String, DynamoDBError> {
            item.get(key)
                .ok_or_else(|| DynamoDBError::Internal(format!("No {} found", key)))?
                .as_s()
                .map(|s| s.to_string())
                .map_err(|_| DynamoDBError::Internal(format!("Invalid {} format", key)))
        }
        fn req_n<T: std::str::FromStr>(
            item: &std::collections::HashMap<String, AttributeValue>,
            key: &str,
        ) -> Result<T, DynamoDBError> {
            item.get(key)
                .ok_or_else(|| DynamoDBError::Internal(format!("No {} found", key)))?
                .as_n()
                .map_err(|_| DynamoDBError::Internal(format!("Invalid {} format", key)))?
                .parse::<T>()
                .map_err(|_| DynamoDBError::Internal(format!("Failed to parse {}", key)))
        }
        fn opt_n(
            item: &std::collections::HashMap<String, AttributeValue>,
            key: &str,
        ) -> Option<i64> {
            item.get(key)
                .and_then(|av| av.as_n().ok())
                .and_then(|n| n.parse::<i64>().ok())
        }
        fn list_s(
            item: &std::collections::HashMap<String, AttributeValue>,
            key: &str,
        ) -> Result<Vec<String>, DynamoDBError> {
            Ok(item
                .get(key)
                .ok_or_else(|| DynamoDBError::Internal(format!("No {} found", key)))?
                .as_l()
                .map_err(|_| DynamoDBError::Internal(format!("Invalid {} format", key)))?
                .iter()
                .filter_map(|av| av.as_s().ok().map(|s| s.to_string()))
                .collect())
        }

        Ok(AgentDelegation {
            agent_did: req_s(item, "agent_did")?,
            delegator_type: req_s(item, "delegator_type")?,
            delegator_id: req_s(item, "delegator_id")?,
            delegator_username: item
                .get("delegator_username")
                .and_then(|av| av.as_s().ok())
                .map(|s| s.to_string()),
            entitlements: list_s(item, "entitlements")?,
            name: req_s(item, "name")?,
            depth: req_n(item, "depth")?,
            root_user_id: Uuid::parse_str(&req_s(item, "root_user_id")?)?,
            chain: list_s(item, "chain")?,
            created_at: req_n(item, "created_at")?,
            expires_at: opt_n(item, "expires_at"),
            revoked_at: opt_n(item, "revoked_at"),
        })
    }
}

fn item_to_patreon_link(
    item: &std::collections::HashMap<String, AttributeValue>,
) -> Result<crate::patreon::PatreonLink, DynamoDBError> {
    fn read_string(
        item: &std::collections::HashMap<String, AttributeValue>,
        key: &str,
    ) -> Result<String, DynamoDBError> {
        item.get(key)
            .ok_or_else(|| DynamoDBError::Internal(format!("Missing patreon field {}", key)))?
            .as_s()
            .map_err(|_| DynamoDBError::Internal(format!("Invalid patreon field {}", key)))
            .map(|s| s.to_string())
    }
    fn read_bytes(
        item: &std::collections::HashMap<String, AttributeValue>,
        key: &str,
    ) -> Result<Vec<u8>, DynamoDBError> {
        item.get(key)
            .ok_or_else(|| DynamoDBError::Internal(format!("Missing patreon field {}", key)))?
            .as_b()
            .map_err(|_| DynamoDBError::Internal(format!("Invalid patreon field {}", key)))
            .map(|b| b.as_ref().to_vec())
    }
    fn read_i64(
        item: &std::collections::HashMap<String, AttributeValue>,
        key: &str,
    ) -> Result<i64, DynamoDBError> {
        item.get(key)
            .ok_or_else(|| DynamoDBError::Internal(format!("Missing patreon field {}", key)))?
            .as_n()
            .map_err(|_| DynamoDBError::Internal(format!("Invalid patreon field {}", key)))?
            .parse::<i64>()
            .map_err(|_| DynamoDBError::Internal(format!("Unparseable number for {}", key)))
    }

    let user_id = Uuid::parse_str(&read_string(item, "user_id")?)?;
    let role = read_string(item, "role")?;
    // Rows written before multi-client support have no client_id; an empty
    // string defers to PatreonOAuthConfig::client_by_id's single-client
    // fallback rather than failing the read.
    let client_id = item
        .get("client_id")
        .and_then(|v| v.as_s().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();
    let patreon_user_id = read_string(item, "patreon_user_id")?;
    let scopes = read_string(item, "scopes")?;
    let access_token_ct = read_bytes(item, "access_token_ct")?;
    let access_token_nonce = read_bytes(item, "access_token_nonce")?;
    let refresh_token_ct = read_bytes(item, "refresh_token_ct")?;
    let refresh_token_nonce = read_bytes(item, "refresh_token_nonce")?;
    let wrapped_dek = read_bytes(item, "wrapped_dek")?;
    let token_expires_at = read_i64(item, "token_expires_at")?;
    let linked_at = read_i64(item, "linked_at")?;
    let campaign_id = item
        .get("campaign_id")
        .and_then(|v| v.as_s().ok())
        .map(|s| s.to_string());

    Ok(crate::patreon::PatreonLink {
        user_id,
        role,
        client_id,
        patreon_user_id,
        campaign_id,
        scopes,
        access_token_ct,
        access_token_nonce,
        refresh_token_ct,
        refresh_token_nonce,
        wrapped_dek,
        token_expires_at,
        linked_at,
    })
}

/// Privacy-preserving subject masker used by `link_identity` logs.
///
/// Returns the first 8 *characters* of an opaque IdP subject (Apple `sub`,
/// future Google `sub`, etc.) so log lines can be correlated end-to-end
/// without disclosing the full pseudonymous identifier. `char_indices` is
/// used so multi-byte UTF-8 subjects do not panic on a mid-codepoint slice.
fn log_subject_prefix(subject: &str) -> &str {
    match subject.char_indices().nth(8) {
        Some((byte_idx, _)) => &subject[..byte_idx],
        None => subject,
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
            entitlements: crate::constants::DEFAULT_USER_ENTITLEMENTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
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
            entitlements: crate::constants::DEFAULT_USER_ENTITLEMENTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
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
            DynamoDBError::LinkConflict,
        ];

        for error in errors {
            let msg = error.to_string();
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_link_conflict_error() {
        let error = DynamoDBError::LinkConflict;
        assert_eq!(
            error.to_string(),
            "Identity already linked to a different user"
        );
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

    #[test]
    fn test_log_subject_prefix_caps_at_eight_chars() {
        assert_eq!(log_subject_prefix("001234.abcdef.ghijkl"), "001234.a");
        assert_eq!(log_subject_prefix("short"), "short");
        assert_eq!(log_subject_prefix(""), "");
    }

    #[test]
    fn test_log_subject_prefix_handles_multibyte_utf8() {
        // Regression guard: byte-slicing would panic mid-codepoint here.
        let sub = "αβγδεζηθι";
        let prefix = log_subject_prefix(sub);
        assert_eq!(prefix, "αβγδεζηθ");
        assert_eq!(prefix.chars().count(), 8);
    }

    #[test]
    fn user_credentials_entitlements_default_when_attribute_missing() {
        use aws_sdk_dynamodb::types::AttributeValue;
        let mut item = std::collections::HashMap::new();
        item.insert(
            "user_id".to_string(),
            AttributeValue::S(Uuid::nil().to_string()),
        );
        item.insert("username".to_string(), AttributeValue::S("alice".into()));
        item.insert(
            "did".to_string(),
            AttributeValue::S("did:key:z6Mkabc".into()),
        );
        let parsed = DynamoDBStore::parse_user_credentials(&item).unwrap();
        assert_eq!(
            parsed.entitlements,
            crate::constants::DEFAULT_USER_ENTITLEMENTS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn user_credentials_entitlements_parsed_from_list() {
        use aws_sdk_dynamodb::types::AttributeValue;
        let mut item = std::collections::HashMap::new();
        item.insert(
            "user_id".to_string(),
            AttributeValue::S(Uuid::nil().to_string()),
        );
        item.insert("username".to_string(), AttributeValue::S("alice".into()));
        item.insert(
            "did".to_string(),
            AttributeValue::S("did:key:z6Mkabc".into()),
        );
        item.insert(
            "entitlements".to_string(),
            AttributeValue::L(vec![AttributeValue::S(
                "https://arkavo.ai/attr/action/value/read".into(),
            )]),
        );
        let parsed = DynamoDBStore::parse_user_credentials(&item).unwrap();
        assert_eq!(
            parsed.entitlements,
            vec!["https://arkavo.ai/attr/action/value/read".to_string()]
        );
    }
}
