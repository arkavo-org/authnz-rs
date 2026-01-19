//! Patreon API Client
//!
//! Handles OAuth token exchange and tier fetching for Patreon account linking.
//! Used to populate the SubscriptionTier attribute in NTDF tokens.

use log::{debug, error, info};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Patreon API client for OAuth and tier operations
pub struct PatreonClient {
    client: Client,
    client_id: String,
    client_secret: String,
}

/// Errors that can occur during Patreon operations
#[derive(Debug, Error)]
pub enum PatreonError {
    #[error("Token exchange failed: {0}")]
    TokenExchangeFailed(String),

    #[error("API request failed: {0}")]
    ApiRequestFailed(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
}

/// OAuth token response from Patreon
#[derive(Debug, Deserialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub scope: String,
    pub token_type: String,
}

/// User identity response from Patreon
#[derive(Debug, Deserialize)]
pub struct IdentityResponse {
    pub data: UserData,
    #[serde(default)]
    pub included: Vec<IncludedResource>,
}

#[derive(Debug, Deserialize)]
pub struct UserData {
    pub id: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub attributes: UserAttributes,
    #[serde(default)]
    pub relationships: Option<UserRelationships>,
}

#[derive(Debug, Deserialize)]
pub struct UserAttributes {
    pub email: Option<String>,
    pub full_name: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UserRelationships {
    #[serde(default)]
    pub memberships: Option<RelationshipData>,
}

#[derive(Debug, Deserialize)]
pub struct RelationshipData {
    pub data: Vec<ResourceIdentifier>,
}

#[derive(Debug, Deserialize)]
pub struct ResourceIdentifier {
    pub id: String,
    #[serde(rename = "type")]
    pub resource_type: String,
}

#[derive(Debug, Deserialize)]
pub struct IncludedResource {
    pub id: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(default)]
    pub attributes: Option<serde_json::Value>,
    #[serde(default)]
    pub relationships: Option<serde_json::Value>,
}

/// Membership attributes from included resources
#[derive(Debug, Deserialize)]
pub struct MembershipAttributes {
    pub patron_status: Option<String>,
    pub currently_entitled_amount_cents: Option<i32>,
    pub lifetime_support_cents: Option<i32>,
}

/// Result of fetching user tier information
#[derive(Debug, Clone)]
pub struct PatreonTierInfo {
    /// Patreon user ID
    pub user_id: String,
    /// User's email (if available)
    pub email: Option<String>,
    /// Subscription tier level (0=free, 1=basic, 2=premium, etc.)
    pub tier_level: u8,
    /// Currently entitled amount in cents (per month)
    pub entitled_cents: i32,
    /// Whether the user is an active patron
    pub is_active_patron: bool,
}

impl PatreonClient {
    /// Create a new Patreon client
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client: Client::new(),
            client_id,
            client_secret,
        }
    }

    /// Exchange an authorization code for access tokens
    pub async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<OAuthTokenResponse, PatreonError> {
        debug!("Exchanging Patreon authorization code");

        let params = [
            ("code", code),
            ("grant_type", "authorization_code"),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("redirect_uri", redirect_uri),
        ];

        let response = self
            .client
            .post("https://www.patreon.com/api/oauth2/token")
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Patreon token exchange failed: {} - {}", status, body);
            return Err(PatreonError::TokenExchangeFailed(format!(
                "HTTP {}: {}",
                status, body
            )));
        }

        let token: OAuthTokenResponse = response.json().await?;
        info!("Successfully exchanged Patreon authorization code");
        Ok(token)
    }

    /// Fetch user identity and tier information using an access token
    pub async fn get_user_tier(&self, access_token: &str) -> Result<PatreonTierInfo, PatreonError> {
        debug!("Fetching Patreon user identity and tier");

        let response = self
            .client
            .get("https://www.patreon.com/api/oauth2/v2/identity")
            .query(&[
                ("include", "memberships,memberships.currently_entitled_tiers"),
                (
                    "fields[user]",
                    "email,full_name",
                ),
                (
                    "fields[member]",
                    "patron_status,currently_entitled_amount_cents,lifetime_support_cents",
                ),
            ])
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Patreon identity request failed: {} - {}", status, body);
            return Err(PatreonError::ApiRequestFailed(format!(
                "HTTP {}: {}",
                status, body
            )));
        }

        let identity: IdentityResponse = response.json().await?;

        // Extract user info
        let user_id = identity.data.id.clone();
        let email = identity.data.attributes.email.clone();

        // Find membership info in included resources
        let mut tier_level: u8 = 0;
        let mut entitled_cents: i32 = 0;
        let mut is_active_patron = false;

        for resource in &identity.included {
            if resource.resource_type == "member" {
                if let Some(attrs) = &resource.attributes {
                    if let Ok(membership) =
                        serde_json::from_value::<MembershipAttributes>(attrs.clone())
                    {
                        // Check patron status
                        if let Some(status) = &membership.patron_status {
                            is_active_patron = status == "active_patron";
                        }

                        // Get entitled amount
                        if let Some(cents) = membership.currently_entitled_amount_cents {
                            entitled_cents = cents;
                        }
                    }
                }
            }
        }

        // Calculate tier level based on entitled amount
        // This is a simple mapping; creators can customize their own tier definitions
        tier_level = calculate_tier_level(entitled_cents);

        info!(
            "Patreon user {} tier_level={} entitled_cents={} active={}",
            user_id, tier_level, entitled_cents, is_active_patron
        );

        Ok(PatreonTierInfo {
            user_id,
            email,
            tier_level,
            entitled_cents,
            is_active_patron,
        })
    }
}

/// Calculate tier level from entitled cents
///
/// Tier mapping:
/// - 0: Free (no pledge or inactive)
/// - 1: Basic ($1-4.99/month)
/// - 2: Premium ($5-19.99/month)
/// - 3: VIP ($20+/month)
fn calculate_tier_level(entitled_cents: i32) -> u8 {
    match entitled_cents {
        0 => 0,           // Free
        1..=499 => 1,     // Basic: $1-4.99
        500..=1999 => 2,  // Premium: $5-19.99
        _ => 3,           // VIP: $20+
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_level_calculation() {
        assert_eq!(calculate_tier_level(0), 0);      // Free
        assert_eq!(calculate_tier_level(100), 1);   // $1 - Basic
        assert_eq!(calculate_tier_level(499), 1);   // $4.99 - Basic
        assert_eq!(calculate_tier_level(500), 2);   // $5 - Premium
        assert_eq!(calculate_tier_level(1000), 2);  // $10 - Premium
        assert_eq!(calculate_tier_level(1999), 2);  // $19.99 - Premium
        assert_eq!(calculate_tier_level(2000), 3);  // $20 - VIP
        assert_eq!(calculate_tier_level(5000), 3);  // $50 - VIP
    }
}
