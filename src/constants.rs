/// Application constants for token lifetimes and session configuration
///
/// CWT registration token lifetime in weeks (~99 years)
///
/// SECURITY: Very long-lived tokens are intentional design choice.
/// Security model relies on WebAuthn passkey validation, not token expiration.
/// The passkey ceremony provides replay protection and strong authentication.
pub const REGISTRATION_TOKEN_WEEKS: i64 = 5148;

/// CWT authentication token lifetime in hours (Arkavo-issued auth + DeviceCheck assertion).
/// Also used for the OIDC access_token CWT lifetime.
pub const AUTH_TOKEN_HOURS: i64 = 1;

/// Session inactivity timeout in seconds (10 minutes)
pub const SESSION_TIMEOUT_SECONDS: i64 = 600;

/// OIDC issuer URL (default; can be overridden via OIDC_ISSUER env var)
pub const DEFAULT_OIDC_ISSUER: &str = "https://identity.arkavo.net";

/// OIDC ID token lifetime in seconds (1 hour)
pub const ID_TOKEN_LIFETIME_SECONDS: i64 = 3600;

/// OIDC access token lifetime in seconds (1 hour)
pub const ACCESS_TOKEN_LIFETIME_SECONDS: i64 = 3600;

/// OIDC authorization code lifetime in seconds (10 minutes)
pub const AUTHORIZATION_CODE_LIFETIME_SECONDS: i64 = 600;

/// Apple JWKS cache TTL in seconds (1 hour). Apple rotates keys infrequently.
pub const APPLE_JWKS_CACHE_TTL_SECONDS: i64 = 3600;

/// Apple JWKS URL
pub const APPLE_JWKS_URL: &str = "https://appleid.apple.com/auth/keys";

/// Apple OIDC issuer (used to validate `iss` claim on Apple id_tokens)
pub const APPLE_ISSUER: &str = "https://appleid.apple.com";

/// OIDC refresh token lifetime in seconds (30 days)
pub const REFRESH_TOKEN_LIFETIME_SECONDS: i64 = 2592000;

/// Patreon OAuth2 authorize endpoint.
///
/// Surfaced in documentation only — the Arkavo client opens this URL itself
/// during the consent step (authnz-rs only sees the resulting `code`).
#[allow(dead_code)]
pub const PATREON_AUTHORIZE_URL: &str = "https://www.patreon.com/oauth2/authorize";

/// Patreon OAuth2 token endpoint
pub const PATREON_TOKEN_URL: &str = "https://www.patreon.com/api/oauth2/token";

/// Patreon API v2 identity endpoint (used to discover the linked Patreon user's
/// id and — for creators — their owned campaign).
pub const PATREON_IDENTITY_URL: &str = "https://www.patreon.com/api/oauth2/v2/identity";

/// Patreon API v2 campaign members endpoint (templated with `{campaign_id}`).
/// Used by membership materialization to read a creator's campaign roster
/// and resolve a consumer's `patron_status`/tiers.
pub const PATREON_CAMPAIGN_MEMBERS_URL_TEMPLATE: &str =
    "https://www.patreon.com/api/oauth2/v2/campaigns/{campaign_id}/members";

/// Patreon membership-materialization cache TTL in seconds (5 minutes).
///
/// Short enough that revocations propagate quickly, long enough that we don't
/// hammer Patreon on every token mint. The plan calls for ~5 min;
/// `verified_at`/`expires_at` are recorded in the cached materialization so a
/// stale cache after Patreon goes down can be detected and rejected.
pub const PATREON_CACHE_TTL_SECONDS: i64 = 300;
