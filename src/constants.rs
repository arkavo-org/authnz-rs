/// Application constants for token lifetimes and session configuration
///
/// JWT registration token lifetime in weeks (~99 years)
///
/// SECURITY: Very long-lived tokens are intentional design choice.
/// Security model relies on WebAuthn passkey validation, not token expiration.
/// The passkey ceremony provides replay protection and strong authentication.
pub const REGISTRATION_TOKEN_WEEKS: i64 = 5148;

/// JWT authentication token lifetime in hours
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
