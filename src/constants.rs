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
