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

// Agent delegation constants

/// Agent NTDF token lifetime in days
pub const AGENT_TOKEN_DAYS: i64 = 30;

/// Agent challenge TTL in seconds (1 minute)
pub const AGENT_CHALLENGE_TTL_SECONDS: i64 = 60;

/// Maximum delegation depth (human -> agent1 -> agent2 -> ... -> agent5)
pub const MAX_DELEGATION_DEPTH: u8 = 5;

/// Maximum number of agents that can be delegated by a single root user
pub const MAX_AGENTS_PER_USER: u32 = 640;
