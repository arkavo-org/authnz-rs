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

/// Freshness window (seconds) for a device's last successful App Attest
/// assertion. Within this window since the last verified assertion, the
/// device is classed `attested`; once it expires the device is `managed`
/// (a binding exists but the hardware attestation is stale).
pub const DEVICE_ATTESTATION_TTL_SECONDS: i64 = 900;

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

/// Total HTTP timeout (seconds) for fetching Apple's JWKS. Bounds the
/// unauthenticated `/oauth/apple/*` and `idp=apple` paths so a stalled or
/// blackholed `appleid.apple.com` cannot hang inbound requests (a `kid`-miss
/// force-refresh makes the fetch attacker-triggerable). Override with the
/// `APPLE_JWKS_HTTP_TIMEOUT_SECS` env var.
pub const APPLE_JWKS_HTTP_TIMEOUT_SECS: u64 = 10;

/// Apple JWKS URL
pub const APPLE_JWKS_URL: &str = "https://appleid.apple.com/auth/keys";

/// Apple OIDC issuer (used to validate `iss` claim on Apple id_tokens)
pub const APPLE_ISSUER: &str = "https://appleid.apple.com";

/// Google JWKS cache TTL in seconds (1 hour).
pub const GOOGLE_JWKS_CACHE_TTL_SECONDS: i64 = 3600;

/// Total HTTP timeout (seconds) for Google's token and JWKS endpoints.
/// Override with the `GOOGLE_HTTP_TIMEOUT_SECS` env var.
pub const GOOGLE_HTTP_TIMEOUT_SECS: u64 = 10;

/// Google OAuth 2.0 authorization endpoint (browser is redirected here).
pub const GOOGLE_AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";

/// Google OAuth 2.0 token endpoint (server-side code exchange).
pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// Google JWKS URL (signing keys for Google id_tokens).
pub const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Accepted `iss` values on Google id_tokens. Google documents both forms.
pub const GOOGLE_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];

/// Lifetime (seconds) of a pending `idp=google` authorize request parked
/// while the browser is at Google (10 minutes).
pub const GOOGLE_PENDING_AUTHORIZE_TTL_SECONDS: i64 = 600;

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

/// TTL for the "this user has no Patreon link" marker. Without it every token
/// mint for every unlinked user costs a DynamoDB GetItem on the login critical
/// path, and unlinked users are the overwhelming majority. Kept short (and
/// cleared by `MembershipCache::invalidate`, which the link handler calls) so a
/// freshly linked user isn't held at "no membership" for long.
pub const PATREON_UNLINKED_CACHE_TTL_SECONDS: i64 = 60;

/// Wall-clock budget for Patreon materialization on a token-mint path. The
/// underlying work can be a DynamoDB read + KMS decrypt + token refresh POST +
/// retry fetch, each with its own 10s HTTP timeout, so an unbounded wait lets a
/// degraded Patreon stall a WebAuthn login past the client's own timeout. Past
/// this deadline the mint proceeds without the `arkavo_patreon` claim
/// (fail-closed), while the materialization itself runs to completion in the
/// background and warms the cache for the next mint.
pub const PATREON_MATERIALIZE_DEADLINE_SECONDS: u64 = 3;

// Agent delegation (PE → agent NPE) constants

/// Lifetime of a delegation record in days. A delegation outlives any single
/// agent token; the agent re-proves key possession to mint a fresh token.
pub const AGENT_DELEGATION_DAYS: i64 = 30;

/// Maximum lifetime, in minutes, of an agent NPE CWT minted via
/// [`crate::cwt::ArkavoClaims::agent`]. Agent tokens are short-lived by
/// design — the agent re-proves key possession (via `/agents/token`) to
/// mint a fresh one rather than holding a long-lived bearer.
pub const AGENT_TOKEN_MINUTES_MAX: i64 = 15;

/// Agent challenge TTL in seconds. The challenge is stored on the delegation
/// row (not a cookie session) so headless CLIs can complete the two-step flow.
pub const AGENT_CHALLENGE_TTL_SECONDS: i64 = 60;

/// Maximum delegation depth (human -> agent1 -> agent2 -> ... -> agent5)
pub const MAX_DELEGATION_DEPTH: u8 = 5;

/// Maximum number of active agents delegated by a single root user
pub const MAX_AGENTS_PER_USER: u32 = 640;

/// Attribute FQN for the "create a TDF" entitlement.
pub const ENTITLEMENT_TDF_CREATE: &str = "https://arkavo.ai/attr/tdf/value/create";

/// Attribute FQN for the "decrypt a TDF" entitlement.
pub const ENTITLEMENT_TDF_DECRYPT: &str = "https://arkavo.ai/attr/tdf/value/decrypt";

/// Entitlements granted to a newly created user and used when a stored user
/// row predates the `entitlements` attribute. Attribute FQNs, never bare
/// strings — the OpenTDF platform's `arkavo` ERS mode emits these verbatim
/// as direct entitlements.
pub const DEFAULT_USER_ENTITLEMENTS: &[&str] = &[
    ENTITLEMENT_TDF_CREATE,
    ENTITLEMENT_TDF_DECRYPT,
    // Delegable to agents (the vocabulary arkavo-edge's --trust QR and the
    // app's canonicalizer request). Must be a superset of the QR default.
    "https://arkavo.ai/attr/action/value/read",
    "https://arkavo.ai/attr/action/value/write",
    "https://arkavo.ai/attr/action/value/execute",
    "https://arkavo.ai/attr/action/value/delegate",
];

/// Username prefixes reserved for IdP-provisioned account rows.
///
/// SECURITY (load-bearing): `apple_signin::map_apple_user` and
/// `google_signin::map_google_user` provision accounts as
/// `apple-<sanitized_sub>` / `google-<sanitized_sub>` with an EMPTY
/// credential list. `authn::start_register` waives its `X-Auth-Token`
/// requirement for accounts that hold zero credentials (so an interrupted
/// first registration can be retried), which would otherwise let anyone who
/// knows the IdP `sub` — it is published as the OIDC `sub` in every
/// `id_token` — enroll their own passkey onto a federated account and
/// receive a registration token for it. These prefixes are therefore
/// rejected outright as registration usernames.
///
/// If the synthetic-username scheme in `apple_signin.rs` / `google_signin.rs`
/// ever changes, this list must change with it.
pub const RESERVED_USERNAME_PREFIXES: &[&str] = &["apple-", "google-"];

/// Maximum age (seconds) of the `X-Auth-Token` CWT accepted by
/// `authn::start_register` when adding a passkey to an account that already
/// has credentials.
///
/// SECURITY: enrollment is an account-takeover-grade operation, so it
/// requires *fresh* proof of control rather than any still-valid bearer
/// token — registration tokens live [`REGISTRATION_TOKEN_WEEKS`] (~99
/// years). A token minted moments ago by `POST /authenticate` (which needs a
/// WebAuthn ceremony against an existing passkey) passes; a long-lived
/// registration token captured at any point in the past does not.
pub const ENROLLMENT_TOKEN_MAX_AGE_SECONDS: i64 = 300;
