use crate::AppState;
use crate::authn::WebauthnError::{
    CorruptSession, InvalidSessionState, MissingToken, Unknown, UserHasNoCredentials, UserNotFound,
};
use crate::constants::{
    AUTH_TOKEN_HOURS, ENROLLMENT_TOKEN_MAX_AGE_SECONDS, REGISTRATION_TOKEN_WEEKS,
    RESERVED_USERNAME_PREFIXES,
};
use crate::db::DynamoDBError;
use axum::extract::Query;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::Response;
use axum::{
    extract::{Extension, Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use ecdsa::Signature;
use ecdsa::signature::Signer;
use log::{error, info, warn};
use p256::NistP256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tower_sessions::Session;
use uuid::Uuid;
use webauthn_rs::prelude::*;

const SESSION_REG_STATE_KEY: &str = "reg_state";

/// `idp` claim value for every WebAuthn-minted CWT. Matches
/// `oidc::idp_from_subject` for an `arkavo:<uuid>` subject.
const IDP_WEBAUTHN: &str = "webauthn";

#[derive(Deserialize)]
pub struct RegisterParams {
    pub handle: String,
    pub did: String,
}

/// ATProto-handle-safe username validation. The username becomes the leftmost
/// label of the `<username>.arkavo.social` handle and flows into the derived
/// did:web id, the `at://` URI, and the prod-handles key — so it must be a valid
/// ATProto handle label: 1–63 chars of **lowercase** ASCII alphanumerics and
/// internal hyphens, no leading/trailing hyphen. Lowercase-only matches ATProto
/// (handles are case-insensitive, normalized to lowercase) and removes the
/// `Alice` vs `alice` case-folding collision on the shared handle key. Blocks
/// `.`, `:`, `/`, `#`, whitespace, uppercase, control, and non-ASCII.
fn is_valid_username(username: &str) -> bool {
    let len = username.len();
    if len == 0 || len > 63 {
        return false;
    }
    let bytes = username.as_bytes();
    if bytes[0] == b'-' || bytes[len - 1] == b'-' {
        return false;
    }
    username
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Is this username in the namespace reserved for IdP-provisioned rows?
///
/// See [`RESERVED_USERNAME_PREFIXES`] — those rows carry zero WebAuthn
/// credentials, which would otherwise satisfy `start_register`'s
/// zero-credential exemption.
fn is_reserved_username(username: &str) -> bool {
    RESERVED_USERNAME_PREFIXES
        .iter()
        .any(|prefix| username.starts_with(prefix))
}

/// Was the presented account token minted recently enough to authorize adding
/// a passkey to an account that already has one?
///
/// `iat` in the future beyond the CWT skew allowance is treated as stale
/// rather than fresh — `cwt::verify` already enforces the skew, so anything
/// left over is not a clock difference we should extend trust to.
fn is_fresh_enough_to_enroll(iat: i64, now: i64) -> bool {
    let age = now - iat;
    (-crate::cwt::DEFAULT_SKEW_SECS..=ENROLLMENT_TOKEN_MAX_AGE_SECONDS).contains(&age)
}

/// Enrollment freshness is only meaningful if it is stricter than the auth
/// token's own lifetime — otherwise "freshly minted" and "not yet expired"
/// would be the same test.
const _: () = assert!(ENROLLMENT_TOKEN_MAX_AGE_SECONDS < AUTH_TOKEN_HOURS * 3600);

pub async fn start_register(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Path(username): Path<String>,
    Query(params): Query<RegisterParams>, // Add query params
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Start register for user: {}", username);

    // Hardening: constrain the username to an ATProto-handle-safe DNS label
    // before it flows into the derived did:web id, `at://` handle, and the
    // prod-handles key.
    if !is_valid_username(&username) {
        return Err(WebauthnError::InvalidUsername(
            "must be 1-63 chars of [a-z0-9-] (lowercase) with no leading/trailing hyphen"
                .to_string(),
        ));
    }

    // SECURITY: the `apple-` / `google-` namespace belongs to IdP-provisioned
    // rows, which exist with zero WebAuthn credentials. Registering into it
    // would hit the zero-credential exemption below and graft a passkey onto a
    // federated account, so refuse before any lookup happens.
    if is_reserved_username(&username) {
        warn!(
            "Rejected registration for reserved IdP username namespace: {}",
            username
        );
        return Err(WebauthnError::ReservedUsername);
    }

    // Validate DID format
    if !params.did.starts_with("did:key:") {
        return Err(WebauthnError::InvalidDID(
            "DID must start with 'did:key:'".to_string(),
        ));
    }
    // Validate username starts with handle
    if !params.handle.starts_with(&username) {
        return Err(WebauthnError::InvalidHandle);
    }

    // Add retry logic for the initial user query
    let mut retry_count = 0;
    let max_retries = 3;
    let user = loop {
        match app_state.db_store.get_user_by_name(&username).await {
            Ok(Some(existing_user)) => {
                info!("Found existing user: {}", username);
                break existing_user;
            }
            Ok(None) => {
                info!("User not found, creating new user: {}", username);
                match app_state.db_store.create_user(&username, &params.did).await {
                    Ok(new_user) => break new_user,
                    Err(err) => {
                        error!("Failed to create user {}: {:?}", username, err);
                        return Err(WebauthnError::UserCreationFailed(err.to_string()));
                    }
                }
            }
            Err(err) => {
                error!(
                    "Database error for {} (attempt {}): {:?}",
                    username,
                    retry_count + 1,
                    err
                );
                if retry_count < max_retries {
                    retry_count += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(
                        500 * (retry_count as u64),
                    ))
                    .await;
                    continue;
                }
                return Err(WebauthnError::DynamoDBOperationError(Box::new(err)));
            }
        }
    };

    // SECURITY: WebAuthn registration is unauthenticated, and start_register
    // reuses an existing user record when the username already exists. Adding a
    // passkey to an account that ALREADY has credentials therefore requires
    // proof of control of that account (a valid CWT for this user_id) —
    // otherwise an unauthenticated caller could graft their own passkey onto an
    // existing user and (under webvh) repoint that user's handle -> DID. A user
    // with zero credentials (initial registration, possibly retried) may still
    // finish without a token.
    if !user.credentials.is_empty() {
        let token_str = headers
            .get("X-Auth-Token")
            .and_then(|h| h.to_str().ok())
            .ok_or(WebauthnError::AccountExistsAuthRequired)?;
        let claims = verify_inbound_account_token(&app_state, token_str)?;
        let tid =
            Uuid::parse_str(&claims.sub).map_err(|_| WebauthnError::AccountExistsAuthRequired)?;
        if tid != user.user_id {
            return Err(WebauthnError::AccountExistsAuthRequired);
        }
        // SECURITY: possession of a still-valid token is not proof of *current*
        // control. Registration tokens live ~99 years, so a single captured
        // token would otherwise authorize passkey enrollment forever. Demand a
        // recently minted one: `POST /authenticate` mints from a WebAuthn
        // ceremony against an existing passkey, which is the fresh proof this
        // operation actually needs.
        if !is_fresh_enough_to_enroll(claims.iat, chrono::Utc::now().timestamp()) {
            warn!(
                "Rejected passkey enrollment for {}: token iat {} is older than {}s",
                username, claims.iat, ENROLLMENT_TOKEN_MAX_AGE_SECONDS
            );
            return Err(WebauthnError::StaleAuthentication);
        }
    }

    // Clean up existing session state
    if let Err(err) = session.remove_value(SESSION_REG_STATE_KEY).await {
        error!("Failed to remove old registration state: {:?}", err);
        return Err(WebauthnError::InvalidSessionState(err));
    }

    // Set up WebAuthn registration
    let exclude_credentials = if !user.credentials.is_empty() {
        Some(
            user.credentials
                .iter()
                .map(|c| c.cred_id().clone())
                .collect(),
        )
    } else {
        None
    };

    match app_state.webauthn.start_passkey_registration(
        user.user_id,
        &username,
        &username,
        exclude_credentials,
    ) {
        Ok((ccr, reg_state)) => {
            if let Err(err) = session
                .insert(
                    SESSION_REG_STATE_KEY,
                    (username.clone(), user.user_id, reg_state),
                )
                .await
            {
                error!("Failed to save registration state: {:?}", err);
                return Err(WebauthnError::InvalidSessionState(err));
            }
            info!("Registration started successfully for: {}", username);
            Ok(Json(ccr))
        }
        Err(err) => {
            error!("WebAuthn registration failed for {}: {:?}", username, err);
            Err(WebauthnError::Unknown)
        }
    }
}

pub async fn finish_register(
    Extension(app_state): Extension<AppState>,
    Extension(patreon): Extension<crate::patreon::PatreonState>,
    session: Session,
    Json(registration_credential): Json<RegisterPublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {
    let (username, user_id, reg_state): (String, Uuid, PasskeyRegistration) =
        session.get(SESSION_REG_STATE_KEY).await?.ok_or_else(|| {
            error!("No registration state found in session");
            CorruptSession
        })?;

    info!(
        "Finishing registration for user: {} ({})",
        username, user_id
    );

    // Clean up session immediately to prevent reuse
    if let Err(e) = session.remove_value(SESSION_REG_STATE_KEY).await {
        error!("Failed to remove registration state from session: {}", e);
        return Err(WebauthnError::SessionError(e.to_string()));
    }

    // Finish WebAuthn registration
    match app_state
        .webauthn
        .finish_passkey_registration(&registration_credential, &reg_state)
    {
        Ok(passkey) => {
            info!(
                "WebAuthn registration successful for user: {}. Adding credential to database...",
                username
            );

            // Store the credential in DynamoDB
            match app_state
                .db_store
                .add_credential(user_id, passkey.clone())
                .await
            {
                Ok(_) => {
                    info!("Successfully stored credential for user: {}", username);
                }
                Err(e) => {
                    error!("Failed to store credential: {}", e);
                    return Err(WebauthnError::DynamoDBOperationError(Box::new(e)));
                }
            }

            // Generate account token (CWT, ~99-year registration token)
            // SECURITY: Long-lived registration token (~99 years) is intentional.
            // Security relies on WebAuthn passkey validation, not token expiration.
            // The passkey ceremony provides replay protection and strong authentication.
            let cnf = crate::cwt::cnf_from_passkey(&passkey)?;

            // Create envelope (signs over a minimal payload for legacy native clients)
            let credential_id = Base64UrlSafeData::from(passkey.cred_id().to_vec());
            let envelope_payload = EnvelopePayload {
                user_unique_id: user_id,
                credential_id,
            };
            let envelope = AttestationEnvelope::new(envelope_payload, &app_state);

            // The account token carries the same Arkavo custom claims as the
            // auth token: a just-registered client holds only this token and
            // has no reason to call `POST /authenticate`, so without them
            // every KAS rewrap fails with `missing authn idP clientID`.
            //
            // Unlike `finish_authentication` this does NOT fail closed. The
            // credential is already stored, so a hard failure here would hand
            // back no token at all — and `start_register` then demands an
            // `X-Auth-Token` for the now-non-empty credential list, locking
            // the user out. A claims-less account token still works for
            // `POST /authenticate`, which mints a fully-claimed auth token.
            let arkavo_user = match app_state.db_store.get_user_by_id(&user_id).await {
                Ok(Some(record)) => {
                    let user = crate::oidc::AuthenticatedUser::webauthn(
                        record.user_id,
                        record.entitlements,
                    );
                    Some(crate::oidc::arkavo_user_claims(&app_state, &patreon, &user).await)
                }
                Ok(None) => {
                    error!(
                        "User row for {} vanished after credential write; minting account token \
                         without arkavo claims",
                        user_id
                    );
                    None
                }
                Err(e) => {
                    error!(
                        "Failed to read user row for {} after credential write: {}; minting \
                         account token without arkavo claims",
                        user_id, e
                    );
                    None
                }
            };

            let token = mint_registration_token(&app_state, &user_id, arkavo_user.as_ref(), cnf)?;

            // did:webvh passport: build (and, with the `webvh` feature + a KMS
            // signer, sign + persist) the DID log for this passkey. Non-fatal —
            // a webvh failure must never break WebAuthn registration.
            crate::webvh::on_passkey_registered(&app_state, &user_id, &username, &passkey).await;

            // Create response with token in header
            let mut response = Json(envelope).into_response();
            match HeaderValue::from_str(&token) {
                Ok(header_value) => {
                    response.headers_mut().insert("X-Auth-Token", header_value);
                    Ok(response)
                }
                Err(e) => {
                    error!("Failed to create header value from token: {}", e);
                    Err(MissingToken)
                }
            }
        }
        Err(error) => {
            error!("WebAuthn registration failed for {}: {:?}", username, error);
            Err(WebauthnError::WebAuthnError(error.to_string()))
        }
    }
}

pub async fn start_authentication(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Start Authentication");

    if let Err(err) = session.remove_value("auth_state").await {
        error!("Failed to remove old auth_state from session: {:?}", err);
        return Err(WebauthnError::InvalidSessionState(err));
    }

    // Verify inbound CWT account token from X-Auth-Token header (optional).
    // If present, validate it; legacy JWT tokens will be rejected with a CWT error.
    let inbound_user_id: Option<Uuid> = if let Some(token_header) = headers.get("X-Auth-Token") {
        let token_str = token_header
            .to_str()
            .map_err(|_| WebauthnError::InvalidToken)?;
        let claims = verify_inbound_account_token(&app_state, token_str)?;
        Some(Uuid::parse_str(&claims.sub).map_err(|_| WebauthnError::UserNotFound)?)
    } else {
        None
    };

    // Look up user from DB (authoritative source).
    let user = match app_state
        .db_store
        .get_user_by_name(&username)
        .await
        .map_err(|e| WebauthnError::DynamoDBOperationError(Box::new(e)))?
    {
        Some(user) => user,
        None => return Err(UserNotFound),
    };

    // If a token was provided, ensure it belongs to this user.
    if let Some(tid) = inbound_user_id {
        if tid != user.user_id {
            return Err(UserNotFound);
        }
    }

    // Credentials come exclusively from DB (authoritative).
    let credentials = if user.credentials.is_empty() {
        return Err(UserHasNoCredentials);
    } else {
        user.credentials.clone()
    };

    let res = match app_state
        .webauthn
        .start_passkey_authentication(&credentials)
    {
        Ok((rcr, auth_state)) => {
            if let Err(err) = session
                .insert("auth_state", (user.user_id, auth_state))
                .await
            {
                error!("Failed to insert auth_state into session: {:?}", err);
                return Err(WebauthnError::InvalidSessionState(err));
            }
            Json(rcr)
        }
        Err(e) => {
            error!("start_authentication -> {:?}", e);
            return Err(Unknown);
        }
    };
    Ok(res)
}

pub async fn finish_authentication(
    Extension(app_state): Extension<AppState>,
    Extension(patreon): Extension<crate::patreon::PatreonState>,
    session: Session,
    Json(auth): Json<PublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {
    let (user_unique_id, auth_state): (Uuid, PasskeyAuthentication) =
        session.get("auth_state").await?.ok_or(CorruptSession)?;

    // The auth token carries the same Arkavo custom claims as the OIDC access
    // token, derived from the same user record by the same helper
    // (`oidc::arkavo_user_claims`) — the OpenTDF platform resolves the caller
    // from `arkavo_account_id` / `arkavo_roles` and refuses a token without
    // them at KAS rewrap. A row that vanished fails closed rather than minting
    // a claims-less token.
    //
    // Read the record BEFORE consuming `auth_state`: a transient DynamoDB
    // error must not turn a successful WebAuthn ceremony into a failed login
    // that forces the client through the whole ceremony again. With the state
    // still in the session the client can simply retry this POST. The state is
    // still consumed exactly once per completed ceremony, below.
    let record = app_state
        .db_store
        .get_user_by_id(&user_unique_id)
        .await
        .map_err(|e| WebauthnError::DynamoDBOperationError(Box::new(e)))?
        .ok_or(UserNotFound)?;

    if let Err(err) = session.remove_value("auth_state").await {
        error!("Failed to remove auth_state from session: {:?}", err);
        return Err(WebauthnError::InvalidSessionState(err));
    }

    match app_state
        .webauthn
        .finish_passkey_authentication(&auth, &auth_state)
    {
        Ok(auth_result) => {
            log::debug!("Authentication result: {:?}", auth_result);
            let user =
                crate::oidc::AuthenticatedUser::webauthn(record.user_id, record.entitlements);
            let arkavo_user = crate::oidc::arkavo_user_claims(&app_state, &patreon, &user).await;
            // Generate CWT auth token (1-hour, no cnf binding at this point;
            // cnf binding is added in Task 15 once the passkey is retrieved from DB).
            let token = mint_auth_token(&app_state, &user_unique_id, Some(&arkavo_user), None)?;
            info!("Authentication successful for user: {}", user_unique_id);

            Ok((StatusCode::OK, Json(AuthResponse { token })))
        }
        Err(e) => {
            error!("finish_authentication -> {:?}", e);
            Ok((
                StatusCode::BAD_REQUEST,
                Json(AuthResponse {
                    token: String::new(),
                }),
            ))
        }
    }
}

#[derive(Serialize)]
struct AuthResponse {
    /// Arkavo-issued CWT (base64url-encoded COSE_Sign1 wrapped in CBOR tag 61).
    /// Field name is format-agnostic so clients don't conflate it with a JWT.
    token: String,
}

/// Minimal envelope payload — identifies the user and registered credential
/// but does NOT embed the full Passkey (DB is authoritative for credentials).
#[derive(Serialize, Deserialize, Clone, Debug)]
struct EnvelopePayload {
    user_unique_id: Uuid,
    credential_id: Base64UrlSafeData,
}

#[derive(Serialize, Deserialize)]
struct AttestationEnvelope {
    payload: EnvelopePayload,
    signature: Base64UrlSafeData,
}

impl AttestationEnvelope {
    fn new(entity: EnvelopePayload, app_state: &AppState) -> Self {
        // EnvelopePayload is `{ user_id: Uuid, public_key: Base64UrlSafeData }`,
        // both of which serialize to JSON unconditionally — this only fails on
        // OOM, which is unrecoverable anyway.
        let payload_bytes =
            serde_json::to_vec(&entity).expect("EnvelopePayload always serializes to JSON");
        let message = Sha256::digest(&payload_bytes);
        let signature: Signature<NistP256> = app_state.signing_key.sign(&message);

        Self {
            payload: entity,
            signature: Base64UrlSafeData::from(signature.to_der().as_bytes().to_vec()),
        }
    }
}

/// Mint the 1-hour WebAuthn auth CWT for `user_id`.
///
/// `arkavo_user` carries the per-user Arkavo custom claims
/// (`arkavo_account_id`, `arkavo_roles`, `arkavo_entitlements`,
/// `arkavo_patreon`) as derived by `oidc::arkavo_user_claims`, the same
/// helper the OIDC access token uses. `POST /authenticate` always passes
/// them; `None` (tests, callers with no record) mints a token with only the
/// registered claims, which the OpenTDF platform will refuse at KAS rewrap.
pub fn mint_auth_token(
    app_state: &AppState,
    user_id: &Uuid,
    arkavo_user: Option<&crate::cwt::ArkavoUserClaims>,
    cnf: Option<crate::cwt::Cnf>,
) -> Result<String, WebauthnError> {
    let mut claims = crate::cwt::ArkavoClaims::auth(
        &app_state.issuer,
        &user_id.to_string(),
        AUTH_TOKEN_HOURS,
        app_state.platform_audience.as_deref(),
    )
    // This token is only ever minted by the WebAuthn ceremony, so the idp is
    // fixed. Set it for parity with the OIDC access token, which always
    // carries `idp` — a verifier keying on it must see the same shape from
    // either token.
    .with_idp(IDP_WEBAUTHN);
    if let Some(u) = arkavo_user {
        claims = claims.with_arkavo_user(u);
    }
    if let Some(c) = cnf {
        claims = claims.with_cnf(c);
    }
    let bytes = crate::cwt::mint(&claims, &app_state.cwt_signing_key, &app_state.cwt_kid)?;
    Ok(crate::cwt::encode_for_header(&bytes))
}

/// Mint the ~99-year WebAuthn account CWT for `user_id`.
///
/// `arkavo_user` carries the same per-user Arkavo custom claims as
/// [`mint_auth_token`]. A just-registered client holds *only* this token and
/// has no reason to run `POST /authenticate`, so omitting the claims here
/// would make every KAS rewrap fail with `missing authn idP clientID` until
/// the user happened to re-authenticate. `POST /register` always passes them;
/// `None` (tests) mints registered-claims-only.
pub fn mint_registration_token(
    app_state: &AppState,
    user_id: &Uuid,
    arkavo_user: Option<&crate::cwt::ArkavoUserClaims>,
    cnf: crate::cwt::Cnf,
) -> Result<String, WebauthnError> {
    let mut claims = crate::cwt::ArkavoClaims::registration(
        &app_state.issuer,
        &user_id.to_string(),
        REGISTRATION_TOKEN_WEEKS,
    )
    .with_idp(IDP_WEBAUTHN)
    .with_cnf(cnf);
    if let Some(u) = arkavo_user {
        claims = claims.with_arkavo_user(u);
    }
    let bytes = crate::cwt::mint(&claims, &app_state.cwt_signing_key, &app_state.cwt_kid)?;
    Ok(crate::cwt::encode_for_header(&bytes))
}

pub fn verify_inbound_account_token(
    app_state: &AppState,
    token: &str,
) -> Result<crate::cwt::ArkavoClaims, WebauthnError> {
    let bytes = crate::cwt::decode_from_header(token)?;
    let opts = crate::cwt::VerifyOptions {
        expected_iss: Some(&app_state.issuer),
        expected_aud: Some("arkavo"),
        now: chrono::Utc::now().timestamp(),
        skew_secs: crate::cwt::DEFAULT_SKEW_SECS,
    };
    Ok(crate::cwt::verify(
        &bytes,
        &app_state.cwt_verifying_key,
        &opts,
    )?)
}

#[derive(Error, Debug)]
pub enum WebauthnError {
    #[error("unknown webauthn error")]
    Unknown,
    #[error("Corrupt Session")]
    CorruptSession,
    #[error("User Not Found")]
    UserNotFound,
    #[error("User Has No Credentials")]
    UserHasNoCredentials,
    #[error("Deserializing Session failed: {0}")]
    InvalidSessionState(#[from] tower_sessions::session::Error),
    #[error("Missing token")]
    MissingToken,
    #[error("Invalid token")]
    InvalidToken,
    #[error("DynamoDB operation failed: {0}")]
    DynamoDBOperationError(#[from] Box<crate::db::DynamoDBError>),
    #[error("Invalid username format")]
    InvalidHandle,
    #[error("Failed to create user: {0}")]
    UserCreationFailed(String),
    #[error("WebAuthn operation failed: {0}")]
    WebAuthnError(String),
    #[error("Session operation failed: {0}")]
    SessionError(String),
    #[error("Invalid DID format: {0}")]
    InvalidDID(String),
    #[error("CWT error: {0}")]
    Cwt(#[from] crate::cwt::CwtError),
    #[error("account exists; adding a passkey requires authentication")]
    AccountExistsAuthRequired,
    #[error("invalid username: {0}")]
    InvalidUsername(String),
    #[error("username is reserved for federated identities")]
    ReservedUsername,
    #[error("authentication is too old; re-authenticate to add a passkey")]
    StaleAuthentication,
}

impl IntoResponse for WebauthnError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            CorruptSession => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Corrupt Session".to_string(),
            ),
            UserNotFound => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "User Not Found".to_string(),
            ),
            Unknown => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unknown Error".to_string(),
            ),
            UserHasNoCredentials => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "User Has No Credentials".to_string(),
            ),
            InvalidSessionState(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Deserializing Session failed".to_string(),
            ),
            MissingToken => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Missing token".to_string(),
            ),
            WebauthnError::InvalidToken => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid token".to_string(),
            ),
            WebauthnError::DynamoDBOperationError(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                match *err {
                    DynamoDBError::TableNotExists(table) => {
                        format!("Service setup incomplete: {} table not configured", table)
                    }
                    _ => format!("Database operation failed: {}", err),
                },
            ),
            WebauthnError::InvalidHandle => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Handle must start with the username".to_string(),
            ),
            WebauthnError::UserCreationFailed(reason) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create user: {}", reason),
            ),
            WebauthnError::WebAuthnError(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("WebAuthn operation failed: {}", err),
            ),
            WebauthnError::SessionError(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Session operation failed: {}", err),
            ),
            WebauthnError::InvalidDID(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid DID format: {}", err),
            ),
            WebauthnError::Cwt(err) => (StatusCode::UNAUTHORIZED, format!("CWT error: {}", err)),
            WebauthnError::AccountExistsAuthRequired => (
                StatusCode::UNAUTHORIZED,
                "Account exists; authenticate (X-Auth-Token) to add a passkey".to_string(),
            ),
            WebauthnError::InvalidUsername(msg) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid username: {}", msg),
            ),
            WebauthnError::ReservedUsername => (
                StatusCode::FORBIDDEN,
                "Username is reserved for federated identities".to_string(),
            ),
            WebauthnError::StaleAuthentication => (
                StatusCode::UNAUTHORIZED,
                "Authentication is too old; re-authenticate (POST /authenticate) to add a passkey"
                    .to_string(),
            ),
        };
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_charset_allow_list() {
        // Valid ATProto-handle-safe labels
        assert!(is_valid_username("alice"));
        assert!(is_valid_username("alice-bob"));
        assert!(is_valid_username("a1b2c3"));
        assert!(is_valid_username("apple-001234"));
        // Rejects injection / structural hazards that would corrupt the
        // derived did:web id, at:// URI, or handle key
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("-alice"));
        assert!(!is_valid_username("alice-"));
        assert!(!is_valid_username("alice.bob")); // '.' label separator
        assert!(!is_valid_username("a/b")); // path separator
        assert!(!is_valid_username("a:b")); // did method separator
        assert!(!is_valid_username("a#b"));
        assert!(!is_valid_username("alice bob")); // whitespace
        assert!(!is_valid_username("älice")); // non-ascii
        assert!(!is_valid_username("Alice")); // uppercase (ATProto handles are lowercase)
        assert!(!is_valid_username("aliceBob")); // uppercase
        assert!(!is_valid_username(&"a".repeat(64))); // too long
    }

    #[test]
    fn test_reserved_username_namespace_is_rejected() {
        // IdP-provisioned rows (`apple-<sub>` / `google-<sub>`) carry zero
        // WebAuthn credentials, so registering into their namespace would hit
        // the zero-credential exemption in `start_register` and graft a passkey
        // onto a federated account.
        assert!(is_reserved_username("google-110248495921238986420"));
        assert!(is_reserved_username("apple-000123"));
        assert!(is_reserved_username("google-"));

        // Google subs are all-digits, so they clear the DNS-label validator —
        // which is exactly why the prefix check has to exist.
        assert!(is_valid_username("google-110248495921238986420"));

        // Ordinary usernames are untouched, including ones that merely
        // contain (but do not start with) a reserved word.
        assert!(!is_reserved_username("alice"));
        assert!(!is_reserved_username("googler"));
        assert!(!is_reserved_username("not-google-me"));
        assert!(!is_reserved_username("apple"));
    }

    #[test]
    fn test_enrollment_requires_a_freshly_minted_token() {
        let now = 1_700_000_000i64;

        // Just minted, and anywhere inside the window.
        assert!(is_fresh_enough_to_enroll(now, now));
        assert!(is_fresh_enough_to_enroll(
            now - ENROLLMENT_TOKEN_MAX_AGE_SECONDS,
            now
        ));

        // One second past the window, and the case that motivates the check:
        // a ~99-year registration token issued long ago is still *valid* but
        // is not proof of current control.
        assert!(!is_fresh_enough_to_enroll(
            now - ENROLLMENT_TOKEN_MAX_AGE_SECONDS - 1,
            now
        ));
        assert!(!is_fresh_enough_to_enroll(now - 86_400, now));

        // Clock skew is tolerated to the same bound `cwt::verify` uses; a
        // token dated further into the future is not treated as fresh.
        assert!(is_fresh_enough_to_enroll(
            now + crate::cwt::DEFAULT_SKEW_SECS,
            now
        ));
        assert!(!is_fresh_enough_to_enroll(
            now + crate::cwt::DEFAULT_SKEW_SECS + 1,
            now
        ));
    }

    #[test]
    fn test_stale_authentication_error_is_unauthorized() {
        let response = WebauthnError::StaleAuthentication.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_reserved_username_error_is_forbidden() {
        let response = WebauthnError::ReservedUsername.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_did_validation_logic() {
        // Valid DID formats
        assert!("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".starts_with("did:key:"));
        assert!("did:key:abc123".starts_with("did:key:"));

        // Invalid DID formats
        assert!(!"did:web:example.com".starts_with("did:key:"));
        assert!(!"key:z6Mk...".starts_with("did:key:"));
        assert!(!"did:".starts_with("did:key:"));
        assert!(!"".starts_with("did:key:"));
    }

    #[test]
    fn test_handle_username_validation() {
        let username = "alice";
        let valid_handle = "alice.arkavo.social";
        let invalid_handle = "bob.arkavo.social";

        assert!(valid_handle.starts_with(username));
        assert!(!invalid_handle.starts_with(username));
    }

    #[test]
    fn test_token_expiration_constants() {
        use crate::constants::{
            AUTH_TOKEN_HOURS, ENROLLMENT_TOKEN_MAX_AGE_SECONDS, REGISTRATION_TOKEN_WEEKS,
        };

        // Verify registration token is long-lived (~99 years = ~5148 weeks)
        assert_eq!(REGISTRATION_TOKEN_WEEKS, 5148);

        // Verify auth token is short-lived (1 hour)
        assert_eq!(AUTH_TOKEN_HOURS, 1);

        // Enrollment freshness must stay well under the auth token lifetime,
        // otherwise a token that merely hasn't expired would pass for fresh
        // proof of control.
        // The stricter-than-auth-lifetime relationship is asserted at compile
        // time next to `is_fresh_enough_to_enroll`.
        assert_eq!(ENROLLMENT_TOKEN_MAX_AGE_SECONDS, 300);
    }

    #[test]
    fn test_webauthn_error_responses() {
        let errors = vec![
            WebauthnError::CorruptSession,
            WebauthnError::UserNotFound,
            WebauthnError::UserHasNoCredentials,
            WebauthnError::MissingToken,
            WebauthnError::InvalidToken,
            WebauthnError::InvalidHandle,
            WebauthnError::InvalidDID("test".to_string()),
        ];

        for error in errors {
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    #[tokio::test]
    async fn auth_token_is_cose_sign1() {
        use coset::CborSerializable;
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
            std::env::set_var("AWS_ACCESS_KEY_ID", "fake_access_key");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "fake_secret_key");
        }
        let app_state = crate::test_helpers::build_test_app_state().await;
        let user_id = uuid::Uuid::new_v4();
        let token = mint_auth_token(&app_state, &user_id, None, None).expect("mint");
        let raw = crate::cwt::decode_from_header(&token).expect("decode header");
        let inner = crate::cwt::strip_cwt_tag(&raw).expect("CWT tag");
        let sign1 = coset::CoseSign1::from_slice(inner).expect("parse COSE_Sign1");
        assert_eq!(
            sign1.protected.header.alg,
            Some(coset::Algorithm::Assigned(coset::iana::Algorithm::ES256))
        );
    }

    #[tokio::test]
    async fn registration_token_is_cose_sign1_with_cnf() {
        use coset::CborSerializable;
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        }

        let app_state = crate::test_helpers::build_test_app_state().await;
        let user_id = uuid::Uuid::new_v4();

        // Build a sample Cnf (cose_key + kid)
        let scalar = p256::FieldBytes::from([0x77u8; 32]);
        let secret = p256::SecretKey::from_bytes(&scalar).expect("scalar");
        let vk: p256::ecdsa::VerifyingKey = *p256::ecdsa::SigningKey::from(&secret).verifying_key();
        let cose_key = crate::cwt::cose_key_from_p256_verifying_key(&vk, b"cred-1");
        let cnf = crate::cwt::Cnf {
            cose_key,
            kid: b"cred-1".to_vec(),
        };

        let token = mint_registration_token(&app_state, &user_id, None, cnf).expect("mint");
        let raw = crate::cwt::decode_from_header(&token).unwrap();
        let inner = crate::cwt::strip_cwt_tag(&raw).expect("CWT tag");
        let sign1 = coset::CoseSign1::from_slice(inner).unwrap();
        let payload = sign1.payload.unwrap();
        let claims = crate::cwt::claims_from_cbor(&payload).unwrap();
        assert!(claims.cnf.is_some());

        // Registration tokens have very long exp (~99 years).
        let now = chrono::Utc::now().timestamp();
        let years_50 = 50 * 365 * 24 * 3600;
        assert!(claims.exp - now > years_50);
    }

    #[tokio::test]
    async fn inbound_legacy_jwt_rejected_in_start_authentication_decode() {
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        }

        let app_state = crate::test_helpers::build_test_app_state().await;

        // Construct a legacy JWT (will be rejected since we now require CWT).
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        #[derive(serde::Serialize)]
        struct LegacyClaims {
            sub: String,
            exp: usize,
        }
        let claims = LegacyClaims {
            sub: uuid::Uuid::new_v4().to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
        };
        let jwt = jsonwebtoken::encode(&header, &claims, &app_state.encoding_key).unwrap();

        // The inbound parser should reject JWT-format tokens (not valid base64url COSE_Sign1).
        let result = verify_inbound_account_token(&app_state, &jwt);
        assert!(
            matches!(result, Err(WebauthnError::Cwt(_))),
            "got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn inbound_cwt_accepted_in_start_authentication_decode() {
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        }

        let app_state = crate::test_helpers::build_test_app_state().await;
        let user_id = uuid::Uuid::new_v4();
        let token = mint_auth_token(&app_state, &user_id, None, None).expect("mint");
        let claims = verify_inbound_account_token(&app_state, &token).expect("verify");
        assert_eq!(claims.sub, user_id.to_string());
    }

    fn decode_claims(token: &str) -> crate::cwt::ArkavoClaims {
        use coset::CborSerializable;
        let raw = crate::cwt::decode_from_header(token).expect("decode header");
        let inner = crate::cwt::strip_cwt_tag(&raw).expect("CWT tag");
        let sign1 = coset::CoseSign1::from_slice(inner).expect("parse COSE_Sign1");
        crate::cwt::claims_from_cbor(sign1.payload.as_ref().expect("payload")).expect("claims")
    }

    fn sample_patreon() -> crate::cwt::ArkavoPatreon {
        crate::cwt::ArkavoPatreon {
            role: "consumer".into(),
            patreon_user_id: "patreon-user-42".into(),
            campaign_id: None,
            memberships: vec![crate::cwt::ArkavoPatreonMembership {
                campaign_id: "camp-1".into(),
                patron_status: Some("active_patron".into()),
                tier_ids: vec!["tier-gold".into()],
                tier_slugs: vec!["gold".into()],
            }],
            verified_at: 1_700_000_000,
            cache_expires_at: 1_700_000_300,
        }
    }

    /// The WebAuthn auth CWT must carry the same Arkavo custom claims as the
    /// OIDC access token for the same user record. The OpenTDF platform is
    /// configured with `client_id_claim: arkavo_account_id` and
    /// `groups_claim: arkavo_roles`, and its Patreon entity resolver reads
    /// `arkavo_patreon`; a token without them is rejected at every KAS rewrap
    /// ("missing authn idP clientID").
    #[tokio::test]
    async fn auth_token_carries_arkavo_custom_claims_like_the_access_token() {
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        }
        let app_state = crate::test_helpers::build_test_app_state().await;
        let user_id = uuid::Uuid::new_v4();
        let user = crate::cwt::ArkavoUserClaims {
            account_id: user_id.to_string(),
            roles: vec!["user".into()],
            entitlements: vec![
                "https://arkavo.ai/attr/tdf/value/create".into(),
                "https://arkavo.ai/attr/tdf/value/decrypt".into(),
            ],
            patreon: Some(sample_patreon()),
        };

        let auth = decode_claims(
            &mint_auth_token(&app_state, &user_id, Some(&user), None).expect("mint auth"),
        );
        let access = decode_claims(
            &crate::oidc::mint_access_token(
                &app_state,
                &format!("arkavo:{}", user_id),
                "opentdf",
                Some(crate::oidc::AccessTokenExtras {
                    idp: "webauthn".into(),
                    arkavo_user: Some(user.clone()),
                    ..Default::default()
                }),
                None,
            )
            .expect("mint access"),
        );

        assert_eq!(auth.sub, user_id.to_string());
        assert_eq!(
            auth.custom.arkavo_account_id.as_deref(),
            Some(user_id.to_string().as_str())
        );
        assert!(auth.custom.arkavo_roles.is_some());
        assert!(auth.custom.arkavo_entitlements.is_some());
        assert!(auth.custom.arkavo_patreon.is_some());
        assert_eq!(
            auth.custom.arkavo_account_id,
            access.custom.arkavo_account_id
        );
        assert_eq!(auth.custom.arkavo_roles, access.custom.arkavo_roles);
        assert_eq!(
            auth.custom.arkavo_entitlements,
            access.custom.arkavo_entitlements
        );
        assert_eq!(auth.custom.arkavo_patreon, access.custom.arkavo_patreon);
        // `idp` too — the access token always carries it, so a verifier that
        // keys on it must see the same value from the auth token.
        assert_eq!(auth.custom.idp.as_deref(), Some(IDP_WEBAUTHN));
        assert_eq!(auth.custom.idp, access.custom.idp);

        // Registered claims are untouched: still the 1-hour "arkavo" auth token.
        assert_eq!(auth.aud, crate::cwt::Audience::Single("arkavo".into()));
        assert_eq!(auth.exp - auth.iat, AUTH_TOKEN_HOURS * 3600);
        assert!(auth.cnf.is_none());
    }

    /// The ~99-year account token minted by `POST /register` must carry the
    /// same claims. A just-registered client holds only this token and has no
    /// reason to call `POST /authenticate`, so without them every KAS rewrap
    /// fails with "missing authn idP clientID".
    #[tokio::test]
    async fn registration_token_carries_arkavo_custom_claims() {
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        }
        let app_state = crate::test_helpers::build_test_app_state().await;
        let user_id = uuid::Uuid::new_v4();
        let cnf = crate::cwt::cnf_from_ed25519(&[9u8; 32], b"kid");
        let user = crate::cwt::ArkavoUserClaims {
            account_id: user_id.to_string(),
            roles: vec!["user".into()],
            entitlements: vec!["https://arkavo.ai/attr/tdf/value/decrypt".into()],
            patreon: Some(sample_patreon()),
        };

        let claims = decode_claims(
            &mint_registration_token(&app_state, &user_id, Some(&user), cnf).expect("mint"),
        );
        assert_eq!(
            claims.custom.arkavo_account_id.as_deref(),
            Some(user_id.to_string().as_str())
        );
        assert_eq!(claims.custom.arkavo_roles, Some(vec!["user".to_string()]));
        assert_eq!(
            claims.custom.arkavo_entitlements,
            Some(vec!["https://arkavo.ai/attr/tdf/value/decrypt".to_string()])
        );
        assert_eq!(claims.custom.arkavo_patreon, Some(sample_patreon()));
        assert_eq!(claims.custom.idp.as_deref(), Some(IDP_WEBAUTHN));

        // Registered claims are untouched: still the long-lived "arkavo" token.
        assert_eq!(claims.aud, crate::cwt::Audience::Single("arkavo".into()));
        assert!(claims.cnf.is_some());
        let years_50 = 50 * 365 * 24 * 3600;
        assert!(claims.exp - chrono::Utc::now().timestamp() > years_50);
    }

    /// Callers without a user record (tests, diagnostics) still get the bare
    /// token, so the Arkavo custom claims are simply absent.
    #[tokio::test]
    async fn auth_token_without_user_record_omits_arkavo_custom_claims() {
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        }
        let app_state = crate::test_helpers::build_test_app_state().await;
        let user_id = uuid::Uuid::new_v4();
        let claims =
            decode_claims(&mint_auth_token(&app_state, &user_id, None, None).expect("mint"));
        assert!(claims.custom.arkavo_account_id.is_none());
        assert!(claims.custom.arkavo_roles.is_none());
        assert!(claims.custom.arkavo_entitlements.is_none());
        assert!(claims.custom.arkavo_patreon.is_none());
    }
}
