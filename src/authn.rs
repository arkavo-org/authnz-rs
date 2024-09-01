use crate::authn::WebauthnError::{CorruptSession, Unknown, UserHasNoCredentials, UserNotFound};
use crate::AppState;
use axum::response::Response;
use axum::{
    extract::{Extension, Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use ecdsa::signature::{Signer, Verifier};
use ecdsa::{Signature, VerifyingKey};
use log::{error, info};
use p256::NistP256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tower_sessions::Session;
use uuid::Uuid;
use webauthn_rs::prelude::*;

/*
 * Webauthn RS auth handlers.
 * These files use webauthn to process the data received from each route, and are closely tied to axum
 */

// 2. The first step a client (user) will carry out is requesting a credential to be
// registered. We need to provide a challenge for this. The work flow will be:
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Reg     │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │  4. Yield PubKey    │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │                      │
//                  │                     │  5. Send Reg Opts    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │         PubKey
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │─ ─ ─
//                  │                     │                      │     │ 6. Persist
//                  │                     │                      │       Credential
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// In this step, we are responding to the start reg(istration) request, and providing
// the challenge to the browser.

pub async fn start_register(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Start register");
    // We get the username from the URL, but you could get this via form submission or
    // some other process. In some parts of Webauthn, you could also use this as a "display name"
    // instead of a username. Generally you should consider that the user *can* and *will* change
    // their username at any time.

    // Since a user's username could change at anytime, we need to bind to a unique id.
    // We use uuid's for this purpose, and you should generate these randomly. If the
    // username does exist and is found, we can match back to our unique id. This is
    // important in authentication, where presented credentials may *only* provide
    // the unique id, and not the username!

    let user_unique_id = {
        let users_guard = app_state.accounts.lock().await;
        users_guard
            .name_to_id
            .get(&username)
            .copied()
            .unwrap_or_else(Uuid::new_v4)
    };

    // Remove any previous registrations that may have occurred from the session.
    // assumption no need to wait or check a failure
    session
        .remove_value("reg_state")
        .await
        .expect("auth_state removal failed");

    // If the user has any other credentials, we exclude these here, so they can't be duplicate registered.
    // It also hints to the browser that only new credentials should be "blinked" for interaction.
    let exclude_credentials = {
        let users_guard = app_state.accounts.lock().await;
        users_guard
            .keys
            .get(&user_unique_id)
            .map(|keys| keys.iter().map(|sk| sk.cred_id().clone()).collect())
    };

    let res = match app_state.webauthn.start_passkey_registration(
        user_unique_id,
        &username,
        &username,
        exclude_credentials,
    ) {
        Ok((ccr, reg_state)) => {
            // Note that due to the session store in use being a server side memory store, this is
            // safe to store the reg_state into the session since it is not client controlled and
            // not open to replay attacks. If this was a cookie store, this would be UNSAFE.
            session
                .insert("reg_state", (username, user_unique_id, reg_state))
                .await
                .expect("Failed to insert");
            info!("Registration Successful!");
            Json(ccr)
        }
        Err(e) => {
            info!("challenge_register -> {:?}", e);
            return Err(Unknown);
        }
    };
    Ok(res)
}

// 3. The browser has completed its steps and the user has created a public key
// on their device. Now we have the registration options sent to us, and we need
// to verify these and persist them.

#[derive(Serialize, Deserialize)]
struct AttestationEntity {
    user_unique_id: Uuid,
    credential_id: Base64UrlSafeData,
}

#[derive(Serialize, Deserialize)]
struct AttestationEnvelope {
    payload: AttestationEntity,
    signature: Base64UrlSafeData,
}

impl AttestationEnvelope {
    fn new(entity: AttestationEntity, app_state: &AppState) -> Self {
        let payload_bytes = serde_json::to_vec(&entity).unwrap();
        let message = Sha256::digest(&payload_bytes);
        let signature: Signature<NistP256> = app_state.signing_key.sign(&message);

        Self {
            payload: entity,
            signature: Base64UrlSafeData::from(signature.to_der().as_bytes().to_vec()),
        }
    }
    fn _verify(&self, verifying_key: &VerifyingKey<NistP256>) -> bool {
        let payload_bytes = serde_json::to_vec(&self.payload).unwrap();
        let message = Sha256::digest(&payload_bytes);
        let signature = Signature::from_der(self.signature.as_ref()).unwrap();

        verifying_key.verify(&message, &signature).is_ok()
    }
}
const SESSION_REG_STATE_KEY: &str = "reg_state";
pub async fn finish_register(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(registration_credential): Json<RegisterPublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {
    let (username, user_unique_id, reg_state) = match session.get(SESSION_REG_STATE_KEY).await? {
        Some((username, user_unique_id, reg_state)) => (username, user_unique_id, reg_state),
        None => {
            error!("Failed to get session");
            return Err(CorruptSession);
        }
    };
    session
        .remove_value(SESSION_REG_STATE_KEY)
        .await
        .expect("auth_state removal failed");
    let res = match app_state
        .webauthn
        .finish_passkey_registration(&registration_credential, &reg_state)
    {
        Ok(session_key) => {
            let mut users_guard = app_state.accounts.lock().await;
            // Store the credential in a database or persist in some other way.
            users_guard
                .keys
                .entry(user_unique_id)
                .and_modify(|keys| keys.push(session_key.clone()))
                .or_insert_with(|| vec![session_key.clone()]);
            users_guard.name_to_id.insert(username, user_unique_id);
            // Send back JSON response with the registration credential.
            let credential_id = Base64UrlSafeData::from(session_key.cred_id().to_vec());
            let attestation_entity = AttestationEntity {
                user_unique_id,
                credential_id,
            };
            let envelope = AttestationEnvelope::new(attestation_entity, &app_state);
            Json(envelope).into_response()
        }
        Err(error) => {
            error!("challenge_register -> {:?}", error);
            StatusCode::BAD_REQUEST.into_response()
        }
    };

    Ok(res)
}

// 4. Now that our public key has been registered, we can authenticate a user and verify
// that they are the holder of that security token. The work flow is similar to registration.
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Auth    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │    4. Yield Sig     │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │    5. Send Auth      │
//                  │                     │        Opts          │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │          Sig
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// The user indicates the wish to start authentication and we need to provide a challenge.

pub async fn start_authentication(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Start Authentication");
    // We get the username from the URL, but you could get this via form submission or
    // some other process.

    // Remove any previous authentication that may have occurred from the session.
    session
        .remove_value("auth_state")
        .await
        .expect("auth_state removal failed");

    // Get the set of keys that the user possesses
    let users_guard = app_state.accounts.lock().await;

    // Look up their unique id from the username
    let user_unique_id = users_guard
        .name_to_id
        .get(&username)
        .copied()
        .ok_or(UserNotFound)?;

    let allow_credentials = users_guard
        .keys
        .get(&user_unique_id)
        .ok_or(UserHasNoCredentials)?;

    let res = match app_state
        .webauthn
        .start_passkey_authentication(allow_credentials)
    {
        Ok((rcr, auth_state)) => {
            // Drop the mutex to allow the mut borrows below to proceed
            drop(users_guard);

            // Note that due to the session store in use being a server side memory store, this is
            // safe to store the auth_state into the session since it is not client controlled and
            // not open to replay attacks. If this was a cookie store, this would be UNSAFE.
            session
                .insert("auth_state", (user_unique_id, auth_state))
                .await
                .expect("Failed to insert");
            Json(rcr)
        }
        Err(e) => {
            info!("challenge_authenticate -> {:?}", e);
            return Err(Unknown);
        }
    };
    Ok(res)
}

// 5. The browser and user have completed their part of the processing. Only in the
// case that the webauthn authenticate call returns Ok, is authentication considered
// a success. If the browser does not complete this call, or *any* error occurs,
// this is an authentication failure.

pub async fn finish_authentication(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(auth): Json<PublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {
    let (user_unique_id, auth_state): (Uuid, PasskeyAuthentication) =
        session.get("auth_state").await?.ok_or(CorruptSession)?;

    session
        .remove_value("auth_state")
        .await
        .expect("auth_state removal failed");

    let res = match app_state
        .webauthn
        .finish_passkey_authentication(&auth, &auth_state)
    {
        Ok(auth_result) => {
            let mut users_guard = app_state.accounts.lock().await;

            // Update the credential counter, if possible.
            users_guard
                .keys
                .get_mut(&user_unique_id)
                .map(|keys| {
                    keys.iter_mut().for_each(|sk| {
                        // This will update the credential if it's the matching
                        // one. Otherwise it's ignored. That is why it is safe to
                        // iterate this over the full list.
                        sk.update_credential(&auth_result);
                    })
                })
                .ok_or(UserHasNoCredentials)?;
            StatusCode::OK
        }
        Err(e) => {
            info!("challenge_register -> {:?}", e);
            StatusCode::BAD_REQUEST
        }
    };
    info!("Authentication Successful!");
    Ok(res)
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
}
impl IntoResponse for WebauthnError {
    fn into_response(self) -> Response {
        let body = match self {
            CorruptSession => "Corrupt Session",
            UserNotFound => "User Not Found",
            Unknown => "Unknown Error",
            UserHasNoCredentials => "User Has No Credentials",
            WebauthnError::InvalidSessionState(_) => "Deserializing Session failed",
        };

        // its often easiest to implement `IntoResponse` by calling other implementations
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
