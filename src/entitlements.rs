//! Admin entitlement management (spec §2.3).
//!
//! `PUT /admin/users/:id/entitlements` replaces a user's attribute-FQN list.
//! Gated by a service CWT (`arkavo_roles` contains `service-account`), the
//! same credential class that runs `scripts/mint-pep-cwt.py`.

use crate::AppState;
use crate::cwt;
use axum::http::HeaderMap;
use axum::{
    extract::{Extension, Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use log::warn;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct PutEntitlementsRequest {
    pub entitlements: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PutEntitlementsResponse {
    pub user_id: Uuid,
    pub entitlements: Vec<String>,
}

/// Verify the `X-Auth-Token` CWT and require the service-account role.
/// Audience is not pinned: service CWTs carry `aud = client_id` (+ platform).
pub fn require_service_cwt(
    app_state: &AppState,
    headers: &HeaderMap,
) -> Result<cwt::ArkavoClaims, EntitlementError> {
    let token = headers
        .get("X-Auth-Token")
        .ok_or(EntitlementError::MissingToken)?
        .to_str()
        .map_err(|_| EntitlementError::InvalidToken)?;
    let bytes = cwt::decode_from_header(token).map_err(|_| EntitlementError::InvalidToken)?;
    let opts = cwt::VerifyOptions {
        expected_iss: Some(&app_state.issuer),
        expected_aud: None,
        now: Utc::now().timestamp(),
        skew_secs: cwt::DEFAULT_SKEW_SECS,
    };
    let claims = cwt::verify(&bytes, &app_state.cwt_verifying_key, &opts).map_err(|e| {
        warn!("Rejected admin token: {}", e);
        EntitlementError::InvalidToken
    })?;
    if !is_service_claims(&claims) {
        return Err(EntitlementError::Forbidden);
    }
    Ok(claims)
}

pub(crate) fn is_service_claims(claims: &cwt::ArkavoClaims) -> bool {
    claims
        .custom
        .arkavo_roles
        .as_ref()
        .is_some_and(|r| r.iter().any(|x| x == "service-account"))
}

/// Attribute FQN shape: `https://<host>/attr/<name>/value/<value>`.
pub(crate) fn validate_fqns(list: &[String]) -> Result<(), EntitlementError> {
    if list.is_empty() {
        return Err(EntitlementError::Empty);
    }
    for f in list {
        let ok = f.starts_with("https://")
            && f.matches("/attr/").count() == 1
            && f.matches("/value/").count() == 1
            && f.find("/attr/") < f.find("/value/");
        if !ok {
            return Err(EntitlementError::InvalidFqn(f.clone()));
        }
    }
    Ok(())
}

/// PUT /admin/users/:id/entitlements
pub async fn put_user_entitlements(
    Extension(app_state): Extension<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
    Json(req): Json<PutEntitlementsRequest>,
) -> Result<impl IntoResponse, EntitlementError> {
    require_service_cwt(&app_state, &headers)?;
    validate_fqns(&req.entitlements)?;
    app_state
        .db_store
        .get_user_by_id(&user_id)
        .await
        .map_err(|e| EntitlementError::Database(e.to_string()))?
        .ok_or(EntitlementError::UserNotFound)?;
    app_state
        .db_store
        .put_user_entitlements(&user_id, &req.entitlements)
        .await
        .map_err(|e| EntitlementError::Database(e.to_string()))?;
    Ok(Json(PutEntitlementsResponse {
        user_id,
        entitlements: req.entitlements,
    }))
}

#[derive(Error, Debug)]
pub enum EntitlementError {
    #[error("Missing token")]
    MissingToken,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Forbidden")]
    Forbidden,
    #[error("Entitlement list is empty")]
    Empty,
    #[error("Invalid attribute FQN: {0}")]
    InvalidFqn(String),
    #[error("User not found")]
    UserNotFound,
    #[error("Database error: {0}")]
    Database(String),
}

impl IntoResponse for EntitlementError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            EntitlementError::MissingToken | EntitlementError::InvalidToken => {
                StatusCode::UNAUTHORIZED
            }
            EntitlementError::Forbidden => StatusCode::FORBIDDEN,
            EntitlementError::Empty | EntitlementError::InvalidFqn(_) => StatusCode::BAD_REQUEST,
            EntitlementError::UserNotFound => StatusCode::NOT_FOUND,
            EntitlementError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[test]
    fn validate_fqns_rejects_non_https_and_non_attr() {
        assert!(validate_fqns(&["https://arkavo.ai/attr/action/value/read".into()]).is_ok());
        assert!(matches!(
            validate_fqns(&["tdf:create".into()]),
            Err(EntitlementError::InvalidFqn(_))
        ));
        assert!(matches!(
            validate_fqns(&["https://x/attr/a/notvalue/b".into()]),
            Err(EntitlementError::InvalidFqn(_))
        ));
        assert!(matches!(validate_fqns(&[]), Err(EntitlementError::Empty)));
    }

    #[test]
    fn service_cwt_rule_requires_service_account_role() {
        let svc =
            crate::cwt::ArkavoClaims::auth("https://identity.arkavo.net", "client:ops", 1, None)
                .with_arkavo_roles(vec!["service-account".into()]);
        assert!(is_service_claims(&svc));
        let user =
            crate::cwt::ArkavoClaims::auth("https://identity.arkavo.net", "arkavo:abc", 1, None)
                .with_arkavo_roles(vec!["user".into()]);
        assert!(!is_service_claims(&user));
    }

    #[test]
    fn error_status_codes() {
        assert_eq!(
            EntitlementError::Forbidden.into_response().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            EntitlementError::InvalidFqn("x".into())
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            EntitlementError::UserNotFound.into_response().status(),
            StatusCode::NOT_FOUND
        );
    }
}
