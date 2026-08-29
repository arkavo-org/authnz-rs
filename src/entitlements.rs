//! Admin entitlement management (spec §2.3).
//!
//! `PUT /admin/users/:id/entitlements` replaces a user's attribute-FQN list.
//! Gated by a service CWT (`arkavo_roles` contains `service-account`), the
//! same credential class that runs `scripts/mint-pep-cwt.py`.

use crate::AppState;
use crate::cwt;
use crate::db::DynamoDBError;
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
    if !is_admin_client(&claims.sub, &app_state.admin_client_ids) {
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

/// Attribute FQN shape: `https://<host>/attr/<name>/value/<value>` with no
/// empty path segments and nothing after `/value/<value>`.
pub(crate) fn validate_fqns(list: &[String]) -> Result<(), EntitlementError> {
    if list.is_empty() {
        return Err(EntitlementError::Empty);
    }
    for f in list {
        if !is_attribute_fqn(f) {
            return Err(EntitlementError::InvalidFqn(f.clone()));
        }
    }
    Ok(())
}

fn is_attribute_fqn(f: &str) -> bool {
    let Some(rest) = f.strip_prefix("https://") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('/').collect();
    parts.len() == 5
        && !parts.iter().any(|p| p.is_empty())
        && parts[1] == "attr"
        && parts[3] == "value"
}

/// `USER_DEFAULT_ENTITLEMENTS` — comma-separated FQNs. Unset/empty uses
/// [`crate::constants::DEFAULT_USER_ENTITLEMENTS`].
pub fn parse_user_default_entitlements(raw: Option<&str>) -> Result<Vec<String>, String> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(crate::constants::DEFAULT_USER_ENTITLEMENTS
            .iter()
            .map(|s| (*s).to_string())
            .collect()),
        Some(s) => {
            let list: Vec<String> = s
                .split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect();
            validate_fqns(&list).map_err(|e| e.to_string())?;
            Ok(list)
        }
    }
}

/// Service CWTs mint `sub = "client:<client_id>"`. Accept either form in
/// `ADMIN_CLIENT_IDS`.
pub(crate) fn is_admin_client(sub: &str, allow: &[String]) -> bool {
    let id = sub.strip_prefix("client:").unwrap_or(sub);
    allow.iter().any(|a| a == id || a == sub)
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
        .map_err(|e| EntitlementError::Database(Box::new(e)))?
        .ok_or(EntitlementError::UserNotFound)?;
    app_state
        .db_store
        .put_user_entitlements(&user_id, &req.entitlements)
        .await
        .map_err(|e| match e {
            // The write is conditioned on the row existing, so losing the
            // race with a delete between the check above and this update is
            // the same answer the check would have given: 404, not 500.
            DynamoDBError::ConditionalConflict => EntitlementError::UserNotFound,
            other => EntitlementError::Database(Box::new(other)),
        })?;
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
    Database(#[from] Box<DynamoDBError>),
}

impl IntoResponse for EntitlementError {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = match &self {
            EntitlementError::MissingToken | EntitlementError::InvalidToken => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            EntitlementError::Forbidden => (StatusCode::FORBIDDEN, self.to_string()),
            EntitlementError::Empty | EntitlementError::InvalidFqn(_) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            EntitlementError::UserNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            EntitlementError::Database(e) => match e.as_ref() {
                DynamoDBError::TableNotExists(table) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Service setup incomplete: {} table not configured", table),
                ),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            },
        };
        (status, body).into_response()
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
        assert!(matches!(
            validate_fqns(&["https://arkavo.ai/attr//value/read".into()]),
            Err(EntitlementError::InvalidFqn(_))
        ));
        assert!(matches!(
            validate_fqns(&["https://arkavo.ai/attr/action/value/read/extra".into()]),
            Err(EntitlementError::InvalidFqn(_))
        ));
        assert!(matches!(
            validate_fqns(&["https://arkavo.ai/attr/action/value/".into()]),
            Err(EntitlementError::InvalidFqn(_))
        ));
    }

    #[test]
    fn parse_user_default_entitlements_unset_uses_constant() {
        let got = parse_user_default_entitlements(None).unwrap();
        assert_eq!(got.len(), crate::constants::DEFAULT_USER_ENTITLEMENTS.len());
        assert!(!parse_user_default_entitlements(Some("")).unwrap().is_empty());
        assert!(parse_user_default_entitlements(Some("not-an-fqn")).is_err());
        let one = parse_user_default_entitlements(Some("https://arkavo.ai/attr/tdf/value/decrypt"))
            .unwrap();
        assert_eq!(one, vec!["https://arkavo.ai/attr/tdf/value/decrypt"]);
    }

    #[test]
    fn admin_client_matches_bare_or_client_prefixed_sub() {
        let allow = vec!["ops".into(), "catalog-node".into()];
        assert!(is_admin_client("client:ops", &allow));
        assert!(is_admin_client("ops", &allow));
        assert!(!is_admin_client("client:mcp-edge", &allow));
        assert!(!is_admin_client("client:ops", &[]));
    }

    #[tokio::test]
    async fn require_service_cwt_rejects_service_account_not_on_allowlist() {
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
            std::env::set_var("AWS_ACCESS_KEY_ID", "fake");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "fake");
        }
        let app_state = crate::test_helpers::build_test_app_state().await;
        let outsider =
            crate::cwt::ArkavoClaims::auth(&app_state.issuer, "client:mcp-edge", 1, None)
                .with_arkavo_roles(vec!["service-account".into()]);
        let token = crate::cwt::encode_for_header(
            &crate::cwt::mint(&outsider, &app_state.cwt_signing_key, &app_state.cwt_kid).unwrap(),
        );
        let mut headers = HeaderMap::new();
        headers.insert("X-Auth-Token", token.parse().unwrap());
        assert!(matches!(
            require_service_cwt(&app_state, &headers),
            Err(EntitlementError::Forbidden)
        ));

        let admin = crate::cwt::ArkavoClaims::auth(&app_state.issuer, "client:it", 1, None)
            .with_arkavo_roles(vec!["service-account".into()]);
        let token = crate::cwt::encode_for_header(
            &crate::cwt::mint(&admin, &app_state.cwt_signing_key, &app_state.cwt_kid).unwrap(),
        );
        headers.insert("X-Auth-Token", token.parse().unwrap());
        assert!(require_service_cwt(&app_state, &headers).is_ok());
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

    #[test]
    fn table_not_exists_maps_to_service_unavailable_like_agent_errors() {
        let err = EntitlementError::Database(Box::new(crate::db::DynamoDBError::TableNotExists(
            "credentials".into(),
        )));
        assert_eq!(
            err.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let other =
            EntitlementError::Database(Box::new(crate::db::DynamoDBError::SdkError("boom".into())));
        assert_eq!(
            other.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
