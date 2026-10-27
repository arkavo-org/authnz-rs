//! Service-gated entity lookup (spec §2.4). Resolves an entity id to the same
//! shape the platform ERS sees, for gateway audit/admin use without a token.
//! A person is what that account's own token would carry if minted now: the
//! platform ERS's live source reads it in place of the token's Patreon claims.

use crate::AppState;
use crate::db::DynamoDBError;
use crate::entitlements::{EntitlementError, require_service_cwt_for};
use crate::patreon::{Materialized, PatreonState};
use axum::http::HeaderMap;
use axum::{
    extract::{Extension, Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
pub enum EntityId {
    Person(Uuid),
    Agent(String),
    Device(String),
}

pub(crate) fn parse_entity_id(raw: &str) -> Result<EntityId, EntityError> {
    if let Some(u) = raw.strip_prefix("arkavo:") {
        return Uuid::parse_str(u)
            .map(EntityId::Person)
            .map_err(|_| EntityError::BadId(raw.into()));
    }
    if raw.starts_with("did:key:") {
        crate::agent::validate_did_key(raw).map_err(|_| EntityError::BadId(raw.into()))?;
        return Ok(EntityId::Agent(raw.to_string()));
    }
    if let Some(d) = raw.strip_prefix("device:")
        && !d.is_empty()
    {
        return Ok(EntityId::Device(d.to_string()));
    }
    Err(EntityError::BadId(raw.into()))
}

#[derive(Debug, Serialize)]
pub struct EntityRepresentation {
    pub id: String,
    pub category: &'static str,
    pub npe_type: Option<&'static str>,
    pub claims: serde_json::Value,
}

/// GET /entities/:id
pub async fn get_entity(
    Extension(app_state): Extension<AppState>,
    Extension(patreon): Extension<PatreonState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, EntityError> {
    let allow: Vec<String> = app_state
        .entity_client_ids
        .iter()
        .chain(app_state.admin_client_ids.iter())
        .cloned()
        .collect();
    require_service_cwt_for(&app_state, &headers, &allow)?;
    let db = &app_state.db_store;
    let rep = match parse_entity_id(&id)? {
        EntityId::Person(uid) => {
            let u = db
                .get_user_by_id(&uid)
                .await
                .map_err(|e| EntityError::Database(Box::new(e)))?
                .ok_or(EntityError::NotFound)?;
            // A mint omits the claim on both; a resolver must not read
            // "unavailable" as "no memberships" and cache it.
            let snap = match crate::patreon::materialize_for_user_resolved(
                &app_state, &patreon, u.user_id,
            )
            .await
            {
                Materialized::Unavailable => return Err(EntityError::PatreonUnavailable),
                outcome => outcome.snapshot(),
            };
            let user = crate::oidc::AuthenticatedUser::webauthn(u.user_id, u.entitlements);
            let claims = crate::oidc::try_arkavo_user_claims_from(&app_state, &user, snap)
                .await
                .map_err(|e| EntityError::Database(Box::new(e)))?;
            let mut body = serde_json::json!({
                "sub": user.subject,
                "arkavo_account_id": u.user_id,
                "username": u.username,
                "did": u.did,
                "arkavo_roles": claims.roles,
                "arkavo_entitlements": claims.effective_entitlements(),
            });
            if let Some(p) = &claims.patreon {
                body["arkavo_patreon"] = crate::cwt::patreon_to_json(p);
            }
            EntityRepresentation {
                id,
                category: "subject",
                npe_type: None,
                claims: body,
            }
        }
        EntityId::Agent(did) => {
            let d = db
                .get_agent_delegation(&did)
                .await
                .map_err(|e| EntityError::Database(Box::new(e)))?
                .ok_or(EntityError::NotFound)?;
            EntityRepresentation {
                id,
                category: "environment",
                npe_type: Some("agent"),
                claims: serde_json::json!({
                    "sub": d.agent_did,
                    "arkavo_account_id": d.root_user_id,
                    "arkavo_roles": ["agent"],
                    "arkavo_entitlements": crate::db::strip_derived_only(d.entitlements.clone(), &d.agent_did),
                    "arkavo_npe": {"type": "agent", "delegation_id": d.agent_did, "depth": d.depth, "chain": d.chain},
                    "revoked": d.revoked_at.is_some(),
                    "expires_at": d.expires_at,
                }),
            }
        }
        EntityId::Device(key_id) => {
            let b = db
                .get_device_binding(&key_id)
                .await
                .map_err(|e| EntityError::Database(Box::new(e)))?
                .ok_or(EntityError::NotFound)?;
            let (class, expiry) =
                crate::device_check::device_class(b.updated_at, Utc::now().timestamp());
            let mut npe = serde_json::json!({"type": "device", "class": class.as_str(), "attestation_expiry": expiry, "device_id": b.device_id});
            let (app_id_hash, app_env) = crate::device_check::device_app_claims(&app_state, &b);
            if let Some(v) = app_id_hash {
                npe["app_id_hash"] = v.into();
            }
            if let Some(v) = app_env {
                npe["app_env"] = v.into();
            }
            EntityRepresentation {
                id,
                category: "environment",
                npe_type: Some("device"),
                claims: serde_json::json!({
                    "arkavo_account_id": b.user_id,
                    "arkavo_npe": npe,
                }),
            }
        }
    };
    Ok(Json(rep))
}

#[derive(Error, Debug)]
pub enum EntityError {
    #[error(transparent)]
    Auth(#[from] EntitlementError),
    #[error("Unrecognized entity id: {0}")]
    BadId(String),
    #[error("Entity not found")]
    NotFound,
    /// The account is Patreon-linked and no snapshot could be produced.
    #[error("patreon_unavailable")]
    PatreonUnavailable,
    #[error("Database error: {0}")]
    Database(#[from] Box<DynamoDBError>),
}

impl IntoResponse for EntityError {
    fn into_response(self) -> axum::response::Response {
        if let EntityError::Auth(e) = self {
            return e.into_response();
        }
        if let EntityError::PatreonUnavailable = self {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "patreon_unavailable"})),
            )
                .into_response();
        }
        let (status, body) = match &self {
            EntityError::Auth(_) | EntityError::PatreonUnavailable => {
                unreachable!("handled above")
            }
            EntityError::BadId(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            EntityError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            EntityError::Database(e) => match e.as_ref() {
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

    #[tokio::test]
    async fn patreon_unavailable_is_a_503_with_a_stable_token() {
        use axum::response::IntoResponse;
        let resp = EntityError::PatreonUnavailable.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"error": "patreon_unavailable"})
        );
    }

    /// An `ENTITY_CLIENT_IDS` client reads `/entities` and nothing more.
    #[tokio::test]
    async fn entity_clients_pass_the_entities_gate_but_not_the_admin_one() {
        unsafe {
            std::env::set_var("AWS_REGION", "us-east-1");
            std::env::set_var("AWS_ACCESS_KEY_ID", "fake");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "fake");
        }
        let app_state = crate::test_helpers::build_test_app_state().await;
        let patreon = PatreonState::new(
            None,
            None,
            fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None),
        );
        let service = |sub: &str| {
            let claims = crate::cwt::ArkavoClaims::auth(&app_state.issuer, sub, 1, None)
                .with_arkavo_roles(vec!["service-account".into()]);
            let token = crate::cwt::encode_for_header(
                &crate::cwt::mint(&claims, &app_state.cwt_signing_key, &app_state.cwt_kid).unwrap(),
            );
            let mut headers = HeaderMap::new();
            headers.insert("X-Auth-Token", token.parse().unwrap());
            headers
        };
        let status = |r: Result<axum::response::Response, EntityError>| match r {
            Ok(resp) => resp.status(),
            Err(e) => e.into_response().status(),
        };
        let call = |headers: HeaderMap| {
            get_entity(
                Extension(app_state.clone()),
                Extension(patreon.clone()),
                headers,
                Path("bogus".into()),
            )
        };

        // Past the gate, an unknown namespace is 400; refused, 403.
        let reader = service("client:entity-reader");
        assert_eq!(
            status(call(reader.clone()).await.map(IntoResponse::into_response)),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(
                call(service("client:it"))
                    .await
                    .map(IntoResponse::into_response)
            ),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(
                call(service("client:mcp-edge"))
                    .await
                    .map(IntoResponse::into_response)
            ),
            StatusCode::FORBIDDEN
        );
        assert!(matches!(
            crate::entitlements::require_service_cwt(&app_state, &reader),
            Err(EntitlementError::Forbidden)
        ));
    }

    #[test]
    fn table_not_exists_maps_to_service_unavailable_like_agent_errors() {
        use axum::response::IntoResponse;
        let err = EntityError::Database(Box::new(crate::db::DynamoDBError::TableNotExists(
            "credentials".into(),
        )));
        assert_eq!(
            err.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let other =
            EntityError::Database(Box::new(crate::db::DynamoDBError::SdkError("boom".into())));
        assert_eq!(
            other.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn parse_entity_id_namespaces() {
        assert!(matches!(
            parse_entity_id("arkavo:00000000-0000-0000-0000-000000000001"),
            Ok(EntityId::Person(_))
        ));
        assert!(matches!(
            parse_entity_id("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
            Ok(EntityId::Agent(_))
        ));
        assert!(
            matches!(parse_entity_id("device:ABCDEF"), Ok(EntityId::Device(d)) if d == "ABCDEF")
        );
        assert!(parse_entity_id("apple:123").is_err());
        assert!(parse_entity_id("arkavo:not-a-uuid").is_err());
    }
}
