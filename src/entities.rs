//! Service-gated entity lookup (spec §2.4). Resolves an entity id to the same
//! shape the platform ERS sees, for gateway audit/admin use without a token.

use crate::AppState;
use crate::entitlements::{EntitlementError, require_service_cwt};
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
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, EntityError> {
    require_service_cwt(&app_state, &headers)?;
    let db = &app_state.db_store;
    let rep = match parse_entity_id(&id)? {
        EntityId::Person(uid) => {
            let u = db
                .get_user_by_id(&uid)
                .await
                .map_err(|e| EntityError::Database(e.to_string()))?
                .ok_or(EntityError::NotFound)?;
            EntityRepresentation {
                id,
                category: "subject",
                npe_type: None,
                claims: serde_json::json!({
                    "sub": format!("arkavo:{}", u.user_id),
                    "arkavo_account_id": u.user_id,
                    "username": u.username,
                    "did": u.did,
                    "arkavo_roles": ["user"],
                    "arkavo_entitlements": u.entitlements,
                }),
            }
        }
        EntityId::Agent(did) => {
            let d = db
                .get_agent_delegation(&did)
                .await
                .map_err(|e| EntityError::Database(e.to_string()))?
                .ok_or(EntityError::NotFound)?;
            EntityRepresentation {
                id,
                category: "environment",
                npe_type: Some("agent"),
                claims: serde_json::json!({
                    "sub": d.agent_did,
                    "arkavo_account_id": d.root_user_id,
                    "arkavo_roles": ["agent"],
                    "arkavo_entitlements": d.entitlements,
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
                .map_err(|e| EntityError::Database(e.to_string()))?
                .ok_or(EntityError::NotFound)?;
            let (class, expiry) =
                crate::device_check::device_class(b.updated_at, Utc::now().timestamp());
            EntityRepresentation {
                id,
                category: "environment",
                npe_type: Some("device"),
                claims: serde_json::json!({
                    "arkavo_account_id": b.user_id,
                    "arkavo_npe": {"type": "device", "class": class.as_str(), "attestation_expiry": expiry, "device_id": b.device_id},
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
    #[error("Database error: {0}")]
    Database(String),
}

impl IntoResponse for EntityError {
    fn into_response(self) -> axum::response::Response {
        match self {
            EntityError::Auth(e) => e.into_response(),
            EntityError::BadId(_) => (StatusCode::BAD_REQUEST, self.to_string()).into_response(),
            EntityError::NotFound => (StatusCode::NOT_FOUND, self.to_string()).into_response(),
            EntityError::Database(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
