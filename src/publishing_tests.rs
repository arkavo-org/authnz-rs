//! Creator-publishing entitlement (#91) through the real mint paths and the
//! suspension endpoints, against DynamoDB Local. Every test returns early
//! unless `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set. The pure qualification
//! rules are unit-tested in `publishing.rs`, which needs no database.
//!
//! Bin-local for the same reason as `agent_plane_tests.rs`: `AppState` is not
//! in the lib.

use crate::AppState;
use crate::constants::ENTITLEMENT_CREATOR_PUBLISH;
use crate::cwt::{ArkavoClaims, ArkavoPatreon, ArkavoPatreonMembership};
use crate::db::{DynamoDBStore, PublishingSuspension, SuspensionSet};
use crate::oidc::AuthenticatedUser;
use crate::patreon::{PatreonClient, PatreonOAuthConfig, PatreonState, TokenSealer};
use crate::publishing::PublisherConfig;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Extension, Router};
use chrono::Utc;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

pub(crate) const ARKAVO_CAMPAIGN: &str = "arkavo-campaign";
pub(crate) const PUBLISH_TIER: &str = "tier-publisher";
/// Allowlisted on `MODERATION_CLIENT_IDS` by `test_helpers`.
const MODERATION_CLIENT: &str = "moderation";

pub(crate) fn publisher_cfg() -> PublisherConfig {
    PublisherConfig::parse(Some(ARKAVO_CAMPAIGN), Some(PUBLISH_TIER)).unwrap()
}

/// A fresh snapshot naming an active, qualifying membership of Arkavo's
/// campaign.
pub(crate) fn qualifying_snapshot(role: &str) -> ArkavoPatreon {
    let now = Utc::now().timestamp();
    ArkavoPatreon {
        role: role.into(),
        patreon_user_id: "p-pub".into(),
        campaign_id: (role == "creator").then(|| "creators-own-campaign".into()),
        memberships: vec![ArkavoPatreonMembership {
            campaign_id: ARKAVO_CAMPAIGN.into(),
            patron_status: Some("active_patron".into()),
            tier_ids: vec![PUBLISH_TIER.into()],
            tier_slugs: vec!["publisher".into()],
        }],
        owned_tiers: Default::default(),
        verified_at: now,
        cache_expires_at: now + 300,
    }
}

/// An enabled Patreon state (configured client, plaintext sealer) whose
/// membership cache — the in-memory fallback, Redis being unconnected —
/// already holds `snap` for `user_id`, so a mint reads it without any
/// Patreon or `patreon_tokens` call.
pub(crate) async fn patreon_with(user_id: Uuid, snap: &ArkavoPatreon) -> PatreonState {
    let redis =
        fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None);
    let state = PatreonState::new(
        Some(PatreonOAuthConfig {
            clients: vec![PatreonClient {
                client_id: "c".into(),
                client_secret: "s".into(),
                redirect_uris: vec!["https://x/cb".into()],
            }],
        }),
        Some(TokenSealer::Plaintext),
        redis,
    );
    state.cache.put(user_id, snap).await;
    state
}

pub(crate) struct Fixture {
    pub state: AppState,
    pub store: Arc<DynamoDBStore>,
    pub patreon: PatreonState,
    pub user_id: Uuid,
    pub stored: Vec<String>,
}

impl Fixture {
    /// A fresh user, the feature configured, and a qualifying snapshot cached.
    pub async fn new() -> Option<Self> {
        let store = Arc::new(crate::db::tests::local_store()?);
        let mut state = crate::test_helpers::build_test_app_state_with_store(store.clone());
        state.publisher = Arc::new(Some(publisher_cfg()));
        let user = store
            .create_user(
                &format!("pub-{}", &Uuid::new_v4().simple().to_string()[..12]),
                "did:key:z6Mkpublishing",
            )
            .await
            .unwrap();
        let patreon = patreon_with(user.user_id, &qualifying_snapshot("creator")).await;
        Some(Self {
            state,
            store,
            patreon,
            user_id: user.user_id,
            stored: user.entitlements,
        })
    }

    pub fn webauthn_user(&self) -> AuthenticatedUser {
        AuthenticatedUser::webauthn(self.user_id, self.stored.clone())
    }

    pub async fn claims(&self) -> crate::cwt::ArkavoUserClaims {
        crate::oidc::arkavo_user_claims(&self.state, &self.patreon, &self.webauthn_user()).await
    }

    pub async fn suspend(&self) {
        let out = self
            .store
            .set_publishing_suspension(
                &self.user_id,
                &PublishingSuspension {
                    reason: "test".into(),
                    report_id: None,
                    suspended_by: "client:moderation".into(),
                    suspended_at: Utc::now().timestamp(),
                },
            )
            .await
            .unwrap();
        assert_eq!(out, SuspensionSet::Created);
    }
}

pub(crate) fn decode(token: &str) -> ArkavoClaims {
    use coset::CborSerializable;
    let raw = crate::cwt::decode_from_header(token).unwrap();
    let inner = crate::cwt::strip_cwt_tag(&raw).unwrap();
    let sign1 = coset::CoseSign1::from_slice(inner).unwrap();
    crate::cwt::claims_from_cbor(sign1.payload.as_ref().unwrap()).unwrap()
}

pub(crate) fn has_publish(claims: &ArkavoClaims) -> bool {
    claims
        .custom
        .arkavo_entitlements
        .as_ref()
        .is_some_and(|e| e.iter().any(|x| x == ENTITLEMENT_CREATOR_PUBLISH))
}

#[tokio::test]
async fn qualifying_creator_gets_publish_on_auth_access_and_devicecheck_not_registration() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let user = f.claims().await;
    assert_eq!(
        user.derived_entitlements,
        vec![ENTITLEMENT_CREATOR_PUBLISH.to_string()]
    );
    // The stored list is untouched; the derived one rides alongside it.
    assert_eq!(user.entitlements, f.stored);
    assert!(
        !user
            .entitlements
            .contains(&ENTITLEMENT_CREATOR_PUBLISH.to_string())
    );
    // The creator's own campaign claim is kept alongside its memberships.
    let snap = user.patreon.as_ref().expect("snapshot");
    assert_eq!(snap.campaign_id.as_deref(), Some("creators-own-campaign"));

    // Passkey auth CWT.
    let auth =
        decode(&crate::authn::mint_auth_token(&f.state, &f.user_id, Some(&user), None).unwrap());
    assert!(has_publish(&auth), "auth CWT must carry it");

    // OIDC access token.
    let access = decode(
        &crate::oidc::mint_access_token(
            &f.state,
            &format!("arkavo:{}", f.user_id),
            "opentdf",
            Some(crate::oidc::AccessTokenExtras {
                idp: "webauthn".into(),
                arkavo_user: Some(user.clone()),
                ..Default::default()
            }),
            None,
        )
        .unwrap(),
    );
    assert!(has_publish(&access), "access token must carry it");

    // DeviceCheck assertion CWT.
    let scalar = p256::FieldBytes::from([0x77u8; 32]);
    let secret = p256::SecretKey::from_bytes(&scalar).unwrap();
    let vk = *p256::ecdsa::SigningKey::from(&secret).verifying_key();
    let now = Utc::now().timestamp();
    let binding = crate::device_check::DeviceBinding {
        device_id: "device-pub".into(),
        user_id: f.user_id,
        public_key: vk.to_encoded_point(false).as_bytes().to_vec(),
        counter: 1,
        app_id: "app".into(),
        created_at: now,
        updated_at: now,
    };
    let dc = decode(
        &crate::device_check::mint_assertion_token(&f.state, &binding, Some(&user), now).unwrap(),
    );
    assert!(has_publish(&dc), "DeviceCheck CWT must carry it");

    // ~99-year registration token: never.
    let cnf = crate::cwt::cnf_from_ed25519(&[5u8; 32], b"kid");
    let reg = decode(
        &crate::authn::mint_registration_token(&f.state, &f.user_id, Some(&user), cnf).unwrap(),
    );
    assert!(!has_publish(&reg), "registration token must not carry it");
    assert_eq!(reg.custom.arkavo_entitlements, Some(f.stored.clone()));

    // Never stored, so never delegable to agents nor visible in /entities.
    let stored = f.store.get_user_entitlements(&f.user_id).await.unwrap();
    assert!(!stored.contains(&ENTITLEMENT_CREATOR_PUBLISH.to_string()));
}

#[tokio::test]
async fn suspension_withholds_publish_until_lifted() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    f.suspend().await;
    let user = f.claims().await;
    assert!(user.derived_entitlements.is_empty(), "suspended ⇒ none");
    // Membership is still reported; only the derived entitlement is withheld.
    assert!(user.patreon.is_some());
    let auth =
        decode(&crate::authn::mint_auth_token(&f.state, &f.user_id, Some(&user), None).unwrap());
    assert!(!has_publish(&auth));

    f.store
        .lift_publishing_suspension(&f.user_id)
        .await
        .unwrap();
    assert_eq!(
        f.claims().await.derived_entitlements,
        vec![ENTITLEMENT_CREATOR_PUBLISH.to_string()]
    );
}

#[tokio::test]
async fn feature_unset_or_non_qualifying_membership_grants_nothing() {
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    f.state.publisher = Arc::new(None);
    assert!(f.claims().await.derived_entitlements.is_empty());

    f.state.publisher = Arc::new(Some(publisher_cfg()));
    let mut lapsed = qualifying_snapshot("consumer");
    lapsed.memberships[0].patron_status = Some("declined_patron".into());
    f.patreon = patreon_with(f.user_id, &lapsed).await;
    assert!(f.claims().await.derived_entitlements.is_empty());

    // A consumer link qualifies exactly like a creator link.
    f.patreon = patreon_with(f.user_id, &qualifying_snapshot("consumer")).await;
    assert_eq!(f.claims().await.derived_entitlements.len(), 1);

    // No Patreon state at all (unlinked / disabled).
    f.patreon = PatreonState::new(
        None,
        None,
        fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None),
    );
    assert!(f.claims().await.derived_entitlements.is_empty());
}

// ---- App Store Creator Membership ----

mod app_store_source {
    use super::*;
    use crate::app_store::{AppStoreConfig, Environment};
    use crate::db::{AppStoreRecord, GraceUpdate, StateOutcome};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const PRODUCT: &str = "com.arkavo.ArkavoCreator.membership.monthly";

    fn publish_count(derived: &[String]) -> usize {
        derived
            .iter()
            .filter(|e| *e == ENTITLEMENT_CREATOR_PUBLISH)
            .count()
    }

    /// A fresh user with the App Store feature configured and Patreon off
    /// (no publisher config, no snapshot).
    async fn app_store_only() -> Option<Fixture> {
        let mut f = Fixture::new().await?;
        f.state.publisher = Arc::new(None);
        f.state.app_store = Arc::new(Some(AppStoreConfig::for_tests(Vec::new())));
        f.patreon = PatreonState::new(
            None,
            None,
            fred::clients::RedisClient::new(fred::types::RedisConfig::default(), None, None, None),
        );
        Some(f)
    }

    fn record(otid: &str, env: Environment, expires_at: i64, signed: i64) -> AppStoreRecord {
        AppStoreRecord {
            original_transaction_id: otid.into(),
            transaction_id: Some(otid.into()),
            product_id: PRODUCT.into(),
            environment: env,
            expires_at,
            grace_expires_at: None,
            revoked_at: None,
            last_signed_at: signed,
        }
    }

    async fn put(f: &Fixture, rec: &AppStoreRecord, grace: GraceUpdate) {
        let out = f
            .store
            .put_app_store_state(&f.user_id, rec, grace)
            .await
            .unwrap();
        assert_eq!(out, StateOutcome::Applied);
    }

    fn unique_otid() -> String {
        Uuid::new_v4().as_u128().to_string()
    }

    #[tokio::test]
    async fn app_store_only_member_gets_publish_without_patreon_config_or_snapshot() {
        let Some(f) = app_store_only().await else {
            return;
        };
        let now = Utc::now().timestamp();
        // Nothing bound yet.
        assert!(f.claims().await.derived_entitlements.is_empty());

        put(
            &f,
            &record(&unique_otid(), Environment::Production, now + 3600, now),
            GraceUpdate::Keep,
        )
        .await;
        let user = f.claims().await;
        assert!(user.patreon.is_none());
        assert_eq!(
            user.derived_entitlements,
            vec![ENTITLEMENT_CREATOR_PUBLISH.to_string()]
        );
        // Derived, never stored.
        assert_eq!(user.entitlements, f.stored);
        assert!(
            !f.store
                .get_user_entitlements(&f.user_id)
                .await
                .unwrap()
                .contains(&ENTITLEMENT_CREATOR_PUBLISH.to_string())
        );
        let auth = decode(
            &crate::authn::mint_auth_token(&f.state, &f.user_id, Some(&user), None).unwrap(),
        );
        assert!(has_publish(&auth));
    }

    #[tokio::test]
    async fn expired_membership_grants_nothing() {
        let Some(f) = app_store_only().await else {
            return;
        };
        let now = Utc::now().timestamp();
        put(
            &f,
            &record(
                &unique_otid(),
                Environment::Production,
                now - 10,
                now - 2_592_000,
            ),
            GraceUpdate::Keep,
        )
        .await;
        assert!(f.claims().await.derived_entitlements.is_empty());
    }

    #[tokio::test]
    async fn grace_period_still_grants() {
        let Some(f) = app_store_only().await else {
            return;
        };
        let now = Utc::now().timestamp();
        put(
            &f,
            &record(
                &unique_otid(),
                Environment::Production,
                now - 10,
                now - 2_592_000,
            ),
            GraceUpdate::Set(Some(now + 3600)),
        )
        .await;
        assert_eq!(
            f.claims().await.derived_entitlements,
            vec![ENTITLEMENT_CREATOR_PUBLISH.to_string()]
        );
    }

    /// Review Focus 4: a refund ends the entitlement at the very next mint,
    /// although `expires_at` is still in the future.
    #[tokio::test]
    async fn refunded_membership_grants_nothing_at_next_mint() {
        let Some(f) = app_store_only().await else {
            return;
        };
        let now = Utc::now().timestamp();
        let otid = unique_otid();
        let mut rec = record(&otid, Environment::Production, now + 3600, now - 100);
        put(&f, &rec, GraceUpdate::Keep).await;
        assert_eq!(f.claims().await.derived_entitlements.len(), 1);

        rec.revoked_at = Some(now);
        rec.last_signed_at = now;
        put(&f, &rec, GraceUpdate::Keep).await;
        assert!(f.claims().await.derived_entitlements.is_empty());
    }

    #[tokio::test]
    async fn suspended_app_store_member_grants_nothing() {
        let Some(f) = app_store_only().await else {
            return;
        };
        let now = Utc::now().timestamp();
        put(
            &f,
            &record(&unique_otid(), Environment::Production, now + 3600, now),
            GraceUpdate::Keep,
        )
        .await;
        f.suspend().await;
        assert!(f.claims().await.derived_entitlements.is_empty());
        f.store
            .lift_publishing_suspension(&f.user_id)
            .await
            .unwrap();
        assert_eq!(f.claims().await.derived_entitlements.len(), 1);
    }

    #[tokio::test]
    async fn patreon_and_app_store_member_gets_one_fqn() {
        let Some(mut f) = Fixture::new().await else {
            return;
        };
        f.state.app_store = Arc::new(Some(AppStoreConfig::for_tests(Vec::new())));
        let now = Utc::now().timestamp();
        put(
            &f,
            &record(&unique_otid(), Environment::Production, now + 3600, now),
            GraceUpdate::Keep,
        )
        .await;
        assert_eq!(publish_count(&f.claims().await.derived_entitlements), 1);

        // Patreon alone still grants once, with the App Store feature on and
        // nothing bound to the account.
        let g = Fixture::new().await.unwrap();
        let mut state = g.state.clone();
        state.app_store = f.state.app_store.clone();
        let derived = crate::publishing::derived_entitlements(
            &state,
            Some(g.user_id),
            Some(&qualifying_snapshot("consumer")),
        )
        .await;
        assert_eq!(derived, vec![ENTITLEMENT_CREATOR_PUBLISH.to_string()]);
    }

    #[tokio::test]
    async fn sandbox_record_ignored_when_only_production_configured() {
        let Some(mut f) = app_store_only().await else {
            return;
        };
        let now = Utc::now().timestamp();
        put(
            &f,
            &record(&unique_otid(), Environment::Sandbox, now + 3600, now),
            GraceUpdate::Keep,
        )
        .await;
        // Sandbox is accepted by default (owner decision).
        assert_eq!(f.claims().await.derived_entitlements.len(), 1);

        let mut cfg = AppStoreConfig::for_tests(Vec::new());
        cfg.environments = [Environment::Production].into_iter().collect();
        f.state.app_store = Arc::new(Some(cfg));
        assert!(f.claims().await.derived_entitlements.is_empty());
    }

    #[tokio::test]
    async fn state_read_error_fails_closed() {
        let Some(mut f) = Fixture::new().await else {
            return;
        };
        f.state.app_store = Arc::new(Some(AppStoreConfig::for_tests(Vec::new())));
        let now = Utc::now().timestamp();
        put(
            &f,
            &record(&unique_otid(), Environment::Production, now + 3600, now),
            GraceUpdate::Keep,
        )
        .await;
        // Both sources would grant, and the read of the row fails.
        assert_eq!(f.claims().await.derived_entitlements.len(), 1);
        f.state.db_store = Arc::new(
            f.store
                .with_credentials_table(format!("missing-credentials-{}", Uuid::new_v4().simple())),
        );
        assert!(f.claims().await.derived_entitlements.is_empty());
    }

    #[tokio::test]
    async fn neither_source_configured_does_no_read() {
        let Some(mut f) = Fixture::new().await else {
            return;
        };
        let now = Utc::now().timestamp();
        // A record that would be active if the feature were on.
        put(
            &f,
            &record(&unique_otid(), Environment::Production, now + 3600, now),
            GraceUpdate::Keep,
        )
        .await;
        let reads = Arc::new(AtomicUsize::new(0));
        f.state.db_store = Arc::new(f.store.counting_get_items(reads.clone()));
        let snap = qualifying_snapshot("consumer");

        // Neither Patreon publishing nor the App Store configured.
        f.state.publisher = Arc::new(None);
        f.state.app_store = Arc::new(None);
        let derived =
            crate::publishing::derived_entitlements(&f.state, Some(f.user_id), Some(&snap)).await;
        assert!(derived.is_empty());
        assert_eq!(reads.load(Ordering::SeqCst), 0);

        // Patreon configured but the membership does not qualify, App Store off.
        f.state.publisher = Arc::new(Some(publisher_cfg()));
        let mut lapsed = snap.clone();
        lapsed.memberships[0].patron_status = Some("declined_patron".into());
        let derived =
            crate::publishing::derived_entitlements(&f.state, Some(f.user_id), Some(&lapsed)).await;
        assert!(derived.is_empty());
        assert_eq!(reads.load(Ordering::SeqCst), 0);

        // A service account has no user id: no read even with the feature on.
        f.state.app_store = Arc::new(Some(AppStoreConfig::for_tests(Vec::new())));
        let derived = crate::publishing::derived_entitlements(&f.state, None, None).await;
        assert!(derived.is_empty());
        assert_eq!(reads.load(Ordering::SeqCst), 0);

        // With a source that can grant, exactly one read replaces the old
        // suspension read.
        let derived =
            crate::publishing::derived_entitlements(&f.state, Some(f.user_id), Some(&snap)).await;
        assert_eq!(derived.len(), 1);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        f.state.publisher = Arc::new(None);
        let derived =
            crate::publishing::derived_entitlements(&f.state, Some(f.user_id), None).await;
        assert_eq!(derived.len(), 1);
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }
}

// ---- Admin endpoint ----

fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/admin/users/:id/publishing-suspension",
            get(crate::publishing::get_publishing_suspension)
                .put(crate::publishing::put_publishing_suspension)
                .delete(crate::publishing::delete_publishing_suspension),
        )
        .layer(Extension(state))
}

fn service_token(state: &AppState, client: &str) -> String {
    let claims = ArkavoClaims::auth(&state.issuer, &format!("client:{client}"), 1, None)
        .with_arkavo_roles(vec!["service-account".into()]);
    crate::cwt::encode_for_header(
        &crate::cwt::mint(&claims, &state.cwt_signing_key, &state.cwt_kid).unwrap(),
    )
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

fn req(method: &str, user: Uuid, token: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(format!("/admin/users/{user}/publishing-suspension"));
    if let Some(t) = token {
        b = b.header("X-Auth-Token", t);
    }
    match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    }
}

#[tokio::test]
async fn suspension_endpoint_auth_set_lift_and_audit_fields() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let app = router(f.state.clone());
    let body = json!({"reason": "upheld report", "reportId": "rpt-42"});
    let moderator = service_token(&f.state, MODERATION_CLIENT);

    // No token ⇒ 401; a service client off the allowlist (even an admin) ⇒ 403;
    // a user's passkey CWT ⇒ 403.
    let (s, _) = send(&app, req("PUT", f.user_id, None, Some(body.clone()))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let admin = service_token(&f.state, "it");
    let (s, _) = send(
        &app,
        req("PUT", f.user_id, Some(&admin), Some(body.clone())),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let user_cwt = crate::authn::mint_auth_token(&f.state, &f.user_id, None, None).unwrap();
    let (s, _) = send(
        &app,
        req("PUT", f.user_id, Some(&user_cwt), Some(body.clone())),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Bad body ⇒ 400.
    let (s, _) = send(
        &app,
        req(
            "PUT",
            f.user_id,
            Some(&moderator),
            Some(json!({"reason": " "})),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // A reportId that could forge an audit line ⇒ 400.
    let (s, _) = send(
        &app,
        req(
            "PUT",
            f.user_id,
            Some(&moderator),
            Some(
                json!({"reason": "r", "reportId": "x\naudit publishing_suspension outcome=lifted"}),
            ),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Set ⇒ 201 with the audit record.
    let (s, b) = send(
        &app,
        req("PUT", f.user_id, Some(&moderator), Some(body.clone())),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    assert_eq!(b["suspended"], true);
    assert_eq!(b["suspension"]["reason"], "upheld report");
    assert_eq!(b["suspension"]["reportId"], "rpt-42");
    assert_eq!(b["suspension"]["suspended_by"], "client:moderation");
    let at = b["suspension"]["suspended_at"].as_i64().unwrap();
    assert!((Utc::now().timestamp() - at).abs() < 60);

    // Repeat ⇒ 200, original record kept.
    let (s, b2) = send(
        &app,
        req(
            "PUT",
            f.user_id,
            Some(&moderator),
            Some(json!({"reason": "second"})),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b2["suspension"]["reason"], "upheld report");
    assert_eq!(b2["suspension"]["suspended_at"].as_i64(), Some(at));

    // GET shows it, and nothing about Patreon.
    let (s, g) = send(&app, req("GET", f.user_id, Some(&moderator), None)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(g["suspended"], true);
    assert_eq!(g["suspension"]["reportId"], "rpt-42");
    assert_eq!(
        g.as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["suspended", "suspension", "user_id"]
    );

    // Suspension is in force at the next mint.
    assert!(f.claims().await.derived_entitlements.is_empty());

    // Lift ⇒ 204, idempotent; GET shows not suspended; the entitlement returns.
    let (s, _) = send(&app, req("DELETE", f.user_id, Some(&moderator), None)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = send(&app, req("DELETE", f.user_id, Some(&moderator), None)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, g) = send(&app, req("GET", f.user_id, Some(&moderator), None)).await;
    assert_eq!(g["suspended"], false);
    assert!(g.get("suspension").is_none());
    assert_eq!(f.claims().await.derived_entitlements.len(), 1);

    // Unknown user ⇒ 404 on every verb, and no row is created.
    let ghost = Uuid::new_v4();
    for (m, b) in [("PUT", Some(body.clone())), ("DELETE", None), ("GET", None)] {
        let (s, _) = send(&app, req(m, ghost, Some(&moderator), b)).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{m}");
    }
    assert!(f.store.get_user_by_id(&ghost).await.unwrap().is_none());
}

#[tokio::test]
async fn empty_moderation_allowlist_refuses_everyone() {
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    f.state.moderation_client_ids = Arc::new(vec![]);
    let app = router(f.state.clone());
    let moderator = service_token(&f.state, MODERATION_CLIENT);
    let (s, _) = send(&app, req("GET", f.user_id, Some(&moderator), None)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn publish_is_never_delegable_to_an_agent() {
    use crate::agent_plane_tests::{authorize_body, did_key, fresh_agent};
    let Some(f) = Fixture::new().await else {
        return;
    };
    // The owner's auth CWT does carry it...
    let user = f.claims().await;
    let cwt = crate::authn::mint_auth_token(&f.state, &f.user_id, Some(&user), None).unwrap();
    assert!(has_publish(&decode(&cwt)));
    // ...but authorize delegates from the stored list, which never holds it.
    let app = crate::agent_plane_tests::router(f.state.clone());
    let a = fresh_agent();
    let mut body = authorize_body(&a, "", false);
    body["entitlements"] = json!([ENTITLEMENT_CREATOR_PUBLISH]);
    let (st, _) = send(
        &app,
        Request::post("/agents/authorize")
            .header("X-Auth-Token", &cwt)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(
        f.store
            .get_agent_delegation(&did_key(&a))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_stored_copy_is_never_emitted_or_delegated() {
    use crate::agent_plane_tests::{authorize_body, did_key, fresh_agent};
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    let publish = ENTITLEMENT_CREATOR_PUBLISH.to_string();
    let decrypt = "https://arkavo.ai/attr/tdf/value/decrypt".to_string();
    let campaign = "https://patreon.arkavo.com/attr/campaign/value/123".to_string();
    // A row written before validate_fqns refused the FQNs.
    f.store
        .put_user_entitlements(
            &f.user_id,
            &[decrypt.clone(), publish.clone(), campaign.clone()],
        )
        .await
        .unwrap();

    // Every read of the stored list drops it (tokens, delegation, /entities).
    let row = f.store.get_user_by_id(&f.user_id).await.unwrap().unwrap();
    assert_eq!(row.entitlements, vec![decrypt.clone()]);
    assert_eq!(
        f.store.get_user_entitlements(&f.user_id).await.unwrap(),
        vec![decrypt.clone()]
    );

    // Even a stored copy that reached the builder is not emitted while the
    // account is suspended or unqualified.
    let leaked = AuthenticatedUser::webauthn(
        f.user_id,
        vec![decrypt.clone(), publish.clone(), campaign.clone()],
    );
    f.suspend().await;
    let suspended = crate::oidc::arkavo_user_claims(&f.state, &f.patreon, &leaked).await;
    assert_eq!(suspended.effective_entitlements(), vec![decrypt.clone()]);
    f.store
        .lift_publishing_suspension(&f.user_id)
        .await
        .unwrap();
    f.state.publisher = Arc::new(None);
    let unqualified = crate::oidc::arkavo_user_claims(&f.state, &f.patreon, &leaked).await;
    assert_eq!(unqualified.effective_entitlements(), vec![decrypt.clone()]);

    // And it cannot be delegated.
    let cwt = crate::authn::mint_auth_token(&f.state, &f.user_id, None, None).unwrap();
    let app = crate::agent_plane_tests::router(f.state.clone());
    let a = fresh_agent();
    let mut body = authorize_body(&a, "", false);
    body["entitlements"] = json!([publish]);
    let (st, _) = send(
        &app,
        Request::post("/agents/authorize")
            .header("X-Auth-Token", &cwt)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(
        f.store
            .get_agent_delegation(&did_key(&a))
            .await
            .unwrap()
            .is_none()
    );
}
