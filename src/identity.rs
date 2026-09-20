//! Federated identity resolution.
//!
//! An Apple or Google identity reaches an Arkavo account through exactly one
//! path: a row in the `identity_links` table, written by an authenticated
//! linking call (`POST /oauth/apple/link`, `POST /oauth/google/link`).
//!
//! Sign-in **never** provisions. Before this module, `map_apple_user` and
//! `map_google_user` called `create_user` on first sight of an unseen `sub`,
//! creating a credential-less account addressable by a synthetic
//! `apple-<sub>` / `google-<sub>` username. That made the IdP subject — a
//! value published in every `id_token` — sufficient to bring an Arkavo
//! account into existence, and (until the registration namespace was closed)
//! to enroll a passkey onto one.

use crate::db::{DynamoDBError, DynamoDBStore, UserCredentials};
use log::{error, warn};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityResolveError {
    /// No `identity_links` row binds this IdP subject to an Arkavo account.
    /// The caller must register a passkey and link before signing in this way.
    #[error("identity is not linked to an Arkavo account")]
    NotLinked,
    #[error("identity lookup failed: {0}")]
    Db(#[from] DynamoDBError),
}

/// Resolve `(provider, subject)` to the Arkavo account it is linked to.
///
/// A link that points at a missing user row resolves as [`NotLinked`] rather
/// than an error: the account is gone, so there is nothing to sign in as, and
/// failing closed is the only safe reading.
///
/// [`NotLinked`]: IdentityResolveError::NotLinked
pub async fn resolve_linked_account(
    db: &DynamoDBStore,
    provider: &str,
    subject: &str,
) -> Result<UserCredentials, IdentityResolveError> {
    let Some(user_id) = db.get_identity_link(provider, subject).await? else {
        return Err(IdentityResolveError::NotLinked);
    };

    match db.get_user_by_id(&user_id).await? {
        Some(record) => Ok(record),
        None => {
            error!(
                "identity_links row for provider={} points at missing user {}",
                provider, user_id
            );
            warn!("Treating dangling identity link as unlinked (fail closed)");
            Err(IdentityResolveError::NotLinked)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    use crate::db::tests::local_store;

    #[tokio::test]
    async fn resolves_a_linked_subject_to_its_account() {
        let Some(store) = local_store() else {
            return;
        };
        let username = format!("user-{}", Uuid::new_v4());
        let account = store
            .create_user(&username, "did:key:zTestResolve")
            .await
            .expect("user creation should succeed");
        let subject = format!("sub-{}", Uuid::new_v4());
        store
            .link_identity(account.user_id, "google", &subject)
            .await
            .expect("link write should succeed");

        let resolved = resolve_linked_account(&store, "google", &subject)
            .await
            .expect("linked subject should resolve");
        assert_eq!(resolved.user_id, account.user_id);
        assert_eq!(resolved.username, username);
    }

    #[tokio::test]
    async fn refuses_an_unlinked_subject_instead_of_provisioning() {
        let Some(store) = local_store() else {
            return;
        };
        let subject = format!("unlinked-{}", Uuid::new_v4());

        let err = resolve_linked_account(&store, "google", &subject)
            .await
            .expect_err("an unlinked subject must not resolve");
        assert!(matches!(err, IdentityResolveError::NotLinked));

        // And nothing was created on the way past.
        assert_eq!(
            store.get_identity_link("google", &subject).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn google_resolution_uses_the_stable_arkavo_subject() {
        let Some(store) = local_store() else {
            return;
        };
        let account = store
            .create_user(&format!("user-{}", Uuid::new_v4()), "did:key:zTestGoogle")
            .await
            .expect("user creation should succeed");
        let sub = format!("sub-{}", Uuid::new_v4());
        store
            .link_identity(account.user_id, "google", &sub)
            .await
            .expect("link write should succeed");

        let claims = crate::google_signin::GoogleIdTokenClaims {
            iss: "https://accounts.google.com".into(),
            sub: sub.clone(),
            aud: "client".into(),
            iat: 0,
            exp: 0,
            nonce: None,
            email: Some("  User@Example.COM ".into()),
            email_verified: None,
            name: Some("A User".into()),
            hd: None,
        };

        let user = crate::google_signin::resolve_google_user(&store, &claims)
            .await
            .expect("linked Google identity should resolve");

        // One human, one account, one subject — regardless of how they signed
        // in. `google:<sub>` would give an RP a second identity for the same
        // person once they also use their passkey.
        assert_eq!(user.subject, format!("arkavo:{}", account.user_id));
        assert_eq!(user.arkavo_account_id, account.user_id.to_string());
        assert_eq!(user.idp, "google");
        assert_eq!(user.email.as_deref(), Some("user@example.com"));
        assert_eq!(user.name.as_deref(), Some("A User"));
        assert_eq!(user.entitlements, account.entitlements);
    }

    #[tokio::test]
    async fn google_resolution_refuses_an_unlinked_subject() {
        let Some(store) = local_store() else {
            return;
        };
        let claims = crate::google_signin::GoogleIdTokenClaims {
            iss: "https://accounts.google.com".into(),
            sub: format!("unlinked-{}", Uuid::new_v4()),
            aud: "client".into(),
            iat: 0,
            exp: 0,
            nonce: None,
            email: None,
            email_verified: None,
            name: None,
            hd: None,
        };
        let err = crate::google_signin::resolve_google_user(&store, &claims)
            .await
            .expect_err("an unlinked Google identity must not resolve");
        assert!(matches!(err, IdentityResolveError::NotLinked));
    }

    #[tokio::test]
    async fn apple_resolution_uses_the_stable_arkavo_subject() {
        let Some(store) = local_store() else {
            return;
        };
        let account = store
            .create_user(&format!("user-{}", Uuid::new_v4()), "did:key:zTestApple")
            .await
            .expect("user creation should succeed");
        let sub = format!("000{}.apple", Uuid::new_v4());
        store
            .link_identity(account.user_id, "apple", &sub)
            .await
            .expect("link write should succeed");

        let claims = crate::apple_signin::AppleIdTokenClaims {
            iss: crate::constants::APPLE_ISSUER.to_string(),
            sub: sub.clone(),
            aud: "com.arkavo.app".into(),
            exp: 0,
            iat: 0,
            nonce: None,
            email: Some("relay@privaterelay.appleid.com".into()),
            email_verified: None,
            is_private_email: None,
        };

        let user = crate::apple_signin::resolve_apple_user(&store, &claims)
            .await
            .expect("linked Apple identity should resolve");
        assert_eq!(user.subject, format!("arkavo:{}", account.user_id));
        assert_eq!(user.idp, "apple");
    }

    #[tokio::test]
    async fn refuses_a_link_pointing_at_a_missing_account() {
        let Some(store) = local_store() else {
            return;
        };
        let subject = format!("dangling-{}", Uuid::new_v4());
        store
            .link_identity(Uuid::new_v4(), "apple", &subject)
            .await
            .expect("link write should succeed");

        let err = resolve_linked_account(&store, "apple", &subject)
            .await
            .expect_err("a dangling link must fail closed");
        assert!(matches!(err, IdentityResolveError::NotLinked));
    }
}
