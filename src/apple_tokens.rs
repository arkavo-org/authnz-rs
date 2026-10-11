//! Sign in with Apple refresh tokens, held so that account deletion can
//! revoke them (TN3194).
//!
//! When an account links Sign in with Apple (`POST /oauth/apple/link`), the
//! app sends the authorization code from the same ceremony with the
//! id_token. The server exchanges the code at Apple's token endpoint for a
//! refresh token, seals it with the Patreon KMS envelope
//! ([`crate::patreon::TokenSealer`]) and keeps it in the `apple_tokens`
//! table under the identity-link key `apple#<sub>`. When the account is
//! deleted, the sweep (`account::sweep`) revokes each token at Apple's
//! revoke endpoint. That removes the app from the person's Sign in with
//! Apple list.
//!
//! Both endpoints authenticate this server with a client secret: an ES256
//! JWT signed by the team's Sign in with Apple key, minted for each call and
//! valid for [`APPLE_CLIENT_SECRET_LIFETIME_SECONDS`].
//!
//! Configuration: `APPLE_TEAM_ID`, `APPLE_SIWA_KEY_ID`, and the `.p8` key
//! as `APPLE_SIWA_PRIVATE_KEY_PATH` (a file) or `APPLE_SIWA_PRIVATE_KEY`
//! (the PEM itself), plus `PATREON_KMS_KEY_ID` for the sealer. Without all
//! of them the link behaves as it did before: it stores the link only and
//! ignores any authorization code.
//!
//! Logging: never a token, code, client secret or Apple response body.
//! Apple failures are logged by HTTP status and Apple's `error` code.

use crate::constants::{APPLE_CLIENT_SECRET_AUDIENCE, APPLE_CLIENT_SECRET_LIFETIME_SECONDS};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

/// The team's Sign in with Apple key. It signs the client secrets.
pub struct AppleSiwaKey {
    team_id: String,
    key_id: String,
    key: EncodingKey,
}

impl fmt::Debug for AppleSiwaKey {
    // Never the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppleSiwaKey")
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// The claims of a client secret, as Apple's token and revoke endpoints
/// read them.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ClientSecretClaims {
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    pub aud: String,
    pub sub: String,
}

impl AppleSiwaKey {
    /// From the team id, the key id and the key's `.p8` PEM (PKCS#8, P-256).
    /// A PEM whose newlines were escaped as `\n` (a one-line env value) is
    /// accepted. It signs a probe secret, so a key that cannot sign is
    /// refused here, at startup, not at the first link.
    pub fn new(team_id: &str, key_id: &str, pem: &str) -> Result<Self, String> {
        let (team_id, key_id) = (team_id.trim(), key_id.trim());
        if team_id.is_empty() || key_id.is_empty() {
            return Err("the team id and key id must not be empty".into());
        }
        let pem = if pem.contains("\\n") && !pem.contains('\n') {
            pem.replace("\\n", "\n")
        } else {
            pem.to_string()
        };
        let key = EncodingKey::from_ec_pem(pem.trim().as_bytes())
            .map_err(|e| format!("not a PKCS#8 EC private key ({e})"))?;
        let siwa = Self {
            team_id: team_id.to_string(),
            key_id: key_id.to_string(),
            key,
        };
        siwa.client_secret("probe", 0)
            .map_err(|e| format!("cannot sign with the key ({e})"))?;
        Ok(siwa)
    }

    /// The client secret for `client_id` (the bundle id or Service ID the
    /// token was or will be issued to), valid from `now` for
    /// [`APPLE_CLIENT_SECRET_LIFETIME_SECONDS`].
    pub fn client_secret(&self, client_id: &str, now: i64) -> Result<String, AppleTokenError> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let claims = ClientSecretClaims {
            iss: self.team_id.clone(),
            iat: now,
            exp: now + APPLE_CLIENT_SECRET_LIFETIME_SECONDS,
            aud: APPLE_CLIENT_SECRET_AUDIENCE.to_string(),
            sub: client_id.to_string(),
        };
        jsonwebtoken::encode(&header, &claims, &self.key)
            .map_err(|e| AppleTokenError::ClientSecret(e.to_string()))
    }
}

/// The Sign in with Apple key configuration, as read from the environment.
#[derive(Debug)]
pub(crate) enum SiwaConfig {
    /// None of the variables is set.
    Off,
    /// Some are set, some are missing (named in the message).
    Incomplete(String),
    /// All are set, but the key is unusable or given twice.
    Invalid(String),
    Ready(AppleSiwaKey),
}

/// Read the key configuration from `(name, value)` pairs (the process
/// environment in production). Blank values count as unset. Messages name
/// variables, never their values.
pub(crate) fn siwa_config_from_vars<I>(vars: I) -> SiwaConfig
where
    I: IntoIterator<Item = (String, String)>,
{
    let env: HashMap<String, String> = vars
        .into_iter()
        .filter(|(_, v)| !v.trim().is_empty())
        .collect();
    let team = env.get("APPLE_TEAM_ID");
    let key_id = env.get("APPLE_SIWA_KEY_ID");
    let path = env.get("APPLE_SIWA_PRIVATE_KEY_PATH");
    let inline = env.get("APPLE_SIWA_PRIVATE_KEY");
    if team.is_none() && key_id.is_none() && path.is_none() && inline.is_none() {
        return SiwaConfig::Off;
    }
    let mut missing = Vec::new();
    if team.is_none() {
        missing.push("APPLE_TEAM_ID");
    }
    if key_id.is_none() {
        missing.push("APPLE_SIWA_KEY_ID");
    }
    if path.is_none() && inline.is_none() {
        missing.push("APPLE_SIWA_PRIVATE_KEY_PATH (or APPLE_SIWA_PRIVATE_KEY)");
    }
    if !missing.is_empty() {
        return SiwaConfig::Incomplete(format!("unset: {}", missing.join(", ")));
    }
    let pem = match (path, inline) {
        (Some(_), Some(_)) => {
            return SiwaConfig::Invalid(
                "set APPLE_SIWA_PRIVATE_KEY_PATH or APPLE_SIWA_PRIVATE_KEY, not both".into(),
            );
        }
        (Some(p), None) => match std::fs::read_to_string(p.trim()) {
            Ok(pem) => pem,
            Err(e) => return SiwaConfig::Invalid(format!("APPLE_SIWA_PRIVATE_KEY_PATH: {e}")),
        },
        (None, Some(pem)) => pem.clone(),
        (None, None) => unreachable!("checked above"),
    };
    match AppleSiwaKey::new(team.unwrap(), key_id.unwrap(), &pem) {
        Ok(key) => SiwaConfig::Ready(key),
        Err(e) => SiwaConfig::Invalid(format!("the Sign in with Apple key: {e}")),
    }
}

/// Why a call to Apple, or the sealing around it, failed.
#[derive(Debug, Error)]
pub enum AppleTokenError {
    /// The Sign in with Apple key or the KMS sealer is not configured.
    #[error("Sign in with Apple token revocation is not configured")]
    NotConfigured,
    #[error("client secret: {0}")]
    ClientSecret(String),
    /// Apple answered 4xx (not 429): the request, or this server's
    /// configuration (key, client id, secret), is wrong. `code` is Apple's
    /// `error` field.
    #[error("Apple refused the request: HTTP {status} {code}")]
    Rejected { status: u16, code: String },
    /// Apple answered 429 or 5xx, or the call failed in transit or timed out.
    #[error("Apple unavailable: {0}")]
    Unavailable(String),
    /// A 2xx whose body is not the documented token response.
    #[error("unexpected Apple response: {0}")]
    Malformed(String),
    /// KMS could not wrap or unwrap the token's key.
    #[error("KMS: {0}")]
    Kms(String),
    /// The token could not be sealed or opened (a corrupt row).
    #[error("token sealing: {0}")]
    Seal(String),
}

impl AppleTokenError {
    /// Whether retrying later cannot help: a refusal, a configuration
    /// problem or a corrupt row. The deletion sweep marks the deletion
    /// `failed` at once on one of these.
    pub fn is_permanent(&self) -> bool {
        !matches!(self, Self::Unavailable(_) | Self::Kms(_))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use base64::Engine;
    use jsonwebtoken::jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurveKeyParameters, EllipticCurveKeyType,
        Jwk,
    };
    use jsonwebtoken::{DecodingKey, Validation};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::EncodePrivateKey;

    pub(crate) const TEAM_ID: &str = "TEAM123456";
    pub(crate) const KEY_ID: &str = "SIWAKEY123";
    pub(crate) const CLIENT_ID: &str = "com.arkavo.ArkavoCreator";
    /// The `kid` of the stub Apple JWKS key that signs test id_tokens.
    pub(crate) const APPLE_KID: &str = "apple-test-kid";

    /// A fresh P-256 key: (PKCS#8 PEM with LF line endings, encoding key,
    /// public JWK with `kid`).
    pub(crate) fn p256_key(kid: &str) -> (String, EncodingKey, Jwk) {
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).unwrap();
        let secret = p256::SecretKey::from_slice(&raw).unwrap();
        let der = secret.to_pkcs8_der().unwrap();
        let pem = pem::encode_config(
            &pem::Pem::new("PRIVATE KEY", der.as_bytes().to_vec()),
            pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        );
        let point = secret.public_key().to_encoded_point(false);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwk = Jwk {
            common: CommonParameters {
                key_id: Some(kid.into()),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: jsonwebtoken::jwk::EllipticCurve::P256,
                x: b64.encode(point.x().unwrap()),
                y: b64.encode(point.y().unwrap()),
            }),
        };
        (pem, EncodingKey::from_ec_der(der.as_bytes()), jwk)
    }

    /// A Sign in with Apple key for tests, and its public half.
    pub(crate) fn siwa_key() -> (AppleSiwaKey, Jwk) {
        let (pem, _, jwk) = p256_key(KEY_ID);
        (AppleSiwaKey::new(TEAM_ID, KEY_ID, &pem).unwrap(), jwk)
    }

    /// Verify a client secret with the key's public half (signature, `aud`,
    /// `iss`, `exp`) and return its claims.
    pub(crate) fn client_secret_claims(secret: &str, jwk: &Jwk) -> ClientSecretClaims {
        let mut v = Validation::new(Algorithm::ES256);
        v.set_audience(&["https://appleid.apple.com"]);
        v.set_issuer(&[TEAM_ID]);
        jsonwebtoken::decode::<ClientSecretClaims>(secret, &DecodingKey::from_jwk(jwk).unwrap(), &v)
            .expect("a valid client secret")
            .claims
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::constants::APPLE_CLIENT_SECRET_LIFETIME_SECONDS;
    use chrono::Utc;
    use jsonwebtoken::decode_header;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn the_client_secret_is_an_es256_jwt_apple_accepts() {
        let (siwa, jwk) = siwa_key();
        let now = Utc::now().timestamp();
        let secret = siwa.client_secret(CLIENT_ID, now).unwrap();

        let header = decode_header(&secret).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some(KEY_ID));

        // Signed by the configured key; iss = team, aud = Apple, sub = client.
        let claims = client_secret_claims(&secret, &jwk);
        assert_eq!(claims.iss, TEAM_ID);
        assert_eq!(claims.aud, "https://appleid.apple.com");
        assert_eq!(claims.sub, CLIENT_ID);
        assert_eq!(claims.iat, now);
        assert_eq!(
            claims.exp - claims.iat,
            APPLE_CLIENT_SECRET_LIFETIME_SECONDS
        );
        assert_eq!(APPLE_CLIENT_SECRET_LIFETIME_SECONDS, 300);

        // Another key's public half does not verify it.
        let (_, _, other) = p256_key("other");
        let mut v = jsonwebtoken::Validation::new(Algorithm::ES256);
        v.set_audience(&["https://appleid.apple.com"]);
        assert!(
            jsonwebtoken::decode::<ClientSecretClaims>(
                &secret,
                &jsonwebtoken::DecodingKey::from_jwk(&other).unwrap(),
                &v
            )
            .is_err()
        );
    }

    #[test]
    fn no_apple_key_variables_means_revocation_is_off() {
        assert!(matches!(siwa_config_from_vars(vars(&[])), SiwaConfig::Off));
        // APPLE_CLIENT_ID alone (today's deployments) is not this feature's config.
        assert!(matches!(
            siwa_config_from_vars(vars(&[("APPLE_CLIENT_ID", CLIENT_ID)])),
            SiwaConfig::Off
        ));
        // Empty values count as unset.
        assert!(matches!(
            siwa_config_from_vars(vars(&[("APPLE_TEAM_ID", "  ")])),
            SiwaConfig::Off
        ));
    }

    #[test]
    fn a_partial_configuration_names_what_is_missing() {
        let (pem, _, _) = p256_key("k");
        match siwa_config_from_vars(vars(&[
            ("APPLE_TEAM_ID", TEAM_ID),
            ("APPLE_SIWA_PRIVATE_KEY", &pem),
        ])) {
            SiwaConfig::Incomplete(why) => assert!(why.contains("APPLE_SIWA_KEY_ID"), "{why}"),
            other => panic!("expected Incomplete, got {other:?}"),
        }
        match siwa_config_from_vars(vars(&[
            ("APPLE_TEAM_ID", TEAM_ID),
            ("APPLE_SIWA_KEY_ID", KEY_ID),
        ])) {
            SiwaConfig::Incomplete(why) => {
                assert!(why.contains("APPLE_SIWA_PRIVATE_KEY_PATH"), "{why}")
            }
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    /// Review Focus 1: how a `.p8` reaches the process.
    #[test]
    fn the_key_may_come_inline_with_escaped_newlines_or_from_a_file() {
        let (pem, _, _) = p256_key("k");
        // As pasted into a one-line env value.
        let escaped = pem.replace('\n', "\\n");
        assert!(!escaped.contains('\n'));
        assert!(matches!(
            siwa_config_from_vars(vars(&[
                ("APPLE_TEAM_ID", TEAM_ID),
                ("APPLE_SIWA_KEY_ID", KEY_ID),
                ("APPLE_SIWA_PRIVATE_KEY", &escaped),
            ])),
            SiwaConfig::Ready(_)
        ));
        // As a file (the repo's *_KEY_PATH convention).
        let path = std::env::temp_dir().join(format!("siwa-{}.p8", uuid::Uuid::new_v4()));
        std::fs::write(&path, &pem).unwrap();
        let ready = siwa_config_from_vars(vars(&[
            ("APPLE_TEAM_ID", TEAM_ID),
            ("APPLE_SIWA_KEY_ID", KEY_ID),
            ("APPLE_SIWA_PRIVATE_KEY_PATH", path.to_str().unwrap()),
        ]));
        std::fs::remove_file(&path).ok();
        assert!(matches!(ready, SiwaConfig::Ready(_)), "{ready:?}");
    }

    #[test]
    fn a_bad_or_ambiguous_key_is_invalid() {
        let (pem, _, _) = p256_key("k");
        let invalid = |pairs: &[(&str, &str)]| {
            matches!(siwa_config_from_vars(vars(pairs)), SiwaConfig::Invalid(_))
        };
        assert!(invalid(&[
            ("APPLE_TEAM_ID", TEAM_ID),
            ("APPLE_SIWA_KEY_ID", KEY_ID),
            ("APPLE_SIWA_PRIVATE_KEY", "not a pem"),
        ]));
        assert!(invalid(&[
            ("APPLE_TEAM_ID", TEAM_ID),
            ("APPLE_SIWA_KEY_ID", KEY_ID),
            ("APPLE_SIWA_PRIVATE_KEY", &pem),
            ("APPLE_SIWA_PRIVATE_KEY_PATH", "/tmp/x.p8"),
        ]));
        match siwa_config_from_vars(vars(&[
            ("APPLE_TEAM_ID", TEAM_ID),
            ("APPLE_SIWA_KEY_ID", KEY_ID),
            ("APPLE_SIWA_PRIVATE_KEY_PATH", "/nonexistent/AuthKey.p8"),
        ])) {
            // The message names the variable, never the key.
            SiwaConfig::Invalid(why) => {
                assert!(why.contains("APPLE_SIWA_PRIVATE_KEY_PATH"), "{why}")
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn only_refusals_and_configuration_problems_are_permanent() {
        assert!(AppleTokenError::NotConfigured.is_permanent());
        assert!(AppleTokenError::ClientSecret("x".into()).is_permanent());
        assert!(
            AppleTokenError::Rejected {
                status: 400,
                code: "invalid_client".into()
            }
            .is_permanent()
        );
        assert!(AppleTokenError::Malformed("x".into()).is_permanent());
        assert!(AppleTokenError::Seal("x".into()).is_permanent());
        assert!(!AppleTokenError::Unavailable("HTTP 503".into()).is_permanent());
        assert!(!AppleTokenError::Kms("throttled".into()).is_permanent());
    }
}
