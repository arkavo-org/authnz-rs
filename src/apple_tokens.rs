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

use crate::constants::{
    APPLE_CLIENT_SECRET_AUDIENCE, APPLE_CLIENT_SECRET_LIFETIME_SECONDS, APPLE_REVOKE_URL,
    APPLE_TOKEN_HTTP_TIMEOUT_SECS, APPLE_TOKEN_URL,
};
use crate::patreon::{PatreonError, SealedToken, TokenSealer};
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

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

/// Apple's token and revoke endpoints. Fixed in production
/// ([`AppleEndpoints::production`]); tests point them at a stub.
#[derive(Debug, Clone)]
pub struct AppleEndpoints {
    pub token_url: String,
    pub revoke_url: String,
}

impl AppleEndpoints {
    pub fn production() -> Self {
        Self {
            token_url: APPLE_TOKEN_URL.to_string(),
            revoke_url: APPLE_REVOKE_URL.to_string(),
        }
    }
}

/// What Apple's token endpoint returned for an authorization code.
pub struct ExchangedTokens {
    pub refresh_token: String,
    pub id_token: String,
}

impl fmt::Debug for ExchangedTokens {
    // Never the tokens.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExchangedTokens { .. }")
    }
}

/// A stored refresh token (`apple_tokens` table, `db::apple_tokens`).
#[derive(Clone)]
pub struct AppleTokenRow {
    /// `apple#<sub>`: the identity-link key ([`apple_link_key`]).
    pub link_key: String,
    /// The account that linked the identity.
    pub user_id: Uuid,
    /// The bundle id or Service ID the token was issued to. Revocation
    /// presents it.
    pub client_id: String,
    pub sealed: SealedToken,
    pub stored_at: i64,
}

impl fmt::Debug for AppleTokenRow {
    // Not the key: it holds the full Apple `sub`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppleTokenRow")
            .field("user_id", &self.user_id)
            .field("client_id", &self.client_id)
            .field("stored_at", &self.stored_at)
            .finish_non_exhaustive()
    }
}

/// The identity-link key of an Apple `sub`: the `identity_links` `link_pk`,
/// and the `apple_tokens` `link_key`.
pub fn apple_link_key(sub: &str) -> String {
    format!("apple#{sub}")
}

/// What the link handler and the deletion sweep need in order to obtain and
/// revoke Apple refresh tokens. An axum `Extension`. Disabled unless the Sign
/// in with Apple key and the KMS sealer are both configured ([`from_env`]).
#[derive(Clone)]
pub struct AppleTokens {
    inner: Option<Arc<Enabled>>,
}

struct Enabled {
    siwa: AppleSiwaKey,
    sealer: TokenSealer,
    http: reqwest::Client,
    endpoints: AppleEndpoints,
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    #[serde(default)]
    error: Option<String>,
}

/// Classify a non-2xx answer. A 4xx other than 429 is a refusal (keeps
/// Apple's sanitized `error` code); 429, 5xx and anything else are
/// transient. Same split as `patreon::token_exchange_error`.
fn apple_failure(status: reqwest::StatusCode, body: &str) -> AppleTokenError {
    if status.is_client_error() && status != reqwest::StatusCode::TOO_MANY_REQUESTS {
        let code = serde_json::from_str::<ErrorResponse>(body)
            .ok()
            .and_then(|b| b.error)
            .map(|c| crate::google_signin::sanitize_error(&c))
            .filter(|c| !c.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        AppleTokenError::Rejected {
            status: status.as_u16(),
            code,
        }
    } else {
        AppleTokenError::Unavailable(format!("HTTP {}", status.as_u16()))
    }
}

fn transport(e: reqwest::Error) -> AppleTokenError {
    if e.is_timeout() {
        AppleTokenError::Unavailable("timed out".into())
    } else {
        AppleTokenError::Unavailable(e.without_url().to_string())
    }
}

fn from_sealer(e: PatreonError) -> AppleTokenError {
    match e {
        PatreonError::Kms(m) => AppleTokenError::Kms(m),
        other => AppleTokenError::Seal(other.to_string()),
    }
}

impl AppleTokens {
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    pub fn new(
        siwa: AppleSiwaKey,
        sealer: TokenSealer,
        endpoints: AppleEndpoints,
        timeout: Duration,
    ) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("authnz-rs/", env!("CARGO_PKG_VERSION")))
            .timeout(timeout)
            // The forms carry the client secret and a code or refresh token:
            // a 3xx is never followed. It lands in `apple_failure` as transient.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            // Only fails when the TLS backend cannot initialize: fatal at startup.
            .expect("failed to build the Apple token HTTP client");
        Self {
            inner: Some(Arc::new(Enabled {
                siwa,
                sealer,
                http,
                endpoints,
            })),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    fn enabled(&self) -> Result<&Enabled, AppleTokenError> {
        self.inner.as_deref().ok_or(AppleTokenError::NotConfigured)
    }

    /// Exchange an authorization code issued to `client_id`. There is no
    /// `redirect_uri`: codes from a native ceremony have none. A response
    /// that carries a refresh token but no id_token is refused, and that
    /// token is revoked.
    pub async fn exchange_code(
        &self,
        client_id: &str,
        code: &str,
    ) -> Result<ExchangedTokens, AppleTokenError> {
        let e = self.enabled()?;
        let secret = e.siwa.client_secret(client_id, Utc::now().timestamp())?;
        let form = [
            ("client_id", client_id),
            ("client_secret", secret.as_str()),
            ("code", code),
            ("grant_type", "authorization_code"),
        ];
        let resp = e
            .http
            .post(&e.endpoints.token_url)
            .form(&form)
            .send()
            .await
            .map_err(transport)?;
        let status = resp.status();
        if !status.is_success() {
            // A refusal stays a refusal even when its body cannot be read.
            let body = resp.text().await.unwrap_or_default();
            return Err(apple_failure(status, &body));
        }
        let body = resp.text().await.map_err(transport)?;
        let parsed: TokenResponse = serde_json::from_str(&body).map_err(|_| {
            AppleTokenError::Malformed("token response is not the documented JSON".into())
        })?;
        let refresh_token = parsed.refresh_token.filter(|t| !t.is_empty());
        let id_token = parsed.id_token.filter(|t| !t.is_empty());
        match (refresh_token, id_token) {
            (Some(refresh_token), Some(id_token)) => Ok(ExchangedTokens {
                refresh_token,
                id_token,
            }),
            (Some(refresh_token), None) => {
                self.revoke_quietly(client_id, &refresh_token, "token response without id_token")
                    .await;
                Err(AppleTokenError::Malformed(
                    "token response lacks id_token".into(),
                ))
            }
            (None, _) => Err(AppleTokenError::Malformed(
                "token response lacks refresh_token".into(),
            )),
        }
    }

    /// Revoke a refresh token issued to `client_id`. Apple answers 200 for a
    /// token it already considers invalid (RFC 7009), so a 200 always means
    /// the token is unusable.
    pub async fn revoke(
        &self,
        client_id: &str,
        refresh_token: &str,
    ) -> Result<(), AppleTokenError> {
        let e = self.enabled()?;
        let secret = e.siwa.client_secret(client_id, Utc::now().timestamp())?;
        let form = [
            ("client_id", client_id),
            ("client_secret", secret.as_str()),
            ("token", refresh_token),
            ("token_type_hint", "refresh_token"),
        ];
        let resp = e
            .http
            .post(&e.endpoints.revoke_url)
            .form(&form)
            .send()
            .await
            .map_err(transport)?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        Err(apple_failure(status, &body))
    }

    /// Revoke where the request is already failing for another reason: a
    /// failure is logged (status and Apple's code only), never returned.
    pub async fn revoke_quietly(&self, client_id: &str, refresh_token: &str, why: &str) {
        if let Err(e) = self.revoke(client_id, refresh_token).await {
            error!("audit apple_token outcome=revoke_failed reason={why}: {e}");
        }
    }

    pub async fn seal(&self, refresh_token: &str) -> Result<SealedToken, AppleTokenError> {
        self.enabled()?
            .sealer
            .seal(refresh_token.as_bytes())
            .await
            .map_err(from_sealer)
    }

    pub async fn open(&self, sealed: &SealedToken) -> Result<String, AppleTokenError> {
        let bytes = self
            .enabled()?
            .sealer
            .open(sealed)
            .await
            .map_err(from_sealer)?;
        String::from_utf8(bytes)
            .map_err(|_| AppleTokenError::Seal("sealed token is not UTF-8".into()))
    }

    /// Revoke a stored token: open it, then revoke it for the client it was
    /// issued to.
    pub async fn revoke_stored(&self, row: &AppleTokenRow) -> Result<(), AppleTokenError> {
        let token = self.open(&row.sealed).await?;
        self.revoke(&row.client_id, &token).await
    }
}

/// Build from the process environment and the Patreon KMS sealer
/// (`PatreonState::sealer`), logging why revocation is off when it is.
pub fn from_env(sealer: Option<TokenSealer>) -> AppleTokens {
    from_parts(siwa_config_from_vars(std::env::vars()), sealer)
}

pub(crate) fn from_parts(siwa: SiwaConfig, sealer: Option<TokenSealer>) -> AppleTokens {
    const OFF: &str = "Apple links are stored without a token, so account deletion \
                       cannot revoke them with Apple";
    match (siwa, sealer) {
        (SiwaConfig::Ready(siwa), Some(sealer)) => {
            info!(
                "Sign in with Apple token revocation enabled (team {}, key {})",
                siwa.team_id, siwa.key_id
            );
            AppleTokens::new(
                siwa,
                sealer,
                AppleEndpoints::production(),
                Duration::from_secs(APPLE_TOKEN_HTTP_TIMEOUT_SECS),
            )
        }
        (SiwaConfig::Ready(_), None) => {
            error!(
                "The Sign in with Apple key is configured but PATREON_KMS_KEY_ID is not, \
                 so the tokens cannot be sealed: {}",
                OFF
            );
            AppleTokens::disabled()
        }
        (SiwaConfig::Off, _) => {
            warn!(
                "APPLE_TEAM_ID, APPLE_SIWA_KEY_ID and APPLE_SIWA_PRIVATE_KEY_PATH are unset: {}",
                OFF
            );
            AppleTokens::disabled()
        }
        (SiwaConfig::Incomplete(why), _) => {
            warn!(
                "Sign in with Apple token revocation is off ({}): {}",
                why, OFF
            );
            AppleTokens::disabled()
        }
        (SiwaConfig::Invalid(why), _) => {
            error!(
                "Sign in with Apple token revocation is off ({}): {}",
                why, OFF
            );
            AppleTokens::disabled()
        }
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

    use axum::extract::State;
    use axum::response::IntoResponse;
    use serde_json::{Value, json};
    use std::sync::Mutex;

    /// Sign in with Apple, enabled, against `stub`, sealing with the test
    /// sealer, and the public half of its client-secret key.
    pub(crate) fn tokens_and_key(stub: &StubApple) -> (AppleTokens, Jwk) {
        let (siwa, jwk) = siwa_key();
        (
            AppleTokens::new(
                siwa,
                TokenSealer::Plaintext,
                stub.endpoints(),
                Duration::from_secs(5),
            ),
            jwk,
        )
    }

    pub(crate) fn tokens(stub: &StubApple) -> AppleTokens {
        tokens_and_key(stub).0
    }

    /// Claims of an Apple id_token for `sub`, issued to `aud`, with `nonce`
    /// when given.
    pub(crate) fn apple_claims(sub: &str, aud: &str, nonce: Option<&str>) -> Value {
        let now = Utc::now().timestamp();
        let mut c = json!({
            "iss": "https://appleid.apple.com", "sub": sub, "aud": aud,
            "iat": now, "exp": now + 600,
        });
        if let Some(n) = nonce {
            c["nonce"] = n.into();
        }
        c
    }

    /// Sign `claims` as the stub Apple key (`kid` = [`APPLE_KID`]) would.
    pub(crate) fn sign_apple_id_token(key: &EncodingKey, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(APPLE_KID.into());
        jsonwebtoken::encode(&header, claims, key).unwrap()
    }

    #[derive(Clone)]
    struct StubState {
        calls: Arc<Mutex<Vec<(String, HashMap<String, String>)>>>,
        token_reply: Arc<Mutex<(u16, Value)>>,
        revoke_reply: Arc<Mutex<(u16, Value)>>,
        /// When set, the token / revoke endpoint answers 307 to this path
        /// instead of its scripted reply.
        token_redirect: Arc<Mutex<Option<String>>>,
        revoke_redirect: Arc<Mutex<Option<String>>>,
        jwks: Value,
    }

    fn temporary_redirect(to: &str) -> axum::response::Response {
        (
            axum::http::StatusCode::TEMPORARY_REDIRECT,
            [(axum::http::header::LOCATION, to.to_string())],
        )
            .into_response()
    }

    async fn stub_elsewhere(
        State(s): State<StubState>,
        axum::Form(form): axum::Form<HashMap<String, String>>,
    ) -> axum::http::StatusCode {
        s.calls
            .lock()
            .unwrap()
            .push(("/auth/elsewhere".into(), form));
        axum::http::StatusCode::OK
    }

    async fn stub_keys(State(s): State<StubState>) -> axum::Json<Value> {
        axum::Json(s.jwks)
    }

    async fn stub_token(
        State(s): State<StubState>,
        axum::Form(form): axum::Form<HashMap<String, String>>,
    ) -> axum::response::Response {
        s.calls.lock().unwrap().push(("/auth/token".into(), form));
        if let Some(to) = s.token_redirect.lock().unwrap().clone() {
            return temporary_redirect(&to);
        }
        let (status, body) = s.token_reply.lock().unwrap().clone();
        (
            axum::http::StatusCode::from_u16(status).unwrap(),
            axum::Json(body),
        )
            .into_response()
    }

    async fn stub_revoke(
        State(s): State<StubState>,
        axum::Form(form): axum::Form<HashMap<String, String>>,
    ) -> axum::response::Response {
        s.calls.lock().unwrap().push(("/auth/revoke".into(), form));
        if let Some(to) = s.revoke_redirect.lock().unwrap().clone() {
            return temporary_redirect(&to);
        }
        let (status, body) = s.revoke_reply.lock().unwrap().clone();
        (
            axum::http::StatusCode::from_u16(status).unwrap(),
            axum::Json(body),
        )
            .into_response()
    }

    /// Stand-in for appleid.apple.com on 127.0.0.1: `GET /auth/keys` (the
    /// given JWKS), `POST /auth/token` and `POST /auth/revoke` (configurable
    /// replies; every form is recorded). Token replies default to a 500;
    /// revoke replies to a 200.
    #[derive(Clone)]
    pub(crate) struct StubApple {
        base: String,
        state: StubState,
    }

    impl StubApple {
        pub(crate) async fn start(keys: Vec<Jwk>) -> Self {
            let state = StubState {
                calls: Arc::new(Mutex::new(Vec::new())),
                token_reply: Arc::new(Mutex::new((500, json!({"error": "server_error"})))),
                revoke_reply: Arc::new(Mutex::new((200, Value::Null))),
                token_redirect: Arc::new(Mutex::new(None)),
                revoke_redirect: Arc::new(Mutex::new(None)),
                jwks: json!({ "keys": keys }),
            };
            let app = axum::Router::new()
                .route("/auth/keys", axum::routing::get(stub_keys))
                .route("/auth/token", axum::routing::post(stub_token))
                .route("/auth/revoke", axum::routing::post(stub_revoke))
                .route("/auth/elsewhere", axum::routing::post(stub_elsewhere))
                .with_state(state.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            Self { base, state }
        }

        pub(crate) fn jwks_url(&self) -> String {
            format!("{}/auth/keys", self.base)
        }

        pub(crate) fn endpoints(&self) -> AppleEndpoints {
            AppleEndpoints {
                token_url: format!("{}/auth/token", self.base),
                revoke_url: format!("{}/auth/revoke", self.base),
            }
        }

        pub(crate) fn reply_token(&self, status: u16, body: Value) {
            *self.state.token_reply.lock().unwrap() = (status, body);
        }

        pub(crate) fn reply_revoke(&self, status: u16, body: Value) {
            *self.state.revoke_reply.lock().unwrap() = (status, body);
        }

        /// Answer the token endpoint with a 307 to `/auth/elsewhere`.
        pub(crate) fn redirect_token(&self) {
            *self.state.token_redirect.lock().unwrap() = Some("/auth/elsewhere".into());
        }

        /// Answer the revoke endpoint with a 307 to `/auth/elsewhere`.
        pub(crate) fn redirect_revoke(&self) {
            *self.state.revoke_redirect.lock().unwrap() = Some("/auth/elsewhere".into());
        }

        /// The forms posted to `path`, oldest first.
        pub(crate) fn calls(&self, path: &str) -> Vec<HashMap<String, String>> {
            self.state
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(p, _)| p == path)
                .map(|(_, f)| f.clone())
                .collect()
        }

        /// The `token` of every revoke call, oldest first.
        pub(crate) fn revoked(&self) -> Vec<String> {
            self.calls("/auth/revoke")
                .into_iter()
                .filter_map(|f| f.get("token").cloned())
                .collect()
        }
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
        // Both forms given, each valid on its own: only the "not both" rule
        // can refuse this.
        let path = std::env::temp_dir().join(format!("siwa-{}.p8", uuid::Uuid::new_v4()));
        std::fs::write(&path, &pem).unwrap();
        let both = siwa_config_from_vars(vars(&[
            ("APPLE_TEAM_ID", TEAM_ID),
            ("APPLE_SIWA_KEY_ID", KEY_ID),
            ("APPLE_SIWA_PRIVATE_KEY", &pem),
            ("APPLE_SIWA_PRIVATE_KEY_PATH", path.to_str().unwrap()),
        ]));
        std::fs::remove_file(&path).ok();
        match both {
            SiwaConfig::Invalid(why) => assert!(why.contains("not both"), "{why}"),
            other => panic!("expected Invalid, got {other:?}"),
        }
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

    use crate::patreon::TokenSealer;
    use serde_json::json;
    use std::time::{Duration, Instant};

    #[test]
    fn apples_endpoints_are_fixed() {
        let p = AppleEndpoints::production();
        assert_eq!(p.token_url, "https://appleid.apple.com/auth/token");
        assert_eq!(p.revoke_url, "https://appleid.apple.com/auth/revoke");
        assert_eq!(apple_link_key("001234.abc"), "apple#001234.abc");
    }

    #[tokio::test]
    async fn the_exchange_posts_the_code_with_a_client_secret_for_that_client() {
        let stub = StubApple::start(vec![]).await;
        let (apple, jwk) = tokens_and_key(&stub);
        stub.reply_token(
            200,
            json!({"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
                   "refresh_token": "rt-1", "id_token": "idt-1"}),
        );
        let got = apple.exchange_code(CLIENT_ID, "code-1").await.unwrap();
        assert_eq!(got.refresh_token, "rt-1");
        assert_eq!(got.id_token, "idt-1");

        let calls = stub.calls("/auth/token");
        assert_eq!(calls.len(), 1);
        let form = &calls[0];
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "code-1");
        assert_eq!(form["client_id"], CLIENT_ID);
        // Native-app codes have no redirect URI; the form must not invent one.
        assert!(!form.contains_key("redirect_uri"), "{form:?}");
        assert_eq!(
            client_secret_claims(&form["client_secret"], &jwk).sub,
            CLIENT_ID
        );
    }

    #[tokio::test]
    async fn exchange_failures_are_classified() {
        let stub = StubApple::start(vec![]).await;
        let apple = tokens(&stub);

        // A used or expired code: Apple's 400 invalid_grant.
        stub.reply_token(400, json!({"error": "invalid_grant"}));
        match apple.exchange_code(CLIENT_ID, "used").await {
            Err(AppleTokenError::Rejected { status: 400, code }) => {
                assert_eq!(code, "invalid_grant")
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        stub.reply_token(503, json!({}));
        assert!(matches!(
            apple.exchange_code(CLIENT_ID, "c").await,
            Err(AppleTokenError::Unavailable(_))
        ));
        // A refresh token without its id_token cannot be bound to the
        // identity: it is revoked, not dropped.
        stub.reply_revoke(200, json!(null));
        stub.reply_token(
            200,
            json!({"access_token": "at", "refresh_token": "rt-orphan"}),
        );
        assert!(matches!(
            apple.exchange_code(CLIENT_ID, "c").await,
            Err(AppleTokenError::Malformed(_))
        ));
        assert_eq!(stub.revoked(), vec!["rt-orphan".to_string()]);
        stub.reply_token(200, json!("not an object"));
        assert!(matches!(
            apple.exchange_code(CLIENT_ID, "c").await,
            Err(AppleTokenError::Malformed(_))
        ));
    }

    /// The form carries the client secret and a code or refresh token, so a
    /// 3xx is never followed. It is "later", not "never".
    #[tokio::test]
    async fn a_redirect_from_apple_is_not_followed() {
        let stub = StubApple::start(vec![]).await;
        let apple = tokens(&stub);

        stub.redirect_token();
        let err = apple.exchange_code(CLIENT_ID, "c").await.unwrap_err();
        assert!(matches!(err, AppleTokenError::Unavailable(_)), "{err:?}");
        assert!(!err.is_permanent());
        assert_eq!(stub.calls("/auth/token").len(), 1);

        stub.redirect_revoke();
        let err = apple.revoke(CLIENT_ID, "rt").await.unwrap_err();
        assert!(matches!(err, AppleTokenError::Unavailable(_)), "{err:?}");
        assert!(!err.is_permanent());
        assert_eq!(stub.calls("/auth/revoke").len(), 1);

        assert!(stub.calls("/auth/elsewhere").is_empty());
    }

    /// Review Focus 2: a 429 is "later", not "never".
    #[tokio::test]
    async fn revoke_posts_the_refresh_token_and_classifies_apples_answer() {
        let stub = StubApple::start(vec![]).await;
        let (apple, jwk) = tokens_and_key(&stub);

        stub.reply_revoke(200, json!(null));
        apple.revoke(CLIENT_ID, "rt-1").await.unwrap();
        let form = &stub.calls("/auth/revoke")[0];
        assert_eq!(form["token"], "rt-1");
        assert_eq!(form["token_type_hint"], "refresh_token");
        assert_eq!(form["client_id"], CLIENT_ID);
        assert_eq!(
            client_secret_claims(&form["client_secret"], &jwk).sub,
            CLIENT_ID
        );

        // A 4xx other than 429: the request or our configuration; retrying cannot help.
        for code in [
            "invalid_client",
            "invalid_request",
            "unsupported_token_type",
        ] {
            stub.reply_revoke(400, json!({ "error": code }));
            let e = apple.revoke(CLIENT_ID, "rt-1").await.unwrap_err();
            assert!(e.is_permanent(), "{e}");
            assert!(e.to_string().contains(code), "{e}");
        }
        // Apple's error code is sanitized before it reaches a log line.
        stub.reply_revoke(401, json!({"error": "bad\nline injected"}));
        let e = apple.revoke(CLIENT_ID, "rt-1").await.unwrap_err();
        assert!(!e.to_string().contains('\n'), "{e}");
        // 429 and 5xx: transient.
        for status in [429u16, 500, 503] {
            stub.reply_revoke(status, json!({}));
            let e = apple.revoke(CLIENT_ID, "rt-1").await.unwrap_err();
            assert!(!e.is_permanent(), "{status}: {e}");
        }
    }

    #[tokio::test]
    async fn a_stalled_apple_fails_fast_and_transiently() {
        // Accepts connections, never answers: a black-holed appleid.apple.com.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let (siwa, _) = siwa_key();
        let apple = AppleTokens::new(
            siwa,
            TokenSealer::Plaintext,
            AppleEndpoints {
                token_url: format!("http://{addr}/auth/token"),
                revoke_url: format!("http://{addr}/auth/revoke"),
            },
            Duration::from_millis(300),
        );
        let start = Instant::now();
        let e = apple.revoke(CLIENT_ID, "rt").await.unwrap_err();
        assert!(!e.is_permanent(), "{e}");
        let e = apple.exchange_code(CLIENT_ID, "c").await.unwrap_err();
        assert!(matches!(e, AppleTokenError::Unavailable(_)), "{e}");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn a_stored_token_is_opened_and_revoked_for_its_own_client() {
        let stub = StubApple::start(vec![]).await;
        let apple = tokens(&stub);
        stub.reply_revoke(200, json!(null));
        let row = AppleTokenRow {
            link_key: apple_link_key("001234.abc"),
            user_id: uuid::Uuid::new_v4(),
            client_id: "com.arkavo.web".into(),
            sealed: apple.seal("rt-9").await.unwrap(),
            stored_at: 0,
        };
        assert_ne!(
            row.sealed.ciphertext,
            b"rt-9".to_vec(),
            "stored in the clear"
        );
        assert_eq!(apple.open(&row.sealed).await.unwrap(), "rt-9");
        apple.revoke_stored(&row).await.unwrap();
        let form = &stub.calls("/auth/revoke")[0];
        assert_eq!(form["token"], "rt-9");
        assert_eq!(form["client_id"], "com.arkavo.web");
    }

    #[tokio::test]
    async fn disabled_tokens_refuse_everything_permanently() {
        let off = AppleTokens::disabled();
        assert!(!off.is_enabled());
        let e = off.revoke(CLIENT_ID, "rt").await.unwrap_err();
        assert!(matches!(e, AppleTokenError::NotConfigured));
        assert!(e.is_permanent());
        assert!(matches!(
            off.exchange_code(CLIENT_ID, "c").await,
            Err(AppleTokenError::NotConfigured)
        ));
        assert!(matches!(
            off.seal("rt").await,
            Err(AppleTokenError::NotConfigured)
        ));
    }

    #[tokio::test]
    async fn revocation_needs_both_the_key_and_the_sealer() {
        let ready = || SiwaConfig::Ready(siwa_key().0);
        assert!(from_parts(ready(), Some(TokenSealer::Plaintext)).is_enabled());
        assert!(!from_parts(ready(), None).is_enabled());
        assert!(!from_parts(SiwaConfig::Off, Some(TokenSealer::Plaintext)).is_enabled());
        assert!(
            !from_parts(
                SiwaConfig::Incomplete("x".into()),
                Some(TokenSealer::Plaintext)
            )
            .is_enabled()
        );
        assert!(
            !from_parts(
                SiwaConfig::Invalid("x".into()),
                Some(TokenSealer::Plaintext)
            )
            .is_enabled()
        );
    }
}
