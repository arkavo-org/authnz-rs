//! End-to-end agent delegation flow against a running authnz-rs + DynamoDB Local.
//! Ignored unless AUTHNZ_TEST_BASE_URL is set (CI sets it after starting the server).
//!
//! Precondition: a user row exists (seeded by `src/bin/seed-test-user.rs` directly
//! in DynamoDB) and the server was started with a known CWT signing key so the
//! seed bin can mint a human CWT (`AUTHNZ_TEST_HUMAN_CWT`) and a service CWT
//! (`AUTHNZ_TEST_SERVICE_CWT`, `arkavo_roles: ["service-account"]`) that verify
//! against it.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Fixed seed user id — must match `src/bin/seed-test-user.rs`.
const SEED_USER_ID: &str = "00000000-0000-0000-0000-0000000000aa";

fn base() -> Option<String> {
    std::env::var("AUTHNZ_TEST_BASE_URL").ok()
}

fn did_key(sk: &SigningKey) -> String {
    let mut b = vec![0xed, 0x01];
    b.extend_from_slice(sk.verifying_key().as_bytes());
    format!("did:key:z{}", bs58::encode(b).into_string())
}

#[tokio::test]
#[ignore = "requires AUTHNZ_TEST_BASE_URL + DynamoDB Local"]
async fn authorize_challenge_token_refresh_revoke() {
    let Some(base) = base() else { return };
    let client = reqwest::Client::new();
    let human_cwt = std::env::var("AUTHNZ_TEST_HUMAN_CWT").expect("seeded human CWT");
    let service_cwt = std::env::var("AUTHNZ_TEST_SERVICE_CWT").expect("seeded service CWT");
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let did = did_key(&sk);

    // Replace the seed user's default entitlements with a smaller, explicit
    // list first, so the authorize subset check below runs against a stored
    // (non-default) list rather than falling back to DEFAULT_USER_ENTITLEMENTS.
    let r = client
        .put(format!("{base}/admin/users/{SEED_USER_ID}/entitlements"))
        .header("X-Auth-Token", &service_cwt)
        .json(&json!({"entitlements": [
            "https://arkavo.ai/attr/tdf/value/decrypt",
            "https://arkavo.ai/attr/action/value/read"
        ]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());

    // authorize — delegate both entitlements the delegator currently holds,
    // so the later stale-entitlements step (I2) has something to intersect
    // against a stored set that only keeps one of them.
    let r = client
        .post(format!("{base}/agents/authorize"))
        .header("X-Auth-Token", &human_cwt)
        .json(
            &json!({"agent_did": did, "name": "it-agent", "entitlements": [
                "https://arkavo.ai/attr/tdf/value/decrypt",
                "https://arkavo.ai/attr/action/value/read"
            ], "swarm": "it-kit"}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());

    // challenge → token (twice = refresh)
    for _ in 0..2 {
        let ch: Value = client
            .get(format!("{base}/agents/challenge"))
            .query(&[("did", &did)])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ch["challenge"].as_str().unwrap())
            .unwrap();
        let sig = base64::engine::general_purpose::STANDARD.encode(sk.sign(&bytes).to_bytes());
        let tok: Value = client.post(format!("{base}/agents/token"))
            .json(&json!({"did": did, "challenge": ch["challenge"], "signature": sig, "nonce": ch["nonce"]}))
            .send().await.unwrap().json().await.unwrap();
        assert!(tok.get("delegation_jwt").is_none());
        let exp = tok["expires_at"].as_i64().unwrap();
        assert!(exp - chrono::Utc::now().timestamp() <= 900);
        assert_eq!(
            tok["entitlements"][0],
            "https://arkavo.ai/attr/tdf/value/decrypt"
        );
    }

    // I2: agents must not keep stale entitlements for the delegation
    // lifetime. Restrict the delegator's stored entitlements to a strict
    // subset of what was delegated; the next minted token must reflect only
    // the intersection (delegation.entitlements ∩ stored), not the full
    // delegated set captured at authorize time.
    let r = client
        .put(format!("{base}/admin/users/{SEED_USER_ID}/entitlements"))
        .header("X-Auth-Token", &service_cwt)
        .json(&json!({"entitlements": [
            "https://arkavo.ai/attr/action/value/read"
        ]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());

    let ch: Value = client
        .get(format!("{base}/agents/challenge"))
        .query(&[("did", &did)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(ch["challenge"].as_str().unwrap())
        .unwrap();
    let sig = base64::engine::general_purpose::STANDARD.encode(sk.sign(&bytes).to_bytes());
    let tok: Value = client
        .post(format!("{base}/agents/token"))
        .json(&json!({"did": did, "challenge": ch["challenge"], "signature": sig, "nonce": ch["nonce"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        tok["entitlements"],
        json!(["https://arkavo.ai/attr/action/value/read"])
    );

    // GET /entities/{did} (service-CWT gated) reflects the live delegation.
    let r = client
        .get(format!("{base}/entities/{did}"))
        .header("X-Auth-Token", &service_cwt)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let entity: Value = r.json().await.unwrap();
    assert_eq!(entity["category"], "environment");
    assert_eq!(entity["npe_type"], "agent");
    assert_eq!(entity["claims"]["arkavo_npe"]["type"], "agent");

    // replayed challenge is rejected
    let ch: Value = client
        .get(format!("{base}/agents/challenge"))
        .query(&[("did", &did)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(ch["challenge"].as_str().unwrap())
        .unwrap();
    let sig = base64::engine::general_purpose::STANDARD.encode(sk.sign(&bytes).to_bytes());
    let body =
        json!({"did": did, "challenge": ch["challenge"], "signature": sig, "nonce": ch["nonce"]});
    assert_eq!(
        client
            .post(format!("{base}/agents/token"))
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .post(format!("{base}/agents/token"))
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );

    // revoke → 403 on next challenge
    assert_eq!(
        client
            .delete(format!("{base}/agents/delegations/{did}"))
            .header("X-Auth-Token", &human_cwt)
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        client
            .get(format!("{base}/agents/challenge"))
            .query(&[("did", &did)])
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
}

const READ: &str = "https://arkavo.ai/attr/action/value/read";

/// The server's CWT key pair, from the same files CI starts it with.
fn server_keys() -> (p256::ecdsa::SigningKey, p256::ecdsa::VerifyingKey, Vec<u8>) {
    let read = |var: &str| {
        std::fs::read_to_string(std::env::var(var).unwrap_or_else(|_| panic!("{var} must be set")))
            .unwrap()
    };
    authnz_rs::keys::load_cwt_keys(&read("ENCODING_KEY_PATH"), &read("DECODING_KEY_PATH")).unwrap()
}

/// A passkey auth CWT for the seed user minted now. Recovery needs one from
/// the last five minutes, and the seeded AUTHNZ_TEST_HUMAN_CWT is minted
/// before this test binary is even compiled.
fn fresh_human_cwt() -> String {
    let (sk, _, kid) = server_keys();
    let issuer = std::env::var("OIDC_ISSUER").expect("OIDC_ISSUER");
    let claims =
        authnz_rs::cwt::ArkavoClaims::auth(&issuer, SEED_USER_ID, 1, None).with_idp("webauthn");
    authnz_rs::cwt::encode_for_header(&authnz_rs::cwt::mint(&claims, &sk, &kid).unwrap())
}

fn random_agent() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    SigningKey::from_bytes(&seed)
}

async fn mint(client: &reqwest::Client, base: &str, sk: &SigningKey) -> reqwest::Response {
    let ch = client
        .get(format!("{base}/agents/challenge"))
        .query(&[("did", did_key(sk))])
        .send()
        .await
        .unwrap();
    if ch.status() != 200 {
        return ch;
    }
    let ch: Value = ch.json().await.unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(ch["challenge"].as_str().unwrap())
        .unwrap();
    let sig = base64::engine::general_purpose::STANDARD.encode(sk.sign(&bytes).to_bytes());
    client
        .post(format!("{base}/agents/token"))
        .json(&json!({"did": did_key(sk), "challenge": ch["challenge"], "signature": sig, "nonce": ch["nonce"]}))
        .send()
        .await
        .unwrap()
}

async fn status(client: &reqwest::Client, base: &str, did: &str) -> Value {
    let r = client
        .get(format!("{base}/agents/{did}/status"))
        .header(
            "X-Auth-Token",
            std::env::var("AUTHNZ_TEST_SERVICE_CWT").unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    r.json().await.unwrap()
}

/// The proof a Guardian key must send with `POST /guardians`: its own
/// signature over `arkavo-guardian-enroll\n<owner_uuid>\n<public_key_b64url>`
/// (contract v2, unchanged from v1; `src/guardian.rs::enrollment_input`).
fn guardian_enrollment_proof(owner: &str, guardian: &SigningKey) -> (String, String) {
    let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(guardian.verifying_key().as_bytes());
    let msg = format!("arkavo-guardian-enroll\n{owner}\n{public_key}");
    let proof = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(guardian.sign(msg.as_bytes()).to_bytes());
    (public_key, proof)
}

/// A Guardian-signed POST of `body` to `path` (contract v2 signing input).
async fn guardian_post(
    client: &reqwest::Client,
    base: &str,
    gid: &str,
    guardian: &SigningKey,
    path: &str,
    body: &str,
) -> reqwest::Response {
    let ts = chrono::Utc::now().timestamp();
    let signed = format!(
        "POST\n{path}\n{ts}\n{}",
        hex::encode(Sha256::digest(body.as_bytes()))
    );
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(guardian.sign(signed.as_bytes()).to_bytes());
    client
        .post(format!("{base}{path}"))
        .header("X-Guardian-Signature", format!("{gid}.{ts}.{sig}"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires AUTHNZ_TEST_BASE_URL + DynamoDB Local"]
async fn quarantine_stops_issuance_and_recovery_leaves_the_key_unassessed() {
    let Some(base) = base() else { return };
    let client = reqwest::Client::new();
    let (a1, a2, guardian) = (random_agent(), random_agent(), random_agent());
    let did = did_key(&a1);
    let authorize = |sk: &SigningKey| {
        json!({"agent_did": did_key(sk), "name": "e2e-agent", "entitlements": [READ],
               "swarm": "kit-e2e", "short_lived": true})
    };

    // The operator authorizes a short-lived agent: the owner's bootstrap
    // appraisal makes it eligible at state_version 1.
    let r = client
        .post(format!("{base}/agents/authorize"))
        .header("X-Auth-Token", fresh_human_cwt())
        .json(&authorize(&a1))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let authorized: Value = r.json().await.unwrap();
    assert_eq!(
        (
            authorized["state"].as_str(),
            authorized["state_version"].as_u64()
        ),
        (Some("eligible"), Some(1))
    );

    // Its token carries the state version and swarm and lives five minutes.
    let r = mint(&client, &base, &a1).await;
    assert_eq!(r.status(), 200);
    let tok: Value = r.json().await.unwrap();
    let (_, vk, _) = server_keys();
    let claims = authnz_rs::cwt::verify(
        &authnz_rs::cwt::decode_from_header(tok["token"].as_str().unwrap()).unwrap(),
        &vk,
        &authnz_rs::cwt::VerifyOptions {
            expected_iss: Some(&std::env::var("OIDC_ISSUER").unwrap()),
            expected_aud: Some("https://platform.test"),
            now: chrono::Utc::now().timestamp(),
            skew_secs: authnz_rs::cwt::DEFAULT_SKEW_SECS,
        },
    )
    .unwrap();
    assert_eq!(claims.custom.arkavo_state_version, Some(1));
    assert_eq!(claims.custom.arkavo_swarm.as_deref(), Some("kit-e2e"));
    assert_eq!(claims.exp - claims.iat, 300);
    let s = status(&client, &base, &did).await;
    assert_eq!(
        (
            s["state"].as_str(),
            s["state_version"].as_u64(),
            s["appraised_by"].as_str()
        ),
        (Some("eligible"), Some(1), Some("owner"))
    );

    // The owner enrolls a Guardian, proving possession of its key; the
    // Guardian quarantines.
    let (public_key, proof) = guardian_enrollment_proof(SEED_USER_ID, &guardian);
    let r = client
        .post(format!("{base}/guardians"))
        .header("X-Auth-Token", fresh_human_cwt())
        .json(&json!({"public_key": public_key, "name": "e2e", "proof": proof}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let gid = r.json::<Value>().await.unwrap()["guardian_id"]
        .as_str()
        .unwrap()
        .to_string();
    let body = json!({"incident": "e2e-inc-1", "evidence_ref": null}).to_string();
    let r = guardian_post(
        &client,
        &base,
        &gid,
        &guardian,
        &format!("/agents/{did}/quarantine"),
        &body,
    )
    .await;
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());

    // The platform's view flips within the lease.
    let s = status(&client, &base, &did).await;
    assert_eq!(s["state"], "quarantined");
    assert_eq!(s["state_version"], 2);
    assert_eq!(s["incident"], "e2e-inc-1");
    assert!(s["valid_until"].as_i64().unwrap() <= chrono::Utc::now().timestamp() + 5);

    // No new tokens for the key; another key is another identity.
    assert_eq!(mint(&client, &base, &a1).await.status(), 403);
    let r = client
        .post(format!("{base}/agents/authorize"))
        .header("X-Auth-Token", fresh_human_cwt())
        .json(&authorize(&a2))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(mint(&client, &base, &a2).await.status(), 200);

    // Owner recovery, citing the incident: the key is unassessed, and the
    // owner may not appraise it again.
    let r = client
        .post(format!("{base}/agents/{did}/recover"))
        .header("X-Auth-Token", fresh_human_cwt())
        .json(&json!({"incident": "e2e-inc-1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let s = status(&client, &base, &did).await;
    assert_eq!(
        (s["state"].as_str(), s["state_version"].as_u64()),
        (Some("unassessed"), Some(3))
    );
    assert_eq!(mint(&client, &base, &a1).await.status(), 403);
    let r = client
        .post(format!("{base}/agents/authorize"))
        .header("X-Auth-Token", fresh_human_cwt())
        .json(&authorize(&a1))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}
