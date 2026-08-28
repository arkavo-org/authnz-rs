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

    // authorize
    let r = client.post(format!("{base}/agents/authorize"))
        .header("X-Auth-Token", &human_cwt)
        .json(&json!({"agent_did": did, "name": "it-agent", "entitlements": ["https://arkavo.ai/attr/tdf/value/decrypt"]}))
        .send().await.unwrap();
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
