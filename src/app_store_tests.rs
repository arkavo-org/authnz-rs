//! StoreKit JWS verification (`app_store::verify_jws`) against fixture chains
//! shaped like Apple's: a root, a WWDR-marked intermediate and a
//! receipt-signing leaf, ES256 unless a test says otherwise. Pure: no
//! network, no database, except `POST /app-store/transactions`, which runs
//! against DynamoDB Local (each of those tests returns early unless
//! `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set, as CI's `test` job sets it).

use crate::app_store::{
    AppStoreConfig, AppStoreError, Environment, app_store_active, apple_root_g3_der,
    decode_notification, decode_renewal_grace, decode_transaction, transactions_handler,
    verify_jws,
};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::Utc;
use ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, CustomExtension, DistinguishedName,
    DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
    SignatureAlgorithm, date_time_ymd,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// SHA-256 of Apple Root CA - G3's DER, as macOS's SystemRootCertificates
/// keychain lists it.
const APPLE_ROOT_G3_SHA256: &str =
    "63343ABFB89A6A03EBB57E9B3F5FA7BE7C4F5C756F3017B3A8C488C3653E9179";

const WWDR_INTERMEDIATE_OID: &[u64] = &[1, 2, 840, 113635, 100, 6, 2, 1];
const RECEIPT_SIGNING_OID: &[u64] = &[1, 2, 840, 113635, 100, 6, 11, 1];

/// 2020-06-01T00:00:00Z, in Apple's milliseconds.
const JUNE_2020_MS: i64 = 1_590_969_600_000;

const ROOT_CN: &str = "Test Root CA - G3";

type Ymd = (i32, u8, u8);

struct Fixture {
    /// The root presented as `x5c[2]`.
    root_der: Vec<u8>,
    /// Leaf, intermediate, root: the `x5c` order.
    x5c: Vec<Vec<u8>>,
    leaf_key: SigningKey,
}

struct Options {
    leaf_oid: bool,
    intermediate_oid: bool,
    intermediate_alg: &'static SignatureAlgorithm,
    leaf_validity: Option<(Ymd, Ymd)>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            leaf_oid: true,
            intermediate_oid: true,
            intermediate_alg: &PKCS_ECDSA_P256_SHA256,
            leaf_validity: None,
        }
    }
}

fn named(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

fn ca_params(cn: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = named(cn);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
}

/// Apple's marker extensions carry DER NULL as their value.
fn marker(oid: &[u64]) -> CustomExtension {
    CustomExtension::from_oid_content(oid, vec![0x05, 0x00])
}

/// A self-signed root with a fresh key. Two roots made with the same `cn`
/// have identical names and different keys.
fn test_root(cn: &str) -> CertifiedIssuer<'static, KeyPair> {
    test_root_for(cn, &PKCS_ECDSA_P256_SHA256)
}

fn test_root_for(cn: &str, alg: &'static SignatureAlgorithm) -> CertifiedIssuer<'static, KeyPair> {
    CertifiedIssuer::self_signed(ca_params(cn), KeyPair::generate_for(alg).unwrap()).unwrap()
}

fn chain_under(root: &CertifiedIssuer<'static, KeyPair>, opts: Options) -> Fixture {
    chain_issued_by(root, root.der(), opts)
}

/// An intermediate issued by `issuer` and a leaf issued by that intermediate,
/// presented with `root_der` as `x5c[2]`.
fn chain_issued_by(
    issuer: &Issuer<'_, impl rcgen::SigningKey>,
    root_der: &[u8],
    opts: Options,
) -> Fixture {
    let mut int_params = ca_params("Test Worldwide Developer Relations");
    if opts.intermediate_oid {
        int_params
            .custom_extensions
            .push(marker(WWDR_INTERMEDIATE_OID));
    }
    let int_key = KeyPair::generate_for(opts.intermediate_alg).unwrap();
    let intermediate = CertifiedIssuer::signed_by(int_params, int_key, issuer).unwrap();

    let leaf_kp = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::default();
    leaf_params.distinguished_name = named("Test StoreKit Signing");
    if opts.leaf_oid {
        leaf_params
            .custom_extensions
            .push(marker(RECEIPT_SIGNING_OID));
    }
    if let Some(((y0, m0, d0), (y1, m1, d1))) = opts.leaf_validity {
        leaf_params.not_before = date_time_ymd(y0, m0, d0);
        leaf_params.not_after = date_time_ymd(y1, m1, d1);
    }
    let leaf = leaf_params.signed_by(&leaf_kp, &*intermediate).unwrap();

    Fixture {
        root_der: root_der.to_vec(),
        x5c: vec![
            leaf.der().to_vec(),
            intermediate.der().to_vec(),
            root_der.to_vec(),
        ],
        leaf_key: SigningKey::from_pkcs8_der(leaf_kp.serialized_der()).unwrap(),
    }
}

fn fixture(opts: Options) -> Fixture {
    chain_under(&test_root(ROOT_CN), opts)
}

fn segment(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
}

/// Compact JWS as Apple signs it: `x5c` holds standard-base64 DER, the
/// signature is base64url of the 64-byte r||s.
fn sign_jws_with_alg(alg: &str, payload: &Value, fx: &Fixture) -> String {
    let x5c: Vec<String> = fx.x5c.iter().map(|der| STANDARD.encode(der)).collect();
    let input = format!(
        "{}.{}",
        segment(&json!({ "alg": alg, "x5c": x5c })),
        segment(payload)
    );
    let signature: Signature = fx.leaf_key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn sign_jws(payload: &Value, fx: &Fixture) -> String {
    sign_jws_with_alg("ES256", payload, fx)
}

fn transaction(signed_date_ms: i64) -> Value {
    json!({
        "transactionId": "2000000123456789",
        "originalTransactionId": "2000000123456789",
        "bundleId": "com.arkavo.ArkavoCreator",
        "productId": "com.arkavo.ArkavoCreator.membership.monthly",
        "inAppOwnershipType": "PURCHASED",
        "environment": "Sandbox",
        "signedDate": signed_date_ms,
    })
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

#[test]
fn accepts_a_valid_three_certificate_chain() {
    let fx = fixture(Options::default());
    let payload = transaction(now_ms());

    assert_eq!(
        verify_jws(&sign_jws(&payload, &fx), &fx.root_der),
        Ok(payload)
    );
}

/// Apple's own shape: a P-384 root and intermediate, each signing with
/// ecdsa-with-SHA384, over a P-256 leaf.
#[test]
fn accepts_apples_p384_ca_chain() {
    let root = test_root_for(ROOT_CN, &PKCS_ECDSA_P384_SHA384);
    let fx = chain_under(
        &root,
        Options {
            intermediate_alg: &PKCS_ECDSA_P384_SHA384,
            ..Options::default()
        },
    );
    let payload = transaction(now_ms());

    assert_eq!(
        verify_jws(&sign_jws(&payload, &fx), &fx.root_der),
        Ok(payload)
    );
}

#[test]
fn refuses_a_two_certificate_chain() {
    let mut fx = fixture(Options::default());
    fx.x5c.truncate(2);

    let jws = sign_jws(&transaction(now_ms()), &fx);
    assert_eq!(
        verify_jws(&jws, &fx.root_der),
        Err(AppStoreError::InvalidChain)
    );
}

#[test]
fn refuses_a_four_certificate_chain() {
    let mut fx = fixture(Options::default());
    let root = fx.x5c[2].clone();
    fx.x5c.push(root);

    let jws = sign_jws(&transaction(now_ms()), &fx);
    assert_eq!(
        verify_jws(&jws, &fx.root_der),
        Err(AppStoreError::InvalidChain)
    );
}

#[test]
fn refuses_a_chain_to_another_root() {
    let pinned = test_root(ROOT_CN);
    let other = test_root(ROOT_CN);

    // Issued under another root of the same name.
    let fx = chain_under(&other, Options::default());
    let jws = sign_jws(&transaction(now_ms()), &fx);
    assert_eq!(
        verify_jws(&jws, pinned.der()),
        Err(AppStoreError::InvalidChain)
    );

    // Issued under the pinned root, but presented with another root.
    let fx = chain_issued_by(&pinned, other.der(), Options::default());
    let jws = sign_jws(&transaction(now_ms()), &fx);
    assert_eq!(
        verify_jws(&jws, pinned.der()),
        Err(AppStoreError::InvalidChain)
    );
}

#[test]
fn refuses_a_chain_whose_signatures_do_not_link() {
    let pinned = test_root(ROOT_CN);
    let genuine = chain_under(&pinned, Options::default());

    // An intermediate issued by an impostor root with the pinned root's name,
    // presented with the pinned root's bytes.
    let impostor = chain_under(&test_root(ROOT_CN), Options::default());
    let forged_int = Fixture {
        root_der: genuine.root_der.clone(),
        x5c: vec![
            impostor.x5c[0].clone(),
            impostor.x5c[1].clone(),
            genuine.x5c[2].clone(),
        ],
        leaf_key: impostor.leaf_key,
    };
    let jws = sign_jws(&transaction(now_ms()), &forged_int);
    assert_eq!(
        verify_jws(&jws, &forged_int.root_der),
        Err(AppStoreError::InvalidChain)
    );

    // A leaf issued by a second intermediate of the same name, presented with
    // the genuine intermediate.
    let sibling = chain_under(&pinned, Options::default());
    let forged_leaf = Fixture {
        root_der: genuine.root_der.clone(),
        x5c: vec![
            sibling.x5c[0].clone(),
            genuine.x5c[1].clone(),
            genuine.x5c[2].clone(),
        ],
        leaf_key: sibling.leaf_key,
    };
    let jws = sign_jws(&transaction(now_ms()), &forged_leaf);
    assert_eq!(
        verify_jws(&jws, &forged_leaf.root_der),
        Err(AppStoreError::InvalidChain)
    );
}

#[test]
fn refuses_a_link_whose_issuer_name_differs() {
    let pinned = test_root(ROOT_CN);
    // The pinned root's key, signing under another name.
    let renamed = Issuer::new(ca_params("Another Root CA"), pinned.key());
    let fx = chain_issued_by(&renamed, pinned.der(), Options::default());

    let jws = sign_jws(&transaction(now_ms()), &fx);
    assert_eq!(
        verify_jws(&jws, &fx.root_der),
        Err(AppStoreError::InvalidChain)
    );
}

#[test]
fn refuses_a_leaf_without_the_receipt_signing_oid() {
    let fx = fixture(Options {
        leaf_oid: false,
        ..Options::default()
    });

    let jws = sign_jws(&transaction(now_ms()), &fx);
    assert_eq!(
        verify_jws(&jws, &fx.root_der),
        Err(AppStoreError::InvalidChain)
    );
}

#[test]
fn refuses_an_intermediate_without_the_wwdr_oid() {
    let fx = fixture(Options {
        intermediate_oid: false,
        ..Options::default()
    });

    let jws = sign_jws(&transaction(now_ms()), &fx);
    assert_eq!(
        verify_jws(&jws, &fx.root_der),
        Err(AppStoreError::InvalidChain)
    );
}

#[test]
fn refuses_a_tampered_payload() {
    let fx = fixture(Options::default());
    let payload = transaction(now_ms());
    let jws = sign_jws(&payload, &fx);

    let mut tampered = payload.clone();
    tampered["productId"] = json!("com.arkavo.ArkavoCreator.membership.yearly");
    let parts: Vec<&str> = jws.split('.').collect();
    let forged = format!("{}.{}.{}", parts[0], segment(&tampered), parts[2]);

    assert_eq!(
        verify_jws(&forged, &fx.root_der),
        Err(AppStoreError::InvalidSignature)
    );
}

#[test]
fn refuses_alg_other_than_es256() {
    let fx = fixture(Options::default());
    let payload = transaction(now_ms());

    for alg in ["none", "HS256", "ES384", "RS256", "es256"] {
        let jws = sign_jws_with_alg(alg, &payload, &fx);
        assert_eq!(
            verify_jws(&jws, &fx.root_der),
            Err(AppStoreError::Malformed),
            "alg {alg}"
        );
    }
}

#[test]
fn checks_validity_at_signed_date() {
    // Expired now, valid on 2020-06-01.
    let expired = fixture(Options {
        leaf_validity: Some(((2020, 1, 1), (2021, 1, 1))),
        ..Options::default()
    });
    let payload = transaction(JUNE_2020_MS);
    assert_eq!(
        verify_jws(&sign_jws(&payload, &expired), &expired.root_der),
        Ok(payload)
    );

    // Without a signedDate the same leaf is judged now.
    let mut undated = transaction(JUNE_2020_MS);
    undated.as_object_mut().unwrap().remove("signedDate");
    assert_eq!(
        verify_jws(&sign_jws(&undated, &expired), &expired.root_der),
        Err(AppStoreError::InvalidChain)
    );

    // Not yet valid on 2020-06-01.
    let future = fixture(Options {
        leaf_validity: Some(((2030, 1, 1), (2031, 1, 1))),
        ..Options::default()
    });
    assert_eq!(
        verify_jws(
            &sign_jws(&transaction(JUNE_2020_MS), &future),
            &future.root_der
        ),
        Err(AppStoreError::InvalidChain)
    );
}

#[test]
fn apple_root_g3_is_the_published_root() {
    let fingerprint = hex::encode(Sha256::digest(apple_root_g3_der()));
    assert!(
        fingerprint.eq_ignore_ascii_case(APPLE_ROOT_G3_SHA256),
        "Apple Root CA - G3 fingerprint is {fingerprint}"
    );
}

// --------- Semantic decoding ---------

const PRODUCT: &str = "com.arkavo.ArkavoCreator.membership.monthly";
const TOKEN: &str = "6f1c1d3e-8a54-4b0e-9d0b-2f4f6f0a7c11";

/// A signed-in-the-past subscription transaction expiring a month on, with
/// `overrides` applied over its fields (a `null` removes one).
fn purchase(overrides: Value) -> Value {
    let signed = now_ms();
    let mut payload = transaction(signed);
    payload["expiresDate"] = json!(signed + 30 * 86_400_000);
    for (key, value) in overrides.as_object().unwrap() {
        if value.is_null() {
            payload.as_object_mut().unwrap().remove(key);
        } else {
            payload[key] = value.clone();
        }
    }
    payload
}

fn decode(
    fx: &Fixture,
    overrides: Value,
) -> Result<crate::app_store::VerifiedTransaction, AppStoreError> {
    let cfg = AppStoreConfig::for_tests(fx.root_der.clone());
    decode_transaction(&cfg, &sign_jws(&purchase(overrides), fx))
}

#[test]
fn decodes_a_production_transaction() {
    let fx = fixture(Options::default());
    let signed = 1_700_000_123_456_i64;
    let tx = decode_transaction(
        &AppStoreConfig::for_tests(fx.root_der.clone()),
        &sign_jws(
            &json!({
                "originalTransactionId": "2000000123456789",
                "bundleId": "com.arkavo.ArkavoCreator",
                "productId": PRODUCT,
                "inAppOwnershipType": "PURCHASED",
                "environment": "Production",
                "appAccountToken": TOKEN,
                "expiresDate": 1_700_086_400_999_i64,
                "revocationDate": 1_700_050_000_500_i64,
                "signedDate": signed,
            }),
            &fx,
        ),
    )
    .unwrap();

    assert_eq!(tx.original_transaction_id, "2000000123456789");
    assert_eq!(tx.product_id, PRODUCT);
    assert_eq!(tx.environment, Environment::Production);
    assert_eq!(tx.app_account_token, Some(TOKEN.parse().unwrap()));
    assert_eq!(tx.expires_at, 1_700_086_400);
    assert_eq!(tx.revoked_at, Some(1_700_050_000));
    assert_eq!(tx.signed_at, 1_700_000_123);
}

#[test]
fn decodes_a_transaction_without_token_or_revocation() {
    let fx = fixture(Options::default());
    let tx = decode(&fx, json!({})).unwrap();
    assert_eq!(tx.app_account_token, None);
    assert_eq!(tx.revoked_at, None);
}

#[test]
fn refuses_wrong_bundle_id() {
    let fx = fixture(Options::default());
    assert_eq!(
        decode(&fx, json!({ "bundleId": "com.example.other" })),
        Err(AppStoreError::WrongApp)
    );
}

#[test]
fn refuses_product_not_configured() {
    let fx = fixture(Options::default());
    assert_eq!(
        decode(&fx, json!({ "productId": "com.arkavo.ArkavoCreator.tip" })),
        Err(AppStoreError::WrongApp)
    );
}

#[test]
fn refuses_family_shared() {
    let fx = fixture(Options::default());
    assert_eq!(
        decode(&fx, json!({ "inAppOwnershipType": "FAMILY_SHARED" })),
        Err(AppStoreError::NotPurchased)
    );
    assert_eq!(
        decode(&fx, json!({ "inAppOwnershipType": null })),
        Err(AppStoreError::NotPurchased)
    );
}

#[test]
fn accepts_sandbox_by_default() {
    let fx = fixture(Options::default());
    assert_eq!(
        decode(&fx, json!({ "environment": "Sandbox" }))
            .unwrap()
            .environment,
        Environment::Sandbox
    );
}

#[test]
fn refuses_sandbox_when_only_production() {
    let fx = fixture(Options::default());
    let mut cfg = AppStoreConfig::for_tests(fx.root_der.clone());
    cfg.environments = [Environment::Production].into();
    let jws = sign_jws(&purchase(json!({ "environment": "Sandbox" })), &fx);
    assert_eq!(
        decode_transaction(&cfg, &jws),
        Err(AppStoreError::WrongEnvironment)
    );
}

/// Their payloads are unsigned, so the refusal comes before verification: a
/// chain that would not verify still answers `WrongEnvironment`.
#[test]
fn refuses_xcode_and_localtesting() {
    let fx = fixture(Options::default());
    let other_root = fixture(Options::default());
    let cfg = AppStoreConfig::for_tests(other_root.root_der.clone());
    for environment in ["Xcode", "LocalTesting"] {
        let jws = sign_jws(&purchase(json!({ "environment": environment })), &fx);
        assert_eq!(
            decode_transaction(&cfg, &jws),
            Err(AppStoreError::WrongEnvironment),
            "{environment}"
        );
    }
    assert_eq!(
        decode_transaction(&cfg, &sign_jws(&purchase(json!({})), &fx)),
        Err(AppStoreError::InvalidChain)
    );
}

#[test]
fn refuses_an_unknown_environment_and_a_bad_token() {
    let fx = fixture(Options::default());
    assert_eq!(
        decode(&fx, json!({ "environment": "Staging" })),
        Err(AppStoreError::WrongEnvironment)
    );
    assert_eq!(
        decode(&fx, json!({ "appAccountToken": "not-a-uuid" })),
        Err(AppStoreError::Malformed)
    );
    assert_eq!(
        decode(&fx, json!({ "expiresDate": null })),
        Err(AppStoreError::Malformed)
    );
}

#[test]
fn refuses_a_transaction_signed_by_another_root() {
    let fx = fixture(Options::default());
    let cfg = AppStoreConfig::for_tests(fixture(Options::default()).root_der);
    assert_eq!(
        decode_transaction(&cfg, &sign_jws(&purchase(json!({})), &fx)),
        Err(AppStoreError::InvalidChain)
    );
}

/// With no test override a config verifies against Apple's root, so a fixture
/// chain does not pass.
#[test]
fn production_config_trusts_only_apples_root() {
    let fx = fixture(Options::default());
    let mut cfg = AppStoreConfig::for_tests(fx.root_der.clone());
    cfg.bundle_id = "com.arkavo.ArkavoCreator".into();
    let parsed = AppStoreConfig::parse(
        Some("com.arkavo.ArkavoCreator"),
        Some("6738845556"),
        Some(PRODUCT),
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        decode_transaction(&parsed, &sign_jws(&purchase(json!({})), &fx)),
        Err(AppStoreError::InvalidChain)
    );
}

fn notification(fx: &Fixture, notification_type: &str, data: Value) -> String {
    sign_jws(
        &json!({
            "notificationType": notification_type,
            "notificationUUID": "9f7b6c46-2c1d-4a45-8a34-3c1a2b5d7e90",
            "data": data,
            "signedDate": now_ms(),
        }),
        fx,
    )
}

fn notification_data(fx: &Fixture, environment: &str) -> Value {
    json!({
        "bundleId": "com.arkavo.ArkavoCreator",
        "appAppleId": 6_738_845_556_i64,
        "environment": environment,
        "signedTransactionInfo": sign_jws(&purchase(json!({ "environment": environment })), fx),
    })
}

#[test]
fn production_notification_requires_app_apple_id() {
    let fx = fixture(Options::default());
    let cfg = AppStoreConfig::for_tests(fx.root_der.clone());
    for app_apple_id in [json!(1), json!(null)] {
        let mut data = notification_data(&fx, "Production");
        data["appAppleId"] = app_apple_id;
        assert_eq!(
            decode_notification(&cfg, &notification(&fx, "DID_RENEW", data)),
            Err(AppStoreError::WrongApp)
        );
    }
    let ok = decode_notification(
        &cfg,
        &notification(&fx, "DID_RENEW", notification_data(&fx, "Production")),
    )
    .unwrap();
    assert_eq!(ok.notification_type, "DID_RENEW");
}

#[test]
fn sandbox_notification_skips_app_apple_id() {
    let fx = fixture(Options::default());
    let cfg = AppStoreConfig::for_tests(fx.root_der.clone());
    let mut data = notification_data(&fx, "Sandbox");
    data.as_object_mut().unwrap().remove("appAppleId");
    let decoded = decode_notification(&cfg, &notification(&fx, "SUBSCRIBED", data)).unwrap();
    assert_eq!(
        decoded.transaction.unwrap().environment,
        Environment::Sandbox
    );
}

#[test]
fn notification_decodes_nested_transaction_and_grace() {
    let fx = fixture(Options::default());
    let cfg = AppStoreConfig::for_tests(fx.root_der.clone());
    let mut data = notification_data(&fx, "Production");
    data["signedRenewalInfo"] = json!(sign_jws(
        &json!({
            "environment": "Production",
            "gracePeriodExpiresDate": 1_700_172_800_321_i64,
        }),
        &fx
    ));
    let decoded = decode_notification(&cfg, &notification(&fx, "DID_FAIL_TO_RENEW", data)).unwrap();

    assert_eq!(decoded.notification_type, "DID_FAIL_TO_RENEW");
    assert_eq!(decoded.grace_expires_at, Some(1_700_172_800));
    let tx = decoded.transaction.unwrap();
    assert_eq!(tx.original_transaction_id, "2000000123456789");
    assert_eq!(tx.environment, Environment::Production);
}

#[test]
fn notification_refuses_a_bad_nested_transaction() {
    let fx = fixture(Options::default());
    let cfg = AppStoreConfig::for_tests(fx.root_der.clone());
    let mut data = notification_data(&fx, "Production");
    data["signedTransactionInfo"] = json!(sign_jws(
        &purchase(json!({ "productId": "com.arkavo.ArkavoCreator.tip" })),
        &fx
    ));
    assert_eq!(
        decode_notification(&cfg, &notification(&fx, "DID_RENEW", data)),
        Err(AppStoreError::WrongApp)
    );

    let mut data = notification_data(&fx, "Production");
    data["signedTransactionInfo"] = json!("not.a.jws");
    assert_eq!(
        decode_notification(&cfg, &notification(&fx, "DID_RENEW", data)),
        Err(AppStoreError::Malformed)
    );
}

#[test]
fn notification_refuses_wrong_bundle_and_unsigned_environments() {
    let fx = fixture(Options::default());
    let unrelated = AppStoreConfig::for_tests(fixture(Options::default()).root_der);
    let cfg = AppStoreConfig::for_tests(fx.root_der.clone());

    let mut data = notification_data(&fx, "Sandbox");
    data["bundleId"] = json!("com.example.other");
    assert_eq!(
        decode_notification(&cfg, &notification(&fx, "DID_RENEW", data)),
        Err(AppStoreError::WrongApp)
    );

    for environment in ["Xcode", "LocalTesting"] {
        let data = json!({ "bundleId": "com.arkavo.ArkavoCreator", "environment": environment });
        assert_eq!(
            decode_notification(&unrelated, &notification(&fx, "TEST", data)),
            Err(AppStoreError::WrongEnvironment),
            "{environment}"
        );
    }
}

#[test]
fn test_notification_has_no_transaction() {
    let fx = fixture(Options::default());
    let cfg = AppStoreConfig::for_tests(fx.root_der.clone());
    let data = json!({ "bundleId": "com.arkavo.ArkavoCreator", "environment": "Sandbox" });
    let decoded = decode_notification(&cfg, &notification(&fx, "TEST", data)).unwrap();

    assert_eq!(decoded.notification_type, "TEST");
    assert_eq!(decoded.transaction, None);
    assert_eq!(decoded.grace_expires_at, None);
}

#[test]
fn renewal_info_without_grace_has_none() {
    let fx = fixture(Options::default());
    let cfg = AppStoreConfig::for_tests(fx.root_der.clone());
    let jws = sign_jws(&json!({ "environment": "Sandbox" }), &fx);
    assert_eq!(decode_renewal_grace(&cfg, &jws), Ok(None));
    let xcode = sign_jws(&json!({ "environment": "Xcode" }), &fx);
    assert_eq!(
        decode_renewal_grace(&cfg, &xcode),
        Err(AppStoreError::WrongEnvironment)
    );
}

#[test]
fn from_env_disabled_without_bundle_id() {
    let parse = AppStoreConfig::parse;
    assert!(
        parse(None, Some("6738845556"), Some(PRODUCT), None)
            .unwrap()
            .is_none()
    );
    assert!(
        parse(Some(" "), Some("6738845556"), Some(PRODUCT), None)
            .unwrap()
            .is_none()
    );
    assert!(
        parse(Some("b"), None, Some(PRODUCT), None)
            .unwrap()
            .is_none()
    );
    assert!(
        parse(Some("b"), Some("1"), Some(" , "), None)
            .unwrap()
            .is_none()
    );
    assert!(parse(Some("b"), Some("six"), Some(PRODUCT), None).is_err());
}

#[test]
fn config_environments_default_and_validate() {
    let parse = |envs| AppStoreConfig::parse(Some("b"), Some("1"), Some("p1, p2"), envs);
    let both = [Environment::Production, Environment::Sandbox].into();

    let default = parse(None).unwrap().unwrap();
    assert_eq!(default.environments, both);
    assert_eq!(default.product_ids.len(), 2);
    assert_eq!(parse(Some("")).unwrap().unwrap().environments, both);
    assert_eq!(
        parse(Some("Production")).unwrap().unwrap().environments,
        [Environment::Production].into()
    );
    assert!(parse(Some("Production,Xcode")).is_err());
    assert!(parse(Some("production")).is_err());
}

// --------- The Active rule ---------

mod active_rule {
    use super::*;
    use crate::db::AppStoreRecord;

    const NOW: i64 = 1_800_000_000;

    fn cfg() -> AppStoreConfig {
        AppStoreConfig::for_tests(Vec::new())
    }

    fn record() -> AppStoreRecord {
        AppStoreRecord {
            original_transaction_id: "1".into(),
            product_id: PRODUCT.into(),
            environment: Environment::Production,
            expires_at: NOW + 100,
            grace_expires_at: None,
            revoked_at: None,
            last_signed_at: NOW - 100,
        }
    }

    #[test]
    fn a_current_unrevoked_configured_record_is_active() {
        assert!(app_store_active(&cfg(), &[record()], NOW));
        // Not before any record exists.
        assert!(!app_store_active(&cfg(), &[], NOW));
    }

    #[test]
    fn expiry_is_exclusive() {
        let r = record();
        assert!(app_store_active(
            &cfg(),
            std::slice::from_ref(&r),
            r.expires_at - 1
        ));
        assert!(!app_store_active(
            &cfg(),
            std::slice::from_ref(&r),
            r.expires_at
        ));
        assert!(!app_store_active(
            &cfg(),
            std::slice::from_ref(&r),
            r.expires_at + 1
        ));
    }

    #[test]
    fn grace_extends_past_expiry_and_never_shortens_it() {
        let in_grace = AppStoreRecord {
            expires_at: NOW - 10,
            grace_expires_at: Some(NOW + 10),
            ..record()
        };
        assert!(app_store_active(
            &cfg(),
            std::slice::from_ref(&in_grace),
            NOW
        ));
        assert!(!app_store_active(&cfg(), &[in_grace], NOW + 10));

        // A grace date earlier than the expiry does not cut the term short.
        let early_grace = AppStoreRecord {
            grace_expires_at: Some(NOW - 50),
            ..record()
        };
        assert!(app_store_active(&cfg(), &[early_grace], NOW));
    }

    #[test]
    fn a_revocation_ends_it_whatever_the_dates() {
        let refunded = AppStoreRecord {
            revoked_at: Some(NOW - 1),
            grace_expires_at: Some(NOW + 1_000),
            ..record()
        };
        assert!(!app_store_active(&cfg(), &[refunded], NOW));
    }

    #[test]
    fn an_unconfigured_product_or_environment_grants_nothing() {
        let other_product = AppStoreRecord {
            product_id: "com.example.other".into(),
            ..record()
        };
        assert!(!app_store_active(&cfg(), &[other_product], NOW));

        let mut production_only = cfg();
        production_only.environments = [Environment::Production].into();
        let sandbox = AppStoreRecord {
            environment: Environment::Sandbox,
            ..record()
        };
        assert!(!app_store_active(
            &production_only,
            std::slice::from_ref(&sandbox),
            NOW
        ));
        assert!(app_store_active(&cfg(), &[sandbox], NOW));
    }

    #[test]
    fn any_one_active_record_is_enough() {
        let lapsed = AppStoreRecord {
            expires_at: NOW - 1,
            ..record()
        };
        assert!(app_store_active(&cfg(), &[lapsed.clone(), record()], NOW));
        assert!(!app_store_active(&cfg(), &[lapsed], NOW));
    }
}

// --------- POST /app-store/transactions ---------

mod transactions_route {
    use super::*;
    use crate::AppState;
    use crate::constants::ENTITLEMENT_CREATOR_PUBLISH;
    use crate::cwt::ArkavoUserClaims;
    use crate::db::{AppStoreRecord, DynamoDBStore, GraceUpdate, StateOutcome};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use axum::{Extension, Router};
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    const OTHER_ACCOUNT_BODY: &str = "transaction belongs to another account";
    const OTHER_SUBSCRIPTION_BODY: &str = "subscription belongs to another account";
    const INVALID_BODY: &str = "invalid transaction";
    const UNAVAILABLE_BODY: &str = "app store purchases unavailable";

    struct Harness {
        state: AppState,
        store: Arc<DynamoDBStore>,
        fx: Fixture,
        app: Router,
    }

    impl Harness {
        /// `None` unless DynamoDB Local is configured.
        fn new() -> Option<Self> {
            Self::with_config(true)
        }

        fn with_config(enabled: bool) -> Option<Self> {
            let store = Arc::new(crate::db::tests::local_store()?);
            let fx = fixture(Options::default());
            let mut state = crate::test_helpers::build_test_app_state_with_store(store.clone());
            state.app_store =
                Arc::new(enabled.then(|| AppStoreConfig::for_tests(fx.root_der.clone())));
            let app = Router::new()
                .route("/app-store/transactions", post(transactions_handler))
                .layer(Extension(state.clone()));
            Some(Self {
                state,
                store,
                fx,
                app,
            })
        }

        async fn user(&self) -> Uuid {
            self.store
                .create_user(
                    &format!("as-{}", &Uuid::new_v4().simple().to_string()[..12]),
                    "did:key:z6MkAppStoreRoute",
                )
                .await
                .unwrap()
                .user_id
        }

        async fn deleted_user(&self) -> Uuid {
            let id = self.user().await;
            self.store
                .tombstone_account(&id, &format!("{id}.test"), None, 1_700_000_000)
                .await
                .unwrap();
            id
        }

        fn token(&self, id: &Uuid) -> String {
            crate::authn::mint_auth_token(&self.state, id, None, None).unwrap()
        }

        /// A token that carries the derived creator-publishing entitlement.
        fn publishing_token(&self, id: &Uuid) -> String {
            let user = ArkavoUserClaims {
                account_id: id.to_string(),
                roles: vec!["user".into()],
                entitlements: vec![],
                derived_entitlements: vec![ENTITLEMENT_CREATOR_PUBLISH.into()],
                patreon: None,
            };
            crate::authn::mint_auth_token(&self.state, id, Some(&user), None).unwrap()
        }

        fn expired_token(&self, id: &Uuid) -> String {
            let mut claims =
                crate::cwt::ArkavoClaims::auth(&self.state.issuer, &id.to_string(), 1, None);
            claims.iat -= 7_200;
            claims.exp -= 7_200;
            let bytes = crate::cwt::mint(&claims, &self.state.cwt_signing_key, &self.state.cwt_kid)
                .unwrap();
            crate::cwt::encode_for_header(&bytes)
        }

        fn jws(&self, overrides: Value) -> String {
            sign_jws(&purchase(overrides), &self.fx)
        }

        async fn post_raw(&self, token: Option<&str>, body: Vec<u8>) -> (StatusCode, String) {
            let mut req =
                Request::post("/app-store/transactions").header("content-type", "application/json");
            if let Some(t) = token {
                req = req.header("X-Auth-Token", t);
            }
            let resp = self
                .app
                .clone()
                .oneshot(req.body(Body::from(body)).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, String::from_utf8_lossy(&bytes).into_owned())
        }

        async fn post(&self, token: &str, jws: &str) -> (StatusCode, String) {
            self.post_raw(
                Some(token),
                json!({ "signed_transaction": jws })
                    .to_string()
                    .into_bytes(),
            )
            .await
        }

        async fn records(&self, id: &Uuid) -> Vec<AppStoreRecord> {
            self.store
                .get_publishing_state(id)
                .await
                .unwrap()
                .map(|s| s.app_store)
                .unwrap_or_default()
        }
    }

    /// Numeric, as Apple's are; unique per test run (the database is shared).
    fn otid() -> String {
        Uuid::new_v4().as_u128().to_string()
    }

    fn secs(ms: i64) -> i64 {
        ms.div_euclid(1000)
    }

    fn json_body(body: &str) -> Value {
        serde_json::from_str(body).unwrap_or_else(|_| panic!("not json: {body}"))
    }

    /// Covers: a purchase by its own account binds and reports active.
    #[tokio::test]
    async fn binds_and_reports_active() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let payload = purchase(json!({
            "originalTransactionId": t,
            "appAccountToken": id.to_string(),
        }));
        let (status, body) = h.post(&h.token(&id), &sign_jws(&payload, &h.fx)).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            json_body(&body),
            json!({
                "active": true,
                "expires_at": secs(payload["expiresDate"].as_i64().unwrap()),
                "environment": "Sandbox",
                "token_can_publish": false,
            })
        );
        // The read-backs prove the database was reached and written.
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(id));
        let records = h.records(&id).await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].original_transaction_id, t);
        assert_eq!(records[0].product_id, PRODUCT);
        assert_eq!(records[0].environment, Environment::Sandbox);
        assert_eq!(
            records[0].last_signed_at,
            secs(payload["signedDate"].as_i64().unwrap())
        );
        assert_eq!(records[0].revoked_at, None);
    }

    #[tokio::test]
    async fn posting_again_is_idempotent() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let jws = h.jws(json!({ "originalTransactionId": t, "appAccountToken": id.to_string() }));
        for _ in 0..2 {
            let (status, body) = h.post(&h.token(&id), &jws).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(json_body(&body)["active"], true);
        }
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(id));
        assert_eq!(h.records(&id).await.len(), 1);
    }

    #[tokio::test]
    async fn a_refunded_transaction_binds_but_reports_inactive() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let revoked_ms = now_ms() - 1_000;
        let jws = h.jws(json!({
            "originalTransactionId": t,
            "appAccountToken": id.to_string(),
            "revocationDate": revoked_ms,
        }));
        let (status, body) = h.post(&h.token(&id), &jws).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(json_body(&body)["active"], false);
        assert_eq!(h.records(&id).await[0].revoked_at, Some(secs(revoked_ms)));
    }

    /// Review Focus 1: the client re-authenticates and re-posts.
    #[tokio::test]
    async fn expired_token_is_401() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let jws = h.jws(json!({ "originalTransactionId": t, "appAccountToken": id.to_string() }));

        let (status, _) = h.post(&h.expired_token(&id), &jws).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), None);
        assert!(h.records(&id).await.is_empty());

        // The same purchase posted with a fresh token goes through.
        let (status, body) = h.post(&h.token(&id), &jws).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn missing_or_garbage_token_is_401() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let jws =
            h.jws(json!({ "originalTransactionId": otid(), "appAccountToken": id.to_string() }));
        let body = json!({ "signed_transaction": jws })
            .to_string()
            .into_bytes();

        let (status, _) = h.post_raw(None, body.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = h.post_raw(Some("not-a-cwt"), body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn deleted_caller_is_401() {
        let Some(h) = Harness::new() else { return };
        let gone = h.deleted_user().await;
        let t = otid();
        let jws = h.jws(json!({ "originalTransactionId": t, "appAccountToken": gone.to_string() }));

        // Its token still verifies; the account behind it does not exist.
        let (status, _) = h.post(&h.token(&gone), &jws).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), None);
        assert!(h.records(&gone).await.is_empty());
    }

    #[tokio::test]
    async fn missing_app_account_token_is_422() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let jws = h.jws(json!({ "originalTransactionId": t, "appAccountToken": null }));
        let (status, body) = h.post(&h.token(&id), &jws).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body, INVALID_BODY);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), None);
        assert!(h.records(&id).await.is_empty());
    }

    /// Review Focus 5: a leaked JWS replayed by another live account.
    #[tokio::test]
    async fn token_for_other_live_account_is_403() {
        let Some(h) = Harness::new() else { return };
        let (owner, thief) = (h.user().await, h.user().await);
        let t = otid();
        let jws =
            h.jws(json!({ "originalTransactionId": t, "appAccountToken": owner.to_string() }));
        let (status, body) = h.post(&h.token(&thief), &jws).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, OTHER_ACCOUNT_BODY);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), None);
        assert!(h.records(&thief).await.is_empty());
        assert!(h.records(&owner).await.is_empty());
    }

    #[tokio::test]
    async fn token_for_deleted_account_binds_to_caller() {
        let Some(h) = Harness::new() else { return };
        let (gone, caller) = (h.deleted_user().await, h.user().await);
        let t = otid();
        let jws = h.jws(json!({ "originalTransactionId": t, "appAccountToken": gone.to_string() }));
        let (status, body) = h.post(&h.token(&caller), &jws).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(json_body(&body)["active"], true);
        assert_eq!(
            h.store.app_store_link_owner(&t).await.unwrap(),
            Some(caller)
        );
        assert_eq!(h.records(&caller).await.len(), 1);
    }

    #[tokio::test]
    async fn token_for_unknown_account_binds_to_caller() {
        let Some(h) = Harness::new() else { return };
        let caller = h.user().await;
        let t = otid();
        let jws = h.jws(json!({
            "originalTransactionId": t,
            "appAccountToken": Uuid::new_v4().to_string(),
        }));
        let (status, body) = h.post(&h.token(&caller), &jws).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            h.store.app_store_link_owner(&t).await.unwrap(),
            Some(caller)
        );
    }

    /// Review Focus 3.
    #[tokio::test]
    async fn second_account_same_otid_is_409() {
        let Some(h) = Harness::new() else { return };
        let (first, second) = (h.user().await, h.user().await);
        let t = otid();

        let by_first =
            h.jws(json!({ "originalTransactionId": t, "appAccountToken": first.to_string() }));
        let (status, body) = h.post(&h.token(&first), &by_first).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // The same Apple ID's subscription, now claimed for another account
        // (here by a transaction naming a dead account).
        let by_second = h.jws(json!({
            "originalTransactionId": t,
            "appAccountToken": second.to_string(),
        }));
        let (status, body) = h.post(&h.token(&second), &by_second).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, OTHER_SUBSCRIPTION_BODY);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(first));
        assert!(h.records(&second).await.is_empty());
        assert_eq!(h.records(&first).await.len(), 1);
    }

    #[tokio::test]
    async fn deleting_the_first_account_frees_the_subscription() {
        let Some(h) = Harness::new() else { return };
        let (first, second) = (h.user().await, h.user().await);
        let t = otid();
        let by_first =
            h.jws(json!({ "originalTransactionId": t, "appAccountToken": first.to_string() }));
        assert_eq!(h.post(&h.token(&first), &by_first).await.0, StatusCode::OK);

        h.store
            .tombstone_account(&first, &format!("{first}.test"), None, 1_700_000_000)
            .await
            .unwrap();
        h.store.delete_identity_links_of(&first).await.unwrap();

        let by_second =
            h.jws(json!({ "originalTransactionId": t, "appAccountToken": second.to_string() }));
        let (status, body) = h.post(&h.token(&second), &by_second).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            h.store.app_store_link_owner(&t).await.unwrap(),
            Some(second)
        );
    }

    #[tokio::test]
    async fn bad_signature_is_422() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let payload =
            purchase(json!({ "originalTransactionId": t, "appAccountToken": id.to_string() }));
        let genuine = sign_jws(&payload, &h.fx);

        // Signed under another root.
        let other = fixture(Options::default());
        let (status, body) = h.post(&h.token(&id), &sign_jws(&payload, &other)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body, INVALID_BODY);

        // Payload swapped under the genuine signature.
        let mut parts: Vec<&str> = genuine.split('.').collect();
        let forged_payload = segment(&purchase(json!({
            "originalTransactionId": t,
            "appAccountToken": id.to_string(),
            "expiresDate": now_ms() + 3_650 * 86_400_000,
        })));
        parts[1] = &forged_payload;
        let (status, body) = h.post(&h.token(&id), &parts.join(".")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body, INVALID_BODY);

        // Not a JWS at all.
        let (status, body) = h.post(&h.token(&id), "garbage").await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body, INVALID_BODY);

        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), None);
        assert!(h.records(&id).await.is_empty());
    }

    #[tokio::test]
    async fn a_transaction_for_another_product_is_422() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let jws = h.jws(json!({
            "originalTransactionId": otid(),
            "appAccountToken": id.to_string(),
            "productId": "com.example.other",
        }));
        let (status, body) = h.post(&h.token(&id), &jws).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body, INVALID_BODY);
    }

    #[tokio::test]
    async fn a_body_without_signed_transaction_is_422_after_auth() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        for body in [&b"{}"[..], b"not json", b""] {
            let (status, text) = h.post_raw(Some(&h.token(&id)), body.to_vec()).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(text, INVALID_BODY);
        }
        // Unauthenticated callers learn nothing about the body.
        let (status, _) = h.post_raw(None, b"{}".to_vec()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn feature_off_is_503() {
        let Some(h) = Harness::with_config(false) else {
            return;
        };
        let id = h.user().await;
        let t = otid();
        let jws = h.jws(json!({ "originalTransactionId": t, "appAccountToken": id.to_string() }));
        let (status, body) = h.post(&h.token(&id), &jws).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, UNAVAILABLE_BODY);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), None);
        assert!(h.records(&id).await.is_empty());
    }

    /// An older snapshot changes nothing; the answer is the stored state, so a
    /// grace period a notification recorded counts.
    #[tokio::test]
    async fn stale_post_returns_stored_state() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let now = secs(now_ms());
        let stored = AppStoreRecord {
            original_transaction_id: t.clone(),
            product_id: PRODUCT.into(),
            environment: Environment::Production,
            expires_at: now - 600,
            grace_expires_at: Some(now + 3_600),
            revoked_at: None,
            last_signed_at: now + 60,
        };
        assert_eq!(
            h.store
                .put_app_store_state(&id, &stored, GraceUpdate::Set(stored.grace_expires_at))
                .await
                .unwrap(),
            StateOutcome::Applied
        );

        // Signed an hour before the stored snapshot, and expired.
        let older_ms = now_ms() - 3_600_000;
        let jws = sign_jws(
            &{
                let mut p = transaction(older_ms);
                p["originalTransactionId"] = json!(t);
                p["appAccountToken"] = json!(id.to_string());
                p["expiresDate"] = json!(older_ms + 1_000);
                p
            },
            &h.fx,
        );
        let (status, body) = h.post(&h.token(&id), &jws).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            json_body(&body),
            json!({
                "active": true,
                "expires_at": stored.expires_at,
                "environment": "Production",
                "token_can_publish": false,
            })
        );
        assert_eq!(h.records(&id).await, vec![stored]);
        // The subscription is still bound to the caller.
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(id));
    }

    #[tokio::test]
    async fn reports_whether_the_presented_token_can_publish() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let jws =
            h.jws(json!({ "originalTransactionId": otid(), "appAccountToken": id.to_string() }));

        let (status, body) = h.post(&h.publishing_token(&id), &jws).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(json_body(&body)["token_can_publish"], true);

        let (status, body) = h.post(&h.token(&id), &jws).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(json_body(&body)["token_can_publish"], false);
    }

    /// A client post never touches the grace a notification recorded: a
    /// member in billing-retry stays active after opening the app.
    #[tokio::test]
    async fn a_client_post_keeps_the_grace_a_notification_recorded() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let now = secs(now_ms());
        let stored = AppStoreRecord {
            original_transaction_id: t.clone(),
            product_id: PRODUCT.into(),
            environment: Environment::Sandbox,
            expires_at: now - 600,
            grace_expires_at: Some(now + 3_600),
            revoked_at: None,
            last_signed_at: now - 100,
        };
        h.store
            .put_app_store_state(&id, &stored, GraceUpdate::Set(stored.grace_expires_at))
            .await
            .unwrap();

        // Signed now (newer than the stored snapshot), same expiry.
        let signed_ms = now_ms();
        let jws = sign_jws(
            &{
                let mut p = transaction(signed_ms);
                p["originalTransactionId"] = json!(t);
                p["appAccountToken"] = json!(id.to_string());
                p["expiresDate"] = json!(stored.expires_at * 1000);
                p
            },
            &h.fx,
        );
        let (status, body) = h.post(&h.token(&id), &jws).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        let answer = json_body(&body);
        assert_eq!(answer["active"], true);
        assert_eq!(answer["expires_at"], stored.expires_at);
        // Applied, not stale: the snapshot moved on while the grace stayed.
        assert_eq!(
            h.records(&id).await,
            vec![AppStoreRecord {
                last_signed_at: secs(signed_ms),
                ..stored
            }]
        );
    }

    /// A storage failure in the account lookup is the server's, not a reason
    /// for the client to sign in again.
    #[tokio::test]
    async fn a_failed_account_lookup_is_500_not_401() {
        let Some(mut h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let jws = h.jws(json!({ "originalTransactionId": t, "appAccountToken": id.to_string() }));
        let token = h.token(&id);

        let blind = Arc::new(
            h.store
                .with_credentials_table(format!("missing-credentials-{}", Uuid::new_v4().simple())),
        );
        h.state.db_store = blind;
        h.app = Router::new()
            .route("/app-store/transactions", post(transactions_handler))
            .layer(Extension(h.state.clone()));

        let (status, _) = h.post(&token, &jws).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        // A bad token is still the client's to fix.
        let (status, _) = h.post("not-a-cwt", &jws).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), None);
    }
}
