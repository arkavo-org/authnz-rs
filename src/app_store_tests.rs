//! StoreKit JWS verification (`app_store::verify_jws`) against fixture chains
//! shaped like Apple's: a root, a WWDR-marked intermediate and a
//! receipt-signing leaf, ES256 unless a test says otherwise. Pure: no
//! network, no database, except `POST /app-store/transactions`, which runs
//! against DynamoDB Local (each of those tests returns early unless
//! `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is set, as CI's `test` job sets it).

use crate::app_store::{
    AppStoreConfig, AppStoreError, Environment, app_store_active, apple_root_g3_der,
    decode_notification, decode_renewal_info, decode_transaction, notifications_handler,
    transactions_handler, verify_jws,
};
use crate::db::GraceUpdate;
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
                "transactionId": "2000000987654321",
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
    assert_eq!(tx.transaction_id, "2000000987654321");
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

/// The transaction id says which billing period a snapshot describes, so a
/// transaction without one is refused.
#[test]
fn refuses_a_transaction_without_a_transaction_id() {
    let fx = fixture(Options::default());
    for transaction_id in [json!(null), json!(2_000_000_987_654_321_i64)] {
        assert_eq!(
            decode(&fx, json!({ "transactionId": transaction_id })),
            Err(AppStoreError::Malformed),
            "{transaction_id}"
        );
    }
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
        Err(AppStoreError::UnknownProduct)
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
            "originalTransactionId": "2000000123456789",
            "environment": "Production",
            "gracePeriodExpiresDate": 1_700_172_800_321_i64,
        }),
        &fx
    ));
    let decoded = decode_notification(&cfg, &notification(&fx, "DID_FAIL_TO_RENEW", data)).unwrap();

    assert_eq!(decoded.notification_type, "DID_FAIL_TO_RENEW");
    assert_eq!(decoded.grace, GraceUpdate::Set(Some(1_700_172_800)));
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
        Err(AppStoreError::UnknownProduct)
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
    assert_eq!(decoded.grace, GraceUpdate::Keep);
}

#[test]
fn renewal_info_without_grace_has_none() {
    let fx = fixture(Options::default());
    let cfg = AppStoreConfig::for_tests(fx.root_der.clone());
    let jws = sign_jws(&json!({ "environment": "Sandbox" }), &fx);
    let info = decode_renewal_info(&cfg, &jws).unwrap();
    assert_eq!(info.grace_expires_at, None);
    assert_eq!(info.original_transaction_id, None);
    assert_eq!(info.environment, Some(Environment::Sandbox));
    let xcode = sign_jws(&json!({ "environment": "Xcode" }), &fx);
    assert_eq!(
        decode_renewal_info(&cfg, &xcode),
        Err(AppStoreError::WrongEnvironment)
    );
}

fn renewal(fx: &Fixture, overrides: Value) -> String {
    let mut payload = json!({
        "originalTransactionId": "2000000123456789",
        "environment": "Sandbox",
    });
    for (key, value) in overrides.as_object().unwrap() {
        if value.is_null() {
            payload.as_object_mut().unwrap().remove(key);
        } else {
            payload[key] = value.clone();
        }
    }
    sign_jws(&payload, fx)
}

/// The outer environment label decides whether `appAppleId` is checked, so it
/// must not be able to wrap a transaction of the other environment.
#[test]
fn notification_refuses_a_nested_transaction_of_another_environment() {
    let fx = fixture(Options::default());
    let cfg = AppStoreConfig::for_tests(fx.root_der.clone());
    for (outer, inner) in [("Sandbox", "Production"), ("Production", "Sandbox")] {
        let mut data = notification_data(&fx, outer);
        data["signedTransactionInfo"] =
            json!(sign_jws(&purchase(json!({ "environment": inner })), &fx));
        assert_eq!(
            decode_notification(&cfg, &notification(&fx, "DID_RENEW", data)),
            Err(AppStoreError::WrongEnvironment),
            "{outer} wrapping {inner}"
        );
    }
}

#[test]
fn notification_refuses_renewal_info_of_another_subscription_or_environment() {
    let fx = fixture(Options::default());
    let cfg = AppStoreConfig::for_tests(fx.root_der.clone());
    let cases = [
        (
            renewal(&fx, json!({ "originalTransactionId": "2000000999999999" })),
            AppStoreError::Malformed,
        ),
        (
            renewal(&fx, json!({ "originalTransactionId": null })),
            AppStoreError::Malformed,
        ),
        (
            renewal(&fx, json!({ "environment": "Production" })),
            AppStoreError::WrongEnvironment,
        ),
    ];
    for (jws, expected) in cases {
        let mut data = notification_data(&fx, "Sandbox");
        data["signedRenewalInfo"] = json!(jws);
        assert_eq!(
            decode_notification(&cfg, &notification(&fx, "DID_FAIL_TO_RENEW", data)),
            Err(expected)
        );
    }

    // A matching renewal info that states no environment is accepted.
    let mut data = notification_data(&fx, "Sandbox");
    data["signedRenewalInfo"] = json!(renewal(
        &fx,
        json!({ "environment": null, "gracePeriodExpiresDate": 1_700_172_800_000_i64 })
    ));
    let decoded = decode_notification(&cfg, &notification(&fx, "DID_FAIL_TO_RENEW", data)).unwrap();
    assert_eq!(decoded.grace, GraceUpdate::Set(Some(1_700_172_800)));
}

/// Only renewal info speaks about the grace period: without it a
/// notification leaves the stored grace alone; with it, an absent
/// `gracePeriodExpiresDate` clears it.
#[test]
fn only_renewal_info_sets_or_clears_the_grace() {
    let fx = fixture(Options::default());
    let cfg = AppStoreConfig::for_tests(fx.root_der.clone());

    let without = notification(&fx, "REFUND", notification_data(&fx, "Sandbox"));
    assert_eq!(
        decode_notification(&cfg, &without).unwrap().grace,
        GraceUpdate::Keep
    );

    let mut data = notification_data(&fx, "Sandbox");
    data["signedRenewalInfo"] = json!(renewal(&fx, json!({})));
    let no_grace = notification(&fx, "DID_RENEW", data);
    assert_eq!(
        decode_notification(&cfg, &no_grace).unwrap().grace,
        GraceUpdate::Set(None)
    );
}

#[test]
fn summary_notification_decodes_without_a_transaction() {
    let fx = fixture(Options::default());
    let cfg = AppStoreConfig::for_tests(fx.root_der.clone());
    let jws = sign_jws(
        &json!({
            "notificationType": "RENEWAL_EXTENSION",
            "subtype": "SUMMARY",
            "summary": { "environment": "Sandbox", "succeededCount": 3 },
            "signedDate": now_ms(),
        }),
        &fx,
    );
    let decoded = decode_notification(&cfg, &jws).unwrap();
    assert_eq!(decoded.notification_type, "RENEWAL_EXTENSION");
    assert_eq!(decoded.transaction, None);

    // Any other verified payload without `data` has no transaction either.
    let bare = sign_jws(
        &json!({ "notificationType": "DID_RENEW", "signedDate": now_ms() }),
        &fx,
    );
    let decoded = decode_notification(&cfg, &bare).unwrap();
    assert_eq!(decoded.notification_type, "DID_RENEW");
    assert_eq!(decoded.transaction, None);

    // Where such a payload names a bundle, it must be this app's.
    for key in ["summary", "externalPurchaseToken"] {
        let named = |bundle: &str| {
            sign_jws(
                &json!({
                    "notificationType": "EXTERNAL_PURCHASE_TOKEN",
                    key: { "bundleId": bundle },
                    "signedDate": now_ms(),
                }),
                &fx,
            )
        };
        assert!(decode_notification(&cfg, &named("com.arkavo.ArkavoCreator")).is_ok());
        assert_eq!(
            decode_notification(&cfg, &named("com.example.other")),
            Err(AppStoreError::WrongApp),
            "{key}"
        );
    }
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
            transaction_id: Some("1".into()),
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

    pub(super) const OTHER_ACCOUNT_BODY: &str = "transaction belongs to another account";
    pub(super) const OTHER_SUBSCRIPTION_BODY: &str = "subscription belongs to another account";
    pub(super) const INVALID_BODY: &str = "invalid transaction";
    pub(super) const UNAVAILABLE_BODY: &str = "app store purchases unavailable";

    pub(super) struct Harness {
        pub(super) state: AppState,
        pub(super) store: Arc<DynamoDBStore>,
        pub(super) fx: Fixture,
        pub(super) app: Router,
    }

    impl Harness {
        /// `None` unless DynamoDB Local is configured.
        pub(super) fn new() -> Option<Self> {
            Self::with_config(true)
        }

        pub(super) fn with_config(enabled: bool) -> Option<Self> {
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

        pub(super) async fn user(&self) -> Uuid {
            self.store
                .create_user(
                    &format!("as-{}", &Uuid::new_v4().simple().to_string()[..12]),
                    "did:key:z6MkAppStoreRoute",
                )
                .await
                .unwrap()
                .user_id
        }

        pub(super) async fn deleted_user(&self) -> Uuid {
            let id = self.user().await;
            self.store
                .tombstone_account(&id, &format!("{id}.test"), None, 1_700_000_000)
                .await
                .unwrap();
            id
        }

        pub(super) fn token(&self, id: &Uuid) -> String {
            crate::authn::mint_auth_token(&self.state, id, None, None).unwrap()
        }

        /// A token that carries the derived creator-publishing entitlement.
        pub(super) fn publishing_token(&self, id: &Uuid) -> String {
            let user = ArkavoUserClaims {
                account_id: id.to_string(),
                roles: vec!["user".into()],
                entitlements: vec![],
                derived_entitlements: vec![ENTITLEMENT_CREATOR_PUBLISH.into()],
                patreon: None,
            };
            crate::authn::mint_auth_token(&self.state, id, Some(&user), None).unwrap()
        }

        pub(super) fn expired_token(&self, id: &Uuid) -> String {
            let mut claims =
                crate::cwt::ArkavoClaims::auth(&self.state.issuer, &id.to_string(), 1, None);
            claims.iat -= 7_200;
            claims.exp -= 7_200;
            let bytes = crate::cwt::mint(&claims, &self.state.cwt_signing_key, &self.state.cwt_kid)
                .unwrap();
            crate::cwt::encode_for_header(&bytes)
        }

        pub(super) fn jws(&self, overrides: Value) -> String {
            sign_jws(&purchase(overrides), &self.fx)
        }

        pub(super) async fn post_raw(
            &self,
            token: Option<&str>,
            body: Vec<u8>,
        ) -> (StatusCode, String) {
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

        pub(super) async fn post(&self, token: &str, jws: &str) -> (StatusCode, String) {
            self.post_raw(
                Some(token),
                json!({ "signed_transaction": jws })
                    .to_string()
                    .into_bytes(),
            )
            .await
        }

        pub(super) async fn records(&self, id: &Uuid) -> Vec<AppStoreRecord> {
            self.store
                .get_publishing_state(id)
                .await
                .unwrap()
                .map(|s| s.app_store)
                .unwrap_or_default()
        }
    }

    /// Numeric, as Apple's are; unique per test run (the database is shared).
    pub(super) fn otid() -> String {
        Uuid::new_v4().as_u128().to_string()
    }

    pub(super) fn secs(ms: i64) -> i64 {
        ms.div_euclid(1000)
    }

    pub(super) fn json_body(body: &str) -> Value {
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

        let by_first = h.jws(json!({
            "originalTransactionId": t,
            "appAccountToken": first.to_string(),
            "environment": "Production",
        }));
        let (status, body) = h.post(&h.token(&first), &by_first).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // The same Apple ID's Production subscription, resubscribed while
        // signed in to another account: the first account is live, so it
        // keeps it.
        let by_second = h.jws(json!({
            "originalTransactionId": t,
            "transactionId": "2000000123456790",
            "appAccountToken": second.to_string(),
            "environment": "Production",
        }));
        let (status, body) = h.post(&h.token(&second), &by_second).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, OTHER_SUBSCRIPTION_BODY);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(first));
        assert!(h.records(&second).await.is_empty());
        assert_eq!(h.records(&first).await.len(), 1);
    }

    /// App Review reuses Sandbox Apple IDs with fresh accounts: a Sandbox
    /// resubscription bought for the caller moves the link to it. The old
    /// owner's entry is left to expire.
    #[tokio::test]
    async fn a_sandbox_resubscription_moves_to_the_caller() {
        let Some(h) = Harness::new() else { return };
        let (first, second) = (h.user().await, h.user().await);
        let t = otid();
        let by_first =
            h.jws(json!({ "originalTransactionId": t, "appAccountToken": first.to_string() }));
        assert_eq!(h.post(&h.token(&first), &by_first).await.0, StatusCode::OK);
        let first_records = h.records(&first).await;

        let by_second = h.jws(json!({
            "originalTransactionId": t,
            "transactionId": "2000000123456790",
            "appAccountToken": second.to_string(),
        }));
        let (status, body) = h.post(&h.token(&second), &by_second).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(json_body(&body)["active"], true);
        assert_eq!(
            h.store.app_store_link_owner(&t).await.unwrap(),
            Some(second)
        );
        let moved = h.records(&second).await;
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].transaction_id.as_deref(), Some("2000000123456790"));
        assert_eq!(h.records(&first).await, first_records);

        // The resubscription was bought for the second account, so the first
        // cannot take it back with it.
        let (status, body) = h.post(&h.token(&first), &by_second).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, OTHER_ACCOUNT_BODY);
        assert_eq!(
            h.store.app_store_link_owner(&t).await.unwrap(),
            Some(second)
        );
    }

    /// A subscription whose account was deleted (not yet swept) moves to the
    /// caller, Production included.
    #[tokio::test]
    async fn a_dead_owners_subscription_moves_to_the_caller() {
        let Some(h) = Harness::new() else { return };
        let (first, second) = (h.user().await, h.user().await);
        let t = otid();
        let by_first = h.jws(json!({
            "originalTransactionId": t,
            "appAccountToken": first.to_string(),
            "environment": "Production",
        }));
        assert_eq!(h.post(&h.token(&first), &by_first).await.0, StatusCode::OK);
        h.store
            .tombstone_account(&first, &format!("{first}.test"), None, 1_700_000_000)
            .await
            .unwrap();
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(first));

        let by_second = h.jws(json!({
            "originalTransactionId": t,
            "appAccountToken": second.to_string(),
            "environment": "Production",
        }));
        let (status, body) = h.post(&h.token(&second), &by_second).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            h.store.app_store_link_owner(&t).await.unwrap(),
            Some(second)
        );
        assert_eq!(h.records(&second).await.len(), 1);
    }

    /// A Sandbox purchase whose `appAccountToken` names a third account is
    /// not the caller's to move: 409 while that account is deleted (and the
    /// owner is live), 403 while it is live.
    #[tokio::test]
    async fn a_move_never_happens_for_a_third_accounts_purchase() {
        let Some(h) = Harness::new() else { return };
        let (owner, caller, third) = (h.user().await, h.user().await, h.user().await);
        let t = otid();
        let by_owner =
            h.jws(json!({ "originalTransactionId": t, "appAccountToken": owner.to_string() }));
        assert_eq!(h.post(&h.token(&owner), &by_owner).await.0, StatusCode::OK);

        let for_third =
            h.jws(json!({ "originalTransactionId": t, "appAccountToken": third.to_string() }));
        let (status, body) = h.post(&h.token(&caller), &for_third).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, OTHER_ACCOUNT_BODY);

        h.store
            .tombstone_account(&third, &format!("{third}.test"), None, 1_700_000_000)
            .await
            .unwrap();
        let (status, body) = h.post(&h.token(&caller), &for_third).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, OTHER_SUBSCRIPTION_BODY);

        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(owner));
        assert!(h.records(&caller).await.is_empty());
        assert_eq!(h.records(&owner).await.len(), 1);
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
            transaction_id: Some("2000000123456789".into()),
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
                p["environment"] = json!("Production");
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

    /// Creator posting last month's refunded transaction (signed after this
    /// month's) changes nothing and is answered with the stored period.
    #[tokio::test]
    async fn a_past_period_post_returns_the_stored_state() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let t0 = now_ms() - 3_600_000;
        let this_month_end = now_ms() + 30 * 86_400_000;
        let current = h.jws(json!({
            "originalTransactionId": t,
            "transactionId": "t2",
            "appAccountToken": id.to_string(),
            "signedDate": t0,
            "expiresDate": this_month_end,
        }));
        let (status, body) = h.post(&h.token(&id), &current).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let before = h.records(&id).await;
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].transaction_id.as_deref(), Some("t2"));

        let last_month = h.jws(json!({
            "originalTransactionId": t,
            "transactionId": "t1",
            "appAccountToken": id.to_string(),
            "signedDate": t0 + 60_000,
            "expiresDate": t0 - 1_000,
            "revocationDate": t0 + 30_000,
        }));
        let (status, body) = h.post(&h.token(&id), &last_month).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            json_body(&body),
            json!({
                "active": true,
                "expires_at": secs(this_month_end),
                "environment": "Sandbox",
                "token_can_publish": false,
            })
        );
        assert_eq!(h.records(&id).await, before);
    }

    /// A Sandbox snapshot of a subscription stored as Production is refused
    /// and changes nothing.
    #[tokio::test]
    async fn a_post_of_another_environment_is_422() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let signed = now_ms() - 60_000;
        let production = h.jws(json!({
            "originalTransactionId": t,
            "appAccountToken": id.to_string(),
            "environment": "Production",
            "signedDate": signed,
        }));
        let (status, body) = h.post(&h.token(&id), &production).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let before = h.records(&id).await;
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].environment, Environment::Production);

        let sandbox = h.jws(json!({
            "originalTransactionId": t,
            "appAccountToken": id.to_string(),
            "environment": "Sandbox",
            "signedDate": signed + 30_000,
            "revocationDate": signed + 10_000,
        }));
        let (status, body) = h.post(&h.token(&id), &sandbox).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body, INVALID_BODY);
        assert_eq!(h.records(&id).await, before);
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
            transaction_id: None,
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
                transaction_id: Some("2000000123456789".into()),
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

// --------- POST /app-store/notifications ---------

mod notifications_route {
    use super::transactions_route::{Harness, json_body, otid, secs};
    use super::*;
    use crate::db::AppStoreRecord;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use axum::{Extension, Router};
    use uuid::Uuid;

    /// A moment well in the past, so the seconds that order snapshots can be
    /// told apart without waiting.
    fn base_ms() -> i64 {
        now_ms() - 3_600_000
    }

    /// A snapshot of one subscription: signed `signed_ms`, valid until
    /// `expires_ms`, bought for `token`.
    fn snapshot(t: &str, token: Option<&Uuid>, signed_ms: i64, expires_ms: i64) -> Value {
        json!({
            "originalTransactionId": t,
            "appAccountToken": token.map(|id| id.to_string()),
            "signedDate": signed_ms,
            "expiresDate": expires_ms,
        })
    }

    impl Harness {
        fn notification_app(&self) -> Router {
            Router::new()
                .route("/app-store/notifications", post(notifications_handler))
                .layer(Extension(self.state.clone()))
        }

        async fn notify_raw(&self, body: Vec<u8>) -> (StatusCode, String) {
            self.notification_app().oneshot_post(body).await
        }

        async fn notify_payload(&self, signed_payload: &str) -> (StatusCode, String) {
            self.notify_raw(
                json!({ "signedPayload": signed_payload })
                    .to_string()
                    .into_bytes(),
            )
            .await
        }

        /// A signed Sandbox notification of `notification_type` carrying the
        /// transaction `tx` (and renewal info `renewal`, if any).
        fn notice(&self, notification_type: &str, tx: Value, renewal: Option<Value>) -> String {
            self.notice_in("Sandbox", notification_type, tx, renewal)
        }

        /// [`Self::notice`] for `environment`, which the transaction and any
        /// renewal info state too (a Production one carries the app's Apple
        /// ID).
        fn notice_in(
            &self,
            environment: &str,
            notification_type: &str,
            mut tx: Value,
            renewal: Option<Value>,
        ) -> String {
            tx["environment"] = json!(environment);
            let mut data = json!({
                "bundleId": "com.arkavo.ArkavoCreator",
                "appAppleId": 6_738_845_556_i64,
                "environment": environment,
                "signedTransactionInfo": self.jws(tx),
            });
            if let Some(mut renewal) = renewal {
                renewal["environment"] = json!(environment);
                data["signedRenewalInfo"] = json!(sign_jws(&renewal, &self.fx));
            }
            notification(&self.fx, notification_type, data)
        }

        async fn deliver_in(
            &self,
            environment: &str,
            notification_type: &str,
            tx: Value,
            renewal: Option<Value>,
        ) -> StatusCode {
            let (status, body) = self
                .notify_payload(&self.notice_in(environment, notification_type, tx, renewal))
                .await;
            assert!(body.is_empty(), "{body}");
            status
        }

        async fn deliver(
            &self,
            notification_type: &str,
            tx: Value,
            renewal: Option<Value>,
        ) -> StatusCode {
            self.deliver_in("Sandbox", notification_type, tx, renewal)
                .await
        }
    }

    trait PostOnce {
        async fn oneshot_post(self, body: Vec<u8>) -> (StatusCode, String);
    }

    impl PostOnce for Router {
        async fn oneshot_post(self, body: Vec<u8>) -> (StatusCode, String) {
            let resp = self
                .oneshot(
                    Request::post("/app-store/notifications")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, String::from_utf8_lossy(&bytes).into_owned())
        }
    }

    use tower::ServiceExt;

    fn renewal_info(t: &str, grace_ms: Option<i64>) -> Value {
        let mut info = json!({ "originalTransactionId": t, "environment": "Sandbox" });
        if let Some(grace) = grace_ms {
            info["gracePeriodExpiresDate"] = json!(grace);
        }
        info
    }

    /// A billing period of `t`: the snapshot of transaction `tid`.
    fn period(t: &str, tid: &str, token: &Uuid, signed_ms: i64, expires_ms: i64) -> Value {
        let mut tx = snapshot(t, Some(token), signed_ms, expires_ms);
        tx["transactionId"] = json!(tid);
        tx
    }

    async fn only_record(h: &Harness, id: &Uuid) -> AppStoreRecord {
        let mut records = h.records(id).await;
        assert_eq!(records.len(), 1, "{records:?}");
        records.remove(0)
    }

    /// Covers: a renewal moves the stored expiry forward.
    #[tokio::test]
    async fn renewal_extends_expiry() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let t0 = base_ms();
        let first_expiry = t0 + 30 * 86_400_000;
        let renewed_expiry = first_expiry + 30 * 86_400_000;

        let status = h
            .deliver(
                "SUBSCRIBED",
                snapshot(&t, Some(&id), t0, first_expiry),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(only_record(&h, &id).await.expires_at, secs(first_expiry));

        let status = h
            .deliver(
                "DID_RENEW",
                snapshot(&t, Some(&id), t0 + 5_000, renewed_expiry),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let record = only_record(&h, &id).await;
        assert_eq!(record.expires_at, secs(renewed_expiry));
        assert_eq!(record.last_signed_at, secs(t0 + 5_000));
        assert_eq!(record.product_id, PRODUCT);
        assert_eq!(record.environment, Environment::Sandbox);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(id));
    }

    /// Covers: a refund's `revocationDate` is stored even though the expiry is
    /// in the future.
    #[tokio::test]
    async fn refund_sets_revoked_at() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let t0 = base_ms();
        let expiry = now_ms() + 30 * 86_400_000;
        h.deliver("SUBSCRIBED", snapshot(&t, Some(&id), t0, expiry), None)
            .await;
        assert_eq!(only_record(&h, &id).await.revoked_at, None);

        let mut refund = snapshot(&t, Some(&id), t0 + 10_000, expiry);
        refund["revocationDate"] = json!(t0 + 9_000);
        assert_eq!(h.deliver("REFUND", refund, None).await, StatusCode::OK);

        let record = only_record(&h, &id).await;
        assert_eq!(record.revoked_at, Some(secs(t0 + 9_000)));
        assert_eq!(record.expires_at, secs(expiry));
    }

    /// A REFUND of last month's transaction is signed when Apple sends it,
    /// after this month's renewal. It neither shortens nor revokes the current
    /// period, so the member's own re-post of the current transaction still
    /// applies (before, it was stale and locked the member out).
    #[tokio::test]
    async fn a_later_refund_of_an_earlier_period_keeps_the_current_one() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let t0 = base_ms();
        let this_month_end = now_ms() + 30 * 86_400_000;

        let status = h
            .deliver(
                "DID_RENEW",
                period(&t, "t2", &id, t0 + 10_000, this_month_end),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let current = only_record(&h, &id).await;

        for notification_type in ["CONSUMPTION_REQUEST", "REFUND", "REFUND_REVERSED"] {
            let mut last_month = period(&t, "t1", &id, t0 + 30_000, t0);
            last_month["revocationDate"] = json!(t0 + 20_000);
            assert_eq!(
                h.deliver(notification_type, last_month, None).await,
                StatusCode::OK,
                "{notification_type}"
            );
            assert_eq!(only_record(&h, &id).await, current, "{notification_type}");
        }
        assert_eq!(current.transaction_id.as_deref(), Some("t2"));
        assert_eq!(current.expires_at, secs(this_month_end));
        assert_eq!(current.revoked_at, None);

        // Creator re-posts the current transaction, signed before the refund
        // was sent.
        let repost = h.jws(period(&t, "t2", &id, t0 + 20_000, this_month_end));
        let (status, body) = h.post(&h.token(&id), &repost).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(json_body(&body)["active"], true);
        assert_eq!(only_record(&h, &id).await.last_signed_at, secs(t0 + 20_000));
    }

    /// A renewal is a new transaction that ends later: it applies, and a
    /// refund of it (the current period) still revokes.
    #[tokio::test]
    async fn a_renewal_by_a_new_transaction_applies_and_its_refund_revokes() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let t0 = base_ms();
        let first_end = t0 + 1_000;
        let second_end = now_ms() + 30 * 86_400_000;

        h.deliver("SUBSCRIBED", period(&t, "t1", &id, t0, first_end), None)
            .await;
        let status = h
            .deliver(
                "DID_RENEW",
                period(&t, "t2", &id, t0 + 5_000, second_end),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let renewed = only_record(&h, &id).await;
        assert_eq!(renewed.transaction_id.as_deref(), Some("t2"));
        assert_eq!(renewed.expires_at, secs(second_end));

        let mut refund = period(&t, "t2", &id, t0 + 10_000, second_end);
        refund["revocationDate"] = json!(t0 + 9_000);
        assert_eq!(h.deliver("REFUND", refund, None).await, StatusCode::OK);
        let refunded = only_record(&h, &id).await;
        assert_eq!(refunded.transaction_id.as_deref(), Some("t2"));
        assert_eq!(refunded.revoked_at, Some(secs(t0 + 9_000)));
        assert_eq!(refunded.expires_at, secs(second_end));
    }

    /// Review Focus 2: an older EXPIRED delivered after a newer DID_RENEW
    /// must not end an active membership.
    #[tokio::test]
    async fn older_expired_after_newer_renew_is_ignored() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let t0 = base_ms();
        let lapsed = t0 + 1_000;
        let renewed = now_ms() + 30 * 86_400_000;

        h.deliver(
            "DID_RENEW",
            snapshot(&t, Some(&id), t0 + 60_000, renewed),
            None,
        )
        .await;
        // The EXPIRED was signed before the renewal and arrives after it.
        let status = h
            .deliver(
                "EXPIRED",
                snapshot(&t, Some(&id), t0 + 30_000, lapsed),
                None,
            )
            .await;

        assert_eq!(status, StatusCode::OK);
        let record = only_record(&h, &id).await;
        assert_eq!(record.expires_at, secs(renewed));
        assert_eq!(record.last_signed_at, secs(t0 + 60_000));
    }

    /// Covers: grace comes from the renewal info and is cleared by the next
    /// snapshot that has none.
    #[tokio::test]
    async fn grace_period_is_stored() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let t0 = base_ms();
        let expiry = t0 + 1_000;
        let grace = now_ms() + 16 * 86_400_000;

        let status = h
            .deliver(
                "DID_FAIL_TO_RENEW",
                snapshot(&t, Some(&id), t0, expiry),
                Some(renewal_info(&t, Some(grace))),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let record = only_record(&h, &id).await;
        assert_eq!(record.grace_expires_at, Some(secs(grace)));
        assert_eq!(record.expires_at, secs(expiry));

        // Billing recovers: the later snapshot carries no grace.
        let status = h
            .deliver(
                "DID_RENEW",
                snapshot(&t, Some(&id), t0 + 5_000, expiry + 30 * 86_400_000),
                Some(renewal_info(&t, None)),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(only_record(&h, &id).await.grace_expires_at, None);
    }

    /// A notification without renewal info (a REFUND_REVERSED, a
    /// CONSUMPTION_REQUEST) leaves a recorded grace period alone: only renewal
    /// info sets or clears it.
    #[tokio::test]
    async fn a_notification_without_renewal_info_keeps_the_grace() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let t0 = base_ms();
        let expiry = t0 + 1_000;
        let grace = now_ms() + 16 * 86_400_000;
        h.deliver(
            "DID_FAIL_TO_RENEW",
            snapshot(&t, Some(&id), t0, expiry),
            Some(renewal_info(&t, Some(grace))),
        )
        .await;
        assert_eq!(
            only_record(&h, &id).await.grace_expires_at,
            Some(secs(grace))
        );

        let status = h
            .deliver(
                "CONSUMPTION_REQUEST",
                snapshot(&t, Some(&id), t0 + 5_000, expiry),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let record = only_record(&h, &id).await;
        // Applied (the snapshot moved on), the grace kept.
        assert_eq!(record.last_signed_at, secs(t0 + 5_000));
        assert_eq!(record.grace_expires_at, Some(secs(grace)));
    }

    /// A Sandbox notification of a subscription stored as Production is
    /// acknowledged and changes nothing, so it cannot flip the record.
    #[tokio::test]
    async fn a_notification_of_another_environment_changes_nothing() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let t0 = base_ms();
        let expiry = now_ms() + 30 * 86_400_000;
        let status = h
            .deliver_in(
                "Production",
                "SUBSCRIBED",
                snapshot(&t, Some(&id), t0, expiry),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let before = only_record(&h, &id).await;
        assert_eq!(before.environment, Environment::Production);

        let mut refund = snapshot(&t, Some(&id), t0 + 10_000, expiry);
        refund["revocationDate"] = json!(t0 + 9_000);
        assert_eq!(
            h.deliver_in("Sandbox", "REFUND", refund, None).await,
            StatusCode::OK
        );
        assert_eq!(only_record(&h, &id).await, before);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(id));
    }

    #[tokio::test]
    async fn unlinked_with_live_token_binds() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), None);

        let expiry = now_ms() + 30 * 86_400_000;
        let status = h
            .deliver(
                "SUBSCRIBED",
                snapshot(&t, Some(&id), base_ms(), expiry),
                None,
            )
            .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(id));
        assert_eq!(only_record(&h, &id).await.original_transaction_id, t);
    }

    /// A linked Production subscription goes to its live owner, whatever the
    /// token names.
    #[tokio::test]
    async fn a_linked_subscription_follows_its_link() {
        let Some(h) = Harness::new() else { return };
        let owner = h.user().await;
        let other = h.user().await;
        let t = otid();
        let expiry = now_ms() + 30 * 86_400_000;
        h.deliver_in(
            "Production",
            "SUBSCRIBED",
            snapshot(&t, Some(&owner), base_ms(), expiry),
            None,
        )
        .await;

        let status = h
            .deliver_in(
                "Production",
                "DID_RENEW",
                snapshot(&t, Some(&other), base_ms() + 5_000, expiry + 86_400_000),
                None,
            )
            .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(owner));
        assert_eq!(
            only_record(&h, &owner).await.expires_at,
            secs(expiry + 86_400_000)
        );
        assert!(h.records(&other).await.is_empty());
    }

    /// A Sandbox notification for a live account other than the owner moves
    /// the link to it (App Review's reused Sandbox Apple IDs). The old
    /// owner's entry is left to expire.
    #[tokio::test]
    async fn a_sandbox_notification_moves_the_link_to_the_account_it_names() {
        let Some(h) = Harness::new() else { return };
        let (owner, other) = (h.user().await, h.user().await);
        let t = otid();
        let expiry = now_ms() + 30 * 86_400_000;
        h.deliver(
            "SUBSCRIBED",
            snapshot(&t, Some(&owner), base_ms(), expiry),
            None,
        )
        .await;
        let owners_record = only_record(&h, &owner).await;

        let status = h
            .deliver(
                "SUBSCRIBED",
                snapshot(&t, Some(&other), base_ms() + 5_000, expiry + 86_400_000),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(other));
        assert_eq!(
            only_record(&h, &other).await.expires_at,
            secs(expiry + 86_400_000)
        );
        assert_eq!(only_record(&h, &owner).await, owners_record);
    }

    /// A deleted owner's subscription (not yet swept) moves to the live
    /// account a notification names, Production included.
    #[tokio::test]
    async fn a_notification_moves_a_dead_owners_link() {
        let Some(h) = Harness::new() else { return };
        let (owner, other) = (h.user().await, h.user().await);
        let t = otid();
        let expiry = now_ms() + 30 * 86_400_000;
        h.deliver_in(
            "Production",
            "SUBSCRIBED",
            snapshot(&t, Some(&owner), base_ms(), expiry),
            None,
        )
        .await;
        h.store
            .tombstone_account(&owner, &format!("{owner}.test"), None, 1_700_000_000)
            .await
            .unwrap();

        let status = h
            .deliver_in(
                "Production",
                "SUBSCRIBED",
                snapshot(&t, Some(&other), base_ms() + 5_000, expiry),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(other));
        assert_eq!(only_record(&h, &other).await.expires_at, secs(expiry));
    }

    /// A notification never moves a link to an account that is not live, or
    /// when it names none: it follows the link.
    #[tokio::test]
    async fn a_notification_never_moves_to_an_account_that_is_not_live() {
        let Some(h) = Harness::new() else { return };
        let owner = h.user().await;
        let gone = h.deleted_user().await;
        let t = otid();
        let t0 = base_ms();
        let expiry = now_ms() + 30 * 86_400_000;
        h.deliver("SUBSCRIBED", snapshot(&t, Some(&owner), t0, expiry), None)
            .await;

        for (i, token) in [Some(gone), Some(Uuid::new_v4()), None].iter().enumerate() {
            let signed = t0 + 5_000 * (i as i64 + 1);
            let status = h
                .deliver(
                    "DID_RENEW",
                    snapshot(&t, token.as_ref(), signed, expiry),
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{token:?}");
            assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(owner));
            assert_eq!(only_record(&h, &owner).await.last_signed_at, secs(signed));
        }
        assert!(h.records(&gone).await.is_empty());
    }

    #[tokio::test]
    async fn unlinked_without_live_token_is_dropped() {
        let Some(h) = Harness::new() else { return };
        let gone = h.deleted_user().await;
        let unknown = Uuid::new_v4();
        let expiry = now_ms() + 30 * 86_400_000;

        for (name, token) in [
            ("none", None),
            ("unknown", Some(unknown)),
            ("deleted", Some(gone)),
        ] {
            let t = otid();
            let status = h
                .deliver(
                    "DID_RENEW",
                    snapshot(&t, token.as_ref(), base_ms(), expiry),
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{name}");
            assert_eq!(
                h.store.app_store_link_owner(&t).await.unwrap(),
                None,
                "{name}"
            );
        }
        assert!(h.records(&gone).await.is_empty());
        assert!(h.records(&unknown).await.is_empty());
    }

    /// Review Focus 3: a notification racing the deletion sweep cannot write
    /// onto the tombstone.
    #[tokio::test]
    async fn notification_after_sweep_writes_nothing() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let expiry = now_ms() + 30 * 86_400_000;
        h.deliver(
            "SUBSCRIBED",
            snapshot(&t, Some(&id), base_ms(), expiry),
            None,
        )
        .await;
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), Some(id));

        // Tombstoned, links not swept yet: the link still names the account.
        h.store
            .tombstone_account(&id, &format!("{id}.test"), None, 1_700_000_000)
            .await
            .unwrap();
        let before = h.store.get_publishing_state(&id).await.unwrap();
        let status = h
            .deliver(
                "DID_RENEW",
                snapshot(&t, Some(&id), now_ms(), expiry + 30 * 86_400_000),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h.store.get_publishing_state(&id).await.unwrap(), before);
        assert!(
            h.records(&id)
                .await
                .iter()
                .all(|r| r.expires_at == secs(expiry))
        );

        // Swept: the link is gone, and the token names a dead account.
        assert_eq!(h.store.delete_identity_links_of(&id).await.unwrap(), 1);
        let status = h
            .deliver(
                "DID_RENEW",
                snapshot(&t, Some(&id), now_ms() + 1_000, expiry + 60 * 86_400_000),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), None);
        assert!(
            h.records(&id)
                .await
                .iter()
                .all(|r| r.expires_at == secs(expiry))
        );
    }

    #[tokio::test]
    async fn unverified_payload_is_400() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let expiry = now_ms() + 30 * 86_400_000;

        // Signed by a chain to another root.
        let rogue = fixture(Options::default());
        let mut data = json!({
            "bundleId": "com.arkavo.ArkavoCreator",
            "environment": "Sandbox",
        });
        data["signedTransactionInfo"] = json!(sign_jws(
            &purchase(snapshot(&t, Some(&id), base_ms(), expiry)),
            &rogue
        ));
        let forged = notification(&rogue, "SUBSCRIBED", data);
        let (status, _) = h.notify_payload(&forged).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Genuine outer signature, forged nested transaction.
        let mut data = json!({
            "bundleId": "com.arkavo.ArkavoCreator",
            "environment": "Sandbox",
        });
        data["signedTransactionInfo"] = json!(sign_jws(
            &purchase(snapshot(&t, Some(&id), base_ms(), expiry)),
            &rogue
        ));
        let (status, _) = h
            .notify_payload(&notification(&h.fx, "SUBSCRIBED", data))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = h.notify_payload("not.a.jws").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), None);
        assert!(h.records(&id).await.is_empty());
    }

    #[tokio::test]
    async fn empty_body_is_400() {
        let Some(h) = Harness::new() else { return };
        for body in [&b""[..], b"{}", b"not json", br#"{"signedPayload":7}"#] {
            let (status, _) = h.notify_raw(body.to_vec()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
        }
    }

    #[tokio::test]
    async fn test_notification_is_200() {
        let Some(h) = Harness::new() else { return };
        // Apple's Production TEST carries the app's Apple ID.
        let production = notification(
            &h.fx,
            "TEST",
            json!({
                "bundleId": "com.arkavo.ArkavoCreator",
                "appAppleId": 6_738_845_556_i64,
                "environment": "Production",
            }),
        );
        let sandbox = notification(
            &h.fx,
            "TEST",
            json!({ "bundleId": "com.arkavo.ArkavoCreator", "environment": "Sandbox" }),
        );
        for payload in [production, sandbox] {
            let (status, body) = h.notify_payload(&payload).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.is_empty(), "{body}");
        }
    }

    #[tokio::test]
    async fn summary_notification_is_200() {
        let Some(h) = Harness::new() else { return };
        let payload = sign_jws(
            &json!({
                "notificationType": "RENEWAL_EXTENSION",
                "subtype": "SUMMARY",
                "summary": { "environment": "Sandbox", "succeededCount": 2 },
                "signedDate": now_ms(),
            }),
            &h.fx,
        );
        let (status, _) = h.notify_payload(&payload).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// Apple's third V2 shape carries an `externalPurchaseToken`, not `data`.
    #[tokio::test]
    async fn payload_without_data_is_200_and_writes_nothing() {
        let Some(h) = Harness::new() else { return };
        let payload = sign_jws(
            &json!({
                "notificationType": "EXTERNAL_PURCHASE_TOKEN",
                "externalPurchaseToken": {
                    "externalPurchaseId": "SANDBOX_abc",
                    "bundleId": "com.arkavo.ArkavoCreator",
                },
                "signedDate": now_ms(),
            }),
            &h.fx,
        );
        let (status, body) = h.notify_payload(&payload).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.is_empty(), "{body}");

        let bare = sign_jws(
            &json!({ "notificationType": "SOMETHING_NEW", "signedDate": now_ms() }),
            &h.fx,
        );
        let (status, _) = h.notify_payload(&bare).await;
        assert_eq!(status, StatusCode::OK);

        // Another app's token is not ours.
        let other = sign_jws(
            &json!({
                "notificationType": "EXTERNAL_PURCHASE_TOKEN",
                "externalPurchaseToken": { "bundleId": "com.example.other" },
                "signedDate": now_ms(),
            }),
            &h.fx,
        );
        let (status, _) = h.notify_payload(&other).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// A product of this app that does not grant membership is acknowledged
    /// and writes nothing; a wrong bundle or an unconfigured environment is
    /// still turned away.
    #[tokio::test]
    async fn another_product_is_200_and_writes_nothing() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let expiry = now_ms() + 30 * 86_400_000;
        let mut tx = snapshot(&t, Some(&id), base_ms(), expiry);
        tx["productId"] = json!("com.arkavo.ArkavoCreator.tip");

        let status = h.deliver("DID_RENEW", tx.clone(), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), None);
        assert!(h.records(&id).await.is_empty());

        // An existing membership is not touched by the other product.
        let member = otid();
        h.deliver(
            "SUBSCRIBED",
            snapshot(&member, Some(&id), base_ms(), expiry),
            None,
        )
        .await;
        let mut tip = snapshot(&member, Some(&id), base_ms() + 5_000, expiry + 86_400_000);
        tip["productId"] = json!("com.arkavo.ArkavoCreator.tip");
        assert_eq!(h.deliver("DID_RENEW", tip, None).await, StatusCode::OK);
        assert_eq!(only_record(&h, &id).await.expires_at, secs(expiry));

        let mut wrong_bundle = tx;
        wrong_bundle["bundleId"] = json!("com.example.other");
        let (status, _) = h
            .notify_payload(&h.notice("DID_RENEW", wrong_bundle, None))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn production_wrong_app_apple_id_is_400() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let expiry = now_ms() + 30 * 86_400_000;
        let mut payload = snapshot(&t, Some(&id), base_ms(), expiry);
        payload["environment"] = json!("Production");
        for app_apple_id in [json!(1), json!(null)] {
            let data = json!({
                "bundleId": "com.arkavo.ArkavoCreator",
                "appAppleId": app_apple_id,
                "environment": "Production",
                "signedTransactionInfo": h.jws(payload.clone()),
            });
            let (status, _) = h
                .notify_payload(&notification(&h.fx, "SUBSCRIBED", data))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        // A Sandbox label wrapped around a Production transaction is no way
        // round the rule.
        let data = json!({
            "bundleId": "com.arkavo.ArkavoCreator",
            "environment": "Sandbox",
            "signedTransactionInfo": h.jws(payload),
        });
        let (status, _) = h
            .notify_payload(&notification(&h.fx, "SUBSCRIBED", data))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        assert_eq!(h.store.app_store_link_owner(&t).await.unwrap(), None);
        assert!(h.records(&id).await.is_empty());
    }

    #[tokio::test]
    async fn feature_off_is_503() {
        let Some(h) = Harness::with_config(false) else {
            return;
        };
        let (status, body) = h.notify_payload("anything").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, "app store purchases unavailable");
    }

    /// A storage failure is the server's: Apple retries a 500.
    #[tokio::test]
    async fn a_storage_failure_is_500() {
        let Some(mut h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let payload = h.notice(
            "SUBSCRIBED",
            snapshot(&t, Some(&id), base_ms(), now_ms() + 86_400_000),
            None,
        );
        h.state.db_store = std::sync::Arc::new(
            h.store
                .with_credentials_table(format!("missing-credentials-{}", Uuid::new_v4().simple())),
        );
        let (status, _) = h.notify_payload(&payload).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Ordering keys on `original_transaction_id` and `signedDate`, never on
    /// the JWS bytes: the same snapshot re-signed (new signature bytes) is
    /// absorbed.
    #[tokio::test]
    async fn a_redelivered_snapshot_changes_nothing() {
        let Some(h) = Harness::new() else { return };
        let id = h.user().await;
        let t = otid();
        let t0 = base_ms();
        let expiry = now_ms() + 30 * 86_400_000;
        for _ in 0..2 {
            let status = h
                .deliver("DID_RENEW", snapshot(&t, Some(&id), t0, expiry), None)
                .await;
            assert_eq!(status, StatusCode::OK);
        }
        let record = only_record(&h, &id).await;
        assert_eq!(record.expires_at, secs(expiry));
        assert_eq!(record.last_signed_at, secs(t0));
    }
}
