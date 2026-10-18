//! StoreKit JWS verification (`app_store::verify_jws`) against fixture chains
//! shaped like Apple's: a root, a WWDR-marked intermediate and a
//! receipt-signing leaf, ES256 unless a test says otherwise. Pure: no
//! network, no database.

use crate::app_store::{AppStoreError, apple_root_g3_der, verify_jws};
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
