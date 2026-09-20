# App Attest Registration Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Require a valid Apple App Attest attestation before any account can be registered, so registration cannot be scripted by a software WebAuthn authenticator.

**Architecture:** A new unauthenticated attest flow runs ahead of account creation and issues a one-shot session ticket that `/register` requires. The attestation verifier currently inlined in `finish_attestation` is extracted so the new unbound path and the existing bound path share one implementation, and the three verification gaps that implementation documents are closed first, because the gate rests entirely on them.

**Tech Stack:** Rust, Axum, `tower-sessions` (MemoryStore), DynamoDB (`aws-sdk-dynamodb`), `x509-parser` 0.16, `ciborium`, `sha2`. Client: Swift, `DeviceCheck.framework`, SPM.

**Spec:** `docs/superpowers/specs/2026-09-20-app-attest-registration-gate-design.md`

## Global Constraints

- Registration targets iOS 26+, macOS on Apple silicon only. No non-Secure-Enclave fallback path may be added.
- `APP_ATTEST_APP_ID` is the hex SHA-256 of `<TeamID>.<BundleID>`. On the registration-gate path it is **mandatory**; unset must fail closed, never warn-and-continue.
- Derived claim/session keys must not collide with existing session keys: `reg_state`, `auth_state`, `SESSION_ATTEST_STATE_KEY`, `SESSION_ASSERT_STATE_KEY`.
- The attestation verifier is shared. Never write a second copy for the unbound path.
- Arkavo-issued tokens are CWT (COSE_Sign1, ES256). This plan issues no new token types.
- Run `cargo fmt` and `cargo clippy` before every commit; both must be clean.

---

### Task 0: Capture a real attestation fixture

Every later task's tests need a genuine App Attest blob. App Attest does not run in the Simulator, so this is a one-time manual capture on real hardware. Nothing else can start until this lands.

**Capture host: the Creator app** at `/Users/arkavo/Projects/Creator` (`ArkavoCreator.xcodeproj`). It is a macOS app on Apple silicon, so the Secure Enclave is present; it is already on team `M8GS7ZT95Y`, already carries the `com.arkavo.webauthn` keychain access group, and already links ArkavoKit. **No App Store or TestFlight release is required** — App Attest's `development` environment works from a locally signed build.

**Files:**
- Modify: `/Users/arkavo/Projects/Creator/ArkavoCreator/ArkavoCreator.entitlements`
- Create: `tests/fixtures/appattest/README.md`
- Create: `tests/fixtures/appattest/attestation.json`

**Interfaces:**
- Consumes: nothing
- Produces: `tests/fixtures/appattest/attestation.json`, a JSON object with keys `key_id` (String), `attestation_object` (String, standard base64), `client_data_hash` (String, standard base64), `challenge` (String, the raw challenge whose SHA-256 is `client_data_hash`), `app_id_hash` (String, lowercase hex), `environment` (String, `"development"` or `"production"`), and `verify_at` (Number, a Unix timestamp inside the leaf certificate's validity window — Task 3's tests check the chain against this instead of the wall clock, so the suite does not start failing the day the captured certificate expires).

- [ ] **Step 0: Add the App Attest entitlement to Creator**

In `/Users/arkavo/Projects/Creator/ArkavoCreator/ArkavoCreator.entitlements`, add:

```xml
	<key>com.apple.developer.devicecheck.appattest-environment</key>
	<string>development</string>
```

Then enable the App Attest capability on the `com.arkavo.ArkavoCreator` app ID in the Apple Developer portal, so the provisioning profile carries the entitlement. This is portal configuration, not a release.

- [ ] **Step 1: Add a temporary capture hook to Creator**

In a scratch build of Creator (do not commit this — a debug menu item or a `#if DEBUG` call on launch is enough), run once on the Mac:

```swift
import DeviceCheck
import CryptoKit

let service = DCAppAttestService.shared
guard service.isSupported else { fatalError("no Secure Enclave") }

let challenge = "fixture-challenge-do-not-reuse"
let clientDataHash = Data(SHA256.hash(data: Data(challenge.utf8)))
let keyId = try await service.generateKey()
let attestation = try await service.attestKey(keyId, clientDataHash: clientDataHash)

print(#"{"key_id":"\#(keyId)","attestation_object":"\#(attestation.base64EncodedString())","client_data_hash":"\#(clientDataHash.base64EncodedString())","challenge":"\#(challenge)"}"#)
```

- [ ] **Step 2: Record the app id hash**

Already computed for Creator — verify rather than re-derive:

```bash
printf '%s' 'M8GS7ZT95Y.com.arkavo.ArkavoCreator' | shasum -a 256 | cut -d' ' -f1
# ea2defc9e7bf14b832b0fb5e4ada8f0af0e114dca9fc7741cda17d875cf1bc01
```

This is Creator's identity, not the app that will ultimately serve registration. That is fine: Tasks 1-3 read `app_id_hash` out of the fixture, so they pass self-consistently. Production sets `APP_ATTEST_APP_ID` to whichever app actually registers users.

- [ ] **Step 3: Write the fixture file**

Save the printed JSON to `tests/fixtures/appattest/attestation.json`, adding:
- `app_id_hash` from Step 2
- `environment`: `"development"`
- `verify_at`: the capture time as a Unix timestamp (`date +%s` at capture). It must fall inside the leaf certificate's validity window, which it does by construction if recorded at capture.

- [ ] **Step 4: Write the README**

```markdown
# App Attest fixtures

`attestation.json` is a real attestation captured once from a physical device.
App Attest does not run in the Simulator, so it cannot be regenerated in CI.

Fields:
- `key_id`              base64 key identifier from `DCAppAttestService.generateKey()`
- `attestation_object`  base64 CBOR blob from `attestKey(_:clientDataHash:)`
- `client_data_hash`    base64 SHA-256 of `challenge`
- `challenge`           the raw challenge string
- `app_id_hash`         lowercase hex SHA-256 of `<TeamID>.<BundleID>`
- `environment`         `development` or `production` — selects the expected aaguid
- `verify_at`           Unix timestamp inside the leaf cert's validity window

Captured from the Creator app (`com.arkavo.ArkavoCreator`, team M8GS7ZT95Y),
a macOS build on Apple silicon. No release is needed: App Attest's
`development` environment works from a locally signed build.

Chain validation tests check against `verify_at`, not the wall clock. The
leaf certificate has a finite validity window, so testing against `now`
would make the suite start failing on a date unrelated to any code change.

This blob contains no user data. The attested key is a throwaway generated
solely for this fixture and is bound to no account.

To regenerate: see Task 0 of
docs/superpowers/plans/2026-09-20-app-attest-registration-gate.md
```

- [ ] **Step 5: Verify the fixture parses**

Run:

```bash
python3 -c "
import json,base64,hashlib
d=json.load(open('tests/fixtures/appattest/attestation.json'))
assert hashlib.sha256(d['challenge'].encode()).digest()==base64.b64decode(d['client_data_hash']), 'client_data_hash mismatch'
assert base64.b64decode(d['attestation_object'])[:1]==b'\xa3', 'not a 3-key CBOR map'
assert len(bytes.fromhex(d['app_id_hash']))==32, 'app_id_hash not 32 bytes'
assert isinstance(d['verify_at'], int) and d['verify_at']>1_700_000_000, 'verify_at missing or implausible'
print('fixture ok')
"
```

Expected: `fixture ok`

- [ ] **Step 6: Commit**

```bash
git add tests/fixtures/appattest/
git commit -m "test(device-check): real App Attest fixture for verifier tests

App Attest does not run in the Simulator, so the verifier cannot be
tested against a synthetic blob without reimplementing Apple's signing.
Captured once from a physical device; the attested key is a throwaway
bound to no account."
```

---

### Task 1: Extract the shared attestation verifier

Pure refactor, no behaviour change. `finish_attestation` keeps working exactly as it does today; the verification body moves into a function the unbound path will also call.

**Files:**
- Modify: `src/device_check.rs:193-330` (`finish_attestation`)
- Modify: `src/device_check.rs` (add `verify_attestation`, `AttestedKey`, `VerifyOptions`)
- Test: `src/device_check.rs` (module `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `tests/fixtures/appattest/attestation.json` from Task 0.
- Produces:

```rust
pub struct AttestedKey {
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub rp_id_hash_str: String,
    pub counter: u32,
}

pub struct VerifyOptions<'a> {
    /// Expected rpIdHash as lowercase hex. `None` keeps the legacy
    /// warn-and-continue behaviour; the registration gate always passes `Some`.
    pub expected_app_id: Option<&'a str>,
    /// When true, a `None` `expected_app_id` is an error rather than a warning.
    pub require_app_id: bool,
}

pub fn verify_attestation(
    challenge: &str,
    key_id: &str,
    attestation_object_b64: &str,
    client_data_hash_b64: &str,
    opts: &VerifyOptions<'_>,
) -> Result<AttestedKey, DeviceCheckError>;
```

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `src/device_check.rs`:

```rust
fn load_fixture() -> serde_json::Value {
    let raw = std::fs::read_to_string("tests/fixtures/appattest/attestation.json")
        .expect("Task 0 fixture missing");
    serde_json::from_str(&raw).expect("fixture is not valid JSON")
}

#[test]
fn verify_attestation_accepts_the_real_fixture() {
    let f = load_fixture();
    let app_id = f["app_id_hash"].as_str().unwrap();
    let out = verify_attestation(
        f["challenge"].as_str().unwrap(),
        f["key_id"].as_str().unwrap(),
        f["attestation_object"].as_str().unwrap(),
        f["client_data_hash"].as_str().unwrap(),
        &VerifyOptions { expected_app_id: Some(app_id), require_app_id: true },
    )
    .expect("the captured attestation must verify");

    assert_eq!(out.counter, 0, "attestation counter is always 0");
    assert_eq!(out.rp_id_hash_str.to_lowercase(), app_id.to_lowercase());
    assert!(!out.public_key.is_empty());
}

#[test]
fn verify_attestation_rejects_a_wrong_challenge() {
    let f = load_fixture();
    let err = verify_attestation(
        "not-the-challenge-that-was-attested",
        f["key_id"].as_str().unwrap(),
        f["attestation_object"].as_str().unwrap(),
        f["client_data_hash"].as_str().unwrap(),
        &VerifyOptions {
            expected_app_id: Some(f["app_id_hash"].as_str().unwrap()),
            require_app_id: true,
        },
    )
    .unwrap_err();
    assert!(matches!(err, DeviceCheckError::ChallengeMismatch), "got {err:?}");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib device_check::tests::verify_attestation -- --nocapture`
Expected: FAIL — `cannot find function 'verify_attestation' in this scope`

- [ ] **Step 3: Write the implementation**

Add to `src/device_check.rs`, lifting the body verbatim from `finish_attestation`:

```rust
#[derive(Debug, Clone)]
pub struct AttestedKey {
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub rp_id_hash_str: String,
    pub counter: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions<'a> {
    pub expected_app_id: Option<&'a str>,
    pub require_app_id: bool,
}

/// Verify an App Attest attestation against the challenge that produced it.
///
/// This is the single verifier. The account-bound path
/// ([`finish_attestation`]) and the unauthenticated registration gate both
/// call it; a second copy would drift, and this one is load-bearing.
pub fn verify_attestation(
    challenge: &str,
    key_id: &str,
    attestation_object_b64: &str,
    client_data_hash_b64: &str,
    opts: &VerifyOptions<'_>,
) -> Result<AttestedKey, DeviceCheckError> {
    let attestation_bytes = base64::engine::general_purpose::STANDARD
        .decode(attestation_object_b64)
        .map_err(|e| DeviceCheckError::InvalidAttestationObject(e.to_string()))?;

    let attestation: AttestationObject = ciborium::from_reader(&attestation_bytes[..])
        .map_err(|e| DeviceCheckError::InvalidAttestationObject(e.to_string()))?;

    if attestation.fmt != "apple-appattest" {
        return Err(DeviceCheckError::InvalidFormat(format!(
            "Expected 'apple-appattest', got '{}'",
            attestation.fmt
        )));
    }

    let client_data_hash = base64::engine::general_purpose::STANDARD
        .decode(client_data_hash_b64)
        .map_err(|e| DeviceCheckError::InvalidClientData(e.to_string()))?;

    let expected_hash = Sha256::digest(challenge.as_bytes());
    if client_data_hash.as_slice() != &expected_hash[..] {
        return Err(DeviceCheckError::ChallengeMismatch);
    }

    validate_certificate_chain(&attestation.att_stmt.x5c)?;
    let public_key = extract_public_key_from_cert(&attestation.att_stmt.x5c[0])?;
    let auth_data = parse_authenticator_data(&attestation.auth_data)?;

    if auth_data.counter != 0 {
        return Err(DeviceCheckError::InvalidCounter(format!(
            "Expected counter 0 for attestation, got {}",
            auth_data.counter
        )));
    }

    match opts.expected_app_id {
        Some(expected) if !auth_data.rp_id_hash_str.eq_ignore_ascii_case(expected) => {
            warn!(
                "App Attest rpIdHash mismatch for key_id {}: got {}, expected {}",
                key_id, auth_data.rp_id_hash_str, expected
            );
            return Err(DeviceCheckError::AppIdMismatch);
        }
        Some(_) => {}
        None if opts.require_app_id => {
            error!("APP_ATTEST_APP_ID is unset and this path requires it; refusing");
            return Err(DeviceCheckError::AppIdNotConfigured);
        }
        None => warn!(
            "APP_ATTEST_APP_ID is unset; accepting attestation with unverified rpIdHash {}",
            auth_data.rp_id_hash_str
        ),
    }

    let mut nonce_data = Vec::with_capacity(attestation.auth_data.len() + client_data_hash.len());
    nonce_data.extend_from_slice(&attestation.auth_data);
    nonce_data.extend_from_slice(&client_data_hash);
    let calculated_nonce = Sha256::digest(&nonce_data);

    // Task 2 replaces this warning with a real check against the credCert
    // extension. Until then the behaviour is unchanged from before the
    // refactor.
    warn!(
        "SECURITY: Nonce validation against certificate extension not implemented. \
         Calculated nonce: {}.",
        hex::encode(calculated_nonce)
    );

    Ok(AttestedKey {
        key_id: key_id.to_string(),
        public_key,
        rp_id_hash_str: auth_data.rp_id_hash_str,
        counter: auth_data.counter,
    })
}
```

Add the new error variant to `DeviceCheckError`:

```rust
    #[error("App Attest app id is not configured")]
    AppIdNotConfigured,
```

- [ ] **Step 4: Rewrite `finish_attestation` to call it**

Replace everything in `finish_attestation` between the session cleanup and `info!("Binding device …")` with:

```rust
    let attested = verify_attestation(
        &challenge,
        &request.key_id,
        &request.attestation_object,
        &request.client_data_hash,
        &VerifyOptions {
            expected_app_id: app_state.app_attest_app_id.as_deref(),
            // Legacy path keeps warn-and-continue; the registration gate does not.
            require_app_id: false,
        },
    )?;

    let public_key = attested.public_key.clone();
```

and change the `DeviceBinding` construction to use `attested.rp_id_hash_str.clone()` for `app_id`.

- [ ] **Step 5: Map the new error to a status code**

Find the `IntoResponse` impl for `DeviceCheckError` and add `AppIdNotConfigured` to the arm that returns `StatusCode::INTERNAL_SERVER_ERROR` — it is a server misconfiguration, not a client fault. Do not leak the variant's message to the client body.

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib device_check`
Expected: PASS, including the 10 pre-existing `device_check` tests.

- [ ] **Step 7: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/device_check.rs
git commit -m "refactor(device-check): extract the shared attestation verifier

The registration gate needs to verify an attestation with no account and
no CWT, which finish_attestation cannot do because verification is
inlined and entangled with an authenticated user_id. Extract it behind
VerifyOptions so both paths call one implementation.

No behaviour change: finish_attestation passes require_app_id: false and
keeps today's warn-and-continue on an unset APP_ATTEST_APP_ID."
```

---

### Task 2: Validate the credCert nonce extension

Closes the gap the code documents at `src/device_check.rs:288-310`. Without it the attestation is not bound to the issued challenge, which is the whole replay property the gate depends on.

**Files:**
- Modify: `Cargo.toml` (x509-parser features)
- Modify: `src/device_check.rs` (`verify_attestation`, new `extract_attestation_nonce`)
- Test: `src/device_check.rs`

**Interfaces:**
- Consumes: `verify_attestation`, `AttestedKey` from Task 1.
- Produces: `fn extract_attestation_nonce(cert_der: &[u8]) -> Result<Vec<u8>, DeviceCheckError>` returning the 32 raw nonce bytes from OID `1.2.840.113635.100.8.2`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn credcert_nonce_matches_the_computed_nonce() {
    let f = load_fixture();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(f["attestation_object"].as_str().unwrap())
        .unwrap();
    let att: AttestationObject = ciborium::from_reader(&bytes[..]).unwrap();
    let client_data_hash = base64::engine::general_purpose::STANDARD
        .decode(f["client_data_hash"].as_str().unwrap())
        .unwrap();

    let mut nonce_data = att.auth_data.clone();
    nonce_data.extend_from_slice(&client_data_hash);
    let computed = Sha256::digest(&nonce_data);

    let from_cert = extract_attestation_nonce(&att.att_stmt.x5c[0])
        .expect("credCert must carry the 1.2.840.113635.100.8.2 extension");

    assert_eq!(from_cert.as_slice(), &computed[..]);
}

#[test]
fn verify_attestation_rejects_a_tampered_nonce() {
    let f = load_fixture();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(f["attestation_object"].as_str().unwrap())
        .unwrap();
    let mut att: AttestationObject = ciborium::from_reader(&bytes[..]).unwrap();

    // Flip a byte of authData, which changes the computed nonce while
    // leaving the certificate's recorded nonce untouched.
    let last = att.auth_data.len() - 1;
    att.auth_data[last] ^= 0xff;

    let mut tampered = Vec::new();
    ciborium::into_writer(&att, &mut tampered).unwrap();
    let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(&tampered);

    let err = verify_attestation(
        f["challenge"].as_str().unwrap(),
        f["key_id"].as_str().unwrap(),
        &tampered_b64,
        f["client_data_hash"].as_str().unwrap(),
        &VerifyOptions {
            expected_app_id: Some(f["app_id_hash"].as_str().unwrap()),
            require_app_id: true,
        },
    )
    .unwrap_err();

    assert!(matches!(err, DeviceCheckError::NonceMismatch), "got {err:?}");
}
```

`AttestationObject` must gain `Serialize` for the re-encode. Change its derive to `#[derive(Debug, Deserialize, Serialize)]` and do the same for `AttestationStatement`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib device_check::tests::credcert_nonce device_check::tests::verify_attestation_rejects_a_tampered_nonce`
Expected: FAIL — `cannot find function 'extract_attestation_nonce'`

- [ ] **Step 3: Enable the x509-parser feature**

In `Cargo.toml`:

```toml
x509-parser = { version = "=0.16.0", features = ["verify"] }  # Certificate chain validation
```

- [ ] **Step 4: Write the implementation**

```rust
/// Apple's App Attest nonce extension. The value is a DER SEQUENCE holding a
/// single `[1] EXPLICIT` OCTET STRING of the 32-byte nonce.
const APPLE_NONCE_OID: &str = "1.2.840.113635.100.8.2";

fn extract_attestation_nonce(cert_der: &[u8]) -> Result<Vec<u8>, DeviceCheckError> {
    use x509_parser::der_parser::asn1_rs::FromDer;
    use x509_parser::der_parser::ber::{parse_ber_octetstring, parse_ber_sequence};

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?;

    let oid = APPLE_NONCE_OID
        .parse()
        .map_err(|_| DeviceCheckError::InvalidCertificateChain("bad OID".into()))?;

    let ext = cert
        .get_extension_unique(&oid)
        .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?
        .ok_or(DeviceCheckError::NonceExtensionMissing)?;

    // SEQUENCE { [1] EXPLICIT OCTET STRING }
    let (_, seq) = parse_ber_sequence(ext.value)
        .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?;
    let inner = seq
        .as_sequence()
        .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?
        .first()
        .ok_or(DeviceCheckError::NonceExtensionMissing)?;

    let (_, octets) = parse_ber_octetstring(inner.content.as_slice().map_err(|e| {
        DeviceCheckError::InvalidCertificateChain(e.to_string())
    })?)
    .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?;

    let nonce = octets
        .as_slice()
        .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?
        .to_vec();

    if nonce.len() != 32 {
        return Err(DeviceCheckError::InvalidCertificateChain(format!(
            "nonce extension is {} bytes, expected 32",
            nonce.len()
        )));
    }
    Ok(nonce)
}
```

Add the error variants:

```rust
    #[error("credCert is missing the App Attest nonce extension")]
    NonceExtensionMissing,

    #[error("Attestation nonce does not match the issued challenge")]
    NonceMismatch,
```

- [ ] **Step 5: Wire it into `verify_attestation`**

Replace the `warn!("SECURITY: Nonce validation …")` block added in Task 1 with:

```rust
    let cert_nonce = extract_attestation_nonce(&attestation.att_stmt.x5c[0])?;
    if cert_nonce.as_slice() != &calculated_nonce[..] {
        warn!("App Attest nonce mismatch for key_id {}", key_id);
        return Err(DeviceCheckError::NonceMismatch);
    }
```

- [ ] **Step 6: Map the new errors**

In the `IntoResponse` impl, map `NonceExtensionMissing` and `NonceMismatch` to `StatusCode::UNAUTHORIZED` — both are a rejected attestation, not a server fault.

- [ ] **Step 7: Run the tests**

Run: `cargo test --lib device_check`
Expected: PASS. `verify_attestation_accepts_the_real_fixture` still passes, proving the real credCert carries a matching nonce.

- [ ] **Step 8: Update the module docs**

In the `//! # Known Limitations` block at the top of `src/device_check.rs`, delete the line:

```
//! - Certificate extension 1.2.840.113635.100.8.2 (nonce) validation not implemented
```

- [ ] **Step 9: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add Cargo.toml Cargo.lock src/device_check.rs
git commit -m "fix(device-check): validate the credCert nonce extension

Without this the attestation is not bound to the challenge the server
issued, so a captured attestation replays against any later challenge.
That is the replay property the registration gate depends on, so it has
to hold before the gate can rest on it.

Parses OID 1.2.840.113635.100.8.2 and compares against
SHA256(authData || clientDataHash)."
```

---

### Task 3: Complete the certificate chain validation

Closes the second documented gap. Today `validate_certificate_chain` parses the leaf and the root, logs, and returns `Ok(())` without verifying a single signature.

**Files:**
- Modify: `src/device_check.rs:497-529` (`validate_certificate_chain`)
- Test: `src/device_check.rs`

**Interfaces:**
- Consumes: the `verify` feature enabled in Task 2; `verify_at` from the Task 0 fixture.
- Produces: `validate_certificate_chain(&[Vec<u8>]) -> Result<(), DeviceCheckError>` keeps its signature and now actually verifies, delegating to a new `validate_certificate_chain_at(x5c: &[Vec<u8>], now: ASN1Time) -> Result<(), DeviceCheckError>`. Production calls the former, which passes `ASN1Time::now()`. Tests call the latter with the fixture's `verify_at`, so the suite does not start failing when the captured certificate expires.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn chain_validation_accepts_the_real_fixture() {
    let f = load_fixture();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(f["attestation_object"].as_str().unwrap())
        .unwrap();
    let att: AttestationObject = ciborium::from_reader(&bytes[..]).unwrap();

    // Checked against the fixture's capture time, not the wall clock: the leaf
    // certificate expires, and a suite that fails on a calendar date rather
    // than a code change teaches people to ignore it.
    let at = ASN1Time::from_timestamp(f["verify_at"].as_i64().unwrap()).unwrap();
    validate_certificate_chain_at(&att.att_stmt.x5c, at)
        .expect("a real Apple chain must validate to the embedded root");
}

#[test]
fn chain_validation_rejects_an_expired_certificate() {
    let f = load_fixture();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(f["attestation_object"].as_str().unwrap())
        .unwrap();
    let att: AttestationObject = ciborium::from_reader(&bytes[..]).unwrap();

    // Ten years past capture, the leaf is certainly outside its window.
    let long_after = ASN1Time::from_timestamp(
        f["verify_at"].as_i64().unwrap() + 10 * 365 * 24 * 3600,
    )
    .unwrap();

    let err = validate_certificate_chain_at(&att.att_stmt.x5c, long_after).unwrap_err();
    assert!(
        matches!(err, DeviceCheckError::InvalidCertificateChain(_)),
        "an expired chain must not validate, got {err:?}"
    );
}

#[test]
fn chain_validation_rejects_a_forged_leaf() {
    let f = load_fixture();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(f["attestation_object"].as_str().unwrap())
        .unwrap();
    let att: AttestationObject = ciborium::from_reader(&bytes[..]).unwrap();

    // Corrupt the leaf's signature bytes: the last 8 bytes of a DER cert are
    // inside the signature value.
    let mut forged = att.att_stmt.x5c.clone();
    let leaf = &mut forged[0];
    let n = leaf.len();
    for b in leaf[n - 8..].iter_mut() {
        *b ^= 0xff;
    }

    let at = ASN1Time::from_timestamp(f["verify_at"].as_i64().unwrap()).unwrap();
    let err = validate_certificate_chain_at(&forged, at).unwrap_err();
    assert!(
        matches!(err, DeviceCheckError::InvalidCertificateChain(_)),
        "got {err:?}"
    );
}

#[test]
fn chain_validation_rejects_a_leaf_only_chain() {
    let f = load_fixture();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(f["attestation_object"].as_str().unwrap())
        .unwrap();
    let att: AttestationObject = ciborium::from_reader(&bytes[..]).unwrap();

    let at = ASN1Time::from_timestamp(f["verify_at"].as_i64().unwrap()).unwrap();
    let err = validate_certificate_chain_at(&att.att_stmt.x5c[..1], at).unwrap_err();
    assert!(
        matches!(err, DeviceCheckError::InvalidCertificateChain(_)),
        "a chain with no intermediate must not validate, got {err:?}"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib device_check::tests::chain_validation`
Expected: FAIL — `validate_certificate_chain_at` does not exist yet, so all four tests fail to compile.

- [ ] **Step 3: Write the implementation**

```rust
/// Verify the App Attest chain: leaf → intermediate(s) → Apple's embedded root.
///
/// Every signature in the chain is checked, and the chain must terminate at
/// the pinned root. Apple sends leaf + intermediate, so a one-element chain
/// is refused rather than treated as self-signed.
fn validate_certificate_chain(x5c: &[Vec<u8>]) -> Result<(), DeviceCheckError> {
    validate_certificate_chain_at(x5c, ASN1Time::now())
}

/// As [`validate_certificate_chain`], but with the validity instant supplied.
///
/// Tests pin this to the fixture's capture time. The captured leaf certificate
/// has a finite validity window, and a suite wired to the wall clock would
/// start failing on a calendar date with no code change behind it.
fn validate_certificate_chain_at(
    x5c: &[Vec<u8>],
    now: ASN1Time,
) -> Result<(), DeviceCheckError> {
    if x5c.len() < 2 {
        return Err(DeviceCheckError::InvalidCertificateChain(format!(
            "expected leaf + intermediate, got {} certificate(s)",
            x5c.len()
        )));
    }

    let root_cert_der = APPLE_ROOT_CERT_DER.get_or_init(|| {
        let root_pem = ::pem::parse(APPLE_APP_ATTEST_ROOT_CA.as_bytes())
            .expect("Failed to parse embedded Apple root CA PEM");
        root_pem.contents().to_vec()
    });
    let (_, root_cert) = X509Certificate::from_der(root_cert_der)
        .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?;

    let mut parsed = Vec::with_capacity(x5c.len());
    for der in x5c {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| DeviceCheckError::InvalidCertificateChain(e.to_string()))?;
        parsed.push(cert);
    }

    for cert in &parsed {
        if !cert.validity().is_valid_at(now) {
            return Err(DeviceCheckError::InvalidCertificateChain(format!(
                "certificate expired or not yet valid: {}",
                cert.subject()
            )));
        }
    }

    // Each certificate must be signed by the next one along.
    for pair in parsed.windows(2) {
        let (child, issuer) = (&pair[0], &pair[1]);
        if child.issuer() != issuer.subject() {
            return Err(DeviceCheckError::InvalidCertificateChain(format!(
                "issuer mismatch: {} is not issued by {}",
                child.subject(),
                issuer.subject()
            )));
        }
        child
            .verify_signature(Some(issuer.public_key()))
            .map_err(|e| {
                DeviceCheckError::InvalidCertificateChain(format!(
                    "signature check failed for {}: {e}",
                    child.subject()
                ))
            })?;
    }

    // The topmost certificate we were sent must chain to the pinned root.
    let top = parsed.last().expect("length checked above");
    if top.issuer() != root_cert.subject() {
        return Err(DeviceCheckError::InvalidCertificateChain(format!(
            "chain does not terminate at Apple's App Attest root: top issuer is {}",
            top.issuer()
        )));
    }
    top.verify_signature(Some(root_cert.public_key()))
        .map_err(|e| {
            DeviceCheckError::InvalidCertificateChain(format!(
                "root signature check failed: {e}"
            ))
        })?;

    Ok(())
}
```

Add the import near the other `x509_parser` uses:

```rust
use x509_parser::prelude::ASN1Time;
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib device_check`
Expected: PASS, all three chain tests plus the Task 1 and Task 2 tests.

- [ ] **Step 5: Update the module docs**

In the `//! # Known Limitations` block, delete:

```
//! - Certificate chain validation is incomplete (intermediate certs not verified)
```

Note in the `validate_certificate_chain_at` doc comment that production always
passes `ASN1Time::now()` and only tests pin the instant, so nobody later
mistakes the parameter for a way to disable expiry checking.

Do the same in `CLAUDE.md` under **Known Limitations** in the Apple DeviceCheck section, and remove the parenthetical `(TODO: implement full chain verification)`.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/device_check.rs CLAUDE.md
git commit -m "fix(device-check): verify the full attestation certificate chain

validate_certificate_chain parsed the leaf and the root, logged both,
and returned Ok without checking a signature, so any well-formed DER
passed. Verify every link, enforce validity windows, and require the
chain to terminate at the pinned Apple root.

A leaf-only chain is now refused: Apple always sends an intermediate, so
a one-element chain is a forgery attempt, not a short chain."
```

---

### Task 4: Persist attested keys and enforce the rate policy

**Files:**
- Modify: `src/constants.rs`
- Modify: `src/db.rs`
- Modify: `src/main.rs:310` area (AppState), `src/main.rs:451` area (env wiring)
- Modify: `CLAUDE.md` (schema + env docs)
- Test: `src/db.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:

```rust
// src/constants.rs
pub const ATTEST_REG_PER_WINDOW: u32 = 3;
pub const ATTEST_REG_WINDOW_SECONDS: i64 = 86_400;
pub const ATTEST_REG_LIFETIME_CAP: u32 = 10;

// src/db.rs
pub struct AttestKeyRecord {
    pub key_id: String,
    pub registrations: u32,
    pub window_started_at: i64,
    pub first_seen_at: i64,
    pub last_reg_at: i64,
}

impl DynamoDBStore {
    /// Reserve one registration slot for `key_id`.
    /// `Ok(record)` on success; `Err(DynamoDBError::RateLimited { retry_after })`
    /// when the window or lifetime cap is exhausted.
    pub async fn reserve_attest_registration(
        &self,
        key_id: &str,
    ) -> Result<AttestKeyRecord, DynamoDBError>;
}
```

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `src/db.rs`:

```rust
#[test]
fn rate_limited_error_carries_a_retry_after() {
    let e = DynamoDBError::RateLimited { retry_after: 3600 };
    assert_eq!(e.to_string(), "Rate limited; retry after 3600s");
}

#[test]
fn window_rolls_over_after_the_configured_period() {
    use crate::constants::{ATTEST_REG_PER_WINDOW, ATTEST_REG_WINDOW_SECONDS};
    let now = 1_800_000_000i64;

    // Window still open and exhausted -> refuse.
    let exhausted = AttestKeyRecord {
        key_id: "k".into(),
        registrations: ATTEST_REG_PER_WINDOW,
        window_started_at: now - 10,
        first_seen_at: now - 10,
        last_reg_at: now - 10,
    };
    assert!(!attest_slot_available(&exhausted, now));

    // Same counts, but the window has rolled over -> allow.
    let rolled = AttestKeyRecord {
        window_started_at: now - ATTEST_REG_WINDOW_SECONDS - 1,
        ..exhausted.clone()
    };
    assert!(attest_slot_available(&rolled, now));
}

#[test]
fn lifetime_cap_is_absolute() {
    use crate::constants::ATTEST_REG_LIFETIME_CAP;
    let now = 1_800_000_000i64;
    let maxed = AttestKeyRecord {
        key_id: "k".into(),
        registrations: ATTEST_REG_LIFETIME_CAP,
        window_started_at: now - 10_000_000,
        first_seen_at: now - 10_000_000,
        last_reg_at: now - 10_000_000,
    };
    assert!(
        !attest_slot_available(&maxed, now),
        "the lifetime cap must hold even with a long-expired window"
    );
}
```

Note: `registrations` is a lifetime total; the window check uses `registrations - registrations_at_window_start`. To keep the pure function testable, store the window baseline too. Adjust `AttestKeyRecord` to carry `window_base: u32` and write `attest_slot_available` against it.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib db::tests::window_rolls_over db::tests::lifetime_cap db::tests::rate_limited`
Expected: FAIL — `AttestKeyRecord` and `attest_slot_available` do not exist.

- [ ] **Step 3: Add the constants**

In `src/constants.rs`:

```rust
/// Registrations one attested device key may perform per rolling window.
/// A genuine device attesting repeatedly is the residual risk the gate does
/// not cover; this bounds it without blocking reinstalls or a second account.
pub const ATTEST_REG_PER_WINDOW: u32 = 3;

/// Length of that rolling window, in seconds.
pub const ATTEST_REG_WINDOW_SECONDS: i64 = 86_400;

/// Absolute lifetime ceiling for one key, independent of the window. A key
/// past this is a farm, not a user.
pub const ATTEST_REG_LIFETIME_CAP: u32 = 10;
```

- [ ] **Step 4: Write the record, the pure policy, and the store method**

In `src/db.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestKeyRecord {
    pub key_id: String,
    pub registrations: u32,
    pub window_base: u32,
    pub window_started_at: i64,
    pub first_seen_at: i64,
    pub last_reg_at: i64,
}

/// Pure policy: may `record` take one more registration slot at `now`?
pub fn attest_slot_available(record: &AttestKeyRecord, now: i64) -> bool {
    use crate::constants::{
        ATTEST_REG_LIFETIME_CAP, ATTEST_REG_PER_WINDOW, ATTEST_REG_WINDOW_SECONDS,
    };

    if record.registrations >= ATTEST_REG_LIFETIME_CAP {
        return false;
    }
    if now - record.window_started_at >= ATTEST_REG_WINDOW_SECONDS {
        return true; // window rolled over
    }
    record.registrations - record.window_base < ATTEST_REG_PER_WINDOW
}
```

The store method reads the row, applies `attest_slot_available`, then writes with a `ConditionExpression` on the observed `registrations` value so two concurrent attests cannot both take the last slot — the same conditional-update pattern `update_device_binding_counter` already uses in this file. On condition failure, re-read once and retry; on a second failure return `DynamoDBError::RateLimited`.

Add to `DynamoDBError`:

```rust
    #[error("Rate limited; retry after {retry_after}s")]
    RateLimited { retry_after: i64 },
```

- [ ] **Step 5: Wire the table name**

`src/main.rs`: add `pub device_attest_keys_table: Arc<String>` to `AppState` beside the other table names, reading `DYNAMODB_DEVICE_ATTEST_KEYS_TABLE` with default `device_attest_keys`. Add the same field to the three test `AppState` constructions at `src/oidc.rs:2701`, `src/oidc.rs:2818`, and `src/main.rs:1403`.

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib db`
Expected: PASS.

- [ ] **Step 7: Document the table**

In `CLAUDE.md`, add under the DynamoDB Schema section:

```markdown
### device_attest_keys table
- **Primary Key**: key_id (String) - App Attest key identifier
- **Attributes**:
  - registrations (Number) - Lifetime count of registrations by this key
  - window_base (Number) - `registrations` when the current window opened
  - window_started_at (Number) - Unix timestamp the current window opened
  - first_seen_at (Number) - Unix timestamp of first attestation
  - last_reg_at (Number) - Unix timestamp of most recent registration
- **Purpose**: bounds how many accounts one genuine device can register. The
  gate proves a real device; this bounds what a real device may do.
- **Conditional updates**: slot reservation is conditional on the observed
  `registrations`, so concurrent attests cannot both take the last slot.
```

Add the local-DynamoDB creation command alongside the others:

```bash
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name device_attest_keys \
    --attribute-definitions AttributeName=key_id,AttributeType=S \
    --key-schema AttributeName=key_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST
```

and `export DYNAMODB_DEVICE_ATTEST_KEYS_TABLE=device_attest_keys` to both the development and production env blocks.

- [ ] **Step 8: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/constants.rs src/db.rs src/main.rs src/oidc.rs CLAUDE.md
git commit -m "feat(device-check): persist attested keys with a registration budget

The gate proves a real device; it does not bound what a real device may
do. One genuine phone could otherwise mint accounts indefinitely. Track
registrations per key_id against a rolling window plus a lifetime cap,
reserved by conditional update so concurrent attests cannot both take
the last slot.

Rate-limited rather than capped at one: a reinstall generates a fresh
key_id, so a hard cap is survivable, but it would permanently block a
second account on one device."
```

---

### Task 5: The unauthenticated attest endpoints

**Files:**
- Modify: `src/device_check.rs` (add `register_challenge`, `register_attest`)
- Modify: `src/main.rs` (routes)
- Test: `src/device_check.rs`

**Interfaces:**
- Consumes: `verify_attestation`, `VerifyOptions` (Task 1); `reserve_attest_registration` (Task 4).
- Produces: session key `SESSION_REG_TICKET_KEY = "reg_attest_ticket"` holding `RegistrationTicket`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationTicket {
    pub key_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
}
```

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn ticket_expiry_is_enforced() {
    let now = 1_800_000_000i64;
    let fresh = RegistrationTicket { key_id: "k".into(), issued_at: now, expires_at: now + 300 };
    assert!(ticket_is_valid(&fresh, now));
    assert!(ticket_is_valid(&fresh, now + 299));
    assert!(!ticket_is_valid(&fresh, now + 301), "an expired ticket must not admit");
}

#[tokio::test]
async fn register_attest_refuses_when_app_id_is_unconfigured() {
    let f = load_fixture();
    let err = verify_attestation(
        f["challenge"].as_str().unwrap(),
        f["key_id"].as_str().unwrap(),
        f["attestation_object"].as_str().unwrap(),
        f["client_data_hash"].as_str().unwrap(),
        // The gate always sets require_app_id; an unset APP_ATTEST_APP_ID
        // would otherwise admit an attestation from any app at all.
        &VerifyOptions { expected_app_id: None, require_app_id: true },
    )
    .unwrap_err();
    assert!(matches!(err, DeviceCheckError::AppIdNotConfigured), "got {err:?}");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib device_check::tests::ticket_expiry device_check::tests::register_attest_refuses`
Expected: FAIL — `RegistrationTicket` and `ticket_is_valid` do not exist.

- [ ] **Step 3: Write the implementation**

```rust
pub const SESSION_REG_CHALLENGE_KEY: &str = "reg_attest_challenge";
pub const SESSION_REG_TICKET_KEY: &str = "reg_attest_ticket";

/// How long an attested registration ticket remains spendable.
const REG_TICKET_TTL_SECONDS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationTicket {
    pub key_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

pub fn ticket_is_valid(ticket: &RegistrationTicket, now: i64) -> bool {
    now <= ticket.expires_at
}

/// Issue an attestation challenge for a caller with no account yet.
///
/// Deliberately takes no username: pre-account, a username-keyed endpoint
/// would tell an unauthenticated caller which handles exist.
pub async fn register_challenge(
    session: Session,
) -> Result<impl IntoResponse, DeviceCheckError> {
    let challenge = generate_random_challenge();
    session
        .insert(SESSION_REG_CHALLENGE_KEY, challenge.clone())
        .await
        .map_err(DeviceCheckError::InvalidSessionState)?;
    Ok(Json(ChallengeResponse { challenge }))
}

/// Verify an attestation from an unregistered caller and issue a one-shot
/// registration ticket.
pub async fn register_attest(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(request): Json<AttestationRequest>,
) -> Result<impl IntoResponse, DeviceCheckError> {
    let challenge: String = session
        .get(SESSION_REG_CHALLENGE_KEY)
        .await?
        .ok_or(DeviceCheckError::CorruptSession)?;

    // One challenge, one attempt.
    session
        .remove_value(SESSION_REG_CHALLENGE_KEY)
        .await
        .map_err(|e| DeviceCheckError::SessionError(e.to_string()))?;

    let attested = verify_attestation(
        &challenge,
        &request.key_id,
        &request.attestation_object,
        &request.client_data_hash,
        &VerifyOptions {
            expected_app_id: app_state.app_attest_app_id.as_deref(),
            require_app_id: true,
        },
    )?;

    app_state
        .db_store
        .reserve_attest_registration(&attested.key_id)
        .await
        .map_err(|e| DeviceCheckError::DynamoDBOperationError(Box::new(e)))?;

    let now = Utc::now().timestamp();
    let ticket = RegistrationTicket {
        key_id: attested.key_id.clone(),
        issued_at: now,
        expires_at: now + REG_TICKET_TTL_SECONDS,
    };
    session
        .insert(SESSION_REG_TICKET_KEY, ticket)
        .await
        .map_err(DeviceCheckError::InvalidSessionState)?;

    info!("Issued registration ticket for attested key {}", attested.key_id);
    Ok(Json(AttestationResponse {
        success: true,
        message: "attested".to_string(),
    }))
}
```

- [ ] **Step 4: Map `RateLimited` to 429**

In the `IntoResponse` impl for `DeviceCheckError`, ensure a `DynamoDBOperationError` wrapping `DynamoDBError::RateLimited { retry_after }` returns `StatusCode::TOO_MANY_REQUESTS` with a `Retry-After: <retry_after>` header. Match on the inner error before the generic DynamoDB arm.

- [ ] **Step 5: Add the routes**

In `src/main.rs`, beside the existing device-check routes:

```rust
        // Registration admission control: unauthenticated, username-free.
        .route(
            "/device-check/register-challenge",
            get(device_check::register_challenge),
        )
        .route(
            "/device-check/register-attest",
            post(device_check::register_attest),
        )
```

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib device_check`
Expected: PASS.

- [ ] **Step 7: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/device_check.rs src/main.rs
git commit -m "feat(device-check): unauthenticated attest flow for registration

The existing challenge endpoint requires a CWT for an account that
already exists, so it cannot gate the creation of one. Add a
username-free unauthenticated pair that verifies an attestation and puts
a short-lived one-shot ticket in the session.

Username-free on purpose: pre-account, a username-keyed endpoint would
tell an unauthenticated caller which handles exist. APP_ATTEST_APP_ID is
mandatory here — unset admits any app's attestation, which is exactly
what the gate exists to refuse."
```

---

### Task 6: Gate registration on the ticket

**Files:**
- Modify: `src/authn.rs:90` area (`start_register`), and `finish_register`
- Modify: `CLAUDE.md` (registration flow docs)
- Test: `src/authn.rs`

**Interfaces:**
- Consumes: `RegistrationTicket`, `ticket_is_valid`, `SESSION_REG_TICKET_KEY` (Task 5).
- Produces: `WebauthnError::AttestationRequired`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn attestation_required_maps_to_forbidden() {
    let response = WebauthnError::AttestationRequired.into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn an_expired_ticket_does_not_admit() {
    use crate::device_check::{ticket_is_valid, RegistrationTicket};
    let now = 1_800_000_000i64;
    let stale = RegistrationTicket {
        key_id: "k".into(),
        issued_at: now - 600,
        expires_at: now - 300,
    };
    assert!(!ticket_is_valid(&stale, now));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib authn::tests::attestation_required authn::tests::an_expired_ticket`
Expected: FAIL — `WebauthnError::AttestationRequired` does not exist.

- [ ] **Step 3: Add the error**

In `src/authn.rs`'s `WebauthnError`:

```rust
    #[error("Device attestation required before registration")]
    AttestationRequired,
```

Map it to `StatusCode::FORBIDDEN` in the `IntoResponse` impl.

- [ ] **Step 4: Gate `start_register`**

Immediately after the `is_reserved_username` check — before any DB lookup, so an unattested caller cannot probe handle existence — insert:

```rust
    // Admission control: registration requires a verified App Attest ticket.
    // Checked before any lookup so an unattested caller learns nothing about
    // which handles exist.
    let ticket: crate::device_check::RegistrationTicket = session
        .get(crate::device_check::SESSION_REG_TICKET_KEY)
        .await
        .map_err(WebauthnError::InvalidSessionState)?
        .ok_or(WebauthnError::AttestationRequired)?;

    if !crate::device_check::ticket_is_valid(&ticket, chrono::Utc::now().timestamp()) {
        warn!("Registration ticket expired for key {}", ticket.key_id);
        return Err(WebauthnError::AttestationRequired);
    }
```

- [ ] **Step 5: Consume the ticket in `finish_register`**

After the WebAuthn ceremony verifies and before the credential is stored, re-read the ticket, re-check `ticket_is_valid`, then remove it:

```rust
    let ticket: crate::device_check::RegistrationTicket = session
        .get(crate::device_check::SESSION_REG_TICKET_KEY)
        .await
        .map_err(WebauthnError::InvalidSessionState)?
        .ok_or(WebauthnError::AttestationRequired)?;

    if !crate::device_check::ticket_is_valid(&ticket, chrono::Utc::now().timestamp()) {
        return Err(WebauthnError::AttestationRequired);
    }

    // One ticket, one account.
    session
        .remove_value(crate::device_check::SESSION_REG_TICKET_KEY)
        .await
        .map_err(|e| WebauthnError::SessionError(e.to_string()))?;
```

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib`
Expected: PASS. If any existing `authn` test drives registration end to end, it must now seed a ticket in the session first — that is the gate working, not a regression. Update those tests to insert a valid `RegistrationTicket` before the call.

- [ ] **Step 7: Document the flow change**

In `CLAUDE.md`, under **Registration Flow**, add as the new first bullet:

```markdown
   - Requires a verified App Attest registration ticket in the session
     (`GET /device-check/register-challenge` → `POST /device-check/register-attest`).
     Checked before any lookup, so an unattested caller cannot probe handle
     existence (HTTP 403 otherwise)
```

- [ ] **Step 8: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/authn.rs CLAUDE.md
git commit -m "feat(authn): require an attested device to register

Registration was open: a software WebAuthn authenticator produces a
valid ceremony with no hardware, so nothing proved a registrant was our
app on a real device. Require the ticket issued by register-attest, and
check it before any DB lookup so an unattested caller cannot probe which
handles exist.

The ticket is consumed in finish_register: one attestation, one account."
```

---

### Task 7: End-to-end proof the gate holds

The load-bearing test. A software authenticator must be able to complete the WebAuthn ceremony and still be refused, because that is exactly the attack.

**Files:**
- Create: `tests/registration_gate.rs`
- Test: itself

**Interfaces:**
- Consumes: the routes from Tasks 5 and 6.
- Produces: nothing downstream.

- [ ] **Step 1: Write the failing test**

```rust
//! The registration gate, end to end.
//!
//! A software WebAuthn authenticator is exactly the attacker's tool: it
//! produces a ceremony indistinguishable from a real one without any
//! hardware. The gate must refuse it on the grounds that it never attested,
//! not on the grounds that its passkey looked wrong.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

mod common;

#[tokio::test]
async fn registration_without_a_ticket_is_refused() {
    let app = common::test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/register/softbot?handle=softbot.arkavo.social&did=did:key:z6MkTest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "an unattested caller must be refused before the ceremony begins"
    );
}

#[tokio::test]
async fn registration_challenge_is_not_issued_before_attestation() {
    let app = common::test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/register/doesnotexist?handle=doesnotexist.arkavo.social&did=did:key:z6MkTest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);

    assert!(
        !text.contains("challenge"),
        "no WebAuthn challenge may leak to an unattested caller: {text}"
    );
}
```

- [ ] **Step 2: Write the test harness**

Create `tests/common/mod.rs` building a router with the same routes as production but a stub `db_store`, mirroring the `AppState` construction already used at `src/main.rs:1403`. Export it as `pub async fn test_app() -> axum::Router`.

- [ ] **Step 3: Run test to verify it fails or passes for the right reason**

Run: `cargo test --test registration_gate`
Expected: PASS once Task 6 landed. If it returns 400 or 404 rather than 403, the gate is being reached after some other check — move the ticket check earlier in `start_register`.

- [ ] **Step 4: Add the positive case**

```rust
#[tokio::test]
async fn a_ticketed_session_reaches_the_ceremony() {
    // Seeds a valid RegistrationTicket directly into the session store, then
    // drives /register/:username. Proves the gate refuses for want of
    // attestation only — not that registration is broken for everyone.
    let (app, session_cookie) = common::test_app_with_ticket("softbot").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/register/softbot?handle=softbot.arkavo.social&did=did:key:z6MkTest")
                .header("cookie", session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a ticketed session must not be refused by the gate"
    );
}
```

Implement `test_app_with_ticket` in `tests/common/mod.rs`: create a session, insert a `RegistrationTicket` with `expires_at` 300s in the future, return the router and the session cookie header value.

- [ ] **Step 5: Run the tests**

Run: `cargo test --test registration_gate`
Expected: PASS, all three.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add tests/registration_gate.rs tests/common/mod.rs
git commit -m "test(authn): prove the registration gate refuses a soft authenticator

A software WebAuthn authenticator is the attack, so the regression test
is that one is refused for want of attestation — and that a ticketed
session is not, which is what stops the gate from being a blanket
outage. Also asserts no WebAuthn challenge leaks to an unattested
caller, since the challenge response would otherwise confirm a handle."
```

---

### Task 8: Client preflight in ArkavoKit

**Repo:** `/Users/arkavo/Projects/ArkavoKit` — a separate repository. Branch and commit there, not in `authnz-rs`.

**Files:**
- Create: `Sources/ArkavoSocial/AppAttestService.swift`
- Modify: `Sources/ArkavoSocial/ArkavoClient.swift:918` (`registerUser`)
- Test: `Tests/ArkavoSocialTests/AppAttestServiceTests.swift`

**Interfaces:**
- Consumes: `GET /device-check/register-challenge`, `POST /device-check/register-attest` (Task 5).
- Produces:

```swift
public protocol AppAttesting: Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attest(keyID: String, clientDataHash: Data) async throws -> Data
}
```

- [ ] **Step 1: Write the failing test**

```swift
import XCTest
@testable import ArkavoSocial

final class AppAttestServiceTests: XCTestCase {
    struct StubAttester: AppAttesting {
        let isSupported: Bool
        var generateCalls = Counter()
        func generateKey() async throws -> String { "stub-key-id" }
        func attest(keyID: String, clientDataHash: Data) async throws -> Data {
            Data("stub-attestation".utf8)
        }
    }

    func testUnsupportedDeviceSurfacesADistinctError() async {
        let attester = StubAttester(isSupported: false)
        do {
            _ = try await AppAttestPreflight(attester: attester).keyAndAttestation(
                challenge: "c"
            )
            XCTFail("an unsupported device must not silently proceed")
        } catch AppAttestError.unsupportedDevice {
            // expected
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testClientDataHashIsSHA256OfTheChallenge() async throws {
        let attester = StubAttester(isSupported: true)
        let result = try await AppAttestPreflight(attester: attester)
            .keyAndAttestation(challenge: "fixture-challenge")
        XCTAssertEqual(
            result.clientDataHash,
            Data(SHA256.hash(data: Data("fixture-challenge".utf8)))
        )
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `swift test --filter AppAttestServiceTests`
Expected: FAIL — `AppAttesting` / `AppAttestPreflight` undefined.

- [ ] **Step 3: Write the implementation**

```swift
import CryptoKit
import DeviceCheck
import Foundation

public enum AppAttestError: Error, Sendable {
    /// No Secure Enclave. Registration targets Apple silicon and iOS 26+, so
    /// this should be unreachable in production — surfaced distinctly rather
    /// than folded into a generic failure so it is visible if it ever is not.
    case unsupportedDevice
    /// The server rejected the attestation.
    case attestationRejected(String)
    /// The registration budget for this device is spent.
    case rateLimited(retryAfter: TimeInterval)
}

public protocol AppAttesting: Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attest(keyID: String, clientDataHash: Data) async throws -> Data
}

public struct LiveAppAttester: AppAttesting {
    public init() {}
    public var isSupported: Bool { DCAppAttestService.shared.isSupported }
    public func generateKey() async throws -> String {
        try await DCAppAttestService.shared.generateKey()
    }
    public func attest(keyID: String, clientDataHash: Data) async throws -> Data {
        try await DCAppAttestService.shared.attestKey(keyID, clientDataHash: clientDataHash)
    }
}

public struct AppAttestPreflight: Sendable {
    public struct Result: Sendable {
        public let keyID: String
        public let attestation: Data
        public let clientDataHash: Data
    }

    private let attester: AppAttesting
    public init(attester: AppAttesting = LiveAppAttester()) {
        self.attester = attester
    }

    public func keyAndAttestation(challenge: String) async throws -> Result {
        guard attester.isSupported else { throw AppAttestError.unsupportedDevice }
        let clientDataHash = Data(SHA256.hash(data: Data(challenge.utf8)))
        let keyID = try await attester.generateKey()
        let attestation = try await attester.attest(keyID: keyID, clientDataHash: clientDataHash)
        return Result(keyID: keyID, attestation: attestation, clientDataHash: clientDataHash)
    }
}
```

- [ ] **Step 4: Wire the preflight into `registerUser`**

At the top of `registerUser(handle:did:)`, before `fetchRegistrationOptions`:

```swift
        // Admission control: the server refuses registration without a
        // ticket issued against a verified App Attest attestation.
        try await performAttestationPreflight()
```

Implement `performAttestationPreflight()` to `GET register/register-challenge`, run `AppAttestPreflight.keyAndAttestation(challenge:)`, `POST` `{key_id, attestation_object, client_data_hash}` (all base64) to `device-check/register-attest`, persist `keyID` via `KeychainManager` under service `com.arkavo.webauthn` so `/device-check/assert` reuses it, and map a 429 to `AppAttestError.rateLimited(retryAfter:)` from the `Retry-After` header.

- [ ] **Step 5: Retry once on an expired ticket**

In `registerUser`, if `completeRegistration` fails with HTTP 403, call `performAttestationPreflight()` once more and retry the ceremony a single time. A ticket can expire between attest and finish; a second failure surfaces to the caller.

- [ ] **Step 6: Run the tests**

Run: `swift test --filter AppAttestServiceTests`
Expected: PASS. App Attest itself cannot run in the Simulator, so these cover ordering and hashing only; real coverage is a device build.

- [ ] **Step 7: Commit**

```bash
git add Sources/ArkavoSocial/AppAttestService.swift \
        Sources/ArkavoSocial/ArkavoClient.swift \
        Tests/ArkavoSocialTests/AppAttestServiceTests.swift
git commit -m "feat(auth): attest the device before registering

The server now refuses registration without a ticket issued against a
verified App Attest attestation, so registerUser runs the attest
preflight first. The generated key_id is kept in the Keychain so the
existing assert flow reuses it instead of generating a fresh key per
launch.

Unsupported device, rejected attestation and rate-limited are distinct
errors: collapsed into one, an unsupported device is indistinguishable
from a network blip."
```

---

## Deployment checklist

Not a task — the sequence the spec requires, to run once every task above has landed.

- [ ] `APP_ATTEST_APP_ID` is set in every environment that serves registration. The gate fails closed without it, so an unset value takes registration down.
- [ ] `device_attest_keys` table created in each environment.
- [ ] `DYNAMODB_DEVICE_ATTEST_KEYS_TABLE` set, or the default `device_attest_keys` matches the created table.
- [ ] If any ArkavoKit build is already in users' hands: deploy the endpoints first, release the app build, and only then flip enforcement. Enforcing on deploy kills registration for every shipped client, since none of them call App Attest.
- [ ] If nothing is shipped yet: enforce from the first deploy.

## Self-Review

**Spec coverage.** Gate placement → Tasks 5, 6. Ticket mechanism → Task 5. Shared verifier → Task 1. The three verification gaps → Tasks 2 (nonce ext), 3 (chain), and the counter-reset gap, which Task 3's refusal of a leaf-only chain does not address — it is bounded instead by Task 4's registration budget, since a re-attest now consumes a slot. Mandatory `APP_ATTEST_APP_ID` → Tasks 1, 5. Rate policy → Task 4. Client → Task 8. Error handling → Tasks 5 (429), 6 (403), 8 (three distinct Swift errors). soft-webauthn test → Task 7. Deployment → checklist above.

**Type consistency.** `AttestedKey`, `VerifyOptions`, `verify_attestation` defined in Task 1 and used unchanged in Tasks 2 and 5. `RegistrationTicket`, `ticket_is_valid`, `SESSION_REG_TICKET_KEY` defined in Task 5 and used unchanged in Tasks 6 and 7. `AttestKeyRecord` gains `window_base` in Task 4 Step 1 and carries it through Step 4. `AppAttesting` defined and consumed within Task 8.

**Known soft spot.** Task 4's `reserve_attest_registration` is described rather than fully written, because the conditional-update call must mirror `update_device_binding_counter`'s existing shape in `src/db.rs` and copying a guess would be worse than pointing at the pattern. The pure policy function it depends on is given in full and is the part under test.
