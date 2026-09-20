# App Attest registration gate

**Date:** 2026-09-20
**Status:** designed
**Spans:** `authnz-rs` (server), `ArkavoKit` (client)

## Problem

`GET /register/:username` and `POST /register` are open HTTP endpoints. The
only thing a caller must produce is a well-formed WebAuthn registration
response. Nothing proves the caller is the Arkavo app, or that it runs on real
hardware, or that it is a person.

WebAuthn does not help here. It proves possession of a private key, not
humanity. A software authenticator — the `soft-webauthn` Python package,
`webauthn-authenticator-rs`'s SoftToken, Chrome's virtual authenticator — mints
credentials with no hardware at all. Registration can be scripted in a few
dozen lines.

The usual WebAuthn defence, requiring `attestation: "direct"` and checking the
statement against FIDO MDS, is unavailable on this stack: Apple platform
passkeys return `none` attestation, so that policy would reject every
legitimate user along with the bots.

Two further facts shape the answer:

1. Registration is iOS/macOS only, iOS 26+, Apple silicon only. **App Attest
   covers the iOS half and not the macOS half** — see "The macOS hole" below.
   An earlier draft of this spec claimed Secure Enclave presence made App
   Attest universally available with no fallback path to defend. That was
   wrong on both counts.
2. The server already implements App Attest (`src/device_check.rs`) and the
   client never calls it. `ArkavoKit` has zero references to
   `DCAppAttestService` or `DeviceCheck`. The server half was built and the
   client half was not.

Handle squatting raises the stakes. A username becomes a `did:web` identifier
and an `at://` handle, so bulk registration burns a namespace permanently, not
just table rows.

## Design

### Gate placement

Attestation runs **before** account creation. A bot never creates a row.

The existing App Attest flow cannot be reused as-is. `generate_challenge`
(`device_check.rs:163`) calls `authenticate_for_username`, requiring a CWT for
an account that already exists — it is post-registration *device binding*, not
admission control. The gate needs an unauthenticated path that binds to a
pending registration instead of a `user_id`.

```
GET  /device-check/register-challenge   → 32-byte challenge, stored in session
POST /device-check/register-attest      → {key_id, attestation_object}
                                        → verify, check rate budget (no charge),
                                          issue one-shot session ticket (~5 min)
GET  /register/:username                [ticket required]
POST /register                          [ticket required, consumed here]
```

Neither new endpoint takes a username. Pre-account, a username-keyed endpoint
would leak handle existence to an unauthenticated caller.

### Ticket mechanism

`tower-sessions`, consistent with the existing `start_register` →
`finish_register` and `generate_challenge` → `finish_attestation` pairs. The
client already sustains a session cookie across the two-step register flow, so
the mechanism is proven in `ArkavoClient`.

The session store is `MemoryStore` with a 10-minute timeout. The ticket
therefore inherits the constraint the register flow already has: a single
instance, or sticky sessions. This adds no new limitation — `reg_state` is
already session-bound — but it does put the gate on the same footing, so a
future move to multi-instance must move both together.

Fallback if cookies prove unreliable from `URLSession`, or when
multi-instance arrives: a signed short-TTL ticket with its `jti` burned in
DynamoDB. Not built unless one of those forces it.

The ticket is one-shot. `start_register` requires an unconsumed ticket;
`finish_register` consumes it, and charges the device's registration budget at
the same point — see "Rate policy".

### Shared verifier

Attestation verification currently sits inline in `finish_attestation`,
entangled with an authenticated `user_id`. Extract it:

```rust
fn verify_attestation(
    challenge: &str,
    key_id: &str,
    attestation_object: &[u8],
) -> Result<AttestedKey, DeviceCheckError>
```

Both the bound and unbound paths call exactly this. Two verifiers would drift,
and this one is load-bearing for the whole gate.

### Verification gaps that must close

`device_check.rs` and `CLAUDE.md` document three limitations. All are
tolerable for a device binding on an already-authenticated account, where the
CWT carries the security. None is tolerable when admission control rests on
attestation alone:

1. Certificate chain validation is incomplete; intermediates are not verified.
2. Extension `1.2.840.113635.100.8.2` (nonce) is not validated.
3. Re-attesting an existing `key_id` resets `counter` to 0, reopening a replay
   window for assertions captured before the re-attest.

The nonce extension is the critical one: without it the attestation is not
cryptographically bound to the issued challenge, which defeats the replay
property the gate depends on.

**`APP_ATTEST_APP_ID` must become mandatory on this path.** Today it is
optional — unset means the rpIdHash is recorded on the binding but not
enforced, logged as a warning. For a device binding that is a defensible
default. For admission control it is fatal: an unset value admits an
attestation from *any* app, which is precisely the property the gate exists to
deny. `register-attest` fails closed when it is unset, rather than warning.

The remaining checks should be confirmed present in the extracted validator:

- `aaguid` matches the environment (`appattest` in production,
  `appattestdevelop` in development). If macOS clients are ever admitted this
  must also cover whatever aaguid macOS emits — possibly `appattestsandbox`,
  unconfirmed; see "The macOS hole"
- counter is 0 at attestation time
- `key_id == SHA256(publicKey)`

### Rate policy

One genuine device can attest repeatedly, so the gate alone does not bound
account creation. Persist the attested key and count registrations:

```
device_attest_key
  key_id          (PK)
  registrations   int
  first_seen_at
  last_reg_at
```

Policy constants in `constants.rs`: on the order of 3 registrations per
rolling 24 hours with a lifetime soft cap. Increment via DynamoDB conditional
update, following the existing assertion-counter race pattern in this module.

**The slot is spent at account creation, not at attestation.** `register-attest`
checks the budget read-only; `finish_register` charges it as it consumes the
ticket. The budget bounds accounts, so it must be paid by an account coming
into existence — charging at attest time would let three flaky passkey
ceremonies lock a genuine user out for a day while creating nothing. The
preflight still refuses an already-exhausted device, so the client keeps
receiving 429/403 from the endpoint that handles them. The residual is a race:
a concurrent registration can spend the last slot between attest and finish, and
that refusal surfaces as a 403 at `finish_register`.

Rate-limited rather than capped at one: an app reinstall generates a fresh
`key_id` so a hard cap is survivable, but a user wanting a second account on
one device would be permanently blocked.

The lifetime cap is a speed bump, not a bound — a reinstall yields a fresh
`key_id`, so a determined farm pays one reinstall per ten accounts. Its real
value is as an abuse signal: a key that reaches the cap has a history no user
produces.

### Client (`ArkavoKit`)

New `AppAttestService` in `Sources/ArkavoSocial/`, wrapping
`DCAppAttestService.shared`.

`ArkavoClient.registerUser` (`ArkavoClient.swift:918`) gains a preflight ahead
of `fetchRegistrationOptions`:

```
register-challenge → generateKey() → attestKey(_:clientDataHash:)
  → POST register-attest → existing passkey ceremony, unchanged
```

The generated `key_id` persists in Keychain through the existing
`KeychainManager` shared access group (`M8GS7ZT95Y.com.arkavo.webauthn`), so
the same key later serves `/device-check/assert` rather than the app
generating a fresh one per launch.

### Error handling

Three states the UI must distinguish. Collapsing them into a generic failure
makes an unsupported device indistinguishable from a network blip and
generates support load.

| Condition | Surface |
|---|---|
| `DCAppAttestService.isSupported == false` | device cannot be verified; not retryable |
| attestation rejected | verification failed; not retryable |
| rate limit exceeded | 429 with retry-after; retryable later |

Ticket expiry between attest and register is retryable: the client re-runs the
preflight once before surfacing an error.

## Testing

### Server

The validator needs a captured real attestation blob as a fixture. The repo
has none; producing one is a prerequisite, not a test-writing detail.

Negative cases: tampered nonce extension, wrong rpId hash, non-zero counter,
expired ticket, replayed ticket, rate limit exceeded, and `APP_ATTEST_APP_ID`
unset (must refuse, not warn).

### The soft-webauthn test authenticator

`soft-webauthn` belongs here — as a test-only authenticator, giving the
registration flow its first end-to-end coverage. There is none today.

The load-bearing test: **a soft-webauthn registration without a ticket must
fail.** That is the regression test proving the gate holds. The same
authenticator with a valid ticket must succeed, proving the gate does not
break legitimate registration.

### Client

Mock the attest service to test preflight ordering and the retry-once path.
App Attest does not run in the Simulator, so real coverage is device-only.

## Deployment

The decision is to enforce rather than run a shadow phase: the gate admits
only attested registrations from the moment it is live. What remains open is
*when* it goes live, and that depends on one fact.

The gate activates when the **server** deploys, and no shipped `ArkavoKit`
build calls App Attest. If no client build is in users' hands, enforce from
the first deploy and the rest of this section does not apply.

If any build is already shipped, enforce-on-deploy kills registration for all
of those users until they update, so enforcement must be deferred by one
release:

1. deploy the endpoints, not enforcing
2. release the app build carrying the preflight
3. flip enforcement


## Prerequisites

- The app target needs the
  `com.apple.developer.devicecheck.appattest-environment` entitlement. It is
  app-level, not in the SPM package, and could not be verified from
  `ArkavoKit`.
- `APP_ATTEST_APP_ID` must be set in every environment that serves
  registration — hex SHA-256 of `<TeamID>.<BundleID>`. The gate fails closed
  without it, so an unset value in production takes registration down.
- A captured attestation blob for the validator fixture.
- The `device_attest_keys` table must exist in every environment that serves
  registration before the gate goes live. Nothing provisions it; the table name
  comes from an env var defaulting to `device_attest_keys`.

## The macOS hole

There are **two** App Attest capabilities, and only one of them covers macOS.

- **App Attest** — entitlement `com.apple.developer.devicecheck.appattest-environment`,
  values `development` / `production`. Platform Support: iOS, visionOS, tvOS.
  **Not macOS.**
- **App Attest Opt-In** — entitlement `com.apple.developer.devicecheck.app-attest-opt-in`,
  value `CDhash`. Platform Support: iOS, tvOS, watchOS, macOS, visionOS.

An earlier draft of this section said App Attest could not work on macOS and
no entitlement fixed it, citing the macOS SDK header's statement that
`supported` is `false` on a Mac. That was wrong: the header does not account
for the opt-in entitlement. With `app-attest-opt-in` granted, a Mac build
reports `isSupported = true` and `generateKey` returns a real Secure Enclave
key — observed on this hardware in both Debug and Release.

The trap that produced the wrong conclusion is worth keeping: the two
capabilities look alike in the portal, and Xcode strips an entitlement the
profile does not grant **silently**. The build succeeds and the signed binary
simply lacks the key. Never judge this from build success — read the signed
binary:

```bash
codesign -d --entitlements - --xml "$APP" | plutil -p - | grep -i attest
```

### What is still unknown about the macOS path

Two questions remain, both answerable by one `attestKey` call and parsing
what comes back. Neither is answered here, and the macOS decision should not
be made until they are:

1. **What does `rpIdHash` contain on macOS?** The entitlement's value is
   `CDhash`, which suggests attestation binds to the code directory hash
   rather than `SHA256("<TeamID>.<BundleID>")`. If so, two things follow: the
   server's `APP_ATTEST_APP_ID` comparison needs a macOS-specific form, and a
   Mac-captured fixture is per-build rather than per-app — every rebuild
   invalidates it.
2. **Which aaguid does macOS emit?** Possibly `appattestsandbox` rather than
   `appattest` / `appattestdevelop`. The verifier's environment check must
   cover whatever it actually is.

Until those are answered, the gate's guarantee must be stated as
"registration from iOS requires an attested device", never as "registration
requires an attested device". If the answers are favourable, macOS joins the
guarantee; if `rpIdHash` turns out to be per-build, macOS needs a different
app-identity check and the choice narrows to dropping macOS registration or
leaving it ungated — the latter being the weakest option, since an ungated
path is the path an attacker takes.

## Out of scope

- Migrating existing users to a device binding. This gate covers registration
  only.
- The web registration path. There is none; registration is iOS/macOS only.
- Rate limiting by IP on `register-challenge`. Worth adding, but it defends
  the challenge endpoint's cost, not the gate.
