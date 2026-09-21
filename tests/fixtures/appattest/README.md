# App Attest fixtures

`attestation.json` is a **real** attestation, captured once from
`com.arkavo.ArkavoCreator` (macOS, team `M8GS7ZT95Y`) on 2026-09-20. It is the
Task 0 fixture the verifier tests load.

## Do not regenerate casually

macOS App Attest has **no sandbox environment**. There is no
`appattest-environment` entitlement on macOS, so every Mac attestation is a
production one, and production keys carry per-device counts that **cannot be
reset**. Each regeneration permanently spends a key against that machine. Four
were already spent diagnosing the camelCase bug.

## Fields

| Field | Meaning |
|---|---|
| `app_id` / `app_id_hash` | `<TeamID>.<BundleID>` and its lowercase hex SHA-256 |
| `challenge` | The raw challenge string; `SHA256(challenge)` is `client_data_hash` |
| `client_data_hash` | Base64 of that digest, as passed to `attestKey` |
| `key_id` | Base64 key identifier from `generateKey()` |
| `attestation_object` | Standard base64 CBOR blob from `attestKey(_:clientDataHash:)` |
| `rp_id_hash` | `authData[0..32]`, which equals `app_id_hash` — see below |
| `environment` / `aaguid` | `production` / `appattest` — **not** `appattestdevelop` |
| `leaf_cert_not_before` / `_not_after` | The leaf's validity window |
| `verify_at` | Unix timestamp inside that window; chain checks use this, not the wall clock |

## Two findings this fixture records

**`rpIdHash` binds per App ID, not per build.** It equals
`SHA256("M8GS7ZT95Y.com.arkavo.ArkavoCreator")` exactly. The `CDhash` value on
the `app-attest-opt-in` entitlement does *not* make macOS attestations
per-build, so a static `APP_ATTEST_APP_ID` entry pins Creator and macOS is
gateable.

**The aaguid is `appattest` — production — even though this came from a locally
signed developer build.** A verifier that infers the environment from build
type (`development ⇒ appattestdevelop`) refuses every Mac client.

## `verify_at` is load-bearing, not hygiene

The leaf certificate is valid for **about three days**
(`2026-09-20T01:47:03Z` → `2026-09-23T01:47:03Z`). Chain validation checks
against `verify_at` rather than `now()` for exactly this reason: testing against
the wall clock would make the suite start failing on a date unrelated to any
code change, which is how people learn to ignore a red suite.
`fixture_verify_at_sits_inside_the_leaf_certificate_window` guards the
invariant.

## The receipt has its own clock

`attStmt.receipt` (3982 bytes) expires **2026-12-20**, not with the leaf on
2026-09-23. They are separate objects with separate lifetimes, and conflating
them makes the receipt exchange look perishable when it is not.
`receipt-exchange.md` records what it carries and what the exchange is still
waiting on. Decode it with:

```bash
python3 scripts/appattest-receipt.py decode
```

## What it does and does not prove

It proves the attestation object **parses** and that its recorded fields are
self-consistent — which is what caught the `attStmt`/`att_stmt` mismatch that
made every genuine attestation fail at CBOR decode.

It also proves the nonce extension (`1.2.840.113635.100.8.2`) matches
`SHA256(authData || clientDataHash)` and that the chain verifies to the pinned
Apple root — Tasks 2 and 3, which load this file. The tamper tests mutate it
and require a refusal, so the fixture carries both the positive and the
negative case.

## Privacy

No user data. The attested key is a throwaway bound to no account.

To regenerate, see Task 0 of
`docs/superpowers/plans/2026-09-20-app-attest-registration-gate.md` — and read
"Do not regenerate casually" above first.
