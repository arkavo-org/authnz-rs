# Attestation receipt — what it carries, and what the exchange is for

Task 0 Step 4 of
`docs/superpowers/plans/2026-09-20-app-attest-registration-gate.md`.

**Findings, not a fixture.** Nothing loads this file, and the exchange response
must never be committed: it is time-bound.

Tool: `scripts/appattest-receipt.py` (`decode` offline, `exchange` against
Apple).

---

## The question this answers

Can Apple supply a **per-device** bound that `device_attest_keys` cannot?

That table bounds a `key_id`, and `attestKey` is once-per-key, so a client
mints a fresh key per attestation and never meets the limit. The Risk Metric is
reportedly computed per *device*, where minting fresh keys cannot evade it. If
it is, a real bound exists and the counter is at best a cheap local pre-filter.
If it is not, drop the per-device framing from Task 4 and keep the budget as
explicit defence in depth.

---

## Step 4a — the receipt survives parsing. **Confirmed.**

The captured attestation's `attStmt.receipt` is **3982 bytes** and decodes
cleanly. The plan's stop condition (a `None` receipt would have broken Task 1's
assumed attestation shape) did not trigger.

`real_attestation_parses_and_matches_its_recorded_fields` asserts the receipt is
present and non-empty, so a regression here fails the suite rather than this
document.

## Step 4c, on the captured receipt — read offline

```
$ python3 scripts/appattest-receipt.py decode
  [ 2] App ID                 M8GS7ZT95Y.com.arkavo.ArkavoCreator
  [ 3] Attested Public Key    1046 bytes (a DER certificate)
  [ 4] Client Hash            32 bytes (bfb5aa99…)
  [ 5] Token                  TcdcAKCtdczEW7JT9l5zNofrxbnwobX0kS24IaOOGYI9…
  [ 6] Receipt Type           ATTEST
  [ 7] Environment            production
  [12] Creation Time          2026-09-21T01:47:03.468Z
  [21] Expiration Time        2026-12-20T01:47:03.468Z
```

Four things worth recording.

**Field 4 is the clientDataHash verbatim.** It equals `SHA256(challenge)` — the
same bytes passed to `attestKey`. The receipt is bound to our challenge, not
just to the key.

**`Receipt Type` is `ATTEST`.** `RECEIPT` is what a successful exchange
returns, so the type is also the check that the exchange worked.

**`Environment` is `production` — from a locally signed developer build.**
macOS has no `appattest-environment` entitlement and therefore no sandbox, so
the exchange must go to `data.appattest.apple.com`, not the development host.
Choosing the endpoint by build type sends every Mac receipt to the wrong one.

**The receipt lives 90 days, not 3.** Creation `2026-09-21`, expiration
`2026-12-20`. This **corrects the plan**, which called Step 4 perishable and
insisted it happen in the capture session. What expires in three days is the
*leaf certificate* (`2026-09-20` → `2026-09-23`), which is why Task 3's tests
pin `verify_at`. The receipt is a separate object with a separate clock, and
the exchange stays available until **2026-12-20**.

## Step 4b — the exchange. **Blocked, not perishable.**

Not run: it needs a DeviceCheck private key (`.p8`) from the developer portal
plus its key id. Neither is in this repo, and neither should be.

When the key is available:

```bash
python3 scripts/appattest-receipt.py exchange \
  --key AuthKey_XXXXXXXXXX.p8 --key-id XXXXXXXXXX --team-id M8GS7ZT95Y
```

It signs the ES256 bearer JWT (`{alg, kid}` / `{iss: team, iat}`), picks the
endpoint from field 7, posts the base64 receipt, and decodes the response.

**Record all four fields, not just the metric:**

| Field | Why it matters |
|---|---|
| Receipt Type | `RECEIPT` confirms the exchange succeeded |
| Risk Metric (17) | The count of attested keys — **and whether it is scoped to the device or the key** |
| Not Before (19) | **Governs how often a device may be exchanged for.** If coarse, the metric cannot be a per-registration gate at all |
| Expiration Time (21) | How long the new receipt stays exchangeable |

Fields 17 and 19 are **absent** from the ATTEST receipt above, which is why the
exchange is the only way to see them — and why their labels here are from
Apple's documentation rather than from observation. Do not treat the numbering
of those two as confirmed until a decode prints them.

## Price the cost, so the comparison stays honest

A receipt exchange on the registration path is an Apple HTTPS round-trip:
latency, an availability dependency, and a forced fail-open/fail-closed choice.
Fail-closed hands Apple an outage switch over registration. Fail-open drops the
bound exactly when someone is attacking. `device_attest_keys` has neither
property, because it never leaves DynamoDB.

`Not Before` is the field most likely to be skipped and the one that decides
the design: a metric that exists but refreshes on a coarse cadence is an
after-the-fact **abuse signal**, not admission control, and would not replace
the counter.

## What is already settled without the exchange

The gate does not wait on this. Admission control is the attestation itself —
a genuine device running a genuine build — and that is what defeats a software
authenticator. The open question is only whether a *second*, per-device bound
is available, not whether the gate works.
