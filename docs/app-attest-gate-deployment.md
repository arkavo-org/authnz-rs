# App Attest registration gate — deployment runbook

**Audience:** whoever operates `identity.arkavo.net`.
**Spec:** `docs/superpowers/specs/2026-09-20-app-attest-registration-gate-design.md`
**Plan:** `docs/superpowers/plans/2026-09-20-app-attest-registration-gate.md`

## Do not deploy PR #66 on its own

PR #66 (`feat/app-attest-registration-gate`) adds a per-device registration
budget to `src/db.rs` and nothing that calls it. There are no new routes, no
ticket type, and no gate on `start_register` / `finish_register`. Deploying it
changes no runtime behaviour, so it buys nothing and costs a restart.

Registration stays exactly as open as it is today until Tasks 1–7 land. Wait.

## Host reality — read before either phase

`identity.arkavo.net` does **not** run under a service manager. The systemd
section in `DEPLOYMENT_GUIDE.md` describes a Linux deployment that was never
the one in service; the host is macOS, so there is no systemd, and
`/etc/authnz-rs/` does not exist.

What is actually running:

| | |
|---|---|
| Binary | `production/authnz-rs`, built by `production/build.sh` |
| Environment | `production/start.sh` — **not** a `.env` file |
| Invocation | `sudo ./start.sh` from `production/`, binding `192.0.2.6:443` |
| Supervision | none — the process runs in the **foreground on a tty** |

Two consequences for everything below. `systemctl restart` does not exist here;
restarting means stopping the process and re-running `start.sh`. And because it
is foreground-attached, the server dies with the terminal session that launched
it and does not survive a reboot — worth fixing independently of this gate, and
a reason to keep restarts few.

## Phase 0 — prepare now (no behaviour change)

Safe to do at any time, and doing it early removes the two things most likely
to break the real deploy.

### 1. Create the `prod-device-attest-keys` table

Nothing provisions it, and a missing table surfaces as `TableNotExists` at the
first attestation. The code's fallback name is the unprefixed
`device_attest_keys`, but every production table carries a `prod-` prefix
(`start.sh:27-34`), so create the prefixed name and set the variable in step 2
— do not rely on the fallback.

```bash
aws dynamodb create-table \
    --region us-east-1 \
    --table-name prod-device-attest-keys \
    --attribute-definitions AttributeName=key_id,AttributeType=S \
    --key-schema AttributeName=key_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST
```

Verify:

```bash
aws dynamodb describe-table --region us-east-1 \
    --table-name prod-device-attest-keys --query 'Table.TableStatus'
```

Expect `"ACTIVE"`. No GSI, no TTL — rows are the abuse history and are meant to
persist.

### 2. Add both variables to `production/start.sh`

There is no `production.env`. These go in the env block of `start.sh`,
alongside the other `DYNAMODB_*_TABLE` exports at lines 27-34.

> **Insert them above line 174.** `start.sh` ends in `exec ./authnz-rs`;
> anything appended after that line — with `>>`, for instance — is never
> reached, and the process starts without it.

```bash
# App Attest registration gate
export DYNAMODB_DEVICE_ATTEST_KEYS_TABLE=prod-device-attest-keys

# Comma-separated set of SHA-256(<TeamID>.<BundleID>), lower-case hex.
# Both apps register users, so both belong here.
#   com.arkavo.Arkavo        (iOS)
#   com.arkavo.ArkavoCreator (macOS)
export APP_ATTEST_APP_ID=543398d88f303adedb67445ee9edbf1e1733a73d92bf6992cfbf228d60763cf8,ea2defc9e7bf14b832b0fb5e4ada8f0af0e114dca9fc7741cda17d875cf1bc01
```

**The set form requires Task 1.** Until it ships, `APP_ATTEST_APP_ID` is parsed
as a single value (`src/main.rs:453`) and a comma-separated string will match
nothing. Set only the iOS hash before Task 1 lands, or leave it unset and add
it during Phase 1.

**Setting it today is safe but not free.** It flips the existing authenticated
device-binding path (`POST /device-check/attest`, `src/device_check.rs:269`)
from warn-only to enforcing `AppIdMismatch`. That path currently has no
callers — ArkavoKit `main` contains no `DCAppAttestService` or `device-check`
usage at all — so nothing can break today. It becomes load-bearing the moment a
client starts attesting.

### 3. Restart and confirm nothing moved

```bash
# Stop the running server: Ctrl-C in the session holding it, or from elsewhere
sudo pkill -f 'production/authnz-rs'

# Start it again (foreground; keep the session alive)
cd <repo>/production && sudo ./start.sh
```

The startup banner echoes bind address, port and TLS paths — check those before
walking away.

Registration must still work end to end. If it doesn't, the cause is Phase 0,
not the gate — the gate does not exist yet.

## Phase 1 — the enforcing deploy

**There is no shadow phase.** This is a deliberate decision in the spec, not an
oversight: the gate admits only attested registrations from the instant the
server starts. A client build without the App Attest preflight cannot register
at all after this deploy.

So the deploy order is fixed, and it is the client that goes first:

1. **ArkavoKit tags a release carrying the preflight** (`df3fa36`, currently on
   the unmerged branch `feat/app-attest-registration-preflight`).
2. **Arkavo and Arkavo Creator ship builds** resolved against that tag.
3. **Only then** deploy the server with Tasks 1–7.

Reversing 2 and 3 breaks registration for every user on a shipped build until
they update.

### Release-order hazard, both directions

`ArkavoClient.registerUser` calls `performAttestationPreflight()`
*unconditionally*. There is no feature flag and no fallback: if the endpoints
are absent the preflight gets a 404, falls through to `attestationRejected`,
and registration fails.

Creator pins ArkavoKit `upToNextMajorVersion` from `0.1.11`. Any `0.1.12+` tag
carrying the preflight is inside that range and Creator's next dependency
resolve picks it up silently. **Do not tag ArkavoKit 0.1.x with the preflight
until this server deploy is live**, or pin Creator to `exact: 0.1.11` for its
release.

### Pre-flight checks

- `prod-device-attest-keys` is `ACTIVE` (Phase 0 step 1)
- `APP_ATTEST_APP_ID` is set and contains **both** hashes. The gate fails
  closed when it is unset, so an unset value in production takes registration
  down — this is intentional; an unset value would otherwise admit an
  attestation from any App Attest-capable app.
- The aaguid environment check accepts what your clients actually emit: a
  shipped build emits `appattest`, a local developer build `appattestdevelop`.
- Confirm the macOS answer. If a released Creator's `rpIdHash` does not equal
  `ea2defc9…`, it is the CDhash — per-build, changing every Creator release,
  and no static `APP_ATTEST_APP_ID` entry can pin it. In that case macOS must
  be resolved (dropped, or given a different identity check) **before** this
  deploy, not after.

### Deploy

```bash
# on the identity.arkavo.net host (the build happens in place)
cd <repo>
git pull
./production/build.sh        # release + --features webvh,http3

sudo pkill -f 'production/authnz-rs'
cd production && sudo ./start.sh
```

`build.sh` is the only supported build: it compiles `--features webvh,http3`,
without which the did:webvh log and the QUIC listener are absent from the
binary.

### Verify

```bash
# The challenge endpoint must answer without authentication.
curl -si https://identity.arkavo.net/device-check/register-challenge | head -1

# Registration without a ticket must be refused.
curl -si https://identity.arkavo.net/register/some-unused-handle | head -1
```

Expect `200` on the first and `403` on the second. A `200` on the second means
the gate is not engaged — roll back.

Then register once from a real device build, end to end, and confirm a row
appears:

```bash
aws dynamodb scan --region us-east-1 --table-name prod-device-attest-keys \
    --max-items 5
```

## Rollback

The gate is one deploy, so rollback is one deploy:

```bash
git checkout <previous-release-tag>
./production/build.sh
sudo pkill -f 'production/authnz-rs'
cd production && sudo ./start.sh
```

`production/authnz-rs.backup.*` holds prior binaries if a rebuild is not
possible; copying one over `production/authnz-rs` and restarting is faster than
a rebuild when the priority is restoring service.

Leave the table and the env vars in place — they are inert without the code.

Do **not** try to disable the gate by unsetting `APP_ATTEST_APP_ID`. It fails
closed, so that takes registration down rather than opening it.

## Monitoring after the deploy

| Signal | Meaning |
|---|---|
| `AppIdMismatch` in logs | A client bundle is not in `APP_ATTEST_APP_ID` — a missed hash, or an unexpected app |
| `APP_ATTEST_APP_ID is unset` warning | Configuration did not reach the process; registration is down |
| 429s on `register-attest` | Per-device window budget spent — 3 per 24h |
| 403s on `finish_register` | Lifetime cap, or the last slot taken by a concurrent registration between attest and finish |
| `TableNotExists: prod-device-attest-keys` | Phase 0 step 1 was skipped |
| Registration volume → 0 | A shipped client without the preflight, or the ordering above was reversed |

Rows in `prod-device-attest-keys` are also the abuse signal: a `key_id` with an
implausible registration history is a farm. The lifetime cap is a speed bump,
not a bound — a reinstall yields a fresh `key_id`.
