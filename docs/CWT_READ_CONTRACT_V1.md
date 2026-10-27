# Arkavo CWT — Read Token Contract (v1)

Audience: tdf-iroh-s3 and other read-side PEPs.
Issuer: the Arkavo authnz service (`authnz-rs`).
Status: v1, last reviewed 2026-05-26.

## 1. Token format

- **COSE_Sign1** (RFC 8392 CWT). Not a JWT.
- Signed with the platform's CWT signing key. Verification key set published at
  `https://<arkavo-platform>/.well-known/cose-keys` (JSON, `kid`-indexed COSE_Key).
- Decoder + verifier reference: `opentdf-rs/examples/pep_check.rs` — vendor or `cargo add opentdf-rs` and reuse it. Do not roll your own COSE_Sign1 parser.

## 2. Required claims

| Claim | CBOR key | Type | Required | Notes |
|---|---|---|---|---|
| `iss` | 1 | text | ✓ | Exact-match the configured platform issuer string. |
| `sub` | 2 | text | ✓ | Stable subject id. Surface to audit logs. |
| `iat` | 6 | int | ✓ | Reject tokens with `iat` more than 60s in the future (clock skew). |
| `exp` | 4 | int | ✓ | Reject if `now >= exp`. Reject if `exp - iat > 3600`. |
| `scope` | text key | text | ✓ | Space-separated. Must contain `catalog.read`. |
| `cnf` | 8 | map | conditional | Required when the connection is iroh-authenticated; see §4. |
| `authorization_details` | text key | array | ✓ | RFC 9396; see §3. |

Claims not in this table are ignored on the read path (e.g. `campaign_id` is a publisher-side concept — accept but do not enforce).

## 3. `authorization_details` (RFC 9396)

CBOR array of grant maps. Example (CBOR diagnostic notation):

```
"authorization_details" : [
  { "type":    "tdf_attribute",
    "fqn":     "https://acme.com/attr/classification/value/topsecret",
    "actions": ["read"] },
  { "type":    "tdf_attribute",
    "fqn":     "https://acme.com/attr/dept/value/eng",
    "actions": ["read"] }
]
```

v1 schema rules:

- `type` allowlist: `"tdf_attribute"`. **Unknown types: skip silently** — keeps clients forward-compatible when the platform adds new grant types.
- `actions` allowlist: `["read"]`. **Unknown action names: reject the whole token** — the issuer promised this allowlist and a violation indicates either a mis-minted token or a downgrade attempt.
- `fqn`: canonical OpenTDF attribute-value FQN (`https://<authority>/attr/<name>/value/<value>`). Case-sensitive. No normalization.
- Optional fields reserved for future use (clients must accept and ignore): `locations`, `obligations`.

After parsing, collapse to `Entitlements` (`HashMap<String, Vec<String>>`) keyed by FQN. ~10 LoC on top of `parse_authorization_details`.

## 4. Channel binding (`cnf.iroh_node_id`)

When the read ALPN handler has an authenticated peer NodeId:

- `cnf.iroh_node_id` (bytes, 32) **must** be present and **must** equal the QUIC peer's NodeId.
- On mismatch: close the iroh connection. Do **not** return a 403 over an authenticated channel — that leaks token validity.
- On absent `cnf` over an iroh-authenticated channel: reject as malformed.

For non-iroh callers (e.g. local debugging tools), `cnf` enforcement is off and the token verifies on standard claims alone. Production read paths always pass `Some(connection_node_id)` and so are bound by construction.

## 5. Decision-time PDP

The token gives you `Entitlements`. To turn that into a yes/no for a specific object, pick the right PDP:

- **Resources tagged with a mandatory set of FQNs (every tag must match)**: use `opentdf_rs::pdp::access::local::decide_any()`. Stateless, allocation-free, hot-path safe.
- **Resources whose attribute definitions use ANY_OF or HIERARCHY**: use `opentdf_rs::pdp::AccessPdp` with a locally loaded attribute-definition catalog. `access::local` cannot evaluate rule semantics from flat grants and will be subtly wrong for these cases.

If you don't know which applies, default to `AccessPdp` — the cost is a catalog load at startup.

## 6. Failure modes — required behavior

| Condition | Action |
|---|---|
| Signature invalid / unknown `kid` | Reject. Log `kid` and source NodeId. |
| `exp` in the past | Reject. No client-side refresh — token-exchange is the platform's job. |
| `iat` > now + 60s | Reject. |
| `scope` missing `catalog.read` | Reject. |
| `cnf.iroh_node_id` mismatch (iroh path) | Close connection. |
| `authorization_details` missing or empty array | Reject — token carries no read rights. |
| `authorization_details[].type` unknown | Skip that entry. Do **not** reject. |
| `authorization_details[].actions` contains unknown action | Reject the whole token. |
| `authorization_details[].fqn` not parseable as a URL | Skip that entry. |
| PDP decision = deny | Return the iroh-equivalent of 403 (after the connection is established and authorized at the channel layer). |

## 7. Versioning

Field-level: additive only. New optional fields and new `type` values land in this document and propagate to clients on their own cadence — that's why §3 mandates skipping unknown types.

Breaking changes (action allowlist contraction, claim removal, signature alg change): bumped to v2 with a new `scope` value (`catalog.read.v2`) so old and new clients can coexist during rollout.

## 8. Reference integration sketch

```rust
let claims = pep_check::verify_cwt(&cwt_bytes, &jwks, expected_iss, expected_node_id)?;
let grants = pep_check::parse_authorization_details(claims.payload())?;
let ents: Entitlements = grants_to_entitlements(&grants); // ~10 LoC
let decision = AccessPdp::new(catalog).check(&ents, &resource_fqns)?;
```

That is the entire integration. Anything more elaborate is probably wrong.
