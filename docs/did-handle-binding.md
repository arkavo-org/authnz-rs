# Public handle binding (#132)

The canonical signing identity is `did:webvh`. New passports use
`did:webvh:<scid>:identity.arkavo.net:dids:<user_id>` with the bare UUID.
Existing DIDs, including `dids:arkavo`, keep their identifier and original log.
Handles are permanent; usernames are display labels. Handles are never reassigned.

## Resolution

- `GET /dids/:id/did.jsonl` returns the stored signed history as `text/jsonl`,
  as recommended by the [v1.0 specification](https://identity.foundation/didwebvh/v1.0/).
- `GET /dids/:id/did.json` returns the parallel `did:web` document from the
  latest log state, with local DID URLs rewritten. It never reconstructs keys
  from a passkey. Accounts without a log return 404.
- `GET /handles/:label/did.json` returns an alias document:

  ```json
  {
    "@context": "https://www.w3.org/ns/did/v1",
    "id": "did:web:arkavo.arkavo.social",
    "alsoKnownAs": ["did:webvh:QmPQfg3Dw3r8geAeWvZCXQ1PtwprZV9XXzt7ge4PsxpXme:identity.arkavo.net:dids:arkavo"]
  }
  ```

  The alias contains no verification methods or authentication/assertion keys.
  Unknown, reserved, retired, deleted, unpublished, or mismatched identities
  return 404. Storage failures return 500.

[devsecops#35](https://github.com/arkavo-org/devsecops/issues/35) routes
`https://<label>.arkavo.social/.well-known/did.json` to this origin endpoint.
Its cache key must include the rewritten label path. Keep the edge TTL short
(the deployment specifies 60 seconds, maximum 300) so deletion propagates.

UUID paths resolve by account primary key. Legacy name paths resolve through
permanent handle ownership and must exactly match the path in the stored DID.
The handle row is the reserved-name map: a changed or reused username cannot
repoint the old path, even on rows predating the stored `handle` attribute.
Do not delete retired handle rows. A legacy log whose handle mapping was never
published needs that owned mapping repaired before its legacy path resolves.

## Publishing existing accounts' forward binding

Build with `--features webvh` and configure the existing `WEBVH_SIGN_KEY_PATH`.
New passports include both `https://<handle>` and `at://<handle>` in `alsoKnownAs`.
Successful passkey sign-in and additional passkey enrollment update existing logs
once, appending the missing aliases with the original update key. This preserves
the DID, SCID, all prior log bytes, verification methods, and other aliases.
The update validates the old and resulting chains and uses a conditional write
against the exact old log. Concurrent initial mints cannot replace a DID, and
concurrent updates cannot lose history. A subsequent login repairs a failed
handle publication without minting another DID.

Deploy the server, then sign in as `arkavo` to publish its forward binding.
Dormant accounts retain their previous log until their next passkey sign-in or
enrollment. GET requests never sign or mutate logs. An unavailable or mismatched
update key leaves the log intact and logs a warning; authentication still works.
The `POST /authenticate` response's historical `handle` field remains the username
pending the separate ArkavoKit contract change.

Check both halves after deployment and account sign-in:

```sh
curl -fsS https://identity.arkavo.net/handles/arkavo/did.json
curl -fsS https://arkavo.arkavo.social/.well-known/did.json
curl -fsS https://identity.arkavo.net/dids/arkavo/did.jsonl | tail -1 | jq .state.alsoKnownAs
```

No DNS change, DID re-mint, bulk database rewrite, or new table is needed.
A future username-rename implementation must persist the permanent `handle`
on pre-attribute user rows before changing their username; the legacy read
fallback elsewhere in the account code still derives that field from username.
Passkey rotation and adding new passkeys to existing DID verification methods
remain outside #132's scope.

## Verifier contract

A handle is verified only when **both directions agree**:

1. Fetch `https://<handle>/.well-known/did.json`; require its `id` to be
   `did:web:<handle>` and its `alsoKnownAs` to name the canonical `did:webvh`.
2. Resolve and cryptographically validate that DID's complete log, including
   the SCID, hash chain, authorized proofs, and deactivation status.
3. Require its latest document's `alsoKnownAs` to include exactly
   `https://<handle>`. An `at://` alias alone does not satisfy this check.

C2PA claims, TDF policies, and other signed artifacts embed the canonical
`did:webvh`, never the handle's `did:web` alias. The parallel `did:web` document
is a compatibility view and does not establish verifiable history.

## Tests

With the local tables initialized by `scripts/dynamodb-local-tables.sh`:

```sh
AUTHNZ_TEST_DYNAMODB_ENDPOINT=http://localhost:8000 cargo test
AUTHNZ_TEST_DYNAMODB_ENDPOINT=http://localhost:8000 cargo test --features webvh --bin authnz-rs webvh::
```

CI runs both. The feature-enabled tests generate throwaway signing keys and
validate complete logs offline; no production credentials are used.
