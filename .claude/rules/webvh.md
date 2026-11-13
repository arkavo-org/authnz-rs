---
paths:
  - "src/webvh.rs"
  - "src/webvh_tests.rs"
---

# webvh.rs - did:webvh passports and handle bindings (#132)

Contract and rollout: [docs/did-handle-binding.md](docs/did-handle-binding.md).

- The canonical identity is `did:webvh`. New passports are minted at
  `identity.arkavo.net:dids:<user_id>` (bare UUID); existing DIDs, such as
  `dids:arkavo`, keep their identifier and log. The log is append-only on
  the `credentials` row, written by `compare_and_swap_webvh_log` against the
  exact old log, so concurrent writers never replace a DID or lose an entry.
- Routes, all read-only (a GET never signs or writes a log):
  - `GET /dids/:id/did.jsonl`: the stored log, `text/jsonl`.
  - `GET /dids/:id/did.json`: the parallel `did:web` view of the latest
    state, never rebuilt from a passkey. No log ⇒ 404.
  - `GET /handles/:label/did.json`: the keyless alias document
    (`did:web:<label>.arkavo.social`, `alsoKnownAs` = the `did:webvh`).
    The edge (devsecops#35) serves it at
    `https://<label>.arkavo.social/.well-known/did.json`. 404 unless the
    handle row is owned, not retired, names the account's live DID, and the
    latest state names the handle.
- `:id` is a UUID (resolved by account key, the DID's path must match) or a
  legacy name, resolved **only** through the permanent handle row, whose DID
  must match the log's id and path. The handle row is the reserved-name map:
  a changed or reused username never repoints an old path. Never resolve a
  path by the current username, and never delete a retired handle row.
- `refresh_handle_binding` (passkey sign-in, enrollment of another passkey):
  once the log names `https://<handle>` and `at://<handle>` and the handle
  row maps the handle to the DID, it only reads those two rows. Otherwise it
  verifies the whole chain, appends the missing aliases with the update key
  (`WEBVH_SIGN_KEY_PATH`), validates the result, writes it conditionally,
  and repairs the handle row. Failure is logged, never fatal to sign-in.
- A verifier accepts a handle only when both directions agree, and only the
  `https://` alias counts: the alias endpoint answers for either alias, so
  an account still holding only `at://` is not verified until its next
  passkey sign-in.
- Behind `--features webvh` (CI runs `cargo test --features webvh --bin
  authnz-rs webvh::`); the tests generate throwaway update keys.
