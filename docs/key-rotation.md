# Signing key rotation

The CWT/JWT signing key (`ENCODING_KEY_PATH` / `DECODING_KEY_PATH`) signs
every Arkavo token, every OIDC `id_token` and every passkey credential
attestation. Since 0.22.0 (#107) the server trusts a **key set**: the current
key plus the public keys listed in `VERIFY_ONLY_KEY_PATHS`.

- Only the current key signs.
- A token or attestation is verified with the key its protected-header `kid`
  names. A missing or unknown `kid` is refused (`unknown signing key`).
- `/.well-known/cose-keys` and `/.well-known/jwks.json` list the whole set,
  current key first, under the same `kid`s (RFC 7638 thumbprint: raw bytes in
  COSE, base64url in the JWKS). `cose-keys` is served with
  `Cache-Control: public, max-age=600`.
- Startup logs one line per key: `CWT signing key kid=…` and
  `CWT verify-only key kid=… (<path>)`. A path that cannot be read or parsed,
  the current key listed again, or a duplicate fails startup.

`SIGN_KEY_PATH` (the registration attestation envelope) is a separate key and
is not part of the set.

## What a key signed, and how long it matters

| Signed with the key | Lifetime | Effect of dropping the key |
|---|---|---|
| Passkey auth CWT, OIDC access token, `id_token`, DeviceCheck CWT | 1 h | Holders sign in again |
| Agent CWT | ≤ 15 min | The agent re-runs challenge/token |
| Registration CWT | ~99 years | Every holder's token stops verifying: they sign in with a passkey again |
| Passkey credential attestation (catalog v2) | **no expiry** | See below |

OIDC refresh tokens are opaque (a hash in Redis), not signed: they survive a
rotation, and a refresh mints under the current key.

An attestation stays in each creator's published catalog bundle until that
creator publishes again. Once its key leaves `cose-keys`, every follower sees
"This catalog couldn't be verified" for that creator, and the node refuses
that creator's next publish with 422 `invalid bundle: credential signed by an
unknown key`; the creator recovers by publishing again.
See [passkey-credential-attestation.md](passkey-credential-attestation.md).

Consumers that read the set: the OpenTDF platform's CWT verifier, the
tdf-iroh-s3 node (catalog v2), the Arkavo app (`IdentityKeySet`, selects by
`kid`), and OIDC relying parties (`jwks.json`). Creator only consumes
attestations.

## Planned rotation

On identity.arkavo.net the variables below go in `production/start.sh`, before
its final `exec`.

1. **Generate the new key pair** (keep the old files):

   ```bash
   openssl ecparam -genkey -noout -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out encodekey-2.pem
   openssl ec -in encodekey-2.pem -pubout -out decodekey-2.pem
   chmod 600 encodekey-2.pem decodekey-2.pem
   ```

2. **Publish it before it signs.** Add the new public key as verify-only and
   restart:

   ```bash
   export VERIFY_ONLY_KEY_PATHS=$(pwd)/decodekey-2.pem
   ```

   Check that the startup log shows both kids, and that
   `curl -s https://identity.arkavo.net/.well-known/jwks.json | jq -r '.keys[].kid'`
   prints two. Then wait for consumers to fetch the new set: at least 600 s
   (the `cose-keys` cache lifetime), longer if a consumer refreshes on its own
   schedule. A consumer that has not fetched the new key refuses tokens signed
   with it.

3. **Switch the signer.** Point `ENCODING_KEY_PATH` / `DECODING_KEY_PATH` at
   the new pair, list the **old** public key as verify-only, and restart:

   ```bash
   export ENCODING_KEY_PATH=$(pwd)/encodekey-2.pem
   export DECODING_KEY_PATH=$(pwd)/decodekey-2.pem
   export VERIFY_ONLY_KEY_PATHS=$(pwd)/decodekey.pem
   ```

   The log now shows the new kid as the signing key and the old one as
   verify-only. Everything signed before the switch still verifies. A
   startup error `verify-only key … is already in the key set` means the
   step is half-applied: a verify-only path names the key `DECODING_KEY_PATH`
   already does.

4. **Retire the old key** by removing it from `VERIFY_ONLY_KEY_PATHS` and
   restarting, but only when both are true:
   - **no stored catalog bundle cites its `kid`.** Every creator has
     published since the switch, re-attesting under the new key. The node is
     the place to check this.
   - **you accept that registration CWTs signed with it stop verifying.**
     They live ~99 years, so there is no point at which they expire. Holders
     sign in with a passkey again.

   Until then the old key costs nothing to keep listed: it never signs.

Keep the old private key (`encodekey.pem`) offline or delete it after step 3;
the server only needs its public half.

## Leaked key

Remove it **at once**. Do not list it as verify-only: a leaked key that stays
listed can still mint tokens and attestations that verify.

1. Generate a new pair (step 1 above).
2. Point `ENCODING_KEY_PATH` / `DECODING_KEY_PATH` at it, drop the leaked
   key from `VERIFY_ONLY_KEY_PATHS`, and restart. There is no time to publish
   first. Consumers pick up the new key when their `cose-keys` cache expires
   (≤ 600 s) or when they refetch on an unknown `kid`.

Accept the consequences: every outstanding token signed with the leaked key
fails (users sign in again), and every creator's catalog fails to verify
until that creator publishes again.
