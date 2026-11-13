---
paths:
  - "src/site.rs"
---

# Operator home page and site icons

## site.rs: The operator's home page and site icons (#138)

- **authnz-rs carries no branding: any organization can deploy it.** Never
  commit an organization's logos, page text or other assets; the operator
  supplies them, like the AASA file.
- Apple Passwords shows a site's icon beside its passkeys, and a passkey's
  site is the RP ID. With `SITE_ASSETS_DIR` set, each file present there is
  read once at boot and served at a fixed path (`site::FILES`):
  - `index.html` at `GET /`;
  - `apple-touch-icon.png` at `/apple-touch-icon.png` and
    `/apple-touch-icon-precomposed.png` (180×180, opaque);
  - `favicon-32x32.png`;
  - `favicon.ico`.
- Only those names are read, so nothing else in the directory is exposed.
  An absent file leaves its path to the 404 fallback. A directory that
  cannot be read, or holds none of the files, fails boot.
- The page should not redirect off-domain: an icon fetcher that follows
  the redirect lands on a host that may have no touch icon.
- Arkavo's files live in `production/site/` on the prod box (gitignored).
