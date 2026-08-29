#!/usr/bin/env python3
"""Mint a PEP service CWT from the IdP env file. Never prints the secret or token.

Run on identity.arkavo.net (or any host that can read the EnvironmentFile):

    python3 scripts/mint-pep-cwt.py catalog-node --eval
    python3 scripts/mint-pep-cwt.py mcp-edge
    python3 scripts/mint-pep-cwt.py opentdf --eval   # 403 after AUTHZEN_PEP_CLIENT_IDS

Looks up OIDC_CLIENT_<TAG>_ID / _SECRET in an env file. With no --env-file and
no AUTHNZ_ENV_FILE, the first readable candidate wins:

    /etc/authnz-rs/production.env   (systemd EnvironmentFile deployment)
    <repo>/production/start.sh      (the current identity.arkavo.net box)

The live host runs authnz-rs from a foreground `sudo ./start.sh`, so its env
source of truth is production/start.sh (gitignored), not an EnvironmentFile.
Both parse the same way: `export KEY=value` lines.

The secret is POSTed on a pipe, not argv, so it does not appear in `ps` or in
this process's stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

TOKEN_URL = os.environ.get("AUTHZEN_TOKEN_URL", "https://identity.arkavo.net/oauth/token")
EVAL_URL = os.environ.get(
    "AUTHZEN_EVAL_URL", "https://platform.arkavo.net/access/v1/evaluation"
)
ENV_FILE_CANDIDATES = (
    "/etc/authnz-rs/production.env",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "production", "start.sh"),
)


def default_env_file() -> str:
    """First readable candidate, or the first candidate for the error message."""
    override = os.environ.get("AUTHNZ_ENV_FILE")
    if override:
        return override
    for candidate in ENV_FILE_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    return ENV_FILE_CANDIDATES[0]


def load_env_file(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :]
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                val = val[1:-1]
            out[key] = val
    return out


def secret_for_client(env: dict[str, str], client_id: str) -> str:
    """The registered OIDC_CLIENT_<TAG>_SECRET wins.

    CATALOG_AUTHZ_CLIENT_SECRET is only a fallback for hosts that predate the
    tagged registration. Consulting it first meant a stale copy left in the
    env file silently shadowed a rotated secret, and the only symptom was an
    unexplained `mint_http: 401`.
    """
    for key, val in env.items():
        if not key.startswith("OIDC_CLIENT_") or not key.endswith("_ID"):
            continue
        if val != client_id:
            continue
        tag = key[len("OIDC_CLIENT_") : -len("_ID")]
        secret = env.get(f"OIDC_CLIENT_{tag}_SECRET", "")
        if not secret:
            raise SystemExit(f"OIDC_CLIENT_{tag}_ID={client_id} but _SECRET is empty")
        return secret
    if client_id == "catalog-node":
        fallback = env.get("CATALOG_AUTHZ_CLIENT_SECRET", "")
        if fallback:
            print(
                "warning: no OIDC_CLIENT_<TAG>_ID=catalog-node in the env file; "
                "falling back to CATALOG_AUTHZ_CLIENT_SECRET",
                file=sys.stderr,
            )
            return fallback
    raise SystemExit(f"no OIDC_CLIENT_<TAG>_ID={client_id} in env file")


def post_form(url: str, fields: dict[str, str]) -> tuple[int, bytes]:
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def post_json(url: str, token: str, payload: dict) -> tuple[int, bytes]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {token}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("client_id", choices=("catalog-node", "mcp-edge", "opentdf"))
    p.add_argument("--env-file", default=None)
    p.add_argument(
        "--eval",
        action="store_true",
        help="POST /access/v1/evaluation with the minted CWT (prints status+decision only)",
    )
    args = p.parse_args()

    env_file = args.env_file or default_env_file()
    if not os.path.isfile(env_file):
        raise SystemExit(
            "env file not found: %s (tried %s; override with --env-file or AUTHNZ_ENV_FILE)"
            % (env_file, ", ".join(ENV_FILE_CANDIDATES))
        )
    env = load_env_file(env_file)
    secret = secret_for_client(env, args.client_id)
    status, raw = post_form(
        TOKEN_URL,
        {
            "grant_type": "client_credentials",
            "client_id": args.client_id,
            "client_secret": secret,
        },
    )
    del secret
    try:
        data = json.loads(raw.decode() or "{}")
    except json.JSONDecodeError:
        data = {}
    token = data.get("access_token") if isinstance(data, dict) else None
    token_s = token if isinstance(token, str) else ""
    print(
        json.dumps(
            {
                "mint_http": status,
                "token_type": data.get("token_type") if isinstance(data, dict) else None,
                "expires_in": data.get("expires_in") if isinstance(data, dict) else None,
                "error": data.get("error") if isinstance(data, dict) else None,
                "access_token_len": len(token_s) or None,
                "access_token_has_dot": ("." in token_s) if token_s else None,
                "id_token_has_dot": (
                    "." in data["id_token"]
                    if isinstance(data, dict) and isinstance(data.get("id_token"), str)
                    else None
                ),
            }
        )
    )
    if status != 200 or not token_s:
        return 1
    if not args.eval:
        return 0
    ev_status, ev_raw = post_json(
        EVAL_URL,
        token_s,
        {
            "subject": {
                "type": "user",
                "id": "arkavo:00000000-0000-0000-0000-000000000000",
            },
            "action": {"name": "read"},
            "resource": {"type": "catalog_item", "id": "probe"},
        },
    )
    del token_s
    try:
        ev = json.loads(ev_raw.decode() or "{}")
    except json.JSONDecodeError:
        ev = {}
    print(
        json.dumps(
            {
                "eval_http": ev_status,
                "decision": ev.get("decision") if isinstance(ev, dict) else None,
                "error": ev.get("error") if isinstance(ev, dict) else None,
            }
        )
    )
    return 0 if ev_status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
