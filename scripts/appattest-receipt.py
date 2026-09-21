#!/usr/bin/env python3
"""Decode an App Attest receipt, and optionally exchange it with Apple.

Task 0 Step 4 of docs/superpowers/plans/2026-09-20-app-attest-registration-gate.md.

Two modes:

  decode   Read the PKCS#7 receipt and print its fields. Works offline, on the
           receipt already embedded in tests/fixtures/appattest/attestation.json.

  exchange POST the receipt to Apple and decode what comes back. This is the
           only way to see the Risk Metric (field 17) and Not Before (19),
           which an ATTEST receipt does not carry. Needs a DeviceCheck private
           key (.p8) from the developer portal.

The exchange answers one design question: whether Apple supplies a per-*device*
bound that the server-side device_attest_keys counter cannot. That counter
bounds a key_id, and attestKey is once-per-key, so a client mints a fresh key
per attestation and never meets the limit.

Usage:
  python3 scripts/appattest-receipt.py decode [--fixture PATH | --receipt FILE]
  python3 scripts/appattest-receipt.py exchange --key AuthKey_XXXX.p8 \
      --key-id XXXXXXXXXX --team-id M8GS7ZT95Y [--fixture PATH]
"""

import argparse
import base64
import datetime
import json
import sys

# Receipt field numbers.
#
# 2-7, 12 and 21 are read off the captured ATTEST receipt and confirmed by
# their values (field 2 is literally the app id string, field 6 is "ATTEST").
# 17 and 19 are from Apple's documentation and have NOT been observed here —
# an ATTEST receipt does not carry them. Treat those two labels as unverified
# until an exchange prints them.
FIELDS = {
    2: "App ID",
    3: "Attested Public Key",
    4: "Client Hash",
    5: "Token",
    6: "Receipt Type",
    7: "Environment",
    12: "Creation Time",
    17: "Risk Metric",          # unobserved
    19: "Not Before",           # unobserved
    21: "Expiration Time",
}

# Rendered as text rather than a byte count.
TEXT_FIELDS = {2, 5, 6, 7, 12, 19, 21}

# The two fields the plan says decide the design, and are the most likely to be
# skipped in a hurry.
LOAD_BEARING = {17, 19}


# ---------------------------------------------------------------------------
# Minimal CBOR + DER readers. Deliberately dependency-light: this script has to
# run on a machine that just captured an attestation, not one set up for it.
# ---------------------------------------------------------------------------


def cbor(b, i=0):
    major, arg = b[i] >> 5, b[i] & 31
    i += 1
    if arg < 24:
        v = arg
    elif arg == 24:
        v, i = b[i], i + 1
    elif arg == 25:
        v, i = int.from_bytes(b[i : i + 2], "big"), i + 2
    elif arg == 26:
        v, i = int.from_bytes(b[i : i + 4], "big"), i + 4
    elif arg == 27:
        v, i = int.from_bytes(b[i : i + 8], "big"), i + 8
    else:
        raise ValueError("indefinite-length CBOR")
    if major == 0:
        return v, i
    if major == 2:
        return b[i : i + v], i + v
    if major == 3:
        return b[i : i + v].decode(), i + v
    if major == 4:
        out = []
        for _ in range(v):
            x, i = cbor(b, i)
            out.append(x)
        return out, i
    if major == 5:
        out = {}
        for _ in range(v):
            k, i = cbor(b, i)
            val, i = cbor(b, i)
            out[k] = val
        return out, i
    raise ValueError(f"unsupported CBOR major type {major}")


def der_tlvs(buf):
    """Yield (tag, contents) for each TLV in buf, skipping EOC markers."""
    i = 0
    while i < len(buf):
        tag = buf[i]
        if tag == 0x00:  # EOC
            i += 2
            continue
        first = buf[i + 1]
        if first < 0x80:
            length, hdr = first, 2
        elif first == 0x80:  # BER indefinite — used by Apple's PKCS#7 wrapper
            yield tag, buf[i + 2 :]
            return
        else:
            n = first & 0x7F
            length = int.from_bytes(buf[i + 2 : i + 2 + n], "big")
            hdr = 2 + n
        yield tag, buf[i + hdr : i + hdr + length]
        i += hdr + length


def find_payload(receipt_der):
    """The receipt's SET of fields, wrapped several layers deep in PKCS#7.

    Rather than model the whole ContentInfo, look for the SET-of-SEQUENCE the
    fields live in: it is the only one whose members all look like
    {INTEGER type, INTEGER version, OCTET STRING value}.
    """
    best = None
    stack = [receipt_der]
    seen = 0
    while stack and seen < 20000:
        buf = stack.pop()
        seen += 1
        # Apple emits the payload as a *constructed* OCTET STRING of ~1 KiB
        # segments, so the field SET straddles two siblings. Rejoin them before
        # looking, or the walk finds only whichever half parses on its own.
        segments = [c for t, c in der_tlvs(buf) if t == 0x04]
        if len(segments) > 1:
            stack.append(b"".join(segments))
        for tag, contents in der_tlvs(buf):
            if tag == 0x31:  # SET
                fields = parse_fields(contents)
                if fields and (best is None or len(fields) > len(best)):
                    best = fields
            # Descend into anything that might hold more DER: constructed
            # types, and OCTET STRINGs — PKCS#7 wraps the field set in one, so
            # a walker that only follows constructed tags never reaches it.
            if tag & 0x20 or tag == 0x04:
                stack.append(contents)
    return best


def parse_fields(set_contents):
    out = []
    for tag, seq in der_tlvs(set_contents):
        if tag != 0x30:
            return None
        parts = list(der_tlvs(seq))
        if len(parts) != 3:
            return None
        (t0, v0), (t1, _), (t2, v2) = parts
        if t0 != 0x02 or t1 != 0x02 or t2 != 0x04:
            return None
        out.append((int.from_bytes(v0, "big"), v2))
    return out or None


def render(field_no, raw):
    if field_no in TEXT_FIELDS:
        return raw.decode("utf-8", "replace")
    if field_no == 17:
        # Small integer if it looks like one, otherwise show the bytes rather
        # than inventing a number — this is the field the design hangs on.
        return str(int.from_bytes(raw, "big")) if len(raw) <= 8 else raw.hex()
    return f"{len(raw)} bytes ({raw[:16].hex()}…)"


def receipt_from_fixture(path):
    doc = json.load(open(path))
    att, _ = cbor(base64.b64decode(doc["attestation_object"]))
    receipt = att["attStmt"].get("receipt")
    if not receipt:
        sys.exit("STOP: attStmt carries no receipt. Record this — Task 1 assumes one.")
    return receipt


def report(receipt, label):
    print(f"=== {label} ({len(receipt)} bytes) ===")
    fields = find_payload(receipt)
    if not fields:
        sys.exit("could not locate the receipt field set")
    by_no = dict(fields)
    for no, raw in sorted(fields):
        print(f"  [{no:>2}] {FIELDS.get(no, 'unknown'):<22} {render(no, raw)}")
    missing = LOAD_BEARING - set(by_no)
    if missing:
        print()
        print(
            "  Absent: "
            + ", ".join(f"{n} ({FIELDS[n]})" for n in sorted(missing))
            + " — expected on an ATTEST receipt; run `exchange` to see them."
        )
    return by_no


def es256_jwt(key_path, key_id, team_id):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    key = serialization.load_pem_private_key(open(key_path, "rb").read(), password=None)
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    header = b64(json.dumps({"alg": "ES256", "kid": key_id}).encode())
    claims = b64(json.dumps({"iss": team_id, "iat": now}).encode())
    signing_input = header + b"." + claims
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return (signing_input + b"." + b64(raw)).decode()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["decode", "exchange"])
    ap.add_argument("--fixture", default="tests/fixtures/appattest/attestation.json")
    ap.add_argument("--receipt", help="raw DER receipt file, instead of --fixture")
    ap.add_argument("--key", help="DeviceCheck private key (.p8)")
    ap.add_argument("--key-id", help="its 10-character key id")
    ap.add_argument("--team-id", default="M8GS7ZT95Y")
    ap.add_argument("--out", help="write the exchanged receipt here (DER)")
    args = ap.parse_args()

    receipt = open(args.receipt, "rb").read() if args.receipt else receipt_from_fixture(args.fixture)
    fields = report(receipt, "captured receipt")

    if args.mode == "decode":
        return

    if not (args.key and args.key_id):
        sys.exit("exchange needs --key and --key-id")

    env = fields.get(6, b"").decode("utf-8", "replace")
    # A development-signed build produces a development receipt and the
    # production endpoint rejects it. macOS has no sandbox, so a Mac capture is
    # always production even from a locally signed build.
    host = "data.appattest.apple.com" if env == "production" else "data-development.appattest.apple.com"
    url = f"https://{host}/v1/attestationData"

    import urllib.request

    req = urllib.request.Request(
        url,
        data=base64.b64encode(receipt),
        headers={
            "Authorization": "Bearer " + es256_jwt(args.key, args.key_id, args.team_id),
            "Content-Type": "text/plain",
        },
        method="POST",
    )
    print(f"\nPOST {url}  (environment={env})")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
    except Exception as e:
        detail = getattr(e, "read", lambda: b"")()
        sys.exit(f"exchange failed: {e}\n{detail[:500].decode('utf-8', 'replace')}")

    exchanged = base64.b64decode(body)
    if args.out:
        open(args.out, "wb").write(exchanged)
        print(f"wrote {args.out}")
    print()
    report(exchanged, "exchanged receipt")
    print(
        "\nRecord Receipt Type, Risk Metric, Not Before and Expiration Time in\n"
        "tests/fixtures/appattest/receipt-exchange.md. Not Before is what decides\n"
        "whether the metric can be admission control or is only an abuse signal.\n"
        "Do NOT commit the exchanged receipt: it is time-bound and is not a fixture."
    )


if __name__ == "__main__":
    main()
