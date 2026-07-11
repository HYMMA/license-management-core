#!/usr/bin/env python3
"""EdDSA (Ed25519) test-vector generator.

tools/vectorgen (C#) pins RS256/ES256 against the license server's signing
code. The server's `format=eddsa` uses standard Ed25519 JWS (RFC 8037), so
these vectors are generated here instead: every *valid* payload from
tests/vectors/vectors.json is re-signed with a fixed Ed25519 key, keeping the
already-pinned NowUtc/ExpectedStatus pairs, plus tampered/malleable variants.

Deterministic: a fixed seed produces the same key and signatures every run.

    pip install cryptography
    python tools/eddsa-vectorgen/gen.py tests/vectors/vectors-eddsa.json
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[2]
SEED = hashlib.sha256(b"license-management-core eddsa vectors v1").digest()

# group order L, little-endian (for the malleable S+L variant)
ED_L = (2**252 + 27742317777372353535851937790883648493).to_bytes(32, "little")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_jws(sk: Ed25519PrivateKey, payload: bytes) -> str:
    header = b64url(b'{"alg":"EdDSA","typ":"JWT"}')
    signing_input = f"{header}.{b64url(payload)}".encode()
    sig = sk.sign(signing_input)
    return f"{header}.{b64url(payload)}.{b64url(sig)}"


def main() -> None:
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        REPO / "tests" / "vectors" / "vectors-eddsa.json")

    sk = Ed25519PrivateKey.from_private_bytes(SEED)
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    base = json.loads((REPO / "tests" / "vectors" / "vectors.json").read_text())

    cases = []
    first_valid_jws = None
    for case in base["Cases"]:
        if not case.get("Valid"):
            continue  # tampered variants are re-derived below, per algorithm
        payload = b64url_dec(case["Jws"].split(".")[1])
        name = case["Name"]
        name = "eddsa-" + name.split("-", 1)[1]  # rs256-x / es256-x -> eddsa-x
        if any(c["Name"] == name for c in cases):
            continue  # rs256/es256 duplicates of the same scenario
        jws = sign_jws(sk, payload)
        if first_valid_jws is None:
            first_valid_jws = jws
        new = {"Name": name, "Jws": jws, "Valid": True}
        for k in ("NowUtc", "ExpectedStatus", "LicenseId"):
            if k in case:
                new[k] = case[k]
        cases.append(new)

    # tampered payload: flip one character of the payload segment
    h, p, s = first_valid_jws.split(".")
    tampered = p[:-2] + ("A" if p[-2] != "A" else "B") + p[-1]
    cases.append({"Name": "eddsa-tampered-payload",
                  "Jws": f"{h}.{tampered}.{s}", "Valid": False})

    # truncated signature
    cases.append({"Name": "eddsa-truncated-signature",
                  "Jws": f"{h}.{p}.{s[:-8]}", "Valid": False})

    # malleable signature: S' = S + L verifies in sloppy implementations
    sig = b64url_dec(s)
    s_plus_l = (int.from_bytes(sig[32:], "little") +
                int.from_bytes(ED_L, "little")).to_bytes(33, "little")[:32]
    cases.append({"Name": "eddsa-malleable-s",
                  "Jws": f"{h}.{p}.{b64url(sig[:32] + s_plus_l)}",
                  "Valid": False})

    # wrong key: same payload signed by a different Ed25519 key
    other = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"some other vendor's key").digest())
    cases.append({"Name": "eddsa-wrong-key",
                  "Jws": sign_jws(other, b64url_dec(p)), "Valid": False})

    out = {
        "EdJwk": {"kty": "OKP", "crv": "Ed25519", "x": b64url(pub)},
        "Cases": cases,
    }
    out_path.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {out_path} ({len(cases)} cases)")


if __name__ == "__main__":
    main()
