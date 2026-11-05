"""A tiny stand-in for a real identity provider (Auth0, Okta, Entra ID, Cognito...).

The IdP holds PRIVATE keys and signs tokens. Your app only ever gets the PUBLIC keys
(a "JWKS", JSON Web Key Set) and can verify tokens but never mint them.

A token looks like this once decoded:
    header:  {"alg": "RS256", "kid": "key-2026-a"}
    claims:  {"iss": "https://idp.lab.example", "aud": "tenant-lab-api",
              "sub": "alice", "tenant": "hospital", "role": "admin",
              "iat": 1730764800, "exp": 1730765100}

  python -m phase7.idp init                  # write dev keys + secrets into ./secrets/
  python -m phase7.idp init --db             # ...plus random database passwords (for the container)
  python -m phase7.idp token hospital-alice  # print a token for a lab user
"""
import json
import secrets as pysecrets
import sys
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from common import LAB_DIR, USERS

ISSUER = "https://idp.lab.example"
AUDIENCE = "tenant-lab-api"
ADMINS = {"hospital-alice", "bank-bob", "lawfirm-lena"}  # one tenant admin per tenant
SECRETS_DIR = LAB_DIR / "secrets"


def directory(user_key: str) -> dict:
    """Lab user key (e.g. 'hospital-alice') -> the claims the IdP knows about them."""
    name, tenant = USERS[user_key]
    return {"sub": name, "tenant": tenant, "role": "admin" if user_key in ADMINS else "member"}


class IdentityProvider:
    def __init__(self, private_keys: dict | None = None):
        # kid -> private key. Two keys so you can practise rotation: sign with the newest,
        # keep publishing the old public key until every token it signed has expired.
        self.keys = private_keys or {kid: rsa.generate_private_key(public_exponent=65537, key_size=2048)
                                     for kid in ("key-2026-a", "key-2026-b")}
        self.current_kid = sorted(self.keys)[-1]

    def jwks(self) -> dict:
        out = []
        for kid, key in sorted(self.keys.items()):
            jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
            out.append({**jwk, "kid": kid, "alg": "RS256", "use": "sig"})
        return {"keys": out}

    def issue(self, user_key: str, ttl: int = 300, kid: str | None = None, **overrides) -> str:
        """Short-lived (5 min) by default: if a token leaks, it's useless soon."""
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + ttl, **directory(user_key), **overrides}
        kid = kid or self.current_kid
        return jwt.encode(claims, self.keys[kid], algorithm="RS256", headers={"kid": kid})

    # ---- persistence for the CLI (dev only)
    def save(self, folder: Path = SECRETS_DIR) -> None:
        folder.mkdir(mode=0o700, exist_ok=True)
        for kid, key in self.keys.items():
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
            (folder / f"idp_{kid}.pem").write_bytes(pem)
        (folder / "jwks").write_text(json.dumps(self.jwks()))

    @classmethod
    def load(cls, folder: Path = SECRETS_DIR) -> "IdentityProvider":
        keys = {p.stem.removeprefix("idp_"): serialization.load_pem_private_key(p.read_bytes(), None)
                for p in folder.glob("idp_*.pem")}
        if not keys:
            raise SystemExit("No IdP keys found. Run: python -m phase7.idp init")
        return cls(keys)


def init_dev_secrets(folder: Path = SECRETS_DIR, db_passwords: bool = False) -> None:
    IdentityProvider().save(folder)
    (folder / "admin_token").write_text(pysecrets.token_urlsafe(32))  # random, never committed
    if db_passwords:  # for the production-mode container (docker compose --profile app)
        for name in ("app_db_password", "ops_db_password", "auditor_db_password"):
            (folder / name).write_text(pysecrets.token_urlsafe(24))
    print(f"Wrote keys and secrets to {folder}/ (git-ignored). The admin token is in {folder}/admin_token")


if __name__ == "__main__":
    if sys.argv[1:2] == ["init"]:
        init_dev_secrets(db_passwords="--db" in sys.argv)
    elif sys.argv[1:2] == ["token"] and len(sys.argv) == 3:
        print(IdentityProvider.load().issue(sys.argv[2]))
    else:
        print(__doc__)
