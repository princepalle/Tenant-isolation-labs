"""JWT verification done properly, plus a live membership check.

A valid signature only proves the IdP issued the token at some point. Before trusting it:
  - the key id must be one we publish, and the algorithm must be exactly RS256
    (never take the algorithm from the token: "alg": "none" is an old classic)
  - issuer = our IdP, audience = THIS api (not another app the same IdP serves)
  - not expired, and has every claim we rely on
  - the user is STILL an active member of that tenant, and the tenant is still active.
    Tokens live for minutes; firing someone or offboarding a customer must work right now.
"""
import json

import jwt
from fastapi import HTTPException
from jwt.algorithms import RSAAlgorithm

REQUIRED_CLAIMS = ["iss", "aud", "sub", "tenant", "iat", "exp"]


class JwtVerifier:
    def __init__(self, jwks: dict, issuer: str, audience: str, leeway: int = 30):
        self.keys = {k["kid"]: RSAAlgorithm.from_jwk(json.dumps(k)) for k in jwks["keys"]}
        self.issuer, self.audience, self.leeway = issuer, audience, leeway

    def verify(self, token: str) -> dict:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
            key = self.keys.get(kid)
            if key is None:
                raise jwt.InvalidTokenError("unknown signing key")
            return jwt.decode(
                token, key,
                algorithms=["RS256"],          # pinned. Never read it from the token.
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,            # small allowance for clock differences
                options={"require": REQUIRED_CLAIMS},
            )
        except jwt.PyJWTError:
            # One vague message for every failure: don't tell an attacker which check they tripped.
            raise HTTPException(401, "Invalid or expired token") from None


def make_authenticator(verifier: JwtVerifier, pool):
    def authenticate(authorization: str | None) -> dict:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Missing bearer token")
        claims = verifier.verify(authorization.removeprefix("Bearer ").strip())
        with pool.connection() as conn:
            active = conn.execute("SELECT auth_member(%s, %s) AS ok", (claims["sub"], claims["tenant"])).fetchone()
        if not active["ok"]:
            raise HTTPException(401, "Invalid or expired token")
        return {"name": claims["sub"], "tenant_id": claims["tenant"], "role": claims.get("role", "member")}
    return authenticate
