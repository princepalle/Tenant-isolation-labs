"""Smoke-test a RUNNING deployment over HTTP, the way a client would. CI runs it against the
freshly built container; you can point it at any environment you deploy to.

  python -m phase7.smoke http://localhost:8000

Uses the IdP keys and admin token from ./secrets (from `python -m phase7.idp init --db`).
Destructive: it offboards the lawfirm tenant at the end. Never point it at production data.
"""
import sys
import time

import httpx
import jwt

from phase7.idp import AUDIENCE, ISSUER, SECRETS_DIR, IdentityProvider


def main(base: str) -> int:
    idp = IdentityProvider.load()
    admin = {"Authorization": f"Bearer {(SECRETS_DIR / 'admin_token').read_text().strip()}"}

    def as_user(key):
        return {"Authorization": f"Bearer {idp.issue(key)}"}

    now = int(time.time())
    forged = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "bob", "tenant": "bank", "iat": now,
                         "exp": now + 300}, None, algorithm="none")
    results = []
    with httpx.Client(base_url=base, timeout=10) as c:
        def check(name, ok):
            results.append(ok)
            print(f"  [{' ok ' if ok else 'FAIL'}] {name}")

        ask = {"question": "What is the staff policy for handovers?"}
        check("ready", c.get("/readyz").json() == {"status": "ready"})
        check("no token -> 401", c.post("/agent", json=ask).status_code == 401)
        check("forged token -> 401", c.post("/agent", json=ask, headers={"Authorization": f"Bearer {forged}"}).status_code == 401)
        r = c.post("/agent", json=ask, headers=as_user("hospital-alice"))
        check("agent answers from own tenant", r.status_code == 200 and "HOSPITAL-SECRET-" in r.text
              and "BANK-SECRET-" not in r.text and "X-Request-ID" in r.headers)
        check("member can't export -> 403", c.get("/export", headers=as_user("hospital-hank")).status_code == 403)
        r = c.get("/export", headers=as_user("hospital-alice"))
        check("admin exports own tenant only", r.status_code == 200 and r.json()["tenant_id"] == "hospital"
              and "BANK-SECRET-" not in r.text and len(r.json()["tables"]["documents"]) >= 20)
        check("dev admin token rejected", c.get("/admin/audit/verify",
              headers={"Authorization": "Bearer platform-admin-dev"}).status_code == 403)
        r = c.get("/admin/audit/verify", headers=admin)
        check("audit chains verify", r.status_code == 200 and all(x["ok"] for x in r.json()))
        r = c.delete("/admin/tenants/lawfirm", headers=admin)
        check("offboard lawfirm", r.status_code == 200 and r.json()["deleted"]["documents"] >= 20)
        check("offboarded user locked out", c.get("/activity", headers=as_user("lawfirm-lena")).status_code == 401)

    print(f"  -> {results.count(False)} of {len(results)} smoke checks failed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"))
