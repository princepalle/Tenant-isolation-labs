"""Phase 7 LEAKY app: what "shipping it" often looks like the first time.

Phases 1-6 are fixed (it's the Phase 5 secure app inside). The problems are in login,
configuration, offboarding and export. Each is marked `# PROBLEM n:`.

  python -m phase7.hunt leaky
  uvicorn phase7.leaky_app:app --port 8011
"""
import jwt
from fastapi import Depends, Header, HTTPException
from fastapi.responses import JSONResponse

from common import DEFAULT_DATA
from phase2.db import APP_DSN, OWNER_DSN, make_pool, tenant_session
from phase4.agent import get_agent
from phase5 import secure_app as phase5_secure

# PROBLEM 29 (secrets in code): hard-coded, committed to git, baked into every image, and
# identical in dev and production. Setting LAB_ENV=production changes nothing.
ADMIN_TOKEN = "platform-admin-dev"


def create_app(settings=None, agent=None, limiter=None, pool=None, side_pool=None, ops_pool=None,
               data_dir=DEFAULT_DATA):
    pool = pool or make_pool(APP_DSN)
    side_pool = side_pool or make_pool(APP_DSN, size=3)
    owner_pool = ops_pool or make_pool(OWNER_DSN, size=1)  # offboarding runs as the table owner

    def authenticate(authorization: str | None) -> dict:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Missing bearer token")
        token = authorization.removeprefix("Bearer ").strip()
        try:
            # PROBLEM 26 (signature not checked): "temporarily" disabled while debugging the
            # IdP integration. Anyone can write {"tenant": "bank"} into a token and become the bank.
            # PROBLEM 27 (audience/issuer not checked): a token minted for a DIFFERENT app
            # (say, the marketing site, where people pick their own company) works here.
            # PROBLEM 28 (no expiry, no membership check): expired tokens work, and so do tokens
            # of people who were deactivated or whose company was offboarded.
            claims = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            raise HTTPException(401, "Invalid token") from None
        return {"name": claims["sub"], "tenant_id": claims["tenant"], "role": claims.get("role", "member")}

    app = phase5_secure.create_app(pool=pool, agent=agent or get_agent(), limiter=limiter,
                                   admin_token=ADMIN_TOKEN, side_pool=side_pool, authenticate_fn=authenticate)
    app.title = "Phase 7: production app (LEAKY)"

    def require_admin(authorization: str | None = Header(None)):
        if authorization != f"Bearer {ADMIN_TOKEN}":
            raise HTTPException(403, "Admin credentials required")

    def tenant_admin(authorization: str | None = Header(None)):
        user = authenticate(authorization)
        if user["role"] != "admin":
            raise HTTPException(403, "Only a tenant admin can do this")
        return user

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz():
        try:
            with pool.connection(timeout=2) as conn:
                conn.execute("SELECT 1")
        except Exception:  # noqa: BLE001
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return {"status": "ready"}

    @app.get("/export")
    def export(user=Depends(tenant_admin)):
        # PROBLEM 31 (incomplete export): "export your data" returns documents only. Chats,
        # emails, usage and the audit trail are missing, which fails a data-access request.
        with tenant_session(pool, user["tenant_id"], user["name"]) as conn:
            docs = conn.execute("SELECT id, tenant_id, doc_type, title, created, body FROM documents ORDER BY id").fetchall()
        return {"tenant_id": user["tenant_id"], "tables": {"documents": docs}}

    @app.delete("/admin/tenants/{tenant_id}", dependencies=[Depends(require_admin)])
    def offboard(tenant_id: str):
        # PROBLEM 30 (offboarding leaves data behind): deletes documents and users, and calls it
        # done. Outbox emails, chats, the leaky activity log, and the files on disk all stay.
        # And since login never checks membership (28), the customer's tokens keep working.
        with owner_pool.connection() as conn:
            docs = conn.execute("DELETE FROM documents WHERE tenant_id = %s", (tenant_id,)).rowcount
            users = conn.execute("DELETE FROM users WHERE tenant_id = %s", (tenant_id,)).rowcount
        return {"tenant_id": tenant_id, "deleted": {"documents": docs, "users": users}}

    return app


def __getattr__(name):
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
