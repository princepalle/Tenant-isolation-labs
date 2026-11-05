"""Phase 7: the app you'd actually ship. Phase 5's secure app, plus:

- Login with signed JWTs from an identity provider: pinned algorithm, issuer, audience,
  expiry, required claims, known key ids, and a live membership check on every request
- Settings from env vars / secret files; refuses to start in production with dev values
- /healthz and /readyz for the container platform (no auth, no tenant data)
- GET /export: a tenant admin downloads everything their workspace holds
- DELETE /admin/tenants/{id}: offboarding through a role that can do only that

  python -m phase7.idp init          # once: dev keys + secrets into ./secrets/
  uvicorn phase7.secure_app:app --port 8012
  curl -H "Authorization: Bearer $(python -m phase7.idp token hospital-alice)" localhost:8012/export
"""
import hmac
import os
import time
from pathlib import Path

import psycopg
from fastapi import Depends, Header, HTTPException
from fastapi.responses import JSONResponse

from common import DEFAULT_DATA
from phase2.db import make_pool, tenant_session
from phase4.agent import get_agent
from phase5 import audit
from phase5 import secure_app as phase5_secure
from phase5.obs import context
from phase7.auth import JwtVerifier, make_authenticator
from phase7.offboarding import EXPORTED, RETAINED, delete_files
from phase7.settings import Settings

EXPORT_QUERIES = {t: f"SELECT * FROM {t} ORDER BY id" for t in EXPORTED}
EXPORT_QUERIES["documents"] = "SELECT id, tenant_id, doc_type, title, created, body, file_name FROM documents ORDER BY id"


def create_app(settings: Settings | None = None, agent=None, limiter=None,
               pool=None, side_pool=None, ops_pool=None, data_dir=None):
    settings = settings or Settings.load()  # raises ConfigError before anything starts
    data_dir = Path(data_dir or os.environ.get("LAB_DATA_DIR", DEFAULT_DATA))
    pool = pool or make_pool(settings.app_dsn)
    side_pool = side_pool or make_pool(settings.app_dsn, size=3)
    ops_pool = ops_pool or make_pool(settings.ops_dsn, size=1)
    authenticate = make_authenticator(JwtVerifier(settings.jwks, settings.issuer, settings.audience), pool)

    app = phase5_secure.create_app(pool=pool, agent=agent or get_agent(), limiter=limiter,
                                   admin_token=settings.admin_token, side_pool=side_pool,
                                   authenticate_fn=authenticate, auditor_dsn=settings.auditor_dsn)
    app.title = "Phase 7: production app (secure)"

    def require_admin(authorization: str | None = Header(None)):
        given = (authorization or "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(given.encode(), settings.admin_token.encode()):
            raise HTTPException(403, "Admin credentials required")

    def tenant_admin(authorization: str | None = Header(None)):
        user = authenticate(authorization)
        if user["role"] != "admin":
            raise HTTPException(403, "Only a tenant admin can do this")
        return user

    @app.get("/healthz")
    def healthz():
        """Liveness: the process is up. Never touches the database or tenant data."""
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz():
        """Readiness: can we serve traffic? The platform stops routing to us if not."""
        try:
            with pool.connection(timeout=2) as conn:
                conn.execute("SELECT 1")
        except Exception:  # noqa: BLE001 - any failure means "not ready"
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return {"status": "ready"}

    @app.get("/export")
    def export(user=Depends(tenant_admin)):
        with tenant_session(pool, user["tenant_id"], user["name"]) as conn:  # RLS: own tenant only
            tables = {t: conn.execute(q).fetchall() for t, q in EXPORT_QUERIES.items()}
        audit.record(side_pool, user["tenant_id"], user["name"], context()["request_id"],
                     "tenant.export", outcome="ok", rows=sum(map(len, tables.values())))
        return {"tenant_id": user["tenant_id"], "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "tables": tables}

    @app.delete("/admin/tenants/{tenant_id}", dependencies=[Depends(require_admin)])
    def offboard(tenant_id: str):
        try:
            with ops_pool.connection() as conn:  # platform_ops: may run offboard_tenant(), nothing else
                deleted = conn.execute("SELECT offboard_tenant(%s) AS r", (tenant_id,)).fetchone()["r"]
        except psycopg.errors.RaiseException:
            raise HTTPException(404, "No active tenant with that id") from None
        return {"tenant_id": tenant_id, "deleted": deleted,
                "files_deleted": delete_files(data_dir, tenant_id), "retained": RETAINED}

    return app


def __getattr__(name):
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
