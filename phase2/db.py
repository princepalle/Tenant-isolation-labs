"""Postgres plumbing for Phase 2: connection settings, auth, and the tenant session.

The most important function in Phase 2 is `tenant_session()`.
"""
import hashlib
import os
from contextlib import contextmanager

import psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

HOST = os.environ.get("LAB_PG_HOST", "localhost")
PORT = os.environ.get("LAB_PG_PORT", "5432")
DB_NAME = "tenantlab"

# Dev-only passwords. In production these come from a secrets manager, never source code.
ADMIN_DSN = os.environ.get("LAB_PG_ADMIN_DSN", f"postgresql://postgres:postgres@{HOST}:{PORT}/postgres")
OWNER_DSN = f"postgresql://lab_owner:owner_pw@{HOST}:{PORT}/{DB_NAME}"   # migrations + seeding only
APP_DSN = f"postgresql://app_user:app_pw@{HOST}:{PORT}/{DB_NAME}"        # what the web app uses


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def make_pool(dsn: str = APP_DSN, size: int = 5) -> ConnectionPool:
    return ConnectionPool(dsn, min_size=1, max_size=size, kwargs={"row_factory": dict_row}, open=True)


def authenticate(pool: ConnectionPool, authorization: str | None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    with pool.connection() as conn:
        row = conn.execute("SELECT name, tenant_id FROM auth_user(%s)", (token_hash(token),)).fetchone()
    if row is None:
        raise HTTPException(401, "Invalid token")
    return row


@contextmanager
def tenant_session(pool: ConnectionPool, tenant_id: str, user_name: str):
    """Borrow a pooled connection and scope it to ONE tenant for ONE transaction.

    The `true` in set_config(..., true) means "local to this transaction", the same as
    SET LOCAL. When the transaction ends, the setting is gone, so the next request that
    borrows this connection starts with no tenant and sees nothing until it sets its own.

    With `false` (or a plain SET), the tenant sticks to the connection and the next
    borrower inherits it. That's a real, common production leak; see rls_demo.py lesson 4.
    """
    with pool.connection() as conn:
        with conn.transaction():
            conn.execute(
                "SELECT set_config('app.tenant_id', %s, true), set_config('app.user_name', %s, true)",
                (tenant_id, user_name),
            )
            yield conn


def install_rls_error_handler(app: FastAPI) -> None:
    """A write blocked by a WITH CHECK policy becomes a clean 403 instead of a 500."""

    @app.exception_handler(psycopg.errors.InsufficientPrivilege)
    async def _rls_denied(request: Request, exc: Exception):
        return JSONResponse(status_code=403, content={"detail": "Not allowed"})
