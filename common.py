"""Shared plumbing for both apps: paths, DB connection, and authentication.

Authentication is NOT the lesson here, so both apps use the same simple
bearer-token lookup. The lesson is what each app does with the tenant
once it knows who the user is.
"""
import sqlite3
from pathlib import Path

from fastapi import HTTPException

LAB_DIR = Path(__file__).resolve().parent
DEFAULT_DB = LAB_DIR / "lab.db"
DEFAULT_DATA = LAB_DIR / "data"

TENANTS = ["hospital", "bank", "lawfirm"]

# token -> (user name, tenant). Two users per tenant.
USERS = {
    "hospital-alice": ("alice", "hospital"),
    "hospital-hank": ("hank", "hospital"),
    "bank-bob": ("bob", "bank"),
    "bank-betty": ("betty", "bank"),
    "lawfirm-lena": ("lena", "lawfirm"),
    "lawfirm-leo": ("leo", "lawfirm"),
}


def connect(db_path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def require_user(conn: sqlite3.Connection, authorization: str | None) -> dict:
    """Turn 'Authorization: Bearer <token>' into {'name', 'tenant_id'} or 401."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    row = conn.execute(
        "SELECT name, tenant_id FROM users WHERE token = ?", (token,)
    ).fetchone()
    if row is None:
        raise HTTPException(401, "Invalid token")
    return dict(row)
