"""Where tenant data lives, what offboarding deletes, and what it keeps (and why).

The easy way to get offboarding wrong is to forget a place. So this file is the data
inventory, and tests/test_phase7.py checks it against the real database: every table with
a tenant_id column must be either DELETED or RETAINED-with-a-reason. Add a table, forget it
here, and the build goes red.
"""
import shutil
from pathlib import Path

DELETED = ["messages", "conversations", "outbox", "documents", "activity_log", "users"]

RETAINED = {
    "usage_events": "billing records must be kept for years; user names are pseudonymized",
    "audit_events": "security record of what happened; holds metadata only (Phase 5), no content",
    "audit_heads": "the audit chain's integrity anchor",
}

# What a tenant admin can download about their own workspace (read under RLS, as the app).
# Not exported: users (credentials) and activity_log (the Phase 5 leaky table, no RLS).
EXPORTED = ["documents", "conversations", "messages", "outbox", "usage_events", "audit_events"]


def tenant_tables(conn) -> set[str]:
    rows = conn.execute(
        "SELECT table_name FROM information_schema.columns"
        " WHERE table_schema = 'public' AND column_name = 'tenant_id'"
    ).fetchall()
    return {r[0] if isinstance(r, tuple) else r["table_name"] for r in rows}


def delete_files(data_dir, tenant_id: str) -> bool:
    """Files on disk aren't in the database, so offboard_tenant() can't reach them."""
    folder = Path(data_dir) / tenant_id
    existed = folder.exists()
    shutil.rmtree(folder, ignore_errors=True)
    return existed
