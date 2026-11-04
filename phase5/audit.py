"""The audit trail: who did what, when, with what result. Plus integrity verification.

Logs are for debugging and can be sampled, rotated and lost. The audit trail is a
RECORD: it must be complete (denied actions included), private per tenant, and
tamper-evident.
"""
import hashlib
import json

import psycopg
from psycopg.rows import dict_row

from phase2.db import tenant_session


def record(pool, tenant_id: str, user_name: str, request_id: str, action: str,
           target: str = "", outcome: str = "ok", **detail) -> None:
    """Write one audit row in its OWN transaction.

    Same reason as metering in Phase 3: if the request then fails (a 404, a 403, a crash),
    its transaction is rolled back. An audit row written inside it would vanish, and
    failed or denied actions are exactly the ones a security team needs to see."""
    with tenant_session(pool, tenant_id, user_name) as conn:
        conn.execute("SELECT audit_append(%s, %s, %s, %s, %s::jsonb)",
                     (request_id, action, target, outcome, json.dumps(detail, sort_keys=True)))


def verify_chain(dsn: str, tenant_id: str) -> dict:
    """Recompute every hash for one tenant. Run as the auditor (or owner).

    Detects: edited rows, deleted or reordered rows, and rows removed from the end (the
    stored head hash no longer matches). It can NOT detect someone with owner rights who
    rewrites the whole chain AND the head consistently. For that you anchor the head hash
    somewhere they can't reach (see the Phase 5 exercises)."""
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        rows = conn.execute(
            "SELECT id, tenant_id, user_name, request_id, action, target, outcome, detail::text AS detail,"
            " to_char(created AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US') AS ts, prev_hash, hash"
            " FROM audit_events WHERE tenant_id = %s ORDER BY id",
            (tenant_id,),
        ).fetchall()
        head = conn.execute("SELECT last_hash FROM audit_heads WHERE tenant_id = %s", (tenant_id,)).fetchone()

    prev = "genesis"
    for r in rows:
        payload = "|".join([prev, r["tenant_id"], r["user_name"], r["request_id"], r["action"],
                            r["target"], r["outcome"], r["detail"], r["ts"]])
        expected = hashlib.sha256(payload.encode()).hexdigest()
        if r["prev_hash"] != prev or r["hash"] != expected:
            return {"tenant_id": tenant_id, "ok": False, "rows": len(rows), "first_bad_id": r["id"]}
        prev = r["hash"]
    if rows and (head is None or head["last_hash"] != prev):
        return {"tenant_id": tenant_id, "ok": False, "rows": len(rows), "first_bad_id": None,
                "reason": "chain head does not match the last row (rows removed from the end?)"}
    return {"tenant_id": tenant_id, "ok": True, "rows": len(rows)}
