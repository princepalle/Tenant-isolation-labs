"""Phase 5 checks: is the record of what happened complete, private, trustworthy, and safe?
`leaked=True` means the check FAILED.

Checks read the app's captured log lines from `client.app.state.log_lines`.
"""
import json
import re

import psycopg
from psycopg.rows import dict_row

from attacks import Finding, auth, foreign_tenants_in
from phase2.db import APP_DSN
from phase4.checks import QUESTION

ADMIN = {"Authorization": "Bearer platform-admin-dev"}
SENSITIVE = re.compile(r"\b[A-Z]+-SECRET-\w+|\bsk-[A-Za-z0-9-]{8,}|John Placeholder")
SENSITIVE_BODY = "Shift notes for John Placeholder, ref HOSPITAL-SECRET-feedc0ffee. Handover at 7pm."


def content_in_logs(client, owner_dsn) -> Finding:
    """Upload a document and ask the agent a question. Then read the logs."""
    client.post("/documents", headers=auth("hospital-alice"),
                json={"title": "Shift notes", "doc_type": "Staff policy", "body": SENSITIVE_BODY})
    client.post("/agent", json={"question": QUESTION}, headers=auth("hospital-alice"))
    lines = client.app.state.log_lines
    bad = [line for line in lines if SENSITIVE.search(line) or QUESTION in line]
    if bad:
        return Finding(21, "Document content in logs", True,
                       f"{len(bad)} of {len(lines)} log lines contain document text, refs or the user's question")
    return Finding(21, "Document content in logs", False, f"{len(lines)} log lines, none with content")


def log_context(client, owner_dsn) -> Finding:
    """Can you find every log line for one request, and tell which tenant it was for?"""
    r = client.post("/agent", json={"question": "staff policy"}, headers=auth("hospital-alice"))
    request_id = r.headers.get("x-request-id")
    if not request_id:
        return Finding(22, "Logs without request/tenant context", True, "no X-Request-ID on the response")
    mine = []
    for line in client.app.state.log_lines:
        try:
            entry = json.loads(line)
        except ValueError:
            return Finding(22, "Logs without request/tenant context", True, f"unstructured log line: {line[:60]}")
        if entry.get("request_id") == request_id:
            mine.append(entry)
    if not mine or any(e.get("tenant_id") != "hospital" for e in mine):
        return Finding(22, "Logs without request/tenant context", True,
                       f"{len(mine)} lines for the request, not all tagged with the tenant")
    return Finding(22, "Logs without request/tenant context", False,
                   f"{len(mine)} lines share request_id {request_id[:8]}..., all tagged hospital")


def cross_tenant_activity(client, owner_dsn) -> Finding:
    """The bank does some work. Then the hospital opens its activity page."""
    client.post("/documents", headers=auth("bank-bob"), json={"title": "Q3 note", "doc_type": "Note", "body": "x"})
    client.post("/agent", json={"question": "loan policy"}, headers=auth("bank-bob"))
    r = client.get("/activity", headers=auth("hospital-alice"))
    hits = foreign_tenants_in(r.text, "hospital")
    if hits:
        return Finding(23, "Other tenants' activity visible", True,
                       f"the hospital's activity page shows {', '.join(sorted(hits))} activity")
    return Finding(23, "Other tenants' activity visible", False, "only the hospital's own activity")


def audit_tampering(client, owner_dsn) -> Finding:
    """1) The app's own database role tries to delete history (think: SQL injection).
    2) Someone with owner rights quietly edits a row. Does verification notice?"""
    client.post("/documents", headers=auth("hospital-alice"), json={"title": "a", "doc_type": "Note", "body": "a"})
    for table in ("audit_events", "activity_log"):
        try:
            with psycopg.connect(APP_DSN) as conn:
                conn.execute("SELECT set_config('app.tenant_id', 'hospital', true)")
                conn.execute(f"DELETE FROM {table} WHERE tenant_id = 'hospital'")
        except psycopg.errors.InsufficientPrivilege:
            pass
    if not client.get("/activity", headers=auth("hospital-alice")).json():
        return Finding(24, "Audit history can be erased or edited", True, "the app role deleted the hospital's history")

    with psycopg.connect(owner_dsn) as conn:
        conn.execute("UPDATE audit_events SET target = 'doc:999' WHERE tenant_id = 'hospital'")
    r = client.get("/admin/audit/verify", headers=ADMIN)
    detected = r.status_code == 200 and any(x["tenant_id"] == "hospital" and not x["ok"] for x in r.json())
    if not detected:
        return Finding(24, "Audit history can be erased or edited", True,
                       f"an edited audit row went unnoticed (verify: HTTP {r.status_code})")
    return Finding(24, "Audit history can be erased or edited", False,
                   "the app role can't delete, and the owner's edit was detected")


def denials_recorded(client, owner_dsn) -> Finding:
    """A bank user tries to approve an email that isn't theirs, and the free law firm
    hits its rate limit. Both must show up in the audit trail."""
    client.post("/outbox/1/approve", headers=auth("bank-bob"))
    for i in range(7):  # free plan: 5 per minute
        client.post("/agent", json={"question": f"billing policy {i}"}, headers=auth("lawfirm-lena"))
    with psycopg.connect(owner_dsn, row_factory=dict_row) as conn:
        rows = conn.execute(
            "SELECT tenant_id FROM audit_events WHERE outcome = 'denied'"
            " UNION ALL SELECT tenant_id FROM activity_log WHERE outcome = 'denied'"
        ).fetchall()
    tenants = {r["tenant_id"] for r in rows}
    if not {"bank", "lawfirm"} <= tenants:
        return Finding(25, "Denied actions missing from audit", True,
                       f"denied actions recorded for: {sorted(tenants) or 'nobody'} (expected bank and lawfirm)")
    return Finding(25, "Denied actions missing from audit", False, f"{len(rows)} denied actions recorded")


ALL_CHECKS = [content_in_logs, log_context, cross_tenant_activity, audit_tampering, denials_recorded]
