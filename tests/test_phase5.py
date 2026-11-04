"""Phase 5 tests: structured logs, redaction and a tamper-evident audit trail.
Database tests skip if Postgres isn't reachable."""
import json
import logging
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from attacks import auth
from phase5.obs import JsonFormatter, redact

try:
    from phase2.db import ADMIN_DSN, OWNER_DSN
    from phase5.audit import verify_chain
    from phase5.checks import ALL_CHECKS
    from phase5.hunt import fresh_client
    from phase5.setup_db import AUDITOR_DSN, bootstrap

    psycopg.connect(ADMIN_DSN, connect_timeout=2).close()
    PG = True
except Exception:  # noqa: BLE001
    PG = False
    ALL_CHECKS = []

needs_pg = pytest.mark.skipif(not PG, reason="Postgres not available for Phase 5 tests")
ADMIN = {"Authorization": "Bearer platform-admin-dev"}


# ---------------------------------------------------------------- logging (no database)

def test_redaction_catches_refs_credentials_and_emails():
    out = redact("ref BANK-SECRET-abc123, key sk-mail-bank-0be1d44e, to bob@bank.example")
    assert "SECRET" not in out and "sk-mail" not in out and "bob@" not in out


def test_json_lines_cannot_be_forged_with_newlines():
    """Log injection: user input with a newline must not create a second, fake log line."""
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "x", None, None)
    record.fields = {"title": 'hi\n{"level": "INFO", "event": "admin.login", "user": "root"}'}
    line = JsonFormatter().format(record)
    assert "\n" not in line and json.loads(line)["title"].startswith("hi\n")


# ---------------------------------------------------------------- against the database

@pytest.fixture(scope="module", autouse=True)
def database():
    if PG:
        bootstrap()


@needs_pg
@pytest.mark.parametrize("check", ALL_CHECKS, ids=lambda c: c.__name__)
def test_secure_app_passes(check, tmp_path):
    with fresh_client("secure", tmp_path / "data") as client:
        f = check(client, OWNER_DSN)
    assert not f.leaked, f.evidence


@needs_pg
@pytest.mark.parametrize("check", ALL_CHECKS, ids=lambda c: c.__name__)
def test_leaky_app_fails(check, tmp_path):
    with fresh_client("leaky", tmp_path / "data") as client:
        f = check(client, OWNER_DSN)
    assert f.leaked, f"check didn't detect the planted problem: {f.evidence}"


@needs_pg
def test_untampered_chain_verifies(tmp_path):
    """No false alarms: normal activity across tenants verifies clean."""
    with fresh_client("secure", tmp_path / "data") as c:
        for token in ("hospital-alice", "bank-bob", "lawfirm-lena"):
            c.post("/agent", json={"question": "policy"}, headers=auth(token))
            c.post("/outbox/999/approve", headers=auth(token))  # a denied action, also chained
        results = c.get("/admin/audit/verify", headers=ADMIN).json()
    assert all(r["ok"] and r["rows"] == 2 for r in results), results


@needs_pg
def test_concurrent_writes_keep_the_chain_intact(tmp_path):
    """20 requests at once for the same tenant: the head-row lock makes them take turns."""
    with fresh_client("secure", tmp_path / "data") as c:
        def upload(i):
            return c.post("/documents", headers=auth("hospital-alice"),
                          json={"title": f"d{i}", "doc_type": "Note", "body": "x"}).status_code
        with ThreadPoolExecutor(max_workers=8) as pool:
            assert set(pool.map(upload, range(20))) == {201}
    assert verify_chain(AUDITOR_DSN, "hospital") == {"tenant_id": "hospital", "ok": True, "rows": 20}


@needs_pg
def test_concurrent_agent_runs_do_not_deadlock(tmp_path):
    """Each /agent run holds a request connection AND writes usage + audit rows on the side pool."""
    with fresh_client("secure", tmp_path / "data") as c:
        def run(i):
            return c.post("/agent", json={"question": f"loan policy {i}"}, headers=auth("bank-bob")).status_code
        with ThreadPoolExecutor(max_workers=12) as pool:
            assert set(pool.map(run, range(24))) == {200}
    assert verify_chain(AUDITOR_DSN, "bank") == {"tenant_id": "bank", "ok": True, "rows": 24}


@needs_pg
def test_request_ids_and_admin_endpoints(tmp_path):
    with fresh_client("secure", tmp_path / "data") as c:
        good = c.post("/agent", json={"question": "policy"}, headers={**auth("hospital-alice"), "X-Request-ID": "ticket-12345678"})
        assert good.headers["x-request-id"] == "ticket-12345678"  # a well-formed caller ID is kept
        bad = c.post("/agent", json={"question": "policy"}, headers={**auth("hospital-alice"), "X-Request-ID": "x\nforged"})
        assert bad.headers["x-request-id"] != "x\nforged"           # a malformed one is replaced

        assert c.get("/admin/security-events", headers=auth("hospital-alice")).status_code == 403
        c.post("/outbox/999/approve", headers=auth("bank-bob"))
        events = c.get("/admin/security-events", headers=ADMIN).json()
        assert any(e["tenant_id"] == "bank" and e["action"] == "email.approve" and e["outcome"] == "denied"
                   for e in events)
