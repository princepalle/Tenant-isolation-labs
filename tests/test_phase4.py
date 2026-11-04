"""Phase 4 tests: prompt injection against an agent with tools. Database tests skip without Postgres."""
import psycopg
import pytest

from attacks import auth
from phase4.secure_app import guard_output

try:
    from phase2.db import ADMIN_DSN, OWNER_DSN
    from phase4.checks import ALL_CHECKS, QUESTION, ask, plant
    from phase4.hunt import fresh_client
    from phase4.setup_db import bootstrap

    psycopg.connect(ADMIN_DSN, connect_timeout=2).close()
    PG = True
except Exception:  # noqa: BLE001
    PG = False
    ALL_CHECKS = []

needs_pg = pytest.mark.skipif(not PG, reason="Postgres not available for Phase 4 tests")


# ---------------------------------------------------------------- output guard (no database)

def test_guard_strips_external_links_but_keeps_own_domain():
    text = "See ![x](https://evil.example/p.png?d=1) and https://intranet.hospital.example/policy"
    out, notes = guard_output(text, "hospital")
    assert "evil.example" not in out and "intranet.hospital.example/policy" in out
    assert notes == ["removed a link to evil.example"]


def test_guard_blocks_another_tenants_data():
    out, notes = guard_output("Summary: BANK-SECRET-0123456789 and HOSPITAL-SECRET-abc", "hospital")
    assert "SECRET" not in out and "withheld" in out and notes


def test_guard_allows_own_tenant_data_and_removes_credentials():
    out, _ = guard_output("Ref HOSPITAL-SECRET-abc. Key sk-mail-hospital-7f3a9c21", "hospital")
    assert "HOSPITAL-SECRET-abc" in out and "sk-mail" not in out


# ---------------------------------------------------------------- against the database

@pytest.fixture(scope="module", autouse=True)
def database():
    if PG:
        bootstrap()


@needs_pg
@pytest.mark.parametrize("check", ALL_CHECKS, ids=lambda c: c.__name__)
def test_secure_app_contains_a_hijacked_agent(check, tmp_path):
    with fresh_client("secure", tmp_path / "data") as client:
        f = check(client, OWNER_DSN)
    assert not f.leaked, f.evidence


@needs_pg
@pytest.mark.parametrize("check", ALL_CHECKS, ids=lambda c: c.__name__)
def test_leaky_app_is_exploited(check, tmp_path):
    with fresh_client("leaky", tmp_path / "data") as client:
        f = check(client, OWNER_DSN)
    assert f.leaked, f"check didn't detect the planted problem: {f.evidence}"


@needs_pg
def test_the_planted_document_really_hijacks_the_agent(tmp_path):
    """Guards against a false 'pass': the secure app must be safe even though the agent obeyed."""
    with fresh_client("secure", tmp_path / "data") as c:
        plant(c, "get_document 2")
        calls = ask(c).json()["tool_calls"]
    assert {"tool": "get_document", "args": {"id": 2}, "result": "No document with that id."} in calls


@needs_pg
def test_internal_email_needs_human_approval(tmp_path):
    with fresh_client("secure", tmp_path / "data") as c:
        plant(c, "send_email hank@hospital.example Handover summary")  # allowed domain
        ask(c)
        [draft] = c.get("/outbox", headers=auth("hospital-alice")).json()
        assert draft["status"] == "pending_approval" and draft["recipient"] == "hank@hospital.example"

        assert c.post(f"/outbox/{draft['id']}/approve", headers=auth("bank-bob")).status_code == 404  # other tenant
        ok = c.post(f"/outbox/{draft['id']}/approve", headers=auth("hospital-hank")).json()
        assert ok["status"] == "sent"
        assert c.post(f"/outbox/{draft['id']}/approve", headers=auth("hospital-hank")).status_code == 404  # only once


@needs_pg
def test_agent_answers_normally_without_injection(tmp_path):
    with fresh_client("secure", tmp_path / "data") as c:
        r = c.post("/agent", json={"question": QUESTION}, headers=auth("hospital-alice")).json()
    assert "HOSPITAL-SECRET-" in r["answer"] and not r["security_notes"]
    assert [t["tool"] for t in r["tool_calls"]] == ["search_documents"]
