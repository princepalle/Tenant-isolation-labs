"""Isolation tests.

- The secure app must survive every attack (this is your regression suite).
- The vulnerable app must FAIL every attack, which proves each attack actually detects its leak.
- Both apps must still work for legitimate use, so "secure" can't just mean "broken".
"""
import pytest
from fastapi.testclient import TestClient

import ai
import secure_app
import vulnerable_app
from attacks import ALL_ATTACKS, ATTACKER_TOKEN, auth
from seed import seed


@pytest.fixture
def make_client(tmp_path):
    seed(tmp_path / "lab.db", tmp_path / "data")

    def _make(module):
        # Always the offline model in tests: free, fast and deterministic.
        return TestClient(module.create_app(tmp_path / "lab.db", tmp_path / "data", llm=ai.OfflineLLM()))

    return _make


@pytest.mark.parametrize("attack", ALL_ATTACKS, ids=lambda a: a.__name__)
def test_secure_app_does_not_leak(make_client, attack):
    finding = attack(make_client(secure_app))
    assert not finding.leaked, finding.evidence


@pytest.mark.parametrize("attack", ALL_ATTACKS, ids=lambda a: a.__name__)
def test_vulnerable_app_leaks(make_client, attack):
    finding = attack(make_client(vulnerable_app))
    assert finding.leaked, f"attack did not detect the planted leak: {finding.evidence}"


@pytest.mark.parametrize("module", [secure_app, vulnerable_app], ids=["secure", "vulnerable"])
def test_legitimate_use_still_works(make_client, module):
    c = make_client(module)
    h = auth(ATTACKER_TOKEN)

    docs = c.get("/documents", headers=h).json()
    assert len(docs) == 20 and {d["tenant_id"] for d in docs} == {"hospital"}

    own = c.get(f"/documents/{docs[0]['id']}", headers=h)
    assert own.status_code == 200 and "HOSPITAL-SECRET-" in own.text

    hits = c.get("/search", params={"q": "policy"}, headers=h).json()["results"]
    assert hits and all(r["tenant_id"] == "hospital" for r in hits)

    assert "HOSPITAL-SECRET-" in c.get("/files", params={"name": "doc_0.txt"}, headers=h).text

    created = c.post("/documents", json={"title": "t", "doc_type": "Note", "body": "b"}, headers=h)
    assert created.status_code == 201 and created.json()["tenant_id"] == "hospital"

    assert c.get("/documents").status_code == 401

    # The AI assistant answers from the tenant's own documents and keeps a conversation going.
    first = c.post("/ask", json={"question": "What is the staff policy for handovers?"}, headers=h).json()
    assert first["sources"] and all(s["tenant_id"] == "hospital" for s in first["sources"])
    assert "HOSPITAL-SECRET-" in first["answer"]
    follow = c.post("/ask", json={"question": "And which ward?", "conversation_id": first["conversation_id"]}, headers=h)
    assert follow.status_code == 200
    convo = c.get(f"/conversations/{first['conversation_id']}", headers=h).json()
    assert len(convo["messages"]) == 4


def test_colleagues_cannot_read_each_others_chats(make_client):
    """Same tenant, different user: isolation inside a tenant matters too."""
    c = make_client(secure_app)
    conv = c.post("/ask", json={"question": "staff policy"}, headers=auth("hospital-alice")).json()["conversation_id"]
    assert c.get(f"/conversations/{conv}", headers=auth("hospital-hank")).status_code == 404
