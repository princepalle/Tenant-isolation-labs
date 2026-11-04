"""Isolation tests.

- The secure app must survive every attack (this is your regression suite).
- The vulnerable app must FAIL every attack, which proves each attack actually detects its leak.
- Both apps must still work for legitimate use, so "secure" can't just mean "broken".
"""
import pytest
from fastapi.testclient import TestClient

import secure_app
import vulnerable_app
from attacks import ALL_ATTACKS, ATTACKER_TOKEN, auth
from seed import seed


@pytest.fixture
def make_client(tmp_path):
    seed(tmp_path / "lab.db", tmp_path / "data")

    def _make(module):
        return TestClient(module.create_app(tmp_path / "lab.db", tmp_path / "data"))

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
