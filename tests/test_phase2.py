"""Phase 2 tests: Postgres + RLS. Skipped if the database isn't reachable.

Start it with `docker compose up -d` and `python -m phase2.setup_db` (see README).
"""
import psycopg
import pytest
from fastapi.testclient import TestClient

import ai
from attacks import ATTACKER_TOKEN, PHASE2_ATTACKS, auth

try:
    from phase2 import leaky_app, rls_demo, secure_app
    from phase2.db import ADMIN_DSN, make_pool
    from phase2.setup_db import bootstrap, reset_and_seed

    psycopg.connect(ADMIN_DSN, connect_timeout=2).close()
except Exception as e:  # noqa: BLE001
    pytest.skip(f"Postgres not available for Phase 2 tests: {e}", allow_module_level=True)

# What RLS alone catches when the app code is leaky. If you change the leaky app or the
# schema, this set tells you whether the database layer got stronger or weaker.
LEAKS_RLS_CANNOT_STOP = {2, 4, 5, 10, 11}


@pytest.fixture(scope="module", autouse=True)
def database():
    bootstrap()


@pytest.fixture
def client_for(tmp_path):
    reset_and_seed(data_dir=tmp_path / "data")
    pools = []

    def _make(module):
        pool = make_pool()
        pools.append(pool)
        app = module.create_app(pool=pool, data_dir=tmp_path / "data", llm=ai.OfflineLLM())
        return TestClient(app, raise_server_exceptions=False)

    yield _make
    for p in pools:
        p.close()


@pytest.mark.parametrize("attack", PHASE2_ATTACKS, ids=lambda a: a.__name__)
def test_secure_app_on_rls_does_not_leak(client_for, attack):
    finding = attack(client_for(secure_app))
    assert not finding.leaked, finding.evidence


@pytest.mark.parametrize("attack", PHASE2_ATTACKS, ids=lambda a: a.__name__)
def test_what_rls_alone_catches(client_for, attack):
    finding = attack(client_for(leaky_app))
    expected = finding.leak in LEAKS_RLS_CANNOT_STOP
    assert finding.leaked == expected, (
        f"leak {finding.leak}: expected {'LEAK' if expected else 'safe'}, got {finding.evidence}"
    )


def test_secure_app_still_works(client_for):
    c = client_for(secure_app)
    h = auth(ATTACKER_TOKEN)
    docs = c.get("/documents", headers=h).json()
    assert len(docs) == 20 and {d["tenant_id"] for d in docs} == {"hospital"}
    assert "HOSPITAL-SECRET-" in c.get(f"/documents/{docs[0]['id']}", headers=h).text

    created = c.post("/documents", json={"title": "t", "doc_type": "Note", "body": "b"}, headers=h)
    assert created.status_code == 201 and created.json()["tenant_id"] == "hospital"  # filled by DB default

    first = c.post("/ask", json={"question": "What is the staff policy for handovers?"}, headers=h).json()
    assert first["sources"] and all(s["tenant_id"] == "hospital" for s in first["sources"])
    c.post("/ask", json={"question": "Which ward?", "conversation_id": first["conversation_id"]}, headers=h)
    assert len(c.get(f"/conversations/{first['conversation_id']}", headers=h).json()["messages"]) == 4

    # A colleague in the same tenant can't read the chat.
    assert c.get(f"/conversations/{first['conversation_id']}", headers=auth("hospital-hank")).status_code == 404


def test_rls_lessons(client_for):
    assert rls_demo.lesson1_fails_closed() == 0
    assert rls_demo.lesson2_vector_search_is_scoped() == {"hospital"}
    assert rls_demo.lesson3_owner_bypasses_rls() == 60
    assert rls_demo.lesson4_pool_leak(local=False) == 20  # the leak
    assert rls_demo.lesson4_pool_leak(local=True) == 0    # the fix
    assert rls_demo.lesson5_with_check_blocks_cross_tenant_write().startswith("blocked")
    assert rls_demo.lesson6_users_table_is_locked().startswith("blocked")
