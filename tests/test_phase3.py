"""Phase 3 tests: rate limits, quotas, metering and billing. Skipped if Postgres isn't reachable."""
import psycopg
import pytest

from attacks import auth
from phase3.metering import RateLimiter, cost_usd

try:
    from phase2.db import ADMIN_DSN, APP_DSN, OWNER_DSN
    from phase3.checks import ALL_CHECKS
    from phase3.hunt import fresh_client
    from phase3.setup_db import bootstrap

    psycopg.connect(ADMIN_DSN, connect_timeout=2).close()
    PG = True
except Exception:  # noqa: BLE001
    PG = False
    ALL_CHECKS = []

needs_pg = pytest.mark.skipif(not PG, reason="Postgres not available for Phase 3 tests")


# ---------------------------------------------------------------- pure unit tests (no database)

def test_rate_limiter_refills_over_time():
    now = [0.0]
    rl = RateLimiter(clock=lambda: now[0])
    assert all(rl.allow("t", 5)[0] for _ in range(5))   # burst up to the limit
    allowed, wait = rl.allow("t", 5)
    assert not allowed and wait == pytest.approx(12.0)  # 5/min = one token every 12 s
    now[0] += 12
    assert rl.allow("t", 5)[0]
    assert rl.allow("other-tenant", 5)[0]                # separate buckets


def test_cost_is_per_million_tokens():
    assert cost_usd("claude-opus-5-5", 1_000_000, 0) == pytest.approx(4.00)
    assert cost_usd("claude-opus-5-5", 0, 1_000_000) == pytest.approx(20.00)
    assert cost_usd("some-new-model", 1_000_000, 0) == pytest.approx(4.00)  # unknown -> priced high, never free


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
def test_usage_admin_and_retry_after(tmp_path):
    with fresh_client("secure", tmp_path / "data") as c:
        for i in range(6):  # free plan: 5/min, so the 6th is refused
            r = c.post("/ask", json={"question": f"billing policy {i}"}, headers=auth("lawfirm-lena"))
        assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1

        u = c.get("/usage", headers=auth("lawfirm-leo")).json()  # a colleague sees the tenant's usage
        assert u["plan"] == "free" and u["by_user"][0]["calls"] == 5
        assert u["tokens_used"] + u["tokens_remaining"] == u["monthly_token_quota"]

        assert c.get("/admin/usage", headers=auth("hospital-alice", **{"X-Admin": "true"})).status_code == 403
        admin = c.get("/admin/usage", headers={"Authorization": "Bearer platform-admin-dev"}).json()
        assert {row["tenant_id"] for row in admin} == {"hospital", "bank", "lawfirm"}


@needs_pg
def test_usage_ledger_is_append_only(tmp_path):
    with fresh_client("secure", tmp_path / "data") as c:
        c.post("/ask", json={"question": "staff policy"}, headers=auth("hospital-alice"))
    with psycopg.connect(APP_DSN) as conn:
        conn.execute("SELECT set_config('app.tenant_id', 'hospital', true)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM usage_events")
