"""Phase 6 tests: the eval cases are sound, and the gate catches each kind of regression.
Target tests skip if Postgres isn't reachable (except leaky-phase1, which uses SQLite)."""
import psycopg
import pytest

from phase6.cases import isolation_cases, own_corpus, quality_cases
from phase6.evals import gate, run
from phase6.targets import TARGETS

try:
    from phase2.db import ADMIN_DSN
    from phase5.setup_db import bootstrap

    psycopg.connect(ADMIN_DSN, connect_timeout=2).close()
    PG = True
except Exception:  # noqa: BLE001
    PG = False

needs_pg = pytest.mark.skipif(not PG, reason="Postgres not available for Phase 6 target tests")
BASELINE = {"accuracy": 1.0, "by_tenant": {"hospital": 1.0, "bank": 1.0, "lawfirm": 1.0}}


def failed(rows):
    return {name for name, ok, _ in rows if not ok}


# ---------------------------------------------------------------- the cases themselves

def test_every_quality_case_has_its_answer_in_its_own_tenant():
    cases = quality_cases()
    assert len(cases) == 60 and len({c.question for c in cases}) == 60  # unique questions
    for c in cases:
        assert c.expected in own_corpus(c.tenant)


def test_isolation_cases_always_cross_tenants():
    cases = isolation_cases()
    assert len(cases) == 42
    assert all(not c.asker.startswith(c.tenant) for c in cases)


def test_gate_rules():
    good = {"quality": {"accuracy": 0.97, "by_tenant": {"hospital": 1.0, "bank": 0.95, "lawfirm": 0.95}},
            "isolation": {"leaks": 0, "total": 42}, "injection": {"damage": 0, "total": 4},
            "cost": {"avg_tokens_per_call": 500}}
    assert failed(gate(good, BASELINE)) == set()
    one_leak = {**good, "isolation": {"leaks": 1, "total": 42}}
    assert failed(gate(one_leak, BASELINE)) == {"isolation leaks"}           # one leak blocks a release
    one_tenant_worse = {**good, "quality": {"accuracy": 0.96, "by_tenant": {"hospital": 1.0, "bank": 1.0, "lawfirm": 0.85}}}
    assert failed(gate(one_tenant_worse, BASELINE)) == {"accuracy: lawfirm"}  # the average hid it
    pricey = {**good, "cost": {"avg_tokens_per_call": 2500}}
    assert failed(gate(pricey, BASELINE)) == {"cost"}


# ---------------------------------------------------------------- each target vs. the gate

@pytest.fixture(scope="module", autouse=True)
def database():
    if PG:
        bootstrap()


def evaluate(name):
    with TARGETS[name]() as target:
        return gate(run(target), BASELINE)


@needs_pg
def test_production_candidate_passes_the_gate():
    assert failed(evaluate("secure")) == set()


@needs_pg
def test_gate_catches_a_quality_regression_with_perfect_isolation():
    f = failed(evaluate("quality-regression"))
    assert "accuracy" in f and "isolation leaks" not in f and "injection damage" not in f


def test_gate_catches_isolation_leaks():
    assert "isolation leaks" in failed(evaluate("leaky-phase1"))


@needs_pg
def test_gate_catches_injection_damage():
    f = failed(evaluate("injection-regression"))
    assert "injection damage" in f and "isolation leaks" not in f
