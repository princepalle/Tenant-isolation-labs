"""What can be evaluated. Each target is a context manager that yields a ready-to-use Target.

  secure                The production candidate: Phase 5 secure app (agent with tools).
  quality-regression    The same app after a "harmless" change: a new embedding model that's
                        broken. Isolation is still perfect; answers get worse.
  leaky-phase1          Phase 1's vulnerable app. Shows the isolation suite catching leaks.
  injection-regression  Phase 4's leaky agent. Shows the injection suite catching damage.

Evals run on a dedicated, freshly seeded database. Every tenant is moved to the enterprise
plan and rate limiting is switched off: limits are tested in Phase 3, and here they would
only turn quality failures into 429s.
"""
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import psycopg
from fastapi.testclient import TestClient

import ai
import vulnerable_app
from phase2.db import OWNER_DSN, make_pool
from phase3.metering import RateLimiter
from phase4 import leaky_app as phase4_leaky
from phase4.agent import get_agent
from phase5 import secure_app as phase5_secure
from phase5.setup_db import reset_and_seed
from seed import seed


@dataclass
class Target:
    name: str
    client: TestClient
    kind: str                 # "agent" (POST /agent) or "ask" (POST /ask)
    owner_dsn: str | None     # for reading usage and running injection checks; None = not Postgres


class NoLimits(RateLimiter):
    def allow(self, key, per_minute):
        return True, 0.0


def _fresh_postgres():
    reset_and_seed()
    with psycopg.connect(OWNER_DSN) as conn:
        conn.execute("UPDATE tenants SET plan = 'enterprise'")


@contextmanager
def _phase5_secure(name):
    _fresh_postgres()
    with make_pool() as pool, make_pool(size=3) as side:
        app = phase5_secure.create_app(pool=pool, agent=get_agent(), limiter=NoLimits(), side_pool=side)
        with TestClient(app, raise_server_exceptions=False) as client:
            yield Target(name, client, "agent", OWNER_DSN)


@contextmanager
def secure():
    with _phase5_secure("secure") as t:
        yield t


@contextmanager
def quality_regression():
    # Every query embeds to the same vector, so "similarity" search returns arbitrary
    # documents. Still all from the right tenant (RLS doesn't care), so no leak. Just bad.
    broken = [1.0] + [0.0] * 255
    with mock.patch("phase2.secure_app.embed", lambda text: broken):
        with _phase5_secure("quality-regression") as t:
            yield t


@contextmanager
def leaky_phase1():
    with tempfile.TemporaryDirectory() as tmp:
        seed(Path(tmp) / "lab.db", Path(tmp) / "data")
        app = vulnerable_app.create_app(Path(tmp) / "lab.db", Path(tmp) / "data", llm=ai.get_llm())
        with TestClient(app, raise_server_exceptions=False) as client:
            yield Target("leaky-phase1", client, "ask", None)


@contextmanager
def injection_regression():
    _fresh_postgres()
    with make_pool() as pool, make_pool(OWNER_DSN, size=2) as service, make_pool(size=3) as side:
        app = phase4_leaky.create_app(pool=pool, service_pool=service, agent=get_agent(),
                                      limiter=NoLimits(), side_pool=side)
        with TestClient(app, raise_server_exceptions=False) as client:
            yield Target("injection-regression", client, "agent", OWNER_DSN)


TARGETS = {
    "secure": secure,
    "quality-regression": quality_regression,
    "leaky-phase1": leaky_phase1,
    "injection-regression": injection_regression,
}
