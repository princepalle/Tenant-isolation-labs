"""Run the Phase 7 checks against both apps, each in a fresh environment.

  python -m phase7.hunt            # both
  python -m phase7.hunt leaky
  python -m phase7.hunt secure
"""
import argparse
import os
import secrets
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import ModuleType

from fastapi.testclient import TestClient

from phase2.db import APP_DSN, OWNER_DSN, make_pool
from phase4.agent import GullibleAgent
from phase6.targets import NoLimits
from phase7 import leaky_app, secure_app
from phase7.checks import ALL_CHECKS
from phase7.idp import AUDIENCE, ISSUER, IdentityProvider
from phase5.setup_db import AUDITOR_DSN
from phase7.settings import DEV_OPS_DSN, Settings
from phase7.setup_db import reset_and_seed

APPS = {"leaky": leaky_app, "secure": secure_app}
os.environ.setdefault("LAB_LOG_LEVEL", "CRITICAL")


@lru_cache(maxsize=1)
def shared_idp() -> IdentityProvider:
    return IdentityProvider()  # RSA key generation is slow-ish; one IdP per process


@dataclass
class Env:
    module: ModuleType
    client: TestClient
    idp: IdentityProvider
    admin: dict
    owner_dsn: str
    data_dir: Path
    pool: object
    side_pool: object
    ops_pool: object
    agent: object


@contextmanager
def fresh_env(name: str, data_dir: Path | None = None):
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = Path(data_dir or Path(tmp) / "data")
        reset_and_seed(data_dir=data_dir)
        idp = shared_idp()
        admin_token = secrets.token_urlsafe(32)
        settings = Settings(env="test", issuer=ISSUER, audience=AUDIENCE, jwks=idp.jwks(),
                            admin_token=admin_token, app_dsn=APP_DSN, ops_dsn=DEV_OPS_DSN,
                            auditor_dsn=AUDITOR_DSN)
        ops_dsn = DEV_OPS_DSN if name == "secure" else OWNER_DSN
        with make_pool() as pool, make_pool(size=3) as side, make_pool(ops_dsn, size=1) as ops:
            agent = GullibleAgent()
            app = APPS[name].create_app(settings=settings, agent=agent, limiter=NoLimits(),
                                        pool=pool, side_pool=side, ops_pool=ops, data_dir=data_dir)
            admin = {"Authorization": f"Bearer {admin_token if name == 'secure' else leaky_app.ADMIN_TOKEN}"}
            with TestClient(app, raise_server_exceptions=False) as client:
                yield Env(APPS[name], client, idp, admin, OWNER_DSN, data_dir, pool, side, ops, agent)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("app", nargs="?", choices=[*APPS, "both"], default="both")
    args = p.parse_args()

    failures = 0
    for name in APPS if args.app == "both" else [args.app]:
        print(f"\n=== phase7/{name}_app.py ===")
        app_failures = 0
        for check in ALL_CHECKS:
            with fresh_env(name) as env:
                f = check(env)
            app_failures += f.leaked
            print(f"  [{'FAIL' if f.leaked else ' ok '}] {f.leak}. {f.name:<38} {f.evidence}")
        print(f"  -> {app_failures} of {len(ALL_CHECKS)} checks failed")
        failures += app_failures
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
