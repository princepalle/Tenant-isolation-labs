"""Run the 5 Phase 3 checks against both apps. Each check gets a fresh database and app.

  python -m phase3.hunt            # both
  python -m phase3.hunt leaky
  python -m phase3.hunt secure
"""
import argparse
import sys
from contextlib import contextmanager

from fastapi.testclient import TestClient

import ai
from phase2.db import OWNER_DSN, make_pool
from phase3 import leaky_app, secure_app
from phase3.checks import ALL_CHECKS
from phase3.setup_db import BILLING_DSN, reset_and_seed

APPS = {"leaky": leaky_app, "secure": secure_app}


@contextmanager
def fresh_client(name: str, data_dir=None):
    """A reset database, new pools, and a new app (so rate limit buckets start full)."""
    reset_and_seed(**({"data_dir": data_dir} if data_dir else {}))
    with make_pool() as pool, make_pool(BILLING_DSN, size=2) as billing, make_pool(OWNER_DSN, size=2) as owner:
        if name == "secure":
            app = secure_app.create_app(pool=pool, billing_pool=billing, llm=ai.OfflineLLM())
        else:
            app = leaky_app.create_app(pool=pool, owner_pool=owner, llm=ai.OfflineLLM())
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("app", nargs="?", choices=[*APPS, "both"], default="both")
    args = p.parse_args()

    failures = 0
    for name in APPS if args.app == "both" else [args.app]:
        print(f"\n=== phase3/{name}_app.py ===")
        app_failures = 0
        for check in ALL_CHECKS:
            with fresh_client(name) as client:
                f = check(client, OWNER_DSN)
            app_failures += f.leaked
            print(f"  [{'FAIL' if f.leaked else ' ok '}] {f.leak}. {f.name:<36} {f.evidence}")
        print(f"  -> {app_failures} of {len(ALL_CHECKS)} checks failed")
        failures += app_failures
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
