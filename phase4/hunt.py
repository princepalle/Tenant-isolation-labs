"""Run the Phase 4 prompt-injection checks against both apps, each on a fresh database.

  python -m phase4.hunt            # both
  python -m phase4.hunt leaky
  python -m phase4.hunt secure

Always uses the gullible offline agent (the worst case). To watch real Claude handle the
same planted documents, run a server with LAB_LLM=claude and try it by hand.
"""
import argparse
import sys
from contextlib import contextmanager

from fastapi.testclient import TestClient

from phase2.db import OWNER_DSN, make_pool
from phase4 import leaky_app, secure_app
from phase4.agent import GullibleAgent
from phase4.checks import ALL_CHECKS
from phase4.setup_db import reset_and_seed

APPS = {"leaky": leaky_app, "secure": secure_app}


@contextmanager
def fresh_client(name: str, data_dir=None):
    reset_and_seed(**({"data_dir": data_dir} if data_dir else {}))
    with make_pool() as pool, make_pool(OWNER_DSN, size=2) as service:
        if name == "secure":
            app = secure_app.create_app(pool=pool, agent=GullibleAgent())
        else:
            app = leaky_app.create_app(pool=pool, service_pool=service, agent=GullibleAgent())
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("app", nargs="?", choices=[*APPS, "both"], default="both")
    args = p.parse_args()

    failures = 0
    for name in APPS if args.app == "both" else [args.app]:
        print(f"\n=== phase4/{name}_app.py (agent: gullible, obeys every planted instruction) ===")
        app_failures = 0
        for check in ALL_CHECKS:
            with fresh_client(name) as client:
                f = check(client, OWNER_DSN)
            app_failures += f.leaked
            print(f"  [{'FAIL' if f.leaked else ' ok '}] {f.leak}. {f.name:<40} {f.evidence}")
        print(f"  -> {app_failures} of {len(ALL_CHECKS)} checks failed")
        failures += app_failures
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
