"""Run all 11 attacks against the Phase 2 apps, each on a freshly reset database.

  python -m phase2.hunt            # both apps
  python -m phase2.hunt leaky      # the leaky code: see which leaks RLS stops on its own
  python -m phase2.hunt secure     # defense in depth: should be 0
"""
import argparse
import sys

from fastapi.testclient import TestClient

import ai
import attacks
from leak_hunter import run
from phase2 import leaky_app, secure_app
from phase2.db import make_pool
from phase2.setup_db import reset_and_seed

APPS = {"leaky": leaky_app, "secure": secure_app}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("app", nargs="?", choices=[*APPS, "both"], default="both")
    args = p.parse_args()

    total = 0
    for name in APPS if args.app == "both" else [args.app]:
        reset_and_seed()
        with make_pool() as pool:
            app = APPS[name].create_app(pool=pool, llm=ai.get_llm())
            # raise_server_exceptions=False: a crash should show up as a 500, like in production
            with TestClient(app, raise_server_exceptions=False) as client:
                total += run(client, attacks.PHASE2_ATTACKS, f"phase2/{name}_app.py (Postgres + RLS)")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
