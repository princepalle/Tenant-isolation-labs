"""Run every attack against an app and print which ones leak.

  python leak_hunter.py                 # both apps, each on a fresh throwaway copy of the data
  python leak_hunter.py vulnerable      # just the leaky app (use this while you fix it)
  python leak_hunter.py --url http://localhost:8001   # a running server (this writes to its DB)
"""
import argparse
import sys
import tempfile
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

import ai
import secure_app
import vulnerable_app
from attacks import ALL_ATTACKS
from seed import seed

APPS = {"vulnerable": vulnerable_app, "secure": secure_app}


def run(client, label: str) -> int:
    print(f"\n=== {label} ===")
    leaks = 0
    for attack in ALL_ATTACKS:
        f = attack(client)
        leaks += f.leaked
        status = "LEAK " if f.leaked else "safe "
        print(f"  [{status}] {f.leak}. {f.name:<32} {f.evidence}")
    print(f"  -> {leaks} of {len(ALL_ATTACKS)} attacks leaked data")
    return leaks


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("app", nargs="?", choices=[*APPS, "both"], default="both")
    p.add_argument("--url", help="attack a running server instead")
    args = p.parse_args()

    if args.url:
        with httpx.Client(base_url=args.url) as client:
            return 1 if run(client, args.url) else 0

    total = 0
    for name in APPS if args.app == "both" else [args.app]:
        with tempfile.TemporaryDirectory() as tmp:
            seed(Path(tmp) / "lab.db", Path(tmp) / "data")
            app = APPS[name].create_app(Path(tmp) / "lab.db", Path(tmp) / "data", llm=ai.get_llm())
            with TestClient(app) as client:
                total += run(client, f"{name}_app.py")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
