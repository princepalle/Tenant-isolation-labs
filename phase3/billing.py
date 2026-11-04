"""Month-to-date invoice for every tenant, read through the least-privilege billing role.

  python -m phase3.billing                 # report on whatever is in the database
  python -m phase3.billing --simulate 40   # reset, send 40 questions per user, then report

The simulation runs the SECURE app with the offline model, so it's free. Watch the free
tenant (lawfirm) get rate-limited while the others keep going.
"""
import argparse
import random

import psycopg
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

import ai
from attacks import auth
from common import USERS
from phase2.db import make_pool
from phase3 import secure_app
from phase3.setup_db import BILLING_DSN, reset_and_seed

QUESTIONS = ["What is the policy?", "Summarize the latest note.", "What are the fees?",
             "Who approved this?", "What must be escalated?", "What are the follow-up steps?"]


def simulate(per_user: int) -> dict[str, int]:
    reset_and_seed()
    blocked: dict[str, int] = {}
    rng = random.Random(7)
    with make_pool() as pool, make_pool(BILLING_DSN, size=2) as billing, make_pool(size=3) as side:
        app = secure_app.create_app(pool=pool, billing_pool=billing, llm=ai.OfflineLLM(), side_pool=side)
        with TestClient(app, raise_server_exceptions=False) as client:
            for i in range(per_user):
                for token, (_, tenant) in USERS.items():
                    q = f"{rng.choice(QUESTIONS)} (#{i})"  # unique, so the answer cache doesn't hide calls
                    if client.post("/ask", json={"question": q}, headers=auth(token)).status_code == 429:
                        blocked[tenant] = blocked.get(tenant, 0) + 1
    return blocked


def report(blocked: dict[str, int] | None = None) -> None:
    with psycopg.connect(BILLING_DSN, row_factory=dict_row) as conn:
        rows = conn.execute(
            "SELECT t.id AS tenant, t.plan, p.monthly_token_quota AS quota,"
            " COUNT(u.id) AS calls,"
            " COALESCE(SUM(u.input_tokens), 0) AS input_tokens,"
            " COALESCE(SUM(u.output_tokens), 0) AS output_tokens,"
            " COALESCE(SUM(u.cost_usd), 0)::float AS cost"
            " FROM tenants t JOIN plans p ON p.name = t.plan"
            " LEFT JOIN usage_events u ON u.tenant_id = t.id AND u.created >= date_trunc('month', now())"
            " GROUP BY t.id, t.plan, p.monthly_token_quota ORDER BY cost DESC"
        ).fetchall()

    print(f"\n{'tenant':<10}{'plan':<12}{'calls':>6}{'in tok':>9}{'out tok':>9}{'quota used':>12}{'cost USD':>11}"
          + ("{:>9}".format("blocked") if blocked is not None else ""))
    for r in rows:
        used = (r["input_tokens"] + r["output_tokens"]) / r["quota"] * 100
        line = (f"{r['tenant']:<10}{r['plan']:<12}{r['calls']:>6}{r['input_tokens']:>9}{r['output_tokens']:>9}"
                f"{used:>11.1f}%{r['cost']:>11.4f}")
        if blocked is not None:
            line += f"{blocked.get(r['tenant'], 0):>9}"
        print(line)
    print("\nRead through billing_reader: it can see usage for every tenant, but not one document.")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--simulate", type=int, metavar="N", help="reset, then send N questions per user")
    args = p.parse_args()
    report(simulate(args.simulate) if args.simulate else None)
