"""Set up the Phase 4 database: Phase 3 plus the email outbox.

  python -m phase4.setup_db
"""
from pathlib import Path

import psycopg

from common import DEFAULT_DATA
from phase2.db import OWNER_DSN
from phase3 import setup_db as phase3_setup

SCHEMA = Path(__file__).with_name("schema.sql")

# Fake per-tenant secrets for the email integration. Real ones live in a secrets manager.
INTEGRATION_KEYS = {
    "hospital": "sk-mail-hospital-7f3a9c21",
    "bank": "sk-mail-bank-0be1d44e",
    "lawfirm": "sk-mail-lawfirm-93c0aa5f",
}
# Each tenant's own email domain. The secure app only emails these.
TENANT_DOMAINS = {"hospital": "hospital.example", "bank": "bank.example", "lawfirm": "lawfirm.example"}

bootstrap = phase3_setup.bootstrap


def reset_and_seed(owner_dsn: str = OWNER_DSN, data_dir=DEFAULT_DATA) -> None:
    phase3_setup.reset_and_seed(owner_dsn, data_dir)
    with psycopg.connect(owner_dsn) as conn:
        conn.execute(SCHEMA.read_text())


if __name__ == "__main__":
    bootstrap()
    reset_and_seed()
    print("Phase 4 database ready: Phase 3 + email outbox.")
