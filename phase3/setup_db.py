"""Set up the Phase 3 database: everything from Phase 2, plus plans, usage and billing.

  python -m phase3.setup_db
"""
from pathlib import Path

import psycopg

from common import DEFAULT_DATA
from phase2 import setup_db as phase2_setup
from phase2.db import ADMIN_DSN, HOST, OWNER_DSN, PORT, DB_NAME

SCHEMA = Path(__file__).with_name("schema.sql")
BILLING_DSN = f"postgresql://billing_reader:billing_pw@{HOST}:{PORT}/{DB_NAME}"


def bootstrap(admin_dsn: str = ADMIN_DSN) -> None:
    phase2_setup.bootstrap(admin_dsn)
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute("""
            DO $$ BEGIN
              IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'billing_reader') THEN
                CREATE ROLE billing_reader LOGIN PASSWORD 'billing_pw' NOBYPASSRLS;
              END IF;
            END $$;
        """)


def reset_and_seed(owner_dsn: str = OWNER_DSN, data_dir=DEFAULT_DATA) -> None:
    phase2_setup.reset_and_seed(owner_dsn, data_dir)
    with psycopg.connect(owner_dsn) as conn:
        conn.execute(SCHEMA.read_text())


if __name__ == "__main__":
    bootstrap()
    reset_and_seed()
    print("Phase 3 database ready: plans (hospital=pro, bank=enterprise, lawfirm=free), usage ledger, billing role.")
