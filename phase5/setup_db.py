"""Set up the Phase 5 database: Phase 4 plus audit tables and the auditor role.

  python -m phase5.setup_db
"""
from pathlib import Path

import psycopg

from common import DEFAULT_DATA
from phase2.db import ADMIN_DSN, DB_NAME, HOST, OWNER_DSN, PORT
from phase4 import setup_db as phase4_setup

SCHEMA = Path(__file__).with_name("schema.sql")
AUDITOR_DSN = f"postgresql://auditor:auditor_pw@{HOST}:{PORT}/{DB_NAME}"


def bootstrap(admin_dsn: str = ADMIN_DSN) -> None:
    phase4_setup.bootstrap(admin_dsn)
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute("""
            DO $$ BEGIN
              IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'auditor') THEN
                CREATE ROLE auditor LOGIN PASSWORD 'auditor_pw' NOBYPASSRLS;
              END IF;
            END $$;
        """)


def reset_and_seed(owner_dsn: str = OWNER_DSN, data_dir=DEFAULT_DATA) -> None:
    phase4_setup.reset_and_seed(owner_dsn, data_dir)
    with psycopg.connect(owner_dsn) as conn:
        conn.execute(SCHEMA.read_text())


if __name__ == "__main__":
    bootstrap()
    reset_and_seed()
    print("Phase 5 database ready: Phase 4 + audit_events (hash-chained), activity_log (leaky), auditor role.")
