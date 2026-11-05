"""Set up the Phase 7 database: Phase 5 plus membership checks, offboarding and the ops role.

  python -m phase7.setup_db
"""
import os
from pathlib import Path

import psycopg
from psycopg import sql

from common import DEFAULT_DATA
from phase2.db import ADMIN_DSN, OWNER_DSN
from phase5 import setup_db as phase5_setup
from phase7.idp import SECRETS_DIR

SCHEMA = Path(__file__).with_name("schema.sql")


def bootstrap(admin_dsn: str = ADMIN_DSN) -> None:
    phase5_setup.bootstrap(admin_dsn)
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute("""
            DO $$ BEGIN
              IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'platform_ops') THEN
                CREATE ROLE platform_ops LOGIN PASSWORD 'ops_pw' NOBYPASSRLS;
              END IF;
            END $$;
        """)


def reset_and_seed(owner_dsn: str = OWNER_DSN, data_dir=DEFAULT_DATA) -> None:
    phase5_setup.reset_and_seed(owner_dsn, data_dir)
    with psycopg.connect(owner_dsn) as conn:
        conn.execute(SCHEMA.read_text())


ROLE_SECRETS = {"app_user": "app_db_password", "platform_ops": "ops_db_password", "auditor": "auditor_db_password"}


def apply_role_passwords(admin_dsn: str = ADMIN_DSN) -> list[str]:
    """If the secrets folder holds DB passwords (see `python -m phase7.idp init --db`), set them
    on the roles, replacing the dev passwords. Running it again with new files = rotation."""
    folder = Path(os.environ.get("LAB_SECRETS_DIR", SECRETS_DIR))
    changed = []
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        for role, name in ROLE_SECRETS.items():
            if (folder / name).is_file():
                password = (folder / name).read_text().strip()
                conn.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
                changed.append(role)
    return changed


if __name__ == "__main__":
    bootstrap()
    reset_and_seed(data_dir=os.environ.get("LAB_DATA_DIR", DEFAULT_DATA))
    # Only in production mode (the container sets LAB_ENV=production). Locally, Phases 2-6
    # still connect with the dev passwords, so changing them here would break those phases.
    changed = apply_role_passwords() if os.environ.get("LAB_ENV") == "production" else []
    if changed:
        print(f"Set passwords from secrets for: {', '.join(changed)}")
    print("Phase 7 database ready: Phase 5 + membership checks, offboard_tenant(), platform_ops role.")
