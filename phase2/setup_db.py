"""Create the Phase 2 database, roles, schema and data. Safe to re-run (it resets everything).

  python -m phase2.setup_db

Needs a Postgres superuser to bootstrap (create roles, database and the vector extension).
By default it uses postgres:postgres@localhost:5432, which matches docker-compose.yml.
Override with LAB_PG_ADMIN_DSN.
"""
from pathlib import Path

import psycopg

from common import DEFAULT_DATA, TENANTS, USERS
from phase2.db import ADMIN_DSN, DB_NAME, OWNER_DSN, token_hash
from phase2.embeddings import embed, to_pg
from seed import generate_docs, write_files

SCHEMA = Path(__file__).with_name("schema.sql")


def bootstrap(admin_dsn: str = ADMIN_DSN) -> None:
    """Superuser-only steps. In a real company, a platform team does this once."""
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute("""
            DO $$ BEGIN
              IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'lab_owner') THEN
                CREATE ROLE lab_owner LOGIN PASSWORD 'owner_pw' BYPASSRLS;
              END IF;
              IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
                CREATE ROLE app_user LOGIN PASSWORD 'app_pw' NOBYPASSRLS;
              END IF;
            END $$;
        """)
        if not conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,)).fetchone():
            conn.execute(f"CREATE DATABASE {DB_NAME}")
    with psycopg.connect(admin_dsn.rsplit("/", 1)[0] + f"/{DB_NAME}", autocommit=True) as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        conn.execute("GRANT USAGE, CREATE ON SCHEMA public TO lab_owner")


def reset_and_seed(owner_dsn: str = OWNER_DSN, data_dir=DEFAULT_DATA) -> None:
    """Rebuild the schema and load the same 60 documents as Phase 1 (as lab_owner)."""
    docs = list(generate_docs())
    write_files(docs, data_dir)
    with psycopg.connect(owner_dsn) as conn:
        conn.execute(SCHEMA.read_text())
        with conn.cursor() as cur:
            cur.executemany("INSERT INTO tenants VALUES (%s)", [(t,) for t in TENANTS])
            cur.executemany(
                "INSERT INTO users (token_hash, name, tenant_id) VALUES (%s, %s, %s)",
                [(token_hash(tok), name, tenant) for tok, (name, tenant) in USERS.items()],
            )
            cur.executemany(
                "INSERT INTO documents (tenant_id, doc_type, title, created, body, file_name, embedding)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s::vector)",
                [(d["tenant_id"], d["doc_type"], d["title"], d["created"], d["body"], d["file_name"],
                  to_pg(embed(d["title"] + " " + d["body"]))) for d in docs],
            )


if __name__ == "__main__":
    bootstrap()
    reset_and_seed()
    print(f"Database '{DB_NAME}' ready: {len(TENANTS)} tenants, 60 documents with embeddings, RLS on.")
