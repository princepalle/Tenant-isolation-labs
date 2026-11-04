"""RLS pitfalls, demonstrated against the real database. Run it and read along:

  python -m phase2.rls_demo

Each lesson is a function that returns what happened, so tests/test_phase2.py can
assert the same facts.
"""
import psycopg
from psycopg.rows import dict_row

from phase2.db import APP_DSN, OWNER_DSN, make_pool, tenant_session
from phase2.embeddings import embed, to_pg


def _count(conn) -> int:
    return conn.execute("SELECT count(*) AS n FROM documents").fetchone()["n"]


def lesson1_fails_closed() -> int:
    """No tenant set means zero rows, not every row."""
    with psycopg.connect(APP_DSN, row_factory=dict_row) as conn:
        return _count(conn)


def lesson2_vector_search_is_scoped() -> set[str]:
    """Similarity search with NO tenant filter in the SQL. Which tenants come back?"""
    with make_pool() as pool, tenant_session(pool, "hospital", "alice") as conn:
        rows = conn.execute(
            "SELECT tenant_id FROM documents ORDER BY embedding <=> %s::vector LIMIT 10",
            (to_pg(embed("loan credit score fraud settlement")),),  # bank and lawfirm words
        ).fetchall()
    return {r["tenant_id"] for r in rows}


def lesson3_owner_bypasses_rls() -> int:
    """lab_owner has BYPASSRLS (and superusers always bypass). If the app connected as
    the owner, every policy would silently do nothing."""
    with psycopg.connect(OWNER_DSN, row_factory=dict_row) as conn:
        conn.execute("SELECT set_config('app.tenant_id', 'hospital', true)")
        return _count(conn)


def lesson4_pool_leak(local: bool) -> int:
    """Request A sets the tenant, finishes and returns its connection to the pool.
    Request B (say, a background job that forgot to set a tenant) borrows the SAME
    connection. How many rows can B see?

    local=False is like a plain `SET app.tenant_id = ...`: it sticks to the connection.
    local=True is like `SET LOCAL`: it vanishes when A's transaction ends."""
    with make_pool(size=1) as pool:  # one connection, so B is guaranteed to reuse A's
        with pool.connection() as a:
            a.execute("SELECT set_config('app.tenant_id', 'bank', %s)", (local,))
        with pool.connection() as b:
            return _count(b)


def lesson5_with_check_blocks_cross_tenant_write() -> str:
    """Scoped to hospital, try to write a row owned by the bank."""
    with make_pool() as pool:
        try:
            with tenant_session(pool, "hospital", "alice") as conn:
                conn.execute(
                    "INSERT INTO documents (tenant_id, doc_type, title, body) VALUES ('bank', 'x', 'planted', 'x')"
                )
            return "inserted (BAD)"
        except psycopg.errors.InsufficientPrivilege as e:
            return f"blocked: {e.diag.message_primary}"


def lesson6_users_table_is_locked() -> str:
    """The app role can't read the users table at all, only call auth_user()."""
    with psycopg.connect(APP_DSN) as conn:
        try:
            conn.execute("SELECT * FROM users")
            return "readable (BAD)"
        except psycopg.errors.InsufficientPrivilege as e:
            return f"blocked: {e.diag.message_primary}"


if __name__ == "__main__":
    print("1. app_user, no tenant set, SELECT count(*) FROM documents ->", lesson1_fails_closed(), "rows (fails closed)")
    print("2. vector search as hospital, with no WHERE clause, returned tenants ->", lesson2_vector_search_is_scoped())
    print("3. same query as lab_owner (BYPASSRLS) ->", lesson3_owner_bypasses_rls(), "rows. Never let the app connect as the owner.")
    print("4. pooled connection reused by a request that forgot to set a tenant:")
    print("     after set_config(..., false) / plain SET ->", lesson4_pool_leak(local=False), "rows  <- LEAK")
    print("     after set_config(..., true)  / SET LOCAL ->", lesson4_pool_leak(local=True), "rows")
    print("5. hospital session inserting a bank row ->", lesson5_with_check_blocks_cross_tenant_write())
    print("6. app_user reading the users table ->", lesson6_users_table_is_locked())
