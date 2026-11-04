"""The LEAKY app. Seven tenant-isolation bugs are planted here on purpose.

Each one is marked `# LEAK n:` and matches a section in README.md.
Your exercise: fix them here, one at a time, and re-run `python leak_hunter.py vulnerable`
until it says 0 leaks. `secure_app.py` is the answer key; try not to peek.

Run it:  uvicorn vulnerable_app:app --port 8001 --reload
"""
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from common import DEFAULT_DATA, DEFAULT_DB, connect, require_user


class NewDocument(BaseModel):
    title: str
    doc_type: str
    body: str
    tenant_id: str | None = None  # LEAK 6: the client gets to pick the tenant


def create_app(db_path=DEFAULT_DB, data_dir=DEFAULT_DATA) -> FastAPI:
    app = FastAPI(title="Tenant Lab: VULNERABLE")
    search_cache: dict = {}

    def db():
        conn = connect(db_path)
        try:
            yield conn
        finally:
            conn.close()

    def current_user(authorization: str | None = Header(None), conn=Depends(db)):
        return require_user(conn, authorization)

    @app.get("/me")
    def me(user=Depends(current_user)):
        return user

    @app.get("/documents")
    def list_documents(
        x_tenant_id: str | None = Header(None),
        user=Depends(current_user),
        conn=Depends(db),
    ):
        # LEAK 2: trusts a tenant ID sent by the client instead of the one from the token.
        tenant = x_tenant_id or user["tenant_id"]
        rows = conn.execute(
            "SELECT id, tenant_id, doc_type, title, created FROM documents WHERE tenant_id = ?",
            (tenant,),
        ).fetchall()
        return [dict(r) for r in rows]

    @app.get("/documents/{doc_id}")
    def get_document(doc_id: int, user=Depends(current_user), conn=Depends(db)):
        # LEAK 1 (IDOR): looks the row up by ID only, never checks which tenant owns it.
        row = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Not found")
        return dict(row)

    @app.post("/documents", status_code=201)
    def create_document(doc: NewDocument, user=Depends(current_user), conn=Depends(db)):
        tenant = doc.tenant_id or user["tenant_id"]  # LEAK 6 (mass assignment)
        cur = conn.execute(
            "INSERT INTO documents (tenant_id, doc_type, title, created, body)"
            " VALUES (?, ?, ?, date('now'), ?)",
            (tenant, doc.doc_type, doc.title, doc.body),
        )
        conn.commit()
        return {"id": cur.lastrowid, "tenant_id": tenant}

    @app.get("/search")
    def search(q: str, user=Depends(current_user), conn=Depends(db)):
        # LEAK 4: the cache key is only the query text, so tenants share cached answers.
        if q in search_cache:
            return search_cache[q]
        # LEAK 3 (SQL injection): user input is pasted into the SQL string,
        # so a crafted query can delete the tenant filter.
        sql = (
            "SELECT id, tenant_id, title, body FROM documents "
            f"WHERE tenant_id = '{user['tenant_id']}' AND body LIKE '%{q}%'"
        )
        rows = conn.execute(sql).fetchall()
        result = {"query": q, "results": [dict(r) for r in rows]}
        search_cache[q] = result
        return result

    @app.get("/files", response_class=PlainTextResponse)
    def read_file(name: str, user=Depends(current_user)):
        # LEAK 5 (path traversal): "../bank/doc_0.txt" walks out of the tenant's folder.
        path = Path(data_dir) / user["tenant_id"] / name
        if not path.is_file():
            raise HTTPException(404, "Not found")
        return path.read_text()

    @app.get("/stats")
    def stats(user=Depends(current_user), conn=Depends(db)):
        # LEAK 7: a "harmless" dashboard aggregate that forgot the tenant filter.
        # Counts and names are data too.
        rows = conn.execute(
            "SELECT tenant_id, doc_type, COUNT(*) AS n FROM documents GROUP BY tenant_id, doc_type"
        ).fetchall()
        return [dict(r) for r in rows]

    return app


app = create_app()
