"""The FIXED app: same API as vulnerable_app.py, with every leak closed.

The core idea: the tenant comes from the authenticated user, and ALL data
access goes through `TenantRepo`, which cannot run an unscoped query.
Route handlers never write SQL themselves, so they can't forget the filter.

Run it:  uvicorn secure_app:app --port 8002 --reload
"""
import sqlite3
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict

from common import DEFAULT_DATA, DEFAULT_DB, connect, require_user


class NewDocument(BaseModel):
    # FIX 6: there's no tenant_id field, and unknown fields are rejected (422).
    model_config = ConfigDict(extra="forbid")
    title: str
    doc_type: str
    body: str


class TenantRepo:
    """Every query in here is bound to one tenant. There's no method that isn't."""

    def __init__(self, conn: sqlite3.Connection, tenant_id: str):
        self.conn = conn
        self.tenant_id = tenant_id

    def list(self):
        return self.conn.execute(
            "SELECT id, tenant_id, doc_type, title, created FROM documents WHERE tenant_id = ?",
            (self.tenant_id,),
        ).fetchall()

    def get(self, doc_id: int):
        # FIX 1: the tenant is part of the lookup key, not checked afterwards.
        return self.conn.execute(
            "SELECT * FROM documents WHERE id = ? AND tenant_id = ?",
            (doc_id, self.tenant_id),
        ).fetchone()

    def search(self, q: str):
        # FIX 3: parameters, never string formatting. LIKE wildcards are escaped too.
        pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        return self.conn.execute(
            "SELECT id, tenant_id, title, body FROM documents"
            " WHERE tenant_id = ? AND body LIKE ? ESCAPE '\\'",
            (self.tenant_id, pattern),
        ).fetchall()

    def create(self, doc: NewDocument) -> int:
        cur = self.conn.execute(
            "INSERT INTO documents (tenant_id, doc_type, title, created, body)"
            " VALUES (?, ?, ?, date('now'), ?)",
            (self.tenant_id, doc.doc_type, doc.title, doc.body),
        )
        self.conn.commit()
        return cur.lastrowid

    def stats(self):
        # FIX 7: aggregates are scoped too.
        return self.conn.execute(
            "SELECT tenant_id, doc_type, COUNT(*) AS n FROM documents"
            " WHERE tenant_id = ? GROUP BY doc_type",
            (self.tenant_id,),
        ).fetchall()


def create_app(db_path=DEFAULT_DB, data_dir=DEFAULT_DATA) -> FastAPI:
    app = FastAPI(title="Tenant Lab: SECURE")
    search_cache: dict = {}

    def db():
        conn = connect(db_path)
        try:
            yield conn
        finally:
            conn.close()

    def current_user(
        authorization: str | None = Header(None),
        x_tenant_id: str | None = Header(None),
        conn=Depends(db),
    ):
        user = require_user(conn, authorization)
        # FIX 2: the token decides the tenant. A header that disagrees is refused, not obeyed.
        if x_tenant_id is not None and x_tenant_id != user["tenant_id"]:
            raise HTTPException(403, "Tenant header does not match your account")
        return user

    def repo(user=Depends(current_user), conn=Depends(db)) -> TenantRepo:
        return TenantRepo(conn, user["tenant_id"])

    @app.get("/me")
    def me(user=Depends(current_user)):
        return user

    @app.get("/documents")
    def list_documents(r: TenantRepo = Depends(repo)):
        return [dict(row) for row in r.list()]

    @app.get("/documents/{doc_id}")
    def get_document(doc_id: int, r: TenantRepo = Depends(repo)):
        row = r.get(doc_id)
        if row is None:
            # Same 404 for "doesn't exist" and "belongs to someone else". A 403 here
            # would confirm the ID exists in another tenant.
            raise HTTPException(404, "Not found")
        return dict(row)

    @app.post("/documents", status_code=201)
    def create_document(doc: NewDocument, r: TenantRepo = Depends(repo)):
        return {"id": r.create(doc), "tenant_id": r.tenant_id}

    @app.get("/search")
    def search(q: str, r: TenantRepo = Depends(repo)):
        key = (r.tenant_id, q)  # FIX 4: the tenant is part of every cache key
        if key not in search_cache:
            search_cache[key] = {"query": q, "results": [dict(row) for row in r.search(q)]}
        return search_cache[key]

    @app.get("/files", response_class=PlainTextResponse)
    def read_file(name: str, user=Depends(current_user)):
        # FIX 5: resolve the real path, then require that it's still inside the tenant's folder.
        base = (Path(data_dir) / user["tenant_id"]).resolve()
        path = (base / name).resolve()
        if not path.is_relative_to(base) or not path.is_file():
            raise HTTPException(404, "Not found")
        return path.read_text()

    @app.get("/stats")
    def stats(r: TenantRepo = Depends(repo)):
        return [dict(row) for row in r.stats()]

    return app


app = create_app()
