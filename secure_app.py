"""The FIXED app: same API as vulnerable_app.py, with every leak closed.

The core idea: the tenant comes from the authenticated user, and ALL data
access goes through `TenantRepo`, which cannot run an unscoped query.
Route handlers never write SQL themselves, so they can't forget the filter.

Run it:  uvicorn secure_app:app --port 8002 --reload
"""
from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict

import ai
from common import DEFAULT_DATA, DEFAULT_DB, connect, require_user


class NewDocument(BaseModel):
    # FIX 6: there's no tenant_id field, and unknown fields are rejected (422).
    model_config = ConfigDict(extra="forbid")
    title: str
    doc_type: str
    body: str


class AskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str
    conversation_id: str | None = None


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

    # --- AI assistant data ---

    def retrieval_corpus(self) -> list[dict]:
        # FIX 8: the tenant filter is applied BEFORE ranking. The model never sees,
        # and can't be tricked into revealing, a document from another tenant.
        return [dict(r) for r in self.conn.execute(
            "SELECT id, tenant_id, title, body FROM documents WHERE tenant_id = ?", (self.tenant_id,)
        )]

    def conversation_owned_by(self, conv_id: str, user_name: str) -> bool:
        # FIX 9: a chat belongs to a tenant AND a user. Colleagues can't read each other's chats.
        return self.conn.execute(
            "SELECT 1 FROM conversations WHERE id = ? AND tenant_id = ? AND user_name = ?",
            (conv_id, self.tenant_id, user_name),
        ).fetchone() is not None

    def history(self, conv_id: str) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY id", (conv_id,)
        )]

    def new_conversation(self, user_name: str) -> str:
        conv_id = str(uuid.uuid4())  # unguessable, but the ownership check is what protects it
        self.conn.execute(
            "INSERT INTO conversations (id, tenant_id, user_name) VALUES (?, ?, ?)",
            (conv_id, self.tenant_id, user_name),
        )
        return conv_id

    def add_turn(self, conv_id: str, question: str, answer: str) -> None:
        self.conn.executemany(
            "INSERT INTO messages (conversation_id, role, content) VALUES (?, ?, ?)",
            [(conv_id, "user", question), (conv_id, "assistant", answer)],
        )
        self.conn.commit()

    def stats(self):
        # FIX 7: aggregates are scoped too.
        return self.conn.execute(
            "SELECT tenant_id, doc_type, COUNT(*) AS n FROM documents"
            " WHERE tenant_id = ? GROUP BY doc_type",
            (self.tenant_id,),
        ).fetchall()


def create_app(db_path=DEFAULT_DB, data_dir=DEFAULT_DATA, llm=None) -> FastAPI:
    app = FastAPI(title="Tenant Lab: SECURE")
    search_cache: dict = {}
    answer_cache: dict = {}
    llm = llm or ai.get_llm()

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

    # ------------------------------------------------------------------ AI assistant

    @app.post("/ask")
    def ask(req: AskRequest, user=Depends(current_user), r: TenantRepo = Depends(repo)):
        key = (r.tenant_id, req.question)  # FIX 10: the tenant is part of the cache key
        if req.conversation_id is None and key in answer_cache:
            return answer_cache[key]

        if req.conversation_id:
            if not r.conversation_owned_by(req.conversation_id, user["name"]):
                raise HTTPException(404, "Not found")
            conv_id, history = req.conversation_id, r.history(req.conversation_id)
        else:
            conv_id, history = r.new_conversation(user["name"]), []

        docs = ai.rank(req.question, r.retrieval_corpus())
        answer = llm.answer(r.tenant_id, ai.system_prompt(r.tenant_id), history, req.question, docs)
        r.add_turn(conv_id, req.question, answer)

        result = {
            "answer": answer,
            "sources": [{"id": d["id"], "title": d["title"], "tenant_id": d["tenant_id"]} for d in docs],
            "conversation_id": conv_id,
            "model": llm.name,
        }
        if req.conversation_id is None:
            answer_cache[key] = result
        return result

    @app.get("/conversations/{conv_id}")
    def get_conversation(conv_id: str, user=Depends(current_user), r: TenantRepo = Depends(repo)):
        if not r.conversation_owned_by(conv_id, user["name"]):
            raise HTTPException(404, "Not found")
        return {"id": conv_id, "messages": r.history(conv_id)}

    return app


app = create_app()
