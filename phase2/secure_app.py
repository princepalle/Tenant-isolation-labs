"""Phase 2 secure app: defense in depth.

Layer 1 (app):      tenant from the token only, tenant-aware caches, safe file paths,
                    parameterized SQL, explicit tenant filters, strict request schemas.
Layer 2 (database): RLS policies, a non-owner role with NOBYPASSRLS, and a
                    transaction-scoped tenant setting.

Either layer alone stops some leaks. Together, a bug in one is caught by the other.

  uvicorn phase2.secure_app:app --port 8004
"""
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict

import ai
from common import DEFAULT_DATA
from phase2.db import authenticate, install_rls_error_handler, make_pool, tenant_session
from phase2.embeddings import embed, to_pg


class NewDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")  # no tenant_id; the database default fills it in
    title: str
    doc_type: str
    body: str


class AskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str
    conversation_id: str | None = None


class TenantRepo:
    """All data access. RLS already scopes every query; the explicit `tenant_id = %s`
    filters are the second lock. They also help Postgres use the tenant index."""

    def __init__(self, conn, tenant_id: str, user_name: str):
        self.conn, self.tenant_id, self.user_name = conn, tenant_id, user_name

    def list(self):
        return self.conn.execute(
            "SELECT id, tenant_id, doc_type, title, created FROM documents WHERE tenant_id = %s ORDER BY id",
            (self.tenant_id,),
        ).fetchall()

    def get(self, doc_id: int):
        return self.conn.execute(
            "SELECT id, tenant_id, doc_type, title, created, body FROM documents WHERE id = %s AND tenant_id = %s",
            (doc_id, self.tenant_id),
        ).fetchone()

    def create(self, doc: NewDocument):
        return self.conn.execute(
            "INSERT INTO documents (doc_type, title, body, embedding) VALUES (%s, %s, %s, %s::vector)"
            " RETURNING id, tenant_id",
            (doc.doc_type, doc.title, doc.body, to_pg(embed(doc.title + " " + doc.body))),
        ).fetchone()

    def search(self, q: str):
        pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        return self.conn.execute(
            "SELECT id, tenant_id, title, body FROM documents WHERE tenant_id = %s AND body ILIKE %s",
            (self.tenant_id, pattern),
        ).fetchall()

    def stats(self):
        return self.conn.execute(
            "SELECT tenant_id, doc_type, COUNT(*) AS n FROM documents WHERE tenant_id = %s"
            " GROUP BY tenant_id, doc_type",
            (self.tenant_id,),
        ).fetchall()

    def similar(self, question: str, k: int = ai.TOP_K):
        return self.conn.execute(
            "SELECT id, tenant_id, title, body FROM documents WHERE tenant_id = %s"
            " ORDER BY embedding <=> %s::vector LIMIT %s",
            (self.tenant_id, to_pg(embed(question)), k),
        ).fetchall()

    def owns_conversation(self, conv_id: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM conversations WHERE id = %s AND tenant_id = %s AND user_name = %s",
            (conv_id, self.tenant_id, self.user_name),
        ).fetchone() is not None

    def history(self, conv_id: str):
        return self.conn.execute(
            "SELECT role, content FROM messages WHERE conversation_id = %s ORDER BY id", (conv_id,)
        ).fetchall()

    def new_conversation(self) -> str:
        return self.conn.execute("INSERT INTO conversations DEFAULT VALUES RETURNING id").fetchone()["id"]

    def add_turn(self, conv_id: str, question: str, answer: str) -> None:
        self.conn.execute(
            "INSERT INTO messages (conversation_id, role, content) VALUES (%s, 'user', %s), (%s, 'assistant', %s)",
            (conv_id, question, conv_id, answer),
        )


def create_app(pool=None, data_dir=DEFAULT_DATA, llm=None) -> FastAPI:
    app = FastAPI(title="Phase 2: secure app on an RLS database")
    install_rls_error_handler(app)
    pool = pool or make_pool()
    llm = llm or ai.get_llm()
    search_cache: dict = {}
    answer_cache: dict = {}

    def current_user(authorization: str | None = Header(None), x_tenant_id: str | None = Header(None)):
        user = authenticate(pool, authorization)
        if x_tenant_id is not None and x_tenant_id != user["tenant_id"]:
            raise HTTPException(403, "Tenant header does not match your account")
        return user

    def repo(user=Depends(current_user)):
        with tenant_session(pool, user["tenant_id"], user["name"]) as conn:
            yield TenantRepo(conn, user["tenant_id"], user["name"])

    @app.get("/me")
    def me(user=Depends(current_user)):
        return user

    @app.get("/documents")
    def list_documents(r: TenantRepo = Depends(repo)):
        return r.list()

    @app.get("/documents/{doc_id}")
    def get_document(doc_id: int, r: TenantRepo = Depends(repo)):
        row = r.get(doc_id)
        if row is None:
            raise HTTPException(404, "Not found")
        return row

    @app.post("/documents", status_code=201)
    def create_document(doc: NewDocument, r: TenantRepo = Depends(repo)):
        return r.create(doc)

    @app.get("/search")
    def search(q: str, r: TenantRepo = Depends(repo)):
        key = (r.tenant_id, q)
        if key not in search_cache:
            search_cache[key] = {"query": q, "results": r.search(q)}
        return search_cache[key]

    @app.get("/files", response_class=PlainTextResponse)
    def read_file(name: str, user=Depends(current_user)):
        base = (Path(data_dir) / user["tenant_id"]).resolve()
        path = (base / name).resolve()
        if not path.is_relative_to(base) or not path.is_file():
            raise HTTPException(404, "Not found")
        return path.read_text()

    @app.get("/stats")
    def stats(r: TenantRepo = Depends(repo)):
        return r.stats()

    @app.post("/ask")
    def ask(req: AskRequest, r: TenantRepo = Depends(repo)):
        key = (r.tenant_id, req.question)
        if req.conversation_id is None and key in answer_cache:
            return answer_cache[key]
        if req.conversation_id:
            if not r.owns_conversation(req.conversation_id):
                raise HTTPException(404, "Not found")
            conv_id, history = req.conversation_id, r.history(req.conversation_id)
        else:
            conv_id, history = r.new_conversation(), []

        docs = r.similar(req.question)
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
    def get_conversation(conv_id: str, r: TenantRepo = Depends(repo)):
        if not r.owns_conversation(conv_id):
            raise HTTPException(404, "Not found")
        return {"id": conv_id, "messages": r.history(conv_id)}

    return app


def __getattr__(name):
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
