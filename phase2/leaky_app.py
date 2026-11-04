"""Phase 1's leaky code, moved onto the Postgres + RLS database.

Every tenant filter has been REMOVED from the SQL here. The code trusts the database to
do the isolating. The question this app answers: which of the 10 leaks does RLS stop on
its own, and which still get through?

Run `python -m phase2.hunt leaky` to see. Each LEAK comment below says what to expect.

  uvicorn phase2.leaky_app:app --port 8003
"""
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

import ai
from common import DEFAULT_DATA
from phase2.db import authenticate, install_rls_error_handler, make_pool, tenant_session
from phase2.embeddings import embed, to_pg


class NewDocument(BaseModel):
    title: str
    doc_type: str
    body: str
    tenant_id: str | None = None


class AskRequest(BaseModel):
    question: str
    conversation_id: str | None = None


def create_app(pool=None, data_dir=DEFAULT_DATA, llm=None) -> FastAPI:
    app = FastAPI(title="Phase 2: leaky code on an RLS database")
    install_rls_error_handler(app)
    pool = pool or make_pool()
    llm = llm or ai.get_llm()
    search_cache: dict = {}
    answer_cache: dict = {}

    def current_user(authorization: str | None = Header(None)):
        return authenticate(pool, authorization)

    def db(user=Depends(current_user), x_tenant_id: str | None = Header(None)):
        # LEAK 2: STILL LEAKS. RLS enforces whatever tenant the session says, and here the
        # client gets to choose it. The database can't tell a forged tenant from a real one.
        with tenant_session(pool, x_tenant_id or user["tenant_id"], user["name"]) as conn:
            yield conn

    @app.get("/me")
    def me(user=Depends(current_user)):
        return user

    @app.get("/documents")
    def list_documents(conn=Depends(db)):
        return conn.execute("SELECT id, tenant_id, doc_type, title, created FROM documents ORDER BY id").fetchall()

    @app.get("/documents/{doc_id}")
    def get_document(doc_id: int, conn=Depends(db)):
        # LEAK 1: FIXED BY RLS. No ownership check in the code, but foreign rows are invisible.
        row = conn.execute(
            "SELECT id, tenant_id, doc_type, title, created, body FROM documents WHERE id = %s", (doc_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Not found")
        return row

    @app.post("/documents", status_code=201)
    def create_document(doc: NewDocument, user=Depends(current_user), conn=Depends(db)):
        # LEAK 6: FIXED BY RLS. The WITH CHECK policy rejects a row for another tenant (403).
        row = conn.execute(
            "INSERT INTO documents (tenant_id, doc_type, title, body, embedding)"
            " VALUES (%s, %s, %s, %s, %s::vector) RETURNING id, tenant_id",
            (doc.tenant_id or user["tenant_id"], doc.doc_type, doc.title, doc.body,
             to_pg(embed(doc.title + " " + doc.body))),
        ).fetchone()
        return row

    @app.get("/search")
    def search(q: str, conn=Depends(db)):
        # LEAK 4: STILL LEAKS. The cache lives in the app, above the database. RLS never sees it.
        if q in search_cache:
            return search_cache[q]
        # LEAK 3: HALF FIXED. A plain `OR 1=1` stays inside the tenant, because the policy is
        # applied on top of the WHERE clause. But see LEAK 11 just below.
        # LEAK 11: STILL LEAKS, and it's Phase 2 only. RLS trusts the `app.tenant_id` setting,
        # and injected SQL can call set_config() to change it mid-query. Injection beats RLS.
        rows = conn.execute(f"SELECT id, tenant_id, title, body FROM documents WHERE body ILIKE '%{q}%'").fetchall()
        search_cache[q] = {"query": q, "results": rows}
        return search_cache[q]

    @app.get("/files", response_class=PlainTextResponse)
    def read_file(name: str, user=Depends(current_user)):
        # LEAK 5: STILL LEAKS. Files on disk aren't in the database, so RLS can't protect them.
        path = Path(data_dir) / user["tenant_id"] / name
        if not path.is_file():
            raise HTTPException(404, "Not found")
        return path.read_text()

    @app.get("/stats")
    def stats(conn=Depends(db)):
        # LEAK 7: FIXED BY RLS. The GROUP BY only ever sees the tenant's own rows.
        return conn.execute(
            "SELECT tenant_id, doc_type, COUNT(*) AS n FROM documents GROUP BY tenant_id, doc_type"
        ).fetchall()

    @app.post("/ask")
    def ask(req: AskRequest, user=Depends(current_user), conn=Depends(db)):
        # LEAK 10: STILL LEAKS. Same story as leak 4: an app-level cache shared by everyone.
        if req.conversation_id is None and req.question in answer_cache:
            return answer_cache[req.question]

        # LEAK 9: FIXED BY RLS. No ownership check here, but the policies on
        # conversations/messages hide other users' chats, so `history` comes back empty
        # and the INSERT into someone else's conversation is rejected (403).
        if req.conversation_id:
            conv_id = req.conversation_id
            history = conn.execute(
                "SELECT role, content FROM messages WHERE conversation_id = %s ORDER BY id", (conv_id,)
            ).fetchall()
        else:
            conv_id = conn.execute(
                "INSERT INTO conversations (id) VALUES (nextval('conv_seq')::text) RETURNING id"
            ).fetchone()["id"]
            history = []

        # LEAK 8: FIXED BY RLS. Vector search over "all" documents, with no tenant filter.
        # The policy applies inside the similarity search, so only the tenant's rows rank.
        docs = conn.execute(
            "SELECT id, tenant_id, title, body FROM documents ORDER BY embedding <=> %s::vector LIMIT %s",
            (to_pg(embed(req.question)), ai.TOP_K),
        ).fetchall()
        answer = llm.answer(user["tenant_id"], ai.system_prompt(user["tenant_id"]), history, req.question, docs)
        conn.execute(
            "INSERT INTO messages (conversation_id, role, content) VALUES (%s, 'user', %s), (%s, 'assistant', %s)",
            (conv_id, req.question, conv_id, answer),
        )
        result = {
            "answer": answer,
            "sources": [{"id": d["id"], "title": d["title"], "tenant_id": d["tenant_id"]} for d in docs],
            "conversation_id": conv_id,
            "model": llm.name,
        }
        if req.conversation_id is None:
            answer_cache[req.question] = result
        return result

    @app.get("/conversations/{conv_id}")
    def get_conversation(conv_id: str, conn=Depends(db)):
        rows = conn.execute(
            "SELECT role, content FROM messages WHERE conversation_id = %s ORDER BY id", (conv_id,)
        ).fetchall()
        if not rows:
            raise HTTPException(404, "Not found")
        return {"id": conv_id, "messages": rows}

    return app


def __getattr__(name):
    # `uvicorn phase2.leaky_app:app` builds the app on first access, so merely importing
    # this module (tests, the hunter) doesn't open a database connection.
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
