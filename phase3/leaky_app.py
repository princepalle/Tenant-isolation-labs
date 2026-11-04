"""Phase 3 LEAKY app. Five limit and billing mistakes, each marked `# PROBLEM n:`.

These aren't all data leaks. Phase 3 is about fairness and money: one tenant hurting the
others, tenants dodging their limits, and your bill not matching what you charge.

  python -m phase3.hunt leaky
  uvicorn phase3.leaky_app:app --port 8005
"""
from fastapi import Depends, FastAPI, Header, HTTPException

import ai
from phase2.db import OWNER_DSN, authenticate, install_rls_error_handler, make_pool, tenant_session
from phase2.secure_app import AskRequest, TenantRepo
from phase3.metering import RateLimiter, cost_usd, too_many

GLOBAL_PER_MINUTE = 60     # "the whole platform can do 60 requests a minute"
PER_USER_PER_MINUTE = 20   # "each user gets 20 a minute"


def create_app(pool=None, owner_pool=None, llm=None, limiter=None) -> FastAPI:
    app = FastAPI(title="Phase 3: limits, quotas and billing (LEAKY)")
    install_rls_error_handler(app)
    pool = pool or make_pool()
    # PROBLEM 16: the admin page connects as the table OWNER "because RLS got in the way".
    # Owner = BYPASSRLS = every tenant, every table.
    owner_pool = owner_pool or make_pool(OWNER_DSN, size=2)
    llm = llm or ai.get_llm()
    limiter = limiter or RateLimiter()
    answer_cache: dict = {}

    def current_user(authorization: str | None = Header(None)):
        return authenticate(pool, authorization)

    def repo(user=Depends(current_user)):
        with tenant_session(pool, user["tenant_id"], user["name"]) as conn:
            yield TenantRepo(conn, user["tenant_id"], user["name"])

    @app.get("/me")
    def me(user=Depends(current_user)):
        return user

    @app.post("/ask")
    def ask(req: AskRequest, r: TenantRepo = Depends(repo)):
        # PROBLEM 12 (noisy neighbor): ONE bucket shared by every tenant. If the bank's batch
        # job sends 60 requests, the hospital gets "429 Too Many Requests" for a minute.
        allowed, wait = limiter.allow("global", GLOBAL_PER_MINUTE)
        if not allowed:
            raise too_many("Platform is busy", wait)
        # PROBLEM 13 (limit evasion): the limit is per USER and ignores the plan. A free
        # tenant with 2 users gets 40 requests a minute; with 10 users, 200.
        allowed, wait = limiter.allow(f"user:{r.tenant_id}:{r.user_name}", PER_USER_PER_MINUTE)
        if not allowed:
            raise too_many("Slow down", wait)

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
        # PROBLEM 14 (no quota): nothing checks the monthly token quota. A free tenant can
        # run up any bill, and you pay the model provider for all of it.
        answer, usage = llm.answer_with_usage(r.tenant_id, ai.system_prompt(r.tenant_id), history, req.question, docs)

        # PROBLEM 15 (unmetered path): usage is only recorded for NEW conversations.
        # Follow-up questions (often the longest prompts, since they carry the whole
        # history) are free. Classic: metering written in one code path, forgotten in another.
        if req.conversation_id is None:
            r.conn.execute(
                "INSERT INTO usage_events (model, input_tokens, output_tokens, cost_usd) VALUES (%s, %s, %s, %s)",
                (llm.name, usage["input_tokens"], usage["output_tokens"],
                 cost_usd(llm.name, usage["input_tokens"], usage["output_tokens"])),
            )
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

    @app.get("/usage")
    def usage(r: TenantRepo = Depends(repo)):
        rows = r.conn.execute(
            "SELECT user_name, COUNT(*) AS calls, SUM(input_tokens + output_tokens) AS tokens"
            " FROM usage_events GROUP BY user_name"
        ).fetchall()
        return {"tenant_id": r.tenant_id, "by_user": rows}

    @app.get("/admin/usage")
    def admin_usage(user=Depends(current_user), x_admin: str | None = Header(None)):
        # PROBLEM 16 (fake admin check): any logged-in user who sends `X-Admin: true` is an
        # admin. And see above: it reads through the owner connection.
        if x_admin != "true":
            raise HTTPException(403, "Admins only")
        with owner_pool.connection() as conn:
            return conn.execute(
                "SELECT t.id AS tenant_id, t.plan, COUNT(u.id) AS calls,"
                " COALESCE(SUM(u.input_tokens + u.output_tokens), 0) AS tokens"
                " FROM tenants t LEFT JOIN usage_events u ON u.tenant_id = t.id"
                " GROUP BY t.id, t.plan ORDER BY t.id"
            ).fetchall()

    return app


def __getattr__(name):
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
