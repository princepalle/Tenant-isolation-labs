"""Phase 3 secure app: the Phase 2 assistant plus fair limits and honest billing.

- Rate limits per TENANT, sized by plan (noisy-neighbor protection)
- Monthly token quotas, checked before every model call
- Every model call metered through one gateway, in its own transaction
- /usage: a tenant's own usage. /admin/usage: all tenants, via a read-only billing role.

  uvicorn phase3.secure_app:app --port 8006
  curl -H "Authorization: Bearer platform-admin-dev" localhost:8006/admin/usage
"""
import hmac
import os

from fastapi import Depends, FastAPI, Header, HTTPException

import ai
from phase2.db import authenticate, install_rls_error_handler, make_pool, tenant_session
from phase2.secure_app import AskRequest, TenantRepo
from phase3.metering import LLMGateway, RateLimiter
from phase3.setup_db import BILLING_DSN


def create_app(pool=None, billing_pool=None, llm=None, limiter=None, admin_token=None) -> FastAPI:
    app = FastAPI(title="Phase 3: limits, quotas and billing (secure)")
    install_rls_error_handler(app)
    pool = pool or make_pool()
    billing_pool = billing_pool or make_pool(BILLING_DSN, size=2)
    gateway = LLMGateway(llm or ai.get_llm(), pool, limiter or RateLimiter())
    # Dev default only. In production this comes from a secrets manager.
    admin_token = admin_token or os.environ.get("LAB_ADMIN_TOKEN", "platform-admin-dev")
    answer_cache: dict = {}

    def current_user(authorization: str | None = Header(None), x_tenant_id: str | None = Header(None)):
        user = authenticate(pool, authorization)
        if x_tenant_id is not None and x_tenant_id != user["tenant_id"]:
            raise HTTPException(403, "Tenant header does not match your account")
        return user

    def repo(user=Depends(current_user)):
        with tenant_session(pool, user["tenant_id"], user["name"]) as conn:
            yield TenantRepo(conn, user["tenant_id"], user["name"])

    def require_admin(authorization: str | None = Header(None)):
        # A separate credential, not "a normal user plus a header". compare_digest takes
        # the same time whether the first character or the last one is wrong, so an
        # attacker can't guess the token one character at a time by timing responses.
        given = (authorization or "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(given.encode(), admin_token.encode()):
            raise HTTPException(403, "Admin credentials required")

    @app.get("/me")
    def me(user=Depends(current_user)):
        return user

    @app.post("/ask")
    def ask(req: AskRequest, r: TenantRepo = Depends(repo)):
        # The rate limit comes BEFORE the cache: it protects the service, not just the model bill.
        gateway.check_rate(r.conn, r.tenant_id)

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
        # Quota check + model call + metering, all in one place. Every path goes through here.
        answer = gateway.answer(r.conn, r.tenant_id, r.user_name, ai.system_prompt(r.tenant_id),
                                history, req.question, docs)
        r.add_turn(conv_id, req.question, answer)
        result = {
            "answer": answer,
            "sources": [{"id": d["id"], "title": d["title"], "tenant_id": d["tenant_id"]} for d in docs],
            "conversation_id": conv_id,
            "model": gateway.llm.name,
        }
        if req.conversation_id is None:
            answer_cache[key] = result
        return result

    @app.get("/usage")
    def usage(r: TenantRepo = Depends(repo)):
        """The tenant's own usage this month. RLS scopes every query here."""
        plan = gateway.plan(r.conn)
        used = gateway.tokens_used_this_month(r.conn)
        by_user = r.conn.execute(
            "SELECT user_name, COUNT(*) AS calls, SUM(input_tokens + output_tokens) AS tokens,"
            " SUM(cost_usd)::float AS cost_usd FROM usage_events"
            " WHERE created >= date_trunc('month', now()) GROUP BY user_name ORDER BY user_name"
        ).fetchall()
        return {
            "tenant_id": r.tenant_id,
            "plan": plan["name"],
            "requests_per_minute": plan["requests_per_minute"],
            "monthly_token_quota": plan["monthly_token_quota"],
            "tokens_used": used,
            "tokens_remaining": max(0, plan["monthly_token_quota"] - used),
            "cost_usd": round(sum(u["cost_usd"] for u in by_user), 6),
            "by_user": by_user,
        }

    @app.get("/admin/usage", dependencies=[Depends(require_admin)])
    def admin_usage():
        """Every tenant's totals, read through billing_reader: usage yes, documents never."""
        with billing_pool.connection() as conn:
            return conn.execute(
                "SELECT t.id AS tenant_id, t.plan, COUNT(u.id) AS calls,"
                " COALESCE(SUM(u.input_tokens + u.output_tokens), 0) AS tokens,"
                " COALESCE(SUM(u.cost_usd), 0)::float AS cost_usd"
                " FROM tenants t LEFT JOIN usage_events u"
                "   ON u.tenant_id = t.id AND u.created >= date_trunc('month', now())"
                " GROUP BY t.id, t.plan ORDER BY t.id"
            ).fetchall()

    return app


def __getattr__(name):
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
