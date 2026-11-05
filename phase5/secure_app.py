"""Phase 5 secure app: you can see what happened, without the record itself leaking.

- Structured JSON logs: request_id + tenant_id + user on every line, metadata only, redacted
- X-Request-ID on every response, linking a support ticket to logs and audit rows
- A per-tenant, append-only, hash-chained audit trail, written in its own transaction
- Denied and blocked actions are audited too (rate limits, refused emails, guard blocks)
- /activity: a tenant's own trail. /admin/audit/verify and /admin/security-events: platform side.

  uvicorn phase5.secure_app:app --port 8010
  curl -H "Authorization: Bearer platform-admin-dev" localhost:8010/admin/audit/verify
"""
import hmac
import logging
import os
import time

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException
from psycopg.rows import dict_row

from common import TENANTS
from phase2.db import authenticate, install_rls_error_handler, make_pool, tenant_session
from phase2.secure_app import NewDocument, TenantRepo
from phase3.metering import LLMGateway, RateLimiter
from phase4.agent import get_agent
from phase4.secure_app import MAX_STEPS, AgentRequest, SecureTools, guard_output, system_prompt
from phase5 import audit
from phase5.obs import context, install_request_context, log, make_logger, set_tenant
from phase5.setup_db import AUDITOR_DSN


class AuditedTools(SecureTools):
    """The Phase 4 tools, plus a log line per call and an audit row for every email action.
    Logs say WHICH tool ran and how long it took, never what it read."""

    def __init__(self, repo, logger, audit_fn):
        super().__init__(repo)
        self.logger, self.audit = logger, audit_fn

    def call(self, name, args):
        start = time.perf_counter()
        out = super().call(name, args)
        log(self.logger, "tool.call", tool=name, result_chars=len(out),
            duration_ms=round((time.perf_counter() - start) * 1000, 1))
        if name == "send_email":
            domain = args["to"].rpartition("@")[2]  # the domain, not the full address
            if out.startswith("Refused"):
                self.audit("email.draft", outcome="denied", recipient_domain=domain)
                log(self.logger, "security.email_refused", logging.WARNING, recipient_domain=domain)
            else:
                self.audit("email.draft", target=f"email:{out.split('#')[1].split()[0]}", recipient_domain=domain)
        return out


def create_app(pool=None, agent=None, limiter=None, admin_token=None, side_pool=None,
               authenticate_fn=None, auditor_dsn=AUDITOR_DSN) -> FastAPI:
    """authenticate_fn(authorization_header) -> {'name', 'tenant_id', ...}. Defaults to the lab's
    simple bearer tokens; Phase 7 passes a JWT verifier instead."""
    app = FastAPI(title="Phase 5: logging and audit (secure)")
    install_rls_error_handler(app)
    pool = pool or make_pool()
    agent = agent or get_agent()
    # Metering/audit writes need their own transaction, so they borrow a SECOND connection.
    # From the same pool, that deadlocks under load: every request holds one connection
    # while waiting for another. A separate side pool can't be starved by requests.
    side_pool = side_pool or make_pool(size=3)
    gateway = LLMGateway(agent, side_pool, limiter or RateLimiter())
    admin_token = admin_token or os.environ.get("LAB_ADMIN_TOKEN", "platform-admin-dev")
    logger, handler = make_logger(f"phase5.secure.{id(app)}")
    app.state.log_lines = handler.lines
    install_request_context(app, logger)

    def current_user(authorization: str | None = Header(None), x_tenant_id: str | None = Header(None)):
        user = authenticate_fn(authorization) if authenticate_fn else authenticate(pool, authorization)
        set_tenant(user["tenant_id"], user["name"])  # from here on, every log line names the tenant
        if x_tenant_id is not None and x_tenant_id != user["tenant_id"]:
            audit.record(side_pool, user["tenant_id"], user["name"], context()["request_id"],
                         "tenant_header.mismatch", outcome="denied")
            log(logger, "security.tenant_header_mismatch", logging.WARNING)
            raise HTTPException(403, "Tenant header does not match your account")
        return user

    def repo(user=Depends(current_user)):
        with tenant_session(pool, user["tenant_id"], user["name"]) as conn:
            yield TenantRepo(conn, user["tenant_id"], user["name"])

    def auditor_for(r: TenantRepo):
        def _audit(action, target="", outcome="ok", **detail):
            audit.record(side_pool, r.tenant_id, r.user_name, context()["request_id"], action, target, outcome, **detail)
        return _audit

    def require_admin(authorization: str | None = Header(None)):
        given = (authorization or "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(given.encode(), admin_token.encode()):
            log(logger, "security.admin_denied", logging.WARNING)
            raise HTTPException(403, "Admin credentials required")

    @app.post("/documents", status_code=201)
    def upload(doc: NewDocument, r: TenantRepo = Depends(repo)):
        row = r.create(doc)
        log(logger, "document.uploaded", doc_id=row["id"], body_chars=len(doc.body))  # size, not content
        auditor_for(r)("document.upload", f"doc:{row['id']}")
        return row

    @app.post("/agent")
    def run_agent(req: AgentRequest, r: TenantRepo = Depends(repo)):
        audit_fn = auditor_for(r)
        try:
            gateway.check_rate(r.conn, r.tenant_id)
            gateway.check_quota(r.conn)
        except HTTPException as e:
            audit_fn("agent.run", outcome="denied", reason=e.detail)
            log(logger, "security.limit_hit", logging.WARNING, reason=e.detail)
            raise

        start = time.perf_counter()
        answer, usage, trace = agent.run(r.tenant_id, system_prompt(r.tenant_id), req.question,
                                         AuditedTools(r, logger, audit_fn), max_steps=MAX_STEPS)
        gateway.record(r.tenant_id, r.user_name, usage)
        answer, notes = guard_output(answer, r.tenant_id)
        tools = [t["tool"] for t in trace]
        log(logger, "agent.run", steps=len(trace), tools=tools, question_chars=len(req.question),
            input_tokens=usage["input_tokens"], output_tokens=usage["output_tokens"],
            guard_actions=len(notes), duration_ms=round((time.perf_counter() - start) * 1000, 1))
        if notes:
            audit_fn("agent.output_guard", outcome="blocked", actions=len(notes))
            log(logger, "security.output_guard", logging.WARNING, actions=len(notes))
        audit_fn("agent.run", tools=tools, input_tokens=usage["input_tokens"], output_tokens=usage["output_tokens"])
        return {"answer": answer, "security_notes": notes, "model": agent.name}

    @app.get("/outbox")
    def outbox(r: TenantRepo = Depends(repo)):
        return r.conn.execute("SELECT id, recipient, subject, status, approved_by FROM outbox ORDER BY id").fetchall()

    @app.post("/outbox/{email_id}/approve")
    def approve(email_id: int, r: TenantRepo = Depends(repo)):
        row = r.conn.execute(
            "UPDATE outbox SET status = 'sent', approved_by = %s WHERE id = %s AND status = 'pending_approval'"
            " RETURNING id, recipient, status", (r.user_name, email_id),
        ).fetchone()
        if row is None:
            auditor_for(r)("email.approve", f"email:{email_id}", "denied")  # own transaction: survives the 404
            log(logger, "security.approve_denied", logging.WARNING, email_id=email_id)
            raise HTTPException(404, "No pending email with that id")
        auditor_for(r)("email.approve", f"email:{email_id}")
        return row

    @app.get("/activity")
    def recent_activity(r: TenantRepo = Depends(repo)):
        """The tenant's own audit trail (RLS), newest first."""
        return r.conn.execute(
            "SELECT id, user_name, request_id, action, target, outcome, detail, created"
            " FROM audit_events ORDER BY id DESC LIMIT 50"
        ).fetchall()

    @app.get("/admin/audit/verify", dependencies=[Depends(require_admin)])
    def verify():
        results = [audit.verify_chain(auditor_dsn, t) for t in TENANTS]
        for res in results:
            if not res["ok"]:
                log(logger, "security.audit_chain_broken", logging.ERROR, broken_tenant=res["tenant_id"],
                    first_bad_id=res.get("first_bad_id"))
        return results

    @app.get("/admin/security-events", dependencies=[Depends(require_admin)])
    def security_events():
        """Denied and blocked actions per tenant: the security team's dashboard query."""
        with psycopg.connect(auditor_dsn, row_factory=dict_row) as conn:
            return conn.execute(
                "SELECT tenant_id, action, outcome, COUNT(*) AS n, MAX(created) AS last_seen"
                " FROM audit_events WHERE outcome <> 'ok'"
                " GROUP BY tenant_id, action, outcome ORDER BY n DESC"
            ).fetchall()

    return app


def __getattr__(name):
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
