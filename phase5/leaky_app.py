"""Phase 5 LEAKY app: the Phase 4 secure agent, with typical first-attempt logging and auditing.

Phases 1-4 are fixed. The problems are all in how the app records what happened.
Each is marked `# PROBLEM n:`.

  python -m phase5.hunt leaky
  uvicorn phase5.leaky_app:app --port 8009
"""
import logging

from fastapi import Depends, FastAPI, Header, HTTPException

from phase2.db import authenticate, install_rls_error_handler, make_pool, tenant_session
from phase2.secure_app import NewDocument, TenantRepo
from phase3.metering import LLMGateway, RateLimiter
from phase4.agent import get_agent
from phase4.secure_app import MAX_STEPS, AgentRequest, SecureTools, guard_output, system_prompt
from phase5.obs import ListHandler


def create_app(pool=None, agent=None, limiter=None, side_pool=None) -> FastAPI:
    app = FastAPI(title="Phase 5: logging and audit (LEAKY)")
    install_rls_error_handler(app)
    pool = pool or make_pool()
    agent = agent or get_agent()
    # Metering/audit writes need their own transaction, so they borrow a SECOND connection.
    # From the same pool, that deadlocks under load: every request holds one connection
    # while waiting for another. A separate side pool can't be starved by requests.
    side_pool = side_pool or make_pool(size=3)
    gateway = LLMGateway(agent, side_pool, limiter or RateLimiter())

    # PROBLEM 22 (no context): plain-text lines with no request ID and no tenant field.
    # When the hospital reports "something weird happened at 14:02", you grep and hope.
    logger = logging.getLogger(f"phase5.leaky.{id(app)}")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.INFO)
    handler = ListHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(handler)
    app.state.log_lines = handler.lines

    def current_user(authorization: str | None = Header(None)):
        return authenticate(pool, authorization)

    def repo(user=Depends(current_user)):
        with tenant_session(pool, user["tenant_id"], user["name"]) as conn:
            yield TenantRepo(conn, user["tenant_id"], user["name"])

    def activity(r: TenantRepo, action, target="", outcome="ok", detail=""):
        # PROBLEM 25 (lost denials): written in the REQUEST's transaction. When the request
        # then fails (404, 403...), the rollback erases this row. Denied actions, the ones
        # security cares about most, never reach the log.
        r.conn.execute(
            "INSERT INTO activity_log (tenant_id, user_name, action, target, outcome, detail)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            (r.tenant_id, r.user_name, action, target, outcome, detail),
        )

    @app.post("/documents", status_code=201)
    def upload(doc: NewDocument, r: TenantRepo = Depends(repo)):
        row = r.create(doc)
        # PROBLEM 21 (content in logs): "temporary" debug logging of the whole document.
        logger.info(f"upload by {r.user_name}: title={doc.title!r} body={doc.body!r}")
        activity(r, "document.upload", f"doc:{row['id']}")
        return row

    @app.post("/agent")
    def run_agent(req: AgentRequest, r: TenantRepo = Depends(repo)):
        gateway.check_rate(r.conn, r.tenant_id)  # a 429 here is never recorded anywhere
        gateway.check_quota(r.conn)
        answer, usage, trace = agent.run(r.tenant_id, system_prompt(r.tenant_id), req.question,
                                         SecureTools(r), max_steps=MAX_STEPS)
        gateway.record(r.tenant_id, r.user_name, usage)
        answer, notes = guard_output(answer, r.tenant_id)
        # PROBLEM 21 again: the question and the full answer (with document refs) in the logs.
        logger.info(f"agent question={req.question!r} answer={answer!r} tools={[t['tool'] for t in trace]}")
        activity(r, "agent.run", detail=f"question={req.question}")
        return {"answer": answer, "security_notes": notes, "model": agent.name}

    @app.get("/outbox")
    def outbox(r: TenantRepo = Depends(repo)):
        return r.conn.execute("SELECT id, recipient, subject, status FROM outbox ORDER BY id").fetchall()

    @app.post("/outbox/{email_id}/approve")
    def approve(email_id: int, r: TenantRepo = Depends(repo)):
        row = r.conn.execute(
            "UPDATE outbox SET status = 'sent', approved_by = %s WHERE id = %s AND status = 'pending_approval'"
            " RETURNING id, recipient, status", (r.user_name, email_id),
        ).fetchone()
        if row is None:
            activity(r, "email.approve", f"email:{email_id}", "denied")
            raise HTTPException(404, "No pending email with that id")  # ...and the row above is rolled back
        activity(r, "email.approve", f"email:{email_id}")
        return row

    @app.get("/activity")
    def recent_activity(r: TenantRepo = Depends(repo)):
        # PROBLEM 23 (shared log, no filter): activity_log has no RLS and this query has no
        # tenant filter, so every customer sees every other customer's activity.
        # PROBLEM 24 (editable history): the app role can UPDATE and DELETE activity_log rows,
        # and nothing would notice if it did.
        return r.conn.execute(
            "SELECT id, tenant_id, user_name, action, target, outcome, created FROM activity_log ORDER BY id DESC LIMIT 50"
        ).fetchall()

    return app


def __getattr__(name):
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
