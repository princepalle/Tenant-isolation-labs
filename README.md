# Tenant Isolation Lab

A practice **multi-tenant AI SaaS**: three customer companies share one platform, one database and one AI assistant. The goal is to learn how to run that **production-ready**: how tenant data leaks, how to catch it, and how to design so it can't.

| Tenant | Users (token) | Document types |
|---|---|---|
| `hospital` | `hospital-alice`, `hospital-hank` | Patient intake note, Discharge instructions, Staff policy |
| `bank` | `bank-bob`, `bank-betty` | Loan policy, Account FAQ, Fraud procedure |
| `lawfirm` | `lawfirm-lena`, `lawfirm-leo` | Case memo, Client engagement letter, Billing policy |

Every document has a canary line such as `Internal ref: BANK-SECRET-e282d63c6e`.
If a hospital user ever sees `BANK-SECRET-…`, that's a leak, with no room for argument.

## Architecture (today)

```
 client ──Bearer token──▶ FastAPI app ──▶ TenantRepo (every query bound to one tenant)
                              │                 │
                              │                 ├─▶ SQLite: tenants, users, documents, conversations, messages
                              │                 └─▶ data/<tenant>/*.txt
                              │
                              └─▶ /ask: retrieve (tenant-filtered) ─▶ prompt ─▶ LLM (offline or Claude)
```

| File | What it is |
|---|---|
| `seed.py` | Builds fake data: `lab.db` and `data/<tenant>/doc_N.txt`. The same data every run. |
| `ai.py` | The AI layer: a TF-IDF retriever (stands in for a vector DB), the prompt, and the model: `OfflineLLM` or `ClaudeLLM` |
| `vulnerable_app.py` | The SaaS API with **10 planted leaks**, each marked `# LEAK n:` |
| `secure_app.py` | The same API with every leak fixed. This is the answer key. |
| `attacks.py` | One attack per leak, run as `hospital-alice` against the other tenants |
| `leak_hunter.py` | Runs all attacks and prints a LEAK/safe report |
| `tests/` | The secure app must pass every attack, the vulnerable app must fail every one, and both must still work |

## Setup

```bash
cd tenant-isolation-lab
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python seed.py
python leak_hunter.py          # 10/10 leaks on vulnerable, 0/10 on secure
pytest -q                      # 23 passed
```

To explore by hand, run a server and open its interactive docs:

```bash
uvicorn vulnerable_app:app --port 8001 --reload   # http://localhost:8001/docs
uvicorn secure_app:app     --port 8002 --reload   # http://localhost:8002/docs

curl -H "Authorization: Bearer hospital-alice" localhost:8001/documents/2   # a bank doc!
curl -X POST localhost:8001/ask -H "Authorization: Bearer hospital-alice" \
     -H "Content-Type: application/json" -d '{"question": "What credit score do loan applicants need?"}'
```

### Using real Claude

By default the assistant is an **offline fake model**: free, instant and deterministic, so tests never cost money. To use Claude:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
LAB_LLM=claude uvicorn secure_app:app --port 8002
# optional: LAB_CLAUDE_MODEL (default claude-opus-5-5), LAB_CLAUDE_EFFORT (default low)
```

Try leak 8 against the vulnerable app with Claude. It will *often* obey the "only use hospital documents" instruction, and sometimes it won't. Either way, the `sources` list hands the bank's documents back to the caller. A prompt is not a security boundary.

## How to practice

1. Read a leak below, then find its `# LEAK n:` comment in `vulnerable_app.py`.
2. Try the attack yourself with curl or the `/docs` page.
3. Fix it in `vulnerable_app.py`.
4. Run `python leak_hunter.py vulnerable` and watch the LEAK count drop.
5. Only then compare your fix with `secure_app.py`.

To start over, run `git checkout vulnerable_app.py`.

## The 10 leaks

### Classic SaaS leaks

**1. IDOR: guessable IDs, no ownership check.** `GET /documents/{id}` looks a row up by ID only. IDs are shared across tenants, so guessing numbers reads everyone's data.
*Fix:* put the tenant in the query itself (`WHERE id = ? AND tenant_id = ?`). Return **404**, not 403, because a 403 confirms the ID exists.

**2. Trusting a tenant ID from the client.** `GET /documents` obeys an `X-Tenant-ID` header. Headers, params, cookies and bodies are all controlled by the attacker.
*Fix:* the tenant comes only from the authenticated identity. Reject hints that disagree.

**3. SQL injection removes the tenant filter.** `/search` pastes `q` into SQL, so `x%' OR 1=1 --` returns everything.
*Fix:* parameterized queries, always.

**4. Shared cache without the tenant in the key.** `/search` caches by query text, so tenants get each other's cached results.
*Fix:* every cache key includes the tenant. This applies to Redis, CDNs and memoized functions.

**5. Path traversal in file storage.** `/files?name=../bank/doc_0.txt` escapes the tenant folder.
*Fix:* resolve the path and check it's still inside the tenant's root. Better: look files up by a tenant-scoped ID.

**6. Mass assignment: writing into another tenant.** `POST /documents` accepts `tenant_id` in the body.
*Fix:* the request schema has no `tenant_id` and rejects unknown fields. The server sets the tenant.

**7. Unscoped aggregates.** `/stats` counts every tenant's documents, which reveals who your other customers are and how big they are.
*Fix:* scope aggregates like any other query.

### AI-specific leaks

**8. RAG retrieval across tenants.** `/ask` searches **all** tenants' documents, then tells the model "only use hospital documents". The model may or may not obey, and the `sources` list leaks anyway. In real systems this is a shared vector index queried without a metadata filter.
*Fix:* filter by tenant **before** ranking, so the model never sees foreign data. With a vector DB, use a per-tenant namespace or collection, or a mandatory metadata filter in the query.

**9. Chat history of another user/tenant.** Conversation IDs are `1, 2, 3…` with no ownership check, so anyone can read or *continue* someone else's chat. Continuing it pulls their history into the prompt.
*Fix:* conversations belong to a tenant **and** a user, and every read checks both. UUIDs help but don't replace the check. (The secure app also stops colleagues inside a tenant from reading each other's chats; see `test_colleagues_cannot_read_each_others_chats`.)

**10. Shared answer cache.** LLM calls are expensive, so teams cache answers. Keying the cache by question text alone serves the bank's answer to the hospital.
*Fix:* cache key = `(tenant, question)`, and never cache answers that depend on a user's chat history.

## The pattern behind all the fixes

Look at `TenantRepo` in `secure_app.py`. Route handlers never write SQL. They get a repository already bound to the caller's tenant, and it has no unscoped method. That includes the AI path: `retrieval_corpus()` only returns the tenant's own documents. **Make the safe path the only path.**

## Roadmap to production

You're at **Phase 1**. Each phase adds one production concern, with leaks to find and tests to prove the fix.

| Phase | Topic | What you'd build and learn |
|---|---|---|
| ✅ 1 | **Isolation basics + RAG** | This lab: 10 leaks, an attack suite and tests |
| 2 | **Database-enforced isolation** | Postgres + **Row-Level Security** + `pgvector` (Docker is available). Even a forgotten `WHERE` can't leak, because the DB refuses. Real embeddings instead of TF-IDF. |
| 3 | **Per-tenant limits and cost** | Rate limits and monthly token quotas per tenant ("noisy neighbor" protection). Record `usage.input_tokens`/`output_tokens` per request so you can bill each tenant. |
| 4 | **Prompt injection** | A document that says "ignore your instructions…". Learn what isolation does and doesn't protect you from (it limits the blast radius to one tenant). Add output checks for canaries. |
| 5 | **Observability and audit** | Structured logs with `tenant_id` on every line, but **no document contents in logs**. An audit trail of who asked what. Traces for each `/ask`. |
| 6 | **Evals** | An eval set per tenant: answer quality *and* isolation (did any answer contain a foreign canary?). Run it in CI before every deploy. |
| 7 | **Ship it** | Docker Compose, real auth (JWT/OIDC with a tenant claim), secrets management, CI that runs `pytest` + `leak_hunter`, and per-tenant data export and deletion. |
