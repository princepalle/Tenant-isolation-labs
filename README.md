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
| `phase2/` | Postgres + Row-Level Security + pgvector. See the Phase 2 section below. |
| `phase3/` | Rate limits, quotas, usage metering and billing. See the Phase 3 section below. |

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

## Phase 2: the database enforces isolation (Postgres + RLS + pgvector)

In Phase 1, isolation depended on every developer remembering `WHERE tenant_id = ?` in every query. Phase 2 moves the rule **into the database** with Row-Level Security. Even a query with no tenant filter only sees the current tenant's rows.

### Setup

```bash
docker compose up -d            # Postgres 16 + pgvector
python -m phase2.setup_db       # roles, schema, RLS policies, 60 docs with embeddings
python -m phase2.rls_demo       # 6 RLS pitfalls, live
python -m phase2.hunt           # 11 attacks vs. the leaky and secure Phase 2 apps
pytest -q                       # 61 tests (the database ones skip if Postgres isn't running)
```

Run the servers with `uvicorn phase2.leaky_app:app --port 8003` and `uvicorn phase2.secure_app:app --port 8004`.

### What's in `phase2/`

| File | What it is |
|---|---|
| `schema.sql` | **Start here.** Tables, the RLS policies, the `auth_user()` function, and grants. Every line is commented. |
| `db.py` | Connection settings and `tenant_session()`, which scopes one transaction to one tenant |
| `embeddings.py` | Text into a 256-number vector for pgvector (offline feature hashing; swap in a real model later) |
| `setup_db.py` | Creates the roles and database, then loads the same 60 documents as Phase 1 |
| `leaky_app.py` | Phase 1's leaky code with **every tenant filter removed**, relying on RLS alone |
| `secure_app.py` | Defense in depth: app-level fixes **and** RLS |
| `rls_demo.py` | Six RLS pitfalls you can run and read |
| `hunt.py` | Runs all 11 attacks against both apps on a fresh database |

### How it works

1. **Two database roles.** `lab_owner` owns the tables and has `BYPASSRLS` (migrations and seeding only). `app_user` is what the web app uses: it owns nothing and has `NOBYPASSRLS`, so policies always apply.
2. **One policy per table**, e.g. `USING (tenant_id = current_setting('app.tenant_id', true))`. `USING` controls what you can read. `WITH CHECK` controls what you can write.
3. **Each request runs one transaction** that starts with `set_config('app.tenant_id', <tenant from the token>, true)`. The `true` makes the setting vanish when the transaction ends.
4. **Vector search is just SQL** (`ORDER BY embedding <=> query LIMIT 3`), so RLS applies to RAG retrieval automatically.

### Results: what RLS catches on its own

| Leak | RLS alone (leaky code) | Why |
|---|---|---|
| 1 IDOR | ✅ stopped | Foreign rows are invisible |
| 2 Client-chosen tenant | ❌ leaks | RLS enforces whatever tenant the app sets. Garbage in, garbage out. |
| 3 SQLi `OR 1=1` | ✅ stopped | The policy is applied on top of the injected WHERE clause |
| 4 Search cache | ❌ leaks | The cache lives in the app, above the database |
| 5 Path traversal | ❌ leaks | Files on disk aren't in the database |
| 6 Mass assignment | ✅ stopped | `WITH CHECK` rejects the row (403) |
| 7 Stats | ✅ stopped | The aggregates only see the tenant's own rows |
| 8 RAG retrieval | ✅ stopped | Vector search is filtered by the policy |
| 9 Chat history | ✅ stopped | The conversation and message policies are per user |
| 10 Answer cache | ❌ leaks | App-level cache again |
| **11 SQLi rewrites the tenant** | ❌ leaks | **New in Phase 2.** Injected SQL calls `set_config('app.tenant_id','bank',true)` and *becomes* the bank. |

**5 of 11 still leak with RLS alone. 0 of 11 leak with the secure app.** RLS is a strong second lock, not a replacement for correct app code.

### The RLS pitfalls (`python -m phase2.rls_demo`)

1. **Fails closed.** No tenant set means 0 rows. That's good: a forgotten setting gives you an empty page, not a breach.
2. **Vector search is scoped.** Similarity search with no `WHERE` still only returns the tenant's own documents.
3. **The owner bypasses RLS.** Connected as `lab_owner`, you see all 60 rows. Superusers always bypass too. **The #1 RLS mistake is the app connecting as the table owner or a superuser.** Everything looks fine in testing, and nothing is enforced.
4. **Connection pools leak settings.** A plain `SET app.tenant_id` sticks to the connection, and the next request on that pooled connection inherits it (20 bank rows). `SET LOCAL` / `set_config(..., true)` doesn't (0 rows). PgBouncer in transaction mode makes this worse.
5. **`WITH CHECK` blocks cross-tenant writes**, even when the app code tries.
6. **The users table is locked.** The app can't `SELECT` it, only call `auth_user()`, a narrow `SECURITY DEFINER` function.

### Lesson from leak 11: test with several payloads

A simple injection payload *sometimes* escapes the tenant and sometimes doesn't. It depends on whether Postgres reads the tenant index, which evaluates `current_setting()` once before the injected code runs, or scans rows, which re-evaluates it per row. The plan changes with table statistics. Attack 11 uses a payload that works under both plans. **"I tried the attack and it didn't work" proves nothing.**

### Phase 2 exercises

1. In `phase2/leaky_app.py`, fix the 5 leaks that remain (2, 4, 5, 10, 11). Run `python -m phase2.hunt leaky` after each fix.
2. Break it on purpose: change `true` to `false` in `tenant_session()` (`db.py`) and run the tests. Which ones catch it? (Hint: probably none of the attack tests. Why? What test would?)
3. Change `APP_DSN` to the owner's credentials and run `python -m phase2.hunt leaky`. Watch RLS silently stop working.
4. **Harden against leak 11 at the database level:** `REVOKE EXECUTE ON FUNCTION set_config(text, text, boolean) FROM PUBLIC`, then add a `SECURITY DEFINER` function `set_tenant(token_hash)` that looks up the tenant itself. Now injected SQL can't choose a tenant without a valid token. What else would you need to change?
5. Swap the embeddings for a real model (`embeddings.py` explains where), and change `vector(256)` to match its size.

## Phase 3: fair limits and honest billing

Phases 1 and 2 were about **data**. Phase 3 is about **fairness and money**. Every AI call costs you real money, and every tenant shares the same servers and model quota. Three questions every AI SaaS has to answer:

1. **Can one tenant hurt the others?** (noisy neighbor)
2. **Can a tenant use more than it pays for?** (limit evasion, missing quotas)
3. **Does your bill from the model provider match what you charge customers?** (metering)

### Setup

```bash
python -m phase3.setup_db              # Phase 2 database + plans, usage ledger, billing role
python -m phase3.hunt                  # 5 checks vs. the leaky and secure Phase 3 apps
python -m phase3.billing --simulate 40 # fake a burst of traffic, then print each tenant's invoice
```

Servers: `uvicorn phase3.leaky_app:app --port 8005` and `uvicorn phase3.secure_app:app --port 8006`.
Admin view: `curl -H "Authorization: Bearer platform-admin-dev" localhost:8006/admin/usage`

### Plans

| Tenant | Plan | Requests / minute | Tokens / month |
|---|---|---|---|
| bank | enterprise | 120 | 5,000,000 |
| hospital | pro | 30 | 500,000 |
| lawfirm | free | 5 | 20,000 |

### What's in `phase3/`

| File | What it is |
|---|---|
| `schema.sql` | **Start here.** Plans, the `usage_events` ledger (append-only), RLS on `tenants`, and the `billing_reader` role |
| `metering.py` | Prices, the token-bucket `RateLimiter`, and `LLMGateway`: **the only way the secure app calls a model** |
| `leaky_app.py` | Five limit and billing mistakes, marked `# PROBLEM n:` |
| `secure_app.py` | The fixed version, built on the Phase 2 secure app |
| `checks.py` / `hunt.py` | One check per problem, each on a fresh database |
| `billing.py` | Invoices for every tenant, read through the least-privilege billing role |

### The 5 problems

| # | Problem (leaky app) | What goes wrong | Fix (secure app) |
|---|---|---|---|
| 12 | **Noisy neighbor:** one global rate limit | The bank's burst of 70 requests uses up the shared bucket. The hospital gets `429` for doing nothing wrong. | One bucket **per tenant**, sized by plan |
| 13 | **Limit evasion:** limit per *user*, ignoring the plan | The free law firm's 2 users get 20 requests through. The plan allows 5. Add users, get more. | Key the limit by **tenant**, not user or API key |
| 14 | **No quota** | A tenant past its monthly tokens keeps calling the model, and you pay for it | Check month-to-date tokens **before** every model call. Refuse with `429` + `Retry-After`. |
| 15 | **Unmetered path** | Usage is recorded for new chats, not follow-ups. 3 model calls, 1 billed. | All calls go through `LLMGateway`, which meters in **its own transaction**, so a later crash can't roll back the bill |
| 16 | **Fake admin + owner connection** | `X-Admin: true` makes anyone an admin, and the admin query runs as the table owner (BYPASSRLS) | A separate admin credential (checked with `hmac.compare_digest`) and a `billing_reader` role that sees **usage for all tenants but no documents** |

### Design ideas worth stealing

- **One gateway for every model call.** Rate limit, then quota, then call, then meter. You can't forget a step, because there's no other path. This is the same idea as `TenantRepo`.
- **The usage ledger is append-only.** `app_user` has `INSERT` but no `UPDATE` or `DELETE`, so even SQL injection can't erase usage to dodge a bill.
- **Least privilege per job.** The web app (`app_user`) sees one tenant's documents. Billing (`billing_reader`) sees all tenants' usage and no documents. Migrations (`lab_owner`) are never used at runtime.
- **Plans are business data.** Phase 2 let every tenant read the whole `tenants` table. Now it holds plans ("the bank pays for enterprise"), so it gets RLS too. Check every table when you add a column.
- **Unknown model = expensive.** `cost_usd()` prices an unrecognized model like Opus, never as free. A pricing gap should never turn into a free model.

### Phase 3 exercises

1. Fix the 5 problems in `phase3/leaky_app.py`. Run `python -m phase3.hunt leaky` after each one.
2. **Multiple servers.** The rate limiter lives in memory, so 3 servers = 3× the limit. Move the buckets into Postgres (an `UPDATE … RETURNING` on a `rate_buckets` table) or Redis, so all servers share them.
3. **The quota race.** Two requests can both pass the quota check and overshoot. Fix it with a *reservation*: insert a "pending" usage row for the worst case before the call, then correct it to the real numbers afterwards.
4. **Per-user fairness.** A tenant-wide bucket stops one tenant from starving others, but one user can still starve their colleagues. Add a smaller per-user bucket *inside* the tenant bucket.
5. **Real costs.** Run with `LAB_LLM=claude` and compare `/usage` against your Anthropic Console usage. Do they match? (Hint: think about prompt caching and failed calls.)

## Roadmap to production

You've done **Phases 1, 2 and 3**. Each phase adds one production concern, with leaks to find and tests to prove the fix.

| Phase | Topic | What you'd build and learn |
|---|---|---|
| ✅ 1 | **Isolation basics + RAG** | This lab: 10 leaks, an attack suite and tests |
| ✅ 2 | **Database-enforced isolation** | Postgres + **Row-Level Security** + `pgvector`. See the Phase 2 section above. |
| ✅ 3 | **Per-tenant limits and cost** | Rate limits, quotas, metering and billing. See the Phase 3 section above. |
| 4 | **Prompt injection** | A document that says "ignore your instructions…". Learn what isolation does and doesn't protect you from (it limits the blast radius to one tenant). Add output checks for canaries. |
| 5 | **Observability and audit** | Structured logs with `tenant_id` on every line, but **no document contents in logs**. An audit trail of who asked what. Traces for each `/ask`. |
| 6 | **Evals** | An eval set per tenant: answer quality *and* isolation (did any answer contain a foreign canary?). Run it in CI before every deploy. |
| 7 | **Ship it** | Docker Compose, real auth (JWT/OIDC with a tenant claim), secrets management, CI that runs `pytest` + `leak_hunter`, and per-tenant data export and deletion. |
