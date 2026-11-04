# Tenant Isolation Lab

A practice project for learning **how multi-tenant data leaks happen and how to stop them**.

Three tenants share one database and one file store:

| Tenant | Users (token) | Document types |
|---|---|---|
| `hospital` | `hospital-alice`, `hospital-hank` | Patient intake note, Discharge instructions, Staff policy |
| `bank` | `bank-bob`, `bank-betty` | Loan policy, Account FAQ, Fraud procedure |
| `lawfirm` | `lawfirm-lena`, `lawfirm-leo` | Case memo, Client engagement letter, Billing policy |

Every document has a canary line such as `Internal ref: BANK-SECRET-e282d63c6e`.
If a hospital user ever sees `BANK-SECRET-…`, that's a leak, with no room for argument.

## What's in here

| File | What it is |
|---|---|
| `seed.py` | Builds fake data: `lab.db` (SQLite) and `data/<tenant>/doc_N.txt`. The same data every run. |
| `vulnerable_app.py` | A FastAPI app with **7 planted leaks**, each marked `# LEAK n:` |
| `secure_app.py` | The same API with every leak fixed. This is the answer key. |
| `attacks.py` | One attack per leak, run as `hospital-alice` against the other tenants |
| `leak_hunter.py` | Runs all attacks and prints a LEAK/safe report |
| `tests/` | pytest suite: the secure app must pass every attack, and the vulnerable app must fail every one |

## Setup

```bash
cd tenant-isolation-lab
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python seed.py
python leak_hunter.py          # 7/7 leaks on vulnerable, 0/7 on secure
pytest -q                      # 16 passed
```

To explore by hand, run a server and open its interactive docs:

```bash
uvicorn vulnerable_app:app --port 8001 --reload   # http://localhost:8001/docs
uvicorn secure_app:app     --port 8002 --reload   # http://localhost:8002/docs
curl -H "Authorization: Bearer hospital-alice" localhost:8001/documents/2   # a bank doc!
```

## How to practice

1. Read a leak below, then find its `# LEAK n:` comment in `vulnerable_app.py`.
2. Try the attack yourself with curl or the `/docs` page.
3. Fix it in `vulnerable_app.py`.
4. Run `python leak_hunter.py vulnerable` and watch the LEAK count drop.
5. Only then compare your fix with `secure_app.py`.

When you've fixed all 7, the hunter prints `0 of 7` for both apps. To start over, run `git checkout vulnerable_app.py`.

## The 7 leaks

### 1. IDOR: guessable IDs, no ownership check
`GET /documents/{id}` looks a row up by ID only. IDs are shared across tenants (1=hospital, 2=bank, 3=lawfirm…), so guessing numbers reads everyone's data.
**Where it happens in real systems:** any "get by ID" endpoint, download links, and admin tools.
**Fix:** put the tenant in the query itself: `WHERE id = ? AND tenant_id = ?`. Return **404**, not 403, for other tenants' IDs, because a 403 confirms the ID exists. Random UUIDs make guessing harder, but they don't replace the check.

### 2. Trusting a tenant ID from the client
`GET /documents` uses an `X-Tenant-ID` header when one is sent. Headers, query params, cookies and request bodies are all controlled by the attacker.
**Fix:** take the tenant only from the authenticated identity (the token or session). Reject any client hint that disagrees.

### 3. SQL injection removes the tenant filter
`/search` pastes `q` into the SQL string, so `x%' OR 1=1 --` turns the query into "everything".
**Fix:** always use parameterized queries. Here, the tenant filter was in the code but injection deleted it.

### 4. Shared cache without the tenant in the key
`/search` caches by query text only. When the bank searches "policy" first, the hospital's "policy" search returns the bank's cached results.
**Where it happens in real systems:** Redis/memcached, CDN caches of authenticated pages, memoized functions, and **LLM/RAG answer caches**.
**Fix:** every cache key includes the tenant, e.g. `(tenant_id, query)`.

### 5. Path traversal in file storage
`/files?name=../bank/doc_0.txt` walks out of the hospital's folder.
**Where it happens in real systems:** file downloads, S3 keys built from user input, and zip extraction.
**Fix:** resolve the final path and check that it's still inside the tenant's root. Better still, look files up by a DB ID that's scoped to the tenant, and never take a raw filename.

### 6. Mass assignment: writing into another tenant
`POST /documents` accepts `tenant_id` in the body, so a hospital user can plant data in the bank's space. This is a **write** leak, and it's just as serious as a read leak.
**Fix:** the request schema has no `tenant_id` field and rejects unknown fields. The server sets the tenant.

### 7. Unscoped aggregates
`/stats` counts documents across all tenants. "It's only counts" still reveals who your other customers are and how big they are.
**Where it happens in real systems:** dashboards, analytics, autocomplete, "recent activity" feeds, and search suggestions.
**Fix:** scope aggregates like any other query.

## The pattern behind all the fixes

Look at `TenantRepo` in `secure_app.py`. Route handlers never write SQL. They get a repository that's already bound to the caller's tenant, and that repository has no unscoped method. Fixing leaks one endpoint at a time doesn't hold up. **Make the safe path the only path.**

## Next levels (when you're ready)

- **Database-enforced isolation:** move to Postgres and turn on **Row-Level Security**, so that even a forgotten `WHERE` can't leak. This is the strongest single upgrade.
- **Error messages and logs:** stack traces and log lines that include other tenants' data. Logs are often shared across tenants.
- **Background jobs:** a worker that processes "all pending docs" without carrying the tenant along.
- **RAG / vector search:** embed the documents and make sure retrieval filters by tenant metadata *before* ranking. A missing filter there is the AI version of leak 3/4.
- **Write your own leak:** add a new endpoint with a subtle bug, write an attack for it in `attacks.py`, and make sure the tests catch it.
