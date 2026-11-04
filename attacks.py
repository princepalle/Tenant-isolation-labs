"""Attacks for each leak. Every attack runs as a hospital user (alice) going after another tenant.

Each function takes an HTTP client (FastAPI TestClient or httpx.Client, which share an API)
and returns a Finding. Leaks are detected by looking for anything belonging to another tenant
in the response: its canary string (BANK-SECRET-...) or its tenant name.
"""
import re
from dataclasses import dataclass

from common import TENANTS

ATTACKER_TOKEN, ATTACKER_TENANT = "hospital-alice", "hospital"
VICTIM_TOKEN, VICTIM_TENANT = "bank-bob", "bank"


@dataclass
class Finding:
    leak: int
    name: str
    leaked: bool
    evidence: str


def auth(token: str, **extra) -> dict:
    return {"Authorization": f"Bearer {token}", **extra}


def foreign_tenants_in(text: str, my_tenant: str) -> set[str]:
    """Which other tenants' data shows up in this text?"""
    found = set()
    for t in TENANTS:
        if t == my_tenant:
            continue
        if f"{t.upper()}-SECRET-" in text or re.search(rf"\b{t}\b", text):
            found.add(t)
    return found


def _check(leak, name, resp, note="") -> Finding:
    hits = foreign_tenants_in(resp.text, ATTACKER_TENANT)
    if hits:
        return Finding(leak, name, True, f"HTTP {resp.status_code}, saw data from: {', '.join(sorted(hits))} {note}".strip())
    return Finding(leak, name, False, f"HTTP {resp.status_code}, nothing foreign")


def idor(client) -> Finding:
    """Guess document IDs. IDs are shared across tenants, so most guesses belong to someone else."""
    leaked_ids, hits = [], set()
    for doc_id in range(1, 61):
        r = client.get(f"/documents/{doc_id}", headers=auth(ATTACKER_TOKEN))
        found = foreign_tenants_in(r.text, ATTACKER_TENANT)
        if found:
            leaked_ids.append(doc_id)
            hits |= found
    if leaked_ids:
        return Finding(1, "IDOR: guess /documents/{id}", True,
                       f"read {len(leaked_ids)} foreign docs (from {', '.join(sorted(hits))})")
    return Finding(1, "IDOR: guess /documents/{id}", False, "every foreign ID returned 404")


def trusted_header(client) -> Finding:
    r = client.get("/documents", headers=auth(ATTACKER_TOKEN, **{"X-Tenant-ID": VICTIM_TENANT}))
    return _check(2, "Client-chosen tenant header", r)


def sql_injection(client) -> Finding:
    r = client.get("/search", params={"q": "x%' OR 1=1 --"}, headers=auth(ATTACKER_TOKEN))
    return _check(3, "SQL injection in /search", r)


def shared_cache(client) -> Finding:
    # The victim searches first and warms the cache. Then the attacker sends the same query.
    client.get("/search", params={"q": "policy"}, headers=auth(VICTIM_TOKEN))
    r = client.get("/search", params={"q": "policy"}, headers=auth(ATTACKER_TOKEN))
    return _check(4, "Cache key without tenant", r)


def path_traversal(client) -> Finding:
    r = client.get("/files", params={"name": f"../{VICTIM_TENANT}/doc_0.txt"}, headers=auth(ATTACKER_TOKEN))
    return _check(5, "Path traversal in /files", r)


def mass_assignment(client) -> Finding:
    """Write INTO another tenant: plant a doc in the bank's space and see if the bank sees it."""
    marker = "PLANTED-BY-HOSPITAL"
    client.post(
        "/documents",
        json={"title": marker, "doc_type": "Note", "body": "hello", "tenant_id": VICTIM_TENANT},
        headers=auth(ATTACKER_TOKEN),
    )
    r = client.get("/documents", headers=auth(VICTIM_TOKEN))
    if marker in r.text:
        return Finding(6, "Mass assignment of tenant_id", True, "the attacker's doc now shows up in the bank's list")
    return Finding(6, "Mass assignment of tenant_id", False, "the bank's list is untouched")


def aggregate_stats(client) -> Finding:
    r = client.get("/stats", headers=auth(ATTACKER_TOKEN))
    return _check(7, "Unscoped aggregate /stats", r)


ALL_ATTACKS = [idor, trusted_header, sql_injection, shared_cache, path_traversal, mass_assignment, aggregate_stats]
