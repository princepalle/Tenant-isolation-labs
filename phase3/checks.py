"""Phase 3 checks: one per problem. Each returns a Finding where `leaked=True` means the
check FAILED (the app let the abuse happen).

Checks get the HTTP client and the owner DSN. The owner connection plays the role of
"the platform team looking at the database" to verify what really got recorded.
"""
import psycopg
from psycopg.rows import dict_row

from attacks import Finding, auth, foreign_tenants_in

FREE_PLAN_RPM = 5
FREE_PLAN_QUOTA = 20_000


def _ask(client, token, question, conversation_id=None):
    body = {"question": question}
    if conversation_id:
        body["conversation_id"] = conversation_id
    return client.post("/ask", json=body, headers=auth(token))


def noisy_neighbor(client, owner_dsn) -> Finding:
    """The bank fires a burst of 70 requests (well within its enterprise plan).
    Then the hospital asks one question. Does the hospital get through?"""
    bank_ok = sum(_ask(client, "bank-bob", f"loan policy question {i}").status_code == 200 for i in range(70))
    r = _ask(client, "hospital-alice", "What is the staff policy?")
    if r.status_code == 429:
        return Finding(12, "Noisy neighbor", True,
                       f"bank got {bank_ok}/70 through, then the hospital was blocked (429)")
    return Finding(12, "Noisy neighbor", False, f"bank got {bank_ok}/70, hospital still served ({r.status_code})")


def limit_evasion(client, owner_dsn) -> Finding:
    """The law firm is on the free plan: 5 requests a minute for the whole tenant.
    Its two users each send 10. How many get through in total?"""
    ok = sum(
        _ask(client, token, f"billing policy question {i}").status_code == 200
        for i in range(10) for token in ("lawfirm-lena", "lawfirm-leo")
    )
    if ok > FREE_PLAN_RPM:
        return Finding(13, "Rate limit evasion via more users", True,
                       f"{ok} of 20 requests got through; the plan allows {FREE_PLAN_RPM}")
    return Finding(13, "Rate limit evasion via more users", False, f"{ok} of 20 got through (plan: {FREE_PLAN_RPM})")


def quota(client, owner_dsn) -> Finding:
    """Pretend it's the end of the month and the law firm has used its whole quota."""
    with psycopg.connect(owner_dsn) as conn:
        conn.execute(
            "INSERT INTO usage_events (tenant_id, user_name, model, input_tokens, output_tokens, cost_usd)"
            " VALUES ('lawfirm', 'lena', 'offline', %s, 0, 0)", (FREE_PLAN_QUOTA,),
        )
    r = _ask(client, "lawfirm-lena", "What does the billing policy say?")
    if r.status_code == 200:
        return Finding(14, "Monthly quota not enforced", True, "quota used up, but the model was still called")
    return Finding(14, "Monthly quota not enforced", False, f"refused with HTTP {r.status_code}")


def every_call_metered(client, owner_dsn) -> Finding:
    """One new question plus two follow-ups = 3 model calls = 3 usage rows."""
    first = _ask(client, "hospital-alice", "What is the staff policy for handovers?").json()
    _ask(client, "hospital-alice", "Which ward does it apply to?", first["conversation_id"])
    _ask(client, "hospital-alice", "Who owns the policy?", first["conversation_id"])
    with psycopg.connect(owner_dsn, row_factory=dict_row) as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM usage_events WHERE tenant_id = 'hospital'").fetchone()["n"]
    if n != 3:
        return Finding(15, "Unmetered model calls", True, f"3 model calls, but only {n} recorded")
    return Finding(15, "Unmetered model calls", False, "3 model calls, 3 recorded")


def usage_privacy(client, owner_dsn) -> Finding:
    """Can a normal hospital user see other tenants' usage and plans?"""
    _ask(client, "bank-bob", "loan policy")  # make sure the bank has some usage to see
    for path, headers in [("/admin/usage", auth("hospital-alice", **{"X-Admin": "true"})),
                          ("/usage", auth("hospital-alice"))]:
        r = client.get(path, headers=headers)
        hits = foreign_tenants_in(r.text, "hospital")
        if hits:
            return Finding(16, "Other tenants' usage visible", True,
                           f"{path} showed {', '.join(sorted(hits))} (HTTP {r.status_code})")
    return Finding(16, "Other tenants' usage visible", False, "only the hospital's own usage was visible")


ALL_CHECKS = [noisy_neighbor, limit_evasion, quota, every_call_metered, usage_privacy]
