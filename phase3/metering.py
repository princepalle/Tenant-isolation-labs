"""Phase 3 building blocks: prices, a per-key rate limiter, and the LLM gateway.

The gateway is the Phase 3 version of "make the safe path the only path": every model
call goes through `LLMGateway.answer()`, which checks the quota, calls the model and
records the usage. There's no way to call the model and forget to bill for it.
"""
import threading
import time

from fastapi import HTTPException

from phase2.db import tenant_session

# USD per million tokens: (input, output). The offline model is priced like Opus 5.5
# so the cost numbers you practice with are realistic.
PRICES = {
    "claude-opus-5-5": (4.00, 20.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
    "offline": (4.00, 20.00),
}


def cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    price_in, price_out = PRICES.get(model, PRICES["claude-opus-5-5"])  # unknown model: assume the dear one
    return (input_tokens * price_in + output_tokens * price_out) / 1_000_000


class RateLimiter:
    """Token bucket, one bucket per key. A bucket holds up to `per_minute` tokens and refills
    at `per_minute` per minute, so short bursts are fine but the average is capped.

    This keeps buckets in process memory, which works for ONE server. Run three servers
    and each tenant gets three times its limit. Production versions keep the buckets in
    Redis or Postgres so all servers share them (see the Phase 3 exercises)."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last refill time)
        self.lock = threading.Lock()  # FastAPI runs sync endpoints on several threads

    def allow(self, key: str, per_minute: int) -> tuple[bool, float]:
        """Take one token. Returns (allowed, seconds to wait before retrying)."""
        with self.lock:
            now = self.clock()
            tokens, last = self.buckets.get(key, (float(per_minute), now))
            tokens = min(per_minute, tokens + (now - last) * per_minute / 60)
            if tokens >= 1:
                self.buckets[key] = (tokens - 1, now)
                return True, 0.0
            self.buckets[key] = (tokens, now)
            return False, (1 - tokens) * 60 / per_minute


def too_many(detail: str, retry_after: float) -> HTTPException:
    # Retry-After tells well-behaved clients exactly how long to back off.
    return HTTPException(429, detail, headers={"Retry-After": str(max(1, round(retry_after)))})


class LLMGateway:
    """The only way the secure app talks to a model."""

    def __init__(self, llm, pool, limiter: RateLimiter):
        """`pool` is only used for usage writes. Give it a SEPARATE pool from the one requests
        use, or concurrent requests deadlock (see Phase 5, "the bug Phase 5 found")."""
        self.llm, self.pool, self.limiter = llm, pool, limiter

    def plan(self, conn) -> dict:
        # RLS on `tenants` means this can only ever return the caller's own plan.
        return conn.execute(
            "SELECT p.* FROM tenants t JOIN plans p ON p.name = t.plan"
        ).fetchone()

    def check_rate(self, conn, tenant_id: str) -> None:
        """Per TENANT, sized by the tenant's plan. Not per user (users could add colleagues
        to multiply their limit) and not one global bucket (one tenant could starve all)."""
        allowed, wait = self.limiter.allow(f"tenant:{tenant_id}", self.plan(conn)["requests_per_minute"])
        if not allowed:
            raise too_many("Rate limit exceeded for your plan", wait)

    def tokens_used_this_month(self, conn) -> int:
        return conn.execute(
            "SELECT COALESCE(SUM(input_tokens + output_tokens), 0) AS n FROM usage_events"
            " WHERE created >= date_trunc('month', now())"
        ).fetchone()["n"]

    def check_quota(self, conn) -> None:
        quota = self.plan(conn)["monthly_token_quota"]
        if self.tokens_used_this_month(conn) >= quota:
            # Known gap: two requests can both pass this check at the same moment and overshoot
            # the quota a little. See the Phase 3 exercises for the reservation fix.
            raise too_many("Monthly token quota used up. Upgrade your plan or wait for next month.", 3600)

    def answer(self, conn, tenant_id: str, user_name: str, system, history, question, docs) -> str:
        self.check_quota(conn)
        text, usage = self.llm.answer_with_usage(tenant_id, system, history, question, docs)
        self.record(tenant_id, user_name, usage)
        return text

    def record(self, tenant_id: str, user_name: str, usage: dict) -> None:
        """Written in its OWN transaction. If the request fails after the model call
        (a bug, a timeout, a rolled-back insert), the model call still cost money,
        so the usage row must survive."""
        model = self.llm.name
        with tenant_session(self.pool, tenant_id, user_name) as conn:
            conn.execute(
                "INSERT INTO usage_events (model, input_tokens, output_tokens, cost_usd) VALUES (%s, %s, %s, %s)",
                (model, usage["input_tokens"], usage["output_tokens"],
                 cost_usd(model, usage["input_tokens"], usage["output_tokens"])),
            )
