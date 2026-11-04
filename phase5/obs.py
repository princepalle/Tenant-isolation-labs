"""Observability for the secure app: structured logs with request context, and redaction.

Three rules this module enforces:
  1. Every log line is JSON and carries request_id, tenant_id and user, so you can answer
     "show me everything that happened in request X" or "...to tenant Y".
  2. Log METADATA, never CONTENT. No prompts, answers, document text or search terms.
     Logs get shipped to third-party tools, kept for years, and read by many people.
  3. A redaction filter catches what slips through anyway (defense in depth).
"""
import contextvars
import json
import logging
import os
import re
import time
import uuid

from fastapi import FastAPI, Request

# One mutable dict per request. The middleware creates it; the auth dependency fills in
# the tenant. A dict (not separate vars) because FastAPI runs dependencies and endpoints
# in worker threads: they get a COPY of the context, but the copy points at the same dict.
_ctx: contextvars.ContextVar[dict] = contextvars.ContextVar("request_ctx", default={})

REQUEST_ID_OK = re.compile(r"^[A-Za-z0-9-]{8,64}$")
REDACTIONS = [
    (re.compile(r"\b[A-Z]+-SECRET-\w+"), "[REDACTED-DOC-REF]"),
    (re.compile(r"\bsk-[A-Za-z0-9-]{8,}"), "[REDACTED-CREDENTIAL]"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "[REDACTED-EMAIL]"),
]


def redact(value):
    if isinstance(value, str):
        for pattern, replacement in REDACTIONS:
            value = pattern.sub(replacement, value)
    return value


def context() -> dict:
    return _ctx.get()


def set_tenant(tenant_id: str, user_name: str) -> None:
    ctx = _ctx.get()
    ctx["tenant_id"], ctx["user"] = tenant_id, user_name


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "event": redact(record.getMessage()),
            **{k: context().get(k) for k in ("request_id", "tenant_id", "user")},
            **{k: redact(v) for k, v in getattr(record, "fields", {}).items()},
        }
        # json.dumps escapes newlines, so a user can't forge extra log lines (log injection).
        return json.dumps(entry, default=str)


class ListHandler(logging.Handler):
    """Keeps formatted lines in memory so tests (and you) can inspect them."""

    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(self.format(record))


def make_logger(name: str) -> tuple[logging.Logger, ListHandler]:
    logger = logging.getLogger(name)
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.INFO)
    handler = ListHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    stream = logging.StreamHandler()  # in production: stdout, collected by your log platform
    stream.setFormatter(JsonFormatter())
    # LAB_LOG_LEVEL=INFO uvicorn ...  to watch every line live. Default: warnings and errors.
    stream.setLevel(os.environ.get("LAB_LOG_LEVEL", "WARNING").upper())
    logger.addHandler(stream)
    return logger, handler


def log(logger: logging.Logger, event: str, level=logging.INFO, **fields) -> None:
    logger.log(level, event, extra={"fields": fields})


def install_request_context(app: FastAPI, logger: logging.Logger) -> None:
    @app.middleware("http")
    async def request_context(request: Request, call_next):
        incoming = request.headers.get("x-request-id", "")
        # Accept a caller's request ID only if it looks like one. Never log raw header values.
        request_id = incoming if REQUEST_ID_OK.match(incoming) else str(uuid.uuid4())
        _ctx.set({"request_id": request_id})
        start = time.perf_counter()
        response = await call_next(request)
        log(logger, "request.finished",
            method=request.method,
            path=request.url.path,  # the path only: query strings carry search terms and PII
            status=response.status_code,
            duration_ms=round((time.perf_counter() - start) * 1000, 1))
        response.headers["X-Request-ID"] = request_id  # give it to the user for support tickets
        return response
