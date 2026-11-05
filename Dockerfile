# The Phase 7 secure app as a container image.
#   docker compose --profile app up --build     (see README, Phase 7)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LAB_ENV=production \
    LAB_SECRETS_DIR=/run/secrets \
    LAB_DATA_DIR=/data \
    LAB_LOG_LEVEL=INFO

WORKDIR /app

# Dependencies first, so code changes don't reinstall them on every build.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Never run as root. No secrets are copied in (.dockerignore excludes secrets/);
# they're mounted at runtime under /run/secrets.
RUN useradd --uid 10001 --create-home app && mkdir -p /data && chown app /data
COPY --chown=app . .
USER app

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"

# One worker: the Phase 3 rate limiter keeps its buckets in process memory.
# More workers (or replicas) need the shared limiter from the Phase 3 exercises first.
CMD ["uvicorn", "phase7.secure_app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
