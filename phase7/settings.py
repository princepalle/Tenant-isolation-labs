"""Configuration and secrets for the shipped app.

Rules:
  1. No secret lives in the code or the image. Each comes from an environment variable
     (LAB_<NAME>) or a file in LAB_SECRETS_DIR (how Docker/Kubernetes secrets are mounted).
  2. In production, a missing secret or a known dev default is a startup ERROR. An app that
     quietly falls back to "platform-admin-dev" is worse than one that won't start.
  3. Secrets never appear in repr(), so they can't leak into logs or tracebacks.
"""
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from phase2.db import DB_NAME, HOST, PORT
from phase7.idp import AUDIENCE, ISSUER, SECRETS_DIR

KNOWN_DEV_VALUES = ("platform-admin-dev", "app_pw", "ops_pw", "auditor_pw")


def dsn(role: str, password: str) -> str:
    """Where the database is (host, port, name) is config. The password is a secret."""
    return f"postgresql://{role}:{password}@{HOST}:{PORT}/{DB_NAME}"


DEV_OPS_DSN = dsn("platform_ops", "ops_pw")


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    env: str
    issuer: str
    audience: str
    jwks: dict = field(repr=False)
    admin_token: str = field(repr=False)
    app_dsn: str = field(repr=False)
    ops_dsn: str = field(repr=False)
    auditor_dsn: str = field(repr=False)

    @property
    def production(self) -> bool:
        return self.env == "production"

    @classmethod
    def load(cls) -> "Settings":
        env = os.environ.get("LAB_ENV", "development")
        folder = Path(os.environ.get("LAB_SECRETS_DIR", SECRETS_DIR))

        def secret(name: str, dev_default: str | None) -> str:
            value = os.environ.get(f"LAB_{name.upper()}")
            if value is None and (folder / name).is_file():
                value = (folder / name).read_text()
            if value:
                value = value.strip()
                if env == "production" and any(dev in value for dev in KNOWN_DEV_VALUES):
                    raise ConfigError(f"secret '{name}' still has a development value; refusing to start")
                return value
            if env == "production" or dev_default is None:
                raise ConfigError(f"secret '{name}' is missing (set LAB_{name.upper()} or {folder / name})")
            return dev_default

        settings = cls(
            env=env,
            issuer=os.environ.get("LAB_JWT_ISSUER", ISSUER),
            audience=os.environ.get("LAB_JWT_AUDIENCE", AUDIENCE),
            jwks=json.loads(secret("jwks", None)),
            admin_token=secret("admin_token", "platform-admin-dev"),
            app_dsn=dsn("app_user", secret("app_db_password", "app_pw")),
            ops_dsn=dsn("platform_ops", secret("ops_db_password", "ops_pw")),
            auditor_dsn=dsn("auditor", secret("auditor_db_password", "auditor_pw")),
        )
        if settings.production and len(settings.admin_token) < 32:
            raise ConfigError("admin_token is too short for production (use 32+ random characters)")
        return settings
