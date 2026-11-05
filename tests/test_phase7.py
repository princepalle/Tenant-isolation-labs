"""Phase 7 tests: JWT login, settings and secrets, offboarding and export.
Unit tests run anywhere; database tests skip if Postgres isn't reachable."""
import json
import os
from unittest import mock

import jwt
import psycopg
import pytest
from fastapi import HTTPException

from phase7.auth import JwtVerifier
from phase7.hunt import shared_idp
from phase7.idp import AUDIENCE, ISSUER
from phase7.settings import ConfigError, Settings

try:
    from phase2.db import ADMIN_DSN, OWNER_DSN
    from phase7.checks import ALL_CHECKS
    from phase7.hunt import fresh_env
    from phase7.offboarding import DELETED, RETAINED, tenant_tables
    from phase7.settings import DEV_OPS_DSN
    from phase7.setup_db import bootstrap

    psycopg.connect(ADMIN_DSN, connect_timeout=2).close()
    PG = True
except Exception:  # noqa: BLE001
    PG = False
    ALL_CHECKS = []

needs_pg = pytest.mark.skipif(not PG, reason="Postgres not available for Phase 7 tests")


# ---------------------------------------------------------------- JWT verification (no database)

@pytest.fixture
def verifier():
    return JwtVerifier(shared_idp().jwks(), ISSUER, AUDIENCE)


def rejected(verifier, token) -> bool:
    try:
        verifier.verify(token)
        return False
    except HTTPException as e:
        return e.status_code == 401


def test_valid_token_gives_tenant_and_role(verifier):
    claims = verifier.verify(shared_idp().issue("hospital-alice"))
    assert (claims["sub"], claims["tenant"], claims["role"]) == ("alice", "hospital", "admin")


def test_bad_tokens_are_rejected(verifier):
    idp = shared_idp()
    assert rejected(verifier, idp.issue("hospital-alice", ttl=-120))              # expired (beyond leeway)
    assert rejected(verifier, idp.issue("hospital-alice", aud="marketing-site"))  # another app
    assert rejected(verifier, idp.issue("hospital-alice", iss="https://evil.example"))
    assert rejected(verifier, jwt.encode({"sub": "x", "tenant": "bank"}, None, algorithm="none"))
    assert rejected(verifier, "not-a-jwt")
    no_tenant = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "alice", "iat": 0, "exp": 2**31},
                           idp.keys[idp.current_kid], algorithm="RS256", headers={"kid": idp.current_kid})
    assert rejected(verifier, no_tenant)                                          # required claim missing


def test_key_rotation():
    """Tokens signed with the old key keep working while its public key is still published,
    and stop the moment it's removed. That's how you rotate keys without logging everyone out."""
    idp = shared_idp()
    old_kid = sorted(idp.keys)[0]
    token = idp.issue("bank-bob", kid=old_kid)
    assert JwtVerifier(idp.jwks(), ISSUER, AUDIENCE).verify(token)["sub"] == "bob"
    newer_only = {"keys": [k for k in idp.jwks()["keys"] if k["kid"] != old_kid]}
    assert rejected(JwtVerifier(newer_only, ISSUER, AUDIENCE), token)


# ---------------------------------------------------------------- settings and secrets (no database)

def load_with(tmp_path, env: dict, files: dict) -> Settings:
    for name, value in files.items():
        (tmp_path / name).write_text(value)
    clean = {k: v for k, v in os.environ.items() if not k.startswith("LAB_")}
    with mock.patch.dict(os.environ, {**clean, "LAB_SECRETS_DIR": str(tmp_path), **env}, clear=True):
        return Settings.load()


GOOD = {"jwks": json.dumps({"keys": []}), "admin_token": "x" * 40, "app_db_password": "a" * 24,
        "ops_db_password": "b" * 24, "auditor_db_password": "c" * 24}


def test_production_needs_every_secret(tmp_path):
    for missing in GOOD:
        folder = tmp_path / missing
        folder.mkdir()
        with pytest.raises(ConfigError, match=missing):
            load_with(folder, {"LAB_ENV": "production"}, {k: v for k, v in GOOD.items() if k != missing})


def test_production_refuses_dev_values_and_short_tokens(tmp_path):
    with pytest.raises(ConfigError, match="development value"):
        load_with(tmp_path, {"LAB_ENV": "production", "LAB_APP_DB_PASSWORD": "app_pw"}, GOOD)
    with pytest.raises(ConfigError, match="too short"):
        load_with(tmp_path, {"LAB_ENV": "production", "LAB_ADMIN_TOKEN": "short"}, GOOD)


def test_secrets_never_show_in_repr(tmp_path):
    s = load_with(tmp_path, {"LAB_ENV": "production"}, GOOD)
    assert "x" * 40 not in repr(s) and "a" * 24 not in repr(s) and "production" in repr(s)


# ---------------------------------------------------------------- against the database

@pytest.fixture(scope="module", autouse=True)
def database():
    if PG:
        bootstrap()


@needs_pg
@pytest.mark.parametrize("check", ALL_CHECKS, ids=lambda c: c.__name__)
def test_secure_app_passes(check):
    with fresh_env("secure") as env:
        f = check(env)
    assert not f.leaked, f.evidence


@needs_pg
@pytest.mark.parametrize("check", ALL_CHECKS, ids=lambda c: c.__name__)
def test_leaky_app_fails(check):
    with fresh_env("leaky") as env:
        f = check(env)
    assert f.leaked, f"check didn't detect the planted problem: {f.evidence}"


@needs_pg
def test_data_inventory_covers_every_tenant_table():
    """Add a table with a tenant_id and forget offboarding: this test goes red."""
    with fresh_env("secure"), psycopg.connect(OWNER_DSN) as conn:
        tables = tenant_tables(conn)
        body = conn.execute("SELECT pg_get_functiondef('offboard_tenant(text)'::regprocedure)").fetchone()[0]
    assert tables == set(DELETED) | set(RETAINED), f"not in the inventory: {tables - set(DELETED) - set(RETAINED)}"
    for t in DELETED:
        assert f"DELETE FROM {t}" in body, f"offboard_tenant() doesn't delete {t}"


@needs_pg
def test_ops_role_can_only_offboard():
    with fresh_env("secure"), psycopg.connect(DEV_OPS_DSN) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT count(*) FROM documents")


@needs_pg
def test_health_endpoints():
    with fresh_env("secure") as env:
        assert env.client.get("/healthz").json() == {"status": "ok"}
        assert env.client.get("/readyz").json() == {"status": "ready"}
