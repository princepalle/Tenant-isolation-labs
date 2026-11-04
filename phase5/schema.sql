-- Phase 5 schema: audit trails. Applied on top of Phase 4, as lab_owner.
--
-- Two tables, on purpose:
--   activity_log  what the LEAKY app uses: an ordinary table. No RLS, the app can edit and
--                 delete rows, nothing detects changes.
--   audit_events  what the SECURE app uses: per-tenant RLS, append-only, and each row
--                 carries a hash of the row before it, so editing history is detectable.
--
-- New role (created in phase5/setup_db.py):
--   auditor   reads every tenant's audit trail (security team), and nothing else.

DROP TABLE IF EXISTS activity_log, audit_events, audit_heads CASCADE;
DROP FUNCTION IF EXISTS audit_append(text, text, text, text, jsonb);

-- ---------------------------------------------------------------- the leaky one
CREATE TABLE activity_log (
    id         bigserial PRIMARY KEY,
    tenant_id  text NOT NULL,
    user_name  text NOT NULL,
    action     text NOT NULL,
    target     text NOT NULL DEFAULT '',
    outcome    text NOT NULL,
    detail     text NOT NULL DEFAULT '',
    created    timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON activity_log TO app_user;
GRANT USAGE ON SEQUENCE activity_log_id_seq TO app_user;

-- ---------------------------------------------------------------- the secure one
CREATE TABLE audit_events (
    id          bigserial PRIMARY KEY,
    tenant_id   text NOT NULL REFERENCES tenants(id),
    user_name   text NOT NULL,
    request_id  text NOT NULL,                 -- joins an audit row to its log lines
    action      text NOT NULL,                 -- e.g. agent.run, document.upload, email.approve
    target      text NOT NULL DEFAULT '',      -- e.g. a document or email id. Never contents.
    outcome     text NOT NULL CHECK (outcome IN ('ok', 'denied', 'blocked')),
    detail      jsonb NOT NULL DEFAULT '{}',   -- metadata only: counts, tool names, token usage
    created     timestamptz NOT NULL,
    prev_hash   text NOT NULL,
    hash        text NOT NULL
);
CREATE INDEX audit_tenant ON audit_events (tenant_id, id);

-- The latest hash per tenant. Locking this row makes concurrent writes take turns,
-- so two requests can't both chain onto the same previous row.
CREATE TABLE audit_heads (tenant_id text PRIMARY KEY REFERENCES tenants(id), last_hash text NOT NULL);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_reads_own ON audit_events FOR SELECT TO app_user
    USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY auditor_reads_all ON audit_events FOR SELECT TO auditor USING (true);

-- The ONLY way to write an audit row. It runs as lab_owner (SECURITY DEFINER), takes the
-- tenant and user from the session (never from arguments), and computes the hash itself.
-- hash = sha256(previous hash | every field of this row)
CREATE FUNCTION audit_append(p_request_id text, p_action text, p_target text, p_outcome text, p_detail jsonb)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    t      text := current_setting('app.tenant_id', true);
    u      text := current_setting('app.user_name', true);
    ts     timestamptz := clock_timestamp();
    prev   text;
    h      text;
    new_id bigint;
BEGIN
    IF coalesce(t, '') = '' THEN
        RAISE EXCEPTION 'audit_append: no tenant in this session';
    END IF;
    INSERT INTO audit_heads VALUES (t, 'genesis') ON CONFLICT DO NOTHING;
    SELECT last_hash INTO prev FROM audit_heads WHERE tenant_id = t FOR UPDATE;
    h := encode(sha256(convert_to(concat_ws('|',
            prev, t, u, p_request_id, p_action, p_target, p_outcome, p_detail::text,
            to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US')), 'UTF8')), 'hex');
    INSERT INTO audit_events (tenant_id, user_name, request_id, action, target, outcome, detail, created, prev_hash, hash)
    VALUES (t, u, p_request_id, p_action, p_target, p_outcome, p_detail, ts, prev, h)
    RETURNING id INTO new_id;
    UPDATE audit_heads SET last_hash = h WHERE tenant_id = t;
    RETURN new_id;
END $$;

-- ---------------------------------------------------------------- grants
REVOKE ALL ON FUNCTION audit_append(text, text, text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_append(text, text, text, text, jsonb) TO app_user;
GRANT SELECT ON audit_events TO app_user;          -- read own tenant's rows (RLS). No INSERT/UPDATE/DELETE.
GRANT SELECT ON audit_events, audit_heads TO auditor;
