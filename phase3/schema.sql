-- Phase 3 schema: plans, quotas and a usage ledger. Applied ON TOP of phase2/schema.sql,
-- as lab_owner. Safe to re-run.
--
-- New role (created in phase3/setup_db.py):
--   billing_reader  The billing/finance service. Can read every tenant's USAGE, but has no
--                   grant on documents, conversations or messages. Least privilege: the
--                   service that sends invoices doesn't need to read patient notes.

DROP TABLE IF EXISTS usage_events, plans CASCADE;

-- ---------------------------------------------------------------- plans
CREATE TABLE plans (
    name                 text PRIMARY KEY,
    requests_per_minute  int    NOT NULL,   -- rate limit: protects everyone from one noisy tenant
    monthly_token_quota  bigint NOT NULL    -- spend limit: protects you (and them) from runaway cost
);
INSERT INTO plans VALUES
    ('free',        5,    20000),
    ('pro',        30,   500000),
    ('enterprise', 120, 5000000);

ALTER TABLE tenants ADD COLUMN plan text NOT NULL DEFAULT 'free' REFERENCES plans(name);
UPDATE tenants SET plan = 'pro'        WHERE id = 'hospital';
UPDATE tenants SET plan = 'enterprise' WHERE id = 'bank';
-- lawfirm stays on 'free'

-- In Phase 2 every tenant could read the whole tenants table. Harmless? Now it holds each
-- customer's plan, which is business-sensitive ("the bank pays for enterprise").
-- So tenants get RLS too: you see your own row only.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY own_tenant  ON tenants FOR SELECT TO app_user       USING (id = current_setting('app.tenant_id', true));
CREATE POLICY billing_all ON tenants FOR SELECT TO billing_reader USING (true);

-- ---------------------------------------------------------------- usage ledger
-- One row per model call. This is what invoices, quotas and cost dashboards are built from.
CREATE TABLE usage_events (
    id             bigserial PRIMARY KEY,
    tenant_id      text NOT NULL REFERENCES tenants(id) DEFAULT current_setting('app.tenant_id', true),
    user_name      text NOT NULL DEFAULT current_setting('app.user_name', true),
    created        timestamptz NOT NULL DEFAULT now(),
    model          text NOT NULL,
    input_tokens   int  NOT NULL CHECK (input_tokens >= 0),
    output_tokens  int  NOT NULL CHECK (output_tokens >= 0),
    cost_usd       numeric(12, 6) NOT NULL
);
CREATE INDEX usage_tenant_month ON usage_events (tenant_id, created);

ALTER TABLE usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_events FORCE ROW LEVEL SECURITY;
-- Tenants see (and the app writes) only their own usage...
CREATE POLICY tenant_usage ON usage_events TO app_user
    USING      (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
-- ...and billing sees everyone's, read-only.
CREATE POLICY billing_read ON usage_events FOR SELECT TO billing_reader USING (true);

-- ---------------------------------------------------------------- grants
GRANT SELECT ON plans TO app_user, billing_reader;
-- Append-only for the app: no UPDATE, no DELETE. Even with SQL injection, a tenant
-- can't erase its own usage to dodge the bill or reset its quota.
GRANT SELECT, INSERT ON usage_events TO app_user;
GRANT USAGE ON SEQUENCE usage_events_id_seq TO app_user;
GRANT SELECT ON usage_events, tenants TO billing_reader;
-- Note: billing_reader gets nothing on documents, conversations or messages.
