-- Phase 4 schema: an outbox for emails the agent sends. Applied on top of Phase 3, as lab_owner.
-- No real email is ever sent. A row with status 'sent' is what WOULD have left the building.

DROP TABLE IF EXISTS outbox CASCADE;

CREATE TABLE outbox (
    id         bigserial PRIMARY KEY,
    tenant_id  text NOT NULL REFERENCES tenants(id) DEFAULT current_setting('app.tenant_id', true),
    user_name  text NOT NULL DEFAULT current_setting('app.user_name', true),  -- whose agent drafted it
    recipient  text NOT NULL,
    subject    text NOT NULL,
    body       text NOT NULL,
    status     text NOT NULL CHECK (status IN ('pending_approval', 'sent')),
    approved_by text,
    created    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_outbox ON outbox
    USING      (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT, UPDATE ON outbox TO app_user;
GRANT USAGE ON SEQUENCE outbox_id_seq TO app_user;
