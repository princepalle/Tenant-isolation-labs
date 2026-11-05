-- Phase 7 schema: membership checks and tenant offboarding. Applied on top of Phase 5, as lab_owner.
--
-- New role (created in phase7/setup_db.py):
--   platform_ops   may run offboard_tenant() and nothing else. Not the app, not the owner.

DROP FUNCTION IF EXISTS auth_member(text, text);
DROP FUNCTION IF EXISTS offboard_tenant(text);

ALTER TABLE users   ADD COLUMN IF NOT EXISTS active boolean NOT NULL DEFAULT true;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'offboarded'));

-- Called on EVERY request after the JWT checks out. A token is valid for minutes;
-- deactivating a user or offboarding a tenant takes effect on the very next request.
CREATE FUNCTION auth_member(p_name text, p_tenant text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1 FROM users u JOIN tenants t ON t.id = u.tenant_id
        WHERE u.name = p_name AND u.tenant_id = p_tenant AND u.active AND t.status = 'active'
    )
$$;

-- Offboarding: delete everything the customer owns, keep only what we're required to keep.
-- The list of tables here MUST match phase7/offboarding.py. A test compares both against
-- every table that has a tenant_id column, so a new table can't be silently forgotten.
CREATE FUNCTION offboard_tenant(p_tenant text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    result jsonb := '{}';
    n      int;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM tenants WHERE id = p_tenant AND status = 'active') THEN
        RAISE EXCEPTION 'no active tenant %', p_tenant;
    END IF;
    -- Children before parents (foreign keys).
    DELETE FROM messages      WHERE tenant_id = p_tenant; GET DIAGNOSTICS n = ROW_COUNT; result := result || jsonb_build_object('messages', n);
    DELETE FROM conversations WHERE tenant_id = p_tenant; GET DIAGNOSTICS n = ROW_COUNT; result := result || jsonb_build_object('conversations', n);
    DELETE FROM outbox        WHERE tenant_id = p_tenant; GET DIAGNOSTICS n = ROW_COUNT; result := result || jsonb_build_object('outbox', n);
    DELETE FROM documents     WHERE tenant_id = p_tenant; GET DIAGNOSTICS n = ROW_COUNT; result := result || jsonb_build_object('documents', n);
    DELETE FROM activity_log  WHERE tenant_id = p_tenant; GET DIAGNOSTICS n = ROW_COUNT; result := result || jsonb_build_object('activity_log', n);
    DELETE FROM users         WHERE tenant_id = p_tenant; GET DIAGNOSTICS n = ROW_COUNT; result := result || jsonb_build_object('users', n);

    -- Retained: invoices must be reproducible for years, so usage stays, but WHO used it
    -- becomes a pseudonym. (audit_events is retained as-is; see the README for why that's hard.)
    UPDATE usage_events SET user_name = 'erased-' || left(md5(user_name), 8) WHERE tenant_id = p_tenant;
    GET DIAGNOSTICS n = ROW_COUNT; result := result || jsonb_build_object('usage_events_pseudonymized', n);

    UPDATE tenants SET status = 'offboarded' WHERE id = p_tenant;
    RETURN result;
END $$;

REVOKE ALL ON FUNCTION auth_member(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION offboard_tenant(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_member(text, text) TO app_user;
GRANT EXECUTE ON FUNCTION offboard_tenant(text) TO platform_ops;
