-- Phase 2 schema. Runs as lab_owner (the role that owns the tables).
-- Safe to re-run: it drops and rebuilds everything.
--
-- The two roles (created in setup_db.py):
--   lab_owner  owns the tables, runs migrations and seeding. BYPASSRLS. The app NEVER uses it.
--   app_user   what the web app connects as. NOBYPASSRLS, owns nothing, so RLS always applies.

DROP TABLE IF EXISTS messages, conversations, documents, users, tenants CASCADE;
DROP SEQUENCE IF EXISTS conv_seq;
DROP FUNCTION IF EXISTS auth_user(text);

-- ---------------------------------------------------------------- tables

CREATE TABLE tenants (id text PRIMARY KEY);

CREATE TABLE users (
    token_hash text PRIMARY KEY,          -- sha256 of the token, never the token itself
    name       text NOT NULL,
    tenant_id  text NOT NULL REFERENCES tenants(id)
);

-- tenant_id defaults to the session's tenant, so app code never has to pass it.
CREATE TABLE documents (
    id         bigserial PRIMARY KEY,
    tenant_id  text NOT NULL REFERENCES tenants(id) DEFAULT current_setting('app.tenant_id', true),
    doc_type   text NOT NULL,
    title      text NOT NULL,
    created    date NOT NULL DEFAULT current_date,
    body       text NOT NULL,
    file_name  text,
    embedding  vector(256)                -- pgvector column for semantic search
);
CREATE INDEX documents_tenant ON documents (tenant_id);
CREATE INDEX documents_embedding ON documents USING hnsw (embedding vector_cosine_ops);

CREATE SEQUENCE conv_seq;  -- only the leaky app uses this, to make guessable chat IDs

CREATE TABLE conversations (
    id         text PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id  text NOT NULL REFERENCES tenants(id) DEFAULT current_setting('app.tenant_id', true),
    user_name  text NOT NULL DEFAULT current_setting('app.user_name', true),
    created    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE messages (
    id              bigserial PRIMARY KEY,
    conversation_id text NOT NULL REFERENCES conversations(id),
    tenant_id       text NOT NULL REFERENCES tenants(id) DEFAULT current_setting('app.tenant_id', true),
    role            text NOT NULL CHECK (role IN ('user', 'assistant')),
    content         text NOT NULL
);

-- ---------------------------------------------------------------- row-level security
-- ENABLE turns RLS on. FORCE makes it apply to the table owner too (unless the owner
-- has BYPASSRLS, which lab_owner does on purpose, for seeding).
--
-- current_setting('app.tenant_id', true) is NULL or '' when no tenant is set, which
-- matches no rows. RLS fails CLOSED: forget to set the tenant and you see nothing.

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON documents
    USING      (tenant_id = current_setting('app.tenant_id', true))   -- which rows you can SEE
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));  -- which rows you can WRITE

-- Chats are private to one user, not just one tenant.
ALTER TABLE conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE conversations FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_only ON conversations
    USING      (tenant_id = current_setting('app.tenant_id', true)
                AND user_name = current_setting('app.user_name', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                AND user_name = current_setting('app.user_name', true));

-- A message is visible only if its conversation is. The subquery is itself
-- filtered by the conversations policy, so the rule is inherited.
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages FORCE ROW LEVEL SECURITY;
CREATE POLICY via_conversation ON messages
    USING      (tenant_id = current_setting('app.tenant_id', true)
                AND conversation_id IN (SELECT id FROM conversations))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                AND conversation_id IN (SELECT id FROM conversations));

-- users: RLS on with NO policy means "deny everything". The app also gets no grant.
-- The only way in is the auth_user() function below.
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------- authentication
-- Before login we don't know the tenant, so RLS would hide every user row.
-- SECURITY DEFINER runs this one function with lab_owner's rights. It's a narrow door:
-- give it a token hash, get back one name and tenant. Nothing else.
CREATE FUNCTION auth_user(p_token_hash text)
RETURNS TABLE (name text, tenant_id text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp       -- always pin search_path on SECURITY DEFINER
AS $$ SELECT name, tenant_id FROM users WHERE token_hash = p_token_hash $$;

-- ---------------------------------------------------------------- grants for app_user
REVOKE ALL ON FUNCTION auth_user(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_user(text) TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON documents, conversations, messages TO app_user;
GRANT SELECT ON tenants TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_user;
-- Note: no grant on `users` at all.
