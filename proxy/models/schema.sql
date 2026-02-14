-- ShieldAI Security Proxy — database schema

CREATE TABLE IF NOT EXISTS customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    plan VARCHAR(50) DEFAULT 'starter',
    api_key_hash VARCHAR(255) NOT NULL,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    origin_url VARCHAR(512) NOT NULL,
    domain VARCHAR(255) UNIQUE NOT NULL,
    enabled_features JSONB DEFAULT '{"waf": true, "error_sanitization": true, "session_validation": true, "audit_logging": true, "rate_limiting": true, "security_headers": true, "bot_protection": false}',
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_apps_domain ON apps(domain);
CREATE INDEX IF NOT EXISTS idx_apps_customer_id ON apps(customer_id);

-- Backfill Sprint 2 feature flags for existing rows
UPDATE apps
SET enabled_features = enabled_features
    || '{"rate_limiting": true, "security_headers": true, "bot_protection": false}'::jsonb
WHERE NOT (enabled_features ? 'rate_limiting');

-- Sprint 5: Audit logging
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    app_id VARCHAR(255) DEFAULT '',
    request_id VARCHAR(64) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    method VARCHAR(10) NOT NULL,
    path VARCHAR(2048) NOT NULL,
    status_code SMALLINT NOT NULL,
    duration_ms REAL NOT NULL,
    client_ip VARCHAR(45) NOT NULL DEFAULT '',
    user_agent VARCHAR(1024) DEFAULT '',
    country VARCHAR(8) DEFAULT '',
    user_id VARCHAR(255) DEFAULT '',
    action VARCHAR(64) NOT NULL DEFAULT 'request',
    blocked BOOLEAN NOT NULL DEFAULT FALSE
);

-- Prevent empty tenant_id — ensures RLS cannot match unset GUC (empty string)
DO $$ BEGIN
    ALTER TABLE audit_logs ADD CONSTRAINT chk_tenant_id_nonempty CHECK (tenant_id != '');
EXCEPTION
    WHEN duplicate_object THEN NULL;  -- constraint already exists
END $$;

CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON audit_logs (tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_path ON audit_logs (tenant_id, path);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_status ON audit_logs (tenant_id, status_code);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_action ON audit_logs (tenant_id, action);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs (timestamp DESC);

-- Sprint 5: Webhook configurations for real-time event streaming
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(2048) NOT NULL,
    provider VARCHAR(32) NOT NULL DEFAULT 'custom',
    events TEXT[] NOT NULL DEFAULT '{}',
    secret VARCHAR(255) DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_webhooks_customer_id ON webhooks(customer_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_enabled ON webhooks(enabled) WHERE enabled = TRUE;

-- Sprint 6: Row-Level Security for tenant isolation (SHIELD-25)
-- Create restricted application role (NOLOGIN — only via SET ROLE)
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shieldai_app') THEN
        CREATE ROLE shieldai_app NOLOGIN;
    END IF;
END $$;

-- Grant app role to current user (enables SET ROLE)
GRANT shieldai_app TO CURRENT_USER;

-- Grant table permissions to app role (DML only — no DDL, no TRUNCATE)
GRANT SELECT, INSERT, UPDATE, DELETE ON customers TO shieldai_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON apps TO shieldai_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_logs TO shieldai_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON webhooks TO shieldai_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO shieldai_app;

-- Explicitly revoke dangerous privileges from app role
REVOKE TRUNCATE ON customers, apps, audit_logs, webhooks FROM shieldai_app;
REVOKE REFERENCES ON customers, apps, audit_logs, webhooks FROM shieldai_app;
REVOKE TRIGGER ON customers, apps, audit_logs, webhooks FROM shieldai_app;

-- GUC protection: prevent app role from directly manipulating tenant context.
-- On PostgreSQL 15+ this prevents SET or set_config() by the app role.
-- The owner role (which executes tenant_transaction) sets the GUC BEFORE
-- switching to shieldai_app via SET LOCAL ROLE, so this is safe.
DO $$ BEGIN
    -- pg_catalog.has_parameter_privilege requires PG15+; guard against older versions.
    IF current_setting('server_version_num')::int >= 150000 THEN
        EXECUTE 'REVOKE SET ON PARAMETER "app.current_tenant_id" FROM shieldai_app';
    END IF;
EXCEPTION
    WHEN undefined_object OR insufficient_privilege THEN
        -- GUC not yet registered or PG < 15 — skip silently.
        NULL;
END $$;

-- Enable RLS on all tenant-scoped tables
ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;

-- RLS policies: DROP IF EXISTS + CREATE for idempotency
-- customers: id IS the tenant
DROP POLICY IF EXISTS tenant_isolation ON customers;
CREATE POLICY tenant_isolation ON customers
    USING (id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (id = current_setting('app.current_tenant_id', true)::uuid);

-- apps: customer_id = tenant
DROP POLICY IF EXISTS tenant_isolation ON apps;
CREATE POLICY tenant_isolation ON apps
    USING (customer_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (customer_id = current_setting('app.current_tenant_id', true)::uuid);

-- audit_logs: tenant_id is VARCHAR (no UUID cast)
-- Extra guard: reject empty GUC to prevent matching rows with tenant_id = ''
DROP POLICY IF EXISTS tenant_isolation ON audit_logs;
CREATE POLICY tenant_isolation ON audit_logs
    USING (tenant_id = current_setting('app.current_tenant_id', true)
        AND current_setting('app.current_tenant_id', true) != '')
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)
        AND current_setting('app.current_tenant_id', true) != '');

-- webhooks: customer_id = tenant
DROP POLICY IF EXISTS tenant_isolation ON webhooks;
CREATE POLICY tenant_isolation ON webhooks
    USING (customer_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (customer_id = current_setting('app.current_tenant_id', true)::uuid);

-- Sprint 8: Customer domain onboarding (SHIELD-41)
CREATE TABLE IF NOT EXISTS onboardings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    customer_domain VARCHAR(253) NOT NULL,
    origin_url VARCHAR(2048) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'certificate_pending',
    acm_certificate_arn VARCHAR(512) DEFAULT '',
    validation_cname_name VARCHAR(512) DEFAULT '',
    validation_cname_value VARCHAR(512) DEFAULT '',
    distribution_tenant_id VARCHAR(512) DEFAULT '',
    cloudfront_cname VARCHAR(512) DEFAULT '',
    error_message VARCHAR(1024) DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Prevent duplicate active onboardings for the same domain
CREATE UNIQUE INDEX IF NOT EXISTS idx_onboardings_domain_active
    ON onboardings(customer_domain) WHERE status NOT IN ('offboarded', 'failed');

CREATE INDEX IF NOT EXISTS idx_onboardings_customer_id ON onboardings(customer_id);
CREATE INDEX IF NOT EXISTS idx_onboardings_status ON onboardings(status);

-- Status constraint: only valid lifecycle states
DO $$ BEGIN
    ALTER TABLE onboardings ADD CONSTRAINT chk_onboarding_status
        CHECK (status IN ('certificate_pending', 'certificate_validated', 'tenant_created', 'active', 'failed', 'offboarded'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- Grant DML to shieldai_app role
GRANT SELECT, INSERT, UPDATE, DELETE ON onboardings TO shieldai_app;

-- Revoke dangerous privileges
REVOKE TRUNCATE ON onboardings FROM shieldai_app;
REVOKE REFERENCES ON onboardings FROM shieldai_app;
REVOKE TRIGGER ON onboardings FROM shieldai_app;

-- Enable RLS
ALTER TABLE onboardings ENABLE ROW LEVEL SECURITY;

-- RLS policy: customer_id = tenant
DROP POLICY IF EXISTS tenant_isolation ON onboardings;
CREATE POLICY tenant_isolation ON onboardings
    USING (customer_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (customer_id = current_setting('app.current_tenant_id', true)::uuid);
