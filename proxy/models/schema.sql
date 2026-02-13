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
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
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

CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON audit_logs (tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_path ON audit_logs (tenant_id, path);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_status ON audit_logs (tenant_id, status_code);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_action ON audit_logs (tenant_id, action);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs (timestamp DESC);

-- Sprint 5: Webhook configurations for real-time event streaming
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
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
