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
