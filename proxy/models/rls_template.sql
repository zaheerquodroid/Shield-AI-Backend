-- ShieldAI RLS Template — apply to your own PostgreSQL tables
--
-- This template enables Row-Level Security so that each tenant can only
-- see its own rows.  The proxy sets the GUC ``app.current_tenant_id``
-- per-transaction via:
--
--     SELECT set_config('app.current_tenant_id', $1, true)
--
-- Replace {table_name} with your table and {tenant_column} with the column
-- that holds the tenant identifier (e.g. ``tenant_id``, ``customer_id``).
--
-- For UUID columns use the ``::uuid`` cast.  For TEXT/VARCHAR columns
-- remove it.

-- 1. Enable RLS on the table
ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY;

-- 2. Drop existing policy (for idempotency)
DROP POLICY IF EXISTS tenant_isolation ON {table_name};

-- 3. Create the isolation policy
--    USING  → filters SELECT / UPDATE / DELETE
--    WITH CHECK → filters INSERT / UPDATE
CREATE POLICY tenant_isolation ON {table_name}
    USING ({tenant_column} = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK ({tenant_column} = current_setting('app.current_tenant_id', true)::uuid);

-- For TEXT/VARCHAR tenant columns, remove the ::uuid cast:
--
-- CREATE POLICY tenant_isolation ON {table_name}
--     USING ({tenant_column} = current_setting('app.current_tenant_id', true))
--     WITH CHECK ({tenant_column} = current_setting('app.current_tenant_id', true));
