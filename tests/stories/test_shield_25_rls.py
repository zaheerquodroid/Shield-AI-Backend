"""Story-level acceptance tests for SHIELD-25: Row-Level Security & Tenant Isolation."""

from __future__ import annotations

import inspect
import os
import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import proxy.store.postgres as pg_store
from proxy.store.postgres import StoreUnavailable, get_pool, run_migrations
from proxy.store.rls import RLS_APP_ROLE, tenant_transaction, validate_tenant_id
from proxy.tools.discover_tenant_tables import (
    discover_tenant_tables,
    generate_rls_migration,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_VALID_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_VALID_UUID_2 = "11111111-2222-3333-4444-555555555555"

_SCHEMA_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, os.pardir, "proxy", "models"
)
_SCHEMA_SQL_PATH = os.path.join(_SCHEMA_DIR, "schema.sql")
_RLS_TEMPLATE_PATH = os.path.join(_SCHEMA_DIR, "rls_template.sql")


def _read_schema_sql() -> str:
    with open(_SCHEMA_SQL_PATH) as f:
        return f.read()


def _read_rls_template() -> str:
    with open(_RLS_TEMPLATE_PATH) as f:
        return f.read()


def _make_pool_mock():
    """Create a mock pool with acquire/transaction context-manager chain."""
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value=None)
    mock_conn.fetchval = AsyncMock(return_value=None)
    mock_conn.fetch = AsyncMock(return_value=[])

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    mock_tx = AsyncMock()
    mock_tx.__aenter__ = AsyncMock(return_value=None)
    mock_tx.__aexit__ = AsyncMock(return_value=False)
    mock_conn.transaction = MagicMock(return_value=mock_tx)

    pool = MagicMock()
    pool.acquire = MagicMock(return_value=mock_ctx)

    return pool, mock_conn


# ---------------------------------------------------------------------------
# AC1: Database Proxy — pool init, tenant_transaction, admin bypass,
#       StoreUnavailable
# ---------------------------------------------------------------------------


class TestAC1_DatabaseProxy:
    """AC1: Database proxy layer provides both tenant-scoped and admin access."""

    def test_get_pool_returns_module_pool(self):
        """get_pool() returns the module-level _pool variable."""
        sentinel = object()
        old = pg_store._pool
        try:
            pg_store._pool = sentinel
            assert get_pool() is sentinel
        finally:
            pg_store._pool = old

    @pytest.mark.asyncio
    async def test_tenant_transaction_wraps_connection_with_rls(self):
        """tenant_transaction acquires from pool, starts a transaction, and
        executes SET LOCAL ROLE + set_config before yielding the connection."""
        pool, mock_conn = _make_pool_mock()
        old = pg_store._pool
        try:
            pg_store._pool = pool
            async with tenant_transaction(_VALID_UUID) as conn:
                assert conn is mock_conn
            # At least two execute calls: SET LOCAL ROLE and set_config
            assert mock_conn.execute.await_count >= 2
        finally:
            pg_store._pool = old

    @pytest.mark.asyncio
    async def test_run_migrations_uses_pool_directly(self):
        """run_migrations reads schema.sql and executes it via pool.acquire
        (superuser path, no RLS context)."""
        pool, mock_conn = _make_pool_mock()
        old = pg_store._pool
        try:
            pg_store._pool = pool
            await run_migrations()
            pool.acquire.assert_called()
            # run_migrations should NOT call tenant_transaction — it uses
            # pool.acquire directly (owner role, bypasses RLS).
            # Note: schema.sql itself may mention SET LOCAL ROLE in comments,
            # which is fine — what matters is the code path.
            execute_args = [str(c) for c in mock_conn.execute.call_args_list]
            # No standalone SET LOCAL ROLE call (exclude schema SQL which is one big execute)
            standalone_set_role = [
                c for c in execute_args
                if "SET LOCAL ROLE" in c and "CREATE TABLE" not in c and "REVOKE" not in c
            ]
            assert not standalone_set_role, "run_migrations should not SET LOCAL ROLE"
        finally:
            pg_store._pool = old

    @pytest.mark.asyncio
    async def test_store_unavailable_when_pool_none(self):
        """tenant_transaction raises StoreUnavailable when pool is None."""
        old = pg_store._pool
        try:
            pg_store._pool = None
            with pytest.raises(StoreUnavailable):
                async with tenant_transaction(_VALID_UUID):
                    pass  # pragma: no cover
        finally:
            pg_store._pool = old


# ---------------------------------------------------------------------------
# AC2: SET LOCAL ROLE + set_config — correct SQL, ordering, parameterization
# ---------------------------------------------------------------------------


class TestAC2_SetTenantId:
    """AC2: tenant_transaction sets the RLS role and GUC correctly."""

    @pytest.mark.asyncio
    async def test_set_local_role_executed(self):
        """SET LOCAL ROLE shieldai_app is executed on the connection."""
        pool, mock_conn = _make_pool_mock()
        old = pg_store._pool
        try:
            pg_store._pool = pool
            async with tenant_transaction(_VALID_UUID):
                pass
            calls = [c.args[0] for c in mock_conn.execute.call_args_list]
            assert any(
                "SET LOCAL ROLE" in c and RLS_APP_ROLE in c for c in calls
            ), f"Expected SET LOCAL ROLE {RLS_APP_ROLE} in calls: {calls}"
        finally:
            pg_store._pool = old

    @pytest.mark.asyncio
    async def test_set_config_executed_with_tenant_id(self):
        """set_config('app.current_tenant_id', $1, true) is called with the
        validated tenant_id."""
        pool, mock_conn = _make_pool_mock()
        old = pg_store._pool
        try:
            pg_store._pool = pool
            async with tenant_transaction(_VALID_UUID):
                pass
            calls = mock_conn.execute.call_args_list
            set_config_call = [
                c for c in calls if "set_config" in str(c.args[0])
            ]
            assert len(set_config_call) == 1
            # The tenant_id should be passed as a parameter
            assert set_config_call[0].args[1] == _VALID_UUID
        finally:
            pg_store._pool = old

    @pytest.mark.asyncio
    async def test_set_role_before_set_config(self):
        """SET LOCAL ROLE is executed before set_config (order matters for
        security — the restricted role must be active before any tenant
        context is established)."""
        pool, mock_conn = _make_pool_mock()
        old = pg_store._pool
        try:
            pg_store._pool = pool
            async with tenant_transaction(_VALID_UUID):
                pass
            calls = [c.args[0] for c in mock_conn.execute.call_args_list]
            role_idx = next(
                i for i, c in enumerate(calls) if "SET LOCAL ROLE" in c
            )
            config_idx = next(
                i for i, c in enumerate(calls) if "set_config" in c
            )
            assert role_idx < config_idx, (
                f"SET LOCAL ROLE (index {role_idx}) must come before "
                f"set_config (index {config_idx})"
            )
        finally:
            pg_store._pool = old

    @pytest.mark.asyncio
    async def test_set_config_uses_parameterized_query(self):
        """set_config query uses $1 placeholder, not string formatting, to
        prevent SQL injection via tenant_id."""
        pool, mock_conn = _make_pool_mock()
        old = pg_store._pool
        try:
            pg_store._pool = pool
            async with tenant_transaction(_VALID_UUID):
                pass
            calls = mock_conn.execute.call_args_list
            set_config_call = [
                c for c in calls if "set_config" in str(c.args[0])
            ]
            sql = set_config_call[0].args[0]
            assert "$1" in sql, f"Expected $1 placeholder in: {sql}"
            # The actual tenant_id value must NOT appear in the SQL string
            assert _VALID_UUID not in sql
        finally:
            pg_store._pool = old

    @pytest.mark.asyncio
    async def test_set_config_transaction_local_true(self):
        """set_config's third argument is true (transaction-local), ensuring
        the GUC resets when the transaction ends."""
        pool, mock_conn = _make_pool_mock()
        old = pg_store._pool
        try:
            pg_store._pool = pool
            async with tenant_transaction(_VALID_UUID):
                pass
            calls = mock_conn.execute.call_args_list
            set_config_call = [
                c for c in calls if "set_config" in str(c.args[0])
            ]
            sql = set_config_call[0].args[0]
            # Third argument to set_config must be 'true'
            assert "true" in sql.lower(), (
                f"Expected 'true' as third arg in set_config: {sql}"
            )
        finally:
            pg_store._pool = old


# ---------------------------------------------------------------------------
# AC3: Tenant ID validation — UUID format only, flows through to set_config
# ---------------------------------------------------------------------------


class TestAC3_TenantFromContext:
    """AC3: validate_tenant_id accepts only valid UUIDs and the value flows
    through to set_config."""

    def test_accepts_valid_uuid(self):
        """validate_tenant_id returns the normalised UUID for valid input."""
        result = validate_tenant_id(_VALID_UUID)
        assert result == _VALID_UUID

    def test_accepts_uppercase_uuid(self):
        """validate_tenant_id normalises uppercase UUIDs to lowercase."""
        upper = _VALID_UUID.upper()
        assert validate_tenant_id(upper) == _VALID_UUID

    @pytest.mark.parametrize(
        "bad_id",
        [
            "not-a-uuid",
            "1234",
            "",
            "ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ",
            "aaaaaaaa-bbbb-cccc-dddd",  # too short
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee-extra",  # too long
            "'; DROP TABLE customers; --",  # SQLi attempt
        ],
    )
    def test_rejects_non_uuid_strings(self, bad_id):
        """validate_tenant_id raises ValueError for non-UUID strings."""
        with pytest.raises(ValueError):
            validate_tenant_id(bad_id)

    @pytest.mark.asyncio
    async def test_tenant_id_flows_to_set_config(self):
        """The validated tenant_id value is passed to set_config as the second
        positional argument."""
        pool, mock_conn = _make_pool_mock()
        old = pg_store._pool
        try:
            pg_store._pool = pool
            async with tenant_transaction(_VALID_UUID.upper()):
                pass
            calls = mock_conn.execute.call_args_list
            set_config_call = [
                c for c in calls if "set_config" in str(c.args[0])
            ]
            # The normalised (lowercase) UUID should be passed
            assert set_config_call[0].args[1] == _VALID_UUID
        finally:
            pg_store._pool = old


# ---------------------------------------------------------------------------
# AC4: RLS Policies — schema.sql contains correct policies for all tables
# ---------------------------------------------------------------------------


class TestAC4_RLSPolicies:
    """AC4: schema.sql defines RLS policies on all five tenant-scoped tables."""

    @pytest.fixture(autouse=True)
    def _load_schema(self):
        self.schema = _read_schema_sql()

    @pytest.mark.parametrize(
        "table_name",
        ["customers", "apps", "audit_logs", "webhooks", "onboardings"],
    )
    def test_enable_rls_on_all_tables(self, table_name):
        """Each tenant-scoped table has ALTER TABLE ... ENABLE ROW LEVEL SECURITY."""
        pattern = rf"ALTER\s+TABLE\s+{table_name}\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY"
        assert re.search(pattern, self.schema, re.IGNORECASE), (
            f"Missing ENABLE ROW LEVEL SECURITY for {table_name}"
        )

    @pytest.mark.parametrize(
        "table_name",
        ["customers", "apps", "audit_logs", "webhooks", "onboardings"],
    )
    def test_create_policy_on_all_tables(self, table_name):
        """Each table has a CREATE POLICY tenant_isolation statement."""
        pattern = rf"CREATE\s+POLICY\s+tenant_isolation\s+ON\s+{table_name}"
        assert re.search(pattern, self.schema, re.IGNORECASE), (
            f"Missing CREATE POLICY tenant_isolation ON {table_name}"
        )

    def test_policies_use_current_setting_with_true(self):
        """All policies use current_setting('app.current_tenant_id', true)
        — the second argument 'true' makes it NULL-safe instead of raising
        an error when the GUC is not set."""
        # Find all current_setting calls in policies
        matches = re.findall(
            r"current_setting\(\s*'app\.current_tenant_id'\s*,\s*(\w+)\s*\)",
            self.schema,
        )
        assert len(matches) >= 5, (
            f"Expected at least 5 current_setting calls, found {len(matches)}"
        )
        for m in matches:
            assert m == "true", f"Expected 'true' but got '{m}'"

    def test_with_check_clauses_present(self):
        """Every tenant_isolation policy has a WITH CHECK clause to prevent
        cross-tenant INSERT and UPDATE operations."""
        # For each CREATE POLICY, find the WITH CHECK
        policy_blocks = re.findall(
            r"CREATE\s+POLICY\s+tenant_isolation\s+ON\s+\w+.*?;",
            self.schema,
            re.DOTALL | re.IGNORECASE,
        )
        assert len(policy_blocks) == 5, (
            f"Expected 5 policy blocks, found {len(policy_blocks)}"
        )
        for block in policy_blocks:
            assert "WITH CHECK" in block, (
                f"Missing WITH CHECK in policy: {block[:80]}..."
            )

    def test_audit_logs_uses_text_comparison(self):
        """audit_logs policy compares tenant_id as text (no ::uuid cast)
        because the tenant_id column is VARCHAR, not UUID."""
        # Extract the audit_logs policy block
        match = re.search(
            r"CREATE\s+POLICY\s+tenant_isolation\s+ON\s+audit_logs\s+.*?;",
            self.schema,
            re.DOTALL | re.IGNORECASE,
        )
        assert match, "audit_logs policy not found"
        policy = match.group(0)
        # Should NOT have ::uuid cast
        assert "::uuid" not in policy, (
            f"audit_logs policy should not cast to uuid: {policy}"
        )

    def test_customers_policy_uses_id_column(self):
        """customers policy uses 'id' column (not 'customer_id') because
        for the customers table, the row's own id IS the tenant."""
        match = re.search(
            r"CREATE\s+POLICY\s+tenant_isolation\s+ON\s+customers\s+.*?;",
            self.schema,
            re.DOTALL | re.IGNORECASE,
        )
        assert match, "customers policy not found"
        policy = match.group(0)
        # USING clause should reference 'id =' not 'customer_id ='
        assert re.search(r"USING\s*\(\s*id\s*=", policy), (
            f"customers USING clause should use 'id' column: {policy}"
        )


# ---------------------------------------------------------------------------
# AC5: Superuser Bypass — admin operations use pool directly, no SET ROLE
# ---------------------------------------------------------------------------


class TestAC5_SuperuserBypass:
    """AC5: Administrative operations bypass RLS by using pool.acquire directly."""

    def test_run_migrations_no_tenant_transaction(self):
        """run_migrations uses _pool.acquire() directly — its source code
        does not reference tenant_transaction."""
        src = inspect.getsource(run_migrations)
        assert "tenant_transaction" not in src
        assert "_pool.acquire" in src or "pool.acquire" in src

    def test_get_all_apps_no_tenant_transaction(self):
        """get_all_apps uses _pool.acquire() directly — no RLS filtering so
        the admin can see all apps across all tenants."""
        from proxy.store.postgres import get_all_apps

        src = inspect.getsource(get_all_apps)
        assert "tenant_transaction" not in src
        assert "_pool.acquire" in src or "pool.acquire" in src

    def test_create_customer_no_tenant_transaction(self):
        """create_customer uses _pool.acquire() directly — a new customer
        cannot be created inside an RLS context because the tenant doesn't
        exist yet."""
        from proxy.store.postgres import create_customer

        src = inspect.getsource(create_customer)
        assert "tenant_transaction" not in src
        assert "_pool.acquire" in src or "pool.acquire" in src

    @pytest.mark.asyncio
    async def test_admin_webhook_get_uses_pool_directly(self):
        """get_webhook with customer_id=None uses pool.acquire directly
        (bypasses RLS)."""
        from proxy.store.webhooks import get_webhook

        src = inspect.getsource(get_webhook)
        # The function has two code paths: customer_id is not None -> tenant_transaction
        # customer_id is None (else branch) -> pool.acquire
        assert "tenant_transaction" in src, "Should use tenant_transaction for scoped path"
        assert "pool.acquire" in src, "Should use pool.acquire for admin path"


# ---------------------------------------------------------------------------
# AC6: Framework-Agnostic — RLS template + discover tool
# ---------------------------------------------------------------------------


class TestAC6_FrameworkAgnostic:
    """AC6: RLS template and discovery tool allow any PostgreSQL app to adopt
    tenant isolation."""

    def test_rls_template_file_exists(self):
        """rls_template.sql exists on disk."""
        assert os.path.isfile(_RLS_TEMPLATE_PATH), (
            f"rls_template.sql not found at {_RLS_TEMPLATE_PATH}"
        )

    def test_rls_template_contains_alter_table(self):
        """rls_template.sql uses standard PostgreSQL ALTER TABLE syntax."""
        template = _read_rls_template()
        assert "ALTER TABLE" in template
        assert "ENABLE ROW LEVEL SECURITY" in template

    def test_rls_template_contains_create_policy(self):
        """rls_template.sql includes CREATE POLICY with USING and WITH CHECK."""
        template = _read_rls_template()
        assert "CREATE POLICY" in template
        assert "USING" in template
        assert "WITH CHECK" in template

    @pytest.mark.asyncio
    async def test_discover_tenant_tables_returns_list_of_dicts(self):
        """discover_tenant_tables queries information_schema and returns
        a list of dicts with table_name and column_name keys."""
        mock_row_1 = {
            "table_name": "audit_logs",
            "column_name": "tenant_id",
            "data_type": "character varying",
        }
        mock_row_2 = {
            "table_name": "apps",
            "column_name": "customer_id",
            "data_type": "uuid",
        }

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[mock_row_1, mock_row_2])

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        pool = MagicMock()
        pool.acquire = MagicMock(return_value=mock_ctx)

        tables = await discover_tenant_tables(pool)

        assert len(tables) == 2
        assert tables[0]["table_name"] == "audit_logs"
        assert tables[0]["column_name"] == "tenant_id"
        assert tables[1]["table_name"] == "apps"
        assert tables[1]["column_name"] == "customer_id"

    def test_generate_rls_migration_produces_valid_sql(self):
        """generate_rls_migration produces ALTER TABLE + CREATE POLICY SQL
        for each discovered table."""
        tables = [
            {
                "table_name": "audit_logs",
                "column_name": "tenant_id",
                "data_type": "character varying",
            },
            {
                "table_name": "apps",
                "column_name": "customer_id",
                "data_type": "uuid",
            },
        ]
        sql = generate_rls_migration(tables)

        # Should have ALTER TABLE for both tables
        assert "ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY" in sql
        assert "ALTER TABLE apps ENABLE ROW LEVEL SECURITY" in sql

        # Should have CREATE POLICY for both
        assert "CREATE POLICY tenant_isolation ON audit_logs" in sql
        assert "CREATE POLICY tenant_isolation ON apps" in sql

        # UUID column should get ::uuid cast, varchar should not
        # Find the audit_logs policy block — no cast
        audit_block_start = sql.index("CREATE POLICY tenant_isolation ON audit_logs")
        audit_block_end = sql.index(";", audit_block_start)
        audit_block = sql[audit_block_start:audit_block_end]
        assert "::uuid" not in audit_block

        # Find the apps policy block — has ::uuid cast
        apps_block_start = sql.index("CREATE POLICY tenant_isolation ON apps")
        apps_block_end = sql.index(";", apps_block_start)
        apps_block = sql[apps_block_start:apps_block_end]
        assert "::uuid" in apps_block

    def test_generate_rls_migration_empty_tables(self):
        """generate_rls_migration handles empty table list gracefully."""
        sql = generate_rls_migration([])
        assert "No tenant-scoped tables found" in sql
