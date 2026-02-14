"""Security and attack simulation tests for PostgreSQL Row-Level Security (RLS).

Tests cover:
- SQL injection via tenant_id
- Tenant isolation bypass attempts
- Privilege escalation vectors
- NULL tenant context safety
- Concurrent request isolation
- RLS on INSERT (WITH CHECK)
- Admin operations safety
- Schema-level security properties
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

import proxy.store.postgres as pg_store
from proxy.store.rls import RLS_APP_ROLE, _UUID_RE, tenant_transaction, validate_tenant_id

VALID_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
VALID_UUID_2 = "11111111-2222-3333-4444-555555555555"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "proxy" / "models" / "schema.sql"
_RLS_SOURCE = Path(__file__).resolve().parent.parent / "proxy" / "store" / "rls.py"
_AUDIT_SOURCE = Path(__file__).resolve().parent.parent / "proxy" / "store" / "audit.py"
_WEBHOOKS_SOURCE = Path(__file__).resolve().parent.parent / "proxy" / "store" / "webhooks.py"
_POSTGRES_SOURCE = Path(__file__).resolve().parent.parent / "proxy" / "store" / "postgres.py"


def _schema_sql() -> str:
    return _SCHEMA_PATH.read_text()


def _make_pool_mock():
    """Build a mock pool + connection + transaction matching the project pattern."""
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value=None)
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


# ===========================================================================
# TestSQLInjectionViaTenantId
# ===========================================================================

class TestSQLInjectionViaTenantId:
    """SQL-injection payloads MUST be rejected by validate_tenant_id."""

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param("'; DROP TABLE customers; --", id="drop-table"),
            pytest.param("' OR '1'='1", id="or-tautology-single-quote"),
            pytest.param("\x00", id="null-byte"),
            pytest.param("1; SELECT * FROM customers", id="stacked-query"),
            pytest.param("UNION SELECT * FROM customers", id="union-select"),
            pytest.param("${jndi:ldap://evil.com}", id="jndi-log4shell"),
            pytest.param("../../../etc/passwd", id="path-traversal"),
            pytest.param("<script>alert(1)</script>", id="xss-script-tag"),
            pytest.param("' OR 1=1 --", id="or-tautology-numeric"),
            pytest.param(
                "\u0410\u0412\u0421\u0414\u0415\u0046\u0047\u0048-"
                "\u0031\u0032\u0033\u0034-"
                "\u0035\u0036\u0037\u0038-"
                "\u0039\u0030\u0061\u0062-"
                "cdef01234567",
                id="unicode-confusable",
            ),
        ],
    )
    def test_sqli_payloads_rejected(self, payload: str):
        """Every SQL-injection / RCE payload MUST raise ValueError."""
        with pytest.raises(ValueError):
            validate_tenant_id(payload)

    def test_valid_uuid_accepted(self):
        """Sanity check — a well-formed UUID passes."""
        result = validate_tenant_id(VALID_UUID)
        assert result == VALID_UUID

    @pytest.mark.parametrize(
        "payload",
        [
            "1' WAITFOR DELAY '0:0:5' --",
            "1' AND SLEEP(5)--",
            "1'; EXEC xp_cmdshell('whoami')--",
            "' HAVING 1=1--",
            "admin'--",
        ],
    )
    def test_blind_sqli_payloads_rejected(self, payload: str):
        """Blind / time-based SQL-injection payloads MUST raise ValueError."""
        with pytest.raises(ValueError):
            validate_tenant_id(payload)


# ===========================================================================
# TestTenantIsolationBypass
# ===========================================================================

class TestTenantIsolationBypass:
    """Attempts to bypass tenant isolation MUST fail."""

    @pytest.mark.asyncio
    async def test_set_config_uses_exact_match(self):
        """set_config is called with the exact tenant_id value, not a pattern."""
        pool, mock_conn = _make_pool_mock()
        pg_store._pool = pool
        try:
            async with tenant_transaction(VALID_UUID) as conn:
                pass
            # The second execute call is set_config
            calls = mock_conn.execute.call_args_list
            set_config_call = calls[1]
            sql = set_config_call[0][0]
            tenant_arg = set_config_call[0][1]
            assert "set_config" in sql
            assert "$1" in sql
            assert tenant_arg == VALID_UUID
            # Ensure no LIKE/IN operators in the SQL
            assert "LIKE" not in sql.upper()
            assert " IN " not in sql.upper()
        finally:
            pg_store._pool = None

    def test_schema_rls_uses_equality_operator(self):
        """RLS policies in schema.sql use '=' operator, not LIKE or IN."""
        schema = _schema_sql()
        # Extract all CREATE POLICY blocks
        policies = re.findall(
            r"CREATE POLICY tenant_isolation.*?;", schema, re.DOTALL
        )
        assert len(policies) >= 4, "Expected at least 4 tenant_isolation policies"
        for policy in policies:
            assert "LIKE" not in policy.upper(), f"Policy uses LIKE: {policy}"
            assert " IN (" not in policy.upper(), f"Policy uses IN: {policy}"
            assert "=" in policy, f"Policy missing = operator: {policy}"

    def test_validate_strips_whitespace(self):
        """Padding with whitespace cannot bypass validation."""
        padded = f"  {VALID_UUID}  "
        result = validate_tenant_id(padded)
        assert result == VALID_UUID
        assert result == result.strip()

    def test_validate_lowercases(self):
        """Mixed-case UUID is normalized to lowercase — no case bypass."""
        upper_uuid = VALID_UUID.upper()
        result = validate_tenant_id(upper_uuid)
        assert result == VALID_UUID
        assert result == result.lower()

    def test_multiple_uuids_rejected(self):
        """Comma-separated UUIDs are rejected (multi-tenant injection)."""
        multi = f"{VALID_UUID},{VALID_UUID_2}"
        with pytest.raises(ValueError):
            validate_tenant_id(multi)

    def test_wildcard_characters_rejected(self):
        """SQL wildcard characters (%, _) in tenant_id are rejected."""
        for wc in ["%", "_"]:
            with pytest.raises(ValueError):
                validate_tenant_id(wc + VALID_UUID[1:])


# ===========================================================================
# TestPrivilegeEscalation
# ===========================================================================

class TestPrivilegeEscalation:
    """Verify that tenant_transaction cannot be used for privilege escalation."""

    def test_uses_set_local_role(self):
        """Source code uses SET LOCAL ROLE (transaction-scoped), not SET ROLE."""
        source = _RLS_SOURCE.read_text()
        assert "SET LOCAL ROLE" in source, "Must use SET LOCAL ROLE"

    @pytest.mark.asyncio
    async def test_set_local_in_execute_call(self):
        """The actual SQL sent to the database starts with 'SET LOCAL ROLE'."""
        pool, mock_conn = _make_pool_mock()
        pg_store._pool = pool
        try:
            async with tenant_transaction(VALID_UUID) as conn:
                pass
            first_call = mock_conn.execute.call_args_list[0]
            sql = first_call[0][0]
            assert sql.startswith("SET LOCAL ROLE")
        finally:
            pg_store._pool = None

    @pytest.mark.asyncio
    async def test_role_reverts_after_transaction(self):
        """No persistent SET ROLE is issued — only transaction-local SET LOCAL."""
        pool, mock_conn = _make_pool_mock()
        pg_store._pool = pool
        try:
            async with tenant_transaction(VALID_UUID) as conn:
                pass
            # Inspect all execute calls — none should be a bare SET ROLE
            for call in mock_conn.execute.call_args_list:
                sql = call[0][0]
                if "SET" in sql.upper() and "ROLE" in sql.upper():
                    assert "LOCAL" in sql.upper(), (
                        f"Found non-local SET ROLE: {sql}"
                    )
        finally:
            pg_store._pool = None

    @pytest.mark.asyncio
    async def test_cannot_set_superuser_role(self):
        """The hardcoded role is shieldai_app — not a superuser."""
        assert RLS_APP_ROLE == "shieldai_app"
        pool, mock_conn = _make_pool_mock()
        pg_store._pool = pool
        try:
            async with tenant_transaction(VALID_UUID) as conn:
                pass
            first_call = mock_conn.execute.call_args_list[0]
            sql = first_call[0][0]
            assert "shieldai_app" in sql
            assert "postgres" not in sql.lower()
            assert "superuser" not in sql.lower()
        finally:
            pg_store._pool = None

    def test_rls_app_role_is_nologin(self):
        """Schema creates the app role with NOLOGIN (cannot be used for direct login)."""
        schema = _schema_sql()
        assert "CREATE ROLE shieldai_app NOLOGIN" in schema


# ===========================================================================
# TestNullTenantContext
# ===========================================================================

class TestNullTenantContext:
    """Verify behaviour when tenant context is absent or empty."""

    def test_schema_uses_current_setting_with_missing_ok(self):
        """Policies use current_setting('app.current_tenant_id', true).

        The second parameter 'true' means return NULL when GUC is unset,
        which means '=' comparison yields false — zero rows.
        """
        schema = _schema_sql()
        occurrences = re.findall(
            r"current_setting\(\s*'app\.current_tenant_id'\s*,\s*true\s*\)",
            schema,
        )
        # Each table has USING + WITH CHECK = 2 occurrences, 4 tables = 8
        assert len(occurrences) >= 8, (
            f"Expected >= 8 current_setting(..., true) occurrences, got {len(occurrences)}"
        )

    def test_null_comparison_yields_false(self):
        """When current_setting returns NULL, '= NULL' is false in SQL.

        This is a logical property: in SQL, NULL = anything is NULL (falsy).
        We verify the policy uses '=' (not IS) which ensures NULL tenant
        context produces zero rows.
        """
        schema = _schema_sql()
        policies = re.findall(
            r"CREATE POLICY tenant_isolation.*?;", schema, re.DOTALL
        )
        for policy in policies:
            # The USING clause uses '=' not 'IS'
            assert "IS current_setting" not in policy
            assert "= current_setting" in policy

    def test_empty_string_rejected(self):
        """Empty string tenant_id is rejected."""
        with pytest.raises(ValueError):
            validate_tenant_id("")

    def test_whitespace_only_rejected(self):
        """Whitespace-only tenant_id is rejected."""
        for ws in [" ", "\t", "\n", "  \t\n  "]:
            with pytest.raises(ValueError, match="must not be empty"):
                validate_tenant_id(ws)


# ===========================================================================
# TestConcurrentRequestSafety
# ===========================================================================

class TestConcurrentRequestSafety:
    """Verify that concurrent requests use independent, transaction-local settings."""

    def test_tenant_transaction_uses_set_local(self):
        """SET LOCAL ensures config is transaction-scoped, not session-scoped."""
        source = _RLS_SOURCE.read_text()
        assert "SET LOCAL ROLE" in source

    @pytest.mark.asyncio
    async def test_independent_connections(self):
        """Two concurrent tenant_transactions acquire independent connections."""
        conn1 = AsyncMock()
        conn1.execute = AsyncMock()
        ctx1 = AsyncMock()
        ctx1.__aenter__ = AsyncMock(return_value=conn1)
        ctx1.__aexit__ = AsyncMock(return_value=False)
        tx1 = AsyncMock()
        tx1.__aenter__ = AsyncMock(return_value=None)
        tx1.__aexit__ = AsyncMock(return_value=False)
        conn1.transaction = MagicMock(return_value=tx1)

        conn2 = AsyncMock()
        conn2.execute = AsyncMock()
        ctx2 = AsyncMock()
        ctx2.__aenter__ = AsyncMock(return_value=conn2)
        ctx2.__aexit__ = AsyncMock(return_value=False)
        tx2 = AsyncMock()
        tx2.__aenter__ = AsyncMock(return_value=None)
        tx2.__aexit__ = AsyncMock(return_value=False)
        conn2.transaction = MagicMock(return_value=tx2)

        pool = MagicMock()
        pool.acquire = MagicMock(side_effect=[ctx1, ctx2])
        pg_store._pool = pool
        try:
            async with tenant_transaction(VALID_UUID) as c1:
                async with tenant_transaction(VALID_UUID_2) as c2:
                    assert c1 is not c2
            assert pool.acquire.call_count == 2
        finally:
            pg_store._pool = None

    @pytest.mark.asyncio
    async def test_set_config_is_transaction_local(self):
        """set_config third parameter is 'true' (transaction-local)."""
        pool, mock_conn = _make_pool_mock()
        pg_store._pool = pool
        try:
            async with tenant_transaction(VALID_UUID) as conn:
                pass
            set_config_call = mock_conn.execute.call_args_list[1]
            sql = set_config_call[0][0]
            assert "true" in sql, "set_config must use 'true' for transaction-local"
        finally:
            pg_store._pool = None

    @pytest.mark.asyncio
    async def test_connection_returned_to_pool(self):
        """After tenant_transaction exits, the connection context manager exits."""
        pool, mock_conn = _make_pool_mock()
        pg_store._pool = pool
        mock_ctx = pool.acquire()
        # Reset so we get a fresh call count
        pool.acquire = MagicMock(return_value=mock_ctx)
        try:
            async with tenant_transaction(VALID_UUID) as conn:
                pass
            # __aexit__ should have been called on the connection context
            assert mock_ctx.__aexit__.called
        finally:
            pg_store._pool = None

    @pytest.mark.asyncio
    async def test_each_call_acquires_new_connection(self):
        """Each tenant_transaction call invokes pool.acquire()."""
        pool, mock_conn = _make_pool_mock()
        pg_store._pool = pool
        try:
            async with tenant_transaction(VALID_UUID) as c1:
                pass
            async with tenant_transaction(VALID_UUID_2) as c2:
                pass
            assert pool.acquire.call_count == 2
        finally:
            pg_store._pool = None


# ===========================================================================
# TestRLSOnInsert
# ===========================================================================

class TestRLSOnInsert:
    """Verify that INSERT operations are protected by WITH CHECK policies."""

    def test_all_tables_have_with_check(self):
        """All 4 tenant-scoped tables have WITH CHECK clauses in their policies."""
        schema = _schema_sql()
        tables = ["customers", "apps", "audit_logs", "webhooks"]
        for table in tables:
            pattern = (
                rf"CREATE POLICY tenant_isolation ON {table}\s+"
                r"USING\s*\(.*?\)\s+"
                r"WITH CHECK\s*\(.*?\)"
            )
            match = re.search(pattern, schema, re.DOTALL)
            assert match is not None, (
                f"Table '{table}' missing WITH CHECK clause in tenant_isolation policy"
            )

    def test_with_check_prevents_cross_tenant_insert(self):
        """WITH CHECK clauses compare to current_setting — prevents inserting for other tenants."""
        schema = _schema_sql()
        with_checks = re.findall(
            r"WITH CHECK\s*\((.*?)\)", schema, re.DOTALL
        )
        assert len(with_checks) >= 4
        for check_expr in with_checks:
            assert "current_setting" in check_expr, (
                f"WITH CHECK must reference current_setting: {check_expr}"
            )

    @pytest.mark.asyncio
    async def test_audit_insert_uses_tenant_transaction(self):
        """insert_audit_log uses tenant_transaction (source code check)."""
        source = _AUDIT_SOURCE.read_text()
        assert "tenant_transaction" in source
        # Verify the import
        assert "from proxy.store.rls import tenant_transaction" in source
        # Verify usage in insert_audit_log
        fn_source = _extract_function_source(source, "insert_audit_log")
        assert "tenant_transaction" in fn_source

    @pytest.mark.asyncio
    async def test_webhook_insert_uses_tenant_transaction(self):
        """create_webhook uses tenant_transaction (source code check)."""
        source = _WEBHOOKS_SOURCE.read_text()
        assert "tenant_transaction" in source
        fn_source = _extract_function_source(source, "create_webhook")
        assert "tenant_transaction" in fn_source


class TestWebhookUUIDFormatSafety:
    """get_enabled_webhooks_for_event must pass canonical UUID to tenant_transaction."""

    def test_source_uses_str_cid_not_raw_customer_id(self):
        """tenant_transaction receives str(cid) — canonical hyphenated lowercase."""
        source = _WEBHOOKS_SOURCE.read_text()
        fn_source = _extract_function_source(source, "get_enabled_webhooks_for_event")
        # Must use str(cid) not raw customer_id for tenant_transaction
        assert "tenant_transaction(str(cid))" in fn_source, (
            "get_enabled_webhooks_for_event must pass str(cid) to tenant_transaction "
            "to ensure canonical UUID format (hyphenated, lowercase)"
        )

    @pytest.mark.asyncio
    async def test_non_hyphenated_uuid_does_not_raise(self):
        """A valid UUID without hyphens should NOT cause an unhandled ValueError."""
        from proxy.store.webhooks import get_enabled_webhooks_for_event

        pool, mock_conn = _make_pool_mock()
        mock_conn.fetch = AsyncMock(return_value=[])
        pg_store._pool = pool
        try:
            # Non-hyphenated UUID passes Python UUID() but would fail validate_tenant_id
            # if raw string were passed. With str(cid) fix, this works.
            result = await get_enabled_webhooks_for_event(
                "aaaaaaaabbbbccccddddeeeeeeeeeeee", "waf_blocked"
            )
            assert result == []
        finally:
            pg_store._pool = None


def _extract_function_source(module_source: str, func_name: str) -> str:
    """Extract the source of a function from module source text."""
    pattern = rf"(async\s+)?def\s+{func_name}\s*\("
    match = re.search(pattern, module_source)
    if not match:
        return ""
    start = match.start()
    # Find next top-level def or end of file
    next_def = re.search(r"\n(?:async\s+)?def\s+", module_source[start + 1:])
    if next_def:
        end = start + 1 + next_def.start()
    else:
        end = len(module_source)
    return module_source[start:end]


# ===========================================================================
# TestAdminOperationsSafety
# ===========================================================================

class TestAdminOperationsSafety:
    """Admin / migration functions bypass RLS intentionally (owner role)."""

    def test_get_all_apps_uses_pool_directly(self):
        """get_all_apps uses _pool.acquire() directly — no tenant_transaction."""
        source = _POSTGRES_SOURCE.read_text()
        fn_source = _extract_function_source(source, "get_all_apps")
        assert "tenant_transaction" not in fn_source
        assert "pool" in fn_source.lower() or "_pool" in fn_source

    def test_run_migrations_uses_pool_directly(self):
        """run_migrations uses _pool.acquire() directly — owner role for DDL."""
        source = _POSTGRES_SOURCE.read_text()
        fn_source = _extract_function_source(source, "run_migrations")
        assert "tenant_transaction" not in fn_source
        assert "_pool" in fn_source

    def test_create_customer_uses_pool_directly(self):
        """create_customer uses _pool.acquire() — no tenant context needed."""
        source = _POSTGRES_SOURCE.read_text()
        fn_source = _extract_function_source(source, "create_customer")
        assert "tenant_transaction" not in fn_source
        assert "_pool" in fn_source

    def test_admin_functions_do_not_call_tenant_transaction(self):
        """No admin function (create_customer, get_all_apps, run_migrations,
        delete_customer, get_customer) invokes tenant_transaction."""
        source = _POSTGRES_SOURCE.read_text()
        admin_fns = [
            "create_customer", "get_customer", "update_customer",
            "delete_customer", "get_all_apps", "run_migrations",
            "create_app", "get_app", "update_app", "delete_app",
        ]
        for fn_name in admin_fns:
            fn_source = _extract_function_source(source, fn_name)
            if fn_source:
                assert "tenant_transaction(" not in fn_source, (
                    f"{fn_name} should NOT call tenant_transaction"
                )


# ===========================================================================
# TestSchemaSecurityProperties
# ===========================================================================

class TestSchemaSecurityProperties:
    """Verify structural security properties of schema.sql."""

    _TABLES_WITH_RLS = ["customers", "apps", "audit_logs", "webhooks"]

    def test_all_tables_enable_rls(self):
        """All 4 tenant-scoped tables have ENABLE ROW LEVEL SECURITY."""
        schema = _schema_sql()
        for table in self._TABLES_WITH_RLS:
            pattern = rf"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"
            assert re.search(pattern, schema), (
                f"Table '{table}' missing ENABLE ROW LEVEL SECURITY"
            )

    def test_all_tables_have_tenant_isolation_policy(self):
        """All 4 tables have a CREATE POLICY tenant_isolation policy."""
        schema = _schema_sql()
        for table in self._TABLES_WITH_RLS:
            pattern = rf"CREATE POLICY tenant_isolation ON {table}"
            assert re.search(pattern, schema), (
                f"Table '{table}' missing tenant_isolation policy"
            )

    def test_policies_use_current_setting(self):
        """Policies use current_setting (built-in GUC), not a custom function
        that could be hijacked or replaced.
        """
        schema = _schema_sql()
        policies = re.findall(
            r"CREATE POLICY tenant_isolation.*?;", schema, re.DOTALL
        )
        for policy in policies:
            assert "current_setting(" in policy, (
                f"Policy should use current_setting: {policy}"
            )
            # Must NOT use a custom function like get_current_tenant()
            assert "get_current_tenant" not in policy
            assert "get_tenant" not in policy

    def test_no_force_rls(self):
        """No FORCE ROW LEVEL SECURITY — owner bypasses RLS by design.

        The owner role is used for migrations and admin operations.  FORCE RLS
        would break those operations.
        """
        schema = _schema_sql()
        assert "FORCE ROW LEVEL SECURITY" not in schema

    def test_grant_limits_to_dml_only(self):
        """GRANT to shieldai_app is limited to SELECT, INSERT, UPDATE, DELETE.

        The app role MUST NOT have TRUNCATE, REFERENCES, TRIGGER, or DDL.
        """
        schema = _schema_sql()
        grant_lines = [
            line.strip()
            for line in schema.splitlines()
            if line.strip().startswith("GRANT") and "shieldai_app" in line
            and "TO CURRENT_USER" not in line
        ]
        for line in grant_lines:
            upper = line.upper()
            assert "TRUNCATE" not in upper, f"shieldai_app must not have TRUNCATE: {line}"
            assert "REFERENCES" not in upper, f"shieldai_app must not have REFERENCES: {line}"
            assert "TRIGGER" not in upper, f"shieldai_app must not have TRIGGER: {line}"
            assert "CREATE" not in upper or "CREATE ROLE" not in upper, (
                f"shieldai_app must not have CREATE: {line}"
            )
            assert "DROP" not in upper, f"shieldai_app must not have DROP: {line}"
            assert "ALTER" not in upper, f"shieldai_app must not have ALTER: {line}"
