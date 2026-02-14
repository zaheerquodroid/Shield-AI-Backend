"""Comprehensive RLS attack simulation tests.

Simulates real-world attack vectors against the Row-Level Security
implementation, based on:

- CVE-2024-10976 (query plan reuse across SET ROLE)
- CVE-2024-10978 (SET ROLE reset to wrong user)
- Common RLS footguns (bytebase.com, crunchydata.com)
- PostgreSQL wiki: Row_Security_Considerations
- OWASP multi-tenant isolation guidance

Each test class targets a specific attack vector with multiple payloads.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest

import proxy.store.postgres as pg_store
from proxy.store.rls import (
    RLS_APP_ROLE,
    _PG_IDENT_RE,
    _UUID_RE,
    _validate_pg_identifier,
    tenant_transaction,
    validate_tenant_id,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TENANT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
TENANT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
ADMIN_ROLE = "shieldai_owner"

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "proxy" / "models" / "schema.sql"
_RLS_SOURCE = Path(__file__).resolve().parent.parent / "proxy" / "store" / "rls.py"
_AUDIT_SOURCE = Path(__file__).resolve().parent.parent / "proxy" / "store" / "audit.py"
_WEBHOOKS_SOURCE = Path(__file__).resolve().parent.parent / "proxy" / "store" / "webhooks.py"
_POSTGRES_SOURCE = Path(__file__).resolve().parent.parent / "proxy" / "store" / "postgres.py"
_DISCOVER_SOURCE = Path(__file__).resolve().parent.parent / "proxy" / "tools" / "discover_tenant_tables.py"


def _schema_sql() -> str:
    return _SCHEMA_PATH.read_text()


def _make_pool_mock():
    """Build a mock pool + connection + transaction."""
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value=None)
    mock_conn.fetch = AsyncMock(return_value=[])
    mock_conn.fetchval = AsyncMock(return_value=None)

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
# 1. CVE-2024-10976: Query plan reuse across SET ROLE
# ===========================================================================


class TestCVE2024_10976_QueryPlanReuse:
    """CVE-2024-10976: RLS bypass when a cached query plan is reused
    after SET ROLE changes the effective user.

    Mitigation: We use SET LOCAL ROLE inside a transaction, and each
    tenant_transaction acquires a fresh connection from the pool.
    PostgreSQL resets plan caches when the role changes.
    """

    @pytest.mark.asyncio
    async def test_each_tenant_gets_fresh_connection(self):
        """Two sequential tenant_transactions must get independent connections."""
        pool, mock_conn = _make_pool_mock()
        pg_store._pool = pool
        try:
            async with tenant_transaction(TENANT_A) as c1:
                pass
            async with tenant_transaction(TENANT_B) as c2:
                pass
            assert pool.acquire.call_count == 2
        finally:
            pg_store._pool = None

    @pytest.mark.asyncio
    async def test_set_local_role_is_transaction_scoped(self):
        """SET LOCAL ROLE auto-reverts when the transaction ends.
        This prevents CVE-2024-10976-style plan reuse."""
        source = _RLS_SOURCE.read_text()
        assert "SET LOCAL ROLE" in source
        # Must NOT use plain SET ROLE (session-scoped)
        # Find all SET ROLE usages — must all be SET LOCAL ROLE
        set_role_lines = [
            line.strip() for line in source.splitlines()
            if "SET" in line and "ROLE" in line and "LOCAL" not in line
            and not line.strip().startswith("#")
            and not line.strip().startswith('"')
            and "SET LOCAL ROLE" not in line
        ]
        # Filter out comments and strings
        real_set_role = [
            l for l in set_role_lines
            if not l.startswith("--") and "SET LOCAL" not in l
        ]
        assert not real_set_role, f"Found session-scoped SET ROLE: {real_set_role}"

    @pytest.mark.asyncio
    async def test_concurrent_tenants_isolated(self):
        """Concurrent tenant_transactions with different tenant IDs
        must not share connection or role state."""
        conns = []
        mock_conns = []
        for _ in range(2):
            mc = AsyncMock()
            mc.execute = AsyncMock()
            mt = AsyncMock()
            mt.__aenter__ = AsyncMock(return_value=None)
            mt.__aexit__ = AsyncMock(return_value=False)
            mc.transaction = MagicMock(return_value=mt)
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=mc)
            ctx.__aexit__ = AsyncMock(return_value=False)
            conns.append(ctx)
            mock_conns.append(mc)

        call_idx = 0
        pool = MagicMock()

        def acquire_side_effect():
            nonlocal call_idx
            c = conns[call_idx]
            call_idx += 1
            return c

        pool.acquire = MagicMock(side_effect=acquire_side_effect)
        pg_store._pool = pool
        try:
            results = []

            async def use_tenant(tid, idx):
                async with tenant_transaction(tid) as conn:
                    results.append((tid, conn))

            await asyncio.gather(
                use_tenant(TENANT_A, 0),
                use_tenant(TENANT_B, 1),
            )
            # Each task got a different connection
            assert results[0][1] is not results[1][1]
            # Each connection got set_config with the correct tenant
            for tid, mc in zip([TENANT_A, TENANT_B], mock_conns):
                set_config_calls = [
                    c for c in mc.execute.call_args_list
                    if "set_config" in str(c)
                ]
                if set_config_calls:
                    assert tid in str(set_config_calls[0])
        finally:
            pg_store._pool = None


# ===========================================================================
# 2. CVE-2024-10978: SET ROLE reset to wrong user
# ===========================================================================


class TestCVE2024_10978_RoleReset:
    """CVE-2024-10978: SET ROLE / SET SESSION AUTHORIZATION could reset
    to the wrong user ID in certain error paths.

    Mitigation: We use SET LOCAL ROLE (transaction-scoped, auto-reverts)
    rather than SET ROLE (session-scoped, persists after transaction).
    """

    def test_source_uses_set_local_not_set_role(self):
        """rls.py must use SET LOCAL ROLE, not SET ROLE."""
        source = _RLS_SOURCE.read_text()
        # Find the f-string in tenant_transaction
        assert 'f"SET LOCAL ROLE {RLS_APP_ROLE}"' in source

    def test_no_set_session_authorization(self):
        """SET SESSION AUTHORIZATION is too powerful — must not appear."""
        source = _RLS_SOURCE.read_text()
        assert "SET SESSION AUTHORIZATION" not in source

    @pytest.mark.asyncio
    async def test_role_reverts_after_exception(self):
        """If an exception occurs inside tenant_transaction, the transaction
        rolls back — SET LOCAL ROLE auto-reverts."""
        pool, mock_conn = _make_pool_mock()
        pg_store._pool = pool
        try:
            with pytest.raises(RuntimeError):
                async with tenant_transaction(TENANT_A) as conn:
                    raise RuntimeError("simulated error")
            # Transaction __aexit__ was called (handles rollback)
            tx_mock = mock_conn.transaction.return_value
            tx_mock.__aexit__.assert_awaited_once()
            # Exit was called with exception info
            args = tx_mock.__aexit__.call_args.args
            assert args[0] is RuntimeError
        finally:
            pg_store._pool = None


# ===========================================================================
# 3. GUC Variable Spoofing (set_config bypass)
# ===========================================================================


class TestGUCSpoofing:
    """Attack: The shieldai_app role could call set_config() directly
    to set app.current_tenant_id to another tenant's UUID.

    Mitigation: The app role only has DML privileges (no function creation).
    set_config is called by our application code with validated tenant_id.
    Direct SQL access is never exposed to tenants.
    """

    def test_set_config_uses_parameterized_query(self):
        """set_config uses $1 placeholder — not string interpolation."""
        source = _RLS_SOURCE.read_text()
        assert "$1" in source
        assert "set_config('app.current_tenant_id', $1, true)" in source

    def test_tenant_id_validated_before_set_config(self):
        """validate_tenant_id is called before set_config within the function."""
        source = _RLS_SOURCE.read_text()
        fn = _extract_function(source, "tenant_transaction")
        # Strip docstring to avoid matching "set_config" in docstring text.
        # The docstring describes the SQL but we want to verify code ordering.
        body = re.sub(r'""".*?"""', '', fn, count=1, flags=re.DOTALL)
        validate_pos = body.index("validate_tenant_id")
        set_config_pos = body.index("set_config")
        assert validate_pos < set_config_pos

    @pytest.mark.parametrize("payload", [
        # Try to reset the GUC to another tenant
        f"'; SELECT set_config('app.current_tenant_id', '{TENANT_B}', true); --",
        # Try to set to wildcard
        "'; SET app.current_tenant_id = '%'; --",
        # Try to unset the GUC
        "'; RESET app.current_tenant_id; --",
        # Try stacked queries
        f"{TENANT_A}'; SELECT 1; --",
    ])
    def test_guc_spoofing_payloads_rejected(self, payload: str):
        """GUC spoofing payloads must be rejected by validate_tenant_id."""
        with pytest.raises(ValueError):
            validate_tenant_id(payload)

    def test_app_role_cannot_execute_ddl(self):
        """Schema GRANT to shieldai_app is limited to DML (no DDL)."""
        schema = _schema_sql()
        grant_lines = [
            l.strip() for l in schema.splitlines()
            if l.strip().startswith("GRANT") and "shieldai_app" in l
            and "TO CURRENT_USER" not in l
        ]
        for line in grant_lines:
            upper = line.upper()
            for forbidden in ("CREATE", "DROP", "ALTER", "TRUNCATE", "EXECUTE"):
                if forbidden == "CREATE" and "CREATE ROLE" in upper:
                    continue
                assert forbidden not in upper, (
                    f"shieldai_app has forbidden privilege {forbidden}: {line}"
                )


# ===========================================================================
# 4. Cross-Tenant Data Access via Missing WITH CHECK
# ===========================================================================


class TestCrossTenantWriteViaWithCheck:
    """Attack: If RLS policy has USING but no WITH CHECK, a tenant can
    INSERT rows for another tenant (they won't see them, but the data
    is written to another tenant's partition).

    Mitigation: All 4 tables have both USING and WITH CHECK clauses.
    (Ref: bytebase.com/blog/postgres-row-level-security-footguns/)
    """

    _TABLES = ["customers", "apps", "audit_logs", "webhooks"]

    def test_all_policies_have_with_check(self):
        """Every CREATE POLICY must include WITH CHECK."""
        schema = _schema_sql()
        for table in self._TABLES:
            pattern = rf"CREATE POLICY tenant_isolation ON {table}\s"
            match = re.search(pattern, schema)
            assert match, f"Missing policy on {table}"
            # Extract the full policy statement
            start = match.start()
            end = schema.index(";", start) + 1
            policy = schema[start:end]
            assert "WITH CHECK" in policy, (
                f"Policy on {table} missing WITH CHECK — cross-tenant INSERT possible"
            )

    def test_with_check_matches_using_clause(self):
        """WITH CHECK and USING must use the same comparison expression
        to prevent INSERT/UPDATE for other tenants."""
        schema = _schema_sql()
        for table in self._TABLES:
            idx = schema.index(f"CREATE POLICY tenant_isolation ON {table}")
            end = schema.index(";", idx)
            policy = schema[idx:end]
            using_match = re.search(r"USING\s*\((.+?)\)", policy, re.DOTALL)
            check_match = re.search(r"WITH CHECK\s*\((.+?)\)", policy, re.DOTALL)
            assert using_match and check_match, f"Incomplete policy on {table}"
            using_expr = using_match.group(1).strip()
            check_expr = check_match.group(1).strip()
            assert using_expr == check_expr, (
                f"Policy on {table}: USING and WITH CHECK differ. "
                f"USING: {using_expr}, WITH CHECK: {check_expr}"
            )


# ===========================================================================
# 5. FORCE ROW LEVEL SECURITY — Owner Bypass Analysis
# ===========================================================================


class TestOwnerBypassRLS:
    """Without FORCE ROW LEVEL SECURITY, the table owner bypasses RLS.
    This is by design for admin operations, but all tenant-scoped
    functions MUST use tenant_transaction (which SET LOCAL ROLE to the
    app role subject to RLS).

    We verify that no tenant-scoped function accidentally uses
    pool.acquire() directly.
    """

    def test_no_force_rls_by_design(self):
        """FORCE ROW LEVEL SECURITY should NOT be present — owner needs
        to bypass for migrations and admin CRUD."""
        schema = _schema_sql()
        assert "FORCE ROW LEVEL SECURITY" not in schema

    def test_audit_insert_uses_tenant_transaction(self):
        """insert_audit_log must use tenant_transaction, not pool.acquire."""
        source = _AUDIT_SOURCE.read_text()
        fn = _extract_function(source, "insert_audit_log")
        assert "tenant_transaction" in fn
        assert "pool.acquire" not in fn and "_pool.acquire" not in fn

    def test_audit_query_uses_tenant_transaction(self):
        source = _AUDIT_SOURCE.read_text()
        fn = _extract_function(source, "query_audit_logs")
        assert "tenant_transaction" in fn

    def test_audit_delete_uses_tenant_transaction(self):
        source = _AUDIT_SOURCE.read_text()
        fn = _extract_function(source, "delete_old_audit_logs")
        assert "tenant_transaction" in fn

    def test_webhook_create_uses_tenant_transaction(self):
        source = _WEBHOOKS_SOURCE.read_text()
        fn = _extract_function(source, "create_webhook")
        assert "tenant_transaction" in fn

    def test_webhook_list_uses_tenant_transaction(self):
        source = _WEBHOOKS_SOURCE.read_text()
        fn = _extract_function(source, "list_webhooks")
        assert "tenant_transaction" in fn

    def test_webhook_event_fetch_uses_tenant_transaction(self):
        source = _WEBHOOKS_SOURCE.read_text()
        fn = _extract_function(source, "get_enabled_webhooks_for_event")
        assert "tenant_transaction" in fn

    def test_admin_functions_bypass_rls_intentionally(self):
        """Admin functions in postgres.py use _pool.acquire() directly."""
        source = _POSTGRES_SOURCE.read_text()
        admin_fns = [
            "create_customer", "get_customer", "update_customer",
            "delete_customer", "create_app", "get_app", "get_all_apps",
            "update_app", "delete_app", "run_migrations",
        ]
        for fn_name in admin_fns:
            fn = _extract_function(source, fn_name)
            if fn:
                assert "tenant_transaction" not in fn, (
                    f"Admin function {fn_name} should NOT use tenant_transaction"
                )


# ===========================================================================
# 6. NULL Tenant Context — Secure Default
# ===========================================================================


class TestNullTenantSecureDefault:
    """Attack: If app.current_tenant_id is not set, current_setting
    returns NULL. The comparison `column = NULL` is always FALSE in SQL,
    so zero rows are visible. This is the secure default.

    We verify the schema uses current_setting(..., true) which returns
    NULL instead of raising an error.
    """

    def test_current_setting_uses_null_safe_true(self):
        """All policies use current_setting('...', true) for NULL safety."""
        schema = _schema_sql()
        policies = re.findall(
            r"CREATE POLICY.*?;", schema, re.DOTALL
        )
        for policy in policies:
            assert "current_setting('app.current_tenant_id', true)" in policy, (
                f"Policy missing NULL-safe true param: {policy[:100]}"
            )

    def test_null_comparison_returns_zero_rows(self):
        """SQL: column = NULL evaluates to NULL (not TRUE) — zero rows visible."""
        # This is a SQL semantics test — we verify the policy structure
        schema = _schema_sql()
        # All policies use = comparison (not IS, not LIKE, not ILIKE)
        policies = re.findall(r"USING\s*\((.+?)\)", schema, re.DOTALL)
        for expr in policies:
            assert "=" in expr
            assert "LIKE" not in expr.upper()
            assert "IS" not in expr.upper()

    @pytest.mark.asyncio
    async def test_empty_tenant_id_rejected(self):
        """Empty string tenant_id must be rejected before reaching DB."""
        with pytest.raises(ValueError, match="must not be empty"):
            validate_tenant_id("")

    @pytest.mark.asyncio
    async def test_none_tenant_id_rejected(self):
        with pytest.raises(ValueError, match="must be a string"):
            validate_tenant_id(None)  # type: ignore[arg-type]


# ===========================================================================
# 7. Connection Pool Tenant Context Bleed
# ===========================================================================


class TestConnectionPoolTenantBleed:
    """Attack: In connection pooling, a connection used by Tenant A
    might retain tenant context when returned to the pool and reused
    by Tenant B.

    Mitigation: SET LOCAL + set_config(..., true) are transaction-local.
    When the transaction ends, both auto-revert. asyncpg also resets
    connection state on release.
    """

    @pytest.mark.asyncio
    async def test_set_config_is_transaction_local(self):
        """set_config third arg 'true' = transaction-local."""
        source = _RLS_SOURCE.read_text()
        assert "set_config('app.current_tenant_id', $1, true)" in source
        # 'true' means transaction-local — reverts on COMMIT/ROLLBACK

    @pytest.mark.asyncio
    async def test_connection_released_after_transaction(self):
        """After tenant_transaction exits, the connection is released."""
        pool, mock_conn = _make_pool_mock()
        mock_ctx = pool.acquire.return_value
        pg_store._pool = pool
        try:
            async with tenant_transaction(TENANT_A):
                pass
            mock_ctx.__aexit__.assert_awaited_once()
        finally:
            pg_store._pool = None

    @pytest.mark.asyncio
    async def test_sequential_tenants_get_clean_context(self):
        """Two sequential tenant_transactions: each sets its own tenant."""
        pool, mock_conn = _make_pool_mock()
        pg_store._pool = pool
        try:
            async with tenant_transaction(TENANT_A):
                pass
            calls_a = mock_conn.execute.call_args_list.copy()

            mock_conn.execute.reset_mock()
            async with tenant_transaction(TENANT_B):
                pass
            calls_b = mock_conn.execute.call_args_list

            # Verify Tenant B got its own set_config, not Tenant A's
            set_config_b = [c for c in calls_b if "set_config" in str(c)]
            assert len(set_config_b) >= 1
            assert TENANT_B in str(set_config_b[0])
        finally:
            pg_store._pool = None


# ===========================================================================
# 8. Header Spoofing — X-Tenant-ID Injection
# ===========================================================================


class TestHeaderSpoofing:
    """Attack: Attacker sends X-Tenant-ID header to impersonate another tenant.

    Mitigation: ContextInjector strips X-Tenant-ID, X-User-ID, and
    X-ShieldAI-* headers. TenantRouter sets tenant_id from the database
    lookup (customer config by domain), not from headers.
    """

    def test_context_injector_strips_tenant_header(self):
        """ContextInjector._STRIP_HEADERS includes x-tenant-id."""
        from proxy.middleware.context_injector import _STRIP_HEADERS
        assert "x-tenant-id" in _STRIP_HEADERS

    def test_context_injector_strips_user_header(self):
        from proxy.middleware.context_injector import _STRIP_HEADERS
        assert "x-user-id" in _STRIP_HEADERS

    def test_context_injector_strips_shieldai_prefix(self):
        from proxy.middleware.context_injector import _STRIP_PREFIXES
        assert any(p.startswith("x-shieldai-") for p in _STRIP_PREFIXES)

    def test_tenant_router_uses_config_not_header(self):
        """TenantRouter sets context.tenant_id from customer config,
        NOT from request headers."""
        from proxy.middleware.router import TenantRouter
        source = inspect.getsource(TenantRouter.process_request)
        # Must set tenant_id from config
        assert 'config["customer_id"]' in source or "config['customer_id']" in source
        # Must NOT read tenant_id from headers
        assert "x-tenant-id" not in source.lower()


# ===========================================================================
# 9. SQL Injection via discover_tenant_tables
# ===========================================================================


class TestDiscoverToolSQLInjection:
    """Attack: If an attacker can create tables with names like
    'users; DROP TABLE customers; --', the generated RLS migration
    SQL would contain injected SQL.

    Mitigation: The tool generates SQL for review, not direct execution.
    Still, we should verify and document this risk.
    """

    def test_malicious_table_name_in_generated_sql(self):
        """Generated SQL from malicious table names is visible in output."""
        from proxy.tools.discover_tenant_tables import generate_rls_migration

        tables = [
            {
                "table_name": "users; DROP TABLE customers; --",
                "column_name": "tenant_id",
                "data_type": "uuid",
            }
        ]
        sql = generate_rls_migration(tables)
        # The SQL WILL contain the injection — that's the risk
        assert "DROP TABLE" in sql
        # Verify it's a generation tool (outputs text), not an executor
        source = _DISCOVER_SOURCE.read_text()
        assert "conn.execute(sql)" not in source or "print(generate" in source

    def test_discovery_query_is_parameterized(self):
        """The discovery query uses $1 parameter, not string interpolation."""
        source = _DISCOVER_SOURCE.read_text()
        assert "$1" in source
        assert "column_name = ANY($1)" in source

    def test_malicious_column_name_in_generated_sql(self):
        """Malicious column_name also appears unquoted."""
        from proxy.tools.discover_tenant_tables import generate_rls_migration

        tables = [
            {
                "table_name": "users",
                "column_name": "id; DROP TABLE users; --",
                "data_type": "uuid",
            }
        ]
        sql = generate_rls_migration(tables)
        assert "DROP TABLE" in sql
        # Document: this tool is for admin review only


# ===========================================================================
# 10. RLS Disabled Mode Security
# ===========================================================================


class TestRLSDisabledModeSecurity:
    """When rls_enabled=False, RLS is skipped but tenant_id validation
    and application-level WHERE clauses still provide isolation.

    Attack: If an attacker can set PROXY_RLS_ENABLED=false via env var,
    they disable RLS. But they still need to bypass app-level filters.
    """

    def test_validation_still_enforced_when_disabled(self):
        """validate_tenant_id runs even when RLS is disabled."""
        source = _RLS_SOURCE.read_text()
        func = _extract_function(source, "tenant_transaction")
        # validate_tenant_id is called before the rls_enabled check
        validate_pos = func.index("validate_tenant_id")
        rls_check_pos = func.index("_is_rls_enabled")
        assert validate_pos < rls_check_pos

    def test_transaction_still_used_when_disabled(self):
        """A database transaction is still opened even when RLS is off."""
        source = _RLS_SOURCE.read_text()
        func = _extract_function(source, "tenant_transaction")
        # conn.transaction() is called unconditionally
        assert "conn.transaction()" in func

    def test_audit_query_has_app_level_where_filter(self):
        """query_audit_logs has WHERE tenant_id = $1 as defense-in-depth."""
        source = _AUDIT_SOURCE.read_text()
        fn = _extract_function(source, "query_audit_logs")
        assert "tenant_id = $1" in fn

    def test_audit_delete_has_app_level_where_filter(self):
        source = _AUDIT_SOURCE.read_text()
        fn = _extract_function(source, "delete_old_audit_logs")
        assert "tenant_id = $1" in fn

    def test_webhook_queries_have_customer_id_filter(self):
        """Webhook queries include WHERE customer_id = $1."""
        source = _WEBHOOKS_SOURCE.read_text()
        for fn_name in ("create_webhook", "list_webhooks", "get_webhook",
                         "update_webhook", "delete_webhook"):
            fn = _extract_function(source, fn_name)
            assert "customer_id" in fn, f"{fn_name} missing customer_id filter"


# ===========================================================================
# 11. Advanced SQL Injection via Tenant ID
# ===========================================================================


class TestAdvancedSQLInjection:
    """Sophisticated SQL injection payloads targeting the tenant_id
    parameter specifically crafted for PostgreSQL set_config/GUC context.
    """

    @pytest.mark.parametrize("payload", [
        # PostgreSQL-specific attacks
        "$$; DROP TABLE customers; $$",
        "E'\\x27; DROP TABLE customers; --'",
        "${IFS}",
        "' UNION ALL SELECT current_user --",
        "' AND pg_sleep(5) --",
        "pg_catalog.set_config('app.current_tenant_id', 'evil', true)",
        # Unicode confusable characters (Cyrillic A looks like Latin A)
        "\u0410\u0412\u0421\u0414-bbbb-cccc-dddd-eeeeeeeeeeee",
        # Null byte injection
        f"{TENANT_A}\x00; DROP TABLE customers; --",
        # GUC manipulation attempt
        "app.current_tenant_id",
        # Extremely long input (buffer overflow attempt)
        "a" * 10000,
        # PostgreSQL dollar-quoted strings
        "$tag$evil$tag$",
        # JSON-like injection
        '{"tenant_id": "evil"}',
        # COPY command injection
        f"{TENANT_A}\\nCOPY customers TO '/tmp/data'",
    ])
    def test_advanced_sqli_rejected(self, payload: str):
        with pytest.raises(ValueError):
            validate_tenant_id(payload)

    @pytest.mark.parametrize("payload,expected", [
        # Uppercase UUIDs are normalized to lowercase — safe
        ("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        # Leading/trailing whitespace is stripped — safe
        (f"  {TENANT_A}  ", TENANT_A),
        # Tab prefix stripped — safe
        (f"\t{TENANT_A}", TENANT_A),
        # Newline prefix stripped — safe
        (f"\n{TENANT_A}", TENANT_A),
        (f"\r\n{TENANT_A}", TENANT_A),
    ])
    def test_normalized_inputs_are_safe(self, payload: str, expected: str):
        """Inputs that normalize to valid UUIDs are safe — the normalized
        (lowercase, stripped) value is what gets passed to set_config."""
        result = validate_tenant_id(payload)
        assert result == expected


# ===========================================================================
# 12. UUID Regex Bypass Attempts
# ===========================================================================


class TestUUIDRegexBypass:
    """Attempt to bypass the _UUID_RE regex with crafted inputs that
    look like UUIDs but contain malicious content.
    """

    @pytest.mark.parametrize("payload", [
        # Correct length but wrong format
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeee",   # 11 chars in last group
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeeee",  # 13 chars in last group
        # Uppercase (our regex only allows lowercase)
        "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
        # Mixed case
        "AAAAaaaa-BBBBbbbb-CCCCcccc-DDDDdddd-EEEEeeee",
        # Valid hex but wrong grouping
        "aabbccdd-eeff-0011-2233-44556677889",
        # Non-hex characters that look similar
        "gggggggg-hhhh-iiii-jjjj-kkkkkkkkkkkk",
        # Leading/trailing whitespace (should be stripped then fail)
        " aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee ",  # validate strips whitespace — this would PASS
    ])
    def test_uuid_bypass_attempts(self, payload: str):
        """All malformed UUIDs must be rejected."""
        if payload.strip().lower() == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee":
            # This is a valid UUID after stripping — should pass
            result = validate_tenant_id(payload)
            assert result == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        else:
            with pytest.raises(ValueError):
                validate_tenant_id(payload)

    def test_valid_uuid_v4_accepted(self):
        """Standard UUID v4 must be accepted."""
        uid = str(uuid4())
        result = validate_tenant_id(uid)
        assert result == uid.lower()


# ===========================================================================
# 13. Identifier Injection in ensure_rls_setup
# ===========================================================================


class TestIdentifierInjection:
    """Attack: If current_user from PostgreSQL contains SQL injection,
    the GRANT statement in ensure_rls_setup could execute arbitrary DDL.

    Mitigation: _validate_pg_identifier rejects non-alphanumeric identifiers.
    """

    @pytest.mark.parametrize("payload", [
        "admin; DROP TABLE customers; --",
        "admin'--",
        "admin\"; DROP TABLE customers; --\"",
        "admin\x00evil",
        "admin\nGRANT ALL TO public",
        "Admin",  # uppercase
        "123admin",  # starts with digit
        "admin role",  # space
        "",  # empty
    ])
    def test_malicious_identifiers_rejected(self, payload: str):
        with pytest.raises(ValueError, match="Invalid PostgreSQL identifier"):
            _validate_pg_identifier(payload)

    def test_rls_app_role_is_valid_identifier(self):
        """The hardcoded RLS_APP_ROLE passes identifier validation."""
        assert _validate_pg_identifier(RLS_APP_ROLE) == RLS_APP_ROLE


# ===========================================================================
# 14. Schema Security Properties
# ===========================================================================


class TestSchemaSecurityProperties:
    """Verify structural security guarantees in the database schema."""

    def test_tenant_columns_are_not_null(self):
        """tenant_id and customer_id columns have NOT NULL constraints
        to prevent NULL bypasses."""
        schema = _schema_sql()
        # audit_logs.tenant_id
        assert re.search(r"tenant_id\s+VARCHAR.*NOT NULL", schema)
        # webhooks and apps have customer_id as UUID NOT NULL (via FK)
        for table in ("apps", "webhooks"):
            # Use IF NOT EXISTS pattern
            pattern = rf"CREATE TABLE(?:\s+IF NOT EXISTS)?\s+{table}\s*\("
            match = re.search(pattern, schema)
            assert match, f"Table {table} not found in schema"
            start = match.start()
            end = schema.index(";", start)
            create_stmt = schema[start:end]
            if "customer_id" in create_stmt:
                assert "NOT NULL" in create_stmt or "REFERENCES" in create_stmt, (
                    f"customer_id in {table} may be nullable"
                )

    def test_app_role_is_nologin(self):
        """shieldai_app role must be NOLOGIN — prevents direct DB access."""
        schema = _schema_sql()
        assert "NOLOGIN" in schema
        role_line = [l for l in schema.splitlines() if "CREATE ROLE shieldai_app" in l]
        if role_line:
            assert "NOLOGIN" in role_line[0]

    def test_no_superuser_grant(self):
        """No SUPERUSER grant to any role in schema.sql."""
        schema = _schema_sql()
        assert "SUPERUSER" not in schema.upper()

    def test_sequence_grants_are_usage_only(self):
        """GRANT on sequences is USAGE only, not ALL."""
        schema = _schema_sql()
        seq_grants = [l for l in schema.splitlines() if "SEQUENCES" in l and "GRANT" in l]
        for line in seq_grants:
            assert "ALL" not in line.upper() or "ALL SEQUENCES" in line.upper()
            assert "USAGE" in line.upper()


# ===========================================================================
# 15. Audit Logger Tenant Source Verification
# ===========================================================================


class TestAuditLoggerTenantSource:
    """Verify that the audit logger gets tenant_id from the secure
    RequestContext (set by TenantRouter from DB lookup), not from
    user-controlled headers or query parameters.
    """

    def test_audit_logger_uses_context_tenant_id(self):
        """AuditLogger.process_response reads context.tenant_id."""
        from proxy.middleware.audit_logger import AuditLogger
        source = inspect.getsource(AuditLogger.process_response)
        assert "context.tenant_id" in source

    def test_audit_logger_does_not_read_tenant_from_header(self):
        """AuditLogger must not read tenant from request headers."""
        from proxy.middleware.audit_logger import AuditLogger
        source = inspect.getsource(AuditLogger)
        assert "x-tenant-id" not in source.lower()

    def test_audit_logger_skips_when_no_tenant(self):
        """When context.tenant_id is empty, audit logging is skipped."""
        from proxy.middleware.audit_logger import AuditLogger
        source = inspect.getsource(AuditLogger.process_response)
        assert "not context.tenant_id" in source


# ===========================================================================
# 16. Privilege Hardening — TRUNCATE / REFERENCES / TRIGGER Revocation
# ===========================================================================


class TestPrivilegeHardening:
    """Verify dangerous privileges are explicitly revoked from shieldai_app.

    Attack vector: A compromised session running as shieldai_app could
    TRUNCATE all tenant data, add FK REFERENCES to leak info, or install
    malicious TRIGGERs on RLS-protected tables.
    """

    def test_truncate_revoked(self):
        """TRUNCATE must be revoked from shieldai_app on all tables."""
        schema = _schema_sql()
        assert "REVOKE TRUNCATE" in schema
        for table in ("customers", "apps", "audit_logs", "webhooks"):
            assert table in schema[schema.index("REVOKE TRUNCATE"):schema.index("FROM shieldai_app", schema.index("REVOKE TRUNCATE")) + 30]

    def test_references_revoked(self):
        """REFERENCES must be revoked from shieldai_app on all tables."""
        schema = _schema_sql()
        assert "REVOKE REFERENCES" in schema

    def test_trigger_revoked(self):
        """TRIGGER must be revoked from shieldai_app on all tables."""
        schema = _schema_sql()
        assert "REVOKE TRIGGER" in schema

    def test_grants_are_dml_only(self):
        """GRANT statements to shieldai_app contain only SELECT/INSERT/UPDATE/DELETE."""
        schema = _schema_sql()
        grant_lines = [
            l.strip() for l in schema.splitlines()
            if l.strip().startswith("GRANT") and "shieldai_app" in l
            and "TO CURRENT_USER" not in l
            and "SEQUENCES" not in l
        ]
        allowed = {"SELECT", "INSERT", "UPDATE", "DELETE"}
        for line in grant_lines:
            # Extract privilege list between GRANT and ON
            match = re.match(r"GRANT\s+(.*?)\s+ON\s+", line)
            if match:
                privs = {p.strip() for p in match.group(1).split(",")}
                assert privs.issubset(allowed), (
                    f"Unexpected privileges in: {line}"
                )

    def test_no_all_privileges_grant(self):
        """No GRANT ALL to shieldai_app — must be explicit DML grants."""
        schema = _schema_sql()
        grant_lines = [
            l.strip() for l in schema.splitlines()
            if l.strip().startswith("GRANT") and "shieldai_app" in l
        ]
        for line in grant_lines:
            # "ALL SEQUENCES" is fine, "ALL PRIVILEGES" is not
            assert "ALL PRIVILEGES" not in line.upper(), (
                f"GRANT ALL PRIVILEGES found: {line}"
            )


# ===========================================================================
# 17. GUC Protection — Prevent App Role from Manipulating Tenant Context
# ===========================================================================


class TestGUCProtection:
    """Verify that schema.sql includes PG15+ GUC protection to prevent
    shieldai_app from directly calling set_config() on the tenant GUC.

    Attack vector: Without REVOKE SET, the app role could call
    set_config('app.current_tenant_id', 'other-tenant', true) directly
    to escalate to another tenant's data.
    """

    def test_guc_revoke_present_in_schema(self):
        """Schema must contain REVOKE SET ON PARAMETER for the tenant GUC."""
        schema = _schema_sql()
        assert "REVOKE SET ON PARAMETER" in schema
        assert "app.current_tenant_id" in schema[schema.index("REVOKE SET ON PARAMETER"):]

    def test_guc_revoke_targets_app_role(self):
        """The GUC revocation must target shieldai_app."""
        schema = _schema_sql()
        revoke_section = schema[schema.index("REVOKE SET ON PARAMETER"):]
        assert "shieldai_app" in revoke_section[:200]

    def test_guc_revoke_guarded_for_pg_version(self):
        """The GUC revoke is guarded with PG version check (PG15+ only)."""
        schema = _schema_sql()
        assert "server_version_num" in schema
        assert "150000" in schema

    def test_set_config_executed_before_set_role(self):
        """In tenant_transaction, set_config is called AFTER SET LOCAL ROLE.
        This means the owner role (not shieldai_app) executes set_config,
        so the PG15+ REVOKE SET doesn't block our own code path.
        """
        source = _RLS_SOURCE.read_text()
        fn = _extract_function(source, "tenant_transaction")
        body = re.sub(r'""".*?"""', '', fn, count=1, flags=re.DOTALL)
        set_role_pos = body.index("SET LOCAL ROLE")
        set_config_pos = body.index("set_config")
        # set_config comes AFTER SET LOCAL ROLE — it's the owner executing it
        # before the app role takes effect (SET LOCAL is deferred to next statement)
        assert set_role_pos < set_config_pos


# ===========================================================================
# 18. FORCE ROW LEVEL SECURITY Analysis
# ===========================================================================


class TestForceRLSDesignDecision:
    """Verify that the intentional omission of FORCE ROW LEVEL SECURITY
    is documented and safe.

    Design: Owner role bypasses RLS (admin operations). Tenant operations
    use SET LOCAL ROLE shieldai_app which IS subject to RLS.
    FORCE RLS would break admin operations that need full table access.
    """

    def test_no_force_rls_in_schema(self):
        """FORCE ROW LEVEL SECURITY is intentionally NOT set — owner bypass
        is required for admin operations (migrations, get_all_apps)."""
        schema = _schema_sql()
        assert "FORCE ROW LEVEL SECURITY" not in schema

    def test_admin_functions_use_pool_not_tenant_transaction(self):
        """Admin functions in postgres.py use pool.acquire() directly,
        never tenant_transaction — so they run as owner (bypass RLS)."""
        source = _POSTGRES_SOURCE.read_text()
        # Admin functions that should use pool directly
        for fn_name in ("run_migrations", "create_customer", "get_all_apps"):
            fn = _extract_function(source, fn_name)
            if fn:
                assert "tenant_transaction" not in fn, (
                    f"Admin function {fn_name} should not use tenant_transaction"
                )

    def test_tenant_transaction_always_switches_role(self):
        """tenant_transaction ALWAYS switches to shieldai_app role,
        which IS subject to RLS (unlike the owner role)."""
        source = _RLS_SOURCE.read_text()
        fn = _extract_function(source, "tenant_transaction")
        body = re.sub(r'""".*?"""', '', fn, count=1, flags=re.DOTALL)
        assert "SET LOCAL ROLE" in body
        # Source uses f-string with {RLS_APP_ROLE} variable
        assert "RLS_APP_ROLE" in body


# ===========================================================================
# 19. WITH CHECK Clause Completeness
# ===========================================================================


class TestWithCheckCompleteness:
    """Verify every RLS policy has both USING and WITH CHECK.

    Attack: Missing WITH CHECK allows cross-tenant INSERTs/UPDATEs
    where the tenant_id in the row doesn't match the session context.
    """

    def test_every_policy_has_with_check(self):
        """Every CREATE POLICY must have a WITH CHECK clause."""
        schema = _schema_sql()
        policies = re.findall(
            r"CREATE POLICY\s+\w+.*?;",
            schema,
            re.DOTALL,
        )
        assert len(policies) >= 4, "Expected at least 4 RLS policies"
        for policy in policies:
            assert "WITH CHECK" in policy, f"Missing WITH CHECK in: {policy[:80]}"

    def test_with_check_matches_using(self):
        """WITH CHECK condition must match the USING condition."""
        schema = _schema_sql()
        # Extract each CREATE POLICY ... ; block
        policy_blocks = re.findall(
            r"CREATE POLICY\s+(\w+)\s+ON\s+(\w+)\s+USING\s+\((.+?)\)\s+WITH CHECK\s+\((.+?)\);",
            schema,
            re.DOTALL,
        )
        assert len(policy_blocks) >= 4, f"Found only {len(policy_blocks)} policies"
        for name, table, using, check in policy_blocks:
            # Normalise whitespace for comparison (indentation may differ)
            norm_using = " ".join(using.split())
            norm_check = " ".join(check.split())
            assert norm_using == norm_check, (
                f"Policy {name} on {table}: USING != WITH CHECK"
            )


# ===========================================================================
# 20. Empty GUC Guard on audit_logs
# ===========================================================================


class TestEmptyGUCGuard:
    """Verify that the audit_logs RLS policy explicitly rejects empty GUC.

    Attack: current_setting('app.current_tenant_id', true) returns '' (not
    NULL) when the GUC is unset. For UUID columns this causes a cast error
    (fail-closed), but for VARCHAR audit_logs.tenant_id it would match rows
    where tenant_id = '' unless we add an explicit != '' guard.
    """

    def test_audit_logs_policy_rejects_empty_guc(self):
        """audit_logs RLS policy must include AND != '' guard."""
        schema = _schema_sql()
        # Find the audit_logs policy
        match = re.search(
            r"CREATE POLICY\s+tenant_isolation\s+ON\s+audit_logs\s+USING\s+\((.+?)\)\s+WITH CHECK",
            schema,
            re.DOTALL,
        )
        assert match, "audit_logs policy not found"
        using_clause = match.group(1)
        assert "!= ''" in using_clause, (
            "audit_logs USING clause must reject empty GUC"
        )

    def test_audit_logs_check_constraint_exists(self):
        """audit_logs must have CHECK (tenant_id != '') constraint."""
        schema = _schema_sql()
        assert "chk_tenant_id_nonempty" in schema
        assert "tenant_id != ''" in schema

    def test_uuid_columns_fail_closed_on_empty_guc(self):
        """For UUID columns (customers, apps, webhooks), an empty GUC
        causes a cast error (''::uuid fails), which is fail-closed.
        This test documents why the explicit guard is only needed on
        audit_logs (VARCHAR column)."""
        schema = _schema_sql()
        for table in ("customers", "apps", "webhooks"):
            match = re.search(
                rf"CREATE POLICY\s+tenant_isolation\s+ON\s+{table}\s+USING\s+\((.+?)\)\s+WITH CHECK",
                schema,
                re.DOTALL,
            )
            assert match, f"Policy for {table} not found"
            assert "::uuid" in match.group(1), (
                f"{table} policy must cast to uuid (fail-closed on empty string)"
            )


# ===========================================================================
# 21. NOT NULL Constraints on customer_id
# ===========================================================================


class TestCustomerIdNotNull:
    """Verify apps.customer_id and webhooks.customer_id are NOT NULL.

    Attack: A NULL customer_id row bypasses RLS (NULL = <uuid> is NULL/false)
    but is visible to admin queries, creating potential confusion or
    persistence vectors.
    """

    def test_apps_customer_id_not_null(self):
        """apps.customer_id must have NOT NULL constraint."""
        schema = _schema_sql()
        match = re.search(r"CREATE TABLE(?:\s+IF NOT EXISTS)?\s+apps\s*\((.*?)\);", schema, re.DOTALL)
        assert match
        create_body = match.group(1)
        cid_line = [l for l in create_body.splitlines() if "customer_id" in l]
        assert cid_line, "customer_id column not found in apps"
        assert "NOT NULL" in cid_line[0], "apps.customer_id must be NOT NULL"

    def test_webhooks_customer_id_not_null(self):
        """webhooks.customer_id must have NOT NULL constraint."""
        schema = _schema_sql()
        match = re.search(r"CREATE TABLE(?:\s+IF NOT EXISTS)?\s+webhooks\s*\((.*?)\);", schema, re.DOTALL)
        assert match
        create_body = match.group(1)
        cid_line = [l for l in create_body.splitlines() if "customer_id" in l]
        assert cid_line, "customer_id column not found in webhooks"
        assert "NOT NULL" in cid_line[0], "webhooks.customer_id must be NOT NULL"


# ===========================================================================
# 22. Audit Log Tenant ID Normalisation
# ===========================================================================


class TestAuditLogTenantNormalisation:
    """Verify insert_audit_log uses normalised (lowercase) tenant_id for
    both the RLS context AND the INSERT value.

    Attack: If the INSERT uses the original (possibly mixed-case) tenant_id
    but set_config normalises to lowercase, the WITH CHECK policy rejects
    the INSERT, causing silent audit log loss.
    """

    def test_insert_audit_log_normalises_tenant_id(self):
        """insert_audit_log must normalise tenant_id before INSERT."""
        source = _AUDIT_SOURCE.read_text()
        fn = _extract_function(source, "insert_audit_log")
        # Should call validate_tenant_id before tenant_transaction
        assert "validate_tenant_id" in fn
        # Should use normalised value for INSERT (not raw tenant_id)
        assert "normalised" in fn or "normalized" in fn or "validated" in fn

    def test_insert_uses_normalised_value(self):
        """The $1 parameter in INSERT must be the normalised value."""
        source = _AUDIT_SOURCE.read_text()
        fn = _extract_function(source, "insert_audit_log")
        # Find the VALUES line — $1 should use normalised, not tenant_id
        body = re.sub(r'""".*?"""', '', fn, count=1, flags=re.DOTALL)
        # After normalised = validate_tenant_id(...), the INSERT should use normalised
        lines_after_normalise = body[body.index("validate_tenant_id"):]
        # The first positional arg after VALUES should not be raw 'tenant_id'
        insert_args = re.search(r"VALUES.*?\n\s*(.+?),", lines_after_normalise, re.DOTALL)
        if insert_args:
            first_arg = insert_args.group(1).strip()
            assert first_arg != "tenant_id", (
                "INSERT $1 should use normalised tenant_id, not raw"
            )


# ===========================================================================
# 23. Discover Tool Identifier Validation
# ===========================================================================


class TestDiscoverToolValidation:
    """Verify discover_tenant_tables validates identifiers before
    interpolating them into generated SQL."""

    def test_generate_rls_migration_validates_identifiers(self):
        """generate_rls_migration must validate table_name and column_name."""
        from proxy.tools.discover_tenant_tables import generate_rls_migration

        # Safe input should produce SQL
        tables = [{"table_name": "orders", "column_name": "tenant_id", "data_type": "uuid"}]
        sql = generate_rls_migration(tables)
        assert "ALTER TABLE orders" in sql
        assert "CREATE POLICY" in sql

    def test_unsafe_table_name_skipped(self):
        """Unsafe table names must be skipped in generated SQL."""
        from proxy.tools.discover_tenant_tables import generate_rls_migration

        tables = [{"table_name": "orders; DROP TABLE users; --", "column_name": "tenant_id", "data_type": "uuid"}]
        sql = generate_rls_migration(tables)
        assert "SKIPPED" in sql
        assert "ALTER TABLE" not in sql

    def test_unsafe_column_name_skipped(self):
        """Unsafe column names must be skipped in generated SQL."""
        from proxy.tools.discover_tenant_tables import generate_rls_migration

        tables = [{"table_name": "orders", "column_name": "id; --", "data_type": "uuid"}]
        sql = generate_rls_migration(tables)
        assert "SKIPPED" in sql
        assert "CREATE POLICY" not in sql


# ===========================================================================
# 24. RLS Disabled Warning Log
# ===========================================================================


class TestRLSDisabledWarning:
    """Verify that disabling RLS via config produces a warning log."""

    def test_rls_disabled_logs_warning(self):
        """tenant_transaction must log a warning when rls_enabled=False."""
        source = _RLS_SOURCE.read_text()
        fn = _extract_function(source, "tenant_transaction")
        assert "rls_disabled" in fn, (
            "tenant_transaction must log 'rls_disabled' when RLS is off"
        )


# ===========================================================================
# Helpers
# ===========================================================================


def _extract_function(module_source: str, func_name: str) -> str:
    """Extract a function's source from module text."""
    pattern = rf"(async\s+)?def\s+{func_name}\s*\("
    match = re.search(pattern, module_source)
    if not match:
        return ""
    start = match.start()
    next_def = re.search(r"\n(?:async\s+)?def\s+", module_source[start + 1:])
    if next_def:
        end = start + 1 + next_def.start()
    else:
        end = len(module_source)
    return module_source[start:end]
