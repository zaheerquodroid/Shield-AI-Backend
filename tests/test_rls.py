"""Unit tests for proxy/store/rls.py — Row-Level Security tenant isolation."""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import proxy.store.postgres as pg_store
from proxy.store.rls import (
    RLS_APP_ROLE,
    _validate_pg_identifier,
    ensure_rls_setup,
    tenant_transaction,
    validate_tenant_id,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

VALID_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
VALID_UUID_UPPER = "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"


def _make_pool_mock():
    """Build a mock pool with acquire() returning an async ctx manager."""
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()
    mock_conn.fetchval = AsyncMock(return_value=None)

    mock_tx = AsyncMock()
    mock_tx.__aenter__ = AsyncMock(return_value=None)
    mock_tx.__aexit__ = AsyncMock(return_value=False)
    mock_conn.transaction = MagicMock(return_value=mock_tx)

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    mock_pool = MagicMock()
    mock_pool.acquire = MagicMock(return_value=mock_ctx)
    return mock_pool, mock_conn, mock_tx


# ===========================================================================
# TestValidateTenantId
# ===========================================================================


class TestValidateTenantId:
    """validate_tenant_id must accept only well-formed UUID strings."""

    def test_valid_uuid_accepted(self):
        result = validate_tenant_id(VALID_UUID)
        assert result == VALID_UUID

    def test_returns_lowercased(self):
        result = validate_tenant_id(VALID_UUID)
        assert result == result.lower()

    def test_uppercase_uuid_normalized(self):
        result = validate_tenant_id(VALID_UUID_UPPER)
        assert result == VALID_UUID_UPPER.lower()

    def test_uuid_without_hyphens_rejected(self):
        no_hyphens = VALID_UUID.replace("-", "")
        with pytest.raises(ValueError, match="not a valid UUID"):
            validate_tenant_id(no_hyphens)

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="must not be empty"):
            validate_tenant_id("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="must not be empty"):
            validate_tenant_id("   ")

    def test_none_raises(self):
        with pytest.raises(ValueError, match="must be a string"):
            validate_tenant_id(None)  # type: ignore[arg-type]

    def test_integer_raises(self):
        with pytest.raises(ValueError, match="must be a string"):
            validate_tenant_id(12345)  # type: ignore[arg-type]

    def test_sql_injection_rejected(self):
        with pytest.raises(ValueError, match="not a valid UUID"):
            validate_tenant_id("'; DROP TABLE customers; --")

    def test_sqli_or_bypass_rejected(self):
        with pytest.raises(ValueError, match="not a valid UUID"):
            validate_tenant_id("' OR '1'='1")

    def test_null_byte_rejected(self):
        with pytest.raises(ValueError, match="not a valid UUID"):
            validate_tenant_id("\x00abc")

    def test_unicode_trick_rejected(self):
        # fullwidth digits look like digits but are not 0-9a-f
        with pytest.raises(ValueError):
            validate_tenant_id("\uff11\uff12b2c3d4-e5f6-7890-abcd-ef1234567890")

    def test_just_hyphens_rejected(self):
        with pytest.raises(ValueError, match="not a valid UUID"):
            validate_tenant_id("--------")


# ===========================================================================
# TestRLSAppRole
# ===========================================================================


class TestRLSAppRole:
    """RLS_APP_ROLE constant checks."""

    def test_value(self):
        assert RLS_APP_ROLE == "shieldai_app"

    def test_is_string(self):
        assert isinstance(RLS_APP_ROLE, str)


# ===========================================================================
# TestTenantTransaction
# ===========================================================================


class TestTenantTransaction:
    """tenant_transaction async context manager."""

    @pytest.fixture(autouse=True)
    def _mock_pool(self):
        """Inject a mock pool and restore original after each test."""
        self.original_pool = pg_store._pool
        self.mock_pool, self.mock_conn, self.mock_tx = _make_pool_mock()
        pg_store._pool = self.mock_pool
        yield
        pg_store._pool = self.original_pool

    @pytest.mark.asyncio
    async def test_set_local_role_is_first_statement(self):
        async with tenant_transaction(VALID_UUID) as conn:
            pass
        first_call = self.mock_conn.execute.call_args_list[0]
        assert "SET LOCAL ROLE" in first_call.args[0]

    @pytest.mark.asyncio
    async def test_set_config_is_second_statement(self):
        async with tenant_transaction(VALID_UUID) as conn:
            pass
        second_call = self.mock_conn.execute.call_args_list[1]
        assert "set_config" in second_call.args[0]

    @pytest.mark.asyncio
    async def test_set_config_uses_validated_tenant_id(self):
        async with tenant_transaction(VALID_UUID_UPPER) as conn:
            pass
        second_call = self.mock_conn.execute.call_args_list[1]
        # The second positional arg is the tenant_id parameter
        assert second_call.args[1] == VALID_UUID_UPPER.lower()

    @pytest.mark.asyncio
    async def test_yields_connection(self):
        async with tenant_transaction(VALID_UUID) as conn:
            assert conn is self.mock_conn

    @pytest.mark.asyncio
    async def test_pool_unavailable_raises(self):
        pg_store._pool = None
        with pytest.raises(pg_store.StoreUnavailable):
            async with tenant_transaction(VALID_UUID) as conn:
                pass

    @pytest.mark.asyncio
    async def test_invalid_tenant_id_raises_before_pool(self):
        """Invalid tenant_id should raise ValueError before touching the pool."""
        with pytest.raises(ValueError):
            async with tenant_transaction("not-a-uuid") as conn:
                pass
        # Pool should never have been accessed
        self.mock_pool.acquire.assert_not_called()

    @pytest.mark.asyncio
    async def test_connection_acquired_from_pool(self):
        async with tenant_transaction(VALID_UUID) as conn:
            pass
        self.mock_pool.acquire.assert_called_once()

    @pytest.mark.asyncio
    async def test_transaction_started(self):
        async with tenant_transaction(VALID_UUID) as conn:
            pass
        self.mock_conn.transaction.assert_called_once()

    @pytest.mark.asyncio
    async def test_set_local_role_uses_constant(self):
        async with tenant_transaction(VALID_UUID) as conn:
            pass
        first_call = self.mock_conn.execute.call_args_list[0]
        assert first_call.args[0] == f"SET LOCAL ROLE {RLS_APP_ROLE}"

    @pytest.mark.asyncio
    async def test_set_config_uses_parameterized_query(self):
        async with tenant_transaction(VALID_UUID) as conn:
            pass
        second_call = self.mock_conn.execute.call_args_list[1]
        sql = second_call.args[0]
        assert "$1" in sql
        assert "app.current_tenant_id" in sql

    @pytest.mark.asyncio
    async def test_set_config_third_arg_is_true(self):
        """set_config third arg 'true' makes it transaction-local."""
        async with tenant_transaction(VALID_UUID) as conn:
            pass
        second_call = self.mock_conn.execute.call_args_list[1]
        sql = second_call.args[0]
        # The SQL literal includes 'true' as the third arg to set_config
        assert "true" in sql

    @pytest.mark.asyncio
    async def test_connection_released_after_block(self):
        """After exiting the ctx manager the connection ctx __aexit__ is called."""
        mock_ctx = self.mock_pool.acquire.return_value
        async with tenant_transaction(VALID_UUID) as conn:
            pass
        mock_ctx.__aexit__.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_concurrent_calls_get_independent_connections(self):
        """Two concurrent tenant_transaction calls each acquire independently."""
        mock_pool2, mock_conn2, _ = _make_pool_mock()

        call_count = 0
        conns = [self.mock_conn, mock_conn2]
        ctxs = []
        for c in conns:
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=c)
            ctx.__aexit__ = AsyncMock(return_value=False)
            ctxs.append(ctx)

        def side_effect():
            nonlocal call_count
            idx = call_count
            call_count += 1
            return ctxs[idx]

        self.mock_pool.acquire = MagicMock(side_effect=side_effect)

        captured = []

        async def use_tx(tid):
            async with tenant_transaction(tid) as conn:
                captured.append(conn)

        await asyncio.gather(use_tx(VALID_UUID), use_tx(VALID_UUID))
        assert len(captured) == 2
        assert captured[0] is not captured[1]

    @pytest.mark.asyncio
    async def test_exception_inside_block_propagates(self):
        with pytest.raises(RuntimeError, match="boom"):
            async with tenant_transaction(VALID_UUID) as conn:
                raise RuntimeError("boom")

    @pytest.mark.asyncio
    async def test_rollback_on_exception(self):
        """Transaction ctx manager __aexit__ receives exception info for rollback."""
        try:
            async with tenant_transaction(VALID_UUID) as conn:
                raise RuntimeError("fail")
        except RuntimeError:
            pass
        # The transaction mock's __aexit__ was called (handles rollback)
        self.mock_tx.__aexit__.assert_awaited_once()
        # Verify it was called with exception info (non-None exc_type)
        exit_args = self.mock_tx.__aexit__.call_args.args
        assert exit_args[0] is RuntimeError


# ===========================================================================
# TestEnsureRlsSetup
# ===========================================================================


class TestEnsureRlsSetup:
    """ensure_rls_setup idempotent role/grant creation."""

    @pytest.mark.asyncio
    async def test_creates_role_when_not_exists(self):
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(side_effect=[None, "owner_user"])
        mock_conn.execute = AsyncMock()
        await ensure_rls_setup(mock_conn)
        # Should have called CREATE ROLE
        create_calls = [
            c for c in mock_conn.execute.call_args_list
            if "CREATE ROLE" in str(c)
        ]
        assert len(create_calls) == 1
        assert RLS_APP_ROLE in create_calls[0].args[0]

    @pytest.mark.asyncio
    async def test_skips_creation_when_role_exists(self):
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(side_effect=[1, "owner_user"])
        mock_conn.execute = AsyncMock()
        await ensure_rls_setup(mock_conn)
        create_calls = [
            c for c in mock_conn.execute.call_args_list
            if "CREATE ROLE" in str(c)
        ]
        assert len(create_calls) == 0

    @pytest.mark.asyncio
    async def test_grants_role_to_current_user(self):
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(side_effect=[1, "myuser"])
        mock_conn.execute = AsyncMock()
        await ensure_rls_setup(mock_conn)
        grant_calls = [
            c for c in mock_conn.execute.call_args_list
            if "GRANT" in str(c)
        ]
        assert len(grant_calls) == 1
        assert "myuser" in grant_calls[0].args[0]

    @pytest.mark.asyncio
    async def test_queries_current_user(self):
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(side_effect=[1, "dbadmin"])
        mock_conn.execute = AsyncMock()
        await ensure_rls_setup(mock_conn)
        fetchval_calls = mock_conn.fetchval.call_args_list
        # Second fetchval call should be SELECT current_user
        assert "current_user" in fetchval_calls[1].args[0]

    @pytest.mark.asyncio
    async def test_uses_rls_app_role_constant(self):
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(side_effect=[None, "owner"])
        mock_conn.execute = AsyncMock()
        await ensure_rls_setup(mock_conn)
        # The first fetchval checks pg_roles for the RLS_APP_ROLE
        first_fetchval_args = mock_conn.fetchval.call_args_list[0]
        assert first_fetchval_args.args[1] == RLS_APP_ROLE

    @pytest.mark.asyncio
    async def test_logs_on_creation(self):
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(side_effect=[None, "owner"])
        mock_conn.execute = AsyncMock()
        with patch("proxy.store.rls.logger") as mock_logger:
            await ensure_rls_setup(mock_conn)
            # Should log rls_role_created
            mock_logger.info.assert_any_call("rls_role_created", role=RLS_APP_ROLE)

    @pytest.mark.asyncio
    async def test_logs_on_verification(self):
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(side_effect=[1, "owner"])
        mock_conn.execute = AsyncMock()
        with patch("proxy.store.rls.logger") as mock_logger:
            await ensure_rls_setup(mock_conn)
            mock_logger.info.assert_any_call(
                "rls_setup_verified", app_role=RLS_APP_ROLE, owner="owner"
            )

    @pytest.mark.asyncio
    async def test_idempotent_double_call(self):
        """Calling ensure_rls_setup twice should not raise."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(side_effect=[None, "owner", 1, "owner"])
        mock_conn.execute = AsyncMock()
        await ensure_rls_setup(mock_conn)
        await ensure_rls_setup(mock_conn)
        # CREATE ROLE should only appear once (first call creates, second skips)
        create_calls = [
            c for c in mock_conn.execute.call_args_list
            if "CREATE ROLE" in str(c)
        ]
        assert len(create_calls) == 1


# ===========================================================================
# TestRLSSchemaSetup — verify schema.sql RLS declarations
# ===========================================================================


class TestRLSSchemaSetup:
    """Static analysis of schema.sql for RLS correctness."""

    @pytest.fixture(autouse=True)
    def _load_schema(self):
        schema_path = Path(__file__).parent.parent / "proxy" / "models" / "schema.sql"
        self.schema = schema_path.read_text()

    def test_rls_enabled_on_customers(self):
        assert "ALTER TABLE customers ENABLE ROW LEVEL SECURITY" in self.schema

    def test_rls_enabled_on_apps(self):
        assert "ALTER TABLE apps ENABLE ROW LEVEL SECURITY" in self.schema

    def test_rls_enabled_on_audit_logs(self):
        assert "ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY" in self.schema

    def test_rls_enabled_on_webhooks(self):
        assert "ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY" in self.schema

    def test_tenant_isolation_policy_on_all_tables(self):
        for table in ("customers", "apps", "audit_logs", "webhooks"):
            assert f"CREATE POLICY tenant_isolation ON {table}" in self.schema, (
                f"Missing tenant_isolation policy on {table}"
            )

    def test_shieldai_app_role_creation(self):
        assert "CREATE ROLE shieldai_app" in self.schema

    def test_grant_statements_for_app_role(self):
        for table in ("customers", "apps", "audit_logs", "webhooks"):
            assert f"ON {table} TO shieldai_app" in self.schema, (
                f"Missing GRANT for shieldai_app on {table}"
            )

    def test_current_setting_with_true_null_safe(self):
        """current_setting uses the second arg 'true' for NULL-safe behavior."""
        assert "current_setting('app.current_tenant_id', true)" in self.schema

    def test_customers_policy_uses_id_not_customer_id(self):
        """customers table policy uses 'id' (PK) not 'customer_id'."""
        # Find the customers policy block
        idx = self.schema.index("CREATE POLICY tenant_isolation ON customers")
        block = self.schema[idx : idx + 200]
        assert "USING (id =" in block
        assert "customer_id" not in block

    def test_audit_logs_policy_no_uuid_cast(self):
        """audit_logs policy compares as varchar (no ::uuid cast)."""
        idx = self.schema.index("CREATE POLICY tenant_isolation ON audit_logs")
        block = self.schema[idx : idx + 300]
        assert "::uuid" not in block


# ===========================================================================
# TestAdminBypass — admin functions in postgres.py bypass RLS
# ===========================================================================


class TestAdminBypass:
    """Admin functions should use pool.acquire directly, never tenant_transaction."""

    @pytest.fixture(autouse=True)
    def _load_source(self):
        source_path = Path(__file__).parent.parent / "proxy" / "store" / "postgres.py"
        self.source = source_path.read_text()

    def test_get_all_apps_uses_pool_acquire(self):
        src = inspect.getsource(pg_store.get_all_apps)
        assert "_pool.acquire" in src or "pool.acquire" in src

    def test_run_migrations_uses_pool_acquire(self):
        src = inspect.getsource(pg_store.run_migrations)
        assert "_pool.acquire" in src or "pool.acquire" in src

    def test_create_customer_uses_pool_acquire(self):
        src = inspect.getsource(pg_store.create_customer)
        assert "_pool.acquire" in src or "pool.acquire" in src

    def test_admin_functions_do_not_call_tenant_transaction(self):
        for fn_name in ("get_all_apps", "run_migrations", "create_customer"):
            src = inspect.getsource(getattr(pg_store, fn_name))
            assert "tenant_transaction" not in src, (
                f"{fn_name} should not call tenant_transaction"
            )

    def test_admin_functions_not_wrapped_with_rls(self):
        """No admin function's source mentions SET LOCAL ROLE."""
        admin_fns = [
            "get_all_apps", "run_migrations", "create_customer",
            "delete_customer", "create_app", "delete_app",
        ]
        for fn_name in admin_fns:
            src = inspect.getsource(getattr(pg_store, fn_name))
            assert "SET LOCAL ROLE" not in src, (
                f"{fn_name} should not contain SET LOCAL ROLE"
            )


# ===========================================================================
# TestValidatePgIdentifier
# ===========================================================================


class TestValidatePgIdentifier:
    """_validate_pg_identifier defends against identifier injection in DDL."""

    def test_valid_identifier(self):
        assert _validate_pg_identifier("shieldai_app") == "shieldai_app"

    def test_underscore_prefix(self):
        assert _validate_pg_identifier("_internal") == "_internal"

    def test_alphanumeric_with_digits(self):
        assert _validate_pg_identifier("role_v2") == "role_v2"

    def test_single_char(self):
        assert _validate_pg_identifier("x") == "x"

    def test_rejects_uppercase(self):
        with pytest.raises(ValueError, match="Invalid PostgreSQL identifier"):
            _validate_pg_identifier("ADMIN")

    def test_rejects_mixed_case(self):
        with pytest.raises(ValueError, match="Invalid PostgreSQL identifier"):
            _validate_pg_identifier("myRole")

    def test_rejects_space(self):
        with pytest.raises(ValueError, match="Invalid PostgreSQL identifier"):
            _validate_pg_identifier("my role")

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError, match="Invalid PostgreSQL identifier"):
            _validate_pg_identifier("role; DROP TABLE x")

    def test_rejects_hyphen(self):
        with pytest.raises(ValueError, match="Invalid PostgreSQL identifier"):
            _validate_pg_identifier("my-role")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="Invalid PostgreSQL identifier"):
            _validate_pg_identifier("")

    def test_rejects_none(self):
        with pytest.raises(ValueError, match="Invalid PostgreSQL identifier"):
            _validate_pg_identifier(None)  # type: ignore[arg-type]

    def test_rejects_digit_start(self):
        with pytest.raises(ValueError, match="Invalid PostgreSQL identifier"):
            _validate_pg_identifier("1role")

    def test_max_length_accepted(self):
        name = "a" * 63
        assert _validate_pg_identifier(name) == name

    def test_exceeds_max_length_rejected(self):
        with pytest.raises(ValueError, match="Invalid PostgreSQL identifier"):
            _validate_pg_identifier("a" * 64)


# ===========================================================================
# TestRLSDisabledConfig
# ===========================================================================


class TestRLSDisabledConfig:
    """When rls_enabled=False, tenant_transaction skips SET LOCAL ROLE / set_config."""

    @pytest.fixture(autouse=True)
    def _mock_pool(self):
        self.original_pool = pg_store._pool
        self.mock_pool, self.mock_conn, self.mock_tx = _make_pool_mock()
        pg_store._pool = self.mock_pool
        yield
        pg_store._pool = self.original_pool

    @pytest.mark.asyncio
    async def test_rls_disabled_skips_set_role(self):
        """When rls_enabled=False, SET LOCAL ROLE is NOT executed."""
        with patch("proxy.store.rls._is_rls_enabled", return_value=False):
            async with tenant_transaction(VALID_UUID) as conn:
                pass
        for call in self.mock_conn.execute.call_args_list:
            assert "SET LOCAL ROLE" not in str(call)

    @pytest.mark.asyncio
    async def test_rls_disabled_skips_set_config(self):
        """When rls_enabled=False, set_config is NOT executed."""
        with patch("proxy.store.rls._is_rls_enabled", return_value=False):
            async with tenant_transaction(VALID_UUID) as conn:
                pass
        for call in self.mock_conn.execute.call_args_list:
            assert "set_config" not in str(call)

    @pytest.mark.asyncio
    async def test_rls_disabled_still_validates_tenant_id(self):
        """Even with rls_enabled=False, invalid tenant_id is rejected."""
        with patch("proxy.store.rls._is_rls_enabled", return_value=False):
            with pytest.raises(ValueError, match="not a valid UUID"):
                async with tenant_transaction("not-a-uuid") as conn:
                    pass

    @pytest.mark.asyncio
    async def test_rls_disabled_still_yields_connection(self):
        """Connection is still yielded inside a transaction."""
        with patch("proxy.store.rls._is_rls_enabled", return_value=False):
            async with tenant_transaction(VALID_UUID) as conn:
                assert conn is self.mock_conn

    @pytest.mark.asyncio
    async def test_rls_disabled_still_uses_transaction(self):
        """Transaction is started even when RLS is disabled."""
        with patch("proxy.store.rls._is_rls_enabled", return_value=False):
            async with tenant_transaction(VALID_UUID) as conn:
                pass
        self.mock_conn.transaction.assert_called_once()

    @pytest.mark.asyncio
    async def test_rls_disabled_no_execute_calls(self):
        """With rls_enabled=False, conn.execute is never called by tenant_transaction."""
        with patch("proxy.store.rls._is_rls_enabled", return_value=False):
            async with tenant_transaction(VALID_UUID) as conn:
                pass
        self.mock_conn.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_rls_enabled_does_execute(self):
        """With rls_enabled=True (default), conn.execute IS called."""
        async with tenant_transaction(VALID_UUID) as conn:
            pass
        assert self.mock_conn.execute.call_count == 2


# ===========================================================================
# TestEnsureRlsSetupIdentifierValidation
# ===========================================================================


class TestEnsureRlsSetupIdentifierValidation:
    """ensure_rls_setup rejects malicious identifiers."""

    @pytest.mark.asyncio
    async def test_rejects_malicious_current_user(self):
        """If current_user contains injection, ensure_rls_setup raises ValueError."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(side_effect=[1, "admin; DROP TABLE users"])
        mock_conn.execute = AsyncMock()
        with pytest.raises(ValueError, match="Invalid PostgreSQL identifier"):
            await ensure_rls_setup(mock_conn)

    @pytest.mark.asyncio
    async def test_rejects_uppercase_current_user(self):
        """PostgreSQL returns lowercase by default; uppercase is suspicious."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(side_effect=[1, "ADMIN"])
        mock_conn.execute = AsyncMock()
        with pytest.raises(ValueError, match="Invalid PostgreSQL identifier"):
            await ensure_rls_setup(mock_conn)
