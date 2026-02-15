"""Direct unit tests for proxy/store/postgres.py."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from proxy.store import postgres as pg_store


class TestHashApiKey:
    def test_returns_pbkdf2_format(self):
        result = pg_store.hash_api_key("my-secret")
        parts = result.split("$")
        assert len(parts) == 3
        assert parts[0] == "pbkdf2"

    def test_salted_not_deterministic(self):
        """Two hashes of the same key differ due to random salt."""
        a = pg_store.hash_api_key("my-secret")
        b = pg_store.hash_api_key("my-secret")
        assert a != b

    def test_different_keys_produce_different_hashes(self):
        a = pg_store.hash_api_key("key-a")
        b = pg_store.hash_api_key("key-b")
        assert a != b

    def test_empty_key(self):
        result = pg_store.hash_api_key("")
        assert result.startswith("pbkdf2$")


class TestPoolNonePaths:
    """All CRUD helpers should raise StoreUnavailable when _pool is None."""

    @pytest.fixture(autouse=True)
    def _ensure_no_pool(self):
        original = pg_store._pool
        pg_store._pool = None
        yield
        pg_store._pool = original

    @pytest.mark.asyncio
    async def test_create_customer_raises(self):
        with pytest.raises(pg_store.StoreUnavailable):
            await pg_store.create_customer("n", "p", "k", {})

    @pytest.mark.asyncio
    async def test_get_customer_raises(self):
        with pytest.raises(pg_store.StoreUnavailable):
            await pg_store.get_customer(uuid4())

    @pytest.mark.asyncio
    async def test_update_customer_raises(self):
        with pytest.raises(pg_store.StoreUnavailable):
            await pg_store.update_customer(uuid4(), name="x")

    @pytest.mark.asyncio
    async def test_delete_customer_raises(self):
        with pytest.raises(pg_store.StoreUnavailable):
            await pg_store.delete_customer(uuid4())

    @pytest.mark.asyncio
    async def test_create_app_raises(self):
        with pytest.raises(pg_store.StoreUnavailable):
            await pg_store.create_app(uuid4(), "n", "u", "d", {}, {})

    @pytest.mark.asyncio
    async def test_get_app_raises(self):
        with pytest.raises(pg_store.StoreUnavailable):
            await pg_store.get_app(uuid4())

    @pytest.mark.asyncio
    async def test_update_app_raises(self):
        with pytest.raises(pg_store.StoreUnavailable):
            await pg_store.update_app(uuid4(), name="x")

    @pytest.mark.asyncio
    async def test_delete_app_raises(self):
        with pytest.raises(pg_store.StoreUnavailable):
            await pg_store.delete_app(uuid4())

    @pytest.mark.asyncio
    async def test_get_all_apps_raises(self):
        with pytest.raises(pg_store.StoreUnavailable):
            await pg_store.get_all_apps()

    @pytest.mark.asyncio
    async def test_run_migrations_skipped(self):
        """Migrations do nothing when pool is None."""
        await pg_store.run_migrations()  # should not raise


class TestColumnWhitelist:
    """update_customer/update_app reject non-whitelisted column names."""

    @pytest.fixture(autouse=True)
    def _mock_pool(self):
        original = pg_store._pool
        pg_store._pool = MagicMock()
        yield
        pg_store._pool = original

    @pytest.mark.asyncio
    async def test_update_customer_rejects_bad_column(self):
        with pytest.raises(ValueError, match="Invalid column name"):
            await pg_store.update_customer(uuid4(), **{"id; DROP TABLE customers--": "evil"})

    @pytest.mark.asyncio
    async def test_update_customer_rejects_id_column(self):
        with pytest.raises(ValueError, match="Invalid column name"):
            await pg_store.update_customer(uuid4(), id=uuid4())

    @pytest.mark.asyncio
    async def test_update_app_rejects_bad_column(self):
        with pytest.raises(ValueError, match="Invalid column name"):
            await pg_store.update_app(uuid4(), **{"1=1; --": "evil"})

    @pytest.mark.asyncio
    async def test_update_app_customer_id_is_scope_not_column(self):
        """customer_id is a scoping param, not an update column — no ValueError."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        pg_store._pool.acquire = MagicMock(return_value=mock_ctx)
        # customer_id scopes the WHERE clause, does not go into SET
        result = await pg_store.update_app(uuid4(), customer_id=uuid4(), name="ok")
        assert result is None  # No matching row

    @pytest.mark.asyncio
    async def test_update_customer_allows_valid_columns(self):
        """Whitelisted columns should not raise."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        pg_store._pool.acquire = MagicMock(return_value=mock_ctx)

        # Should not raise
        await pg_store.update_customer(uuid4(), name="ok", plan="pro")

    @pytest.mark.asyncio
    async def test_update_app_allows_valid_columns(self):
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        pg_store._pool.acquire = MagicMock(return_value=mock_ctx)

        await pg_store.update_app(uuid4(), name="ok", domain="x.com")


class TestUpdateNoChanges:
    """update with all-None fields delegates to get."""

    @pytest.fixture(autouse=True)
    def _mock_pool(self):
        original = pg_store._pool
        pg_store._pool = MagicMock()
        yield
        pg_store._pool = original

    @pytest.mark.asyncio
    async def test_update_customer_no_fields_calls_get(self):
        cid = uuid4()
        with patch.object(pg_store, "get_customer", new_callable=AsyncMock, return_value={"id": cid}) as mock_get:
            result = await pg_store.update_customer(cid)
        mock_get.assert_awaited_once_with(cid)
        assert result["id"] == cid

    @pytest.mark.asyncio
    async def test_update_app_no_fields_calls_get(self):
        aid = uuid4()
        with patch.object(pg_store, "get_app", new_callable=AsyncMock, return_value={"id": aid}) as mock_get:
            result = await pg_store.update_app(aid)
        mock_get.assert_awaited_once_with(aid, customer_id=None)


class TestInitPostgres:
    @pytest.mark.asyncio
    async def test_init_returns_none_without_asyncpg(self):
        with patch.object(pg_store, "asyncpg", None):
            result = await pg_store.init_postgres("postgresql://x")
        assert result is None

    @pytest.mark.asyncio
    async def test_init_returns_none_on_exception(self):
        mock_asyncpg = MagicMock()
        mock_asyncpg.create_pool = AsyncMock(side_effect=Exception("connection refused"))
        with patch.object(pg_store, "asyncpg", mock_asyncpg):
            original = pg_store._pool
            result = await pg_store.init_postgres("postgresql://x")
            pg_store._pool = original
        assert result is None


class TestClosePostgres:
    @pytest.mark.asyncio
    async def test_close_when_pool_exists(self):
        mock_pool = AsyncMock()
        original = pg_store._pool
        pg_store._pool = mock_pool
        await pg_store.close_postgres()
        mock_pool.close.assert_awaited_once()
        assert pg_store._pool is None
        pg_store._pool = original

    @pytest.mark.asyncio
    async def test_close_when_no_pool(self):
        original = pg_store._pool
        pg_store._pool = None
        await pg_store.close_postgres()  # should not raise
        pg_store._pool = original
