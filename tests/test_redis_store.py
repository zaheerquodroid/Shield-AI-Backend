"""Direct unit tests for proxy/store/redis.py."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from proxy.store import redis as redis_store


@pytest.fixture(autouse=True)
def _reset_pool():
    """Ensure clean pool state for each test."""
    original = redis_store._pool
    yield
    redis_store._pool = original


class TestInitRedis:
    @pytest.mark.asyncio
    async def test_successful_init(self):
        mock_pool = AsyncMock()
        mock_pool.ping = AsyncMock(return_value=True)

        with patch("proxy.store.redis.aioredis.from_url", return_value=mock_pool):
            result = await redis_store.init_redis("redis://localhost:6379", pool_size=5)

        assert result is mock_pool
        assert redis_store._pool is mock_pool
        redis_store._pool = None

    @pytest.mark.asyncio
    async def test_all_retries_exhausted(self):
        """Returns None when all retries fail."""
        import redis.asyncio as aioredis

        mock_pool = AsyncMock()
        mock_pool.ping = AsyncMock(side_effect=aioredis.ConnectionError("refused"))

        with (
            patch("proxy.store.redis.aioredis.from_url", return_value=mock_pool),
            patch("proxy.store.redis.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await redis_store.init_redis("redis://bad:6379")

        assert result is None
        assert redis_store._pool is None

    @pytest.mark.asyncio
    async def test_retries_on_os_error(self):
        """OSError triggers retry."""
        import redis.asyncio as aioredis

        mock_pool = AsyncMock()
        call_count = 0

        async def _ping():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise OSError("Connection refused")
            return True

        mock_pool.ping = _ping

        with (
            patch("proxy.store.redis.aioredis.from_url", return_value=mock_pool),
            patch("proxy.store.redis.asyncio.sleep", new_callable=AsyncMock),
        ):
            result = await redis_store.init_redis("redis://localhost:6379")

        assert result is mock_pool
        redis_store._pool = None

    @pytest.mark.asyncio
    async def test_exponential_backoff_delays(self):
        """Retry delays follow exponential backoff."""
        import redis.asyncio as aioredis

        mock_pool = AsyncMock()
        mock_pool.ping = AsyncMock(side_effect=aioredis.ConnectionError("refused"))

        sleep_calls = []

        async def _mock_sleep(delay):
            sleep_calls.append(delay)

        with (
            patch("proxy.store.redis.aioredis.from_url", return_value=mock_pool),
            patch("proxy.store.redis.asyncio.sleep", side_effect=_mock_sleep),
        ):
            await redis_store.init_redis("redis://bad:6379")

        # 4 retries (5 attempts total, last one doesn't sleep)
        assert len(sleep_calls) == 4
        assert sleep_calls[0] == 0.5   # 0.5 * 2^0
        assert sleep_calls[1] == 1.0   # 0.5 * 2^1
        assert sleep_calls[2] == 2.0   # 0.5 * 2^2
        assert sleep_calls[3] == 4.0   # 0.5 * 2^3


class TestGetRedis:
    def test_returns_pool_when_set(self):
        mock_pool = MagicMock()
        redis_store._pool = mock_pool
        assert redis_store.get_redis() is mock_pool
        redis_store._pool = None

    def test_returns_none_when_not_set(self):
        redis_store._pool = None
        assert redis_store.get_redis() is None


class TestPing:
    @pytest.mark.asyncio
    async def test_ping_success(self):
        mock_pool = AsyncMock()
        mock_pool.ping = AsyncMock(return_value=True)
        redis_store._pool = mock_pool

        assert await redis_store.ping() is True
        redis_store._pool = None

    @pytest.mark.asyncio
    async def test_ping_no_pool(self):
        redis_store._pool = None
        assert await redis_store.ping() is False

    @pytest.mark.asyncio
    async def test_ping_exception(self):
        mock_pool = AsyncMock()
        mock_pool.ping = AsyncMock(side_effect=ConnectionError("down"))
        redis_store._pool = mock_pool

        assert await redis_store.ping() is False
        redis_store._pool = None


class TestCloseRedis:
    @pytest.mark.asyncio
    async def test_close_clears_pool(self):
        mock_pool = AsyncMock()
        redis_store._pool = mock_pool
        await redis_store.close_redis()

        mock_pool.aclose.assert_awaited_once()
        assert redis_store._pool is None

    @pytest.mark.asyncio
    async def test_close_when_no_pool(self):
        redis_store._pool = None
        await redis_store.close_redis()  # should not raise
        assert redis_store._pool is None
