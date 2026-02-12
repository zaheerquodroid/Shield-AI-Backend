"""Tests for store layer utilities (API key hashing, StoreUnavailable)."""

from __future__ import annotations

import pytest

from proxy.store.postgres import (
    StoreUnavailable,
    hash_api_key,
    verify_api_key,
)


class TestPBKDF2Hashing:
    """API key hashing with PBKDF2."""

    def test_hash_produces_pbkdf2_format(self):
        """hash_api_key returns pbkdf2$salt$hash format."""
        result = hash_api_key("my-secret-key")
        parts = result.split("$")
        assert len(parts) == 3
        assert parts[0] == "pbkdf2"
        assert len(parts[1]) == 64  # 32 bytes hex
        assert len(parts[2]) == 64  # 32 bytes hex (sha256)

    def test_hash_is_salted(self):
        """Two hashes of the same key should differ (different salts)."""
        h1 = hash_api_key("same-key")
        h2 = hash_api_key("same-key")
        assert h1 != h2

    def test_verify_correct_key(self):
        """verify_api_key returns True for the correct key."""
        stored = hash_api_key("my-secret")
        assert verify_api_key("my-secret", stored) is True

    def test_verify_wrong_key(self):
        """verify_api_key returns False for a wrong key."""
        stored = hash_api_key("my-secret")
        assert verify_api_key("wrong-key", stored) is False

    def test_verify_legacy_sha256(self):
        """verify_api_key supports legacy unsalted SHA-256 hashes."""
        import hashlib

        legacy_hash = hashlib.sha256(b"old-key").hexdigest()
        assert verify_api_key("old-key", legacy_hash) is True
        assert verify_api_key("wrong", legacy_hash) is False

    def test_verify_malformed_pbkdf2(self):
        """verify_api_key returns False for malformed pbkdf2 hash."""
        assert verify_api_key("key", "pbkdf2$bad") is False
        assert verify_api_key("key", "pbkdf2$only$two") is False  # hex decode will fail if bad

    def test_verify_empty_key(self):
        """Empty key can be hashed and verified."""
        stored = hash_api_key("")
        assert verify_api_key("", stored) is True
        assert verify_api_key("notempty", stored) is False


class TestStoreUnavailable:
    """StoreUnavailable exception tests."""

    def test_store_unavailable_is_exception(self):
        assert issubclass(StoreUnavailable, Exception)

    @pytest.mark.asyncio
    async def test_get_customer_raises_when_no_pool(self):
        """get_customer raises StoreUnavailable when pool is None."""
        from uuid import uuid4
        from proxy.store import postgres as pg

        original = pg._pool
        pg._pool = None
        try:
            with pytest.raises(StoreUnavailable):
                await pg.get_customer(uuid4())
        finally:
            pg._pool = original

    @pytest.mark.asyncio
    async def test_create_app_raises_when_no_pool(self):
        """create_app raises StoreUnavailable when pool is None."""
        from uuid import uuid4
        from proxy.store import postgres as pg

        original = pg._pool
        pg._pool = None
        try:
            with pytest.raises(StoreUnavailable):
                await pg.create_app(uuid4(), "n", "u", "d", {}, {})
        finally:
            pg._pool = original

    @pytest.mark.asyncio
    async def test_delete_app_raises_when_no_pool(self):
        """delete_app raises StoreUnavailable when pool is None."""
        from uuid import uuid4
        from proxy.store import postgres as pg

        original = pg._pool
        pg._pool = None
        try:
            with pytest.raises(StoreUnavailable):
                await pg.delete_app(uuid4())
        finally:
            pg._pool = original
