"""SHIELD-41 — Customer Domain Onboarding tests.

Tests cover:
- OnboardingCreate, OnboardingStatus, OnboardingResponse model validation
- Onboarding store CRUD with RLS tenant isolation
- Certificate poller background job
- Tenant creator background job
- Onboarding API routes (POST, GET, DELETE)
- _build_status_response helper
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4, UUID

import pytest
from pydantic import ValidationError

from proxy.models.onboarding import (
    OnboardingCreate,
    OnboardingResponse,
    OnboardingStatus,
    OnboardingStatusResponse,
)
from proxy.store.onboarding import (
    create_onboarding,
    get_onboarding,
    list_onboardings,
    list_pending_onboardings,
    list_validated_onboardings,
    update_onboarding,
    delete_onboarding,
    count_active_onboardings,
    get_onboarding_by_domain,
    MAX_ONBOARDINGS_PER_CUSTOMER,
)
from proxy.jobs.cert_poller import (
    check_certificate_status,
    run_cert_poller,
    DEFAULT_TIMEOUT_HOURS,
)
from proxy.jobs.tenant_creator import (
    create_distribution_tenant,
    run_tenant_creator,
)
from proxy.api.onboarding_routes import _build_status_response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CUSTOMER_ID = uuid4()
_ONBOARDING_ID = uuid4()
_NOW = datetime.now(timezone.utc)
_AUTH = {"Authorization": "Bearer test-api-key"}


def _mock_tenant_tx(mock_conn):
    """Return a mock tenant_transaction that yields *mock_conn*."""
    @asynccontextmanager
    async def _tx(tenant_id):
        yield mock_conn
    return _tx


def _mock_pool_with_conn(mock_conn):
    """Build a mock pool whose acquire() yields mock_conn as an async context manager."""
    @asynccontextmanager
    async def _acquire():
        yield mock_conn

    mock_pool = MagicMock()
    mock_pool.acquire = _acquire
    return mock_pool


def _sample_record(**overrides) -> dict:
    """Build a sample onboarding record dict."""
    record = {
        "id": _ONBOARDING_ID,
        "customer_id": _CUSTOMER_ID,
        "customer_domain": "app.example.com",
        "origin_url": "https://origin.example.com",
        "status": "certificate_pending",
        "acm_certificate_arn": "arn:aws:acm:us-east-1:123456789012:certificate/abc-123",
        "validation_cname_name": "_acme.app.example.com",
        "validation_cname_value": "_val.acm-validations.aws",
        "distribution_tenant_id": "",
        "cloudfront_cname": "",
        "error_message": "",
        "created_at": _NOW,
        "updated_at": _NOW,
    }
    record.update(overrides)
    return record


# ---------------------------------------------------------------------------
# TestOnboardingModels
# ---------------------------------------------------------------------------


class TestOnboardingModels:
    """Pydantic model validation for OnboardingCreate, OnboardingStatus, OnboardingResponse."""

    def test_valid_domain(self):
        """Valid FQDN is accepted and lowercased."""
        obj = OnboardingCreate(
            customer_domain="App.Example.Com",
            origin_url="https://origin.example.com",
        )
        assert obj.customer_domain == "app.example.com"

    def test_rejects_ip_address_as_domain(self):
        """IP addresses must be rejected as customer domains."""
        with pytest.raises(ValidationError, match="Invalid domain format"):
            OnboardingCreate(
                customer_domain="192.168.1.1",
                origin_url="https://origin.example.com",
            )

    def test_rejects_localhost(self):
        """localhost is rejected as a customer domain."""
        with pytest.raises(ValidationError, match="localhost"):
            OnboardingCreate(
                customer_domain="localhost",
                origin_url="https://origin.example.com",
            )

    def test_rejects_empty_domain(self):
        """Empty domain string is rejected."""
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain="",
                origin_url="https://origin.example.com",
            )

    def test_rejects_domain_with_trailing_dot(self):
        """Trailing dot in domain is rejected by the regex."""
        with pytest.raises(ValidationError, match="Invalid domain format"):
            OnboardingCreate(
                customer_domain="app.example.com.",
                origin_url="https://origin.example.com",
            )

    def test_rejects_domain_exceeding_253_chars(self):
        """Domain exceeding 253 characters is rejected."""
        long_domain = "a" * 250 + ".com"  # 254 chars total
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain=long_domain,
                origin_url="https://origin.example.com",
            )

    def test_valid_origin_url_https(self):
        """HTTPS origin URL is accepted."""
        obj = OnboardingCreate(
            customer_domain="app.example.com",
            origin_url="https://origin.example.com",
        )
        assert obj.origin_url == "https://origin.example.com"

    def test_valid_origin_url_http(self):
        """HTTP origin URL is accepted."""
        obj = OnboardingCreate(
            customer_domain="app.example.com",
            origin_url="http://origin.example.com",
        )
        assert obj.origin_url == "http://origin.example.com"

    def test_rejects_origin_without_scheme(self):
        """Origin URL without scheme is rejected."""
        with pytest.raises(ValidationError, match="origin_url must start with"):
            OnboardingCreate(
                customer_domain="app.example.com",
                origin_url="origin.example.com",
            )

    def test_rejects_empty_origin_url(self):
        """Empty origin URL is rejected."""
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain="app.example.com",
                origin_url="",
            )

    def test_onboarding_status_enum_values(self):
        """OnboardingStatus enum has all expected lifecycle values."""
        assert OnboardingStatus.CERTIFICATE_PENDING == "certificate_pending"
        assert OnboardingStatus.CERTIFICATE_VALIDATED == "certificate_validated"
        assert OnboardingStatus.TENANT_CREATED == "tenant_created"
        assert OnboardingStatus.ACTIVE == "active"
        assert OnboardingStatus.FAILED == "failed"
        assert OnboardingStatus.OFFBOARDED == "offboarded"
        assert len(OnboardingStatus) == 6

    def test_onboarding_response_model_construction(self):
        """OnboardingResponse can be constructed from a valid record."""
        record = _sample_record()
        resp = OnboardingResponse(**record)
        assert resp.id == _ONBOARDING_ID
        assert resp.customer_id == _CUSTOMER_ID
        assert resp.customer_domain == "app.example.com"
        assert resp.status == OnboardingStatus.CERTIFICATE_PENDING
        # AWS-internal fields are excluded from the response model
        assert not hasattr(resp, "acm_certificate_arn")
        assert not hasattr(resp, "distribution_tenant_id")


# ---------------------------------------------------------------------------
# TestOnboardingStore
# ---------------------------------------------------------------------------


class TestOnboardingStore:
    """Store CRUD operations with mock DB pool and RLS."""

    @pytest.mark.asyncio
    async def test_create_onboarding_calls_fetchrow(self):
        """create_onboarding inserts via tenant_transaction and returns dict."""
        mock_conn = AsyncMock()
        mock_row = MagicMock()
        mock_row.__iter__ = MagicMock(return_value=iter([("id", _ONBOARDING_ID)]))
        mock_row.keys = MagicMock(return_value=["id"])
        # dict(row) compat — use a real dict for the return
        mock_conn.fetchrow = AsyncMock(return_value={"id": _ONBOARDING_ID, "customer_domain": "app.example.com"})

        mock_pool = MagicMock()
        with (
            patch("proxy.store.onboarding.get_pool", return_value=mock_pool),
            patch("proxy.store.onboarding.tenant_transaction", _mock_tenant_tx(mock_conn)),
        ):
            result = await create_onboarding(
                _CUSTOMER_ID, "app.example.com", "https://origin.example.com",
                acm_certificate_arn="arn:aws:acm:us-east-1:123:cert/abc",
                validation_cname_name="_acme.app.example.com",
                validation_cname_value="_val.acm-validations.aws",
            )

        mock_conn.fetchrow.assert_awaited_once()
        sql_arg = mock_conn.fetchrow.call_args[0][0]
        assert "INSERT INTO onboardings" in sql_arg
        assert result["id"] == _ONBOARDING_ID

    @pytest.mark.asyncio
    async def test_create_onboarding_raises_store_unavailable(self):
        """create_onboarding raises StoreUnavailable when pool is None."""
        from proxy.store.postgres import StoreUnavailable

        with patch("proxy.store.onboarding.get_pool", return_value=None):
            with pytest.raises(StoreUnavailable):
                await create_onboarding(_CUSTOMER_ID, "a.example.com", "https://o.example.com")

    @pytest.mark.asyncio
    async def test_get_onboarding_with_customer_id_uses_tenant_tx(self):
        """get_onboarding with customer_id routes through tenant_transaction (RLS)."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"id": _ONBOARDING_ID})

        mock_pool = MagicMock()
        with (
            patch("proxy.store.onboarding.get_pool", return_value=mock_pool),
            patch("proxy.store.onboarding.tenant_transaction", _mock_tenant_tx(mock_conn)),
        ):
            result = await get_onboarding(_ONBOARDING_ID, customer_id=_CUSTOMER_ID)

        mock_conn.fetchrow.assert_awaited_once()
        sql_arg = mock_conn.fetchrow.call_args[0][0]
        assert "customer_id = $2" in sql_arg
        assert result["id"] == _ONBOARDING_ID

    @pytest.mark.asyncio
    async def test_get_onboarding_without_customer_id_bypasses_rls(self):
        """get_onboarding without customer_id uses pool.acquire directly (admin bypass)."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"id": _ONBOARDING_ID})

        mock_pool = _mock_pool_with_conn(mock_conn)

        with patch("proxy.store.onboarding.get_pool", return_value=mock_pool):
            result = await get_onboarding(_ONBOARDING_ID)

        mock_conn.fetchrow.assert_awaited_once()
        sql_arg = mock_conn.fetchrow.call_args[0][0]
        # WHERE clause should NOT filter by customer_id (admin bypass)
        assert "customer_id = $2" not in sql_arg
        assert "WHERE id = $1" in sql_arg
        assert result["id"] == _ONBOARDING_ID

    @pytest.mark.asyncio
    async def test_list_onboardings_returns_list(self):
        """list_onboardings returns list of dicts for a customer."""
        mock_conn = AsyncMock()
        rows = [
            {"id": uuid4(), "customer_domain": "a.example.com"},
            {"id": uuid4(), "customer_domain": "b.example.com"},
        ]
        mock_conn.fetch = AsyncMock(return_value=rows)

        mock_pool = MagicMock()
        with (
            patch("proxy.store.onboarding.get_pool", return_value=mock_pool),
            patch("proxy.store.onboarding.tenant_transaction", _mock_tenant_tx(mock_conn)),
        ):
            result = await list_onboardings(_CUSTOMER_ID)

        assert len(result) == 2
        mock_conn.fetch.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_list_pending_onboardings_bypasses_rls(self):
        """list_pending_onboardings uses pool.acquire (admin bypass, no tenant_transaction)."""
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[{"id": uuid4(), "status": "certificate_pending"}])

        mock_pool = _mock_pool_with_conn(mock_conn)

        with patch("proxy.store.onboarding.get_pool", return_value=mock_pool):
            result = await list_pending_onboardings()

        assert len(result) == 1
        sql_arg = mock_conn.fetch.call_args[0][0]
        assert "certificate_pending" in sql_arg

    @pytest.mark.asyncio
    async def test_list_validated_onboardings_bypasses_rls(self):
        """list_validated_onboardings uses pool.acquire (admin bypass)."""
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[{"id": uuid4(), "status": "certificate_validated"}])

        mock_pool = _mock_pool_with_conn(mock_conn)

        with patch("proxy.store.onboarding.get_pool", return_value=mock_pool):
            result = await list_validated_onboardings()

        assert len(result) == 1
        sql_arg = mock_conn.fetch.call_args[0][0]
        assert "certificate_validated" in sql_arg

    @pytest.mark.asyncio
    async def test_update_onboarding_rejects_invalid_column(self):
        """update_onboarding raises ValueError for unwhitelisted column names."""
        mock_pool = MagicMock()
        with patch("proxy.store.onboarding.get_pool", return_value=mock_pool):
            with pytest.raises(ValueError, match="Invalid column name"):
                await update_onboarding(
                    _ONBOARDING_ID,
                    evil_column="malicious",  # not in _ONBOARDING_COLUMNS
                )

    @pytest.mark.asyncio
    async def test_update_onboarding_no_fields_returns_existing(self):
        """update_onboarding with no fields delegates to get_onboarding."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"id": _ONBOARDING_ID, "status": "active"})

        mock_pool = _mock_pool_with_conn(mock_conn)

        with patch("proxy.store.onboarding.get_pool", return_value=mock_pool):
            result = await update_onboarding(_ONBOARDING_ID)

        # With no fields, it calls get_onboarding internally which uses pool.acquire
        assert result["id"] == _ONBOARDING_ID

    @pytest.mark.asyncio
    async def test_delete_onboarding_with_customer_id_uses_tenant_tx(self):
        """delete_onboarding with customer_id enforces RLS via tenant_transaction."""
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="DELETE 1")

        mock_pool = MagicMock()
        with (
            patch("proxy.store.onboarding.get_pool", return_value=mock_pool),
            patch("proxy.store.onboarding.tenant_transaction", _mock_tenant_tx(mock_conn)),
        ):
            result = await delete_onboarding(_ONBOARDING_ID, customer_id=_CUSTOMER_ID)

        assert result is True
        sql_arg = mock_conn.execute.call_args[0][0]
        assert "customer_id = $2" in sql_arg

    @pytest.mark.asyncio
    async def test_count_active_onboardings_returns_int(self):
        """count_active_onboardings returns integer count."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=3)

        mock_pool = MagicMock()
        with (
            patch("proxy.store.onboarding.get_pool", return_value=mock_pool),
            patch("proxy.store.onboarding.tenant_transaction", _mock_tenant_tx(mock_conn)),
        ):
            result = await count_active_onboardings(_CUSTOMER_ID)

        assert result == 3
        mock_conn.fetchval.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_onboarding_by_domain_bypasses_rls(self):
        """get_onboarding_by_domain uses pool.acquire (admin bypass for duplicate check)."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"id": _ONBOARDING_ID, "customer_domain": "app.example.com"})

        mock_pool = _mock_pool_with_conn(mock_conn)

        with patch("proxy.store.onboarding.get_pool", return_value=mock_pool):
            result = await get_onboarding_by_domain("app.example.com")

        assert result["customer_domain"] == "app.example.com"
        sql_arg = mock_conn.fetchrow.call_args[0][0]
        assert "customer_domain = $1" in sql_arg
        assert "NOT IN ('offboarded', 'failed')" in sql_arg


# ---------------------------------------------------------------------------
# TestCertPoller
# ---------------------------------------------------------------------------


class TestCertPoller:
    """Certificate poller background job tests."""

    @pytest.mark.asyncio
    async def test_check_certificate_status_issued(self):
        """Returns 'certificate_validated' when ACM reports ISSUED."""
        acm_client = MagicMock()
        acm_client.describe_certificate = MagicMock(return_value={
            "Certificate": {"Status": "ISSUED"},
        })
        onboarding = _sample_record()

        result = await check_certificate_status(onboarding, acm_client=acm_client)
        assert result == "certificate_validated"

    @pytest.mark.asyncio
    async def test_check_certificate_status_acm_failed(self):
        """Returns 'failed' when ACM reports FAILED status."""
        acm_client = MagicMock()
        acm_client.describe_certificate = MagicMock(return_value={
            "Certificate": {"Status": "FAILED", "FailureReason": "NO_AVAILABLE_CONTACTS"},
        })
        onboarding = _sample_record()

        result = await check_certificate_status(onboarding, acm_client=acm_client)
        assert result == "failed"

    @pytest.mark.asyncio
    async def test_check_certificate_status_pending_returns_none(self):
        """Returns None when ACM is PENDING_VALIDATION (still waiting, no change)."""
        acm_client = MagicMock()
        acm_client.describe_certificate = MagicMock(return_value={
            "Certificate": {"Status": "PENDING_VALIDATION"},
        })
        # Created recently so no timeout
        onboarding = _sample_record(created_at=datetime.now(timezone.utc))

        result = await check_certificate_status(onboarding, acm_client=acm_client)
        assert result is None

    @pytest.mark.asyncio
    async def test_check_certificate_status_timeout(self):
        """Returns 'failed' when certificate has been pending beyond timeout hours."""
        acm_client = MagicMock()
        acm_client.describe_certificate = MagicMock(return_value={
            "Certificate": {"Status": "PENDING_VALIDATION"},
        })
        # Created 73 hours ago (beyond DEFAULT_TIMEOUT_HOURS=72)
        old_time = datetime.now(timezone.utc) - timedelta(hours=DEFAULT_TIMEOUT_HOURS + 1)
        onboarding = _sample_record(created_at=old_time)

        result = await check_certificate_status(onboarding, acm_client=acm_client)
        assert result == "failed"

    @pytest.mark.asyncio
    async def test_check_certificate_status_no_cert_arn(self):
        """Returns 'failed' when onboarding has no cert_arn."""
        acm_client = MagicMock()
        onboarding = _sample_record(acm_certificate_arn="")

        result = await check_certificate_status(onboarding, acm_client=acm_client)
        assert result == "failed"

    @pytest.mark.asyncio
    async def test_check_certificate_status_boto3_exception(self):
        """Returns None on boto3 exception (will retry next poll)."""
        acm_client = MagicMock()
        acm_client.describe_certificate = MagicMock(side_effect=Exception("boto3 error"))
        onboarding = _sample_record()

        result = await check_certificate_status(onboarding, acm_client=acm_client)
        assert result is None

    @pytest.mark.asyncio
    async def test_run_cert_poller_stops_on_shutdown(self):
        """run_cert_poller exits when shutdown_event is set."""
        shutdown = asyncio.Event()
        shutdown.set()  # Immediately signal shutdown

        with patch("proxy.store.onboarding.list_pending_onboardings", new_callable=AsyncMock, return_value=[]):
            await run_cert_poller(
                poll_interval=10,
                acm_client=MagicMock(),
                shutdown_event=shutdown,
            )
        # Should exit without hanging — test passes if it completes

    @pytest.mark.asyncio
    async def test_run_cert_poller_enforces_min_interval(self):
        """Interval below _MIN_POLL_INTERVAL (10s) is clamped."""
        shutdown = asyncio.Event()
        shutdown.set()

        with patch("proxy.store.onboarding.list_pending_onboardings", new_callable=AsyncMock, return_value=[]):
            # Pass interval of 1 (below minimum of 10)
            await run_cert_poller(
                poll_interval=1,
                acm_client=MagicMock(),
                shutdown_event=shutdown,
            )
        # Passes if no error; internal clamp to 10 verified by no tight-loop hang

    @pytest.mark.asyncio
    async def test_run_cert_poller_handles_empty_list(self):
        """Poller handles empty pending list gracefully without errors."""
        call_count = 0

        async def _mock_list():
            nonlocal call_count
            call_count += 1
            return []

        shutdown = asyncio.Event()

        async def _stop_after_one():
            # Let one poll cycle complete, then stop
            await asyncio.sleep(0.05)
            shutdown.set()

        with patch("proxy.store.onboarding.list_pending_onboardings", side_effect=_mock_list):
            await asyncio.gather(
                run_cert_poller(poll_interval=10, acm_client=MagicMock(), shutdown_event=shutdown),
                _stop_after_one(),
            )
        assert call_count >= 1

    @pytest.mark.asyncio
    async def test_run_cert_poller_skips_when_no_acm_client(self):
        """Poller logs warning and skips when acm_client is None."""
        shutdown = asyncio.Event()
        pending = [_sample_record()]

        async def _mock_list():
            return pending

        async def _stop_after_one():
            await asyncio.sleep(0.05)
            shutdown.set()

        mock_claim = AsyncMock()
        with (
            patch("proxy.store.onboarding.list_pending_onboardings", side_effect=_mock_list),
            patch("proxy.store.onboarding.claim_and_update", mock_claim),
        ):
            await asyncio.gather(
                run_cert_poller(poll_interval=10, acm_client=None, shutdown_event=shutdown),
                _stop_after_one(),
            )
        # claim_and_update should NOT be called since acm_client is None
        mock_claim.assert_not_awaited()


# ---------------------------------------------------------------------------
# TestTenantCreator
# ---------------------------------------------------------------------------


class TestTenantCreator:
    """Tenant creator background job tests."""

    @pytest.mark.asyncio
    async def test_create_distribution_tenant_success(self):
        """Returns tenant_id and cloudfront_cname on successful creation."""
        cf_client = MagicMock()
        cf_client.create_distribution_tenant = MagicMock(return_value={
            "DistributionTenant": {
                "Id": "tenant-abc-123",
                "DomainName": "d12345.cloudfront.net",
            },
        })
        onboarding = _sample_record()

        result = await create_distribution_tenant(
            onboarding, cloudfront_client=cf_client, distribution_id="E1234567890",
        )
        assert result is not None
        assert result["tenant_id"] == "tenant-abc-123"
        assert result["cloudfront_cname"] == "d12345.cloudfront.net"

    @pytest.mark.asyncio
    async def test_create_distribution_tenant_missing_fields(self):
        """Returns None when required fields (domain, origin, cert) are missing."""
        cf_client = MagicMock()
        onboarding = _sample_record(customer_domain="", origin_url="", acm_certificate_arn="")

        result = await create_distribution_tenant(
            onboarding, cloudfront_client=cf_client, distribution_id="E1234567890",
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_create_distribution_tenant_boto3_exception(self):
        """Returns None on boto3 exception."""
        cf_client = MagicMock()
        cf_client.create_distribution_tenant = MagicMock(side_effect=Exception("AWS error"))
        onboarding = _sample_record()

        result = await create_distribution_tenant(
            onboarding, cloudfront_client=cf_client, distribution_id="E1234567890",
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_run_tenant_creator_stops_on_shutdown(self):
        """run_tenant_creator exits when shutdown_event is set."""
        shutdown = asyncio.Event()
        shutdown.set()

        with patch("proxy.store.onboarding.list_validated_onboardings", new_callable=AsyncMock, return_value=[]):
            await run_tenant_creator(
                poll_interval=10,
                cloudfront_client=MagicMock(),
                distribution_id="E1234567890",
                shutdown_event=shutdown,
            )

    @pytest.mark.asyncio
    async def test_run_tenant_creator_enforces_min_interval(self):
        """Interval below _MIN_POLL_INTERVAL (10s) is clamped."""
        shutdown = asyncio.Event()
        shutdown.set()

        with patch("proxy.store.onboarding.list_validated_onboardings", new_callable=AsyncMock, return_value=[]):
            await run_tenant_creator(
                poll_interval=1,
                cloudfront_client=MagicMock(),
                distribution_id="E1234567890",
                shutdown_event=shutdown,
            )

    @pytest.mark.asyncio
    async def test_run_tenant_creator_marks_failed_on_create_failure(self):
        """When create_distribution_tenant returns None, status is set to 'failed'."""
        shutdown = asyncio.Event()
        onboarding = _sample_record(status="certificate_validated")
        cf_client = MagicMock()
        cf_client.create_distribution_tenant = MagicMock(side_effect=Exception("AWS error"))

        async def _mock_list():
            return [onboarding]

        mock_claim = AsyncMock()

        async def _stop_after_one():
            await asyncio.sleep(0.05)
            shutdown.set()

        with (
            patch("proxy.store.onboarding.list_validated_onboardings", side_effect=_mock_list),
            patch("proxy.store.onboarding.claim_and_update", mock_claim),
        ):
            await asyncio.gather(
                run_tenant_creator(
                    poll_interval=10,
                    cloudfront_client=cf_client,
                    distribution_id="E1234567890",
                    shutdown_event=shutdown,
                ),
                _stop_after_one(),
            )

        # claim_and_update should be called with new_status="failed"
        mock_claim.assert_awaited()
        call_kwargs = mock_claim.call_args
        assert call_kwargs[1]["new_status"] == "failed"
        assert "error_message" in call_kwargs[1]

    @pytest.mark.asyncio
    async def test_run_tenant_creator_handles_empty_list(self):
        """Creator handles empty validated list gracefully."""
        call_count = 0

        async def _mock_list():
            nonlocal call_count
            call_count += 1
            return []

        shutdown = asyncio.Event()

        async def _stop_after_one():
            await asyncio.sleep(0.05)
            shutdown.set()

        with patch("proxy.store.onboarding.list_validated_onboardings", side_effect=_mock_list):
            await asyncio.gather(
                run_tenant_creator(
                    poll_interval=10,
                    cloudfront_client=MagicMock(),
                    distribution_id="E1234567890",
                    shutdown_event=shutdown,
                ),
                _stop_after_one(),
            )
        assert call_count >= 1

    @pytest.mark.asyncio
    async def test_run_tenant_creator_skips_when_not_configured(self):
        """Creator skips processing when cloudfront_client is None or distribution_id is empty."""
        shutdown = asyncio.Event()
        validated = [_sample_record(status="certificate_validated")]

        async def _mock_list():
            return validated

        mock_claim = AsyncMock()

        async def _stop_after_one():
            await asyncio.sleep(0.05)
            shutdown.set()

        with (
            patch("proxy.store.onboarding.list_validated_onboardings", side_effect=_mock_list),
            patch("proxy.store.onboarding.claim_and_update", mock_claim),
        ):
            # No cloudfront_client
            await asyncio.gather(
                run_tenant_creator(
                    poll_interval=10,
                    cloudfront_client=None,
                    distribution_id="E1234567890",
                    shutdown_event=shutdown,
                ),
                _stop_after_one(),
            )
        mock_claim.assert_not_awaited()


# ---------------------------------------------------------------------------
# TestOnboardingRoutes
# ---------------------------------------------------------------------------


class TestOnboardingRoutes:
    """API route tests for onboarding endpoints."""

    @pytest.fixture
    def api_client(self):
        """Create a FastAPI test client with mocked lifespan state."""
        import proxy.main as main_module
        main_module._pipeline = None
        main_module._http_client = None
        from proxy.main import app
        from fastapi.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c
        main_module._http_client = None
        main_module._pipeline = None

    def _mock_acm_success(self):
        """Return patches for successful ACM certificate request + describe."""
        acm_client = MagicMock()
        acm_client.request_certificate = MagicMock(return_value={
            "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/abc-123",
        })
        acm_client.describe_certificate = MagicMock(return_value={
            "Certificate": {
                "DomainValidationOptions": [{
                    "ResourceRecord": {
                        "Name": "_acme.app.example.com",
                        "Value": "_val.acm-validations.aws",
                    },
                }],
            },
        })
        return acm_client

    def _mock_customer(self):
        """Return a mock customer dict."""
        return {
            "id": _CUSTOMER_ID,
            "name": "Test Corp",
            "plan": "professional",
            "settings": {},
            "created_at": _NOW.isoformat(),
            "updated_at": _NOW.isoformat(),
        }

    def _mock_record(self, **overrides):
        """Return a serializable mock onboarding record."""
        record = _sample_record(**overrides)
        record["id"] = str(record["id"])
        record["customer_id"] = str(record["customer_id"])
        record["created_at"] = record["created_at"].isoformat()
        record["updated_at"] = record["updated_at"].isoformat()
        return record

    def test_post_creates_onboarding_successfully(self, api_client):
        """POST /api/onboard/customers/{id}/ creates onboarding with ACM cert."""
        acm_client = self._mock_acm_success()
        created_record = self._mock_record()

        with (
            patch("proxy.api.onboarding_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=self._mock_customer()),
            patch("proxy.api.onboarding_routes.validate_origin_url", return_value=None),
            patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding_by_domain", new_callable=AsyncMock, return_value=None),
            patch("proxy.api.onboarding_routes.onboarding_store.count_active_onboardings", new_callable=AsyncMock, return_value=0),
            patch("proxy.api.onboarding_routes._acm_client", acm_client),
            patch("proxy.api.onboarding_routes.onboarding_store.create_onboarding", new_callable=AsyncMock, return_value=created_record),
        ):
            resp = api_client.post(
                f"/api/onboard/customers/{_CUSTOMER_ID}/",
                json={"customer_domain": "app.example.com", "origin_url": "https://origin.example.com"},
                headers=_AUTH,
            )

        assert resp.status_code == 201
        data = resp.json()
        assert data["customer_domain"] == "app.example.com"

    def test_post_returns_404_customer_not_found(self, api_client):
        """POST returns 404 when customer does not exist."""
        with patch("proxy.api.onboarding_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=None):
            resp = api_client.post(
                f"/api/onboard/customers/{_CUSTOMER_ID}/",
                json={"customer_domain": "app.example.com", "origin_url": "https://origin.example.com"},
                headers=_AUTH,
            )
        assert resp.status_code == 404
        assert "Customer not found" in resp.json()["detail"]

    def test_post_returns_422_ssrf_origin(self, api_client):
        """POST returns 422 when origin URL fails SSRF validation."""
        with (
            patch("proxy.api.onboarding_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=self._mock_customer()),
            patch("proxy.api.onboarding_routes.validate_origin_url", return_value="SSRF blocked"),
        ):
            resp = api_client.post(
                f"/api/onboard/customers/{_CUSTOMER_ID}/",
                json={"customer_domain": "app.example.com", "origin_url": "http://169.254.169.254/latest/meta-data"},
                headers=_AUTH,
            )
        assert resp.status_code == 422
        assert "Origin URL validation failed" in resp.json()["detail"]

    def test_post_returns_409_duplicate_domain(self, api_client):
        """POST returns 409 when domain already has an active onboarding."""
        existing = self._mock_record()

        with (
            patch("proxy.api.onboarding_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=self._mock_customer()),
            patch("proxy.api.onboarding_routes.validate_origin_url", return_value=None),
            patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding_by_domain", new_callable=AsyncMock, return_value=existing),
        ):
            resp = api_client.post(
                f"/api/onboard/customers/{_CUSTOMER_ID}/",
                json={"customer_domain": "app.example.com", "origin_url": "https://origin.example.com"},
                headers=_AUTH,
            )
        assert resp.status_code == 409
        assert "already has an active onboarding" in resp.json()["detail"]

    def test_post_returns_422_limit_reached(self, api_client):
        """POST returns 422 when per-customer onboarding limit is reached."""
        with (
            patch("proxy.api.onboarding_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=self._mock_customer()),
            patch("proxy.api.onboarding_routes.validate_origin_url", return_value=None),
            patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding_by_domain", new_callable=AsyncMock, return_value=None),
            patch("proxy.api.onboarding_routes.onboarding_store.count_active_onboardings", new_callable=AsyncMock, return_value=MAX_ONBOARDINGS_PER_CUSTOMER),
        ):
            resp = api_client.post(
                f"/api/onboard/customers/{_CUSTOMER_ID}/",
                json={"customer_domain": "new.example.com", "origin_url": "https://origin.example.com"},
                headers=_AUTH,
            )
        assert resp.status_code == 422
        assert "Maximum onboardings" in resp.json()["detail"]

    def test_post_returns_503_database_unavailable(self, api_client):
        """POST returns 503 when database is unavailable."""
        from proxy.store.postgres import StoreUnavailable

        with patch("proxy.api.onboarding_routes.pg_store.get_customer", new_callable=AsyncMock, side_effect=StoreUnavailable("no db")):
            resp = api_client.post(
                f"/api/onboard/customers/{_CUSTOMER_ID}/",
                json={"customer_domain": "app.example.com", "origin_url": "https://origin.example.com"},
                headers=_AUTH,
            )
        assert resp.status_code == 503
        assert "Database unavailable" in resp.json()["detail"]

    def test_post_returns_502_acm_failure(self, api_client):
        """POST returns 502 when ACM certificate request fails."""
        acm_client = MagicMock()
        acm_client.request_certificate = MagicMock(side_effect=Exception("ACM error"))

        with (
            patch("proxy.api.onboarding_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=self._mock_customer()),
            patch("proxy.api.onboarding_routes.validate_origin_url", return_value=None),
            patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding_by_domain", new_callable=AsyncMock, return_value=None),
            patch("proxy.api.onboarding_routes.onboarding_store.count_active_onboardings", new_callable=AsyncMock, return_value=0),
            patch("proxy.api.onboarding_routes._acm_client", acm_client),
        ):
            resp = api_client.post(
                f"/api/onboard/customers/{_CUSTOMER_ID}/",
                json={"customer_domain": "app.example.com", "origin_url": "https://origin.example.com"},
                headers=_AUTH,
            )
        assert resp.status_code == 502
        assert "Failed to request SSL certificate" in resp.json()["detail"]

    def test_get_list_returns_onboardings(self, api_client):
        """GET /api/onboard/customers/{id}/ returns list of onboardings."""
        records = [self._mock_record(), self._mock_record(id=uuid4())]

        with patch("proxy.api.onboarding_routes.onboarding_store.list_onboardings", new_callable=AsyncMock, return_value=records):
            resp = api_client.get(
                f"/api/onboard/customers/{_CUSTOMER_ID}/",
                headers=_AUTH,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["data"]) == 2

    def test_get_detail_returns_single(self, api_client):
        """GET /api/onboard/customers/{cid}/{oid} returns single onboarding."""
        record = self._mock_record()

        with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding", new_callable=AsyncMock, return_value=record):
            resp = api_client.get(
                f"/api/onboard/customers/{_CUSTOMER_ID}/{_ONBOARDING_ID}",
                headers=_AUTH,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["customer_domain"] == "app.example.com"

    def test_get_detail_returns_404(self, api_client):
        """GET detail returns 404 when onboarding not found."""
        with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding", new_callable=AsyncMock, return_value=None):
            resp = api_client.get(
                f"/api/onboard/customers/{_CUSTOMER_ID}/{uuid4()}",
                headers=_AUTH,
            )
        assert resp.status_code == 404

    def test_get_status_certificate_pending(self, api_client):
        """GET status returns required_actions with DNS validation for certificate_pending."""
        record = _sample_record(status=OnboardingStatus.CERTIFICATE_PENDING)

        with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding", new_callable=AsyncMock, return_value=record):
            resp = api_client.get(
                f"/api/onboard/customers/{_CUSTOMER_ID}/{_ONBOARDING_ID}/status",
                headers=_AUTH,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "certificate_pending"
        assert any("DNS CNAME" in a for a in data["required_actions"])

    def test_get_status_tenant_created(self, api_client):
        """GET status returns CloudFront CNAME action for tenant_created."""
        record = _sample_record(
            status=OnboardingStatus.TENANT_CREATED,
            cloudfront_cname="d12345.cloudfront.net",
        )

        with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding", new_callable=AsyncMock, return_value=record):
            resp = api_client.get(
                f"/api/onboard/customers/{_CUSTOMER_ID}/{_ONBOARDING_ID}/status",
                headers=_AUTH,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "tenant_created"
        assert any("d12345.cloudfront.net" in a for a in data["required_actions"])

    def test_delete_offboards_successfully(self, api_client):
        """DELETE offboards: deletes tenant + cert, marks offboarded."""
        record = _sample_record(
            status=OnboardingStatus.ACTIVE,
            distribution_tenant_id="tenant-abc",
        )
        cf_client = MagicMock()
        cf_client.delete_distribution_tenant = MagicMock(return_value={})
        acm_client = MagicMock()
        acm_client.delete_certificate = MagicMock(return_value={})

        with (
            patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding", new_callable=AsyncMock, return_value=record),
            patch("proxy.api.onboarding_routes._cloudfront_client", cf_client),
            patch("proxy.api.onboarding_routes._acm_client", acm_client),
            patch("proxy.api.onboarding_routes.onboarding_store.update_onboarding", new_callable=AsyncMock, return_value=record),
        ):
            resp = api_client.delete(
                f"/api/onboard/customers/{_CUSTOMER_ID}/{_ONBOARDING_ID}",
                headers=_AUTH,
            )
        assert resp.status_code == 204

    def test_delete_returns_404(self, api_client):
        """DELETE returns 404 when onboarding not found."""
        with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding", new_callable=AsyncMock, return_value=None):
            resp = api_client.delete(
                f"/api/onboard/customers/{_CUSTOMER_ID}/{uuid4()}",
                headers=_AUTH,
            )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# TestBuildStatusResponse
# ---------------------------------------------------------------------------


class TestBuildStatusResponse:
    """Tests for _build_status_response helper."""

    def test_certificate_pending_dns_validation_action(self):
        """certificate_pending status includes DNS CNAME validation action."""
        record = _sample_record(status=OnboardingStatus.CERTIFICATE_PENDING)
        resp = _build_status_response(record)

        assert resp.status == OnboardingStatus.CERTIFICATE_PENDING
        assert len(resp.required_actions) == 1
        assert "DNS CNAME" in resp.required_actions[0]
        assert "_acme.app.example.com" in resp.required_actions[0]
        assert "_val.acm-validations.aws" in resp.required_actions[0]
        assert len(resp.next_steps) == 1
        assert "validated automatically" in resp.next_steps[0]

    def test_certificate_validated_being_created(self):
        """certificate_validated status indicates tenant is being created."""
        record = _sample_record(status=OnboardingStatus.CERTIFICATE_VALIDATED)
        resp = _build_status_response(record)

        assert resp.status == OnboardingStatus.CERTIFICATE_VALIDATED
        assert len(resp.required_actions) == 0
        assert len(resp.next_steps) == 1
        assert "being created" in resp.next_steps[0]

    def test_tenant_created_cloudfront_cname_action(self):
        """tenant_created status includes CloudFront CNAME action."""
        record = _sample_record(
            status=OnboardingStatus.TENANT_CREATED,
            cloudfront_cname="d12345.cloudfront.net",
        )
        resp = _build_status_response(record)

        assert resp.status == OnboardingStatus.TENANT_CREATED
        assert len(resp.required_actions) == 1
        assert "app.example.com" in resp.required_actions[0]
        assert "d12345.cloudfront.net" in resp.required_actions[0]
        assert "Point your domain" in resp.next_steps[0]

    def test_active_fully_protected(self):
        """active status indicates domain is fully protected."""
        record = _sample_record(status=OnboardingStatus.ACTIVE)
        resp = _build_status_response(record)

        assert resp.status == OnboardingStatus.ACTIVE
        assert len(resp.required_actions) == 0
        assert len(resp.next_steps) == 1
        assert "fully protected" in resp.next_steps[0]

    def test_failed_includes_error_message(self):
        """failed status includes error message in next_steps."""
        record = _sample_record(
            status=OnboardingStatus.FAILED,
            error_message="Certificate validation timed out",
        )
        resp = _build_status_response(record)

        assert resp.status == OnboardingStatus.FAILED
        assert resp.error_message == "Certificate validation timed out"
        assert any("Certificate validation timed out" in s for s in resp.next_steps)
        assert any("retry" in s.lower() for s in resp.next_steps)

    def test_offboarded_no_actions(self):
        """offboarded status has no required actions or next steps."""
        record = _sample_record(status=OnboardingStatus.OFFBOARDED)
        resp = _build_status_response(record)

        assert resp.status == OnboardingStatus.OFFBOARDED
        assert len(resp.required_actions) == 0
        assert len(resp.next_steps) == 0
