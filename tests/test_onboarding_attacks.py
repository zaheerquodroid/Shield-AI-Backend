"""Attack simulation tests for SHIELD-41 customer domain onboarding.

Simulates real-world attack vectors against the onboarding system:
- Domain injection (SQL injection, XSS, null bytes, homoglyphs, wildcards)
- Origin URL SSRF (localhost, internal nets, metadata endpoints, scheme abuse)
- IDOR prevention (tenant scoping via RLS, ownership enforcement)
- Resource exhaustion (per-customer limits, duplicate domains)
- Certificate security flaws (empty ARN, timeout, exception handling)
- Tenant creator security flaws (missing fields, exception handling)
- Offboarding security flaws (idempotency, cleanup failures, 404)
- Store security properties (column whitelist, parameterized queries)
- Schema security properties (RLS, constraints, grants)
"""

from __future__ import annotations

import asyncio
import inspect
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from proxy.models.onboarding import (
    OnboardingCreate,
    OnboardingResponse,
    OnboardingStatus,
    VALID_TRANSITIONS,
    _BLOCKED_DOMAIN_SUFFIXES,
    _BLOCKED_DOMAINS,
    _DOMAIN_RE,
    _MAX_DOMAIN_LEN,
)
from proxy.store.onboarding import (
    DuplicateDomain,
    MAX_ONBOARDINGS_PER_CUSTOMER,
    _ONBOARDING_COLUMNS,
    claim_and_update,
    count_active_onboardings,
    create_onboarding,
    delete_onboarding,
    get_onboarding,
    get_onboarding_by_domain,
    list_onboardings,
    list_pending_onboardings,
    list_validated_onboardings,
    update_onboarding,
)
from proxy.store.postgres import StoreUnavailable
from proxy.jobs.cert_poller import (
    DEFAULT_TIMEOUT_HOURS,
    _MIN_POLL_INTERVAL as CERT_MIN_POLL_INTERVAL,
    check_certificate_status,
    run_cert_poller,
)
from proxy.jobs.tenant_creator import (
    _MIN_POLL_INTERVAL as TENANT_MIN_POLL_INTERVAL,
    create_distribution_tenant,
    run_tenant_creator,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CUSTOMER_A = uuid4()
CUSTOMER_B = uuid4()
ONBOARDING_A = uuid4()

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "proxy" / "models" / "schema.sql"
_STORE_SOURCE = Path(__file__).resolve().parent.parent / "proxy" / "store" / "onboarding.py"


def _schema_sql() -> str:
    return _SCHEMA_PATH.read_text()


def _store_source() -> str:
    return _STORE_SOURCE.read_text()


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

def _mock_tenant_tx(mock_conn):
    """Return a mock tenant_transaction that yields *mock_conn*."""
    @asynccontextmanager
    async def _tx(tenant_id):
        yield mock_conn
    return _tx


def _make_pool_mock():
    """Build a mock pool + connection."""
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock(return_value="DELETE 1")
    mock_conn.fetchrow = AsyncMock(return_value=None)
    mock_conn.fetch = AsyncMock(return_value=[])
    mock_conn.fetchval = AsyncMock(return_value=0)

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    pool = MagicMock()
    pool.acquire = MagicMock(return_value=mock_ctx)

    return pool, mock_conn


def _make_onboarding_record(**overrides) -> dict:
    """Build a fake onboarding DB record dict."""
    defaults = {
        "id": ONBOARDING_A,
        "customer_id": CUSTOMER_A,
        "customer_domain": "app.example.com",
        "origin_url": "https://origin.example.com",
        "status": "certificate_pending",
        "acm_certificate_arn": "arn:aws:acm:us-east-1:123456:certificate/abc-123",
        "validation_cname_name": "_abc.app.example.com",
        "validation_cname_value": "_abc.acm-validations.aws",
        "distribution_tenant_id": "",
        "cloudfront_cname": "",
        "error_message": "",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return defaults


# ===========================================================================
# TestDomainInjection (~8 tests)
# ===========================================================================


class TestDomainInjection:
    """Validates that the domain validator rejects malicious domain inputs.

    Attack vectors: SQL injection, XSS, null bytes, Unicode homoglyphs,
    wildcards, oversized domains, TLD-only, consecutive dots.
    """

    def test_rejects_sql_injection_in_domain(self):
        """SQL injection payload must not pass domain validation."""
        with pytest.raises(ValidationError) as exc_info:
            OnboardingCreate(
                customer_domain="'; DROP TABLE onboardings--",
                origin_url="https://app.example.com",
            )
        assert "customer_domain" in str(exc_info.value).lower() or "domain" in str(exc_info.value).lower()

    def test_rejects_xss_in_domain(self):
        """XSS payload must not pass domain validation."""
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain="<script>alert(1)</script>.com",
                origin_url="https://app.example.com",
            )

    def test_rejects_null_bytes_in_domain(self):
        """Null bytes in domain enable truncation attacks — must reject."""
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain="evil\x00.com",
                origin_url="https://app.example.com",
            )

    def test_rejects_unicode_homoglyph_domain(self):
        """Cyrillic 'a' (U+0430) looks like Latin 'a' but is different.

        Homoglyph attacks trick users into visiting phishing domains.
        The domain regex only allows [A-Za-z0-9-] — non-ASCII is rejected.
        """
        # Cyrillic 'а' (U+0430) instead of Latin 'a'
        cyrillic_a = "\u0430"
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain=f"{cyrillic_a}pp.example.com",
                origin_url="https://app.example.com",
            )

    def test_rejects_wildcard_domain(self):
        """Wildcard domains (*.example.com) must be rejected.

        Allowing wildcards could let attackers claim certificates for
        entire domain trees.
        """
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain="*.example.com",
                origin_url="https://app.example.com",
            )

    def test_rejects_extremely_long_domain(self):
        """Domains > 253 chars must be rejected (RFC 1035 limit)."""
        # Build a domain that is 254+ chars long
        long_label = "a" * 63
        # 63 chars per label + dots => need 4 labels + .com = 63*4 + 3 + 4 = 259
        long_domain = f"{long_label}.{long_label}.{long_label}.{long_label}.com"
        assert len(long_domain) > _MAX_DOMAIN_LEN
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain=long_domain,
                origin_url="https://app.example.com",
            )

    def test_rejects_tld_only_domain(self):
        """A domain with only a TLD ('com') has no subdomain — reject.

        The regex requires at least one dot-separated label before the TLD.
        """
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain="com",
                origin_url="https://app.example.com",
            )

    def test_rejects_consecutive_dots_in_domain(self):
        """Consecutive dots ('example..com') indicate malformed domain — reject."""
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain="example..com",
                origin_url="https://app.example.com",
            )

    def test_rejects_ip_address_as_domain(self):
        """IP addresses must not be accepted as customer domains."""
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain="192.168.1.1",
                origin_url="https://app.example.com",
            )

    def test_rejects_localhost_domain(self):
        """localhost must not be accepted as a customer domain."""
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain="localhost",
                origin_url="https://app.example.com",
            )

    def test_accepts_valid_domain(self):
        """Sanity check: valid domain is accepted."""
        model = OnboardingCreate(
            customer_domain="app.example.com",
            origin_url="https://origin.example.com",
        )
        assert model.customer_domain == "app.example.com"


# ===========================================================================
# TestOriginURLSSRF (~8 tests)
# ===========================================================================


class TestOriginURLSSRF:
    """Validates that origin_url validation blocks SSRF attack vectors.

    The Pydantic model validates scheme; the route calls validate_origin_url()
    for deeper SSRF checks. We test both layers.
    """

    def test_rejects_localhost_origin(self):
        """http://127.0.0.1 is a classic SSRF target — must be blocked by route."""
        from proxy.middleware.url_validator import validate_origin_url
        error = validate_origin_url("http://127.0.0.1", strict_dns=True)
        assert error is not None, "localhost should be rejected by SSRF validator"

    def test_rejects_internal_network_origin(self):
        """RFC 1918 private network 10.0.0.0/8 — must be blocked."""
        from proxy.middleware.url_validator import validate_origin_url
        error = validate_origin_url("http://10.0.0.1", strict_dns=True)
        assert error is not None, "10.x.x.x should be rejected"

    def test_rejects_metadata_endpoint(self):
        """AWS metadata service at 169.254.169.254 — critical SSRF target."""
        from proxy.middleware.url_validator import validate_origin_url
        error = validate_origin_url("http://169.254.169.254/latest/meta-data/", strict_dns=True)
        assert error is not None, "AWS metadata endpoint should be rejected"

    def test_rejects_file_scheme(self):
        """file:// scheme enables local file reading — must reject."""
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain="app.example.com",
                origin_url="file:///etc/passwd",
            )

    def test_rejects_data_scheme(self):
        """data:// scheme can exfiltrate data — must reject."""
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain="app.example.com",
                origin_url="data:text/html,<script>alert(1)</script>",
            )

    def test_rejects_origin_with_port_scan_attempt(self):
        """Origin URL pointing to common service port (SSH) — SSRF vector."""
        from proxy.middleware.url_validator import validate_origin_url
        # 127.0.0.1:22 = SSH port scan via SSRF
        error = validate_origin_url("http://127.0.0.1:22", strict_dns=True)
        assert error is not None, "Port scanning via SSRF should be blocked"

    def test_rejects_origin_url_with_credentials(self):
        """URL with userinfo (user:pass@host) enables parser confusion SSRF."""
        from proxy.middleware.url_validator import validate_origin_url
        error = validate_origin_url("http://user:pass@evil.com", strict_dns=True)
        assert error is not None, "URLs with userinfo should be rejected"

    def test_accepts_valid_https_origin(self):
        """Sanity check: valid HTTPS origin passes model validation."""
        model = OnboardingCreate(
            customer_domain="app.example.com",
            origin_url="https://app.example.com",
        )
        assert model.origin_url == "https://app.example.com"

    def test_rejects_null_byte_in_origin(self):
        """Null byte in URL enables truncation attacks — must reject."""
        from proxy.middleware.url_validator import validate_origin_url
        error = validate_origin_url("http://evil.com%00.allowed.com", strict_dns=True)
        assert error is not None, "Null byte in URL should be rejected"

    def test_rejects_link_local_origin(self):
        """Link-local addresses (169.254.x.x) used for cloud metadata — reject."""
        from proxy.middleware.url_validator import validate_origin_url
        error = validate_origin_url("http://169.254.1.1", strict_dns=True)
        assert error is not None, "Link-local addresses should be rejected"


# ===========================================================================
# TestIDORPrevention (~6 tests)
# ===========================================================================


class TestIDORPrevention:
    """Validates that onboarding operations enforce tenant isolation.

    IDOR = Insecure Direct Object Reference — attacker guesses another
    tenant's onboarding ID to read/modify/delete it.
    """

    @pytest.mark.asyncio
    async def test_get_onboarding_with_customer_uses_tenant_transaction(self):
        """get_onboarding(id, customer_id=X) must use tenant_transaction (RLS)."""
        pool, mock_conn = _make_pool_mock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        with patch("proxy.store.onboarding.get_pool", return_value=pool), \
             patch("proxy.store.onboarding.tenant_transaction", _mock_tenant_tx(mock_conn)) as mock_tx:
            result = await get_onboarding(ONBOARDING_A, customer_id=CUSTOMER_A)
            # When customer_id is provided, it should NOT use pool.acquire directly
            # — it should go through tenant_transaction for RLS
            assert result is None  # Not found is fine — we're testing the path
            mock_conn.fetchrow.assert_called_once()
            sql = mock_conn.fetchrow.call_args[0][0]
            assert "customer_id = $2" in sql, "Query must filter by customer_id"

    @pytest.mark.asyncio
    async def test_list_onboardings_scoped_to_customer(self):
        """list_onboardings() uses tenant_transaction — RLS enforces isolation."""
        pool, mock_conn = _make_pool_mock()

        with patch("proxy.store.onboarding.get_pool", return_value=pool), \
             patch("proxy.store.onboarding.tenant_transaction", _mock_tenant_tx(mock_conn)):
            result = await list_onboardings(CUSTOMER_A)
            assert result == []
            sql = mock_conn.fetch.call_args[0][0]
            assert "customer_id = $1" in sql

    @pytest.mark.asyncio
    async def test_update_onboarding_with_customer_enforces_ownership(self):
        """update_onboarding(id, customer_id=X, ...) must scope to customer."""
        pool, mock_conn = _make_pool_mock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        with patch("proxy.store.onboarding.get_pool", return_value=pool), \
             patch("proxy.store.onboarding.tenant_transaction", _mock_tenant_tx(mock_conn)):
            result = await update_onboarding(
                ONBOARDING_A,
                customer_id=CUSTOMER_A,
                status="active",
            )
            # The SQL should include customer_id in WHERE clause
            sql = mock_conn.fetchrow.call_args[0][0]
            assert "customer_id" in sql, "UPDATE must scope to customer_id"

    @pytest.mark.asyncio
    async def test_delete_onboarding_with_customer_enforces_ownership(self):
        """delete_onboarding(id, customer_id=X) must scope to customer."""
        pool, mock_conn = _make_pool_mock()
        mock_conn.execute = AsyncMock(return_value="DELETE 0")

        with patch("proxy.store.onboarding.get_pool", return_value=pool), \
             patch("proxy.store.onboarding.tenant_transaction", _mock_tenant_tx(mock_conn)):
            result = await delete_onboarding(ONBOARDING_A, customer_id=CUSTOMER_A)
            sql = mock_conn.execute.call_args[0][0]
            assert "customer_id = $2" in sql, "DELETE must scope to customer_id"

    @pytest.mark.asyncio
    async def test_store_column_whitelist_blocks_sql_injection(self):
        """Passing a non-whitelisted column name must raise ValueError.

        Attacker tries: update_onboarding(id, customer_id=X, **{"id": new_uuid})
        to overwrite the record ID (primary key).
        """
        pool, mock_conn = _make_pool_mock()

        with patch("proxy.store.onboarding.get_pool", return_value=pool), \
             patch("proxy.store.onboarding.tenant_transaction", _mock_tenant_tx(mock_conn)):
            with pytest.raises(ValueError, match="Invalid column name"):
                await update_onboarding(
                    ONBOARDING_A,
                    customer_id=CUSTOMER_A,
                    id=uuid4(),  # Attack: overwrite primary key
                )

    @pytest.mark.asyncio
    async def test_count_active_onboardings_scoped_to_customer(self):
        """count_active_onboardings uses tenant_transaction — RLS scoping."""
        pool, mock_conn = _make_pool_mock()
        mock_conn.fetchval = AsyncMock(return_value=3)

        with patch("proxy.store.onboarding.get_pool", return_value=pool), \
             patch("proxy.store.onboarding.tenant_transaction", _mock_tenant_tx(mock_conn)):
            count = await count_active_onboardings(CUSTOMER_A)
            assert count == 3
            sql = mock_conn.fetchval.call_args[0][0]
            assert "customer_id = $1" in sql


# ===========================================================================
# TestResourceExhaustion (~5 tests)
# ===========================================================================


class TestResourceExhaustion:
    """Validates defenses against resource exhaustion / abuse.

    Attacker tries to create unlimited onboardings, duplicate domains,
    or abuse polling intervals to amplify AWS API costs.
    """

    def test_per_customer_onboarding_limit_value(self):
        """MAX_ONBOARDINGS_PER_CUSTOMER must be 10 — prevents mass onboarding abuse."""
        assert MAX_ONBOARDINGS_PER_CUSTOMER == 10

    @pytest.mark.asyncio
    async def test_per_customer_onboarding_limit_enforced_in_route(self):
        """Route must return 422 when customer already has max onboardings."""
        from proxy.api.onboarding_routes import create_onboarding as route_create

        mock_customer = {"id": CUSTOMER_A, "name": "Test"}

        with patch("proxy.api.onboarding_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock_customer), \
             patch("proxy.api.onboarding_routes.validate_origin_url", return_value=None), \
             patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding_by_domain", new_callable=AsyncMock, return_value=None), \
             patch("proxy.api.onboarding_routes.onboarding_store.count_active_onboardings", new_callable=AsyncMock, return_value=10):

            body = OnboardingCreate(
                customer_domain="new-domain.example.com",
                origin_url="https://origin.example.com",
            )

            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                await route_create(CUSTOMER_A, body)
            assert exc_info.value.status_code == 422
            assert "Maximum" in str(exc_info.value.detail) or "maximum" in str(exc_info.value.detail).lower()

    @pytest.mark.asyncio
    async def test_duplicate_domain_returns_409(self):
        """Route must return 409 when domain already has active onboarding."""
        from proxy.api.onboarding_routes import create_onboarding as route_create
        from fastapi import HTTPException

        mock_customer = {"id": CUSTOMER_A, "name": "Test"}
        existing_record = _make_onboarding_record()

        with patch("proxy.api.onboarding_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock_customer), \
             patch("proxy.api.onboarding_routes.validate_origin_url", return_value=None), \
             patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding_by_domain", new_callable=AsyncMock, return_value=existing_record):

            body = OnboardingCreate(
                customer_domain="app.example.com",
                origin_url="https://origin.example.com",
            )

            with pytest.raises(HTTPException) as exc_info:
                await route_create(CUSTOMER_A, body)
            assert exc_info.value.status_code == 409

    def test_schema_has_unique_index_on_active_domain(self):
        """Schema must have a unique partial index preventing duplicate active domains.

        Without this, concurrent requests could create duplicates.
        """
        schema = _schema_sql()
        assert "idx_onboardings_domain_active" in schema
        assert "UNIQUE INDEX" in schema.upper() or "unique index" in schema.lower()
        # Verify it's a partial index that excludes offboarded/failed
        assert "NOT IN ('offboarded', 'failed')" in schema

    def test_cert_poller_minimum_interval(self):
        """Cert poller must enforce minimum 10s interval to prevent tight loops."""
        assert CERT_MIN_POLL_INTERVAL >= 10

    def test_tenant_creator_minimum_interval(self):
        """Tenant creator must enforce minimum 10s interval to prevent tight loops."""
        assert TENANT_MIN_POLL_INTERVAL >= 10


# ===========================================================================
# TestCertificateSecurityFlaws (~6 tests)
# ===========================================================================


class TestCertificateSecurityFlaws:
    """Validates certificate poller security properties.

    Attack vectors: empty ARN bypass, indefinite pending state,
    exception handling, orphaned certificates.
    """

    @pytest.mark.asyncio
    async def test_empty_cert_arn_returns_failed(self):
        """Empty certificate ARN must return 'failed' — prevents describe without ARN.

        An empty ARN could cause a boto3 error or unvalidated API call.
        """
        onboarding = _make_onboarding_record(acm_certificate_arn="")
        mock_acm = MagicMock()
        result = await check_certificate_status(onboarding, acm_client=mock_acm)
        assert result == "failed"
        # boto3 should NOT have been called
        mock_acm.describe_certificate.assert_not_called()

    @pytest.mark.asyncio
    async def test_72_hour_timeout_prevents_indefinite_pending(self):
        """Certificates pending > 72 hours must be marked failed.

        Prevents infinite AWS API calls for abandoned certificate requests.
        """
        old_time = datetime.now(timezone.utc) - timedelta(hours=73)
        onboarding = _make_onboarding_record(created_at=old_time)
        mock_acm = MagicMock()
        mock_acm.describe_certificate = MagicMock(return_value={
            "Certificate": {"Status": "PENDING_VALIDATION"},
        })
        result = await check_certificate_status(onboarding, acm_client=mock_acm)
        assert result == "failed"

    @pytest.mark.asyncio
    async def test_failed_acm_status_propagated(self):
        """ACM 'FAILED' status must propagate to onboarding as 'failed'."""
        onboarding = _make_onboarding_record()
        mock_acm = MagicMock()
        mock_acm.describe_certificate = MagicMock(return_value={
            "Certificate": {"Status": "FAILED", "FailureReason": "CNAME_CONFLICT"},
        })
        result = await check_certificate_status(onboarding, acm_client=mock_acm)
        assert result == "failed"

    @pytest.mark.asyncio
    async def test_boto3_exception_handled_gracefully(self):
        """boto3 exception during describe must NOT crash — returns None."""
        onboarding = _make_onboarding_record()
        mock_acm = MagicMock()
        mock_acm.describe_certificate = MagicMock(side_effect=Exception("AWS SDK error"))
        result = await check_certificate_status(onboarding, acm_client=mock_acm)
        assert result is None  # No crash, no status change

    @pytest.mark.asyncio
    async def test_offboarding_deletes_certificate(self):
        """Offboarding must delete the ACM certificate — no orphaned certs.

        Orphaned certificates accumulate in AWS and count toward limits.
        """
        from proxy.api.onboarding_routes import delete_onboarding as route_delete
        from proxy.api import onboarding_routes

        record = _make_onboarding_record(status="active")
        mock_acm = MagicMock()
        mock_acm.delete_certificate = MagicMock()

        # Inject the mock ACM client
        original_acm = onboarding_routes._acm_client
        onboarding_routes._acm_client = mock_acm

        try:
            with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding", new_callable=AsyncMock, return_value=record), \
                 patch("proxy.api.onboarding_routes.onboarding_store.update_onboarding", new_callable=AsyncMock, return_value=record):
                await route_delete(CUSTOMER_A, ONBOARDING_A)
                mock_acm.delete_certificate.assert_called_once_with(
                    CertificateArn=record["acm_certificate_arn"],
                )
        finally:
            onboarding_routes._acm_client = original_acm

    @pytest.mark.asyncio
    async def test_cert_poller_shutdown_event_respected(self):
        """Cert poller must stop when shutdown_event is set — clean shutdown."""
        shutdown = asyncio.Event()
        shutdown.set()  # Pre-set to stop immediately

        with patch("proxy.store.onboarding.list_pending_onboardings", new_callable=AsyncMock, return_value=[]) as mock_list, \
             patch("proxy.store.onboarding.claim_and_update", new_callable=AsyncMock):
            # Should return quickly without hanging
            await asyncio.wait_for(
                run_cert_poller(
                    poll_interval=10,
                    acm_client=None,
                    shutdown_event=shutdown,
                ),
                timeout=5.0,
            )


# ===========================================================================
# TestTenantCreatorSecurityFlaws (~5 tests)
# ===========================================================================


class TestTenantCreatorSecurityFlaws:
    """Validates tenant creator security properties.

    Attack vectors: partial creation from missing fields, stuck states,
    exception handling, missing client configuration.
    """

    @pytest.mark.asyncio
    async def test_missing_fields_returns_none(self):
        """Missing domain/origin/cert must return None — no partial creation.

        Partial creation could leave orphaned AWS resources.
        """
        mock_cf = MagicMock()
        # Missing customer_domain
        onboarding = _make_onboarding_record(customer_domain="")
        result = await create_distribution_tenant(
            onboarding,
            cloudfront_client=mock_cf,
            distribution_id="E123456",
        )
        assert result is None
        mock_cf.create_distribution_tenant.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_cert_arn_returns_none(self):
        """Missing certificate ARN must return None."""
        mock_cf = MagicMock()
        onboarding = _make_onboarding_record(acm_certificate_arn="")
        result = await create_distribution_tenant(
            onboarding,
            cloudfront_client=mock_cf,
            distribution_id="E123456",
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_boto3_exception_returns_none(self):
        """boto3 exception during create must return None — not stuck in validated.

        The caller (run_tenant_creator) marks it as failed.
        """
        mock_cf = MagicMock()
        mock_cf.create_distribution_tenant = MagicMock(
            side_effect=Exception("CloudFront API error"),
        )
        onboarding = _make_onboarding_record()
        result = await create_distribution_tenant(
            onboarding,
            cloudfront_client=mock_cf,
            distribution_id="E123456",
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_tenant_creator_shutdown_event_respected(self):
        """Tenant creator must stop when shutdown_event is set — clean shutdown."""
        shutdown = asyncio.Event()
        shutdown.set()

        with patch("proxy.store.onboarding.list_validated_onboardings", new_callable=AsyncMock, return_value=[]), \
             patch("proxy.store.onboarding.claim_and_update", new_callable=AsyncMock):
            await asyncio.wait_for(
                run_tenant_creator(
                    poll_interval=10,
                    cloudfront_client=None,
                    distribution_id="E123",
                    shutdown_event=shutdown,
                ),
                timeout=5.0,
            )

    @pytest.mark.asyncio
    async def test_no_client_configured_warns_and_skips(self):
        """When cloudfront_client is None, loop warns and skips — no crash."""
        shutdown = asyncio.Event()
        validated_records = [_make_onboarding_record(status="certificate_validated")]

        async def _set_shutdown_after_one_iter():
            await asyncio.sleep(0.05)
            shutdown.set()

        with patch("proxy.store.onboarding.list_validated_onboardings", new_callable=AsyncMock, return_value=validated_records), \
             patch("proxy.store.onboarding.claim_and_update", new_callable=AsyncMock):
            # Run concurrently: creator + shutdown timer
            await asyncio.wait_for(
                asyncio.gather(
                    run_tenant_creator(
                        poll_interval=10,
                        cloudfront_client=None,  # Not configured
                        distribution_id="",
                        shutdown_event=shutdown,
                    ),
                    _set_shutdown_after_one_iter(),
                ),
                timeout=5.0,
            )
            # No crash = success

    @pytest.mark.asyncio
    async def test_failed_creation_stores_error_message(self):
        """When create_distribution_tenant returns None, the loop must store error."""
        shutdown = asyncio.Event()
        validated_records = [_make_onboarding_record(status="certificate_validated")]
        mock_cf = MagicMock()
        mock_cf.create_distribution_tenant = MagicMock(side_effect=Exception("API boom"))
        mock_claim = AsyncMock()

        async def _stop():
            await asyncio.sleep(0.05)
            shutdown.set()

        with patch("proxy.store.onboarding.list_validated_onboardings", new_callable=AsyncMock, return_value=validated_records), \
             patch("proxy.store.onboarding.claim_and_update", mock_claim):
            await asyncio.wait_for(
                asyncio.gather(
                    run_tenant_creator(
                        poll_interval=10,
                        cloudfront_client=mock_cf,
                        distribution_id="E123",
                        shutdown_event=shutdown,
                    ),
                    _stop(),
                ),
                timeout=5.0,
            )
            # Verify claim_and_update was called with new_status=failed and error_message
            mock_claim.assert_called()
            call_kwargs = mock_claim.call_args
            assert call_kwargs.kwargs.get("new_status") == "failed"
            assert "error_message" in call_kwargs.kwargs


# ===========================================================================
# TestOffboardingSecurityFlaws (~5 tests)
# ===========================================================================


class TestOffboardingSecurityFlaws:
    """Validates offboarding security properties.

    Attack vectors: non-idempotent offboarding, orphaned AWS resources,
    cleanup failure propagation, 404 for non-existent records.
    """

    @pytest.mark.asyncio
    async def test_offboarding_idempotent_already_offboarded(self):
        """Offboarding an already-offboarded record must return 204 (no-op)."""
        from proxy.api.onboarding_routes import delete_onboarding as route_delete

        record = _make_onboarding_record(status=OnboardingStatus.OFFBOARDED)

        with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding", new_callable=AsyncMock, return_value=record):
            result = await route_delete(CUSTOMER_A, ONBOARDING_A)
            # Should return None (204 no content) without calling update
            assert result is None

    @pytest.mark.asyncio
    async def test_offboarding_cleans_up_cloudfront_tenant(self):
        """Offboarding must delete CloudFront tenant to prevent orphaned resources."""
        from proxy.api.onboarding_routes import delete_onboarding as route_delete
        from proxy.api import onboarding_routes

        record = _make_onboarding_record(
            status="tenant_created",
            distribution_tenant_id="tenant-abc-123",
        )
        mock_cf = MagicMock()
        mock_cf.delete_distribution_tenant = MagicMock()
        original_cf = onboarding_routes._cloudfront_client
        onboarding_routes._cloudfront_client = mock_cf

        try:
            with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding", new_callable=AsyncMock, return_value=record), \
                 patch("proxy.api.onboarding_routes.onboarding_store.update_onboarding", new_callable=AsyncMock, return_value=record):
                await route_delete(CUSTOMER_A, ONBOARDING_A)
                mock_cf.delete_distribution_tenant.assert_called_once()
        finally:
            onboarding_routes._cloudfront_client = original_cf

    @pytest.mark.asyncio
    async def test_offboarding_handles_cleanup_failures_by_marking_failed(self):
        """Cleanup failures must mark as FAILED (not offboarded) and raise 502.

        If CloudFront or ACM deletion fails, the onboarding is marked as FAILED
        so that dangling AWS resources remain visible and can be retried. The
        API returns 502 to signal partial failure to the client.
        """
        from proxy.api.onboarding_routes import delete_onboarding as route_delete
        from proxy.api import onboarding_routes
        from fastapi import HTTPException

        record = _make_onboarding_record(
            status="active",
            distribution_tenant_id="tenant-abc",
        )
        mock_cf = MagicMock()
        mock_cf.delete_distribution_tenant = MagicMock(side_effect=Exception("AWS error"))
        mock_acm = MagicMock()
        mock_acm.delete_certificate = MagicMock(side_effect=Exception("AWS error"))

        original_cf = onboarding_routes._cloudfront_client
        original_acm = onboarding_routes._acm_client
        onboarding_routes._cloudfront_client = mock_cf
        onboarding_routes._acm_client = mock_acm

        mock_update = AsyncMock(return_value=record)

        try:
            with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding", new_callable=AsyncMock, return_value=record), \
                 patch("proxy.api.onboarding_routes.onboarding_store.update_onboarding", mock_update):
                # Should raise 502 because cleanup failed
                with pytest.raises(HTTPException) as exc_info:
                    await route_delete(CUSTOMER_A, ONBOARDING_A)
                assert exc_info.value.status_code == 502
                # Verify it marks as FAILED (not offboarded) so resources stay visible
                mock_update.assert_called_once()
                assert mock_update.call_args.kwargs.get("status") == OnboardingStatus.FAILED
                assert "error_message" in mock_update.call_args.kwargs
        finally:
            onboarding_routes._cloudfront_client = original_cf
            onboarding_routes._acm_client = original_acm

    @pytest.mark.asyncio
    async def test_offboarding_returns_404_for_nonexistent_record(self):
        """Offboarding a non-existent record must return 404 — prevents probing."""
        from proxy.api.onboarding_routes import delete_onboarding as route_delete
        from fastapi import HTTPException

        with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding", new_callable=AsyncMock, return_value=None):
            with pytest.raises(HTTPException) as exc_info:
                await route_delete(CUSTOMER_A, uuid4())
            assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_offboarding_cleans_up_acm_certificate(self):
        """Offboarding must delete ACM certificate — prevents cert accumulation."""
        from proxy.api.onboarding_routes import delete_onboarding as route_delete
        from proxy.api import onboarding_routes

        cert_arn = "arn:aws:acm:us-east-1:123:certificate/xyz"
        record = _make_onboarding_record(
            status="active",
            acm_certificate_arn=cert_arn,
            distribution_tenant_id="",  # No CloudFront to clean
        )
        mock_acm = MagicMock()
        mock_acm.delete_certificate = MagicMock()
        original_acm = onboarding_routes._acm_client
        onboarding_routes._acm_client = mock_acm

        try:
            with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding", new_callable=AsyncMock, return_value=record), \
                 patch("proxy.api.onboarding_routes.onboarding_store.update_onboarding", new_callable=AsyncMock, return_value=record):
                await route_delete(CUSTOMER_A, ONBOARDING_A)
                mock_acm.delete_certificate.assert_called_once_with(CertificateArn=cert_arn)
        finally:
            onboarding_routes._acm_client = original_acm


# ===========================================================================
# TestStoreSecurityProperties (~6 tests)
# ===========================================================================


class TestStoreSecurityProperties:
    """Validates code-level security properties in the onboarding store.

    Inspects source code to verify parameterized queries, column whitelists,
    and correct use of RLS context managers.
    """

    def test_onboarding_columns_whitelist_is_minimal(self):
        """_ONBOARDING_COLUMNS should contain ONLY expected safe columns.

        Must NOT include 'id', 'customer_id', 'customer_domain', 'created_at',
        'updated_at' — these are system-controlled fields.
        """
        expected = {
            "status", "acm_certificate_arn", "validation_cname_name",
            "validation_cname_value", "distribution_tenant_id", "cloudfront_cname",
            "error_message",
        }
        assert _ONBOARDING_COLUMNS == expected

        # Explicitly verify dangerous columns are NOT whitelisted
        dangerous = {"id", "customer_id", "customer_domain", "origin_url", "created_at", "updated_at"}
        assert _ONBOARDING_COLUMNS.isdisjoint(dangerous), \
            f"Dangerous columns found in whitelist: {_ONBOARDING_COLUMNS & dangerous}"

    def test_admin_functions_bypass_rls_via_pool_acquire(self):
        """list_pending, list_validated, get_by_domain must use pool.acquire (bypass RLS).

        These are admin/background functions that need cross-tenant visibility.
        """
        src = _store_source()

        # list_pending_onboardings should use pool.acquire, not tenant_transaction
        pending_fn = inspect.getsource(list_pending_onboardings)
        assert "pool.acquire()" in pending_fn, "list_pending must use pool.acquire"
        assert "tenant_transaction" not in pending_fn, "list_pending must NOT use tenant_transaction"

        # list_validated_onboardings same
        validated_fn = inspect.getsource(list_validated_onboardings)
        assert "pool.acquire()" in validated_fn
        assert "tenant_transaction" not in validated_fn

        # get_onboarding_by_domain same
        by_domain_fn = inspect.getsource(get_onboarding_by_domain)
        assert "pool.acquire()" in by_domain_fn
        assert "tenant_transaction" not in by_domain_fn

    def test_tenant_scoped_functions_use_tenant_transaction(self):
        """create, list, count_active must use tenant_transaction for RLS."""
        create_fn = inspect.getsource(create_onboarding)
        assert "tenant_transaction" in create_fn

        list_fn = inspect.getsource(list_onboardings)
        assert "tenant_transaction" in list_fn

        count_fn = inspect.getsource(count_active_onboardings)
        assert "tenant_transaction" in count_fn

    @pytest.mark.asyncio
    async def test_store_unavailable_raised_when_pool_is_none(self):
        """StoreUnavailable must be raised when pool is None — fail-closed."""
        with patch("proxy.store.onboarding.get_pool", return_value=None):
            with pytest.raises(StoreUnavailable):
                await create_onboarding(CUSTOMER_A, "app.example.com", "https://origin.com")

            with pytest.raises(StoreUnavailable):
                await get_onboarding(ONBOARDING_A, customer_id=CUSTOMER_A)

            with pytest.raises(StoreUnavailable):
                await list_onboardings(CUSTOMER_A)

            with pytest.raises(StoreUnavailable):
                await count_active_onboardings(CUSTOMER_A)

    @pytest.mark.asyncio
    async def test_update_rejects_nonwhitelisted_columns(self):
        """Passing non-whitelisted column to update must raise ValueError.

        Prevents SQL injection via dynamic column names.
        """
        pool, mock_conn = _make_pool_mock()

        with patch("proxy.store.onboarding.get_pool", return_value=pool), \
             patch("proxy.store.onboarding.tenant_transaction", _mock_tenant_tx(mock_conn)):
            # Attack: inject SQL via column name
            with pytest.raises(ValueError, match="Invalid column name"):
                await update_onboarding(
                    ONBOARDING_A,
                    customer_id=CUSTOMER_A,
                    **{"status; DROP TABLE--": "active"},
                )

    def test_sql_uses_parameterized_queries(self):
        """All SQL queries must use $1, $2, ... parameters — never string interpolation.

        String interpolation (f-string with user data) enables SQL injection.
        We verify that user-supplied values go through parameter binding.
        """
        src = _store_source()

        # Check that all SQL queries use $N parameter binding
        # The only f-string usage should be for column lists (_SELECT_COLS)
        # and set clauses (built from whitelisted column names)
        sql_patterns = re.findall(r'(?:fetchrow|fetch|fetchval|execute)\(\s*f?"([^"]+)"', src)

        for sql in sql_patterns:
            # If the SQL references user-supplied values, it should use $N placeholders
            # Check that there are no bare {variable} interpolations (except _SELECT_COLS)
            interpolations = re.findall(r'\{(\w+)\}', sql)
            for interp in interpolations:
                assert interp in ("_SELECT_COLS", "where", "idx"), \
                    f"Unexpected interpolation {{{interp}}} in SQL — possible injection risk"


# ===========================================================================
# TestSchemaSecurityProperties (~5 tests)
# ===========================================================================


class TestSchemaSecurityProperties:
    """Validates security properties in the database schema (schema.sql).

    Reads the actual SQL file and verifies RLS, constraints, grants.
    """

    def test_onboarding_table_has_rls_enabled(self):
        """RLS must be enabled on the onboardings table — enforces tenant isolation."""
        schema = _schema_sql()
        assert "ALTER TABLE onboardings ENABLE ROW LEVEL SECURITY" in schema

    def test_schema_has_tenant_isolation_policy_on_onboardings(self):
        """A tenant_isolation RLS policy must exist on the onboardings table.

        It must reference current_setting('app.current_tenant_id') for
        the GUC-based tenant context used by tenant_transaction().
        """
        schema = _schema_sql()
        # Find the policy creation for onboardings
        assert "CREATE POLICY tenant_isolation ON onboardings" in schema
        # Verify it uses the GUC
        assert "current_setting('app.current_tenant_id'" in schema

    def test_schema_has_status_check_constraint(self):
        """Status column must have a CHECK constraint limiting valid values.

        Prevents invalid status values from being stored — defense in depth.
        """
        schema = _schema_sql()
        assert "chk_onboarding_status" in schema
        # Verify all valid statuses are in the constraint
        for status in OnboardingStatus:
            assert status.value in schema, f"Status {status.value} missing from CHECK constraint"

    def test_schema_grants_only_dml_no_truncate(self):
        """shieldai_app role must only have SELECT/INSERT/UPDATE/DELETE — no TRUNCATE.

        TRUNCATE bypasses RLS policies, enabling bulk data deletion.
        """
        schema = _schema_sql()
        # Verify GRANT only DML
        assert "GRANT SELECT, INSERT, UPDATE, DELETE ON onboardings TO shieldai_app" in schema
        # Verify explicit REVOKE of dangerous privileges
        assert "REVOKE TRUNCATE ON onboardings FROM shieldai_app" in schema
        assert "REVOKE REFERENCES ON onboardings FROM shieldai_app" in schema
        assert "REVOKE TRIGGER ON onboardings FROM shieldai_app" in schema

    def test_schema_has_unique_index_on_active_domain(self):
        """Unique partial index must prevent duplicate active domain onboardings.

        The index must exclude 'offboarded' and 'failed' statuses so that
        domains can be re-onboarded after offboarding.
        """
        schema = _schema_sql()
        # Find the unique index
        idx_match = re.search(
            r"CREATE\s+UNIQUE\s+INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?idx_onboardings_domain_active\s+ON\s+onboardings\(customer_domain\)\s+WHERE\s+status\s+NOT\s+IN\s+\('offboarded',\s*'failed'\)",
            schema,
            re.IGNORECASE,
        )
        assert idx_match is not None, "Missing unique partial index on onboardings(customer_domain)"

    def test_schema_onboarding_customer_id_foreign_key_cascade(self):
        """customer_id must FK to customers(id) with ON DELETE CASCADE.

        Ensures orphaned onboardings are cleaned up when a customer is deleted.
        """
        schema = _schema_sql()
        # Find the onboardings table CREATE and verify FK
        onboarding_section = schema[schema.index("CREATE TABLE IF NOT EXISTS onboardings"):]
        assert "REFERENCES customers(id) ON DELETE CASCADE" in onboarding_section


# ===========================================================================
# TestSecurityHardening (~30 tests)
# ===========================================================================


class TestSecurityHardening:
    """Tests for SHIELD-41 security hardening round 1.

    Covers:
    - Orphaned ACM certificate cleanup on DB insert failure
    - TOCTOU race protection (UniqueViolationError → DuplicateDomain → 409)
    - Atomic status claim (claim_and_update optimistic lock)
    - Response field filtering (_safe_record strips internal fields)
    - Infrastructure domain blocking (blocked suffixes, null bytes, control chars)
    - Offboarding failure handling (FAILED status, 502 on cleanup failure)
    - Valid state transitions (VALID_TRANSITIONS dict)
    - Silent empty return logging (list_pending/list_validated log when pool is None)
    """

    # -----------------------------------------------------------------------
    # 1. Orphaned ACM certificate cleanup
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_cleanup_acm_on_duplicate_domain_race(self):
        """When DuplicateDomain is caught (TOCTOU race), orphaned cert is cleaned up."""
        from proxy.api.onboarding_routes import create_onboarding as route_create
        from proxy.api import onboarding_routes
        from fastapi import HTTPException

        mock_customer = {"id": CUSTOMER_A, "name": "Test"}
        mock_acm = MagicMock()
        mock_acm.request_certificate = MagicMock(return_value={
            "CertificateArn": "arn:aws:acm:us-east-1:123:certificate/orphan-1",
        })
        mock_acm.describe_certificate = MagicMock(return_value={
            "Certificate": {
                "DomainValidationOptions": [{
                    "ResourceRecord": {"Name": "_c.example.com", "Value": "_v.aws"},
                }],
            },
        })
        mock_acm.delete_certificate = MagicMock()

        original_acm = onboarding_routes._acm_client
        onboarding_routes._acm_client = mock_acm

        try:
            with patch("proxy.api.onboarding_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock_customer), \
                 patch("proxy.api.onboarding_routes.validate_origin_url", return_value=None), \
                 patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding_by_domain", new_callable=AsyncMock, return_value=None), \
                 patch("proxy.api.onboarding_routes.onboarding_store.count_active_onboardings", new_callable=AsyncMock, return_value=0), \
                 patch("proxy.api.onboarding_routes.onboarding_store.create_onboarding", new_callable=AsyncMock, side_effect=DuplicateDomain("race")):

                body = OnboardingCreate(
                    customer_domain="race.example.com",
                    origin_url="https://origin.example.com",
                )
                with pytest.raises(HTTPException) as exc_info:
                    await route_create(CUSTOMER_A, body)

                assert exc_info.value.status_code == 409
                # Verify the orphaned cert was cleaned up
                mock_acm.delete_certificate.assert_called_once_with(
                    CertificateArn="arn:aws:acm:us-east-1:123:certificate/orphan-1",
                )
        finally:
            onboarding_routes._acm_client = original_acm

    @pytest.mark.asyncio
    async def test_cleanup_acm_on_store_unavailable(self):
        """When StoreUnavailable is caught after ACM request, cert is cleaned up."""
        from proxy.api.onboarding_routes import create_onboarding as route_create
        from proxy.api import onboarding_routes
        from fastapi import HTTPException

        mock_customer = {"id": CUSTOMER_A, "name": "Test"}
        mock_acm = MagicMock()
        mock_acm.request_certificate = MagicMock(return_value={
            "CertificateArn": "arn:aws:acm:us-east-1:123:certificate/orphan-2",
        })
        mock_acm.describe_certificate = MagicMock(return_value={
            "Certificate": {"DomainValidationOptions": [{"ResourceRecord": {"Name": "_n", "Value": "_v"}}]},
        })
        mock_acm.delete_certificate = MagicMock()

        original_acm = onboarding_routes._acm_client
        onboarding_routes._acm_client = mock_acm

        try:
            with patch("proxy.api.onboarding_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock_customer), \
                 patch("proxy.api.onboarding_routes.validate_origin_url", return_value=None), \
                 patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding_by_domain", new_callable=AsyncMock, return_value=None), \
                 patch("proxy.api.onboarding_routes.onboarding_store.count_active_onboardings", new_callable=AsyncMock, return_value=0), \
                 patch("proxy.api.onboarding_routes.onboarding_store.create_onboarding", new_callable=AsyncMock, side_effect=StoreUnavailable("DB down")):

                body = OnboardingCreate(
                    customer_domain="dbfail.example.com",
                    origin_url="https://origin.example.com",
                )
                with pytest.raises(HTTPException) as exc_info:
                    await route_create(CUSTOMER_A, body)

                assert exc_info.value.status_code == 503
                mock_acm.delete_certificate.assert_called_once_with(
                    CertificateArn="arn:aws:acm:us-east-1:123:certificate/orphan-2",
                )
        finally:
            onboarding_routes._acm_client = original_acm

    @pytest.mark.asyncio
    async def test_cleanup_acm_on_unexpected_exception(self):
        """When any unexpected exception occurs after ACM request, cert is cleaned up."""
        from proxy.api.onboarding_routes import create_onboarding as route_create
        from proxy.api import onboarding_routes
        from fastapi import HTTPException

        mock_customer = {"id": CUSTOMER_A, "name": "Test"}
        mock_acm = MagicMock()
        mock_acm.request_certificate = MagicMock(return_value={
            "CertificateArn": "arn:aws:acm:us-east-1:123:certificate/orphan-3",
        })
        mock_acm.describe_certificate = MagicMock(return_value={
            "Certificate": {"DomainValidationOptions": [{"ResourceRecord": {"Name": "_n", "Value": "_v"}}]},
        })
        mock_acm.delete_certificate = MagicMock()

        original_acm = onboarding_routes._acm_client
        onboarding_routes._acm_client = mock_acm

        try:
            with patch("proxy.api.onboarding_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock_customer), \
                 patch("proxy.api.onboarding_routes.validate_origin_url", return_value=None), \
                 patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding_by_domain", new_callable=AsyncMock, return_value=None), \
                 patch("proxy.api.onboarding_routes.onboarding_store.count_active_onboardings", new_callable=AsyncMock, return_value=0), \
                 patch("proxy.api.onboarding_routes.onboarding_store.create_onboarding", new_callable=AsyncMock, side_effect=RuntimeError("unexpected")):

                body = OnboardingCreate(
                    customer_domain="crash.example.com",
                    origin_url="https://origin.example.com",
                )
                with pytest.raises(HTTPException) as exc_info:
                    await route_create(CUSTOMER_A, body)

                assert exc_info.value.status_code == 500
                mock_acm.delete_certificate.assert_called_once_with(
                    CertificateArn="arn:aws:acm:us-east-1:123:certificate/orphan-3",
                )
        finally:
            onboarding_routes._acm_client = original_acm

    @pytest.mark.asyncio
    async def test_cleanup_acm_does_not_crash_on_failure(self):
        """_cleanup_acm_certificate logs but does not raise if delete fails."""
        from proxy.api.onboarding_routes import _cleanup_acm_certificate
        from proxy.api import onboarding_routes

        mock_acm = MagicMock()
        mock_acm.delete_certificate = MagicMock(side_effect=Exception("AWS exploded"))
        original_acm = onboarding_routes._acm_client
        onboarding_routes._acm_client = mock_acm

        try:
            # Must NOT raise — just logs the error
            await _cleanup_acm_certificate("arn:aws:acm:us-east-1:123:certificate/dead")
            # If we reach here, no exception was raised — test passes
        finally:
            onboarding_routes._acm_client = original_acm

    @pytest.mark.asyncio
    async def test_cleanup_acm_noop_when_empty_arn(self):
        """_cleanup_acm_certificate is a no-op when cert_arn is empty."""
        from proxy.api.onboarding_routes import _cleanup_acm_certificate
        from proxy.api import onboarding_routes

        mock_acm = MagicMock()
        original_acm = onboarding_routes._acm_client
        onboarding_routes._acm_client = mock_acm

        try:
            await _cleanup_acm_certificate("")
            mock_acm.delete_certificate.assert_not_called()
        finally:
            onboarding_routes._acm_client = original_acm

    @pytest.mark.asyncio
    async def test_cleanup_acm_noop_when_no_client(self):
        """_cleanup_acm_certificate is a no-op when _acm_client is None."""
        from proxy.api.onboarding_routes import _cleanup_acm_certificate
        from proxy.api import onboarding_routes

        original_acm = onboarding_routes._acm_client
        onboarding_routes._acm_client = None

        try:
            await _cleanup_acm_certificate("arn:aws:acm:us-east-1:123:certificate/some")
            # No crash, no call — success
        finally:
            onboarding_routes._acm_client = original_acm

    # -----------------------------------------------------------------------
    # 2. TOCTOU race protection
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_store_create_catches_unique_violation_raises_duplicate_domain(self):
        """Store create_onboarding converts UniqueViolationError to DuplicateDomain."""
        pool, mock_conn = _make_pool_mock()

        # Simulate UniqueViolationError with the expected name
        class UniqueViolationError(Exception):
            pass

        mock_conn.fetchrow = AsyncMock(side_effect=UniqueViolationError("unique constraint"))

        with patch("proxy.store.onboarding.get_pool", return_value=pool), \
             patch("proxy.store.onboarding.tenant_transaction", _mock_tenant_tx(mock_conn)):
            with pytest.raises(DuplicateDomain):
                await create_onboarding(CUSTOMER_A, "dup.example.com", "https://origin.example.com")

    @pytest.mark.asyncio
    async def test_route_returns_409_on_duplicate_domain_exception(self):
        """Route catches DuplicateDomain from store and returns 409."""
        from proxy.api.onboarding_routes import create_onboarding as route_create
        from proxy.api import onboarding_routes
        from fastapi import HTTPException

        mock_customer = {"id": CUSTOMER_A, "name": "Test"}
        mock_acm = MagicMock()
        mock_acm.request_certificate = MagicMock(return_value={"CertificateArn": "arn:test"})
        mock_acm.describe_certificate = MagicMock(return_value={
            "Certificate": {"DomainValidationOptions": [{"ResourceRecord": {"Name": "_n", "Value": "_v"}}]},
        })
        mock_acm.delete_certificate = MagicMock()

        original_acm = onboarding_routes._acm_client
        onboarding_routes._acm_client = mock_acm

        try:
            with patch("proxy.api.onboarding_routes.pg_store.get_customer", new_callable=AsyncMock, return_value=mock_customer), \
                 patch("proxy.api.onboarding_routes.validate_origin_url", return_value=None), \
                 patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding_by_domain", new_callable=AsyncMock, return_value=None), \
                 patch("proxy.api.onboarding_routes.onboarding_store.count_active_onboardings", new_callable=AsyncMock, return_value=0), \
                 patch("proxy.api.onboarding_routes.onboarding_store.create_onboarding", new_callable=AsyncMock, side_effect=DuplicateDomain("toctou race")):

                body = OnboardingCreate(
                    customer_domain="toctou.example.com",
                    origin_url="https://origin.example.com",
                )
                with pytest.raises(HTTPException) as exc_info:
                    await route_create(CUSTOMER_A, body)
                assert exc_info.value.status_code == 409
                assert "already has an active onboarding" in str(exc_info.value.detail)
        finally:
            onboarding_routes._acm_client = original_acm

    # -----------------------------------------------------------------------
    # 3. Atomic status claim (claim_and_update)
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_claim_and_update_returns_none_when_already_claimed(self):
        """claim_and_update returns None when row status doesn't match expected."""
        pool, mock_conn = _make_pool_mock()
        # Simulate that the WHERE clause matched 0 rows (already claimed)
        mock_conn.fetchrow = AsyncMock(return_value=None)

        with patch("proxy.store.onboarding.get_pool", return_value=pool):
            from proxy.store.onboarding import claim_and_update
            result = await claim_and_update(
                ONBOARDING_A,
                expected_status="certificate_pending",
                new_status="certificate_validated",
            )
            assert result is None
            # Verify the SQL contains both id and expected_status in WHERE
            sql = mock_conn.fetchrow.call_args[0][0]
            assert "status = $" in sql, "SQL must use WHERE status = $N as optimistic lock"

    @pytest.mark.asyncio
    async def test_claim_and_update_succeeds_when_status_matches(self):
        """claim_and_update returns the updated record when status matches."""
        pool, mock_conn = _make_pool_mock()
        updated_record = _make_onboarding_record(status="certificate_validated")
        mock_conn.fetchrow = AsyncMock(return_value=updated_record)

        with patch("proxy.store.onboarding.get_pool", return_value=pool):
            from proxy.store.onboarding import claim_and_update
            result = await claim_and_update(
                ONBOARDING_A,
                expected_status="certificate_pending",
                new_status="certificate_validated",
            )
            assert result is not None
            assert result["status"] == "certificate_validated"

    @pytest.mark.asyncio
    async def test_claim_and_update_rejects_nonwhitelisted_fields(self):
        """claim_and_update raises ValueError for non-whitelisted column names."""
        pool, mock_conn = _make_pool_mock()

        with patch("proxy.store.onboarding.get_pool", return_value=pool):
            from proxy.store.onboarding import claim_and_update
            with pytest.raises(ValueError, match="Invalid column name"):
                await claim_and_update(
                    ONBOARDING_A,
                    expected_status="certificate_pending",
                    new_status="certificate_validated",
                    customer_id=CUSTOMER_B,  # Attack: overwrite customer_id
                )

    @pytest.mark.asyncio
    async def test_claim_and_update_passes_extra_fields_correctly(self):
        """claim_and_update correctly includes whitelisted extra fields."""
        pool, mock_conn = _make_pool_mock()
        mock_conn.fetchrow = AsyncMock(return_value=_make_onboarding_record())

        with patch("proxy.store.onboarding.get_pool", return_value=pool):
            from proxy.store.onboarding import claim_and_update
            await claim_and_update(
                ONBOARDING_A,
                expected_status="certificate_pending",
                new_status="failed",
                error_message="Timed out",
            )
            sql = mock_conn.fetchrow.call_args[0][0]
            assert "error_message" in sql, "error_message must be in SET clause"

    @pytest.mark.asyncio
    async def test_claim_and_update_raises_store_unavailable_when_no_pool(self):
        """claim_and_update raises StoreUnavailable when pool is None."""
        with patch("proxy.store.onboarding.get_pool", return_value=None):
            from proxy.store.onboarding import claim_and_update
            with pytest.raises(StoreUnavailable):
                await claim_and_update(
                    ONBOARDING_A,
                    expected_status="certificate_pending",
                    new_status="certificate_validated",
                )

    def test_cert_poller_uses_claim_and_update(self):
        """Cert poller must use claim_and_update (not update_onboarding) for concurrency safety."""
        src = inspect.getsource(run_cert_poller)
        assert "claim_and_update" in src, "cert_poller must use claim_and_update"
        assert "update_onboarding" not in src, "cert_poller must NOT use update_onboarding"

    def test_tenant_creator_uses_claim_and_update(self):
        """Tenant creator must use claim_and_update (not update_onboarding) for concurrency safety."""
        src = inspect.getsource(run_tenant_creator)
        assert "claim_and_update" in src, "tenant_creator must use claim_and_update"
        assert "update_onboarding" not in src, "tenant_creator must NOT use update_onboarding"

    # -----------------------------------------------------------------------
    # 4. Response field filtering
    # -----------------------------------------------------------------------

    def test_safe_record_strips_acm_certificate_arn(self):
        """_safe_record must strip acm_certificate_arn from response."""
        from proxy.api.onboarding_routes import _safe_record
        record = _make_onboarding_record()
        safe = _safe_record(record)
        assert "acm_certificate_arn" not in safe

    def test_safe_record_strips_distribution_tenant_id(self):
        """_safe_record must strip distribution_tenant_id from response."""
        from proxy.api.onboarding_routes import _safe_record
        record = _make_onboarding_record(distribution_tenant_id="tenant-secret-123")
        safe = _safe_record(record)
        assert "distribution_tenant_id" not in safe

    def test_safe_record_preserves_public_fields(self):
        """_safe_record must preserve all non-internal fields."""
        from proxy.api.onboarding_routes import _safe_record
        record = _make_onboarding_record()
        safe = _safe_record(record)
        assert "id" in safe
        assert "customer_id" in safe
        assert "customer_domain" in safe
        assert "status" in safe
        assert "origin_url" in safe
        assert "created_at" in safe

    def test_onboarding_response_model_excludes_internal_fields(self):
        """OnboardingResponse model must NOT have acm_certificate_arn or distribution_tenant_id."""
        fields = OnboardingResponse.model_fields
        assert "acm_certificate_arn" not in fields, \
            "OnboardingResponse must not expose acm_certificate_arn"
        assert "distribution_tenant_id" not in fields, \
            "OnboardingResponse must not expose distribution_tenant_id"

    # -----------------------------------------------------------------------
    # 5. Infrastructure domain blocking
    # -----------------------------------------------------------------------

    @pytest.mark.parametrize("suffix", [
        ".internal", ".local", ".localhost", ".corp", ".lan",
        ".home", ".localdomain", ".example", ".invalid", ".test",
        ".amazonaws.com", ".google.internal", ".nip.io", ".sslip.io",
        ".xip.io", ".traefik.me",
    ])
    def test_blocked_domain_suffix_rejected(self, suffix):
        """Infrastructure domain suffixes must be rejected by the validator."""
        domain = f"app{suffix}"
        # Some of these might also fail the regex, which is also acceptable
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain=domain,
                origin_url="https://origin.example.com",
            )

    def test_null_byte_in_domain_rejected(self):
        """Null bytes in domain must be rejected (control character check)."""
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain="app\x00.example.com",
                origin_url="https://origin.example.com",
            )

    def test_control_character_in_domain_rejected(self):
        """Control characters (e.g. \\x01) in domain must be rejected."""
        with pytest.raises(ValidationError):
            OnboardingCreate(
                customer_domain="app\x01.example.com",
                origin_url="https://origin.example.com",
            )

    def test_blocked_suffixes_list_is_comprehensive(self):
        """_BLOCKED_DOMAIN_SUFFIXES must contain all critical infrastructure suffixes."""
        from proxy.models.onboarding import _BLOCKED_DOMAIN_SUFFIXES
        critical_suffixes = [".internal", ".local", ".localhost", ".amazonaws.com", ".nip.io", ".sslip.io"]
        for suffix in critical_suffixes:
            assert suffix in _BLOCKED_DOMAIN_SUFFIXES, \
                f"Critical suffix {suffix} missing from _BLOCKED_DOMAIN_SUFFIXES"

    def test_error_message_does_not_echo_domain(self):
        """Validator error messages for blocked domains must not echo the input domain.

        The validator's own message (what it raises) must be generic.
        Echoing user input in validator errors enables information disclosure.
        """
        with pytest.raises(ValidationError) as exc_info:
            OnboardingCreate(
                customer_domain="evil.amazonaws.com",
                origin_url="https://origin.example.com",
            )
        # Check the validator's own message, not Pydantic's wrapper (which includes input_value)
        errors = exc_info.value.errors()
        for error in errors:
            msg = error.get("msg", "")
            assert "evil.amazonaws.com" not in msg, \
                "Validator error message must not echo back the invalid domain"

    # -----------------------------------------------------------------------
    # 6. Offboarding failure handling
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_offboarding_cf_failure_returns_502_and_marks_failed(self):
        """When CF tenant deletion fails, status is FAILED and client gets 502."""
        from proxy.api.onboarding_routes import delete_onboarding as route_delete
        from proxy.api import onboarding_routes
        from fastapi import HTTPException

        record = _make_onboarding_record(
            status="active",
            distribution_tenant_id="tenant-to-fail",
            acm_certificate_arn="",  # No ACM to clean
        )
        mock_cf = MagicMock()
        mock_cf.delete_distribution_tenant = MagicMock(side_effect=Exception("CF exploded"))

        original_cf = onboarding_routes._cloudfront_client
        onboarding_routes._cloudfront_client = mock_cf

        mock_update = AsyncMock(return_value=record)

        try:
            with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding", new_callable=AsyncMock, return_value=record), \
                 patch("proxy.api.onboarding_routes.onboarding_store.update_onboarding", mock_update):
                with pytest.raises(HTTPException) as exc_info:
                    await route_delete(CUSTOMER_A, ONBOARDING_A)
                assert exc_info.value.status_code == 502
                # Verify status set to FAILED
                assert mock_update.call_args.kwargs.get("status") == OnboardingStatus.FAILED
                error_msg = mock_update.call_args.kwargs.get("error_message", "")
                assert "CloudFront" in error_msg
        finally:
            onboarding_routes._cloudfront_client = original_cf

    @pytest.mark.asyncio
    async def test_offboarding_acm_failure_returns_502_and_marks_failed(self):
        """When ACM cert deletion fails, status is FAILED and client gets 502."""
        from proxy.api.onboarding_routes import delete_onboarding as route_delete
        from proxy.api import onboarding_routes
        from fastapi import HTTPException

        record = _make_onboarding_record(
            status="active",
            distribution_tenant_id="",  # No CF tenant to clean
            acm_certificate_arn="arn:aws:acm:us-east-1:123:certificate/fail-cert",
        )
        mock_acm = MagicMock()
        mock_acm.delete_certificate = MagicMock(side_effect=Exception("ACM exploded"))

        original_acm = onboarding_routes._acm_client
        onboarding_routes._acm_client = mock_acm

        mock_update = AsyncMock(return_value=record)

        try:
            with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding", new_callable=AsyncMock, return_value=record), \
                 patch("proxy.api.onboarding_routes.onboarding_store.update_onboarding", mock_update):
                with pytest.raises(HTTPException) as exc_info:
                    await route_delete(CUSTOMER_A, ONBOARDING_A)
                assert exc_info.value.status_code == 502
                assert mock_update.call_args.kwargs.get("status") == OnboardingStatus.FAILED
                error_msg = mock_update.call_args.kwargs.get("error_message", "")
                assert "ACM" in error_msg
        finally:
            onboarding_routes._acm_client = original_acm

    # -----------------------------------------------------------------------
    # 7. Valid state transitions
    # -----------------------------------------------------------------------

    def test_valid_transitions_dict_exists(self):
        """VALID_TRANSITIONS must be defined and cover all OnboardingStatus values."""
        from proxy.models.onboarding import VALID_TRANSITIONS
        for status in OnboardingStatus:
            assert status.value in VALID_TRANSITIONS or status in VALID_TRANSITIONS, \
                f"Status {status.value} missing from VALID_TRANSITIONS"

    def test_offboarded_is_terminal(self):
        """OFFBOARDED must be a terminal state with no valid transitions."""
        from proxy.models.onboarding import VALID_TRANSITIONS
        offboarded_transitions = VALID_TRANSITIONS[OnboardingStatus.OFFBOARDED]
        assert len(offboarded_transitions) == 0, "OFFBOARDED must be terminal (no transitions)"

    def test_cannot_skip_states(self):
        """certificate_pending must NOT transition directly to active (skip states)."""
        from proxy.models.onboarding import VALID_TRANSITIONS
        pending_targets = VALID_TRANSITIONS[OnboardingStatus.CERTIFICATE_PENDING]
        assert OnboardingStatus.ACTIVE not in pending_targets, \
            "certificate_pending must NOT skip directly to active"
        assert OnboardingStatus.TENANT_CREATED not in pending_targets, \
            "certificate_pending must NOT skip directly to tenant_created"

    def test_failed_can_only_transition_to_offboarded(self):
        """FAILED state can only transition to OFFBOARDED (for cleanup)."""
        from proxy.models.onboarding import VALID_TRANSITIONS
        failed_targets = VALID_TRANSITIONS[OnboardingStatus.FAILED]
        assert failed_targets == frozenset({OnboardingStatus.OFFBOARDED}), \
            "FAILED must only allow transition to OFFBOARDED"

    def test_active_can_only_transition_to_offboarded(self):
        """ACTIVE state can only transition to OFFBOARDED."""
        from proxy.models.onboarding import VALID_TRANSITIONS
        active_targets = VALID_TRANSITIONS[OnboardingStatus.ACTIVE]
        assert active_targets == frozenset({OnboardingStatus.OFFBOARDED}), \
            "ACTIVE must only allow transition to OFFBOARDED"

    def test_all_states_can_reach_failed_except_terminal(self):
        """All non-terminal in-progress states must be able to transition to FAILED."""
        from proxy.models.onboarding import VALID_TRANSITIONS
        in_progress_states = [
            OnboardingStatus.CERTIFICATE_PENDING,
            OnboardingStatus.CERTIFICATE_VALIDATED,
            OnboardingStatus.TENANT_CREATED,
        ]
        for state in in_progress_states:
            assert OnboardingStatus.FAILED in VALID_TRANSITIONS[state], \
                f"{state.value} must be able to transition to FAILED"

    # -----------------------------------------------------------------------
    # 8. Silent empty return logging
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_list_pending_returns_empty_and_warns_when_pool_none(self):
        """list_pending_onboardings returns [] and logs warning when pool is None."""
        with patch("proxy.store.onboarding.get_pool", return_value=None), \
             patch("proxy.store.onboarding.logger") as mock_logger:
            result = await list_pending_onboardings()
            assert result == []
            mock_logger.warning.assert_called_once()
            assert "list_pending" in str(mock_logger.warning.call_args)

    @pytest.mark.asyncio
    async def test_list_validated_returns_empty_and_warns_when_pool_none(self):
        """list_validated_onboardings returns [] and logs warning when pool is None."""
        with patch("proxy.store.onboarding.get_pool", return_value=None), \
             patch("proxy.store.onboarding.logger") as mock_logger:
            result = await list_validated_onboardings()
            assert result == []
            mock_logger.warning.assert_called_once()
            assert "list_validated" in str(mock_logger.warning.call_args)
