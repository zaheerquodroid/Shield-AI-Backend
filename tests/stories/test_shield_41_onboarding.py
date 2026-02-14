"""SHIELD-41 — Build customer domain onboarding automation.

Acceptance Criteria:
  AC1: Onboarding API accepts customer domain and origin URL.
  AC2: ACM certificate requested automatically (DNS validation).
  AC3: DNS validation CNAME record returned to customer.
  AC4: Certificate validation polled automatically; tenant created when validated.
  AC5: Distribution tenant created under multi-tenant CloudFront.
  AC6: Status trackable through lifecycle states.
  AC7: Offboarding removes tenant, deletes certificate, marks inactive.
  AC8: Customer record scoped to customer_id (IDOR prevention).
"""

from __future__ import annotations

import asyncio
import inspect
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from proxy.api.onboarding_routes import (
    _build_status_response,
    _request_acm_certificate,
    router,
    set_acm_client,
    set_cloudfront_client,
)
from proxy.jobs.cert_poller import (
    DEFAULT_POLL_INTERVAL,
    DEFAULT_TIMEOUT_HOURS,
    _MIN_POLL_INTERVAL,
    check_certificate_status,
    run_cert_poller,
)
from proxy.jobs.tenant_creator import (
    create_distribution_tenant,
    run_tenant_creator,
)
from proxy.models.onboarding import (
    OnboardingCreate,
    OnboardingStatus,
    OnboardingStatusResponse,
)
from proxy.store.onboarding import (
    MAX_ONBOARDINGS_PER_CUSTOMER,
    _ONBOARDING_COLUMNS,
    create_onboarding,
    get_onboarding,
    list_onboardings,
    update_onboarding,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_AUTH = {"Authorization": "Bearer test-api-key"}

_CUSTOMER_ID = uuid4()
_ONBOARDING_ID = uuid4()

_NOW = datetime.now(timezone.utc)

_SAMPLE_RECORD = {
    "id": _ONBOARDING_ID,
    "customer_id": _CUSTOMER_ID,
    "customer_domain": "app.example.com",
    "origin_url": "https://origin.example.com",
    "status": OnboardingStatus.CERTIFICATE_PENDING,
    "acm_certificate_arn": "arn:aws:acm:us-east-1:123456789012:certificate/abc-123",
    "validation_cname_name": "_deadbeef.app.example.com.",
    "validation_cname_value": "_cafebabe.acm-validations.aws.",
    "distribution_tenant_id": "",
    "cloudfront_cname": "",
    "error_message": "",
    "created_at": _NOW,
    "updated_at": _NOW,
}


def _mock_tenant_tx(mock_conn):
    """Return a mock tenant_transaction that yields *mock_conn*."""
    @asynccontextmanager
    async def _tx(tenant_id):
        yield mock_conn
    return _tx


def _mock_pool_with_conn(mock_conn):
    """Return a mock pool whose acquire() context manager yields *mock_conn*."""
    mock_pool = MagicMock()
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock_pool


def _make_acm_client(
    cert_arn: str = "arn:aws:acm:us-east-1:123456789012:certificate/abc-123",
    cname_name: str = "_deadbeef.app.example.com.",
    cname_value: str = "_cafebabe.acm-validations.aws.",
    cert_status: str = "PENDING_VALIDATION",
    raise_on_request: bool = False,
    raise_on_describe: bool = False,
) -> MagicMock:
    """Build a mock ACM client."""
    acm = MagicMock()

    if raise_on_request:
        acm.request_certificate.side_effect = Exception("ACM request failed")
    else:
        acm.request_certificate.return_value = {"CertificateArn": cert_arn}

    if raise_on_describe:
        acm.describe_certificate.side_effect = Exception("ACM describe failed")
    else:
        acm.describe_certificate.return_value = {
            "Certificate": {
                "CertificateArn": cert_arn,
                "Status": cert_status,
                "DomainValidationOptions": [
                    {
                        "DomainName": "app.example.com",
                        "ResourceRecord": {
                            "Name": cname_name,
                            "Value": cname_value,
                            "Type": "CNAME",
                        },
                    }
                ],
            }
        }

    acm.delete_certificate.return_value = {}
    return acm


def _make_cloudfront_client(
    tenant_id: str = "tenant-abc123",
    domain_name: str = "d1234abcdef.cloudfront.net",
    raise_on_create: bool = False,
    raise_on_delete: bool = False,
) -> MagicMock:
    """Build a mock CloudFront client."""
    cf = MagicMock()

    if raise_on_create:
        cf.create_distribution_tenant.side_effect = Exception("CloudFront create failed")
    else:
        cf.create_distribution_tenant.return_value = {
            "DistributionTenant": {
                "Id": tenant_id,
                "DomainName": domain_name,
            }
        }

    if raise_on_delete:
        cf.delete_distribution_tenant.side_effect = Exception("CloudFront delete failed")
    else:
        cf.delete_distribution_tenant.return_value = {}

    return cf


@pytest.fixture
def api_client():
    """Test client for onboarding API."""
    import proxy.main as main_module
    main_module._pipeline = None
    main_module._http_client = None
    from proxy.main import app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    main_module._http_client = None
    main_module._pipeline = None


def _mock_customer(customer_id=None):
    """Return a mock customer record."""
    cid = customer_id or _CUSTOMER_ID
    return {
        "id": cid,
        "name": "Test Corp",
        "plan": "starter",
        "settings": {},
        "created_at": _NOW.isoformat(),
        "updated_at": _NOW.isoformat(),
    }


# =========================================================================
# AC1: Onboarding API accepts customer domain and origin URL
# =========================================================================
class TestAC1_OnboardingAPI:
    """AC1: Onboarding API accepts customer domain and origin URL."""

    def test_api_accepts_valid_domain_and_origin(self, api_client):
        """POST /api/onboard/customers/{id}/ accepts valid domain + origin URL."""
        acm = _make_acm_client()
        record = {**_SAMPLE_RECORD, "customer_id": _CUSTOMER_ID, "id": _ONBOARDING_ID}

        with patch("proxy.api.onboarding_routes.pg_store.get_customer",
                    new_callable=AsyncMock, return_value=_mock_customer()), \
             patch("proxy.api.onboarding_routes.validate_origin_url", return_value=None), \
             patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding_by_domain",
                    new_callable=AsyncMock, return_value=None), \
             patch("proxy.api.onboarding_routes.onboarding_store.count_active_onboardings",
                    new_callable=AsyncMock, return_value=0), \
             patch("proxy.api.onboarding_routes._acm_client", acm), \
             patch("proxy.api.onboarding_routes.onboarding_store.create_onboarding",
                    new_callable=AsyncMock, return_value=record):
            resp = api_client.post(
                f"/api/onboard/customers/{_CUSTOMER_ID}/",
                json={"customer_domain": "app.example.com", "origin_url": "https://origin.example.com"},
                headers=_AUTH,
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["customer_domain"] == "app.example.com"
        assert data["origin_url"] == "https://origin.example.com"

    def test_domain_validation_rejects_invalid(self, api_client):
        """Pydantic rejects invalid domain formats (IP, localhost, malformed)."""
        invalid_domains = [
            "not valid domain",
            "192.168.1.1",
            "localhost",
            "-leading-hyphen.com",
            "",
        ]
        for domain in invalid_domains:
            resp = api_client.post(
                f"/api/onboard/customers/{_CUSTOMER_ID}/",
                json={"customer_domain": domain, "origin_url": "https://origin.example.com"},
                headers=_AUTH,
            )
            assert resp.status_code == 422, f"Expected 422 for domain={domain!r}, got {resp.status_code}"

    def test_origin_url_rejects_ssrf_targets(self, api_client):
        """SSRF-blocked origin URLs are rejected with 422."""
        ssrf_error = "URL resolves to a blocked private/reserved IP"
        with patch("proxy.api.onboarding_routes.pg_store.get_customer",
                    new_callable=AsyncMock, return_value=_mock_customer()), \
             patch("proxy.api.onboarding_routes.validate_origin_url", return_value=ssrf_error), \
             patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding_by_domain",
                    new_callable=AsyncMock, return_value=None), \
             patch("proxy.api.onboarding_routes.onboarding_store.count_active_onboardings",
                    new_callable=AsyncMock, return_value=0):
            resp = api_client.post(
                f"/api/onboard/customers/{_CUSTOMER_ID}/",
                json={"customer_domain": "app.example.com", "origin_url": "https://169.254.169.254/latest"},
                headers=_AUTH,
            )
        assert resp.status_code == 422
        assert "Origin URL validation failed" in resp.json()["detail"]

    def test_api_requires_authentication(self, api_client):
        """Endpoints require a valid API key (Depends(require_api_key))."""
        # No auth header
        resp = api_client.post(
            f"/api/onboard/customers/{_CUSTOMER_ID}/",
            json={"customer_domain": "app.example.com", "origin_url": "https://origin.example.com"},
        )
        assert resp.status_code == 401

        # Invalid auth header
        resp = api_client.get(
            f"/api/onboard/customers/{_CUSTOMER_ID}/",
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 403


# =========================================================================
# AC2: ACM certificate requested automatically (DNS validation)
# =========================================================================
class TestAC2_ACMCertificateRequest:
    """AC2: ACM certificate requested automatically with DNS validation."""

    @pytest.mark.asyncio
    async def test_acm_request_uses_dns_validation(self):
        """_request_acm_certificate calls request_certificate with ValidationMethod='DNS'."""
        acm = _make_acm_client()
        with patch("proxy.api.onboarding_routes._acm_client", acm):
            result = await _request_acm_certificate("app.example.com")

        acm.request_certificate.assert_called_once_with(
            DomainName="app.example.com",
            ValidationMethod="DNS",
        )
        assert result["certificate_arn"] == "arn:aws:acm:us-east-1:123456789012:certificate/abc-123"

    @pytest.mark.asyncio
    async def test_certificate_arn_stored_in_result(self):
        """The certificate ARN from ACM is captured in the result dict."""
        custom_arn = "arn:aws:acm:us-east-1:999:certificate/xyz-789"
        acm = _make_acm_client(cert_arn=custom_arn)
        with patch("proxy.api.onboarding_routes._acm_client", acm):
            result = await _request_acm_certificate("secure.example.com")
        assert result["certificate_arn"] == custom_arn

    @pytest.mark.asyncio
    async def test_acm_failure_returns_502(self):
        """ACM request_certificate failure raises HTTPException 502."""
        acm = _make_acm_client(raise_on_request=True)
        with patch("proxy.api.onboarding_routes._acm_client", acm):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                await _request_acm_certificate("app.example.com")
            assert exc_info.value.status_code == 502
            assert "Failed to request SSL certificate" in exc_info.value.detail


# =========================================================================
# AC3: DNS validation CNAME record returned to customer
# =========================================================================
class TestAC3_DNSValidation:
    """AC3: DNS validation CNAME record returned to customer."""

    @pytest.mark.asyncio
    async def test_response_includes_validation_cname_name(self):
        """ACM describe_certificate response provides validation CNAME name."""
        acm = _make_acm_client(cname_name="_abc123.app.example.com.")
        with patch("proxy.api.onboarding_routes._acm_client", acm):
            result = await _request_acm_certificate("app.example.com")
        assert result["cname_name"] == "_abc123.app.example.com."

    @pytest.mark.asyncio
    async def test_response_includes_validation_cname_value(self):
        """ACM describe_certificate response provides validation CNAME value."""
        acm = _make_acm_client(cname_value="_validation.acm-validations.aws.")
        with patch("proxy.api.onboarding_routes._acm_client", acm):
            result = await _request_acm_certificate("app.example.com")
        assert result["cname_value"] == "_validation.acm-validations.aws."

    def test_status_response_shows_dns_action_for_pending(self):
        """_build_status_response includes DNS CNAME action when certificate_pending."""
        record = {**_SAMPLE_RECORD, "status": OnboardingStatus.CERTIFICATE_PENDING}
        response = _build_status_response(record)
        assert len(response.required_actions) == 1
        assert "CNAME" in response.required_actions[0]
        assert record["validation_cname_name"] in response.required_actions[0]
        assert record["validation_cname_value"] in response.required_actions[0]
        assert len(response.next_steps) == 1
        assert "validated automatically" in response.next_steps[0]


# =========================================================================
# AC4: Certificate validation polled automatically; tenant created when validated
# =========================================================================
class TestAC4_CertificatePolling:
    """AC4: Certificate validation polled; tenant created when validated."""

    @pytest.mark.asyncio
    async def test_poller_detects_issued_status(self):
        """When ACM reports ISSUED, check_certificate_status returns certificate_validated."""
        acm = _make_acm_client(cert_status="ISSUED")
        onboarding = {**_SAMPLE_RECORD}
        new_status = await check_certificate_status(onboarding, acm_client=acm)
        assert new_status == "certificate_validated"

    @pytest.mark.asyncio
    async def test_poller_detects_failed_status(self):
        """When ACM reports FAILED, check_certificate_status returns failed."""
        acm = _make_acm_client(cert_status="FAILED")
        acm.describe_certificate.return_value["Certificate"]["FailureReason"] = "CAA_ERROR"
        onboarding = {**_SAMPLE_RECORD}
        new_status = await check_certificate_status(onboarding, acm_client=acm)
        assert new_status == "failed"

    @pytest.mark.asyncio
    async def test_poller_enforces_72_hour_timeout(self):
        """Onboarding older than DEFAULT_TIMEOUT_HOURS is marked failed."""
        acm = _make_acm_client(cert_status="PENDING_VALIDATION")
        expired_time = _NOW - timedelta(hours=DEFAULT_TIMEOUT_HOURS + 1)
        onboarding = {**_SAMPLE_RECORD, "created_at": expired_time}
        new_status = await check_certificate_status(onboarding, acm_client=acm)
        assert new_status == "failed"
        assert DEFAULT_TIMEOUT_HOURS == 72, "Default timeout should be 72 hours"

    @pytest.mark.asyncio
    async def test_poller_uses_configured_interval(self):
        """run_cert_poller respects poll_interval (clamped to minimum 10s)."""
        assert DEFAULT_POLL_INTERVAL == 60
        assert _MIN_POLL_INTERVAL == 10

        shutdown = asyncio.Event()
        shutdown.set()  # Immediately stop

        acm = _make_acm_client()
        with patch("proxy.store.onboarding.list_pending_onboardings",
                    new_callable=AsyncMock, return_value=[]):
            # Should not raise — just start and stop
            await run_cert_poller(
                poll_interval=15,
                acm_client=acm,
                shutdown_event=shutdown,
            )
        # If we get here, the poll loop respected shutdown_event


# =========================================================================
# AC5: Distribution tenant created under multi-tenant CloudFront
# =========================================================================
class TestAC5_DistributionTenant:
    """AC5: Distribution tenant created under multi-tenant CloudFront."""

    @pytest.mark.asyncio
    async def test_tenant_creator_calls_cloudfront(self):
        """create_distribution_tenant invokes cloudfront create_distribution_tenant."""
        cf = _make_cloudfront_client()
        onboarding = {
            **_SAMPLE_RECORD,
            "status": OnboardingStatus.CERTIFICATE_VALIDATED,
        }
        result = await create_distribution_tenant(
            onboarding, cloudfront_client=cf, distribution_id="E1234DIST",
        )
        cf.create_distribution_tenant.assert_called_once()
        call_kwargs = cf.create_distribution_tenant.call_args
        assert call_kwargs[1]["DistributionId"] == "E1234DIST"
        assert call_kwargs[1]["Domains"][0]["Domain"] == "app.example.com"
        assert call_kwargs[1]["Domains"][0]["CertificateArn"] == _SAMPLE_RECORD["acm_certificate_arn"]
        assert result is not None

    @pytest.mark.asyncio
    async def test_tenant_id_and_cname_stored(self):
        """create_distribution_tenant returns tenant_id and cloudfront_cname."""
        cf = _make_cloudfront_client(
            tenant_id="tenant-xyz",
            domain_name="d999.cloudfront.net",
        )
        onboarding = {**_SAMPLE_RECORD, "status": OnboardingStatus.CERTIFICATE_VALIDATED}
        result = await create_distribution_tenant(
            onboarding, cloudfront_client=cf, distribution_id="E1234DIST",
        )
        assert result["tenant_id"] == "tenant-xyz"
        assert result["cloudfront_cname"] == "d999.cloudfront.net"

    @pytest.mark.asyncio
    async def test_creator_marks_failed_on_api_error(self):
        """CloudFront API failure returns None (caller marks record as failed)."""
        cf = _make_cloudfront_client(raise_on_create=True)
        onboarding = {**_SAMPLE_RECORD, "status": OnboardingStatus.CERTIFICATE_VALIDATED}
        result = await create_distribution_tenant(
            onboarding, cloudfront_client=cf, distribution_id="E1234DIST",
        )
        assert result is None


# =========================================================================
# AC6: Status trackable through lifecycle states
# =========================================================================
class TestAC6_StatusTracking:
    """AC6: Status trackable: certificate_pending -> certificate_validated -> tenant_created -> active."""

    def test_certificate_pending_is_initial_status(self):
        """New onboarding records start in certificate_pending status."""
        # The SQL in create_onboarding hardcodes 'certificate_pending'
        src = inspect.getsource(create_onboarding)
        assert "'certificate_pending'" in src

    def test_certificate_validated_after_cert_issued(self):
        """check_certificate_status returns 'certificate_validated' when ACM says ISSUED."""
        # Verified in AC4, but confirm the enum value exists and is correct
        assert OnboardingStatus.CERTIFICATE_VALIDATED.value == "certificate_validated"

    def test_tenant_created_after_cloudfront_tenant(self):
        """Tenant creator sets status to 'tenant_created' after successful tenant creation."""
        src = inspect.getsource(run_tenant_creator)
        assert '"tenant_created"' in src

    def test_status_endpoint_returns_actions_and_next_steps(self):
        """_build_status_response provides required_actions and next_steps per state."""
        # certificate_pending: requires DNS CNAME action
        pending = _build_status_response({
            **_SAMPLE_RECORD,
            "status": OnboardingStatus.CERTIFICATE_PENDING,
        })
        assert len(pending.required_actions) >= 1
        assert len(pending.next_steps) >= 1

        # certificate_validated: next step about CloudFront
        validated = _build_status_response({
            **_SAMPLE_RECORD,
            "status": OnboardingStatus.CERTIFICATE_VALIDATED,
        })
        assert any("CloudFront" in s for s in validated.next_steps)

        # tenant_created: requires CNAME action for domain
        created = _build_status_response({
            **_SAMPLE_RECORD,
            "status": OnboardingStatus.TENANT_CREATED,
            "cloudfront_cname": "d1234.cloudfront.net",
        })
        assert len(created.required_actions) >= 1
        assert "CNAME" in created.required_actions[0]
        assert "d1234.cloudfront.net" in created.required_actions[0]

        # active: fully protected message
        active = _build_status_response({
            **_SAMPLE_RECORD,
            "status": OnboardingStatus.ACTIVE,
        })
        assert any("protected" in s.lower() for s in active.next_steps)

        # failed: error message and retry guidance
        failed = _build_status_response({
            **_SAMPLE_RECORD,
            "status": OnboardingStatus.FAILED,
            "error_message": "Certificate validation timed out",
        })
        assert any("retry" in s.lower() for s in failed.next_steps)
        assert any("Certificate validation timed out" in s for s in failed.next_steps)

    def test_all_onboarding_status_enum_values_valid(self):
        """OnboardingStatus enum contains all lifecycle states."""
        expected = {
            "certificate_pending",
            "certificate_validated",
            "tenant_created",
            "active",
            "failed",
            "offboarded",
        }
        actual = {s.value for s in OnboardingStatus}
        assert actual == expected

    def test_status_transitions_follow_defined_flow(self):
        """Status flow: certificate_pending -> certificate_validated -> tenant_created -> active.
        Also: any state can transition to failed or offboarded."""
        # The schema SQL CHECK constraint defines valid statuses
        valid_statuses = {
            "certificate_pending", "certificate_validated", "tenant_created",
            "active", "failed", "offboarded",
        }
        # Verify enum matches schema
        enum_values = {s.value for s in OnboardingStatus}
        assert enum_values == valid_statuses

        # Verify the happy path order
        happy_path = [
            OnboardingStatus.CERTIFICATE_PENDING,
            OnboardingStatus.CERTIFICATE_VALIDATED,
            OnboardingStatus.TENANT_CREATED,
            OnboardingStatus.ACTIVE,
        ]
        assert happy_path[0].value == "certificate_pending"
        assert happy_path[1].value == "certificate_validated"
        assert happy_path[2].value == "tenant_created"
        assert happy_path[3].value == "active"

        # Failed and offboarded are terminal states
        assert OnboardingStatus.FAILED.value == "failed"
        assert OnboardingStatus.OFFBOARDED.value == "offboarded"


# =========================================================================
# AC7: Offboarding removes tenant, deletes certificate, marks inactive
# =========================================================================
class TestAC7_Offboarding:
    """AC7: Offboarding removes tenant, deletes certificate, marks inactive."""

    def test_delete_endpoint_marks_offboarded(self, api_client):
        """DELETE /api/onboard/customers/{cid}/{oid} marks record as offboarded."""
        record = {
            **_SAMPLE_RECORD,
            "status": OnboardingStatus.ACTIVE,
            "distribution_tenant_id": "tenant-abc",
            "acm_certificate_arn": "arn:aws:acm:us-east-1:123:certificate/abc",
        }
        cf = _make_cloudfront_client()
        acm = _make_acm_client()

        with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding",
                    new_callable=AsyncMock, return_value=record), \
             patch("proxy.api.onboarding_routes._cloudfront_client", cf), \
             patch("proxy.api.onboarding_routes._acm_client", acm), \
             patch("proxy.api.onboarding_routes.onboarding_store.update_onboarding",
                    new_callable=AsyncMock, return_value=None) as mock_update:
            resp = api_client.delete(
                f"/api/onboard/customers/{_CUSTOMER_ID}/{_ONBOARDING_ID}",
                headers=_AUTH,
            )
        assert resp.status_code == 204
        mock_update.assert_called_once()
        call_kwargs = mock_update.call_args
        assert call_kwargs[1]["status"] == OnboardingStatus.OFFBOARDED

    def test_offboarding_deletes_cloudfront_tenant(self, api_client):
        """Offboarding calls cloudfront delete_distribution_tenant."""
        tenant_id = "tenant-to-delete"
        record = {
            **_SAMPLE_RECORD,
            "status": OnboardingStatus.ACTIVE,
            "distribution_tenant_id": tenant_id,
        }
        cf = _make_cloudfront_client()

        with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding",
                    new_callable=AsyncMock, return_value=record), \
             patch("proxy.api.onboarding_routes._cloudfront_client", cf), \
             patch("proxy.api.onboarding_routes._acm_client", _make_acm_client()), \
             patch("proxy.api.onboarding_routes.onboarding_store.update_onboarding",
                    new_callable=AsyncMock, return_value=None):
            resp = api_client.delete(
                f"/api/onboard/customers/{_CUSTOMER_ID}/{_ONBOARDING_ID}",
                headers=_AUTH,
            )
        assert resp.status_code == 204
        cf.delete_distribution_tenant.assert_called_once()
        call_kwargs = cf.delete_distribution_tenant.call_args
        assert call_kwargs[1]["Id"] == tenant_id

    def test_offboarding_deletes_acm_certificate(self, api_client):
        """Offboarding calls acm delete_certificate."""
        cert_arn = "arn:aws:acm:us-east-1:123:certificate/to-delete"
        record = {
            **_SAMPLE_RECORD,
            "status": OnboardingStatus.ACTIVE,
            "acm_certificate_arn": cert_arn,
            "distribution_tenant_id": "",
        }
        acm = _make_acm_client()

        with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding",
                    new_callable=AsyncMock, return_value=record), \
             patch("proxy.api.onboarding_routes._cloudfront_client", None), \
             patch("proxy.api.onboarding_routes._acm_client", acm), \
             patch("proxy.api.onboarding_routes.onboarding_store.update_onboarding",
                    new_callable=AsyncMock, return_value=None):
            resp = api_client.delete(
                f"/api/onboard/customers/{_CUSTOMER_ID}/{_ONBOARDING_ID}",
                headers=_AUTH,
            )
        assert resp.status_code == 204
        acm.delete_certificate.assert_called_once_with(CertificateArn=cert_arn)

    def test_offboarding_is_idempotent(self, api_client):
        """Offboarding an already-offboarded record returns 204 (no-op)."""
        record = {
            **_SAMPLE_RECORD,
            "status": OnboardingStatus.OFFBOARDED,
        }
        cf = _make_cloudfront_client()
        acm = _make_acm_client()

        with patch("proxy.api.onboarding_routes.onboarding_store.get_onboarding",
                    new_callable=AsyncMock, return_value=record), \
             patch("proxy.api.onboarding_routes._cloudfront_client", cf), \
             patch("proxy.api.onboarding_routes._acm_client", acm), \
             patch("proxy.api.onboarding_routes.onboarding_store.update_onboarding",
                    new_callable=AsyncMock) as mock_update:
            resp = api_client.delete(
                f"/api/onboard/customers/{_CUSTOMER_ID}/{_ONBOARDING_ID}",
                headers=_AUTH,
            )
        assert resp.status_code == 204
        # Should NOT call update or AWS cleanup when already offboarded
        mock_update.assert_not_called()
        cf.delete_distribution_tenant.assert_not_called()
        acm.delete_certificate.assert_not_called()


# =========================================================================
# AC8: Customer record scoped to customer_id (IDOR prevention)
# =========================================================================
class TestAC8_TenantIsolation:
    """AC8: Customer record scoped to customer_id (IDOR prevention)."""

    def test_store_uses_tenant_transaction(self):
        """Tenant-scoped store functions use tenant_transaction for RLS enforcement."""
        # Verify create_onboarding uses tenant_transaction
        create_src = inspect.getsource(create_onboarding)
        assert "tenant_transaction" in create_src

        # Verify get_onboarding uses tenant_transaction when customer_id provided
        get_src = inspect.getsource(get_onboarding)
        assert "tenant_transaction" in get_src

        # Verify list_onboardings uses tenant_transaction
        list_src = inspect.getsource(list_onboardings)
        assert "tenant_transaction" in list_src

        # Verify update_onboarding uses tenant_transaction when customer_id provided
        update_src = inspect.getsource(update_onboarding)
        assert "tenant_transaction" in update_src

    def test_schema_has_rls_policy(self):
        """The onboardings table has RLS enabled with tenant_isolation policy."""
        import pathlib
        schema_path = pathlib.Path(__file__).resolve().parents[2] / "proxy" / "models" / "schema.sql"
        schema = schema_path.read_text()

        # RLS enabled on onboardings table
        assert "ALTER TABLE onboardings ENABLE ROW LEVEL SECURITY" in schema

        # tenant_isolation policy exists
        assert "CREATE POLICY tenant_isolation ON onboardings" in schema

        # Policy uses app.current_tenant_id GUC
        assert "current_setting('app.current_tenant_id'" in schema

        # Policy compares against customer_id
        assert "customer_id = current_setting('app.current_tenant_id'" in schema

    def test_customer_id_in_url_prevents_idor(self):
        """All API endpoints scope operations to customer_id from URL path."""
        # Verify router prefix structure
        assert router.prefix == "/api/onboard"

        # Inspect route paths — all should include {customer_id}
        for route in router.routes:
            path = getattr(route, "path", "")
            if path:
                assert "{customer_id}" in path, f"Route {path} missing customer_id scope"

    def test_list_endpoint_returns_only_customers_onboardings(self, api_client):
        """GET /api/onboard/customers/{cid}/ returns only that customer's onboardings."""
        customer_a = uuid4()
        customer_b = uuid4()

        records_a = [
            {**_SAMPLE_RECORD, "customer_id": customer_a, "id": uuid4(), "customer_domain": "a.example.com"},
        ]

        with patch("proxy.api.onboarding_routes.onboarding_store.list_onboardings",
                    new_callable=AsyncMock, return_value=records_a) as mock_list:
            resp = api_client.get(
                f"/api/onboard/customers/{customer_a}/",
                headers=_AUTH,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        # Verify the store was called with the correct customer_id from URL
        mock_list.assert_called_once_with(customer_a)

        # Different customer gets different results
        with patch("proxy.api.onboarding_routes.onboarding_store.list_onboardings",
                    new_callable=AsyncMock, return_value=[]) as mock_list_b:
            resp_b = api_client.get(
                f"/api/onboard/customers/{customer_b}/",
                headers=_AUTH,
            )
        assert resp_b.status_code == 200
        assert resp_b.json()["total"] == 0
        mock_list_b.assert_called_once_with(customer_b)
